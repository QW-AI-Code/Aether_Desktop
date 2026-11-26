//! Smart mode 1.5.0 - port of Aether Mobile 1.7.0.
//!
//! 1. Fingerprint → two lanes (WARP family, MASQUE family), **both from 0 s**.
//! 2. Every lane walks light → heavy on its own leased port; each attempt waits
//!    for the engine to really *serve* (`readiness.rs`) and then proves outbound
//!    TCP. A proven engine is kept running.
//! 3. After the first proof the other lane gets `QUALITY_WINDOW_MS` more.
//! 4. Two or more proven routes are measured one after another through their
//!    own port (latency, download, upload) and ranked with a protocol overhead.
//! 5. All lane engines are stopped; the ranked tactics are confirmed in order as
//!    normal connections. Nothing proved → two deep last-resort rungs.
pub mod brain;
pub mod memory;
pub mod network;
pub mod plan;
pub mod scheduler;
use crate::{
    engine::AetherProcess,
    log::DiagnosticsLog,
    profile::{
        AccessMode, ConnectionProfile, EndpointMode, Noize, Protocol, ScanMode, TransportBackend,
    },
    smart_auto::{Candidate, NetFingerprint},
};
use parking_lot::Mutex;
use plan::{Family, Hardness, Proto, Tactic};
use std::{
    collections::VecDeque,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
/// Proof window after the engine serves (the stage gate's grace).
const PROOF_GRACE_MS: u64 = 12_000;
/// Confirmation of a ranked route is a normal connect, capped at 60 s.
const CONFIRM_MAX_MS: u64 = 60_000;
pub const PHASE_RACING: u8 = 0;
pub const PHASE_COMPARING: u8 = 1;
pub fn eligible(p: &ConnectionProfile) -> bool {
    p.protocol == Protocol::Smart
        && p.endpoint_mode == EndpointMode::Auto
        && p.backend == TransportBackend::Aether
        && !(p.uses_zero_trust() && p.access_mode == AccessMode::Email)
        && p.upstream_proxy().is_none()
}
fn noize_of(h: Hardness) -> Noize {
    match h {
        Hardness::Off => Noize::Off,
        Hardness::Light => Noize::Light,
        Hardness::Firewall => Noize::Firewall,
        Hardness::Balanced => Noize::Balanced,
        Hardness::Gfw => Noize::Gfw,
        Hardness::Aggressive => Noize::Aggressive,
    }
}
/// The user's profile with one tactic applied. It can only ever make the
/// profile *harder*: noize = max(user, tactic), HTTP/2 and fragmentation are
/// OR-ed in, and **ECH stays exactly as the user set it**. Quick reconnect is
/// not overridden.
pub fn apply(t: &Tactic, user: &ConnectionProfile, confirm: bool) -> ConnectionProfile {
    let mut p = user.clone();
    p.protocol = match t.protocol {
        Proto::Wireguard => Protocol::Wireguard,
        Proto::Gool => Protocol::Gool,
        Proto::Masque => Protocol::Masque,
        Proto::Mim => Protocol::Mim,
    };
    let floor = noize_of(t.noize);
    if (p.noize as u8) < floor as u8 {
        p.noize = floor;
    }
    p.masque_http2 = user.masque_http2 || (t.h2 && t.family == Family::Masque);
    p.fragment = user.fragment || t.fragment;
    p.ech = user.ech;
    if !confirm {
        p.scan_mode = ScanMode::Turbo;
    }
    p
}
/// A last-resort rung: the tactic with the user's full ranges and a deep scan
/// (Turbo → Balanced, otherwise the user's own scan).
pub fn last_resort_profile(t: &Tactic, user: &ConnectionProfile) -> ConnectionProfile {
    let mut p = apply(t, user, true);
    p.scan_mode = if user.scan_mode == ScanMode::Turbo {
        ScanMode::Balanced
    } else {
        user.scan_mode
    };
    p
}
#[derive(Debug, Clone)]
pub enum Step {
    Race(Vec<plan::Lane>),
    Confirm(Tactic),
    LastResort(Tactic),
}
pub struct Session {
    pub fingerprint: NetFingerprint,
    pub key: String,
    pub user: ConnectionProfile,
    pub ctx: plan::Context,
    pub steps: VecDeque<Step>,
    pub current: Option<Tactic>,
    pub confirmed_probe: bool,
    pub race: Option<RaceTask>,
    /// 1.5.0 (same version): what the Smart brain learned on this network,
    /// shared by both race lanes and the last-resort rungs.
    pub brain: Arc<brain::Board>,
}
fn lane_summary(l: &plan::Lane) -> String {
    format!(
        "{}@+{}s",
        l.tactics.iter().map(|t| t.id).collect::<Vec<_>>().join(","),
        l.start_after_ms / 1_000
    )
}
impl Session {
    pub fn new(user: &ConnectionProfile, fp: NetFingerprint, dir: &Path, prefer_tcp: bool) -> Self {
        let n = network::current();
        let m = memory::recall(dir, &n.key);
        let mut ctx = crate::smart_auto::smart_context(user, fp, prefer_tcp);
        ctx.mobile = n.mobile;
        let lanes = plan::plan(ctx, m.as_ref(), crate::custom::now_millis());
        DiagnosticsLog::i(
            "smart+",
            &format!(
                "Smart on network {} ({:?}, quic={}): fair race[{}]",
                n.key,
                ctx.dpi,
                match ctx.quic {
                    Some(true) => "ok",
                    Some(false) => "blocked",
                    None => "unknown",
                },
                lanes.iter().map(lane_summary).collect::<Vec<_>>().join(" | ")
            ),
        );
        Self {
            fingerprint: fp,
            key: n.key,
            user: user.clone(),
            ctx,
            steps: VecDeque::from([Step::Race(lanes)]),
            current: None,
            confirmed_probe: false,
            race: None,
            brain: Arc::new(brain::Board::new(brain::initial(
                fp.udp_ok,
                fp.quic_reachable,
                fp.filtered,
            ))),
        }
    }
    /// Queue the ranked winners for confirmation, then the two last resorts.
    pub fn after_race(&mut self, ranked: Vec<Tactic>) {
        if ranked.is_empty() {
            DiagnosticsLog::w(
                "smart+",
                "Smart: no route proved itself in the race - last resort: deep scan of MASQUE over HTTP/2 and WireGuard.",
            );
        }
        for t in ranked {
            self.steps.push_back(Step::Confirm(t));
        }
        // The last resorts start already adapted to what the race learned.
        let learned = self.brain.now();
        if learned != brain::Knowledge::default() {
            DiagnosticsLog::i("smart+", &format!("Smart brain after the race: {}", learned.describe()));
        }
        for t in brain::adapt(plan::last_resort(self.ctx), &learned) {
            self.steps.push_back(Step::LastResort(t));
        }
    }
    pub fn candidate(&mut self, t: Tactic, last_resort: bool) -> Candidate {
        let (profile, timeout_ms, label) = if last_resort {
            let p = last_resort_profile(&t, &self.user);
            let ms = p.connect_timeout_ms();
            let label = crate::smart_auto::tactic_label(&p, true);
            (p, ms, label)
        } else {
            let p = apply(&t, &self.user, true);
            (
                p,
                self.user.connect_timeout_ms().min(CONFIRM_MAX_MS),
                format!("Smart {} (confirm)", t.id),
            )
        };
        let id = t.id;
        self.current = Some(t);
        self.confirmed_probe = true;
        Candidate {
            profile,
            timeout_ms,
            label,
            tactic: Some(id),
        }
    }
    pub fn failed(&mut self, dir: &Path) {
        if let Some(t) = self.current.take() {
            memory::failure(dir, &self.key, t.id, crate::custom::now_millis());
        }
    }
    pub fn succeeded(&mut self, dir: &Path, verified: bool) {
        if verified || self.confirmed_probe {
            if let Some(t) = self.current.take() {
                memory::remember(dir, &self.key, t.id, crate::custom::now_millis());
            }
        }
    }
}
type Engine = Arc<Mutex<AetherProcess>>;
/// Stops the lane engine when an attempt ends - unless the attempt proved its
/// route, in which case the engine stays up to be measured.
struct OwnedProbe {
    engine: Engine,
    armed: bool,
}
impl Drop for OwnedProbe {
    fn drop(&mut self) {
        if self.armed {
            self.engine.lock().stop();
        }
    }
}
fn quality(q: crate::probe::TunnelQuality) -> plan::Quality {
    plan::Quality {
        rtt_ms: q.rtt_ms,
        down_kbps: q.down_kbps,
        up_kbps: q.up_kbps,
    }
}
pub struct RaceTask {
    cancel: Arc<crate::custom::cancel::Cancel>,
    engines: Arc<Mutex<Vec<Engine>>>,
    phase: Arc<AtomicU8>,
    result: mpsc::Receiver<Vec<Tactic>>,
    join: Option<JoinHandle<()>>,
}
impl RaceTask {
    pub fn spawn(
        user: ConnectionProfile,
        lanes: Vec<plan::Lane>,
        engine: &AetherProcess,
        dir: PathBuf,
        key: String,
        board: Arc<brain::Board>,
    ) -> Self {
        let cancel = crate::custom::cancel::Cancel::new();
        let engines = Arc::new(Mutex::new(Vec::new()));
        let phase = Arc::new(AtomicU8::new(PHASE_RACING));
        let (tx, result) = mpsc::channel();
        // Reserve simultaneously, excluding every fixed session role. No fixed-port fallback.
        let mut leased = vec![];
        for lane in lanes.into_iter().take(2) {
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", 0)) {
                let port = listener.local_addr().unwrap().port();
                if crate::engine::FIXED_PORTS.contains(&port) {
                    continue;
                }
                leased.push((
                    lane,
                    listener,
                    Arc::new(Mutex::new(engine.fork_probe(port))),
                ));
            }
        }
        let c = cancel.clone();
        let es = engines.clone();
        let ph = phase.clone();
        let join = thread::spawn(move || {
            let mut running = Vec::new();
            let mut resources = Vec::new();
            for (lane, listener, eng) in leased {
                es.lock().push(eng.clone());
                running.push(lane);
                resources.push((Mutex::new(Some(listener)), eng));
            }
            let race_started = Instant::now();
            let proven = scheduler::run_adaptive(
                running,
                c.clone(),
                Duration::from_millis(plan::RACE_CEILING_MS),
                Duration::from_millis(plan::QUALITY_WINDOW_MS),
                |index, tactic, lane_cancel| {
                    let (lease, eng) = &resources[index];
                    let port = eng.lock().probe_bind_port().unwrap();
                    lease.lock().take();
                    let mut owned = OwnedProbe {
                        engine: eng.clone(),
                        armed: true,
                    };
                    DiagnosticsLog::i(
                        "smart+",
                        &format!(
                            "Smart lane {}: {} ({:?}) on local :{}",
                            index + 1,
                            tactic.id,
                            tactic.family,
                            port
                        ),
                    );
                    let attempt = Instant::now();
                    let profile = apply(tactic, &user, false);
                    {
                        let mut e = eng.lock();
                        if lane_cancel.stopped() {
                            return false;
                        }
                        if e.start(&profile, Some(tactic.budget_ms)).is_err() {
                            memory::failure(&dir, &key, tactic.id, crate::custom::now_millis());
                            return false;
                        }
                    }
                    let ready = eng.lock().readiness();
                    let left = tactic
                        .budget_ms
                        .saturating_sub(attempt.elapsed().as_millis() as u64)
                        .max(3_000);
                    let label = format!("Smart lane {}: {}", index + 1, tactic.id);
                    // 1.5.0 (same version): a UDP rung on a network already known
                    // to drop UDP is abandoned early instead of burning its budget.
                    let abandoned = std::cell::Cell::new(false);
                    let outcome = crate::readiness::await_ready(
                        &ready,
                        port,
                        left,
                        &label,
                        &mut || eng.lock().is_alive(),
                        &|| {
                            if lane_cancel.stopped() {
                                return true;
                            }
                            let give_up = brain::should_abandon(
                                tactic,
                                &board.now(),
                                attempt.elapsed().as_millis() as u64,
                                ready.serving(),
                            );
                            if give_up {
                                abandoned.set(true);
                            }
                            give_up
                        },
                        &crate::probe::socks_greeting_within,
                    );
                    let mut verdict = match outcome {
                        crate::readiness::Outcome::Died => format!(
                            "engine stopped ({})",
                            ready.fatal_line().unwrap_or_else(|| "no error line".into())
                        ),
                        crate::readiness::Outcome::Timeout if abandoned.get() => {
                            "abandoned early - UDP is dropped on this network".to_string()
                        }
                        crate::readiness::Outcome::Timeout => {
                            "no working gateway in time (timeout-before-serving)".to_string()
                        }
                        crate::readiness::Outcome::Ready => String::new(),
                    };
                    let mut good = false;
                    if outcome == crate::readiness::Outcome::Ready {
                        let left = tactic
                            .budget_ms
                            .saturating_sub(attempt.elapsed().as_millis() as u64)
                            .max(PROOF_GRACE_MS);
                        let proof_deadline = Instant::now() + Duration::from_millis(left);
                        verdict = "engine serves, but no outbound TCP got through".to_string();
                        while Instant::now() < proof_deadline && !lane_cancel.stopped() {
                            if !eng.lock().is_alive() {
                                verdict = "engine stopped while proving its route".to_string();
                                break;
                            }
                            if eng.lock().owns_probe_listener(port)
                                && crate::custom::realdelay::request_through_cancel(
                                    port,
                                    "",
                                    "",
                                    "www.gstatic.com",
                                    Some(lane_cancel),
                                )
                                .is_ok()
                            {
                                good = true;
                                break;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                    if good {
                        owned.armed = false; // keep it running: it is measured next
                        DiagnosticsLog::i(
                            "smart+",
                            &format!(
                                "Smart lane {}: {} carried traffic after {:.1}s",
                                index + 1,
                                tactic.id,
                                race_started.elapsed().as_secs_f64()
                            ),
                        );
                    } else if !lane_cancel.stopped() {
                        DiagnosticsLog::w(
                            "smart+",
                            &format!("Smart lane {}: {} - {verdict}", index + 1, tactic.id),
                        );
                        memory::failure(&dir, &key, tactic.id, crate::custom::now_millis());
                        // 1.5.0 (same version) Smart brain: why did it fail?
                        let died = !eng.lock().is_alive();
                        let diagnosis = if abandoned.get() {
                            brain::Verdict::UdpBlocked
                        } else {
                            brain::diagnose(
                                ready.signals(),
                                died,
                                attempt.elapsed().as_millis() as u64,
                                brain::rides_udp(tactic),
                                ready.fatal_line().is_some(),
                            )
                        };
                        // An attempt the brain abandoned itself is not new evidence.
                        let learned = if abandoned.get() { board.now() } else { board.learn(diagnosis) };
                        DiagnosticsLog::i(
                            "smart+",
                            &format!(
                                "Smart brain: {} -> {:?} | {}",
                                tactic.id,
                                diagnosis,
                                learned.describe()
                            ),
                        );
                        if diagnosis == brain::Verdict::IdentityDamaged {
                            let mut e = eng.lock();
                            e.stop();
                            let healed = e.heal_damaged_identity();
                            DiagnosticsLog::w(
                                "smart+",
                                &format!(
                                    "Smart brain: the engine's identity was damaged - {healed} damaged file(s) removed; the next attempt provisions a fresh one."
                                ),
                            );
                        }
                    }
                    good
                },
                |index| {
                    if let Some((_, e)) = resources.get(index) {
                        e.lock().stop();
                    }
                },
                |_, rest| brain::adapt(rest, &board.now()),
            );
            let mut ranked: Vec<Tactic> = vec![];
            if !c.stopped() {
                if proven.len() >= 2 {
                    ph.store(PHASE_COMPARING, Ordering::SeqCst);
                    let mut measured = vec![];
                    for p in &proven {
                        if c.stopped() {
                            break;
                        }
                        let port = resources[p.lane].1.lock().probe_bind_port().unwrap_or(0);
                        let q = crate::probe::measure_tunnel_quality(port, plan::MEASURE_MS)
                            .map(quality);
                        match q {
                            Some(q) => DiagnosticsLog::i(
                                "smart+",
                                &format!(
                                    "Smart: {} proved after {:.1}s - rtt={}ms down={}kbps up={}kbps overhead={:.2} score={:.0}",
                                    p.tactic.id,
                                    p.after_ms as f64 / 1000.0,
                                    q.rtt_ms,
                                    q.down_kbps,
                                    q.up_kbps,
                                    p.tactic.overhead(),
                                    plan::score(&q, p.tactic.overhead())
                                ),
                            ),
                            None => DiagnosticsLog::w(
                                "smart+",
                                &format!(
                                    "Smart: {} proved after {:.1}s - quality could not be measured",
                                    p.tactic.id,
                                    p.after_ms as f64 / 1000.0
                                ),
                            ),
                        }
                        measured.push((p.tactic.clone(), q));
                    }
                    ranked = plan::rank(measured);
                    DiagnosticsLog::i(
                        "smart+",
                        &format!(
                            "Smart: ranking {} -> {}",
                            proven.len(),
                            ranked.iter().map(|t| t.id).collect::<Vec<_>>().join(" > ")
                        ),
                    );
                } else if let Some(p) = proven.first() {
                    DiagnosticsLog::i(
                        "smart+",
                        &format!(
                            "Smart: {} proved after {:.1}s - the only working route, no comparison needed",
                            p.tactic.id,
                            p.after_ms as f64 / 1000.0
                        ),
                    );
                    ranked.push(p.tactic.clone());
                }
            }
            // No lane engine may outlive the race: the confirmation is a normal
            // connection on the session's own port.
            for (_, e) in &resources {
                e.lock().stop();
            }
            // Publish only after ALL children have stopped and been joined.
            let _ = tx.send(if c.stopped() { vec![] } else { ranked });
        });
        Self {
            cancel,
            engines,
            phase,
            result,
            join: Some(join),
        }
    }
    pub fn phase(&self) -> u8 {
        self.phase.load(Ordering::SeqCst)
    }
    pub fn poll(&mut self) -> Option<Vec<Tactic>> {
        match self.result.try_recv() {
            Ok(t) => {
                if let Some(h) = self.join.take() {
                    let _ = h.join();
                }
                Some(t)
            }
            Err(mpsc::TryRecvError::Disconnected) => Some(vec![]),
            Err(_) => None,
        }
    }
}
impl Drop for RaceTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        for e in self.engines.lock().iter() {
            e.lock().stop();
        }
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eligibility_and_user_hardening() {
        let mut p = ConnectionProfile::default();
        p.protocol = Protocol::Smart;
        assert!(eligible(&p));
        p.endpoint_mode = EndpointMode::ManualRange;
        assert!(!eligible(&p));
        p.endpoint_mode = EndpointMode::Auto;
        p.backend = TransportBackend::Tor;
        assert!(!eligible(&p));
        let t = plan::tactics(plan::Family::Masque, plan::Context::new(plan::Dpi::Open))[0].clone();
        p.noize = Noize::Aggressive;
        p.fragment = true;
        p.ech = true;
        p.masque_http2 = true;
        let q = apply(&t, &p, false);
        assert_eq!(q.noize, Noize::Aggressive);
        assert!(q.fragment && q.ech && q.masque_http2);
        assert_eq!(q.scan_mode, ScanMode::Turbo);
    }
    #[test]
    fn apply_hardens_but_never_switches_ech_on() {
        let user = ConnectionProfile::default();
        assert!(!user.ech);
        for d in [
            plan::Dpi::Open,
            plan::Dpi::SniFiltering,
            plan::Dpi::UdpThrottled,
            plan::Dpi::Hostile,
        ] {
            for lane in plan::plan(plan::Context::new(d), None, 1) {
                for t in lane.tactics {
                    let p = apply(&t, &user, false);
                    assert!(!p.ech, "{}", t.id);
                    assert!((p.noize as u8) >= (noize_of(t.noize) as u8));
                    assert_eq!(p.fragment, t.fragment);
                    assert_eq!(p.masque_http2, t.h2 && t.family == Family::Masque);
                    assert_eq!(p.quick_reconnect, user.quick_reconnect);
                }
            }
        }
    }
    #[test]
    fn the_last_resort_scans_deep() {
        let t = plan::last_resort(plan::Context::new(plan::Dpi::Open))[0].clone();
        let turbo = ConnectionProfile {
            scan_mode: ScanMode::Turbo,
            ..Default::default()
        };
        assert_eq!(last_resort_profile(&t, &turbo).scan_mode, ScanMode::Balanced);
        let deep = ConnectionProfile {
            scan_mode: ScanMode::Thorough,
            ..Default::default()
        };
        assert_eq!(last_resort_profile(&t, &deep).scan_mode, ScanMode::Thorough);
        assert!(last_resort_profile(&t, &deep).masque_http2);
    }
}
