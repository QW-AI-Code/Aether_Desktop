//! SmartPlus mobile 1.6.0: independent identity families race; serial tactics per family.
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
use plan::{Hardness, Proto, Step, Tactic};
use std::{
    collections::VecDeque,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
pub fn eligible(p: &ConnectionProfile) -> bool {
    p.protocol == Protocol::Smart
        && p.endpoint_mode == EndpointMode::Auto
        && p.backend == TransportBackend::Aether
        && !(p.uses_zero_trust() && p.access_mode == AccessMode::Email)
        && p.upstream_proxy().is_none()
}
pub fn apply(t: &Tactic, user: &ConnectionProfile, confirm: bool) -> ConnectionProfile {
    let mut p = user.clone();
    p.protocol = match t.protocol {
        Proto::Wireguard => Protocol::Wireguard,
        Proto::Gool => Protocol::Gool,
        Proto::Masque => Protocol::Masque,
        Proto::Mim => Protocol::Mim,
    };
    let floor = match t.noize {
        Hardness::Off => Noize::Off,
        Hardness::Light => Noize::Light,
        Hardness::Firewall => Noize::Firewall,
        Hardness::Balanced => Noize::Balanced,
        Hardness::Gfw => Noize::Gfw,
        Hardness::Aggressive => Noize::Aggressive,
    };
    if (p.noize as u8) < floor as u8 {
        p.noize = floor;
    }
    p.masque_http2 |= t.h2;
    p.fragment |= t.fragment;
    p.ech |= t.ech;
    if !confirm {
        p.scan_mode = ScanMode::Turbo;
    }
    p
}
pub struct Session {
    pub fingerprint: NetFingerprint,
    pub key: String,
    pub user: ConnectionProfile,
    pub steps: VecDeque<Step>,
    pub current: Option<Tactic>,
    pub confirmed_probe: bool,
    pub race: Option<RaceTask>,
}
impl Session {
    pub fn new(user: &ConnectionProfile, fp: NetFingerprint, dir: &Path) -> Self {
        let n = network::current();
        let m = memory::recall(dir, &n.key);
        let dpi = match fp.dpi_class() {
            crate::smart_auto::DpiClass::Open => plan::Dpi::Open,
            crate::smart_auto::DpiClass::SniFiltering => plan::Dpi::SniFiltering,
            crate::smart_auto::DpiClass::UdpThrottled => plan::Dpi::UdpThrottled,
            crate::smart_auto::DpiClass::Hostile => plan::Dpi::Hostile,
        };
        Self {
            fingerprint: fp,
            key: n.key,
            user: user.clone(),
            steps: plan::build(dpi, n.mobile, m.as_ref(), crate::custom::now_millis()).into(),
            current: None,
            confirmed_probe: false,
            race: None,
        }
    }
    pub fn candidate(&mut self, t: Tactic, confirm: bool) -> Candidate {
        let profile = apply(&t, &self.user, confirm);
        let timeout_ms = if confirm {
            self.user.connect_timeout_ms()
        } else {
            t.budget_ms
        };
        self.current = Some(t.clone());
        self.confirmed_probe = confirm;
        Candidate {
            profile,
            timeout_ms,
            label: format!(
                "SmartPlus {}{}",
                t.id,
                if confirm {
                    " (confirm)"
                } else {
                    " (remembered)"
                }
            ),
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
struct OwnedProbe(Engine);
impl Drop for OwnedProbe {
    fn drop(&mut self) {
        self.0.lock().stop();
    }
}
pub struct RaceTask {
    cancel: Arc<crate::custom::cancel::Cancel>,
    engines: Arc<Mutex<Vec<Engine>>>,
    result: mpsc::Receiver<Option<Tactic>>,
    join: Option<JoinHandle<()>>,
}
impl RaceTask {
    pub fn spawn(
        user: ConnectionProfile,
        lanes: Vec<plan::Lane>,
        engine: &AetherProcess,
        dir: PathBuf,
        key: String,
    ) -> Self {
        let cancel = crate::custom::cancel::Cancel::new();
        let engines = Arc::new(Mutex::new(Vec::new()));
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
        let join = thread::spawn(move || {
            let mut running = Vec::new();
            let mut resources = Vec::new();
            for (lane, listener, eng) in leased {
                es.lock().push(eng.clone());
                running.push(lane);
                resources.push((Mutex::new(Some(listener)), eng));
            }
            let winner = scheduler::run(
                running,
                c.clone(),
                Duration::from_millis(plan::RACE_CEILING_MS),
                |index, tactic, c| {
                    let (lease, eng) = &resources[index];
                    let port = eng.lock().probe_bind_port().unwrap();
                    lease.lock().take();
                    let _owned = OwnedProbe(eng.clone());
                    DiagnosticsLog::i(
                        "smart+",
                        &format!(
                            "lane {:?} tactic {} on local :{}",
                            tactic.family, tactic.id, port
                        ),
                    );
                    let attempt = Instant::now();
                    let profile = apply(tactic, &user, false);
                    {
                        let mut e = eng.lock();
                        if c.stopped() {
                            return false;
                        }
                        if e.start(&profile, Some(tactic.budget_ms)).is_err() {
                            memory::failure(&dir, &key, tactic.id, crate::custom::now_millis());
                            return false;
                        }
                    }
                    let mut good = false;
                    while attempt.elapsed() < Duration::from_millis(tactic.budget_ms)
                        && !c.stopped()
                    {
                        if !eng.lock().is_alive() {
                            break;
                        }
                        if eng.lock().owns_probe_listener(port)
                            && crate::custom::realdelay::request_through_cancel(
                                port,
                                "",
                                "",
                                "www.gstatic.com",
                                Some(c),
                            )
                            .is_ok()
                        {
                            good = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    if !good && !c.stopped() {
                        memory::failure(&dir, &key, tactic.id, crate::custom::now_millis());
                    }
                    good
                },
                || {
                    for e in es.lock().iter() {
                        e.lock().stop();
                    }
                },
            );
            // Publish only after ALL children have stopped and been joined.
            let _ = tx.send(winner);
        });
        Self {
            cancel,
            engines,
            result,
            join: Some(join),
        }
    }
    pub fn poll(&mut self) -> Option<Option<Tactic>> {
        match self.result.try_recv() {
            Ok(t) => {
                if let Some(h) = self.join.take() {
                    let _ = h.join();
                }
                Some(t)
            }
            Err(mpsc::TryRecvError::Disconnected) => Some(None),
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
        let t = plan::tactics(plan::Family::Masque, plan::Dpi::Open, false)[0].clone();
        p.noize = Noize::Aggressive;
        p.fragment = true;
        p.ech = true;
        p.masque_http2 = true;
        let q = apply(&t, &p, false);
        assert_eq!(q.noize, Noize::Aggressive);
        assert!(q.fragment && q.ech && q.masque_http2);
        assert_eq!(q.scan_mode, ScanMode::Turbo);
    }
}
