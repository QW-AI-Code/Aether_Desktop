//! 1.5.0 - the engine readiness gate (port of Aether Mobile 1.7.0).
//!
//! # The bug this fixes
//!
//! Core 2.4.0 binds its local SOCKS5 port the moment it starts (`Listeners::bind`
//! in `lib.rs`) but only *serves* it once a tunnel has been validated - that is
//! when it prints `[+] socks5 server listening on 127.0.0.1:<port>`. The kernel
//! completes the TCP handshake on a bound listener by itself, so
//! `probe::socks_ready` (a bare TCP connect) said "up" about 0.3 s after launch.
//! The self-test then gave the engine one 4-second SOCKS5 handshake. Verifying
//! a cached MASQUE gateway alone takes 2-3.5 s on Iranian links and a fresh scan
//! far longer, so the app killed engines that were still working: in the Tehran
//! logs every attempt died exactly 4.0 s after its port opened.
//!
//! Now an attempt waits - for its whole budget - until the engine itself says it
//! serves and a real SOCKS5 greeting succeeds, and stops the instant the engine
//! exits (with the engine's own `Error:` line as the reason).
use crate::log::DiagnosticsLog;
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

/// The line core 2.4.0 prints from `socks::serve` once the tunnel is validated.
pub const SERVING_MARK: &str = "socks5 server listening on";
const FATAL_MAX_CHARS: usize = 400;
/// Greeting cadence while the engine says it serves / while it is silent.
const SERVING_RETRY: Duration = Duration::from_millis(300);
const BLIND_RETRY: Duration = Duration::from_millis(2_000);
const SERVING_GREETING: Duration = Duration::from_millis(2_000);
const BLIND_GREETING: Duration = Duration::from_millis(1_000);

// >>> AETHER-APP-PATCH smart-brain-signals (1.5.0, same version)
// What an engine's own output says about the network. Read by the Smart brain
// (`smart_plus/brain.rs`) to decide the next tactic instead of walking a fixed
// list - the desktop twin of mobile 1.7.0 `DpiBrain.signalsOf`.
pub const S_UDP_SILENT: u32 = 1;
pub const S_TLS_RESET: u32 = 1 << 1;
pub const S_SCAN_EMPTY: u32 = 1 << 2;
pub const S_API_BLOCKED: u32 = 1 << 3;
pub const S_IDENTITY: u32 = 1 << 4;
pub const S_ECH: u32 = 1 << 5;
pub const S_TCP_BLOCKED: u32 = 1 << 6;

/// Symptom bits found in one engine output line (0 = nothing of interest).
pub fn signals_of(line: &str) -> u32 {
    let l = line.to_ascii_lowercase();
    let has = |needle: &str| l.contains(needle);
    let mut bits = 0;
    // "provisioning a fresh identity" is the engine RECOVERING from a damaged
    // identity (core overlay `identity-not-utf8`), not a symptom.
    let recovered = has("provisioning a fresh identity");
    if !recovered
        && (has("valid utf-8")
            || has("config parse")
            || has("damaged file was moved")
            || has("fresh identity can be provisioned"))
    {
        bits |= S_IDENTITY;
    }
    if has("ech is on but") || has("no ech key") {
        bits |= S_ECH;
    }
    if has("could not reach the account api")
        || ((has("register") || has("enrol") || has("provision")) && (has("failed") || has("error")))
        || (has("api.cloudflareclient.com") && (has("timed out") || has("error") || has("refused")))
    {
        bits |= S_API_BLOCKED;
    }
    if has("scan deadline reached with no")
        || (has("no usable") && has("found"))
        || has("found no data-plane endpoint")
    {
        bits |= S_SCAN_EMPTY;
    }
    if has("connection reset")
        || has("reset by peer")
        || has("broken pipe")
        || has("unexpected eof")
        || (has("tls") && (has("alert") || has("handshake failure") || has("handshake eof")))
        || (has("handshake") && has("reset"))
    {
        bits |= S_TLS_RESET;
    }
    if (has("handshake") && (has("timed out") || has("timeout")))
        || has("idle timeout")
        || (has("no response") && (has("udp") || has("quic") || has("wireguard") || has("endpoint")))
    {
        bits |= S_UDP_SILENT;
    }
    if has("network is unreachable")
        || has("connection refused")
        || (has("tcp") && has("connect") && (has("timed out") || has("timeout")))
    {
        bits |= S_TCP_BLOCKED;
    }
    bits
}
// <<< AETHER-APP-PATCH smart-brain-signals

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
        .max(1)
}

/// Per-process readiness, fed by that process's own stdout/stderr drain.
/// A fresh one is created for every engine start, so a late line from an
/// older process can never mark a newer one as ready.
#[derive(Debug, Default)]
pub struct Readiness {
    /// Wall-clock ms at which the serving line appeared; 0 = not yet.
    serving_at_ms: AtomicU64,
    fatal_line: Mutex<Option<String>>,
    /// AETHER-APP-PATCH smart-brain-signals: OR of [`signals_of`] over every line.
    signals: AtomicU32,
}

impl Readiness {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn reset(&self) {
        self.serving_at_ms.store(0, Ordering::SeqCst);
        *self.fatal_line.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.signals.store(0, Ordering::SeqCst);
    }
    /// Called for **every** engine output line.
    pub fn ingest(&self, line: &str) {
        if line.contains(SERVING_MARK) {
            let _ = self.serving_at_ms.compare_exchange(
                0,
                now_ms(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        let bits = signals_of(line);
        if bits != 0 {
            self.signals.fetch_or(bits, Ordering::SeqCst);
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("Error:") {
            let short: String = trimmed.trim_end().chars().take(FATAL_MAX_CHARS).collect();
            *self.fatal_line.lock().unwrap_or_else(|e| e.into_inner()) = Some(short);
        }
    }
    /// AETHER-APP-PATCH smart-brain-signals: every symptom this engine reported.
    pub fn signals(&self) -> u32 {
        self.signals.load(Ordering::SeqCst)
    }
    pub fn serving(&self) -> bool {
        self.serving_at_ms.load(Ordering::SeqCst) != 0
    }
    pub fn serving_at_ms(&self) -> u64 {
        self.serving_at_ms.load(Ordering::SeqCst)
    }
    pub fn fatal_line(&self) -> Option<String> {
        self.fatal_line
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ready,
    Died,
    Timeout,
}

/// Blocking gate, for worker threads (Smart race lanes).
///
/// `greet(port, timeout)` must perform a real SOCKS5 greeting; production passes
/// [`crate::probe::socks_greeting_within`].
pub fn await_ready(
    ready: &Readiness,
    port: u16,
    budget_ms: u64,
    label: &str,
    alive: &mut dyn FnMut() -> bool,
    abort: &dyn Fn() -> bool,
    greet: &dyn Fn(u16, Duration) -> bool,
) -> Outcome {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(budget_ms.max(1_000));
    let mut last_try: Option<Instant> = None;
    while Instant::now() < deadline {
        if !alive() {
            let why = ready
                .fatal_line()
                .unwrap_or_else(|| "no error line".to_string());
            DiagnosticsLog::w(
                "ready",
                &format!("{label}: the engine exited before it served SOCKS5 ({why})."),
            );
            return Outcome::Died;
        }
        if abort() {
            return Outcome::Timeout;
        }
        let serving = ready.serving();
        let gap = if serving { SERVING_RETRY } else { BLIND_RETRY };
        if last_try.map(|t| t.elapsed() >= gap).unwrap_or(true) {
            last_try = Some(Instant::now());
            let timeout = if serving {
                SERVING_GREETING
            } else {
                BLIND_GREETING
            };
            if greet(port, timeout) {
                DiagnosticsLog::i(
                    "ready",
                    &format!(
                        "{label}: engine serving after {} ms.",
                        started.elapsed().as_millis()
                    ),
                );
                return Outcome::Ready;
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    DiagnosticsLog::w(
        "ready",
        &format!(
            "{label}: the engine did not start serving within {}s.",
            budget_ms.max(1_000) / 1_000
        ),
    );
    Outcome::Timeout
}

/// Non-blocking gate, for the 200 ms tick of `state.rs`: the greeting runs on a
/// short-lived thread so the tick (and with it the UI) never waits on it.
pub struct Gate {
    port: u16,
    started: Instant,
    budget: Duration,
    next_try: Instant,
    probe: Option<Arc<Mutex<Option<bool>>>>,
}

impl Gate {
    pub fn new(port: u16, budget_ms: u64) -> Self {
        let now = Instant::now();
        Self {
            port,
            started: now,
            budget: Duration::from_millis(budget_ms.max(1_000)),
            next_try: now,
            probe: None,
        }
    }
    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
    pub fn budget_ms(&self) -> u64 {
        self.budget.as_millis() as u64
    }
    pub fn poll(&mut self, ready: &Readiness, alive: bool) -> Option<Outcome> {
        if !alive {
            return Some(Outcome::Died);
        }
        if let Some(slot) = self.probe.as_ref() {
            match *slot.lock().unwrap_or_else(|e| e.into_inner()) {
                Some(true) => return Some(Outcome::Ready),
                Some(false) => {}
                None => return None, // greeting still in flight
            }
            self.probe = None;
        }
        if self.started.elapsed() >= self.budget {
            return Some(Outcome::Timeout);
        }
        let now = Instant::now();
        if now >= self.next_try {
            let serving = ready.serving();
            self.next_try = now + if serving { SERVING_RETRY } else { BLIND_RETRY };
            let timeout = if serving {
                SERVING_GREETING
            } else {
                BLIND_GREETING
            };
            let slot = Arc::new(Mutex::new(None));
            self.probe = Some(slot.clone());
            let port = self.port;
            let spawned = std::thread::Builder::new()
                .name("aether-ready".into())
                .spawn(move || {
                    let ok = crate::probe::socks_greeting_within(port, timeout);
                    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(ok);
                });
            if spawned.is_err() {
                self.probe = None;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn the_serving_line_and_the_fatal_line_are_recognised() {
        let r = Readiness::default();
        r.ingest("[2026-11-01T10:00:00Z INFO  aether::scan] probing 162.159.198.2:443");
        assert!(!r.serving());
        r.ingest("[2026-11-01T10:00:03Z INFO  aether::socks] [+] socks5 server listening on 127.0.0.1:1819");
        assert!(r.serving());
        let at = r.serving_at_ms();
        r.ingest("[+] socks5 server listening on 127.0.0.1:1819");
        assert_eq!(r.serving_at_ms(), at, "first sighting wins");
        r.ingest("Error: Ech(\"ECH is on but there is no ECH key to offer\")");
        assert!(r.fatal_line().unwrap().starts_with("Error: Ech("));
        r.ingest(&format!("Error: {}", "x".repeat(2_000)));
        assert_eq!(r.fatal_line().unwrap().chars().count(), FATAL_MAX_CHARS);
        r.reset();
        assert!(!r.serving() && r.fatal_line().is_none());
    }

    #[test]
    fn the_engine_output_carries_dpi_signals() {
        let r = Readiness::default();
        r.ingest("[*] performance profile: Medium (cpus=4 mem=2815MB)");
        assert_eq!(r.signals(), 0);
        r.ingest("Error: Io(Error { kind: InvalidData, message: \"stream did not contain valid UTF-8\" })");
        assert!(r.signals() & S_IDENTITY != 0);
        r.ingest("[h2] tls handshake failure: connection reset by peer");
        assert!(r.signals() & S_TLS_RESET != 0);
        r.ingest("[-] scan deadline reached with no gateway");
        assert!(r.signals() & S_SCAN_EMPTY != 0);
        r.reset();
        assert_eq!(r.signals(), 0);
        r.ingest("[-] identity file aether.toml is not valid UTF-8; moved it to aether.toml.corrupt and provisioning a fresh identity");
        assert_eq!(r.signals() & S_IDENTITY, 0, "a recovery is not a symptom");
    }

    #[test]
    fn a_dead_engine_ends_the_wait_at_once() {
        let r = Readiness::default();
        let t = Instant::now();
        let out = await_ready(&r, 1, 60_000, "t", &mut || false, &|| false, &|_, _| false);
        assert_eq!(out, Outcome::Died);
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_silent_engine_is_probed_blind_and_a_serving_one_quickly() {
        let r = Readiness::default();
        let tries = Cell::new(0);
        let out = await_ready(
            &r,
            1,
            1_000,
            "t",
            &mut || true,
            &|| false,
            &|_, _| {
                tries.set(tries.get() + 1);
                false
            },
        );
        assert_eq!(out, Outcome::Timeout);
        assert_eq!(tries.get(), 1, "blind greetings are 2 s apart");
        r.ingest("[+] socks5 server listening on 127.0.0.1:1819");
        let n = Cell::new(0);
        let out = await_ready(
            &r,
            1,
            5_000,
            "t",
            &mut || true,
            &|| false,
            &|_, _| {
                n.set(n.get() + 1);
                n.get() >= 2
            },
        );
        assert_eq!(out, Outcome::Ready);
    }

    #[test]
    fn the_tick_gate_reports_death_and_timeout() {
        let r = Readiness::default();
        let mut g = Gate::new(1, 1_000);
        assert_eq!(g.poll(&r, false), Some(Outcome::Died));
        let mut g = Gate::new(1, 0);
        g.started -= Duration::from_secs(2);
        assert_eq!(g.poll(&r, true), Some(Outcome::Timeout));
    }
}
