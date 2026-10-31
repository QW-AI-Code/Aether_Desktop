//! Live latency for the home-screen badge — ported from the mobile edition's
//! `core/PingMonitor.kt` (Aether Mobile 1.2.8-r3 → r7).
//!
//! # Why this module exists (the "ping goes over 1000, sometimes 3000" report)
//!
//! The desktop build measured latency the way the mobile build used to, and it
//! inherited every one of the defects mobile already root-caused:
//!
//! 1. **It opened a brand new connection for every measurement and reported how
//!    long that took.** Through a chained `Aether → Psiphon` session that number
//!    is not latency, it is: the local SOCKS5 handshake, *plus* Psiphon opening a
//!    NEW SSH `direct-tcpip` channel across BOTH hops, *plus* the remote TCP
//!    handshake. The channel open is the expensive term and it queues behind
//!    whatever the tunnel is already carrying — which is exactly how a healthy
//!    ~200 ms path reads as 1637 ms (the screenshot) or 3000 ms.
//!
//! 2. **It generated the load it then displayed.** One dial every 15 s means a
//!    fresh SSH channel through both hops, forever. The field log carries the
//!    bill directly: `channel dial timeout: direct-tcpip` and
//!    `port forward failures for qkhOScJt: 2`. A diagnostic that manufactures
//!    the failure it reports is worse than no diagnostic.
//!
//! 3. **It probed a fresh dial on port 80 and every refusal was scored against
//!    the exit.** The old desktop Psiphon scorer treated refusals as evidence
//!    of filtering and could rotate a working server; scoring was removed
//!    when the engine took ownership of the child.
//!
//! 4. **The first sample after connecting was the self-test's own HTTP fetch**,
//!    timed during the busiest second of the session, and it then never changed
//!    until the next probe. That is the 1637 ms in the screenshot.
//!
//! # What this does instead (mobile r5 + r6 + r7, in one place)
//!
//! * The probe session is dialled **once** and kept warm. A measurement is an
//!   HTTP `HEAD` keep-alive round trip on a connection that already exists: one
//!   packet out, one packet back, zero channel opens. The dial cost is still
//!   recorded, as [`last_setup_ms`], where it belongs — it is a useful number
//!   about the control path, and it is not the ping.
//! * Port **443**, not 53 and not 80: 443 is the one port an exit cannot refuse
//!   and still be an exit. Every target is also registered with
//!   The desktop no longer scores Psiphon servers; that lifecycle belongs
//!   to the engine's child supervisor.
//! * The **first** round trip on a freshly dialled session is not a ping either
//!   (it rides a connection whose own handshake just queued behind everything
//!   the tunnel was carrying), so a re-warm takes a confirming sample and
//!   reports the lower of the two.
//! * A **steady-state outlier** is re-checked against the session's floor before
//!   it is published, and every sample is logged with the floor beside it, so a
//!   screenshot can always be reconciled against the log.
//!
//! The probe deliberately goes through [`crate::engine::exit_socks_port`], which
//! is the port the *finished* pipeline exposes — stage 2 in a chained session.
//! Probing stage 1 would measure the first hop only and say nothing about the
//! path the user's traffic actually takes.

use crate::log::DiagnosticsLog;
use crate::probe;
use parking_lot::Mutex;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const TAG: &str = "ping";

/// Hard ceiling on any single dial or round trip.
const TIMEOUT: Duration = Duration::from_millis(8_000);

/// How far above the session floor a sample has to be before it is treated as
/// suspect rather than reported.
///
/// Both terms are needed. The multiplier alone would re-check every sample on a
/// genuinely fast path (250 ms is a 5x outlier when the floor is 50 ms, and that
/// is just jitter); the absolute term alone would let a 3x jump through on a slow
/// path. A sample has to break both to be doubted.
const OUTLIER_FACTOR: u64 = 3;
const OUTLIER_ABSOLUTE_MS: u64 = 400;

/// A destination a latency measurement may use.
#[derive(Clone, Copy)]
pub struct Target {
    pub host: &'static str,
    pub port: u16,
    /// Wrap the SOCKS5 stream in TLS before speaking HTTP.
    tls: bool,
    /// The name the TLS certificate is verified against (and sent as SNI and
    /// `Host`). Always fully verified — chain **and** host name.
    ///
    /// 1.3.0 security fix: the IP-literal targets used to set
    /// the native-tls "accept invalid host names" switch, because SChannel will not put an IP
    /// literal in SNI. That accepted *any* valid certificate for *any* name, so
    /// whoever sat on the path could answer the probe. The resolvers' own
    /// certificates carry their service names (`one.one.one.one`, `dns.google`,
    /// `dns.quad9.net`), so the TCP dial still goes to the same IP literal (no
    /// DNS lookup, the same anycast path as before) and the handshake verifies
    /// that name in full.
    tls_name: &'static str,
}

/// Probe destinations, in the order they are tried.
///
/// More than one so a single unreachable anycast target cannot make a healthy
/// tunnel look broken — the old single-target probe had no second opinion. The
/// three IP literals are exactly the mobile edition's list; the named target and
/// the plain-HTTP tier are the desktop's fallbacks for a Windows TLS stack that
/// refuses to hand-shake against an address.
pub const TARGETS: [Target; 5] = [
    Target {
        host: "1.1.1.1",
        port: 443,
        tls: true,
        tls_name: "one.one.one.one",
    },
    Target {
        host: "8.8.8.8",
        port: 443,
        tls: true,
        tls_name: "dns.google",
    },
    Target {
        host: "9.9.9.9",
        port: 443,
        tls: true,
        tls_name: "dns.quad9.net",
    },
    Target {
        host: "www.cloudflare.com",
        port: 443,
        tls: true,
        tls_name: "www.cloudflare.com",
    },
    Target {
        host: "1.1.1.1",
        port: 80,
        tls: false,
        tls_name: "",
    },
];

/// The destinations above, for whoever needs to exempt them from health scoring.
pub fn probe_targets() -> impl Iterator<Item = (&'static str, u16)> {
    TARGETS.iter().map(|t| (t.host, t.port))
}

/// Anything that can carry the probe's request/response bytes.
trait Io: Read + Write + Send {}
impl<T: Read + Write + Send> Io for T {}

/// A warm probe session: one tunnelled connection kept alive across
/// measurements, so a measurement is a ROUND TRIP and not a connection setup.
struct Warm {
    io: Box<dyn Io>,
    host: &'static str,
    /// `Host:` header — the verified TLS name, or the address for plain HTTP.
    name: &'static str,
    port: u16,
}

struct Session {
    warm: Option<Warm>,
    /// Best round trip seen on the current warm session: this path's floor.
    floor_ms: Option<u64>,
    /// Generation the warm session was dialled in. See [`reset`].
    generation: u64,
}

/// Bumped whenever the pipeline underneath the warm session changes (exit-port
/// retarget, Psiphon server rotation, disconnect).
///
/// It is an atomic and not a flag inside the mutex on purpose: [`reset`] is
/// called from the controller tick while it holds the controller lock, and it
/// must never be able to block behind an eight-second measurement.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Dial cost of the current warm session, in ms, or -1. Diagnostic only, never
/// the badge.
static SETUP_MS: AtomicI64 = AtomicI64::new(-1);

fn cell() -> &'static Mutex<Session> {
    static CELL: OnceLock<Mutex<Session>> = OnceLock::new();
    CELL.get_or_init(|| {
        Mutex::new(Session {
            warm: None,
            floor_ms: None,
            generation: 0,
        })
    })
}

/// What it cost to establish the current warm probe session, if any.
pub fn last_setup_ms() -> Option<u64> {
    let v = SETUP_MS.load(Ordering::Relaxed);
    if v < 0 {
        None
    } else {
        Some(v as u64)
    }
}

/// Drops the warm session; call whenever the pipeline underneath it changes.
///
/// Cheap and non-blocking: the next [`measure`] notices the generation moved and
/// re-dials. Costs one dial and stops the badge reporting a dead connection's
/// timeout as latency.
pub fn reset() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
    SETUP_MS.store(-1, Ordering::Relaxed);
}

/// Opens a warm session: SOCKS5 (pipeline exit) → TCP → optional TLS → HTTP.
///
/// The dial is the expensive part and it is paid ONCE per session, not once per
/// measurement — which is the entire point of this module.
fn open_warm(target: &Target) -> Option<Warm> {
    let started = Instant::now();
    let plain: TcpStream = probe::socks5_stream(target.host, target.port, TIMEOUT)?;
    let _ = plain.set_nodelay(true);
    plain.set_read_timeout(Some(TIMEOUT)).ok()?;
    plain.set_write_timeout(Some(TIMEOUT)).ok()?;

    let io: Box<dyn Io> = if target.tls {
        // Full verification: no `danger_*` switch anywhere in this module.
        let connector = native_tls::TlsConnector::builder().build().ok()?;
        Box::new(connector.connect(target.tls_name, plain).ok()?)
    } else {
        Box::new(plain)
    };

    SETUP_MS.store(started.elapsed().as_millis() as i64, Ordering::Relaxed);
    Some(Warm {
        io,
        host: target.host,
        name: if target.tls { target.tls_name } else { target.host },
        port: target.port,
    })
}

/// One application round trip on an ALREADY ESTABLISHED session.
///
/// `HEAD / HTTP/1.1` + `Connection: keep-alive`, timed from the last byte written
/// to the first byte read. No dial, no handshake, no channel open: one packet
/// out, one packet back, over a connection that already exists. That is a
/// latency measurement.
///
/// Returns `None` if the session is unusable, so the caller re-warms once.
fn round_trip(w: &mut Warm) -> Option<u64> {
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: aether-ping\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        w.name
    );
    w.io.write_all(request.as_bytes()).ok()?;
    w.io.flush().ok()?;

    let started = Instant::now();
    let mut first = [0u8; 1];
    if w.io.read(&mut first).ok()? == 0 {
        return None;
    }
    let rtt = started.elapsed().as_millis() as u64;

    // Leave the socket positioned at the start of the next response, or the
    // following round trip would time itself against leftover bytes and report a
    // nonsense 0 ms. A HEAD response is a few hundred bytes of headers and
    // carries no body, so "drain to the blank line" is the whole job.
    drain_headers(w, first[0])?;
    Some(rtt)
}

/// Reads up to the `\r\n\r\n` that ends the response header block.
fn drain_headers(w: &mut Warm, first_byte: u8) -> Option<()> {
    const CAP: usize = 8192;
    let mut seen: Vec<u8> = Vec::with_capacity(512);
    seen.push(first_byte);
    let mut chunk = [0u8; 512];
    while seen.len() < CAP {
        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(());
        }
        match w.io.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    None
}

/// Publishes a steady-state round trip, re-checking it if it is an outlier.
///
/// This is the path the badge reads from almost every time. An outlier gets
/// exactly ONE confirming sample and the lower of the two is reported: if the
/// path really has degraded both samples say so and the badge tells the truth;
/// if the probe was only waiting behind a full send buffer, the second sample is
/// clean. Both numbers always go to the log with the floor next to them.
///
/// Returns the value to publish, and whether the session is still usable.
fn publish_fast(w: &mut Warm, floor: &mut Option<u64>, first: u64) -> (Option<u64>, bool) {
    let known_floor = *floor;
    let suspect = match known_floor {
        Some(f) => {
            first > f.saturating_mul(OUTLIER_FACTOR)
                && first.saturating_sub(f) >= OUTLIER_ABSOLUTE_MS
        }
        None => false,
    };

    if !suspect {
        if known_floor.map(|f| first < f).unwrap_or(true) {
            *floor = Some(first);
        }
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Latency {first} ms via {}:{} (warm round trip, session floor {}).",
                w.host,
                w.port,
                known_floor
                    .map(|f| format!("{f} ms"))
                    .unwrap_or_else(|| "n/a".to_string()),
            ),
        );
        return (Some(first), true);
    }

    let f = known_floor.unwrap_or(first);
    let Some(confirm) = round_trip(w) else {
        // Session died mid-check. Report the sample we have and let the next call
        // re-warm; do not silently invent a better number.
        DiagnosticsLog::w(
            TAG,
            &format!(
                "Latency {first} ms via {}:{} was {}x this session's floor of {f} ms, and the \
                 confirming probe could not complete. Reporting {first} ms unverified.",
                w.host,
                w.port,
                first / f.max(1),
            ),
        );
        return (Some(first), false);
    };

    let rtt = first.min(confirm);
    if rtt < f {
        *floor = Some(rtt);
    }
    let queue_ms = first.max(confirm) - rtt;
    DiagnosticsLog::w(
        TAG,
        &format!(
            "Latency spike via {}:{}: first round trip {first} ms, confirming {confirm} ms, \
             session floor {f} ms, reporting {rtt} ms. The gap of {queue_ms} ms is this probe \
             waiting behind data already queued in the tunnel's send buffer, NOT path latency.",
            w.host, w.port,
        ),
    );
    (Some(rtt), true)
}

/// Measures the pipeline's real round-trip latency, in ms.
///
/// Called from the controller's background latency thread only, and it never
/// touches the controller lock, so a slow measurement can never stall the UI.
pub fn measure() -> Option<u64> {
    // Serialises overlapping probes the way the mobile edition's tryLock does.
    let mut s = cell().try_lock()?;

    let generation = GENERATION.load(Ordering::Relaxed);
    if s.generation != generation {
        s.warm = None;
        s.floor_ms = None;
        s.generation = generation;
    }

    // Fast path: a session is already warm, so this is a pure round trip.
    if let Some(mut w) = s.warm.take() {
        if let Some(rtt) = round_trip(&mut w) {
            let mut floor = s.floor_ms;
            let (out, keep) = publish_fast(&mut w, &mut floor, rtt);
            s.floor_ms = floor;
            if keep {
                s.warm = Some(w);
            } else {
                s.floor_ms = None;
            }
            return out;
        }
        // The peer closed a keep-alive session, which is ordinary. Re-warm once
        // below rather than reporting a failure for it.
        s.floor_ms = None;
    }

    let mut last_error: Option<String> = None;
    for target in TARGETS.iter() {
        let Some(mut w) = open_warm(target) else {
            last_error = Some(format!("{}:{} dial failed", target.host, target.port));
            continue;
        };
        // The FIRST round trip on a session that was just dialled is not a ping:
        // it rides a connection whose own handshake queued behind everything the
        // tunnel was carrying. Take a confirming sample and report the lower.
        let Some(first) = round_trip(&mut w) else {
            last_error = Some(format!(
                "{}:{} no answer on an established session",
                target.host, target.port
            ));
            continue;
        };
        let confirm = round_trip(&mut w);
        let rtt = match confirm {
            Some(c) => first.min(c),
            None => first,
        };
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Warm latency session up via {}:{}: setup {} ms, first round trip {first} ms, \
                 confirming round trip {}, reporting {rtt} ms. A large gap between the two is \
                 queue left over from the dial, not latency. Further probes reuse this \
                 connection, so they cost no channel dial.",
                target.host,
                target.port,
                last_setup_ms()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                confirm
                    .map(|c| format!("{c} ms"))
                    .unwrap_or_else(|| "n/a".to_string()),
            ),
        );
        // Seed the floor from the session's own first honest sample rather than
        // leaving it unset for publish_fast.
        s.floor_ms = Some(rtt);
        if confirm.is_some() {
            s.warm = Some(w);
        }
        return Some(rtt);
    }

    DiagnosticsLog::w(
        TAG,
        &format!(
            "Latency probe failed: {}",
            last_error.unwrap_or_else(|| "no target answered".to_string())
        ),
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mobile root cause in one assertion: nothing may probe TCP 53, which a
    /// large share of Psiphon exits refuse outright, and 443 has to lead.
    #[test]
    fn probe_targets_avoid_port_53_and_lead_with_443() {
        assert!(TARGETS.iter().all(|t| t.port != 53));
        assert_eq!(TARGETS[0].port, 443);
        assert!(TARGETS.iter().filter(|t| t.port == 443).count() >= 3);
    }

    /// A second opinion is mandatory: one unreachable anycast target must not be
    /// able to make a healthy tunnel look broken.
    #[test]
    fn there_is_always_more_than_one_target() {
        assert!(TARGETS.len() > 1);
        assert_eq!(probe_targets().count(), TARGETS.len());
    }

    /// 1.3.0: every TLS target verifies a real host name — no IP literal is
    /// ever handed to the verifier, and no target may skip verification.
    #[test]
    fn every_tls_target_verifies_a_host_name() {
        for t in TARGETS.iter().filter(|t| t.tls) {
            assert!(t.tls_name.contains('.'), "{}", t.host);
            assert!(t.tls_name.parse::<std::net::IpAddr>().is_err(), "{}", t.host);
        }
        let src = include_str!("ping.rs");
        let needle = ["danger", "_accept_invalid"].concat();
        assert!(!src.contains(&needle));
    }

    #[test]
    fn reset_moves_the_generation_so_the_next_measure_redials() {
        let before = GENERATION.load(Ordering::Relaxed);
        reset();
        assert_ne!(GENERATION.load(Ordering::Relaxed), before);
        assert_eq!(last_setup_ms(), None);
    }

    /// r7 rule: a steady-state sample far above the floor is re-checked, and a
    /// sample near the floor is published untouched.
    #[test]
    fn outlier_rule_needs_both_terms_to_fire() {
        let suspect = |first: u64, floor: u64| {
            first > floor * OUTLIER_FACTOR && first - floor >= OUTLIER_ABSOLUTE_MS
        };
        // 6442 ms on a 200 ms path: the screenshot. Doubted.
        assert!(suspect(6442, 200));
        // 250 ms on a 50 ms path: a 5x outlier, but only 200 ms of jitter. Kept.
        assert!(!suspect(250, 50));
        // 1500 ms on a 900 ms path: 600 ms worse, but not 3x. Kept.
        assert!(!suspect(1500, 900));
    }
}

/// A governor owns this connection; it never mutates the home-screen ping cell.
#[derive(Default)]
pub struct UplinkProbe { warm:Option<Warm>, tracked:Option<crate::custom::cancel::Tracked> }
impl UplinkProbe {
    pub fn measure(&mut self,port:u16,cancel:&std::sync::Arc<crate::custom::cancel::Cancel>)->Option<u64>{
        if cancel.stopped(){return None;}
        if let Some(w)=self.warm.as_mut(){if let Some(rtt)=round_trip(w){return Some(rtt);}}
        self.warm=None;self.tracked=None;
        for t in TARGETS.iter().filter(|t|t.tls){
            if cancel.stopped(){break;}
            let Some((plain,track))=probe::socks5_stream_cancelled(port,t.host,t.port,TIMEOUT,cancel)else{continue;};
            let _=plain.set_nodelay(true);
            let Some(connector)=native_tls::TlsConnector::builder().build().ok()else{continue;};
            let Ok(tls)=connector.connect(t.tls_name,plain)else{continue;};
            let mut warm=Warm{io:Box::new(tls),host:t.host,name:t.tls_name,port:t.port};
            if let Some(first)=round_trip(&mut warm){let confirm=round_trip(&mut warm);let rtt=confirm.map(|n|n.min(first)).unwrap_or(first);self.warm=Some(warm);self.tracked=Some(track);return Some(rtt);}
        }None
    }
}
