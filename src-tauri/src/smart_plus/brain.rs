//! Smart brain 1.5.0 (same version) - port of Aether Mobile 1.7.0 `DpiBrain.kt`.
//!
//! Nine out of ten users never open a settings page: they press Connect in
//! Smart mode and expect the app to deal with their operator. The race already
//! went light → heavy, but in an order fixed before the first packet. When
//! WireGuard's UDP was silently dropped (Tehran), the MASQUE lane still spent its
//! light budget on MASQUE over HTTP/3 - the same UDP - before HTTP/2; when TLS
//! handshakes were reset, the plain HTTP/2 tactic came before the fragmented one.
//!
//! The brain:
//!  1. **listens** - `readiness::signals_of` tags every engine line (UDP
//!     silence, TLS reset, empty scan, blocked account API, damaged identity, no
//!     ECH key);
//!  2. **diagnoses** ([`diagnose`]) how an attempt failed;
//!  3. **learns** ([`Knowledge`], shared by both lanes through a [`Board`]);
//!  4. **adapts** ([`adapt`]) the tactics still to come - UDP carriers behind TCP
//!     ones once UDP is known to be dropped, TLS fragmentation and a stronger
//!     obfuscation floor on TCP carriers once TLS is interfered with, the
//!     heaviest disguise for WireGuard once its gateways stay silent. Nothing is
//!     ever removed: a verdict can be wrong;
//!  5. **gives up early** ([`should_abandon`]) on a UDP rung that still is not
//!     serving after [`EARLY_ABANDON_MS`] on a UDP-hostile network.
//!
//! Pure: only `plan.rs` types and the signal bits of `readiness.rs`, so it is
//! compiled by `tests/rust-port` too.
use super::plan::{Family, Hardness, Proto, Tactic, HARDENED_MS};
use crate::readiness::{
    S_API_BLOCKED, S_ECH, S_IDENTITY, S_SCAN_EMPTY, S_TCP_BLOCKED, S_TLS_RESET, S_UDP_SILENT,
};
use std::sync::Mutex;

/// An engine that dies sooner than this after spawn did not meet the network.
pub const FAST_DEATH_MS: u64 = 3_000;
/// A UDP tactic on a UDP-hostile network gets this long to start serving.
pub const EARLY_ABANDON_MS: u64 = 7_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The engine's identity file is damaged (the core 2.4.0 `valid UTF-8` death).
    IdentityDamaged,
    /// ECH was requested but no key exists here - not a network verdict.
    EchUnavailable,
    /// The WARP account API is unreachable.
    ApiBlocked,
    /// The engine stopped before it met the network.
    EngineFault,
    /// A UDP carrier got nowhere: UDP is dropped or throttled.
    UdpBlocked,
    /// TLS handshakes are reset or alerted: SNI / ClientHello based DPI.
    TlsInterference,
    /// The scan found nothing on a TCP carrier: gateways are IP-filtered.
    GatewaysFiltered,
    /// Nothing specific; it ran out of time.
    TooSlow,
    Nothing,
}

pub fn diagnose(signals: u32, died: bool, alive_ms: u64, rides_udp: bool, has_fatal: bool) -> Verdict {
    let has = |bit: u32| signals & bit != 0;
    if has(S_IDENTITY) {
        Verdict::IdentityDamaged
    } else if has(S_ECH) {
        Verdict::EchUnavailable
    } else if has(S_API_BLOCKED) {
        Verdict::ApiBlocked
    } else if died && alive_ms < FAST_DEATH_MS && has_fatal {
        Verdict::EngineFault
    } else if has(S_TLS_RESET) && !rides_udp {
        Verdict::TlsInterference
    } else if rides_udp && (has(S_UDP_SILENT) || has(S_SCAN_EMPTY) || !died) {
        Verdict::UdpBlocked
    } else if has(S_SCAN_EMPTY) || has(S_TCP_BLOCKED) {
        Verdict::GatewaysFiltered
    } else if has(S_TLS_RESET) {
        Verdict::TlsInterference
    } else if !died {
        Verdict::TooSlow
    } else {
        Verdict::Nothing
    }
}

/// What is known about this network so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Knowledge {
    pub udp_strikes: u32,
    pub tls_strikes: u32,
    pub filtered_strikes: u32,
    pub api_blocked: bool,
    /// The fingerprint already saw UDP or QUIC struggle on this network.
    pub udp_weak_hint: bool,
}

impl Knowledge {
    pub fn udp_blocked(&self) -> bool {
        self.udp_strikes >= 2 || (self.udp_strikes >= 1 && self.udp_weak_hint)
    }
    pub fn tls_interference(&self) -> bool {
        self.tls_strikes >= 1
    }
    pub fn gateways_filtered(&self) -> bool {
        self.filtered_strikes >= 1
    }
    pub fn learn(mut self, v: Verdict) -> Self {
        match v {
            Verdict::UdpBlocked => self.udp_strikes += 1,
            Verdict::TlsInterference => self.tls_strikes += 1,
            Verdict::GatewaysFiltered => self.filtered_strikes += 1,
            Verdict::ApiBlocked => self.api_blocked = true,
            _ => {}
        }
        self
    }
    pub fn describe(&self) -> String {
        format!(
            "udp={}({}) tls={} gateways={}{}",
            if self.udp_blocked() { "blocked" } else { "ok?" },
            self.udp_strikes,
            if self.tls_interference() { "interfered" } else { "ok?" },
            if self.gateways_filtered() { "filtered" } else { "ok?" },
            if self.api_blocked { " api=blocked" } else { "" }
        )
    }
}

/// What both lanes learned; shared between the lane threads.
#[derive(Debug, Default)]
pub struct Board(Mutex<Knowledge>);

impl Board {
    pub fn new(initial: Knowledge) -> Self {
        Self(Mutex::new(initial))
    }
    pub fn now(&self) -> Knowledge {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn learn(&self, v: Verdict) -> Knowledge {
        let mut k = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *k = k.learn(v);
        *k
    }
}

/// Whether `t`'s outer carrier is UDP (WireGuard, QUIC).
pub fn rides_udp(t: &Tactic) -> bool {
    match t.protocol {
        Proto::Wireguard => true,
        Proto::Gool => t.family == Family::Warp || !t.h2,
        Proto::Masque | Proto::Mim => !t.h2,
    }
}

fn at_least(current: Hardness, floor: Hardness) -> Hardness {
    if current >= floor {
        current
    } else {
        floor
    }
}

/// `t` hardened for what is known; an identical copy when nothing changes.
/// The id is kept, so per-network memory keeps working with catalogue ids.
pub fn boost(t: &Tactic, k: &Knowledge) -> Tactic {
    let mut out = t.clone();
    if !rides_udp(t) {
        if k.tls_interference() || k.gateways_filtered() {
            out.fragment = true;
            out.noize = at_least(out.noize, Hardness::Firewall);
        }
    } else if k.gateways_filtered() || k.udp_blocked() {
        out.noize = at_least(out.noize, Hardness::Gfw);
    }
    if out != *t {
        out.budget_ms = out.budget_ms.max(HARDENED_MS);
        out.overhead_milli = out.overhead_milli.saturating_add(30);
    }
    out
}

/// What makes two tactics the same attempt, whatever their ids.
pub fn signature(t: &Tactic) -> (Family, Proto, Hardness, bool, bool) {
    (t.family, t.protocol, t.noize, t.h2, t.fragment)
}

/// Re-plans the tactics still to come. Never removes one (a verdict can be
/// wrong) - only re-orders and hardens, and drops exact duplicates.
pub fn adapt(remaining: Vec<Tactic>, k: &Knowledge) -> Vec<Tactic> {
    let boosted: Vec<Tactic> = remaining.iter().map(|t| boost(t, k)).collect();
    let ordered: Vec<Tactic> = if k.udp_blocked() {
        let (udp, tcp): (Vec<Tactic>, Vec<Tactic>) = boosted.into_iter().partition(rides_udp);
        tcp.into_iter().chain(udp).collect()
    } else {
        boosted
    };
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for t in ordered {
        let sig = signature(&t);
        if !seen.contains(&sig) {
            seen.push(sig);
            out.push(t);
        }
    }
    out
}

/// Whether a still-silent attempt should be stopped before its budget ends.
pub fn should_abandon(t: &Tactic, k: &Knowledge, elapsed_ms: u64, serving: bool) -> bool {
    !serving && rides_udp(t) && k.udp_blocked() && elapsed_ms >= EARLY_ABANDON_MS
}

/// Starting knowledge from the direct probes, before any attempt.
pub fn initial(udp_ok: bool, quic_reachable: Option<bool>, filtered: bool) -> Knowledge {
    Knowledge {
        udp_weak_hint: !udp_ok || quic_reachable == Some(false),
        tls_strikes: if filtered { 1 } else { 0 },
        ..Knowledge::default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::plan::{tactics, Context, Dpi};
    use super::*;

    fn masque() -> Vec<Tactic> {
        tactics(Family::Masque, Context::new(Dpi::Open))
    }
    fn warp() -> Vec<Tactic> {
        tactics(Family::Warp, Context::new(Dpi::Open))
    }

    #[test]
    fn the_utf8_death_is_a_damaged_identity() {
        let bits = crate::readiness::signals_of(
            "Error: Io(Error { kind: InvalidData, message: \"stream did not contain valid UTF-8\" })",
        );
        assert_eq!(diagnose(bits, true, 400, true, true), Verdict::IdentityDamaged);
    }

    #[test]
    fn silent_udp_and_reset_tls_are_told_apart() {
        assert_eq!(diagnose(0, false, 20_000, true, false), Verdict::UdpBlocked);
        let reset = crate::readiness::signals_of("[h2] tls handshake failure: connection reset by peer");
        assert_eq!(diagnose(reset, false, 20_000, false, false), Verdict::TlsInterference);
    }

    #[test]
    fn two_udp_strikes_block_udp_and_tcp_carriers_lead() {
        let k = Knowledge::default().learn(Verdict::UdpBlocked);
        assert!(!k.udp_blocked());
        let k = k.learn(Verdict::UdpBlocked);
        assert!(k.udp_blocked());
        let lane = masque();
        let adapted = adapt(lane.clone(), &k);
        assert!(!rides_udp(&adapted[0]));
        assert!(adapted.iter().all(|t| t.family == Family::Masque));
        assert!(adapted.iter().any(|t| t.protocol == Proto::Masque && !t.h2));
    }

    #[test]
    fn tls_interference_fragments_every_tcp_carrier() {
        let k = Knowledge { tls_strikes: 1, ..Knowledge::default() };
        for t in adapt(masque(), &k).iter().filter(|t| !rides_udp(t)) {
            assert!(t.fragment, "{}", t.id);
            assert!(t.noize >= Hardness::Firewall, "{}", t.id);
        }
    }

    #[test]
    fn wireguard_gets_the_heaviest_disguise_when_udp_is_dropped() {
        let k = Knowledge { udp_strikes: 2, ..Knowledge::default() };
        for t in adapt(warp(), &k) {
            assert!(t.noize >= Hardness::Gfw, "{}", t.id);
        }
    }

    #[test]
    fn nothing_learned_changes_nothing() {
        assert_eq!(adapt(masque(), &Knowledge::default()), masque());
    }

    #[test]
    fn a_hopeless_udp_rung_is_abandoned_early() {
        let k = Knowledge { udp_strikes: 2, ..Knowledge::default() };
        let lane = masque();
        let h3 = lane.iter().find(|t| t.id == "masque.h3").unwrap();
        let h2 = lane.iter().find(|t| t.id == "masque.h2").unwrap();
        assert!(!should_abandon(h3, &k, 1_000, false));
        assert!(should_abandon(h3, &k, EARLY_ABANDON_MS, false));
        assert!(!should_abandon(h3, &k, EARLY_ABANDON_MS, true));
        assert!(!should_abandon(h2, &k, 60_000, false));
    }
}
