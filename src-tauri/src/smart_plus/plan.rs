//! Pure, wire-stable SmartPlusPlan - ported from Aether Mobile 1.7.0
//! (`SmartPlusPlan.kt`). No Android or Windows dependencies, so the very same
//! file is compiled by `tests/rust-port` on a Linux host.
//!
//! # What changed against 1.4.0 (mobile 1.6.0)
//!
//! * **Fair race.** Both families start at `0 ms` with the same per-weight
//!   budgets (light 20 s, hardened 25 s, two-hop 40 s). 1.4.0 started WARP
//!   first, MASQUE 7 s later, and only after a serial 45 s remembered slot.
//! * **Light to heavy.** Every lane walks from its cleanest tactic to its
//!   heaviest: bare carriers, then obfuscation / TLS fragmentation, then the
//!   two-hop protocols.
//! * **Gool belongs to MASQUE.** Core 2.4.0's modern Gool is WireGuard *inside*
//!   MASQUE and shares `aether-masque.toml` and the MASQUE gateway cache; racing
//!   it in the WARP lane next to a MASQUE lane made two engines fight over one
//!   identity. Only classic Gool (WARP-in-WARP) stays in the WARP lane.
//! * **No tactic ever switches ECH on.** Without a fetchable ECH key the core
//!   refuses to start (`Ech("ECH is on but there is no ECH key to offer")`) -
//!   that killed every anti-DPI rung on Iranian links within 0.4 s.
//! * **Best route, not first route.** [`score`] / [`rank`] order every proven
//!   route by measured latency, download, upload and a per-protocol overhead.
use super::memory::Entry;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dpi {
    Open,
    SniFiltering,
    UdpThrottled,
    Hostile,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Warp,
    Masque,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Wireguard,
    Gool,
    Masque,
    Mim,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hardness {
    Off,
    Light,
    Firewall,
    Balanced,
    Gfw,
    Aggressive,
}
/// One way of connecting. There is deliberately **no ECH field**: ECH is only
/// ever the user's own choice (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tactic {
    pub id: &'static str,
    pub family: Family,
    pub protocol: Proto,
    pub noize: Hardness,
    pub h2: bool,
    pub fragment: bool,
    pub budget_ms: u64,
    /// Protocol overhead factor in thousandths (1000 = 1.00). Kept integral so
    /// `Tactic` stays `Eq`.
    pub overhead_milli: u32,
}
impl Tactic {
    pub fn overhead(&self) -> f64 {
        self.overhead_milli as f64 / 1000.0
    }
    /// Two-hop tactics (Gool, MASQUE x2) are the heaviest of a lane.
    pub fn two_hop(&self) -> bool {
        matches!(self.protocol, Proto::Gool | Proto::Mim)
    }
}
#[derive(Debug, Clone)]
pub struct Lane {
    pub tactics: Vec<Tactic>,
    pub start_after_ms: u64,
}
/// The network as the planner sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub dpi: Dpi,
    /// Cellular link. Windows has no reliable signal, so it is normally `false`.
    pub mobile: bool,
    /// Did a QUIC Version-Negotiation probe to the MASQUE gateways come back?
    /// `None` = not measured.
    pub quic: Option<bool>,
    /// The user picked classic Gool (WARP-in-WARP) instead of core 2.4.0's
    /// modern WireGuard-inside-MASQUE.
    pub gool_classic: bool,
    /// Known before connecting that the direct path is an Iranian one.
    pub prefer_tcp: bool,
}
impl Context {
    pub fn new(dpi: Dpi) -> Self {
        Self {
            dpi,
            mobile: false,
            quic: None,
            gool_classic: false,
            prefer_tcp: false,
        }
    }
}
/// Measured quality of one proven route, taken through that route itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Quality {
    pub rtt_ms: u64,
    pub down_kbps: u64,
    pub up_kbps: u64,
}
pub const LIGHT_MS: u64 = 20_000;
pub const HARDENED_MS: u64 = 25_000;
pub const TWO_HOP_MS: u64 = 40_000;
/// Kept for compatibility with older callers: the light budget.
pub const LANE_MS: u64 = LIGHT_MS;
/// Both lanes start at the same instant (1.4.0: 7 000 ms).
pub const SECOND_LANE_AFTER_MS: u64 = 0;
/// After the first proof, how long the other lane may still prove one.
pub const QUALITY_WINDOW_MS: u64 = 2_500; // 1.5.0 (same version): = mobile 1.7.0
/// Budget for measuring one proven route.
pub const MEASURE_MS: u64 = 4_500; // 1.5.0 (same version): = mobile 1.7.0
pub const RACE_CEILING_MS: u64 = 150_000;
pub const KNOWN_IDS: [&str; 8] = [
    "wg",
    "wg.noize",
    "wg.heavy",
    "gool",
    "masque.h3",
    "masque.h2",
    "masque.h2.frag",
    "mim",
];
pub fn known_id(id: &str) -> bool {
    KNOWN_IDS.contains(&id)
}
/// Does MASQUE over HTTP/2 (TCP) lead the MASQUE lane, and the MASQUE lane the race?
pub fn h2_first(dpi: Dpi, mobile: bool, quic_reachable: Option<bool>, prefer_tcp: bool) -> bool {
    prefer_tcp
        || mobile
        || dpi == Dpi::UdpThrottled
        || dpi == Dpi::Hostile
        || quic_reachable == Some(false)
}
fn t(
    id: &'static str,
    family: Family,
    protocol: Proto,
    noize: Hardness,
    budget_ms: u64,
    overhead_milli: u32,
) -> Tactic {
    Tactic {
        id,
        family,
        protocol,
        noize,
        h2: false,
        fragment: false,
        budget_ms,
        overhead_milli,
    }
}
/// The catalogue of one family, lightest first.
pub fn tactics(family: Family, ctx: Context) -> Vec<Tactic> {
    use Hardness::*;
    let dpi = ctx.dpi;
    match family {
        Family::Warp => {
            let bare = t("wg", Family::Warp, Proto::Wireguard, Off, LIGHT_MS, 1000);
            let noize = match dpi {
                Dpi::Open => Light,
                Dpi::SniFiltering => Balanced,
                Dpi::UdpThrottled => Gfw,
                Dpi::Hostile => Aggressive,
            };
            let hard = t("wg.noize", Family::Warp, Proto::Wireguard, noize, HARDENED_MS, 1030);
            let heavy = t(
                "wg.heavy",
                Family::Warp,
                Proto::Wireguard,
                if noize == Aggressive { Gfw } else { Aggressive },
                HARDENED_MS,
                1060,
            );
            let mut out = if matches!(dpi, Dpi::Open | Dpi::SniFiltering) {
                vec![bare, hard, heavy]
            } else {
                vec![hard, heavy, bare]
            };
            if ctx.gool_classic {
                out.push(t(
                    "gool",
                    Family::Warp,
                    Proto::Gool,
                    if dpi == Dpi::Open { Light } else { Aggressive },
                    TWO_HOP_MS,
                    1250,
                ));
            }
            out
        }
        Family::Masque => {
            let h2_lead = h2_first(dpi, ctx.mobile, ctx.quic, ctx.prefer_tcp);
            let floor = match dpi {
                Dpi::Open => Off,
                Dpi::SniFiltering => Firewall,
                Dpi::UdpThrottled => Light,
                Dpi::Hostile => Gfw,
            };
            let h3 = t("masque.h3", Family::Masque, Proto::Masque, floor, LIGHT_MS, 1050);
            let mut h2 = t("masque.h2", Family::Masque, Proto::Masque, floor, LIGHT_MS, 1100);
            h2.h2 = true;
            let mut frag = t(
                "masque.h2.frag",
                Family::Masque,
                Proto::Masque,
                floor.max(Firewall),
                HARDENED_MS,
                1150,
            );
            frag.h2 = true;
            frag.fragment = true;
            let mut out = if matches!(dpi, Dpi::SniFiltering | Dpi::Hostile) {
                vec![h2, frag, h3]
            } else if h2_lead {
                vec![h2, h3, frag]
            } else {
                vec![h3, h2, frag]
            };
            if !ctx.gool_classic {
                let mut gool = t(
                    "gool",
                    Family::Masque,
                    Proto::Gool,
                    if dpi == Dpi::Open { Light } else { Aggressive },
                    TWO_HOP_MS,
                    1250,
                );
                gool.h2 = h2_lead;
                out.push(gool);
            }
            let mut mim = t(
                "mim",
                Family::Masque,
                Proto::Mim,
                if dpi == Dpi::Open { Light } else { Firewall },
                TWO_HOP_MS,
                1350,
            );
            mim.h2 = h2_lead;
            out.push(mim);
            out
        }
    }
}
fn same(a: &Tactic, b: &Tactic) -> bool {
    a.id == b.id && a.family == b.family
}
/// [remembered] + rest + failed. Failed tactics move to the end; they are never dropped.
fn order_by_evidence(
    list: Vec<Tactic>,
    remembered: Option<&Tactic>,
    memory: Option<&Entry>,
    now: i64,
) -> Vec<Tactic> {
    let failed = |t: &Tactic| memory.map(|m| m.failed(t.id, now)).unwrap_or(false);
    let mut first = vec![];
    let mut rest = vec![];
    let mut last = vec![];
    for t in list {
        if failed(&t) {
            last.push(t);
        } else if remembered.map(|r| same(r, &t)).unwrap_or(false) {
            first.push(t);
        } else {
            rest.push(t);
        }
    }
    first.extend(rest);
    first.extend(last);
    first
}
/// The race: two lanes, one per family, both starting at `0 ms`.
pub fn plan(ctx: Context, memory: Option<&Entry>, now: i64) -> Vec<Lane> {
    let warp = tactics(Family::Warp, ctx);
    let masque = tactics(Family::Masque, ctx);
    let remembered = memory
        .filter(|m| m.proven(now))
        .and_then(|m| {
            warp.iter()
                .chain(masque.iter())
                .find(|t| Some(t.id) == m.tactic_id.as_deref())
        })
        .cloned();
    let remembered_ok = remembered
        .as_ref()
        .filter(|r| !memory.map(|m| m.failed(r.id, now)).unwrap_or(false));
    let masque_leads = match remembered_ok {
        Some(r) => r.family == Family::Masque,
        None => h2_first(ctx.dpi, ctx.mobile, ctx.quic, ctx.prefer_tcp),
    };
    let warp = order_by_evidence(warp, remembered.as_ref(), memory, now);
    let masque = order_by_evidence(masque, remembered.as_ref(), memory, now);
    let (a, b) = if masque_leads { (masque, warp) } else { (warp, masque) };
    vec![
        Lane {
            tactics: a,
            start_after_ms: 0,
        },
        Lane {
            tactics: b,
            start_after_ms: SECOND_LANE_AFTER_MS,
        },
    ]
}
/// Serial ladder for profiles that cannot race (chains, a fixed endpoint, Zero
/// Trust e-mail sign-in): the two lanes interleaved, every tactic once.
pub fn ladder(ctx: Context, memory: Option<&Entry>, now: i64) -> Vec<Tactic> {
    let lanes = plan(ctx, memory, now);
    let longest = lanes.iter().map(|l| l.tactics.len()).max().unwrap_or(0);
    let mut out: Vec<Tactic> = vec![];
    for i in 0..longest {
        for lane in &lanes {
            if let Some(t) = lane.tactics.get(i) {
                if !out.iter().any(|o| same(o, t)) {
                    out.push(t.clone());
                }
            }
        }
    }
    out
}
/// The two cleanest carriers, tried with a deep full-range scan when nothing
/// proved itself in the race.
pub fn last_resort(ctx: Context) -> Vec<Tactic> {
    let masque = tactics(Family::Masque, ctx);
    let warp = tactics(Family::Warp, ctx);
    masque
        .into_iter()
        .filter(|t| t.id == "masque.h2")
        .chain(warp.into_iter().filter(|t| t.id == "wg"))
        .collect()
}
/// Lower is better: `(4·rtt + 0.5·downMs + 0.5·upMs) × max(overhead, 1)`.
pub fn score(q: &Quality, overhead: f64) -> f64 {
    let rtt = q.rtt_ms.max(1) as f64;
    let down_ms = if q.down_kbps > 0 {
        8_000_000.0 / q.down_kbps as f64
    } else {
        4_000.0
    };
    let up_ms = if q.up_kbps > 0 {
        2_000_000.0 / q.up_kbps as f64
    } else {
        2_000.0
    };
    (4.0 * rtt + 0.5 * down_ms + 0.5 * up_ms) * overhead.max(1.0)
}
/// Measured routes by ascending score, then unmeasured ones in proof order.
pub fn rank(list: Vec<(Tactic, Option<Quality>)>) -> Vec<Tactic> {
    let mut measured: Vec<(f64, Tactic)> = vec![];
    let mut unmeasured: Vec<Tactic> = vec![];
    for (t, q) in list {
        match q {
            Some(q) => measured.push((score(&q, t.overhead()), t)),
            None => unmeasured.push(t),
        }
    }
    measured.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    measured
        .into_iter()
        .map(|(_, t)| t)
        .chain(unmeasured)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    const ALL: [Dpi; 4] = [
        Dpi::Open,
        Dpi::SniFiltering,
        Dpi::UdpThrottled,
        Dpi::Hostile,
    ];
    fn ctx(dpi: Dpi, classic: bool) -> Context {
        Context {
            gool_classic: classic,
            ..Context::new(dpi)
        }
    }
    fn ids(l: &[Tactic]) -> Vec<&'static str> {
        l.iter().map(|t| t.id).collect()
    }
    fn entry(id: &str, proven_at: i64, failed: &[(&str, i64)]) -> Entry {
        Entry {
            tactic_id: Some(id.into()),
            proven_at,
            failed_at: failed.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }
    #[test]
    fn lanes_never_mix_families_and_both_start_at_zero() {
        for d in ALL {
            for classic in [false, true] {
                for mobile in [false, true] {
                    let c = Context {
                        mobile,
                        ..ctx(d, classic)
                    };
                    let l = plan(c, None, 1);
                    assert_eq!(l.len(), 2);
                    assert_ne!(l[0].tactics[0].family, l[1].tactics[0].family);
                    for lane in &l {
                        assert_eq!(lane.start_after_ms, 0);
                        let f = lane.tactics[0].family;
                        assert!(lane.tactics.iter().all(|t| t.family == f), "{d:?}");
                    }
                }
            }
        }
    }
    #[test]
    fn modern_gool_races_with_masque_classic_gool_with_warp() {
        for d in ALL {
            let modern: Vec<_> = plan(ctx(d, false), None, 1)
                .into_iter()
                .flat_map(|l| l.tactics)
                .filter(|t| t.id == "gool")
                .collect();
            assert_eq!(modern.len(), 1);
            assert_eq!(modern[0].family, Family::Masque);
            let classic: Vec<_> = plan(ctx(d, true), None, 1)
                .into_iter()
                .flat_map(|l| l.tactics)
                .filter(|t| t.id == "gool")
                .collect();
            assert_eq!(classic.len(), 1);
            assert_eq!(classic[0].family, Family::Warp);
        }
    }
    #[test]
    fn every_tactic_appears_once_and_ids_are_known() {
        for d in ALL {
            for classic in [false, true] {
                let all: Vec<_> = plan(ctx(d, classic), None, 1)
                    .into_iter()
                    .flat_map(|l| l.tactics)
                    .collect();
                assert_eq!(all.len(), 8);
                for t in &all {
                    assert!(known_id(t.id));
                    assert_eq!(all.iter().filter(|o| o.id == t.id).count(), 1, "{}", t.id);
                }
            }
        }
        assert!(!known_id("unknown"));
    }
    #[test]
    fn budgets_follow_the_weight_and_light_goes_before_heavy() {
        for d in ALL {
            for classic in [false, true] {
                for lane in plan(ctx(d, classic), None, 1) {
                    for t in &lane.tactics {
                        let want = if t.two_hop() {
                            TWO_HOP_MS
                        } else if matches!(t.id, "wg.noize" | "wg.heavy" | "masque.h2.frag") {
                            HARDENED_MS
                        } else {
                            LIGHT_MS
                        };
                        assert_eq!(t.budget_ms, want, "{}", t.id);
                    }
                    // Single-hop before two-hop; MASQUE x2 last.
                    let first_two_hop = lane.tactics.iter().position(|t| t.two_hop());
                    if let Some(i) = first_two_hop {
                        assert!(lane.tactics[i..].iter().all(|t| t.two_hop()));
                    }
                    if lane.tactics[0].family == Family::Masque {
                        assert_eq!(lane.tactics.last().unwrap().id, "mim");
                    }
                }
            }
        }
    }
    #[test]
    fn h2_h3_order() {
        let m = |c: Context| ids(&tactics(Family::Masque, c))[..3].to_vec();
        let open = Context::new(Dpi::Open);
        assert_eq!(m(open), ["masque.h3", "masque.h2", "masque.h2.frag"]);
        assert_eq!(m(Context { quic: Some(true), ..open }), ["masque.h3", "masque.h2", "masque.h2.frag"]);
        assert_eq!(m(Context { quic: None, ..open }), ["masque.h3", "masque.h2", "masque.h2.frag"]);
        assert_eq!(m(Context { quic: Some(false), ..open }), ["masque.h2", "masque.h3", "masque.h2.frag"]);
        assert_eq!(m(Context { mobile: true, ..open }), ["masque.h2", "masque.h3", "masque.h2.frag"]);
        assert_eq!(m(Context { prefer_tcp: true, ..open }), ["masque.h2", "masque.h3", "masque.h2.frag"]);
        assert_eq!(m(Context::new(Dpi::UdpThrottled)), ["masque.h2", "masque.h3", "masque.h2.frag"]);
        // h2 lead also makes MASQUE the first lane.
        assert_eq!(plan(Context { quic: Some(false), ..open }, None, 1)[0].tactics[0].family, Family::Masque);
        assert_eq!(plan(open, None, 1)[0].tactics[0].family, Family::Warp);
    }
    #[test]
    fn sni_filtering_and_hostile_lead_with_h2_then_fragmented_h2() {
        for d in [Dpi::SniFiltering, Dpi::Hostile] {
            assert_eq!(
                ids(&tactics(Family::Masque, Context::new(d)))[..3].to_vec(),
                ["masque.h2", "masque.h2.frag", "masque.h3"]
            );
        }
    }
    #[test]
    fn warp_order_and_heavy_noize() {
        assert_eq!(ids(&tactics(Family::Warp, Context::new(Dpi::Open))), ["wg", "wg.noize", "wg.heavy"]);
        assert_eq!(ids(&tactics(Family::Warp, Context::new(Dpi::Hostile))), ["wg.noize", "wg.heavy", "wg"]);
        let h = tactics(Family::Warp, Context::new(Dpi::Hostile));
        assert_eq!(h[0].noize, Hardness::Aggressive);
        assert_eq!(h[1].noize, Hardness::Gfw);
        let o = tactics(Family::Warp, Context::new(Dpi::Open));
        assert_eq!(o[2].noize, Hardness::Aggressive);
    }
    #[test]
    fn memory_puts_the_proven_tactic_first_in_its_own_lane_and_that_lane_first() {
        let e = entry("masque.h2", 100, &[]);
        let l = plan(Context::new(Dpi::Open), Some(&e), 100);
        assert_eq!(l[0].tactics[0].id, "masque.h2");
        assert_eq!(l[0].tactics[0].family, Family::Masque);
        assert_eq!(l[1].tactics[0].id, "wg");
        let e = entry("wg.heavy", 100, &[]);
        let l = plan(Context { quic: Some(false), ..Context::new(Dpi::Open) }, Some(&e), 100);
        assert_eq!(l[0].tactics[0].id, "wg.heavy");
    }
    #[test]
    fn expired_unknown_failed_and_stale_memory() {
        let open = Context::new(Dpi::Open);
        let fresh = plan(open, None, 100);
        for e in [
            entry("unknown", 100, &[]),
            entry("masque.h2", -super::super::memory::PROVEN_TTL_MS, &[]),
        ] {
            let l = plan(open, Some(&e), 100);
            assert_eq!(ids(&l[0].tactics), ids(&fresh[0].tactics));
            assert_eq!(ids(&l[1].tactics), ids(&fresh[1].tactics));
        }
        // A recent failure goes to the end of its lane, but is never dropped.
        let e = entry("wg", 100, &[("wg", 100)]);
        let l = plan(open, Some(&e), 100);
        assert_eq!(l[0].tactics.last().unwrap().id, "wg");
        assert_eq!(l[0].tactics.len(), 3);
        // A stale failure is ignored.
        let e = Entry {
            tactic_id: None,
            proven_at: 0,
            failed_at: BTreeMap::from([("wg".into(), 0)]),
        };
        let l = plan(open, Some(&e), super::super::memory::FAILED_TTL_MS + 1);
        assert_eq!(l[0].tactics[0].id, "wg");
    }
    #[test]
    fn ladder_interleaves_both_families_and_contains_every_tactic() {
        for d in ALL {
            for classic in [false, true] {
                let c = ctx(d, classic);
                let l = ladder(c, None, 1);
                assert_eq!(l.len(), 8);
                assert!(l.iter().any(|t| t.id == "masque.h2"));
                assert_ne!(l[0].family, l[1].family);
            }
        }
    }
    #[test]
    fn last_resort_is_the_two_cleanest_carriers() {
        let l = last_resort(Context::new(Dpi::Hostile));
        assert_eq!(ids(&l), ["masque.h2", "wg"]);
        assert!(l[0].h2);
    }
    #[test]
    fn ranking() {
        let t = tactics(Family::Masque, Context::new(Dpi::Open));
        let (h3, h2) = (t[0].clone(), t[1].clone());
        let q = |rtt| Quality {
            rtt_ms: rtt,
            down_kbps: 4000,
            up_kbps: 2000,
        };
        // Lower latency wins.
        assert_eq!(ids(&rank(vec![(h3.clone(), Some(q(200))), (h2.clone(), Some(q(50)))])), ["masque.h2", "masque.h3"]);
        // Overhead breaks a tie.
        assert_eq!(ids(&rank(vec![(h2.clone(), Some(q(80))), (h3.clone(), Some(q(80)))])), ["masque.h3", "masque.h2"]);
        // Unmeasured goes last, even behind a slow measured route.
        assert_eq!(ids(&rank(vec![(h3.clone(), None), (h2.clone(), Some(q(2000)))])), ["masque.h2", "masque.h3"]);
        // An unmeasured leg is penalised in the score.
        assert!(score(&Quality { rtt_ms: 50, ..Default::default() }, 1.0) > score(&q(50), 1.0));
    }
    #[test]
    fn no_tactic_carries_ech_and_the_race_fits_its_ceiling() {
        for d in ALL {
            for classic in [false, true] {
                for lane in plan(ctx(d, classic), None, 1) {
                    let total: u64 = lane.tactics.iter().map(|t| t.budget_ms).sum();
                    assert!(total <= RACE_CEILING_MS && total < 330_000, "{d:?}: {total}");
                }
            }
        }
    }
}
