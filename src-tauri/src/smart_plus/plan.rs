//! Pure, wire-stable mobile 1.6.0 SmartPlusPlan. No Android or Windows dependencies.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tactic {
    pub id: &'static str,
    pub family: Family,
    pub protocol: Proto,
    pub noize: Hardness,
    pub h2: bool,
    pub fragment: bool,
    pub ech: bool,
    pub budget_ms: u64,
}
#[derive(Debug, Clone)]
pub struct Lane {
    pub tactics: Vec<Tactic>,
    pub start_after_ms: u64,
}
#[derive(Debug, Clone)]
pub enum Step {
    Remembered(Tactic),
    Race(Vec<Lane>),
}
pub const LANE_MS: u64 = 60_000;
pub const REMEMBERED_MS: u64 = 45_000;
pub const SECOND_LANE_AFTER_MS: u64 = 7_000;
pub const RACE_CEILING_MS: u64 = 3 * LANE_MS + SECOND_LANE_AFTER_MS;
pub fn known_id(id: &str) -> bool {
    matches!(
        id,
        "wg" | "wg.noize" | "gool" | "masque.h2" | "masque.h3" | "mim"
    )
}
fn t(id: &'static str, family: Family, protocol: Proto, noize: Hardness) -> Tactic {
    Tactic {
        id,
        family,
        protocol,
        noize,
        h2: false,
        fragment: false,
        ech: false,
        budget_ms: LANE_MS,
    }
}
pub fn tactics(family: Family, dpi: Dpi, mobile: bool) -> Vec<Tactic> {
    use {
        Hardness::*,
        Proto::{Gool, Mim, Wireguard},
    };
    match family {
        Family::Warp => {
            let bare = t("wg", Family::Warp, Wireguard, Off);
            let hard = t(
                "wg.noize",
                Family::Warp,
                Wireguard,
                match dpi {
                    Dpi::Open => Light,
                    Dpi::SniFiltering => Balanced,
                    Dpi::UdpThrottled => Gfw,
                    Dpi::Hostile => Aggressive,
                },
            );
            let gool = t(
                "gool",
                Family::Warp,
                Gool,
                if dpi == Dpi::Open { Light } else { Aggressive },
            );
            if matches!(dpi, Dpi::Open | Dpi::SniFiltering) {
                vec![bare, hard, gool]
            } else {
                vec![hard, gool, bare]
            }
        }
        Family::Masque => {
            let floor = match dpi {
                Dpi::Open => Off,
                Dpi::SniFiltering => Firewall,
                Dpi::UdpThrottled => Light,
                Dpi::Hostile => Gfw,
            };
            let mut h3 = t("masque.h3", Family::Masque, Proto::Masque, floor);
            h3.fragment = dpi != Dpi::Open;
            h3.ech = dpi != Dpi::Open;
            let mut h2 = h3.clone();
            h2.id = "masque.h2";
            h2.h2 = true;
            let mim = t(
                "mim",
                Family::Masque,
                Mim,
                if dpi == Dpi::Open { Light } else { Firewall },
            );
            if mobile || dpi == Dpi::UdpThrottled {
                vec![h2, h3, mim]
            } else {
                vec![h3, h2, mim]
            }
        }
    }
}
pub fn build(dpi: Dpi, mobile: bool, memory: Option<&Entry>, now: i64) -> Vec<Step> {
    let mut warp = tactics(Family::Warp, dpi, mobile);
    let mut masque = tactics(Family::Masque, dpi, mobile);
    let remembered = memory
        .filter(|m| m.proven(now))
        .and_then(|m| {
            warp.iter()
                .chain(masque.iter())
                .find(|t| Some(t.id) == m.tactic_id.as_deref())
        })
        .cloned();
    for lane in [&mut warp, &mut masque] {
        lane.sort_by_key(|t| {
            if memory.map(|m| m.failed(t.id, now)).unwrap_or(false) {
                2
            } else if remembered.as_ref().map(|r| r.id == t.id).unwrap_or(false) {
                0
            } else {
                1
            }
        });
    }
    let lead = remembered
        .as_ref()
        .map(|t| t.family == Family::Masque)
        .unwrap_or(matches!(dpi, Dpi::UdpThrottled | Dpi::Hostile));
    let (a, b) = if lead { (masque, warp) } else { (warp, masque) };
    let race = Step::Race(vec![
        Lane {
            tactics: a,
            start_after_ms: 0,
        },
        Lane {
            tactics: b,
            start_after_ms: SECOND_LANE_AFTER_MS,
        },
    ]);
    let mut steps = vec![];
    if let Some(mut t) = remembered.filter(|t| !memory.unwrap().failed(t.id, now)) {
        t.budget_ms = REMEMBERED_MS;
        steps.push(Step::Remembered(t));
    }
    steps.push(race);
    steps
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn all_fingerprints_and_link_types() {
        for d in [
            Dpi::Open,
            Dpi::SniFiltering,
            Dpi::UdpThrottled,
            Dpi::Hostile,
        ] {
            for m in [false, true] {
                let p = build(d, m, None, 1);
                let Step::Race(l) = &p[0] else { panic!() };
                assert_eq!(l.len(), 2);
                assert_eq!(l[0].start_after_ms, 0);
                assert_eq!(l[1].start_after_ms, 7000);
                assert_ne!(l[0].tactics[0].family, l[1].tactics[0].family);
                for lane in l {
                    assert_eq!(lane.tactics.len(), 3);
                    assert!(lane
                        .tactics
                        .iter()
                        .all(|t| t.family == lane.tactics[0].family && t.budget_ms == LANE_MS));
                }
                let mt = tactics(Family::Masque, d, m);
                assert_eq!(mt[0].h2, m || d == Dpi::UdpThrottled);
            }
        }
    }
    #[test]
    fn memory_prioritizes_its_family() {
        let e = Entry {
            tactic_id: Some("masque.h2".into()),
            proven_at: 100,
            failed_at: BTreeMap::new(),
        };
        let p = build(Dpi::Open, false, Some(&e), 100);
        let Step::Remembered(t) = &p[0] else { panic!() };
        assert_eq!(t.id, "masque.h2");
        assert_eq!(t.budget_ms, REMEMBERED_MS);
        let Step::Race(l) = &p[1] else { panic!() };
        assert_eq!(l[0].tactics[0].id, "masque.h2");
    }
    #[test]
    fn failed_unknown_expired_memory() {
        for (id, time) in [
            ("unknown", 100),
            ("wg", -super::super::memory::PROVEN_TTL_MS),
        ] {
            let e = Entry {
                tactic_id: Some(id.into()),
                proven_at: time,
                failed_at: BTreeMap::new(),
            };
            assert!(matches!(
                build(Dpi::Open, false, Some(&e), 100)[0],
                Step::Race(_)
            ));
        }
        let e = Entry {
            tactic_id: Some("wg".into()),
            proven_at: 100,
            failed_at: BTreeMap::from([("wg".into(), 100)]),
        };
        let p = build(Dpi::Open, false, Some(&e), 100);
        let Step::Race(l) = &p[0] else { panic!() };
        assert_eq!(l[0].tactics.last().unwrap().id, "wg");
    }
}
