//! Mobile AiAvailability custom-exit rules, plus an owned active-session route.
//! Never infer the active exit from mutable catalog/preferences.
use super::{ChainBase, ChainMode, ChainPlacement};
use std::sync::Mutex;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub mode: Option<ChainMode>,
    pub port: u16,
}
static ACTIVE: Mutex<Option<Route>> = Mutex::new(None);
pub fn custom_eligible(mode: ChainMode) -> bool {
    mode.placement() != ChainPlacement::First
        || matches!(
            mode.base(),
            Some(ChainBase::Psiphon | ChainBase::AetherPsiphon | ChainBase::TorPsiphon)
        )
}
pub fn route(mode: Option<ChainMode>, port: u16) -> Option<Route> {
    if port == 0 {
        None
    } else {
        Some(Route { mode, port })
    }
}
pub fn note(mode: Option<ChainMode>, port: u16) {
    *ACTIVE.lock().unwrap() = route(mode, port);
}
pub fn clear() {
    *ACTIVE.lock().unwrap() = None;
}
pub fn active() -> Option<Route> {
    *ACTIVE.lock().unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_mobile_custom_exit_rules() {
        for m in ChainMode::ALL {
            let expected = matches!(
                m,
                ChainMode::Solo
                    | ChainMode::AetherConfig
                    | ChainMode::PsiphonConfig
                    | ChainMode::TorConfig
                    | ChainMode::AetherPsiphonConfig
                    | ChainMode::AetherTorConfig
                    | ChainMode::TorPsiphonConfig
                    | ChainMode::TorAetherConfig
                    | ChainMode::ConfigPsiphon
                    | ChainMode::ConfigAetherPsiphon
                    | ChainMode::ConfigTorPsiphon
            );
            assert_eq!(custom_eligible(m), expected, "{}", m.name());
        }
    }
    #[test]
    fn active_route_is_not_a_store_snapshot() {
        clear();
        assert!(active().is_none());
        note(Some(ChainMode::Solo), 18836);
        assert_eq!(active().unwrap().port, 18836);
        clear();
        assert!(active().is_none());
    }
    #[test]
    fn preserves_actual_exit_and_rejects_zero() {
        assert!(route(None, 0).is_none());
        let r = route(Some(ChainMode::Solo), 18833).unwrap();
        assert_eq!(r.port, 18833);
        assert_eq!(r.mode, Some(ChainMode::Solo));
    }
}
