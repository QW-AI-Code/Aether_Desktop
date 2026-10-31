//! کانفیگ‌های ذخیره‌شده و زنجیره‌ای که کاربر انتخاب کرده — پورتِ
//! `CustomConfigStore.kt` نسخهٔ اندروید ۱.۵.۰.
//!
//! # مهرشده با DPAPI، جدا از پروفایل
//!
//! کانفیگ‌ها اطلاعاتِ ورودِ سرور دارند، پس مثل بقیهٔ رازها با DPAPI
//! (`CryptProtectData`، همان سازوکارِ `secret_store.rs`) مهر می‌شوند و در فایلِ
//! جداگانهٔ `custom_configs.bin` کنارِ `profile.json` می‌نشینند. عمداً **داخلِ
//! پروفایل نیستند**: «بازنشانیِ همهٔ تنظیمات» تنظیماتِ تونل را برمی‌گرداند، نه
//! اینکه سرورهای واردشدهٔ کاربر را پاک کند. نوشتن اتمیک است (فایلِ موقت +
//! rename). اگر مهرکردن شکست بخورد، وضعیت فقط در حافظهٔ همین اجرا می‌ماند —
//! هرگز اطلاعاتِ ورود به‌صورتِ متنِ ساده روی دیسک نوشته نمی‌شود.

use super::{
    ChainMode, ConfigFormat, ConfigProtocol, ConfigSource, CustomConfig, CustomSelection, MAX_NAME,
};
use serde_json::{json, Value};
use serde::{Serialize,Deserialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FILE_NAME: &str = "custom_configs.bin";
pub const MAX_CONFIGS: usize = 500;

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub struct Group {pub id:String,pub name:String}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase")]
pub struct Subscription {pub id:String,pub name:String,pub url:String,pub group_id:Option<String>,pub updated_at:i64,pub config_ids:Vec<String>}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub configs: Vec<CustomConfig>,
    pub active_id: Option<String>,
    pub mode: ChainMode,
    /// کلیدِ اصلی: خاموش = هر نشست دقیقاً مثل پیش از این قابلیت اجرا می‌شود.
    pub enabled: bool,
    pub groups: Vec<Group>,
    pub membership: BTreeMap<String,String>,
    pub tab_names: BTreeMap<String,String>,
    pub hidden_tabs: Vec<String>,
    pub subscriptions: Vec<Subscription>,
}

impl Default for State {
    fn default() -> Self {
        State {
            configs: Vec::new(),
            active_id: None,
            mode: ChainMode::Solo,
            enabled: false,
            groups:Vec::new(),membership:BTreeMap::new(),tab_names:BTreeMap::new(),hidden_tabs:Vec::new(),subscriptions:Vec::new(),
        }
    }
}

impl State {
    /// Delete only this tab's owned configs. All is permanent. A family tab
    /// never owns a config explicitly assigned to a manual group.
    pub fn delete_tab(mut self, id: &str) -> Self {
        if id == "all" { return self; }
        let manual = self.groups.iter().any(|g| g.id == id);
        let family = id == "format:v2ray" || id == "format:npvt";
        let sub_ids = self.subscriptions.iter().find(|s| s.id == id)
            .map(|s| s.config_ids.clone());
        if !manual && !family && sub_ids.is_none() { return self; }
        let removed: Vec<String> = self.configs.iter().filter(|c| {
            if manual { self.membership.get(&c.id).map(String::as_str) == Some(id) }
            else if family { !self.membership.contains_key(&c.id) &&
                ((id == "format:npvt") == (c.format == ConfigFormat::Npvt)) }
            else { sub_ids.as_ref().map(|ids| ids.contains(&c.id)).unwrap_or(false) }
        }).map(|c| c.id.clone()).collect();
        for key in removed { self = self.delete(&key); }
        self.groups.retain(|g| g.id != id);
        self.membership.retain(|_, group| group != id);
        self.subscriptions.retain(|sub| sub.id != id &&
            sub.group_id.as_deref() != Some(id) && !sub.config_ids.is_empty());
        self.tab_names.remove(id);
        self.hidden_tabs.retain(|tab| tab != id);
        self.fix_active();
        self
    }

    pub fn active(&self) -> Option<&CustomConfig> {
        let id = self.active_id.as_ref()?;
        self.configs.iter().find(|c| &c.id == id)
    }

    /// آنچه نشستِ بعدی اجرا می‌کند، یا `None` وقتی کانفیگِ سفارشی در کار نیست.
    pub fn selection(&self) -> Option<CustomSelection> {
        if !self.enabled {
            return None;
        }
        self.active().map(|c| CustomSelection {
            config: c.clone(),
            mode: self.mode,
        })
    }

    pub fn add(mut self, configs: Vec<CustomConfig>) -> State {
        let first = configs.first().map(|c| c.id.clone());
        for c in configs {
            if !self.configs.iter().any(|x| x.id == c.id) {
                self.configs.push(c);
            }
        }
        if self.configs.len() > MAX_CONFIGS {
            let drop = self.configs.len() - MAX_CONFIGS;
            self.configs.drain(..drop);
        }
        // اولین ورود به یک فهرستِ خالی آن را انتخاب می‌کند تا کاربر ببیند در کار است.
        if self.active_id.is_none() {
            self.active_id = first;
        }
        self.fix_active();
        self
    }

    /// Validate and assign ownership in the SAME transaction as insertion.
    /// No transient automatic-family tab or orphan on a deleted destination.
    pub fn import_into(&self, configs: Vec<CustomConfig>, group: Option<&str>) -> Result<Self, &'static str> {
        if group.map(|id| !self.groups.iter().any(|g| g.id == id)).unwrap_or(false) {
            return Err("Destination tab no longer exists");
        }
        let incoming = configs.iter().filter(|c| !self.configs.iter().any(|old| old.id == c.id)).count();
        if self.configs.len() + incoming > MAX_CONFIGS { return Err("Too many configs (maximum 500); nothing imported"); }
        let ids: Vec<_> = configs.iter().map(|c| c.id.clone()).collect();
        let mut next = self.clone().add(configs);
        for id in ids { if let Some(group) = group { next.membership.insert(id, group.into()); } }
        Ok(next)
    }

    pub fn replace(mut self, config: CustomConfig) -> State {
        for c in self.configs.iter_mut() {
            if c.id == config.id {
                *c = config.clone();
            }
        }
        self
    }

    pub fn delete(mut self, id: &str) -> State {
        self.configs.retain(|c| c.id != id);
        self.membership.remove(id);
        for sub in &mut self.subscriptions {sub.config_ids.retain(|s|s!=id);}
        if self.active_id.as_deref() == Some(id) {
            self.active_id = None;
        }
        self.enabled = self.enabled && self.active_id.is_some();
        self
    }

    pub fn delete_all(self) -> State {
        State {
            mode: self.mode,
            ..State::default()
        }
    }

    pub fn select(mut self, id: &str) -> State {
        if self.configs.iter().any(|c| c.id == id) {
            self.active_id = Some(id.to_string());
        }
        self
    }

    pub fn set_mode(mut self, mode: ChainMode) -> State {
        self.mode = mode;
        self
    }

    pub fn set_enabled(mut self, enabled: bool) -> State {
        self.enabled = enabled && self.active().is_some();
        self
    }

    pub fn rename(mut self, id: &str, name: &str) -> State {
        let clean: String = name.trim().chars().take(MAX_NAME).collect();
        if clean.is_empty() {
            return self;
        }
        for c in self.configs.iter_mut() {
            if c.id == id {
                c.name = clean.clone();
            }
        }
        self
    }

    fn fix_active(&mut self) {
        if let Some(id) = &self.active_id {
            if !self.configs.iter().any(|c| &c.id == id) {
                self.active_id = None;
            }
        }
        self.enabled = self.enabled && self.active_id.is_some();
    }
}

// ------------------------------------------------------------- codec (v1)

pub fn encode(s: &State) -> String {
    let configs: Vec<Value> = s
        .configs
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "protocol": c.protocol.name(),
                "format": c.format.name(),
                "source": c.source.name(),
                "outbound": c.outbound,
                "raw": c.raw,
                "server": c.server,
                "locked": c.locked,
                "note": c.note,
                "expiresAt": c.expires_at,
                "mobileOnly": c.mobile_only,
                "addedAt": c.added_at,
            })
        })
        .collect();
    let mut o = serde_json::Map::new();
    o.insert("v".into(), json!(2));
    o.insert("groups".into(),json!(s.groups));
    o.insert("membership".into(),json!(s.membership));
    o.insert("tabNames".into(),json!(s.tab_names));
    o.insert("hiddenTabs".into(),json!(s.hidden_tabs));
    o.insert("subscriptions".into(),json!(s.subscriptions));
    if let Some(a) = &s.active_id {
        o.insert("active".into(), json!(a));
    }
    o.insert("mode".into(), json!(s.mode.name()));
    o.insert("enabled".into(), json!(s.enabled));
    o.insert("configs".into(), Value::Array(configs));
    Value::Object(o).to_string()
}

pub fn decode(text: &str) -> Option<State> {
    let o = match serde_json::from_str::<Value>(text).ok()? {
        Value::Object(o) => o,
        _ => return None,
    };
    let s = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(|v| v.as_str()).map(String::from);
    let b = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let l = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    let configs: Vec<CustomConfig> = o
        .get("configs")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let c = e.as_object()?;
                    Some(CustomConfig {
                        id: s(c, "id")?,
                        name: s(c, "name").unwrap_or_default(),
                        protocol: s(c, "protocol")
                            .and_then(|p| ConfigProtocol::from_name(&p))
                            .unwrap_or(ConfigProtocol::Other),
                        format: s(c, "format")
                            .and_then(|p| ConfigFormat::from_name(&p))
                            .unwrap_or(ConfigFormat::Uri),
                        source: s(c, "source")
                            .and_then(|p| ConfigSource::from_name(&p))
                            .unwrap_or(ConfigSource::Link),
                        outbound: s(c, "outbound")?,
                        raw: s(c, "raw").unwrap_or_default(),
                        server: s(c, "server").unwrap_or_default(),
                        locked: b(c, "locked"),
                        note: s(c, "note").unwrap_or_default(),
                        expires_at: l(c, "expiresAt"),
                        mobile_only: b(c, "mobileOnly"),
                        added_at: l(c, "addedAt"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let active = s(&o, "active").filter(|id| configs.iter().any(|c| &c.id == id));
    let enabled = b(&o, "enabled") && active.is_some();
    Some(State {
        groups: o.get("groups").cloned().and_then(|v|serde_json::from_value(v).ok()).unwrap_or_default(),
        membership:o.get("membership").cloned().and_then(|v|serde_json::from_value(v).ok()).unwrap_or_default(),
        tab_names:o.get("tabNames").cloned().and_then(|v|serde_json::from_value(v).ok()).unwrap_or_default(),
        hidden_tabs:o.get("hiddenTabs").cloned().and_then(|v|serde_json::from_value(v).ok()).unwrap_or_default(),
        subscriptions:o.get("subscriptions").cloned().and_then(|v|serde_json::from_value(v).ok()).unwrap_or_default(),
        configs,
        active_id: active,
        mode: ChainMode::from_stored_name(s(&o, "mode").as_deref()),
        enabled,
    })
}

// ------------------------------------------------------------- disk

struct Disk {
    path: PathBuf,
    state: State,
}

static STORE: Mutex<Option<Disk>> = Mutex::new(None);

fn file_in(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

fn read_file(path: &Path) -> State {
    let Ok(sealed) = std::fs::read(path) else {
        return State::default();
    };
    match crate::secret_store::unseal(&sealed) {
        Ok(plain) => decode(&String::from_utf8_lossy(&plain)).unwrap_or_default(),
        Err(e) => {
            crate::log::DiagnosticsLog::w(
                "custom",
                &format!("The saved custom configs could not be unsealed ({e}); starting with an empty list."),
            );
            State::default()
        }
    }
}

fn write_file(path: &Path, state: &State) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let sealed = crate::secret_store::seal(encode(state).as_bytes()).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("bin.tmp");
    std::fs::write(&tmp, &sealed).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

/// انبار را برای این پوشهٔ داده باز می‌کند (یک بار، در شروعِ برنامه).
pub fn init(data_dir: &Path) {
    let path = file_in(data_dir);
    let state = read_file(&path);
    if let Ok(mut g) = STORE.lock() {
        *g = Some(Disk { path, state });
    }
}

/// وضعیتِ فعلی (کپی).
pub fn snapshot() -> State {
    STORE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|d| d.state.clone()))
        .unwrap_or_default()
}

/// آنچه نشستِ بعدی اجرا می‌کند؛ `None` = کانفیگِ سفارشی خاموش است.
pub fn selection() -> Option<CustomSelection> {
    snapshot().selection()
}

/// مثل [`update`] ولی فقط وقتی تغییر را در حافظه می‌پذیرد که نوشتنِ مهرشده موفق شود
/// و `change` خودش `Some` بدهد. اسکنر IP تمیز موفقیت را فقط پس از این گزارش می‌کند.
pub fn update_checked(change: impl FnOnce(&State) -> Option<State>) -> Result<State, String> {
    let mut g = STORE.lock().map_err(|_| "store unavailable".to_string())?;
    let disk = g.as_mut().ok_or_else(|| "store not initialised".to_string())?;
    let next = change(&disk.state).ok_or_else(|| "config changed".to_string())?;
    write_file(&disk.path, &next)?;
    disk.state = next.clone();
    Ok(next)
}

/// یک تغییر را اعمال و (مهرشده) ذخیره می‌کند.
pub fn update(change: impl FnOnce(State) -> State) -> State {
    let Ok(mut g) = STORE.lock() else {
        return State::default();
    };
    let Some(disk) = g.as_mut() else {
        return State::default();
    };
    let next = change(disk.state.clone());
    disk.state = next.clone();
    if let Err(e) = write_file(&disk.path, &next) {
        // بی‌کلیدِ DPAPI: وضعیت فقط در همین اجرا می‌ماند، به‌جای نوشتنِ متنِ ساده.
        crate::log::DiagnosticsLog::w(
            "custom",
            &format!("Custom configs could not be saved sealed ({e}); keeping them for this session only."),
        );
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: &str) -> CustomConfig {
        CustomConfig {
            id: id.into(),
            name: format!("n-{id}"),
            protocol: ConfigProtocol::Vless,
            format: ConfigFormat::Uri,
            source: ConfigSource::Link,
            outbound: "{\"protocol\":\"vless\"}".into(),
            raw: "vless://x@h:1".into(),
            server: "h:1".into(),
            locked: false,
            note: String::new(),
            expires_at: 0,
            mobile_only: false,
            added_at: 5,
        }
    }

    #[test]
    fn import_target_is_atomic_and_deleted_target_changes_nothing() {
        let mut s = State::default();
        s.groups.push(Group {id:"user:manual".into(),name:"Manual".into()});
        let next=s.import_into(vec![cfg("new")],Some("user:manual")).unwrap();
        assert_eq!(next.membership.get("new").map(String::as_str),Some("user:manual"));
        assert!(s.configs.is_empty());
        assert!(s.import_into(vec![cfg("orphan")],Some("user:deleted")).is_err());
        assert_eq!(next.clone().delete_tab("format:v2ray"),next);
    }

    #[test]
    fn deleting_family_cascades_but_preserves_manual_ownership() {
        let mut s = State::default().add(vec![cfg("a"), cfg("b")]).set_enabled(true);
        s.groups.push(Group { id:"user:one".into(), name:"One".into() });
        s.membership.insert("b".into(), "user:one".into());
        s.subscriptions.push(Subscription { id:"sub:one".into(), name:"Feed".into(),
            url:"https://example.invalid/private".into(), group_id:None,
            updated_at:1, config_ids:vec!["a".into(),"b".into()] });
        let s = s.delete_tab("format:v2ray");
        assert_eq!(s.configs.len(),1);
        assert_eq!(s.configs[0].id,"b");
        assert_eq!(s.subscriptions[0].config_ids,vec!["b"]);
        assert!(s.active_id.is_none() && !s.enabled);
        assert_eq!(decode(&encode(&s)).unwrap(),s);
        assert_eq!(s.clone().delete_tab("all"),s);
        assert_eq!(s.clone().delete_tab("missing"),s);
        assert_eq!(s.clone().delete_tab("format:v2ray"),s);
    }

    #[test]
    fn deleting_manual_tab_deletes_its_configs_membership_and_feed() {
        let mut s = State::default().add(vec![cfg("a"),cfg("outside")]);
        s.groups.push(Group {id:"user:one".into(),name:"One".into()});
        s.membership.insert("a".into(),"user:one".into());
        s.subscriptions.push(Subscription { id:"sub:one".into(),name:"One".into(),
            url:"https://example.invalid/private".into(),group_id:Some("user:one".into()),
            updated_at:1,config_ids:vec!["a".into()] });
        let s = s.delete_tab("user:one");
        assert!(s.groups.is_empty() && s.membership.is_empty() && s.subscriptions.is_empty());
        assert_eq!(s.configs.len(),1);
        assert_eq!(s.configs[0].id,"outside");
    }

    #[test]
    fn the_first_import_selects_and_delete_disables() {
        let s = State::default().add(vec![cfg("a"), cfg("b")]);
        assert_eq!(s.active_id.as_deref(), Some("a"));
        assert!(!s.enabled, "importing never switches the feature on");
        assert!(s.selection().is_none());
        let s = s.set_enabled(true).set_mode(ChainMode::TorConfig);
        assert_eq!(s.selection().unwrap().mode, ChainMode::TorConfig);
        let s = s.select("b").delete("b");
        assert!(s.active_id.is_none());
        assert!(!s.enabled);
        let s = s.set_enabled(true);
        assert!(!s.enabled, "cannot switch on without an active config");
        let s = s.add(vec![cfg("c")]).delete_all();
        assert!(s.configs.is_empty());
        assert_eq!(s.mode, ChainMode::TorConfig, "delete all keeps the chain");
    }

    #[test]
    fn rename_trims_and_caps() {
        let s = State::default().add(vec![cfg("a")]);
        let s = s.rename("a", "   ");
        assert_eq!(s.configs[0].name, "n-a");
        let long = "x".repeat(200);
        let s = s.rename("a", &format!("  {long} "));
        assert_eq!(s.configs[0].name.chars().count(), MAX_NAME);
    }

    #[test]
    fn the_list_is_capped() {
        let many: Vec<CustomConfig> = (0..MAX_CONFIGS + 3).map(|i| cfg(&i.to_string())).collect();
        let s = State::default().add(many);
        assert_eq!(s.configs.len(), MAX_CONFIGS);
        assert_eq!(s.configs[0].id, "3");
    }

    #[test]
    fn codec_round_trips() {
        let mut locked = cfg("l");
        locked.locked = true;
        locked.raw.clear();
        locked.server.clear();
        locked.format = ConfigFormat::Npvt;
        locked.note = "hello".into();
        locked.expires_at = 4_000_000_000_000;
        let s = State::default()
            .add(vec![cfg("a"), locked])
            .set_enabled(true)
            .set_mode(ChainMode::ConfigTorPsiphon);
        let back = decode(&encode(&s)).unwrap();
        assert_eq!(back, s);
        assert!(decode("nope").is_none());
        // An active id that no longer exists is dropped, and with it `enabled`.
        let broken = encode(&s).replace("\"active\":\"a\"", "\"active\":\"zz\"");
        let b = decode(&broken).unwrap();
        assert!(b.active_id.is_none() && !b.enabled);
    }

    #[test]
    fn disk_round_trip_through_the_sealed_file() {
        let dir = std::env::temp_dir().join(format!("aether-cc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        init(&dir);
        update(|s| s.add(vec![cfg("a")]).set_enabled(true));
        assert!(dir.join(FILE_NAME).exists());
        init(&dir);
        assert_eq!(snapshot().configs.len(), 1);
        assert!(selection().is_some());
        update(|s| s.delete_all());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)] mod catalog_metadata_tests {
 use super::*;
 #[test]fn catalog_metadata_roundtrip(){
  let mut s=State::default();s.groups.push(Group{id:"user:one".into(),name:"آزمایش".into()});
  s.tab_names.insert("all".into(),"همه".into());
  s.subscriptions.push(Subscription{id:"sub:one".into(),name:"Fixture".into(),url:"https://example.invalid/private-token".into(),group_id:Some("user:one".into()),updated_at:1,config_ids:vec![]});
  assert_eq!(decode(&encode(&s)).unwrap(),s);
 }
 #[test]fn old_empty_store_defaults_to_no_groups(){let s=decode(r#"{"version":1,"configs":[],"enabled":false,"mode":"SOLO"}"#).unwrap();assert!(s.groups.is_empty()&&s.membership.is_empty()&&s.subscriptions.is_empty());}
}
