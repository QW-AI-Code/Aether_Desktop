//! Named settings snapshots, DPAPI sealed. Never expose profile contents in list IPC.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const DEFAULT_ID: &str = "default";
/// Keys that never cross devices (same list as mobile PresetTransferCodec,
/// plus private Tor bridge lines).
const PRIVATE_KEYS: [&str; 7] = ["upstream","team","accessMode","accessEmail","accessId","gateway","torBridgeLines"];
const MAX_TRANSFER: usize = 256*1024;

/// Clean factory profile used by the locked "default" preset.
pub fn factory_profile() -> Value {
    serde_json::to_value(crate::profile::ConnectionProfile::default()).unwrap_or(Value::Null)
}
fn allowed_keys() -> Vec<String> {
    factory_profile().as_object().map(|o|o.keys().filter(|k|!PRIVATE_KEYS.contains(&k.as_str())).cloned().collect()).unwrap_or_default()
}
fn portable(v:&Value)->Value {
    let mut out=serde_json::Map::new();
    if let Some(o)=v.as_object() { for (k,val) in o { if !PRIVATE_KEYS.contains(&k.as_str()) { out.insert(k.clone(),val.clone()); } } }
    Value::Object(out)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Preset { pub id: String, pub name: String, pub profile: Value, #[serde(default)] pub custom: Option<CustomSel> }
/// Custom-config selection stored next to a profile (mobile `ConnectionPreset`:
/// customConfigId / customEnabled / chainMode). Without it, switching profiles
/// changed the engine settings but left the previous custom route active.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomSel {
    pub config_id: Option<String>, pub enabled: bool, pub mode: String,
    /// Name of the config; lets an imported profile re-link when ids differ.
    #[serde(default)] pub config_name: Option<String>,
}
impl CustomSel {
    pub fn off() -> Self { Self { config_id: None, enabled: false, mode: "SOLO".into(), config_name: None } }
    pub fn from_state(s:&crate::custom::store::State) -> Self {
        let config_name=s.active_id.as_ref().and_then(|id|s.configs.iter().find(|c|c.id==*id)).map(|c|c.name.clone());
        Self { config_id: s.active_id.clone(), enabled: s.enabled, mode: s.mode.name().into(), config_name }
    }
    /// Applies the selection to the custom store. A config that no longer exists
    /// switches custom routing off instead of silently using another one.
    pub fn apply(&self) -> crate::custom::store::State {
        let mode=crate::custom::ChainMode::from_stored_name(Some(&self.mode));
        crate::custom::store::update(|s| {
            let by_id=self.config_id.as_deref().filter(|id| s.configs.iter().any(|c| c.id==*id)).map(str::to_string);
            // Unknown id (e.g. re-imported file): fall back to a UNIQUE name match.
            let target=by_id.or_else(|| {
                let n=self.config_name.as_deref()?;
                let mut m=s.configs.iter().filter(|c|c.name==n);
                match (m.next(),m.next()) { (Some(c),None)=>Some(c.id.clone()), _=>None }
            });
            let s=match &target { Some(id)=>s.select(id), None=>s };
            s.set_mode(mode).set_enabled(self.enabled && target.is_some())
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Collection { pub active: String, pub items: Vec<Preset> }
pub struct PresetStore { path: PathBuf, pub data: Collection }
impl Collection {
    /// Non-secret export of one profile. `current` is the live profile and
    /// replaces the stored copy of the active, non-default profile.
    pub fn export_selected(&self, current: Value, live: &CustomSel) -> Result<String,String> {
        let p=self.items.iter().find(|p|p.id==self.active).ok_or("No active profile")?;
        let profile=if p.id==DEFAULT_ID { factory_profile() } else { current };
        let mut entry=json!({"name":p.name,"profile":portable(&profile)});
        // Reference only (id/name/switches): server data and credentials never leave the device.
        if p.id!=DEFAULT_ID {
            entry["custom"]=json!({"configId":live.config_id,"configName":live.config_name,"enabled":live.enabled,"mode":live.mode});
        }
        let text=serde_json::to_string_pretty(&json!({
            "schemaVersion":1,"appVersion":"1.4.0",
            "presets":[entry]
        })).map_err(|e|e.to_string())?;
        if text.len()>MAX_TRANSFER { return Err("Export is too large".into()); }
        Ok(text)
    }
    /// Validates and appends imported profiles (use [`import_and_select`] to also activate them).
    pub fn import(&self, text:&str) -> Result<(Self,usize),String> {
        if text.len()>MAX_TRANSFER { return Err("Import is too large".into()); }
        let root:Value=serde_json::from_str(text).map_err(|_|"Invalid profile file")?;
        if root.get("schemaVersion").and_then(Value::as_i64)!=Some(1) { return Err("Unsupported profile schema".into()); }
        let list=root.get("presets").and_then(Value::as_array).ok_or("Profiles missing")?;
        if list.is_empty() || list.len()>20 { return Err("Invalid profile count".into()); }
        let allowed=allowed_keys();
        let mut next=self.clone();
        for item in list {
            let name=clean_name(item.get("name").and_then(Value::as_str).unwrap_or(""))?;
            let obj=item.get("profile").and_then(Value::as_object).ok_or("Profile missing")?;
            if obj.keys().any(|k|!allowed.contains(k)) { return Err("Unknown or sensitive field".into()); }
            let parsed:crate::profile::ConnectionProfile=serde_json::from_value(Value::Object(obj.clone())).map_err(|_|"Invalid profile value")?;
            let mut value=serde_json::to_value(parsed).map_err(|e|e.to_string())?;
            value=portable(&value);
            if next.items.len()>=20 { return Err("Too many profiles (maximum 20)".into()); }
            next.items.push(Preset{id:crate::custom::new_id(),name,profile:value,custom:parse_custom(item)});
        }
        Ok((next,list.len()))
    }
    /// Imports profiles and makes the FIRST imported one the active profile.
    /// Returns the new collection, the exact stored settings of the selected
    /// profile (to be applied by the caller) and the custom-config selection
    /// to apply with it. Pending live edits of the outgoing non-default profile
    /// are saved first, exactly like [`change`]; nothing is touched on error.
    pub fn import_and_select(&self, text:&str, current:Value, live:CustomSel)
        -> Result<(Self,Value,CustomSel,usize),String> {
        let mut base=self.clone();
        if base.active!=DEFAULT_ID {
            let old=base.active.clone();
            if let Some(a)=base.items.iter_mut().find(|p|p.id==old) { a.profile=current; }
            base.stamp(&old,&live);
        }
        let first=base.items.len();
        let (mut next,count)=base.import(text)?;
        let picked=next.items.get(first).ok_or("Profiles missing")?;
        let (id,target)=(picked.id.clone(),picked.profile.clone());
        let sel=picked.custom.clone().unwrap_or_else(CustomSel::off);
        next.active=id;
        Ok((next,target,sel,count))
    }
    pub fn initial(profile: Value) -> Self {
        Self { active:DEFAULT_ID.into(), items:vec![Preset {id:DEFAULT_ID.into(),name:"Default".into(),profile,custom:None}] }
    }
    pub fn view(&self) -> Value { json!({"activeId":self.active,"presets":self.items.iter().map(|p|json!({"id":p.id,"name":p.name})).collect::<Vec<_>>()}) }
    fn stamp(&mut self, id:&str, sel:&CustomSel) {
        if id==DEFAULT_ID { return; }
        if let Some(p)=self.items.iter_mut().find(|p|p.id==id) { p.custom=Some(sel.clone()); }
    }
    /// Like [`change`], plus the custom-config selection: the outgoing profile
    /// keeps the live selection, a saved profile starts with it, and the
    /// returned selection (if any) is what must be applied for the new profile.
    pub fn change_with(&self, action:&str, id:&str, name:&str, current:Value, live:CustomSel)
        -> Result<(Self,Option<Value>,Option<CustomSel>),String> {
        let (mut next,target)=self.change(action,id,name,current)?;
        let old=self.active.clone();
        next.stamp(&old,&live);
        if action=="save" { let a=next.active.clone(); next.stamp(&a,&live); }
        let apply=target.as_ref().map(|_| next.items.iter().find(|p|p.id==next.active)
            .and_then(|p|p.custom.clone()).unwrap_or_else(CustomSel::off));
        Ok((next,target,apply))
    }
    /// All changes are prepared on a clone; invalid input never changes live state.
    pub fn change(&self, action: &str, id: &str, name: &str, current: Value) -> Result<(Self,Option<Value>),String> {
        let mut next=self.clone();
        // 1.4.0: the built-in "default" profile is immutable. Live edits made
        // while it is active are never written back, so selecting it always
        // returns to the clean factory settings.
        if next.active!=DEFAULT_ID {
            if let Some(active)=next.items.iter_mut().find(|p|p.id==next.active) { active.profile=current.clone(); }
        }
        let mut target=None;
        match action {
            "save" => {
                if next.items.len()>=20 { return Err("Too many profiles (maximum 20)".into()); }
                let name=clean_name(name)?;
                let id=crate::custom::new_id();
                next.items.push(Preset {id:id.clone(),name,profile:current,custom:None});next.active=id;
            },
            "select" => {
                let p=next.items.iter().find(|p|p.id==id).ok_or("Profile not found")?;
                target=Some(if p.id==DEFAULT_ID { factory_profile() } else { p.profile.clone() });
                next.active=id.into();
            },
            "rename" => { if id==DEFAULT_ID { return Err("The default profile cannot be renamed".into()); } let name=clean_name(name)?;next.items.iter_mut().find(|p|p.id==id).ok_or("Profile not found")?.name=name; },
            "delete" => {
                if id==DEFAULT_ID { return Err("The default profile cannot be deleted".into()); }
                if next.items.len()<=1 { return Err("The last profile cannot be deleted".into()); }
                if !next.items.iter().any(|p|p.id==id) { return Err("Profile not found".into()); }
                next.items.retain(|p|p.id!=id);
                if next.active==id { next.active=DEFAULT_ID.into();target=Some(factory_profile()); }
            },
            _ => return Err("Unknown profile action".into()),
        }
        Ok((next,target))
    }
}
/// Optional `custom` block of an imported profile; malformed parts fall back to "off".
fn parse_custom(item:&Value)->Option<CustomSel> {
    let c=item.get("custom")?.as_object()?;
    let text=|k:&str|c.get(k).and_then(Value::as_str).filter(|v|!v.is_empty()&&v.len()<=200).map(str::to_string);
    Some(CustomSel{
        config_id:text("configId"),config_name:text("configName"),
        enabled:c.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        mode:text("mode").unwrap_or_else(||"SOLO".into()),
    })
}
fn clean_name(name:&str)->Result<String,String> {
    let name:String=name.chars().filter(|c|!c.is_control()).take(40).collect();
    let name=name.trim();if name.is_empty() {Err("Profile name is empty".into())}else{Ok(name.into())}
}
impl PresetStore {
    pub fn new(dir:&Path, current:Value)->Self {
        let path=dir.join("connection_presets.bin");
        let data=std::fs::read(&path).ok().filter(|b| b.len()<=512*1024)
            .and_then(|b|crate::secret_store::unseal(&b).ok())
            .and_then(|b|serde_json::from_slice::<Collection>(&b).ok())
            .filter(|s| !s.items.is_empty() && s.items.len()<=20 && s.items.iter().any(|p|p.id==s.active))
            .unwrap_or_else(||Collection::initial(current));
        Self {path,data}
    }
    pub fn persist(&self,data:&Collection)->Result<(),String> {
        let plain=serde_json::to_vec(data).map_err(|e|e.to_string())?;
        if plain.len()>512*1024 {return Err("Profile collection is too large".into());}
        let sealed=crate::secret_store::seal(&plain).map_err(|e|e.to_string())?;
        let tmp=self.path.with_extension("bin.tmp");
        std::fs::write(&tmp,sealed).map_err(|e|e.to_string())?;
        std::fs::rename(tmp,&self.path).map_err(|e|e.to_string())
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn names_active_selection_and_secret_free_metadata() {
        let s=Collection::initial(json!({"upstream":"private"}));
        let (s,_)=s.change("save","","نام واقعی",json!({"dns":["1.1.1.1"]})).unwrap();
        assert_eq!(s.items[1].name,"نام واقعی");
        assert!(!s.view().to_string().contains("private"));
        let raw=serde_json::to_vec(&s).unwrap();let s:Collection=serde_json::from_slice(&raw).unwrap();
        let id=s.active.clone();let (s,_)=s.change("rename",&id,"کار",json!({})).unwrap();
        assert_eq!(s.items[1].name,"کار");
        assert!(s.change("rename",&id,"  ",json!({})).is_err());
        let (s,target)=s.change("delete",&id,"",json!({})).unwrap();
        assert_eq!(s.active,"default");assert!(target.is_some());
        assert!(s.change("delete","default","",json!({})).is_err());
    }
    #[test] fn custom_selection_follows_the_profile() {
        let live=CustomSel{config_id:Some("c1".into()),enabled:true,mode:"CONFIG_TOR".into(),config_name:Some("V2ray".into())};
        let s=Collection::initial(json!({}));
        let (s,_,apply)=s.change_with("save","","Work",json!({}),live.clone()).unwrap();
        assert!(apply.is_none());
        assert_eq!(s.items[1].custom.as_ref(),Some(&live));
        let (s,_,apply)=s.change_with("select","default","",json!({}),live.clone()).unwrap();
        assert_eq!(apply,Some(CustomSel::off()));
        let work=s.items[1].id.clone();
        let (_,_,apply)=s.change_with("select",&work,"",json!({}),CustomSel::off()).unwrap();
        assert_eq!(apply,Some(live));
    }
    #[test] fn default_is_locked_and_never_overwritten() {
        let s=Collection::initial(json!({}));
        assert!(s.change("rename","default","x",json!({})).is_err());
        let (s,_)=s.change("save","","Work",json!({"dns":["9.9.9.9"]})).unwrap();
        let (s,target)=s.change("select","default","",json!({"dns":["8.8.8.8"]})).unwrap();
        assert_eq!(target.unwrap(),factory_profile());
        let (s,_)=s.change("select",&s.items[1].id.clone(),"",json!({"dns":["8.8.8.8"]})).unwrap();
        assert_eq!(s.items[0].profile,json!({}));
    }
    #[test] fn export_import_round_trip_is_secret_free() {
        let s=Collection::initial(json!({}));
        let (s,_)=s.change("save","","Work",json!({})).unwrap();
        let text=s.export_selected(factory_profile(),&CustomSel::off()).unwrap();
        for k in PRIVATE_KEYS { assert!(!text.contains(&format!("\"{}\"",k))); }
        let (n,count)=s.import(&text).unwrap();
        assert_eq!(count,1);assert_eq!(n.items.len(),3);assert_eq!(n.active,s.active);
        assert!(s.import(&text.replace("schemaVersion","x")).is_err());
        assert!(s.import("{\"schemaVersion\":1,\"presets\":[{\"name\":\"a\",\"profile\":{\"upstream\":\"x\"}}]}").is_err());
    }
    #[test] fn import_selects_and_keeps_name_and_settings() {
        let s=Collection::initial(json!({}));
        let (s,_)=s.change("save","","Test",json!({})).unwrap();
        let mut live=factory_profile();live["killSwitch"]=json!(false);live["mtu"]=json!(1280);
        let text=s.export_selected(live.clone(),&CustomSel::off()).unwrap();
        let id=s.active.clone();
        let (s,_)=s.change("delete",&id,"",json!({})).unwrap();
        assert_eq!(s.active,"default");
        let (n,target,sel,count)=s.import_and_select(&text,factory_profile(),CustomSel::off()).unwrap();
        assert_eq!(count,1);
        let p=n.items.iter().find(|p|p.id==n.active).unwrap();
        assert_eq!(p.name,"Test");
        assert_eq!(target["mtu"],json!(1280));assert_eq!(target["killSwitch"],json!(false));
        assert_eq!(p.profile,target);assert_eq!(sel,CustomSel::off());
        assert!(s.import_and_select("garbage",factory_profile(),CustomSel::off()).is_err());
    }
    #[test] fn custom_block_survives_export_and_import() {
        let s=Collection::initial(json!({}));
        let (s,_)=s.change("save","","V2ray",json!({})).unwrap();
        let live=CustomSel{config_id:Some("old-id".into()),enabled:true,mode:"CONFIG_AETHER".into(),config_name:Some("My VLESS".into())};
        let text=s.export_selected(factory_profile(),&live).unwrap();
        let (n,_,sel,_)=s.import_and_select(&text,factory_profile(),CustomSel::off()).unwrap();
        assert_eq!(sel,live);assert!(n.items.iter().any(|p|p.custom.as_ref()==Some(&live)));
    }
}
