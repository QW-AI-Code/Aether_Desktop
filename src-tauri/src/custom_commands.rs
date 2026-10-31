//! ۱.۳.۰ — فرمان‌های Tauri برای صفحهٔ «کانفیگ‌های سفارشی».
//!
//! نمایی که به رابط کاربری می‌رود **هرگز** outbound یا متنِ خامِ کانفیگ را
//! ندارد؛ متنِ خام فقط با `cc_get_raw` و فقط برای کانفیگِ قفل‌نشده داده
//! می‌شود (برای ویرایش و کپیِ لینک). کانفیگِ قفل‌شدهٔ npvt نشانی، کلید و
//! متنِ خامش را هیچ‌جا نشان نمی‌دهد.
//!
//! بدونِ QR: نسخهٔ ویندوز دوربین و اسکنرِ تصویر ندارد. ورود از راهِ متن،
//! نشانیِ اشتراکِ https، انتخابِ فایل (در خودِ صفحه) و کشیدن‌ورها‌کردنِ فایل.

use crate::custom::parser::ImportError;
use crate::custom::store::{self, State as CcState};
use crate::custom::{import, now_millis, realdelay, ChainMode, CustomConfig};
use crate::mini_https::Dial;
use crate::state::ConnectionState;
use crate::AppState;
use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CcError {
    /// `password` (رمز لازم است)، `wrongPassword`، `invalid`، `locked`، `notFound`.
    pub kind: &'static str,
    pub message: String,
}

impl From<ImportError> for CcError {
    fn from(e: ImportError) -> Self {
        let kind = match e {
            ImportError::Password { wrong: false } => "password",
            ImportError::Password { wrong: true } => "wrongPassword",
            ImportError::Invalid(_) => "invalid",
        };
        CcError { kind, message: e.to_string() }
    }
}

fn not_found() -> CcError {
    CcError { kind: "notFound", message: "config not found".into() }
}

fn config_view(c: &CustomConfig, now: i64) -> Value {
    json!({
        "id": c.id,
        "name": c.name,
        "protocol": c.protocol.short(),
        "format": c.format.name(),
        "source": c.source.name(),
        // قفل‌شده: خالی (همان چیزی که انبار نگه می‌دارد).
        "server": if c.locked { String::new() } else { c.server.clone() },
        "locked": c.locked,
        "note": c.note,
        "expiresAt": c.expires_at,
        "expired": c.is_expired(now),
        "addedAt": c.added_at,
        "chainLabel": c.chain_label(),
        "endpoint": crate::custom::present::display_endpoint(c),
        "shareable": !c.locked && !c.raw.is_empty(),
    })
}

pub fn view(s: &CcState) -> Value {
    let now = now_millis();
    let active = s.active();
    // نامِ پروتکلِ کانفیگِ انتخاب‌شده (VLESS، Npvt، VMess…) جای «Config»ِ عمومی
    // می‌نشیند — همان `chainLabel` موبایل ۱.۵.۰. فقط بی‌کانفیگ «Config» می‌ماند.
    let name = active.map(|c| c.chain_label()).unwrap_or("Config");
    let modes: Vec<Value> = ChainMode::ALL
        .iter()
        .map(|m| json!({ "id": m.name(), "label": m.label(name, None), "hops": m.hops() }))
        .collect();
    json!({
        "enabled": s.enabled,
        "mode": s.mode.name(),
        "modeLabel": s.mode.label(name, None),
        "activeId": s.active_id,
        "modes": modes,
        "configs": s.configs.iter().map(|c| {let mut v=config_view(c,now);v["groupId"]=json!(s.membership.get(&c.id));v}).collect::<Vec<_>>(),
        "groups":s.groups,"tabNames":s.tab_names,"hiddenTabs":s.hidden_tabs,
        "subscriptions":s.subscriptions.iter().map(|sub|json!({"id":sub.id,"name":sub.name,"groupId":sub.group_id,"updatedAt":sub.updated_at,"count":sub.config_ids.len(),"configIds":sub.config_ids})).collect::<Vec<_>>(),
        "max": store::MAX_CONFIGS,
        "qr": false,
    })
}

pub(crate) fn publish(app: &AppHandle, s: &CcState) -> Value {
    let v = view(s);
    let _ = app.emit("aether://custom", &v);
    v
}

fn dial_for(app: &AppHandle) -> Dial {
    let st = app.state::<AppState>();
    let connected = st.latest.lock().state == ConnectionState::Connected;
    if connected {
        Dial::Socks(crate::engine::exit_socks_port())
    } else {
        Dial::Direct
    }
}

fn added(app: &AppHandle, configs: Vec<CustomConfig>, group_id: Option<String>) -> Result<Value,CcError> {
    let n = configs.len();
    let names: Vec<String> = configs.iter().map(|c| c.name.clone()).collect();
    let ids:Vec<String>=configs.iter().map(|c|c.id.clone()).collect();
    let mut error = None;
    let s = store::update(|s| {
        match s.import_into(configs, group_id.as_deref()) {
            Ok(next) => next,
            Err(message) => { error = Some(CcError { kind:"invalid", message:message.into() }); s }
        }
    });
    if let Some(e) = error { return Err(e); }
    crate::log::DiagnosticsLog::i("custom", &format!("Imported {n} custom config(s)."));
    let mut v = publish(app, &s);
    v["added"] = json!(n);
    v["addedNames"] = json!(names);
    v["addedIds"]=json!(ids);
    Ok(v)
}

fn pw(password: &Option<String>) -> Option<&str> {
    password.as_deref().filter(|p| !p.is_empty())
}

#[tauri::command]
pub fn cc_state() -> Value {
    view(&store::snapshot())
}

#[tauri::command]
pub async fn cc_import_text(
    app: AppHandle,
    text: String,
    password: Option<String>,
    group_id: Option<String>,
) -> Result<Value, CcError> {
    let dial = dial_for(&app);
    let configs = tauri::async_runtime::spawn_blocking(move || import::from_text(&text, pw(&password), dial))
        .await
        .map_err(|_| CcError { kind: "invalid", message: "import was interrupted".into() })??;
    added(&app, configs, group_id)
}

/// فایلی که خودِ صفحه با `<input type="file">` خوانده.
#[tauri::command]
pub fn cc_import_file(
    app: AppHandle,
    name: String,
    text: String,
    password: Option<String>,
    group_id: Option<String>,
) -> Result<Value, CcError> {
    let configs = import::from_file_text(&name, &text, pw(&password))?;
    added(&app, configs, group_id)
}

#[tauri::command]
pub fn cc_import_bytes(app: AppHandle, name: String, bytes: Vec<u8>, password: Option<String>, group_id: Option<String>) -> Result<Value,CcError> {
    let ext=std::path::Path::new(&name).extension().and_then(|s|s.to_str()).unwrap_or("").to_ascii_lowercase();
    if !import::FILE_EXTENSIONS.contains(&ext.as_str()) {return Err(CcError{kind:"invalid",message:"unsupported file type".into()});}
    let configs=crate::custom::parser::parse_bytes(&bytes,crate::custom::ConfigSource::File,pw(&password),now_millis())?;
    added(&app,configs,group_id)
}

/// فایلی که روی پنجره رها شده (مسیرش از رویدادِ drag-drop می‌آید).
#[tauri::command]
pub fn cc_import_path(app: AppHandle, path: String, password: Option<String>, group_id: Option<String>) -> Result<Value, CcError> {
    let configs = import::from_file(std::path::Path::new(&path), pw(&password))?;
    added(&app, configs, group_id)
}

#[tauri::command]
pub fn cc_select(app: AppHandle, id: String) -> Value {
    let s = store::update(|s| s.select(&id));
    publish(&app, &s)
}

#[tauri::command]
pub fn cc_set_mode(app: AppHandle, mode: String) -> Value {
    let m = ChainMode::from_stored_name(Some(&mode));
    let s = store::update(|s| s.set_mode(m));
    publish(&app, &s)
}

#[tauri::command]
pub fn cc_set_enabled(app: AppHandle, enabled: bool) -> Value {
    let s = store::update(|s| s.set_enabled(enabled));
    crate::log::DiagnosticsLog::i(
        "custom",
        if s.enabled { "Custom config switched on (applies from the next connection)." } else { "Custom config switched off." },
    );
    publish(&app, &s)
}

#[tauri::command]
pub fn cc_rename(app: AppHandle, id: String, name: String) -> Value {
    let s = store::update(|s| s.rename(&id, &name));
    publish(&app, &s)
}

/// متنِ قابلِ ویرایش/اشتراک؛ برای کانفیگِ قفل‌شده هرگز.
#[tauri::command]
pub fn cc_get_raw(id: String) -> Result<String, CcError> {
    let s = store::snapshot();
    let c = s.configs.iter().find(|c| c.id == id).ok_or_else(not_found)?;
    if c.locked || c.raw.is_empty() {
        return Err(CcError { kind: "locked", message: "this config is locked by its author".into() });
    }
    Ok(c.raw.clone())
}

#[tauri::command]
pub fn cc_edit(app: AppHandle, id: String, raw: String, password: Option<String>) -> Result<Value, CcError> {
    let s = store::snapshot();
    let old = s.configs.iter().find(|c| c.id == id).ok_or_else(not_found)?.clone();
    if old.locked {
        return Err(CcError { kind: "locked", message: "locked configs cannot be edited".into() });
    }
    let next = import::reparse(&old, &raw, pw(&password))?;
    let s = store::update(|s| s.replace(next));
    Ok(publish(&app, &s))
}

#[tauri::command]
pub fn cc_delete(app: AppHandle, id: String) -> Value {
    let s = store::update(|s| s.delete(&id));
    publish(&app, &s)
}

#[tauri::command]
pub fn cc_delete_all(app: AppHandle) -> Value {
    let s = store::update(|s| s.delete_all());
    crate::log::DiagnosticsLog::i("custom", "All custom configs were deleted.");
    publish(&app, &s)
}

// >>> AETHER-APP-PATCH custom-configs-real-delay
/// یک سنجشِ هم‌زمان کافی است: «Test all» دوباره زده شود، دومی منتظر نمی‌ماند.
static PING_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct PingSlot;
impl Drop for PingSlot {
    fn drop(&mut self) {
        PING_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn ping_targets(ids: Option<&[String]>) -> Vec<realdelay::Target> {
    let s = store::snapshot();
    s.configs
        .iter()
        .filter(|c| ids.map(|ids| ids.iter().any(|i| i == &c.id)).unwrap_or(true))
        .map(|c| realdelay::Target { id: c.id.clone(), name: c.name.clone(), outbound: c.outbound.clone() })
        .collect()
}

async fn ping_run(app: AppHandle, ids: Option<Vec<String>>) -> Result<Value, CcError> {
    if PING_BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err(CcError { kind: "busy", message: "a real-delay test is already running".into() });
    }
    let slot = PingSlot;
    if scan_glue::with(|l| l.running) {
        return Err(CcError { kind: "busy", message: "a clean-IP scan is running".into() });
    }
    let targets = ping_targets(ids.as_deref());
    if targets.is_empty() {
        return Err(not_found());
    }
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|e| CcError { kind: "invalid", message: e.to_string() })?;
    let install_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| data_dir.clone());
    let Some(binary) = crate::custom::process::locate(&install_dir, &data_dir) else {
        return Err(CcError {
            kind: "invalid",
            message: "the bundled Xray core (engine\\xray\\xray.exe) is missing — reinstall Aether".into(),
        });
    };
    crate::log::DiagnosticsLog::i("custom", &format!("Real delay: testing {} config(s) through a temporary Xray.", targets.len()));
    let results = tauri::async_runtime::spawn_blocking(move || {
        let _slot = slot;
        realdelay::measure(&binary, &data_dir, &targets)
    })
    .await
    .map_err(|_| CcError { kind: "invalid", message: "the test was interrupted".into() })?;
    crate::custom::selection::record(&results);
    let v = json!({ "results": results });
    let _ = app.emit("aether://custom-ping", &v);
    Ok(v)
}

/// «پینگِ واقعی» یک کانفیگ: Xrayِ موقت + `GET /generate_204` از دلِ آن.
#[tauri::command]
pub async fn cc_ping(app: AppHandle, id: String) -> Result<Value, CcError> {
    ping_run(app, Some(vec![id])).await
}

/// «Test all»: همهٔ کانفیگ‌ها، دسته‌های ۳۲تایی در یک Xray.
#[tauri::command]
pub async fn cc_ping_all(app: AppHandle) -> Result<Value, CcError> {
    ping_run(app, None).await
}
// <<< AETHER-APP-PATCH custom-configs-real-delay

// >>> AETHER-APP-PATCH custom-configs-speed-test
/// تست سرعت دانلود/آپلود (پورت `ConfigSpeedTest.kt`): همزمان فقط یکی.
static SPEED_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SPEED_RESULTS: std::sync::Mutex<Option<std::collections::BTreeMap<String, Value>>> = std::sync::Mutex::new(None);

fn speed_row(id: &str, running: bool, down: i64, up: i64) -> Value {
    json!({ "id": id, "running": running, "downloadBps": down, "uploadBps": up })
}
fn speed_store(id: &str, row: Value) {
    let mut g = SPEED_RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(Default::default).insert(id.to_string(), row);
}

#[tauri::command]
pub fn cc_speed_state() -> Value {
    let g = SPEED_RESULTS.lock().unwrap_or_else(|e| e.into_inner());
    json!({ "results": g.as_ref().map(|m| m.values().cloned().collect::<Vec<_>>()).unwrap_or_default() })
}

#[tauri::command]
pub async fn cc_speed_test(app: AppHandle, id: String) -> Result<Value, CcError> {
    let busy = |m: &str| CcError { kind: "busy", message: m.into() };
    if scan_glue::with(|l| l.running) { return Err(busy("a clean-IP scan is running")); }
    if PING_BUSY.load(std::sync::atomic::Ordering::SeqCst) { return Err(busy("a real-delay test is running")); }
    if SPEED_BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) { return Err(busy("a speed test is already running")); }
    struct Slot;
    impl Drop for Slot { fn drop(&mut self) { SPEED_BUSY.store(false, std::sync::atomic::Ordering::SeqCst); } }
    let slot = Slot;
    let Some(config) = store::snapshot().configs.into_iter().find(|c| c.id == id) else { return Err(not_found()); };
    let data_dir = app.path().app_local_data_dir().map_err(|e| CcError { kind: "invalid", message: e.to_string() })?;
    let install_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(std::path::Path::to_path_buf)).unwrap_or_else(|| data_dir.clone());
    let Some(binary) = crate::custom::process::locate(&install_dir, &data_dir) else {
        return Err(CcError { kind: "invalid", message: "the bundled Xray core (engine\\xray\\xray.exe) is missing — reinstall Aether".into() });
    };
    let running = speed_row(&id, true, -1, -1);
    speed_store(&id, running.clone());
    let _ = app.emit("aether://custom-speed", &running);
    crate::log::DiagnosticsLog::i("custom", "Speed test: measuring real throughput through a temporary Xray.");
    let outbound = config.outbound.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        let _slot = slot;
        let cancel = crate::custom::cancel::Cancel::new();
        crate::custom::speedtest::measure(&binary, &data_dir, &outbound, &cancel)
    }).await.unwrap_or_else(|_| crate::custom::speedtest::Report::none());
    let done = speed_row(&id, false, report.download_bps, report.upload_bps);
    speed_store(&id, done.clone());
    let _ = app.emit("aether://custom-speed", &done);
    Ok(done)
}
// <<< AETHER-APP-PATCH custom-configs-speed-test

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom::{ConfigFormat, ConfigProtocol, ConfigSource};

    fn cfg(id: &str, protocol: ConfigProtocol, format: ConfigFormat) -> CustomConfig {
        CustomConfig {
            id: id.into(),
            name: format!("n-{id}"),
            protocol,
            format,
            source: ConfigSource::Link,
            outbound: "{\"protocol\":\"vless\"}".into(),
            raw: String::new(),
            server: "h:1".into(),
            locked: false,
            note: String::new(),
            expires_at: 0,
            mobile_only: false,
            added_at: 5,
        }
    }

    fn labels(v: &Value) -> Vec<String> {
        v["modes"].as_array().unwrap().iter().map(|m| m["label"].as_str().unwrap().to_string()).collect()
    }

    // AETHER-APP-FIX chain-labels-name-the-protocol: پس از ورود، فهرستِ زنجیره و
    // کارتِ وضعیت نامِ پروتکل را نشان می‌دهند و نه «Config»ِ عمومی (مثلِ موبایل).
    #[test]
    fn chain_labels_name_the_imported_protocol() {
        let empty = view(&CcState::default());
        assert!(labels(&empty).iter().any(|l| l == "Config \u{2192} Tor"));

        let npvt = CcState::default()
            .add(vec![cfg("a", ConfigProtocol::Vless, ConfigFormat::Npvt)])
            .set_mode(ChainMode::ConfigTorAether);
        let v = view(&npvt);
        let l = labels(&v);
        assert!(l.iter().all(|x| !x.contains("Config")), "{l:?}");
        assert!(l.iter().any(|x| x == "Npvt \u{2192} Aether"), "{l:?}");
        assert_eq!(v["modeLabel"], "Npvt \u{2192} Tor \u{2192} Aether");

        let vmess = CcState::default().add(vec![cfg("b", ConfigProtocol::Vmess, ConfigFormat::Uri)]);
        assert!(labels(&view(&vmess)).iter().any(|x| x == "Psiphon \u{2192} VMess"));
    }
}

fn clean_name(name:&str)->Result<String,CcError> {
    let name:String=name.trim().chars().take(80).collect();
    if name.is_empty(){Err(CcError{kind:"invalid",message:"Tab name is empty".into()})}else{Ok(name)}
}
#[tauri::command]
pub fn cc_tab_save(app:AppHandle,id:Option<String>,name:String)->Result<Value,CcError> {
 let name=clean_name(&name)?;let mut full=false;
 let key=id.unwrap_or_else(||format!("user:{}",crate::custom::new_id()));
 if !["all","format:v2ray","format:npvt"].contains(&key.as_str()) && !key.starts_with("user:") && !store::snapshot().subscriptions.iter().any(|sub|sub.id==key){return Err(not_found());}
 let s=store::update(|mut s|{
    if key.starts_with("user:") && !s.groups.iter().any(|g|g.id==key) && s.groups.len()>=50 {full=true;return s;}
    if key.starts_with("user:") {if let Some(g)=s.groups.iter_mut().find(|g|g.id==key){g.name=name;}else{s.groups.push(store::Group{id:key,name});}}
    else{s.tab_names.insert(key,name);}s
 });if full{return Err(CcError{kind:"invalid",message:"Too many tabs".into()});}Ok(publish(&app,&s))
}
#[tauri::command]
pub fn cc_tab_delete(app:AppHandle,id:String)->Value {
 let s=store::update(|s|s.delete_tab(&id));publish(&app,&s)
}
#[tauri::command]
pub fn cc_move(app:AppHandle,ids:Vec<String>,group_id:Option<String>)->Result<Value,CcError> {
 let mut invalid=false;
 let s=store::update(|mut s|{if group_id.as_ref().map(|id|!s.groups.iter().any(|g|&g.id==id)).unwrap_or(false){invalid=true;return s;}for id in ids {if s.configs.iter().any(|c|c.id==id){if let Some(g)=&group_id{s.membership.insert(id,g.clone());}else{s.membership.remove(&id);}}}s});if invalid {return Err(not_found());}Ok(publish(&app,&s))
}
/// Persist URLs only inside DPAPI store; downloading/validation occurs outside transaction.
#[tauri::command]
pub async fn cc_subscription_save(app:AppHandle,id:Option<String>,url:String,name:String,group_id:Option<String>,password:Option<String>)->Result<Value,CcError> {
 if import::subscription_url(&url).is_none(){return Err(CcError{kind:"invalid",message:"Subscription requires one HTTPS URL".into()});}
 let dial=dial_for(&app);let fetch=url.clone();
 let configs=tauri::async_runtime::spawn_blocking(move||import::from_text(&fetch,pw(&password),dial)).await.map_err(|_|CcError{kind:"invalid",message:"Subscription interrupted".into()})??;
 let mut configs=configs;let mut unique=Vec::new();for c in configs.drain(..){if !unique.iter().any(|old:&CustomConfig|old.outbound==c.outbound){unique.push(c);}}let configs=unique;
 if configs.is_empty(){return Err(CcError{kind:"invalid",message:"Subscription is empty".into()});}
 let key=id.unwrap_or_else(||format!("sub:{}",crate::custom::new_id()));let name=clean_name(&name)?;
 // Check current state after download, not a stale pre-download snapshot.
 let mut error=None;
 let s=store::update(|mut s|{
  if group_id.as_ref().map(|id|!s.groups.iter().any(|g|&g.id==id)).unwrap_or(false){error=Some(not_found());return s;}
  let previous=s.subscriptions.iter().find(|sub|sub.id==key).cloned();
  let old_ids=previous.as_ref().map(|sub|sub.config_ids.clone()).unwrap_or_default();
  let old_configs:Vec<_>=s.configs.iter().filter(|c|old_ids.contains(&c.id)).cloned().collect();
  let other=s.configs.iter().filter(|c|!old_ids.contains(&c.id)).count();
  if other+configs.len()>store::MAX_CONFIGS {error=Some(CcError{kind:"invalid",message:"Too many configs (maximum 500)".into()});return s;}
  s.configs.retain(|c|!old_ids.contains(&c.id));let mut ids=Vec::new();
  for mut c in configs {if let Some(old)=old_configs.iter().find(|o|o.outbound==c.outbound){c.id=old.id.clone();c.added_at=old.added_at;}
   if !ids.contains(&c.id) {ids.push(c.id.clone());if let Some(g)=&group_id{s.membership.entry(c.id.clone()).or_insert(g.clone());}s.configs.push(c);}}
  s.membership.retain(|id,_|s.configs.iter().any(|c|&c.id==id));
  if !s.configs.iter().any(|c|Some(&c.id)==s.active_id.as_ref()){s.active_id=ids.first().cloned();}
  s.subscriptions.retain(|sub|sub.id!=key);s.subscriptions.push(store::Subscription{id:key,name,url,group_id,updated_at:now_millis(),config_ids:ids});s
 });if let Some(e)=error{return Err(e);}Ok(publish(&app,&s))
}
#[tauri::command]
pub async fn cc_subscription_refresh(app:AppHandle,id:String,password:Option<String>)->Result<Value,CcError> {
 let sub=store::snapshot().subscriptions.into_iter().find(|s|s.id==id).ok_or_else(not_found)?;
 cc_subscription_save(app,Some(id),sub.url,sub.name,sub.group_id,password).await
}
#[tauri::command]
pub fn cc_subscription_delete(app:AppHandle,id:String)->Value {
 let s=store::update(|mut s|{if let Some(sub)=s.subscriptions.iter().find(|sub|sub.id==id).cloned(){for id in sub.config_ids {s=s.delete(&id);}s.subscriptions.retain(|sub|sub.id!=id);}s});publish(&app,&s)
}

#[tauri::command]
pub fn cc_read_qr_image(path:String)->Result<Vec<u8>,CcError>{use std::io::Read;let p=std::path::Path::new(&path);let ext=p.extension().and_then(|e|e.to_str()).unwrap_or("").to_ascii_lowercase();if !["png","jpg","jpeg","webp"].contains(&ext.as_str()){return Err(CcError{kind:"invalid",message:"Unsupported QR image".into()});}let f=std::fs::File::open(p).map_err(|_|not_found())?;if !f.metadata().map(|m|m.is_file()&&m.len()<=10*1024*1024).unwrap_or(false){return Err(CcError{kind:"invalid",message:"QR image is too large or not a file".into()});}let mut b=vec![];f.take(10*1024*1024+1).read_to_end(&mut b).map_err(|_|not_found())?;if b.len()>10*1024*1024{return Err(not_found());}Ok(b)}

// >>> AETHER-APP-PATCH clean-ip-scanner (1.4.0)
// اسکنر IP تمیز Cloudflare — پورت `CleanIpScanManager.kt`. موتور و کاوش در
// `custom/cleanip.rs` است؛ این‌جا فقط چسب Tauri: گزینه‌ها، چرخهٔ عمر، رویدادها.
mod scan_glue {
    use super::*;
    use crate::custom::cancel::Cancel;
    use crate::custom::cleanip::{self as cip, Backend, Candidate, Options, Outcome, Pick, Space};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    pub const OPTIONS_KEY: &str = "cleanip.options";
    const NOTICE_LIMIT: usize = 24;

    #[derive(Default)]
    pub struct Live {
        pub running: bool,
        pub progress: u32,
        pub validating: bool,
        pub applied: usize,
        pub completed: usize,
        pub total: usize,
        pub target_id: Option<String>,
        pub message: String,
        pub results: Vec<Value>,
        pub cancel: Option<Arc<Cancel>>,
        pub seq: u64,
    }
    pub static LIVE: Mutex<Option<Live>> = Mutex::new(None);

    pub fn with<R>(f: impl FnOnce(&mut Live) -> R) -> R {
        let mut g = LIVE.lock().unwrap_or_else(|e| e.into_inner());
        f(g.get_or_insert_with(Live::default))
    }

    pub fn view() -> Value {
        with(|l| json!({
            "running": l.running, "progress": l.progress, "validating": l.validating,
            "applied": l.applied, "completed": l.completed, "total": l.total,
            "targetId": l.target_id, "message": l.message, "results": l.results,
        }))
    }

    pub fn publish(app: &AppHandle) { let _ = app.emit("aether://cleanip", view()); }

    pub fn load_options(app: &AppHandle) -> Options {
        let Ok(dir) = app.path().app_local_data_dir() else { return Options::default() };
        crate::store::PrefsStore::new(&dir)
            .get_string(OPTIONS_KEY)
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .map(|v| Options::from_json(&v))
            .unwrap_or_default()
    }

    pub fn save_options(app: &AppHandle, o: &Options) -> Result<(), CcError> {
        let dir = app.path().app_local_data_dir().map_err(|e| CcError { kind: "invalid", message: e.to_string() })?;
        std::fs::create_dir_all(&dir).map_err(|e| CcError { kind: "invalid", message: e.to_string() })?;
        crate::store::PrefsStore::new(&dir)
            .set_string(OPTIONS_KEY, &o.to_json().to_string())
            .map_err(|e| CcError { kind: "invalid", message: e.to_string() })
    }

    pub fn idle(app: &AppHandle) -> bool {
        matches!(app.state::<AppState>().latest.lock().state, ConnectionState::Disconnected | ConnectionState::Failed)
    }

    pub struct Real {
        pub app: AppHandle,
        pub cancel: Arc<Cancel>,
        pub options: Options,
        pub space: Space,
        pub binary: std::path::PathBuf,
        pub data_dir: std::path::PathBuf,
    }

    impl Backend for Real {
        fn current(&self) -> Vec<CustomConfig> { store::snapshot().configs }
        fn allowed(&self) -> bool { idle(&self.app) }
        fn discover(&self, config: &CustomConfig, excluded: &HashSet<String>, progress: &(dyn Fn(u32) + Sync)) -> Vec<Candidate> {
            if !self.allowed() { return vec![]; }
            let Some(endpoint) = cip::describe(&config.outbound) else { return vec![] };
            let p = self.options.profile;
            let mut ports: Vec<u16> = if endpoint.tls { vec![endpoint.port] } else { vec![] };
            for d in cip::DEFAULT_PORTS { if !ports.contains(&d) { ports.push(d); } }
            let counters = cip::Counters::default();
            let (timeout, tries) = (p.timeout_ms(), p.probes_per_ip());
            let prober = |ip: &str| cip::probe_best(&self.cancel, ip, &ports, timeout, tries, &counters);
            let params = cip::PoolParams {
                count: cip::MAX_CANDIDATES, ports: ports.clone(), parallelism: p.parallelism(),
                candidate_budget: p.candidate_budget(), neighbor_per_hit: p.neighbor_per_hit(), max_rounds: 10,
            };
            let pool = cip::scan_pool(&self.cancel, &self.space, &params, excluded, &prober, progress);
            pool.into_iter().map(|r| Candidate { ip: r.ip, port: cip::applicable_port(&endpoint, r.port) }).collect()
        }
        fn measure(&self, config: &CustomConfig, candidates: &[Candidate]) -> Vec<i64> {
            if !self.allowed() || self.cancel.stopped() { return vec![-1; candidates.len()]; }
            let targets: Vec<realdelay::Target> = candidates.iter().enumerate().filter_map(|(i, c)| {
                cip::replace_endpoint(&self.space, &config.outbound, &c.ip, c.port).ok()
                    .map(|outbound| realdelay::Target { id: format!("scan-{i}"), name: format!("scan-{i}"), outbound })
            }).collect();
            if targets.len() != candidates.len() { return vec![-1; candidates.len()]; }
            let rows = realdelay::measure_cancellable(&self.binary, &self.data_dir, &targets, &self.cancel);
            candidates.iter().enumerate().map(|(i, _)| {
                rows.iter().find(|d| d.id == format!("scan-{i}"))
                    .filter(|d| d.status == realdelay::Verdict::Ok).map(|d| d.ms).unwrap_or(-1)
            }).collect()
        }
        fn commit(&self, expected: &CustomConfig, pick: &Pick) -> Result<(), String> {
            if !self.allowed() || self.cancel.stopped() { return Err("not allowed".into()); }
            let next = cip::rewritten(&self.space, expected, pick).map_err(|e| e.to_string())?;
            let s = store::update_checked(|s| {
                // فقط اگر کانفیگ هنوز همان است که اسکن شد؛ ویرایش هم‌زمان کاربر پایمال نمی‌شود.
                (s.configs.iter().find(|c| c.id == expected.id) == Some(expected)).then(|| s.clone().replace(next.clone()))
            })?;
            let _ = self.app.emit("aether://custom", &super::view(&s));
            let row = realdelay::Delay { id: expected.id.clone(), ms: pick.ping_ms, status: realdelay::Verdict::Ok, label: "OK" };
            crate::custom::selection::record(std::slice::from_ref(&row));
            let _ = self.app.emit("aether://custom-ping", &json!({ "results": [row] }));
            Ok(())
        }
    }

    pub fn start(app: AppHandle, ids: Option<Vec<String>>) -> Result<Value, CcError> {
        let busy = |m: &str| CcError { kind: "busy", message: m.into() };
        if with(|l| l.running) { return Err(busy("a scan is already running")); }
        if !idle(&app) { return Err(busy("disconnect before scanning")); }
        if PING_BUSY.load(std::sync::atomic::Ordering::SeqCst) { return Err(busy("a real-delay test is running")); }
        let snapshot = store::snapshot();
        let now = now_millis();
        let targets: Vec<CustomConfig> = snapshot.configs.iter()
            .filter(|c| ids.as_ref().map(|v| v.contains(&c.id)).unwrap_or(true))
            .filter(|c| cip::supported(c, now)).cloned().collect();
        if targets.is_empty() { return Err(CcError { kind: "empty", message: "no scannable config".into() }); }
        let options = load_options(&app);
        let space = if options.custom_enabled {
            let ranges = cip::parse_ranges(&options.custom_ranges).ranges;
            if ranges.is_empty() { return Err(CcError { kind: "ranges", message: "custom ranges are enabled but none is valid".into() }); }
            Space { custom: ranges }
        } else { Space::default() };
        let data_dir = app.path().app_local_data_dir().map_err(|e| CcError { kind: "invalid", message: e.to_string() })?;
        let install_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(std::path::Path::to_path_buf)).unwrap_or_else(|| data_dir.clone());
        let Some(binary) = crate::custom::process::locate(&install_dir, &data_dir) else {
            return Err(CcError { kind: "invalid", message: "the bundled Xray core (engine\\xray\\xray.exe) is missing — reinstall Aether".into() });
        };
        let cancel = Cancel::new();
        with(|l| {
            let seq = l.seq + 1;
            *l = Live { running: true, total: targets.len(), target_id: targets.first().map(|c| c.id.clone()), cancel: Some(cancel.clone()), seq, ..Live::default() };
        });
        publish(&app);
        let app2 = app.clone();
        let ceiling = options.manual.then_some(options.ceiling);
        let real = Real { app: app.clone(), cancel: cancel.clone(), options, space, binary, data_dir };
        std::thread::Builder::new().name("aether-cleanip".into()).spawn(move || {
            // اتصال شروع شد → اسکن لغو می‌شود (موبایل: watcher روی AetherController.state).
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let watcher = { let (a, c, d) = (app2.clone(), cancel.clone(), done.clone());
                std::thread::spawn(move || { while !d.load(std::sync::atomic::Ordering::SeqCst) {
                    if !idle(&a) { c.cancel(); break; }
                    std::thread::sleep(std::time::Duration::from_millis(300)); } }) };
            crate::log::DiagnosticsLog::i("custom", &format!("Clean-IP scan: {} config(s).", targets.len()));
            let a = app2.clone();
            cip::run(&cancel, &real, &targets, ceiling,
                &|p| { with(|l| { if l.target_id.as_deref() != Some(&p.target_id) { l.progress = 0; }
                    l.progress = l.progress.max(p.percent); l.target_id = Some(p.target_id.clone()); l.validating = p.validating; l.completed = p.completed; });
                    publish(&a); },
                &|r| { with(|l| {
                    if r.outcome == Outcome::Applied { l.applied += 1; }
                    l.completed += 1;
                    l.results.push(json!({ "id": r.config_id, "protocol": r.protocol, "previous": r.previous,
                        "next": r.next, "pingMs": r.ping_ms, "outcome": r.outcome.name() }));
                    if l.results.len() > NOTICE_LIMIT { l.results.remove(0); } });
                    publish(&a); });
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = watcher.join();
            let stopped = cancel.stopped();
            with(|l| { l.running = false; l.validating = false; l.target_id = None; l.cancel = None;
                if !stopped { l.progress = 100; }
                l.message = if stopped { "cancelled".into() } else { "finished".into() }; });
            publish(&app2);
        }).map_err(|e| { with(|l| l.running = false); CcError { kind: "invalid", message: e.to_string() } })?;
        Ok(view())
    }
}

#[tauri::command]
pub fn cc_scan_options(app: AppHandle) -> Value {
    let o = scan_glue::load_options(&app);
    let mut v = o.to_json();
    let p = crate::custom::cleanip::parse_ranges(&o.custom_ranges);
    v["profiles"] = json!(["FAST", "BALANCED", "DEEP"].iter().map(|n| {
        let pr = crate::custom::cleanip::ScanProfile::from_name(Some(n));
        json!({ "id": n, "candidates": pr.candidate_budget(), "timeoutMs": pr.timeout_ms(), "probes": pr.probes_per_ip(), "parallel": pr.parallelism() })
    }).collect::<Vec<_>>());
    v["rangeCount"] = json!(p.ranges.len());
    v["rangeTotal"] = json!(crate::custom::cleanip::total(&p.ranges));
    v["rangeInvalid"] = json!(p.invalid);
    v
}

#[tauri::command]
pub fn cc_scan_set_options(app: AppHandle, options: Value) -> Result<Value, CcError> {
    if scan_glue::with(|l| l.running) {
        return Err(CcError { kind: "busy", message: "options are locked while a scan runs".into() });
    }
    let o = crate::custom::cleanip::Options::validate_strict(&options).map_err(|m| CcError { kind: "invalid", message: m.into() })?;
    scan_glue::save_options(&app, &o)?;
    Ok(cc_scan_options(app))
}

#[tauri::command]
pub fn cc_scan_state() -> Value { scan_glue::view() }

#[tauri::command]
pub fn cc_scan_start(app: AppHandle, ids: Option<Vec<String>>) -> Result<Value, CcError> { scan_glue::start(app, ids) }

#[tauri::command]
pub fn cc_scan_stop(app: AppHandle) -> Value {
    scan_glue::with(|l| { if let Some(c) = &l.cancel { c.cancel(); } });
    scan_glue::publish(&app);
    scan_glue::view()
}

#[tauri::command]
pub fn cc_scan_dismiss(app: AppHandle, id: Option<String>) -> Value {
    scan_glue::with(|l| match &id { Some(id) => l.results.retain(|r| r["id"] != json!(id)), None => { l.results.clear(); l.message.clear(); } });
    scan_glue::publish(&app);
    scan_glue::view()
}
// <<< AETHER-APP-PATCH clean-ip-scanner
