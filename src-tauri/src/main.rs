#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Aether Desktop — entry point.
//!
//! Module mapping from Android to Windows:
//!   MainActivity / AetherApp -> main.rs
//!   AetherController         -> state.rs
//!   AetherVpnService         -> tun.rs + sysproxy.rs + share.rs + leakguard.rs
//!   AetherProcess            -> engine.rs
//!   Profile                  -> profile.rs
//!   ProfileStore             -> store.rs
//!   NetProbe / PortProbe     -> probe.rs
//!   SmartAuto                -> smart_auto.rs
//!   Diagnostics              -> diagnostics.rs
//!   DiagnosticsLog           -> log.rs
//!   ai/AiSession + GeminiClient -> ai_session.rs + ai_client.rs (+ ai_* siblings)
//!   data/SecretStore         -> secret_store.rs (DPAPI instead of Keystore)
//!   custom/* (1.5.0)          -> custom/*.rs + state_custom.rs + custom_commands.rs (Xray as engine\xray\xray.exe; no QR)

mod ai_client;
mod ai_gate;
mod ai_http;
mod ai_model_policy;
mod ai_patch;
mod ai_prompts;
mod ai_redaction;
mod ai_session;
mod ai_topic;
mod diagnostics;
mod engine;
mod exit_regions;
mod filedrop;
// >>> AETHER-APP-PATCH endpoint-is-the-first-hop
mod firsthop;
// >>> AETHER-APP-PATCH the-flag-is-already-on-disk
mod geoip;
// <<< AETHER-APP-PATCH the-flag-is-already-on-disk
// <<< AETHER-APP-PATCH endpoint-is-the-first-hop
mod budgets;
// >>> AETHER-APP-PATCH custom-configs (mobile 1.5.0 `custom/*`, no QR on Windows)
mod custom;
mod custom_commands;
// <<< AETHER-APP-PATCH custom-configs
mod leakguard;
mod log;
mod login_code;
mod mini_https;
mod ping;
mod uplink;
mod uplink_policy;
mod probe;
mod procguard;
mod profile;
mod provenance;
pub mod presets;
mod savedialog;
mod pt;
mod secret_store;
mod share;
mod share_guard;
mod share_pages;
mod smart_auto;
mod smart_plus;
mod smart_lists;
mod smart_routes;
mod state;
mod store;
mod sysproxy;
mod tor_bootstrap;
mod zt_signin;
mod zt_web;
// >>> AETHER-APP-PATCH tor-native-carrier
// tor.exe رسمی به‌عنوان فرزندِ نظارت‌شده؛ دلیلش در سرِ خودِ ماژول.
mod tor_native;
mod tor_relay;
// <<< AETHER-APP-PATCH tor-native-carrier
mod tun;
mod window;

use ai_session::{AiSession, AiSnapshot};
use profile::ConnectionProfile;
use state::{AetherController, Snapshot};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};

/// The in-app updater was removed in 1.2.2; only a read-only link remains.
pub const RELEASES_URL: &str = "https://github.com/QW-AI-Code/Aether_Desktop/releases";

/// How often the controller is stepped. Same ~5x/second cap as Android.
const TICK: Duration = Duration::from_millis(200);

pub struct AppState {
    controller: Mutex<AetherController>,
    presets: Mutex<presets::PresetStore>,
    /// The most recent snapshot, readable WITHOUT the controller lock.
    ///
    /// # Why this cache exists
    ///
    /// Every UI read used to take the controller mutex, and the mutex is held by
    /// whatever slow thing the controller is currently doing — a `netsh` rule, a
    /// registry write, a process teardown. So the panel that was only asking
    /// "what is the state?" queued behind work it had nothing to do with, and the
    /// window stopped answering. Reads are served from here instead; only writes
    /// touch the controller.
    latest: parking_lot::Mutex<Arc<Snapshot>>,
    /// The AI layer. `Arc` because every network-facing AI command hands it to a
    /// worker thread — see [`ai_session`] for why none of that work may happen
    /// on the IPC thread.
    ai: Arc<AiSession>,
}

/// A failed background bootstrap must reach the UI rather than leave a blank window.
#[derive(Default)]
struct StartupStatus(parking_lot::Mutex<Option<String>>);

#[tauri::command]
async fn startup_ready(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let began = Instant::now();
        loop {
            if app.try_state::<AppState>().is_some() { return Ok(()); }
            if let Some(status) = app.try_state::<StartupStatus>() {
                if let Some(error) = status.0.lock().clone() { return Err(error); }
            }
            if began.elapsed() > Duration::from_secs(90) {
                return Err("Aether initialization timed out; restart the app and check diagnostics".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }).await.map_err(|_| "Startup worker interrupted".to_owned())?
}

/// Publishes a snapshot: refresh the lock-free cache, and push it to the UI only
/// if it actually differs from the last thing the UI was told.
/// کمترین فاصلهٔ بین دو انتشارِ snapshot به رابط کاربری.
///
/// # چرا این لازم است، در حالی که `publish` «فقط در صورت تغییر» می‌فرستد
///
/// آن محافظ در حالت **قطع** کار می‌کرد و در حالت **متصل** بی‌اثر بود:
/// `Snapshot` شامل `uptime_secs`، `rx_bytes` و `tx_bytes` است و هر سه در هر
/// تیک عوض می‌شوند. یعنی به‌محض برقراری اتصال، همان پنج انتشار در ثانیه
/// برمی‌گشت — و هر انتشار یک سریال‌سازیِ JSON، یک عبور از مرز IPC، و یک
/// رنگ‌آمیزیِ کاملِ صفحهٔ خانه بود. همان چیزی که کاربر به‌عنوان «مصرف CPU پس از
/// Connect» گزارش کرد.
///
/// تیکِ کنترل روی ۲۰۰ms می‌ماند و دست نمی‌خورد: پاسخِ دکمه، واچ‌داگ و
/// نظارتِ پردازه به آن بسته‌اند. تنها چیزی که کند می‌شود، *گفتنِ* وضعیت به
/// رابط کاربری است، و آن هم فقط وقتی چیزِ معناداری عوض نشده باشد.
///
/// ۵۰۰ms و نه بیشتر: تنها چیزی که در این فاصله دیده می‌شود ساعتِ نشست است
/// (`HH:MM:SS`) و با دو انتشار در ثانیه هیچ ثانیه‌ای از قلم نمی‌افتد.
const UI_MIN_INTERVAL: Duration = Duration::from_millis(500);

/// آیا این snapshot چیزی جز شمارنده‌های همیشه‌درحال‌تغییر را عوض کرده؟
///
/// مقایسه روی کپی‌ای انجام می‌شود که سه فیلدِ پرنوسان در آن صفر شده‌اند. هر
/// تغییرِ دیگری — حالت، خطا، اندپوینت، پروتکل، تأخیر، آی‌پی، گارد نشتی، درصد
/// تور — «معنادار» است و فوراً می‌رود.
fn only_counters_changed(previous: Option<&Snapshot>, next: &Snapshot) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    let strip = |s: &Snapshot| {
        let mut c = s.clone();
        c.uptime_secs = 0;
        c.rx_bytes = 0;
        c.tx_bytes = 0;
        c
    };
    strip(previous) == strip(next)
}

fn publish(
    app: &AppHandle,
    state: &AppState,
    snapshot: Snapshot,
    last: &mut Option<Arc<Snapshot>>,
    last_emit_at: &mut Option<Instant>,
) {
    let snapshot = Arc::new(snapshot);
    // `latest` همیشه و بی‌قید تازه می‌شود: `get_snapshot` از همین می‌خواند و
    // نباید هرگز مقدارِ خفه‌شده ببیند.
    *state.latest.lock() = snapshot.clone();
    if last.as_deref() == Some(snapshot.as_ref()) {
        return;
    }
    // چیزی جز شمارنده‌ها عوض نشده و هنوز نوبتِ انتشار نرسیده؟ رد کن. مقدار
    // در `latest` نشسته و انتشارِ بعدی همان تازه‌ترین را می‌برد، پس هیچ چیزی
    // گم نمی‌شود — فقط دیرتر گفته می‌شود.
    if only_counters_changed(last.as_deref(), snapshot.as_ref()) {
        if let Some(at) = last_emit_at {
            if at.elapsed() < UI_MIN_INTERVAL {
                return;
            }
        }
    }
    *last = Some(snapshot.clone());
    *last_emit_at = Some(Instant::now());
    let _ = app.emit("aether://state", snapshot.as_ref());
}

#[tauri::command]
fn get_snapshot(app: State<'_, AppState>) -> Snapshot {
    // Lock-free by design — see [`AppState::latest`].
    app.latest.lock().as_ref().clone()
}

#[tauri::command]
fn get_profile(app: State<'_, AppState>) -> ConnectionProfile {
    app.controller.lock().unwrap().profile()
}

#[tauri::command]
fn set_profile(app: State<'_, AppState>, profile: ConnectionProfile) -> Result<(), String> {
    app.controller
        .lock()
        .unwrap()
        .set_profile(profile)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn preset_state(app: State<'_, AppState>) -> serde_json::Value {
    app.presets.lock().unwrap().data.view()
}

#[tauri::command]
fn preset_action(handle: AppHandle, app: State<'_, AppState>, action:String,
    id:Option<String>, name:Option<String>) -> Result<serde_json::Value,String> {
    let mut controller=app.controller.lock().map_err(|_|"Controller unavailable")?;
    if !matches!(controller.snapshot().state, state::ConnectionState::Disconnected | state::ConnectionState::Failed) {
        return Err("Disconnect before changing connection profiles".into());
    }
    let current=controller.profile();
    let mut store=app.presets.lock().map_err(|_|"Profile store unavailable")?;
    let live_custom=presets::CustomSel::from_state(&custom::store::snapshot());
    let (next,target,custom_apply)=store.data.change_with(&action,id.as_deref().unwrap_or(""),name.as_deref().unwrap_or(""),
        serde_json::to_value(&current).map_err(|e|e.to_string())?,live_custom)?;
    // Validate the target before writing either store. Secrets keep the existing
    // controller semantics (they are not serialized into settings snapshots).
    let target=target.map(serde_json::from_value::<ConnectionProfile>).transpose().map_err(|e|e.to_string())?;
    if let Some(profile)=target {
        // The clean "default" profile also clears in-memory Zero Trust secrets;
        // set_profile treats an empty secret as "keep", which would leak the
        // previous profile's token into the factory settings.
        let is_factory=serde_json::to_value(&profile).ok().as_ref()==Some(&presets::factory_profile());
        if is_factory { controller.reset_profile().map(|_|()).map_err(|e|e.to_string())?; }
        else { controller.set_profile(profile).map_err(|e|e.to_string())?; }
    }
    if let Err(error)=store.persist(&next) {
        let _=controller.set_profile(current);
        return Err(error);
    }
    store.data=next;
    if let Some(sel)=custom_apply {
        let s=sel.apply();
        let _=handle.emit("aether://custom", &custom_commands::view(&s));
    }
    let profile=controller.profile();
    let _=handle.emit("aether://profile", &profile);
    Ok(store.data.view())
}

/// Non-secret export of the selected (active) profile as JSON text.
#[tauri::command]
fn preset_export(app: State<'_, AppState>) -> Result<String,String> {
    let current=app.controller.lock().map_err(|_|"Controller unavailable")?.profile();
    let store=app.presets.lock().map_err(|_|"Profile store unavailable")?;
    let live=presets::CustomSel::from_state(&custom::store::snapshot());
    store.data.export_selected(serde_json::to_value(&current).map_err(|e|e.to_string())?,&live)
}

/// Export with a native "Save as" dialog. Returns the saved file name, or
/// `null` when the user cancelled (nothing is written in that case).
#[tauri::command]
async fn preset_export_save(window: tauri::WebviewWindow, app: State<'_, AppState>) -> Result<Option<String>,String> {
    let text=preset_export(app)?;
    let owner=window.hwnd().map(|h|h.0 as isize).unwrap_or(0);
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path)=savedialog::pick_save_path(owner,"Aether-1.4.0-profile.json")? else { return Ok(None) };
        std::fs::write(&path,text.as_bytes()).map_err(|e|format!("Could not save the file: {e}"))?;
        Ok(path.file_name().map(|n|n.to_string_lossy().into_owned()))
    }).await.map_err(|e|e.to_string())?
}

/// Imports profiles from JSON text. The first imported profile keeps its exact
/// name, becomes the active profile and its saved settings are applied right
/// away. While a connection is running (settings must not change underneath
/// it) the profiles are only appended and `applied` is `false`.
#[tauri::command]
fn preset_import(handle: AppHandle, app: State<'_, AppState>, text:String) -> Result<serde_json::Value,String> {
    let mut controller=app.controller.lock().map_err(|_|"Controller unavailable")?;
    let idle=matches!(controller.snapshot().state, state::ConnectionState::Disconnected | state::ConnectionState::Failed);
    let mut store=app.presets.lock().map_err(|_|"Profile store unavailable")?;
    if !idle {
        let (next,_count)=store.data.import(&text)?;
        store.persist(&next)?;
        store.data=next;
        let mut view=store.data.view();view["applied"]=serde_json::json!(false);
        return Ok(view);
    }
    let current=controller.profile();
    let live_custom=presets::CustomSel::from_state(&custom::store::snapshot());
    let (next,target,sel,_count)=store.data.import_and_select(&text,
        serde_json::to_value(&current).map_err(|e|e.to_string())?,live_custom)?;
    let profile:ConnectionProfile=serde_json::from_value(target).map_err(|e|e.to_string())?;
    // Same path as selecting a profile: validate, apply, persist, roll back on failure.
    let is_factory=serde_json::to_value(&profile).ok().as_ref()==Some(&presets::factory_profile());
    if is_factory { controller.reset_profile().map(|_|()).map_err(|e|e.to_string())?; }
    else { controller.set_profile(profile).map_err(|e|e.to_string())?; }
    if let Err(error)=store.persist(&next) {
        let _=controller.set_profile(current);
        return Err(error);
    }
    store.data=next;
    let s=sel.apply();
    let _=handle.emit("aether://custom", &custom_commands::view(&s));
    let _=handle.emit("aether://profile", &controller.profile());
    let mut view=store.data.view();view["applied"]=serde_json::json!(true);
    Ok(view)
}

/// v8: "Reset to defaults" - persists the factory profile and returns it
/// so the UI can re-render immediately. UI language is left untouched.
///
/// v10: goes through the controller's dedicated reset path so the in-memory
/// Zero Trust secrets are cleared too (a plain set_profile treats an empty
/// secret as "keep the current one" and would silently retain the token).
#[tauri::command]
fn reset_profile(app: State<'_, AppState>) -> Result<ConnectionProfile, String> {
    app.controller
        .lock()
        .unwrap()
        .reset_profile()
        .map_err(|e| e.to_string())
}

/// Equivalent of `onToggleConnection` in HomeScreen.kt.
///
/// Records the intent, repaints, returns. The connect/disconnect work itself
/// happens on the controller's own thread — see `state::Intent` for the root
/// cause. This command used to run the whole thing inline, which is why the
/// button, the spinner and the whole window sat still for seconds after a tap.
#[tauri::command]
fn toggle_connection(handle: AppHandle, app: State<'_, AppState>) -> Result<(), String> {
    let snapshot = {
        let mut c = app.controller.lock().unwrap();
        c.request_toggle();
        c.snapshot()
    };
    // Push the new phase to the UI immediately: the tick thread is about to be
    // busy tearing down or starting up, and the user must see that instantly.
    let cached = Arc::new(snapshot);
    *app.latest.lock() = cached.clone();
    let _ = handle.emit("aether://state", cached.as_ref());
    Ok(())
}

#[tauri::command]
fn read_logs(limit: Option<usize>) -> Vec<String> {
    log::DiagnosticsLog::tail(limit.unwrap_or(800))
}

/// Equivalent of the Android "Copy logs" button — full text for the clipboard.
#[tauri::command]
fn export_logs() -> String {
    log::DiagnosticsLog::export_text()
}

#[tauri::command]
fn clear_logs() {
    log::DiagnosticsLog::clear();
}

/// Live state of the 4 checks — equivalent of the check StateFlows in Diagnostics.kt.
#[tauri::command]
fn get_checks() -> Vec<log::ComponentCheck> {
    log::DiagnosticsLog::checks()
}

/// Equivalent of the Android "Run test" button — runs in a background thread
/// so the UI never freezes; live results arrive via get_checks/read_logs.
#[tauri::command]
fn run_self_test() {
    std::thread::Builder::new()
        .name("aether-manual-test".into())
        .spawn(|| {
            diagnostics::self_test(20_000);
        })
        .ok();
}

/// Environment report (binary/driver/permissions) — complements the mobile-style self-test.
#[tauri::command]
fn run_diagnostics(app: State<'_, AppState>) -> diagnostics::Report {
    let profile = app.controller.lock().unwrap().profile();
    diagnostics::run(&profile)
}

/// v1.2.0 — دکمهٔ «آزمایش نشتی WebRTC» در پنل عیب‌یابی.
///
/// همان کاری که یک صفحهٔ وب با WebRTC می‌کند: یک درخواست STUN روی UDP خام.
/// اگر آی‌پی برگشته با آی‌پی خروجی تونل یکی نباشد، یعنی نشتی واقعی است.
#[tauri::command]
fn webrtc_leak_test(app: State<'_, AppState>) -> diagnostics::LeakReport {
    let exit = app
        .controller
        .lock()
        .unwrap()
        .snapshot()
        .ip_info
        .and_then(|i| if i.via_tunnel { Some(i.ip) } else { None });
    diagnostics::webrtc_leak_check(exit.as_deref())
}

#[tauri::command]
fn about_info() -> serde_json::Value {
    serde_json::json!({
        "appVersion": env!("CARGO_PKG_VERSION"),
        "coreVersion": core_version(),
        "arch": std::env::consts::ARCH,
        "releasesUrl": RELEASES_URL,
    })
}

/// v10: قابلیت‌های هستهٔ همراه — UI با این تصمیم می‌گیرد که بخش‌های
/// Zero Trust / مسیریابی / DNS را فعال نشان بدهد یا با توضیح غیرفعال.
/// بدون این، کاربرِ هستهٔ پین‌شدهٔ قدیمی تنطیمی را پر می‌کرد که بی‌اثر بود.
/// v11: پروکسی بالادست و تشخیص نام میزبان (هستهٔ 1.7.0) هم همین‌جا گزارش
/// می‌شوند تا پنل پیشرفته آن‌ها را روی هستهٔ قدیمی‌تر خاکستری کند.
#[tauri::command]
fn core_caps() -> serde_json::Value {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("engine").join("aether.exe")))
        .unwrap_or_default();
    let caps = engine::engine_caps(&exe);
    serde_json::json!({
        "zeroTrust": caps.zero_trust,
        "routing": caps.routing,
        "customDns": caps.custom_dns,
        "upstream": caps.upstream,
        "routeSniff": caps.route_sniff,
        // ۱.۲.۵ — بدون این، پنل چهار بک‌اند تور را روی هستهٔ قدیمی هم پیشنهاد
        // می‌داد و کاربر تنظیمی را پر می‌کرد که هرگز به موتور نمی‌رسد.
        "tor": caps.tor,
        // Core 2.4.0 — TLS fingerprint / API routing options.
        "tls24": caps.tls24,
    })
}

fn core_version() -> String {
    // Placed next to aether.exe (equivalent of assets/CORE_VERSION on Android).
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("engine").join("CORE_VERSION")))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ===========================================================================
//  v12 — لایهٔ هوش مصنوعی
// ===========================================================================
//
// # چرا هر فرمانِ شبکه‌ای اینجا `async` است و کار را spawn_blocking می‌کند
//
// یک فراخوان جمینای از **دو** تونل رد می‌شود و می‌تواند ده‌ها ثانیه طول بکشد.
// فرمان‌های Tauri روی رشتهٔ IPC اجرا می‌شوند؛ کارِ همگام آنجا یعنی پنجره تا
// برگشتن پاسخ جواب ندهد — همان بیماری‌ای که `AppState::latest` برای درمانش وجود
// دارد، فقط این بار با تأخیرِ صدبرابر. پس هر مسیری که به سوکت دست می‌زند به
// استخر بلاک‌کننده می‌رود و رشتهٔ IPC فوراً آزاد می‌شود.
//
// # چرا پروفایل و وضعیت *پیش از* پرش خوانده می‌شوند
//
// `State<'_, AppState>` را نمی‌توان به یک تسک `'static` برد، و مهم‌تر: قفل
// کنترلر نباید در طول یک فراخوان شبکه نگه داشته شود. یک `advise` که ۴۰ ثانیه
// طول بکشد و قفل را داشته باشد، کل برنامه را برای ۴۰ ثانیه می‌خواباند. پس یک
// کپی از پروفایل گرفته می‌شود، قفل رها می‌شود، و بعد شبکه.

// >>> AETHER-APP-PATCH ui-lang-on-disk (1.3.0)
/// کلیدِ زبان رابط در `prefs.json`.
const UI_LANG_KEY: &str = "ui.lang";

/// زبان رابط کاربری، از `prefs.json` کنار پروفایل.
///
/// زبان قبلاً فقط در `localStorage` وب‌ویو می‌ماند. WebView2 آن را با تأخیر روی
/// دیسک می‌نویسد، پس بستن برنامه کمی بعد از انتخاب زبان (یا پاک‌شدن پوشهٔ
/// `EBWebView` با نصب/به‌روزرسانی) آن را از بین می‌برد و برنامه انگلیسی باز
/// می‌شد. حالا منبعِ حقیقت فایلِ خودِ برنامه است و `localStorage` فقط کش.
#[tauri::command]
fn get_ui_lang(app: AppHandle) -> Option<String> {
    let dir = app.path().app_local_data_dir().ok()?;
    store::PrefsStore::new(&dir)
        .get_string(UI_LANG_KEY)
        .filter(|v| v == "fa" || v == "en")
}

#[tauri::command]
fn set_ui_lang(app: AppHandle, lang: String) -> Result<(), String> {
    let lang = if lang == "fa" { "fa" } else { "en" };
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    store::PrefsStore::new(&dir)
        .set_string(UI_LANG_KEY, lang)
        .map_err(|e| e.to_string())
}
// <<< AETHER-APP-PATCH ui-lang-on-disk

// >>> AETHER-APP-PATCH whats-new (1.3.0)
/// نسخه‌ای که برنامه آخرین بار با آن اجرا شد — در `prefs.json`.
const NEWS_LAST_LAUNCHED_KEY: &str = "news.last_launched";
/// نسخه‌ای که کاربر برایش «دیگر این پیام را نمایش نده» را زد.
const NEWS_SUPPRESSED_KEY: &str = "news.suppressed";

/// وضعیتِ پنجرهٔ «تازه‌ها» (What's New).
///
/// به همان دلیلِ `get_ui_lang` روی دیسکِ خودِ برنامه می‌ماند و نه فقط در
/// `localStorage`: WebView2 دیر می‌نویسد و نصب/به‌روزرسانی ممکن است پوشهٔ
/// `EBWebView` را پاک کند؛ آن‌وقت تیکِ «دیگر نمایش نده» گم می‌شد و پنجره
/// دوباره مزاحم می‌شد.
#[tauri::command]
fn news_state(app: AppHandle) -> serde_json::Value {
    let prefs = app
        .path()
        .app_local_data_dir()
        .ok()
        .map(|dir| store::PrefsStore::new(&dir));
    let read = |key: &str| prefs.as_ref().and_then(|p| p.get_string(key));
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "lastLaunched": read(NEWS_LAST_LAUNCHED_KEY),
        "suppressed": read(NEWS_SUPPRESSED_KEY),
    })
}

/// اجرای این نسخه را ثبت می‌کند و اگر `suppress` باشد، پنجره را فقط برای
/// **همین** نسخه ساکت می‌کند (آپدیتِ بعدی دوباره نشانش می‌دهد).
#[tauri::command]
fn news_mark(app: AppHandle, suppress: bool) -> Result<(), String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let prefs = store::PrefsStore::new(&dir);
    let version = env!("CARGO_PKG_VERSION");
    prefs
        .set_string(NEWS_LAST_LAUNCHED_KEY, version)
        .map_err(|e| e.to_string())?;
    if suppress {
        prefs
            .set_string(NEWS_SUPPRESSED_KEY, version)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
// <<< AETHER-APP-PATCH whats-new

/// وضعیت دیدنیِ لایهٔ هوش مصنوعی. همگام و ارزان — هیچ I/O شبکه‌ای.
#[tauri::command]
fn ai_snapshot(app: State<'_, AppState>) -> AiSnapshot {
    let snapshot = app.latest.lock().as_ref().clone();
    let profile = app.controller.lock().unwrap().profile();
    app.ai.snapshot(snapshot.state, &profile)
}

/// یک snapshot تازهٔ هوش مصنوعی را به رابط کاربری هل می‌دهد.
///
/// رخداد جدا از `aether://state` است چون منابعشان جداست: حالت اتصال پنج بار در
/// ثانیه تیک می‌خورد، و حالت هوش مصنوعی فقط وقتی کاربر کاری کرده. یکی‌کردنشان
/// یعنی صفحهٔ چت با هر تیکِ تایمر دوباره رندر شود.
fn publish_ai(app: &AppHandle) {
    let state: State<'_, AppState> = app.state();
    let snapshot = state.latest.lock().as_ref().clone();
    let profile = state.controller.lock().unwrap().profile();
    let _ = app.emit("aether://ai", state.ai.snapshot(snapshot.state, &profile));
}

/// پروفایلی را که **خودِ Rust** نوشته به رابط کاربری اعلام می‌کند.
///
/// # چرا این رخداد لازم است
///
/// رابط کاربری پروفایل را یک بار در استارتاپ با `get_profile` می‌گیرد و از آن
/// پس فقط کپیِ خودش را دست‌کاری می‌کند. تا وقتی هر نوشتنی از خودِ UI شروع
/// می‌شد، این کافی بود. مسیرهای هوش مصنوعی این فرض را شکستند: آن‌ها پروفایل را
/// در Rust می‌نویسند، پس کپیِ UI کهنه می‌شد و دو چیز رخ می‌داد — صفحهٔ تنظیمات
/// مقدارِ قبلی را نشان می‌داد (کاربر نتیجه می‌گرفت «اعمال نشد»، حتی بعد از قطع و
/// وصل)، و ویرایشِ بعدیِ هر تنظیمِ دیگر همان شیءِ کهنه را برمی‌گرداند و تغییرِ
/// دستیار را بی‌صدا **باطل** می‌کرد.
///
/// رخدادِ جدا از `aether://ai` است چون گیرنده‌اش جداست: این یکی به همهٔ
/// صفحه‌های تنظیمات می‌رسد و نه فقط به صفحهٔ چت.
fn publish_profile(app: &AppHandle) {
    let _ = app.emit("aether://profile", profile_copy(app));
}

/// پروفایل فعلی، بی‌آنکه قفل نگه داشته شود.
fn profile_copy(app: &AppHandle) -> ConnectionProfile {
    let state: State<'_, AppState> = app.state();
    // پروفایل به یک متغیر بسته می‌شود و بعد قفل می‌افتد: برگرداندنِ مستقیمِ
    // `…lock().unwrap().profile()` یعنی گاردِ موقتی تا پایان عبارت زنده بماند،
    // که کامپایلر همان را رد کرد — و درست هم می‌گفت، چون هدفِ همین تابع این است
    // که قفل را پیش از رفتن به شبکه رها کند.
    let profile = state.controller.lock().unwrap().profile();
    profile
}

// ===========================================================================
//  ۱.۴.۰ — ورودِ Zero Trust پیش از اتصال، و فهرست‌های هوشمند
// ===========================================================================
//
// همان قاعدهٔ فرمان‌های جمینای: کارِ شبکه با spawn_blocking، و قفلِ کنترلر
// فقط برای برداشتنِ مسیرها و پروفایل، پیش از رفتن به شبکه.

fn zt_paths(app: &AppHandle) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let state: State<'_, AppState> = app.state();
    let guard = state.controller.lock().unwrap();
    let out = (guard.data_dir().to_path_buf(), guard.identity_dirs());
    drop(guard);
    out
}

fn zt_status_now(app: &AppHandle, team: &str, email: &str) -> zt_signin::Status {
    let (data_dir, dirs) = zt_paths(app);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    zt_signin::status(&data_dir, &refs, team, email)
}

/// وضعیتِ ورود برای تیم/ایمیلِ فعلیِ تنظیمات. هرگز خودِ توکن.
#[tauri::command]
fn zt_status(app: AppHandle) -> zt_signin::Status {
    let p = profile_copy(&app);
    zt_status_now(&app, &p.team, &p.access_email)
}

/// ۱.۵.۰ — خطای ساختاریافتهٔ Zero Trust، تا رابط کاربری جملهٔ دقیقِ موبایل را
/// (به هر دو زبان) بسازد: `kind` + کدِ HTTP / جزئیاتِ شبکه / میزبانِ تیم.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ZtProblem {
    kind: &'static str,
    status: Option<u16>,
    detail: Option<String>,
    host: String,
}

impl ZtProblem {
    fn of(failure: &zt_signin::Failure, raw_team: &str) -> Self {
        use zt_signin::Failure as F;
        let (kind, status, detail) = match failure {
            F::BadTeam => ("badTeam", None, None),
            F::BadEmail => ("badEmail", None, None),
            F::NoEmailCode => ("noEmailCode", None, None),
            F::Refused(code) => ("refused", Some(*code), None),
            F::NoNonce => ("noNonce", None, None),
            F::NoSession => ("noSession", None, None),
            F::NoToken(code) => ("noToken", Some(*code), None),
            F::Network(d) => ("network", None, Some(d.clone())),
        };
        Self::bare(kind, raw_team).with(status, detail)
    }

    fn bare(kind: &'static str, raw_team: &str) -> Self {
        let host = zt_web::normalize_team(raw_team)
            .map(|t| zt_web::team_host(&t))
            .unwrap_or_else(|| raw_team.trim().to_string());
        Self {
            kind,
            status: None,
            detail: None,
            host,
        }
    }

    fn with(mut self, status: Option<u16>, detail: Option<String>) -> Self {
        self.status = status;
        self.detail = detail;
        self
    }
}

fn zt_thread_died(raw_team: &str) -> ZtProblem {
    ZtProblem::bare("network", raw_team)
        .with(None, Some("the request thread stopped unexpectedly".into()))
}

/// گام ۱: صفحهٔ ثبت‌نامِ تیم باز و کدِ ایمیلی درخواست می‌شود (شبکهٔ مستقیم).
#[tauri::command]
async fn zt_request_code(app: AppHandle) -> Result<zt_signin::Status, ZtProblem> {
    let p = profile_copy(&app);
    let (team, email) = (p.team.clone(), p.access_email.clone());
    let session =
        tauri::async_runtime::spawn_blocking(move || zt_signin::request_code(&team, &email))
            .await
            .map_err(|_| zt_thread_died(&p.team))?
            .map_err(|f| ZtProblem::of(&f, &p.team))?;
    *zt_signin::pending().lock() = Some(session);
    Ok(zt_status_now(&app, &p.team, &p.access_email))
}

#[tauri::command]
async fn zt_resend_code(app: AppHandle) -> Result<zt_signin::Status, ZtProblem> {
    let p = profile_copy(&app);
    let mut session = zt_signin::pending()
        .lock()
        .clone()
        .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::NoSession, &p.team))?;
    let session = tauri::async_runtime::spawn_blocking(move || {
        zt_signin::resend_code(&mut session).map(|_| session)
    })
    .await
    .map_err(|_| zt_thread_died(&p.team))?
    .map_err(|f| ZtProblem::of(&f, &p.team))?;
    *zt_signin::pending().lock() = Some(session);
    Ok(zt_status_now(&app, &p.team, &p.access_email))
}

/// گام ۲: کدِ ایمیل → JWT، مهرشده با DPAPI ذخیره می‌شود.
///
/// مثل `store()` در دیالوگِ موبایل: توکنی که همین حالا منقضی است ذخیره نمی‌شود
/// (`expiredOnArrival` — ساعتِ ویندوز را بررسی کنید)، و ذخیره فقط وقتی موفق
/// حساب می‌شود که خواندنِ دوباره همان توکن را برگرداند (`storeFailed`).
#[tauri::command]
async fn zt_submit_code(app: AppHandle, code: String) -> Result<zt_signin::Status, ZtProblem> {
    let p = profile_copy(&app);
    let mut session = zt_signin::pending()
        .lock()
        .clone()
        .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::NoSession, &p.team))?;
    let (outcome, session) = tauri::async_runtime::spawn_blocking(move || {
        let r = zt_signin::submit_code(&mut session, &code);
        (r, session)
    })
    .await
    .map_err(|_| zt_thread_died(&p.team))?;
    match outcome.map_err(|f| ZtProblem::of(&f, &p.team))? {
        zt_signin::CodeOutcome::Token(token) => {
            let now = zt_signin::now_secs();
            if !matches!(zt_web::inspect(&token, now), zt_web::Verdict::Usable(_)) {
                *zt_signin::pending().lock() = Some(session);
                return Err(ZtProblem::bare("expiredOnArrival", &p.team));
            }
            let (data_dir, _) = zt_paths(&app);
            let record = zt_signin::Record::of(&session.team, &session.email, &token, now)
                .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::BadTeam, &p.team))?;
            zt_signin::save_record(&data_dir, Some(&record));
            *zt_signin::pending().lock() = None;
            if zt_signin::load_record(&data_dir).as_ref() != Some(&record) {
                return Err(ZtProblem::bare("storeFailed", &p.team));
            }
            Ok(zt_status_now(&app, &p.team, &p.access_email))
        }
        zt_signin::CodeOutcome::Rejected(code) => {
            // نشست می‌ماند تا کاربر کد را دوباره وارد کند یا کدِ تازه بخواهد.
            *zt_signin::pending().lock() = Some(session);
            Err(ZtProblem::bare("rejected", &p.team).with(Some(code), None))
        }
    }
}

/// ۱.۵.۰ — عضویتِ همین دستگاه، جدا از هر ورودِ ذخیره‌شده (`TeamMembership.isEnrolled`).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ZtMembership {
    /// نامِ نرمال‌شدهٔ تیم، یا `None` وقتی نامِ بالا معتبر نیست.
    team: Option<String>,
    enrolled: bool,
    /// اتصال خاموش است و می‌شود وارد شد یا عضویت را تغییر داد.
    editable: bool,
    /// روشِ ورود: "EMAIL" | "SERVICE_TOKEN" | "TOKEN"
    mode: String,
    /// برای «آزمایش توکن سرویس»: شناسه و رازِ کلاینت هر دو هست؟
    service_complete: bool,
}

fn zt_editable(app: &AppHandle) -> bool {
    !connection_state(app).is_active()
}

// ===========================================================================
//  ۱.۵.۰ — رمزِ اختیاریِ اشتراک LAN (مهرشده با DPAPI)
// ===========================================================================

#[tauri::command]
fn share_info(app: AppHandle) -> share::ShareCredentials {
    let (data_dir, _) = zt_paths(&app);
    share::load_credentials(&data_dir)
}

#[tauri::command]
fn share_set_auth(app: AppHandle, required: bool) -> Result<share::ShareCredentials, String> {
    let (data_dir, _) = zt_paths(&app);
    share::set_auth_required(&data_dir, required).map_err(|e| e.to_string())
}

#[tauri::command]
fn share_set_credentials(
    app: AppHandle,
    user: String,
    password: String,
) -> Result<share::ShareCredentials, String> {
    let (data_dir, _) = zt_paths(&app);
    share::set_credentials(&data_dir, &user, &password)
}

#[tauri::command]
fn share_rotate_password(app: AppHandle) -> Result<share::ShareCredentials, String> {
    let (data_dir, _) = zt_paths(&app);
    share::rotate_password(&data_dir).map_err(|e| e.to_string())
}

#[tauri::command]
fn zt_membership(app: AppHandle) -> ZtMembership {
    let p = profile_copy(&app);
    let team = zt_web::normalize_team(&p.team);
    let (_, dirs) = zt_paths(&app);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    let enrolled = team
        .as_deref()
        .is_some_and(|t| zt_signin::is_enrolled(&refs, t));
    let mode = serde_json::to_value(p.access_mode)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    ZtMembership {
        team,
        enrolled,
        editable: zt_editable(&app),
        mode,
        service_complete: !p.access_id.trim().is_empty() && !p.access_secret.trim().is_empty(),
    }
}

/// «حذف عضویت این دستگاه» — فقط برای همین تیم، و هرگز وقتی تونل روشن است.
#[tauri::command]
fn zt_forget_membership(app: AppHandle) -> Result<usize, ZtProblem> {
    let p = profile_copy(&app);
    if !zt_editable(&app) {
        return Err(ZtProblem::bare("busy", &p.team));
    }
    let team = zt_web::normalize_team(&p.team)
        .ok_or_else(|| ZtProblem::of(&zt_signin::Failure::BadTeam, &p.team))?;
    let (_, dirs) = zt_paths(&app);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    Ok(zt_signin::forget_membership(&refs, &team))
}

/// «آزمایش توکن سرویس» — همان مبادلهٔ موتور؛ چیزی ذخیره نمی‌شود.
#[tauri::command]
async fn zt_test_service_token(app: AppHandle) -> Result<(), ZtProblem> {
    let p = profile_copy(&app);
    let (team, id, secret) = (p.team.clone(), p.access_id.clone(), p.access_secret.clone());
    tauri::async_runtime::spawn_blocking(move || zt_signin::test_service_token(&team, &id, &secret))
        .await
        .map_err(|_| zt_thread_died(&p.team))?
        .map_err(|f| ZtProblem::of(&f, &p.team))
}

/// ۱.۵.۰ — بررسیِ توکنِ عضویت هنگامِ چسباندن (`AccessToken.inspect`):
/// توکن است یا نه، و تا کی معتبر است. امضا بررسی نمی‌شود و نمی‌تواند بشود.
/// `raw` خالی یعنی «توکنِ ذخیره‌شده در حافظه» — خودِ توکن هرگز برنمی‌گردد.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenCheck {
    /// "empty" | "malformed" | "expired" | "usable"
    verdict: &'static str,
    seconds_left: Option<i64>,
}

#[tauri::command]
fn zt_inspect_token(app: AppHandle, raw: Option<String>) -> TokenCheck {
    let typed = raw.unwrap_or_default();
    let token = if typed.trim().is_empty() {
        profile_copy(&app).access_token
    } else {
        typed
    };
    let now = zt_signin::now_secs();
    let verdict = match zt_web::inspect(&token, now) {
        zt_web::Verdict::Empty => "empty",
        zt_web::Verdict::Malformed => "malformed",
        zt_web::Verdict::Expired => "expired",
        zt_web::Verdict::Usable(_) => "usable",
    };
    TokenCheck {
        verdict,
        seconds_left: (verdict == "usable")
            .then(|| zt_web::expiry_seconds(token.trim()).map(|exp| exp - now))
            .flatten(),
    }
}

/// کدِ ورودی که هسته وسطِ اتصال خواست (`LoginCodePrompt.submit`).
#[tauri::command]
fn zt_login_code_submit(code: String) -> bool {
    login_code::submit(&code)
}

/// «حالا نه» — اتصال همین حالا متوقف می‌شود.
#[tauri::command]
fn zt_login_code_dismiss() {
    login_code::dismiss();
}

/// ورودِ ذخیره‌شده و نشستِ نیمه‌کاره فراموش می‌شوند.
#[tauri::command]
fn zt_forget(app: AppHandle) -> zt_signin::Status {
    let (data_dir, _) = zt_paths(&app);
    zt_signin::save_record(&data_dir, None);
    *zt_signin::pending().lock() = None;
    let p = profile_copy(&app);
    zt_status_now(&app, &p.team, &p.access_email)
}

/// نشستِ نیمه‌کارهٔ «کد فرستاده شد» کنار گذاشته می‌شود؛ ورودِ ذخیره‌شده دست نمی‌خورد.
/// (دکمهٔ «انصراف» پنل — `zt_forget` آن را هم پاک می‌کرد.)
#[tauri::command]
fn zt_cancel(app: AppHandle) -> zt_signin::Status {
    *zt_signin::pending().lock() = None;
    let p = profile_copy(&app);
    zt_status_now(&app, &p.team, &p.access_email)
}

/// شمارِ ورودی‌های فهرست‌های داخلی، برای زیرنویسِ دو کلید در تنظیمات.
#[tauri::command]
fn smart_list_counts(app: AppHandle) -> smart_lists::ListCounts {
    let (data_dir, _) = zt_paths(&app);
    smart_lists::counts(&data_dir)
}

/// وضعیتِ زندهٔ اتصال برای پرامپتِ چت (۱.۴.۰-r4).
///
/// از همان آخرین snapshotی خوانده می‌شود که رابط کاربری می‌بیند، پس مدل و کاربر
/// یک وضعیت را می‌بینند. ارزان است: یک قفلِ کوتاه و یک کپیِ `Copy`.
fn connection_state(app: &AppHandle) -> state::ConnectionState {
    let state: State<'_, AppState> = app.state();
    let current = state.latest.lock().as_ref().state;
    current
}

fn ai_handle(app: &AppHandle) -> Arc<AiSession> {
    let state: State<'_, AppState> = app.state();
    state.ai.clone()
}

/// کلید API را ذخیره (یا با رشتهٔ خالی، پاک) می‌کند.
///
/// کلید فقط در همین یک جهت از مرز IPC رد می‌شود. هیچ فرمانی آن را برنمی‌گرداند؛
/// رابط کاربری فقط `hasKey` و چهار نویسهٔ آخر را می‌بیند.
#[tauri::command]
fn ai_set_key(app: AppHandle, key: String) -> Result<(), String> {
    let result = ai_handle(&app).set_api_key(&key);
    // پیش از `?`: چه ذخیره موفق شده باشد چه نه، `hasKey` و `keyHint` عوض شده‌اند و
    // صفحه باید همان را ببیند.
    publish_ai(&app);
    result
}

#[tauri::command]
fn ai_select_model(app: AppHandle, id: String) -> Result<(), String> {
    let result = ai_handle(&app).select_model(&id);
    publish_ai(&app);
    result
}

#[tauri::command]
fn ai_clear_chat(app: AppHandle) {
    ai_handle(&app).clear_chat();
    publish_ai(&app);
}

#[tauri::command]
fn ai_dismiss_error(app: AppHandle) {
    ai_handle(&app).dismiss_error();
    publish_ai(&app);
}

#[tauri::command]
fn ai_dismiss_advisor(app: AppHandle) {
    ai_handle(&app).dismiss_advisor();
    publish_ai(&app);
}

/// «تست اتصال به API» — پورت از دکمهٔ `ai_test` در `AiPages.kt`.
///
/// دو انتشار دارد و این عمدی است: اولی پیش از کارِ شبکه می‌رود تا دکمه فوراً
/// «در حال تست…» شود، دومی بعد از نتیجه. بدون اولی، کاربر روی دکمه‌ای کلیک
/// می‌کند که تا ده ثانیه هیچ نشانی از زنده‌بودن نمی‌دهد — همان چیزی که باعث شد
/// کاربر فکر کند «کار نمی‌کند» و دوباره کلیک کند.
#[tauri::command]
async fn ai_test_key(app: AppHandle) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    // `RUNNING` پیش از spawn نشانده و منتشر می‌شود؛ خودِ `test_connection` هم آن
    // را می‌نشاند، ولی آن اتفاق داخل رشتهٔ کارگر می‌افتد و برای دکمه دیر است.
    session.mark_probe_running();
    publish_ai(&app);
    let result = tauri::async_runtime::spawn_blocking(move || session.test_connection(&profile))
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

/// مدل‌های موجود برای این کلید را کشف می‌کند.
#[tauri::command]
async fn ai_refresh_models(app: AppHandle) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let result = tauri::async_runtime::spawn_blocking(move || session.refresh_models(&profile))
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    // در هر دو حالت منتشر می‌شود: شکست هم بخشی از snapshot است (`error`,
    // `busy=false`) و رابط کاربری باید اسپینر را پایین بیاورد.
    publish_ai(&app);
    result
}

/// «این تنظیم چه کار می‌کند؟»
#[tauri::command]
async fn ai_explain(
    app: AppHandle,
    lang: String,
    title: String,
    subtitle: String,
    value: String,
) -> Result<String, String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let result = tauri::async_runtime::spawn_blocking(move || {
        session.explain(&profile, &lang, &title, &subtitle, &value)
    })
    .await
    .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

/// یک نوبت چت.
///
/// # ترتیب، و چرا مهم است
///
/// حبابِ کاربر روی همین رشته و **پیش از** رفتن به کارگر نشانده می‌شود، بعد یک
/// انتشار، بعد درخواستِ شبکه. نسخهٔ قبل هر دو کار را به کارگر می‌داد و بلافاصله
/// `publish_ai` می‌زد — یک مسابقه که انتشار تقریباً همیشه می‌برد، پس snapshot پیش
/// از وجودِ حباب گرفته می‌شد و پرسشِ کاربر تا رسیدنِ پاسخ روی صفحه نبود. یعنی
/// کاربر متن را می‌فرستاد و یک جعبهٔ خالی می‌دید.
///
/// حالا ترتیب خودش تضمین است و نه یک تأخیر: وقتی `append_user_message` برمی‌گردد،
/// حباب در تاریخ هست. رجوع به [`ai_session::AiSession::append_user_message`].
#[tauri::command]
async fn ai_send_chat(app: AppHandle, lang: String, text: String) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let status = connection_state(&app);
    let prompt = session.append_user_message(&text)?;
    publish_ai(&app);
    let handle = tauri::async_runtime::spawn_blocking(move || {
        session.ask_existing(&profile, status, &lang, &prompt)
    });
    let result = handle
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

/// همان پرسشِ شکست‌خورده را دوباره می‌فرستد — دکمهٔ «تلاش مجدد».
///
/// حبابِ شکست را برمی‌دارد و با همان `sourcePrompt` می‌پرسد. به همان دلیلِ
/// `ai_send_chat` دو نیم شده: برداشتنِ حبابِ قرمز همگام انجام می‌شود و انتشار
/// **بعد** از آن می‌آید، نه در مسابقه با آن.
#[tauri::command]
async fn ai_retry(app: AppHandle, lang: String, id: u64) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let status = connection_state(&app);
    let prompt = session.take_failed_prompt(id)?;
    publish_ai(&app);
    let handle = tauri::async_runtime::spawn_blocking(move || {
        session.ask_existing(&profile, status, &lang, &prompt)
    });
    let result = handle
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

/// یکی از پیام‌های خودِ کاربر را بازنویسی می‌کند و از همان نقطه دوباره می‌پرسد.
#[tauri::command]
async fn ai_edit_message(
    app: AppHandle,
    lang: String,
    id: u64,
    text: String,
) -> Result<(), String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let status = connection_state(&app);
    let echo = app.clone();
    let handle = tauri::async_runtime::spawn_blocking(move || {
        session.edit_message(&profile, status, &lang, id, &text)
    });
    publish_ai(&echo);
    let result = handle
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    publish_ai(&app);
    result
}

/// چند حباب را در یک رفت حذف می‌کند. همگام — هیچ I/O شبکه‌ای.
#[tauri::command]
fn ai_delete_messages(app: AppHandle, ids: Vec<u64>) {
    ai_handle(&app).delete_messages(&ids);
    publish_ai(&app);
}

/// پاسخِ در راه را رها می‌کند. رجوع به [`ai_session::AiSession::stop`].
#[tauri::command]
fn ai_stop(app: AppHandle) {
    ai_handle(&app).stop();
    publish_ai(&app);
}

/// تنظیماتی که یک پاسخ پیشنهاد کرده را می‌نویسد — دکمهٔ «اعمال».
///
/// همگام است: هیچ I/O شبکه‌ای ندارد. ذخیره اینجا انجام می‌شود و نه در
/// `ai_session`، به همان دلیلِ [`ai_advise`]: `set_profile` تنها دروازهٔ نوشتن است
/// — همان چیزی که به دیسک می‌نویسد، `settings_rev` را بالا می‌برد و تصمیم می‌گیرد
/// نشستِ در جریان باید بازپیکربندی شود.
///
/// حباب فقط پس از یک نوشتنِ **موفق** «اعمال‌شده» علامت می‌خورد: یک تیکِ سبز روی
/// تغییری که به دیسک نرسیده، دروغ است.
#[tauri::command]
fn ai_apply_changes(app: AppHandle, id: u64) -> Result<Vec<(String, String)>, String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let (patched, applied) = session.changes_for(&profile, id)?;
    if !applied.is_empty() {
        let state: State<'_, AppState> = app.state();
        let written = state.controller.lock().unwrap().set_profile(patched);
        if let Err(e) = written {
            log::DiagnosticsLog::e("ai", &format!("chat changes could not be saved: {e}"));
            publish_ai(&app);
            return Err(format!("The changes could not be saved: {e}"));
        }
        // نوشتن بی‌اعلام‌کردن، همان اشکالی بود که کاربر دید: تنظیم روی دیسک
        // عوض می‌شد و صفحهٔ تنظیمات مقدارِ قبلی را نشان می‌داد.
        publish_profile(&app);
        log::DiagnosticsLog::i(
            "ai",
            &format!(
                "chat applied: {}",
                applied
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    session.mark_applied(id);
    publish_ai(&app);
    Ok(applied)
}

/// مشاورِ ضد‌DPI: لاگ را می‌خواند، پچ می‌گیرد، و اگر چیزی پذیرفته شد ذخیره می‌کند.
///
/// # چرا ذخیره‌کردن اینجاست و نه در `ai_session`
///
/// نوشتنِ پروفایل مالِ کنترلر است: `set_profile` است که به دیسک می‌نویسد،
/// `settings_rev` را بالا می‌برد و تصمیم می‌گیرد آیا نشستِ در جریان باید
/// بازپیکربندی شود. لایهٔ نشست پروفایلِ **نتیجه** را برمی‌گرداند و همین‌جا، پس
/// از آزاد‌شدنِ رشتهٔ شبکه، از همان یک دروازهٔ نوشتن رد می‌شود.
#[tauri::command]
async fn ai_advise(app: AppHandle, lang: String) -> Result<ai_session::AdvisorResult, String> {
    let session = ai_handle(&app);
    let profile = profile_copy(&app);
    let outcome = tauri::async_runtime::spawn_blocking(move || session.advise(&profile, &lang))
        .await
        .map_err(|_| "The request thread stopped unexpectedly.".to_string())?;
    let result = match outcome {
        Ok((patched, result)) => {
            if !result.applied.is_empty() {
                let state: State<'_, AppState> = app.state();
                let written = state.controller.lock().unwrap().set_profile(patched);
                if written.is_ok() {
                    publish_profile(&app);
                }
                if let Err(e) = written {
                    // پچ اعمال شد ولی ذخیره نشد: باید *گفته* شود، چون وگرنه
                    // کاربر فهرست تغییرات را می‌بیند و باور می‌کند نشسته‌اند.
                    log::DiagnosticsLog::e(
                        "ai",
                        &format!("advisor changes could not be saved: {e}"),
                    );
                    publish_ai(&app);
                    return Err(format!("The changes could not be saved: {e}"));
                }
            }
            Ok(result)
        }
        Err(message) => Err(message),
    };
    publish_ai(&app);
    result
}

/// هندسهٔ پنجره را از `prefs.json` بازمی‌گردانَد.
///
/// چرا این‌جا و نه در `tauri.conf.json`: آن فایل یک اندازهٔ ثابت می‌دهد و از
/// نمایشگرِ کاربر چیزی نمی‌داند. اندازهٔ پیش‌فرضِ ۱۱۸۰×۷۸۰ روی لپ‌تاپِ
/// ۱۳۶۶×۷۶۸ بلندتر از خودِ صفحه بود، و چون پنجره `decorations: false` است،
/// لبهٔ پایینی — یعنی تنها دستگیرهٔ تغییرِ اندازه — زیرِ صفحه گم می‌شد.
///
/// همهٔ حساب‌ها در `window.rs` است و آزمون دارد؛ این تابع فقط واحدها را
/// ترجمه می‌کند: API فیزیکی می‌دهد، منطق منطقی می‌خواهد.
fn restore_window_geometry(win: &tauri::WebviewWindow, prefs: &store::PrefsStore) {
    let saved = prefs
        .get_string(window::PREFS_KEY)
        .as_deref()
        .and_then(window::decode);

    let scale = win.scale_factor().unwrap_or(1.0).max(0.1);
    // `current_monitor` روی مانیتوری که پنجره رویش است؛ اگر معلوم نبود،
    // مانیتورِ اصلی. اگر هیچ‌کدام معلوم نبود، هیچ کاری نمی‌کنیم — بهتر از
    // جابه‌جا کردنِ پنجره بر اساسِ یک حدس.
    let monitor = match win.current_monitor() {
        Ok(Some(m)) => Some(m),
        _ => win.primary_monitor().ok().flatten(),
    };
    let Some(monitor) = monitor else {
        log::DiagnosticsLog::w(
            "ui",
            "No monitor could be queried, so the window keeps the size from the config.",
        );
        return;
    };
    let area = monitor.work_area();
    let work = window::Rect::new(
        (f64::from(area.position.x) / scale).round() as i32,
        (f64::from(area.position.y) / scale).round() as i32,
        (f64::from(area.size.width) / scale).round() as u32,
        (f64::from(area.size.height) / scale).round() as u32,
    );

    // اندازهٔ پیش‌فرض از خودِ پنجره خوانده می‌شود (همان چیزی که
    // `tauri.conf.json` ساخته)، نه از عددی که این‌جا دوباره نوشته شده باشد.
    let (default_w, default_h) = match win.inner_size() {
        Ok(s) => (
            (f64::from(s.width) / scale).round() as u32,
            (f64::from(s.height) / scale).round() as u32,
        ),
        Err(_) => (window::MIN_W, window::MIN_H),
    };

    let g = window::place(saved, work, default_w, default_h);
    let _ = win.set_size(tauri::LogicalSize::new(g.rect.w, g.rect.h));
    let _ = win.set_position(tauri::LogicalPosition::new(g.rect.x, g.rect.y));
    if g.maximized {
        let _ = win.maximize();
    }
}

/// اندازه و جای فعلیِ پنجره را می‌نویسد.
///
/// موقع بیشینه‌بودن، اندازهٔ صفحه ذخیره **نمی‌شود**: کاربری که بیشینه را لغو
/// می‌کند باید پنجرهٔ خودش را ببیند. فقط پرچمِ `maximized` تازه می‌شود.
fn remember_window_geometry(win: &tauri::WebviewWindow, prefs: &store::PrefsStore) {
    let maximized = win.is_maximized().unwrap_or(false);
    let previous = prefs
        .get_string(window::PREFS_KEY)
        .as_deref()
        .and_then(window::decode);

    let rect = if maximized {
        match previous {
            Some(g) => g.rect,
            // هیچ اندازهٔ قبلی‌ای نیست (اولین اجرا، و کاربر همان اول بیشینه
            // کرده): همان اندازهٔ فعلی، تا چیزی برای بازگشت وجود داشته باشد.
            None => match current_rect(win) {
                Some(r) => r,
                None => return,
            },
        }
    } else {
        match current_rect(win) {
            Some(r) => r,
            None => return,
        }
    };

    let g = window::Geometry { rect, maximized };
    if previous == Some(g) {
        return; // نوشتنِ همان مقدار، یک I/O بی‌دلیل در هر پیکسل کشیدن است.
    }
    if let Err(e) = prefs.set_string(window::PREFS_KEY, &window::encode(&g)) {
        log::DiagnosticsLog::w("ui", &format!("Could not save the window size: {e}"));
    }
}

/// اندازه/جای فعلی در واحدِ منطقی.
fn current_rect(win: &tauri::WebviewWindow) -> Option<window::Rect> {
    let scale = win.scale_factor().unwrap_or(1.0).max(0.1);
    let size = win.inner_size().ok()?;
    let pos = win.outer_position().ok()?;
    let w = (f64::from(size.width) / scale).round() as u32;
    let h = (f64::from(size.height) / scale).round() as u32;
    if w == 0 || h == 0 {
        return None; // پنجرهٔ کمینه‌شده روی ویندوز صفر گزارش می‌شود.
    }
    Some(window::Rect::new(
        (f64::from(pos.x) / scale).round() as i32,
        (f64::from(pos.y) / scale).round() as i32,
        w,
        h,
    ))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // Equivalent of launchMode=singleTask in the Android manifest.
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            log::DiagnosticsLog::init(&data_dir);
            // Only small local preferences are needed on the UI thread. Engine
            // staging/copying and sealed stores are initialized on the worker below.
            let prefs = Arc::new(store::PrefsStore::new(&data_dir));
            app.manage(StartupStatus::default());

            // پیش از نخستین فریم: اندازه/جای پنجره از اجرای قبلی، و جا دادنش
            // در نمایشگرِ همین لحظه. بعد از نمایش انجام‌دادنش یعنی کاربر یک
            // جهشِ اندازه ببیند.
            if let Some(win) = app.get_webview_window("main") {
                restore_window_geometry(&win, &prefs);
                // رها کردنِ فایلِ کانفیگ از Explorer روی پنجرهٔ ارتقایافته — filedrop.rs.
                filedrop::install(&win);
                let prefs_for_events = prefs.clone();
                let watched = win.clone();
                win.on_window_event(move |event| match event {
                    // Resized هم هنگام بیشینه/بازگردانی می‌آید، پس پرچم هم با
                    // همین مسیر تازه می‌شود.
                    tauri::WindowEvent::Resized(_) | tauri::WindowEvent::Moved(_) => {
                        remember_window_geometry(&watched, &prefs_for_events);
                    }
                    // و یک نوشتنِ آخر: بستن ممکن است پیش از رسیدنِ آخرین
                    // Resized برسد.
                    tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed => {
                        remember_window_geometry(&watched, &prefs_for_events);
                    }
                    _ => {}
                });
            }
            // Equivalent of collecting StateFlow in Compose, with two rules the
            // old loop did not have:
            //
            //   * `try_lock`, so a beat is SKIPPED rather than queued when an IPC
            //     command owns the controller. The old loop piled up behind a slow
            //     teardown and then fired every backed-up tick at once.
            //   * emit only on CHANGE. An idle app used to serialise a snapshot
            //     and repaint the whole home screen five times a second, forever,
            //     with nothing in it different. That is most of the background
            //     cost the UI was competing with.
            let handle = app.handle().clone();
            std::thread::Builder::new().name("aether-bootstrap".into()).spawn(move || {
                // AetherController::new stages the engine bundle (large disk I/O).
                // Do not gate creation/painting of WebView2 on that work.
                let initialized = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    custom::store::init(&data_dir);
                    let controller = AetherController::new(&data_dir);
                    let first = controller.snapshot();
                    let preset_store = presets::PresetStore::new(&data_dir,
                        serde_json::to_value(controller.profile()).unwrap_or_default());
                    handle.manage(AppState {
                        presets: Mutex::new(preset_store),
                        controller: Mutex::new(controller),
                        latest: parking_lot::Mutex::new(Arc::new(first)),
                        ai: Arc::new(AiSession::new(&data_dir, prefs)),
                    });
                }));
                if initialized.is_err() {
                    *handle.state::<StartupStatus>().0.lock() = Some("Aether background initialization failed".into());
                    return;
                }
                let mut last: Option<Arc<Snapshot>> = None;
                let mut last_emit_at: Option<Instant> = None;
                // >>> AETHER-APP-PATCH ai-gate-follows-tunnel (1.3.0)
                // دروازهٔ هوش مصنوعی به حالت اتصال وابسته است ولی `aether://ai`
                // فقط بعد از کارهای دستیار منتشر می‌شد؛ پس بعد از وصل‌شدن، چت
                // همچنان «تونل وصل نیست» می‌گفت. با هر تغییر *حالت* یک انتشار
                // تازه — روی رشتهٔ جدا، تا قفلِ کنترلر هرگز این تیک را نگه ندارد.
                let mut last_gate_state: Option<state::ConnectionState> = None;
                // <<< AETHER-APP-PATCH ai-gate-follows-tunnel
                loop {
                    let began = Instant::now();
                    let st: State<'_, AppState> = handle.state();
                    let snapshot = match st.controller.try_lock() {
                        Ok(mut c) => {
                            c.tick();
                            Some(c.snapshot())
                        }
                        Err(TryLockError::WouldBlock) => None,
                        Err(TryLockError::Poisoned(p)) => {
                            let mut c = p.into_inner();
                            c.tick();
                            Some(c.snapshot())
                        }
                    };
                    if let Some(snapshot) = snapshot {
                        let current_state = snapshot.state;
                        publish(&handle, &st, snapshot, &mut last, &mut last_emit_at);
                        // >>> AETHER-APP-PATCH ai-gate-follows-tunnel
                        if last_gate_state != Some(current_state) {
                            last_gate_state = Some(current_state);
                            let ai_handle = handle.clone();
                            std::thread::spawn(move || publish_ai(&ai_handle));
                        }
                        // <<< AETHER-APP-PATCH ai-gate-follows-tunnel
                    }
                    // Sleep the REMAINDER of the beat. A tick that took 900ms must
                    // not then wait another 200ms before the next one.
                    std::thread::sleep(TICK.saturating_sub(began.elapsed()));
                }
            })?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            startup_ready,
            preset_state,
            preset_action,
            preset_export,
            preset_export_save,
            preset_import,
            custom_commands::cc_state,
            custom_commands::cc_tab_save,
            custom_commands::cc_tab_delete,
            custom_commands::cc_move,
            custom_commands::cc_subscription_save,
            custom_commands::cc_subscription_refresh,
            custom_commands::cc_subscription_delete,
            custom_commands::cc_import_text,
            custom_commands::cc_import_file,
            custom_commands::cc_import_bytes,
            custom_commands::cc_read_qr_image,
            custom_commands::cc_import_path,
            custom_commands::cc_select,
            custom_commands::cc_set_mode,
            custom_commands::cc_set_enabled,
            custom_commands::cc_rename,
            custom_commands::cc_get_raw,
            custom_commands::cc_edit,
            custom_commands::cc_delete,
            custom_commands::cc_delete_all,
            custom_commands::cc_ping,
            custom_commands::cc_ping_all,
            custom_commands::cc_scan_options,
            custom_commands::cc_scan_set_options,
            custom_commands::cc_scan_state,
            custom_commands::cc_scan_start,
            custom_commands::cc_scan_stop,
            custom_commands::cc_scan_dismiss,
            custom_commands::cc_speed_test,
            custom_commands::cc_speed_state,
            share_info,
            share_set_auth,
            share_set_credentials,
            share_rotate_password,
            get_snapshot,
            get_profile,
            set_profile,
            reset_profile,
            toggle_connection,
            read_logs,
            export_logs,
            clear_logs,
            get_checks,
            run_self_test,
            run_diagnostics,
            webrtc_leak_test,
            about_info,
            core_caps,
            ai_snapshot,
            get_ui_lang,
            set_ui_lang,
            news_state,
            news_mark,
            ai_set_key,
            ai_test_key,
            ai_select_model,
            ai_refresh_models,
            ai_explain,
            ai_send_chat,
            ai_retry,
            ai_apply_changes,
            ai_edit_message,
            ai_delete_messages,
            ai_stop,
            ai_advise,
            ai_clear_chat,
            ai_dismiss_error,
            ai_dismiss_advisor,
            zt_status,
            zt_request_code,
            zt_resend_code,
            zt_submit_code,
            zt_forget,
            zt_cancel,
            zt_membership,
            zt_forget_membership,
            zt_test_service_token,
            zt_inspect_token,
            zt_login_code_submit,
            zt_login_code_dismiss,
            smart_list_counts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aether");
}
