//! پورت از `core/ShareBridge.kt` (موبایل ۱.۵.۰) — رلهٔ واقعیِ HTTP/SOCKS5.
//!
//!   * SOCKS5 (10810) و HTTP (10811): هر دو پورت هر دو پروتکل را می‌فهمند
//!     (بایت اول 0x05 = SOCKS5). خروجی همیشه SOCKS5 خطِ لوله است
//!     (`engine::exit_socks_port`) — پل هرگز خودش به اینترنت شماره نمی‌گیرد.
//!   * شنوندهٔ loopback فقط همتای loopback را می‌پذیرد (پروکسی سیستمیِ همین
//!     رایانه). شنونده‌های LAN روی «هر» کارت Wi‑Fi/Ethernetِ واقعی بالا
//!     می‌آیند و فقط همتایی را می‌پذیرند که در زیرشبکهٔ یکی از همان کارت‌ها
//!     باشد (۱.۵.۰).
//!   * رمزِ اختیاریِ اشتراک (پیش‌فرض خاموش): HTTP با `Proxy-Authorization:
//!     Basic`، SOCKS5 با RFC 1929. رمز با DPAPI مهر می‌شود (`secret_store`).
//!   * `http://aether.check` از هر مسیری (HTTP، CONNECT، SOCKS5 و حتی DNS
//!     داخلِ UDP ASSOCIATE) همین‌جا پاسخ داده می‌شود؛ صفحهٔ راه‌اندازی روی
//!     `http://<host>:10811/` است و PAC روی `/proxy.pac`.
//!   * مقصدهای غیرعمومی (LAN، loopback، link-local…) برای دستگاه‌های شبکه رد
//!     می‌شوند و سرآیندهای هویتی حذف می‌شوند — «بی‌نشتی».
//!
//! رفع‌های پیشین حفظ شده‌اند: سوکتِ پذیرفته‌شده صریحاً blocking می‌شود (ارثِ
//! non-blocking در WinSock)، هر نسل پرچم خودش را دارد و stop() تردها را join
//! می‌کند (os error 10048).

use crate::log::DiagnosticsLog;
use crate::probe;
use crate::share_guard;
use crate::share_pages;
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const TAG: &str = "share";
/// مهلت بیکاری یک اتصال TCP رله‌شده.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const UPSTREAM_TIMEOUT: Duration = TCP_IDLE_TIMEOUT;
/// مهلتِ دست‌دادن/احراز هویتِ یک دستگاهِ شبکه (موبایل: AUTH_TIMEOUT_MS).
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// تلاش‌های bind روی loopback (پورت ممکن است هنوز دست نسل قبل باشد).
const BIND_RETRIES: u32 = 20;
/// روی LAN کمتر: این bind از تیکِ کنترل‌گر صدا زده می‌شود.
const LAN_BIND_RETRIES: u32 = 3;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(150);
/// هر چند وقت کارت‌های شبکه دوباره بررسی شوند (موبایل: LAN_WATCH_INTERVAL_MS).
const LAN_WATCH_INTERVAL: Duration = Duration::from_secs(3);
/// اگر بعد از این مدت هیچ دستگاهی نیامد، یک راهنما در لاگ.
const IDLE_HINT_AFTER: Duration = Duration::from_secs(90);
/// خلاصهٔ رد شدن‌ها حداکثر هر ۳۰ ثانیه یک بار در لاگ.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(30);
const MAX_UDP_DATAGRAM: usize = 65_535;

// ===================================================================== state

/// تنظیمِ رمزِ اشتراک — از کنترل‌گر (انبار مهرشده) پر می‌شود.
#[derive(Clone, Default)]
struct Auth {
    required: bool,
    user: String,
    password: String,
}

fn auth_slot() -> &'static RwLock<Auth> {
    static SLOT: OnceLock<RwLock<Auth>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Auth::default()))
}

/// رمز اشتراک را برای شنونده‌ها تنظیم می‌کند (بی‌درنگ اثر می‌کند).
pub fn set_auth(required: bool, user: &str, password: &str) {
    *auth_slot().write() = Auth {
        required,
        user: user.to_string(),
        password: password.to_string(),
    };
}

fn auth() -> Auth {
    auth_slot().read().clone()
}

fn exit_ip_slot() -> &'static RwLock<Option<String>> {
    static SLOT: OnceLock<RwLock<Option<String>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

/// IPِ خروجیِ تأییدشدهٔ تونل — برای آزمون WebRTC در صفحهٔ بررسی.
pub fn note_exit_ip(ip: Option<&str>) {
    let next = ip.map(str::to_string);
    if *exit_ip_slot().read() != next {
        *exit_ip_slot().write() = next;
    }
}

fn current_exit_ip() -> Option<String> {
    exit_ip_slot().read().clone()
}

/// کارت‌هایی که الان رویشان گوش می‌دهیم — مبنای پذیرشِ همتای LAN.
fn lan_targets_slot() -> &'static RwLock<Vec<LanTarget>> {
    static SLOT: OnceLock<RwLock<Vec<LanTarget>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Vec::new()))
}

static LAN_LIVE: AtomicUsize = AtomicUsize::new(0);
static LAN_SEEN: AtomicBool = AtomicBool::new(false);
static STUN_NOTED: AtomicBool = AtomicBool::new(false);
static REFUSALS: AtomicU64 = AtomicU64::new(0);

fn last_refusal_log() -> &'static Mutex<Option<Instant>> {
    static SLOT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// یک رد شدن را می‌شمارد؛ حداکثر هر ۳۰ ثانیه یک خلاصه — هرگز آدرس همتا.
fn note_refusal(reason: &str) {
    let total = REFUSALS.fetch_add(1, Ordering::Relaxed) + 1;
    let mut last = last_refusal_log().lock();
    if last.is_some_and(|t| t.elapsed() < REFUSAL_LOG_INTERVAL) {
        return;
    }
    *last = Some(Instant::now());
    DiagnosticsLog::w(
        TAG,
        &format!(
            "Refused a shared-proxy connection because of {reason} ({total} refused so far this session)."
        ),
    );
}

/// یک کارت شبکهٔ واقعی که اشتراک رویش باز است.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanTarget {
    pub address: Ipv4Addr,
    pub prefix: u8,
    /// `wifi` یا `ethernet`.
    pub kind: &'static str,
    pub name: String,
}

/// نمای UI از یک آدرس اشتراک.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareTarget {
    pub address: String,
    pub kind: String,
}

/// وضعیت اشتراک LAN — همان `LanStatus` موبایل.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanStatus {
    Off,
    Waiting,
    Ready,
    PortBusy,
}

impl LanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LanStatus::Off => "off",
            LanStatus::Waiting => "waiting",
            LanStatus::Ready => "ready",
            LanStatus::PortBusy => "portBusy",
        }
    }
}

// ============================================================ credentials

const KEY_USER: &str = "shareProxyUser";
const KEY_PASSWORD: &str = "shareProxyPassword";
const KEY_REQUIRED: &str = "shareAuthRequired";
const GENERATED_PASSWORD_LEN: usize = 16;

/// نمای UIِ رمز اشتراک (موبایل `ShareCredentials`). رمز فقط برای نمایش در
/// برنامه برمی‌گردد؛ صفحه‌های اشتراک هرگز آن را نشان نمی‌دهند.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareCredentials {
    pub auth_required: bool,
    pub user: String,
    pub password: String,
}

/// رمز را از انبارِ مهرشده (DPAPI) می‌خواند، اگر نبود یکی می‌سازد و به
/// شنونده‌ها می‌دهد. پیش‌فرض: رمز خاموش.
pub fn load_credentials(data_dir: &std::path::Path) -> ShareCredentials {
    let store = crate::secret_store::SecretStore::new(data_dir);
    let mut user = store.read(KEY_USER);
    if !share_guard::valid_user(&user) {
        user = share_guard::DEFAULT_USER.to_string();
    }
    let mut password = store.read(KEY_PASSWORD);
    if !share_guard::valid_password(&password) {
        password = share_guard::random_password(GENERATED_PASSWORD_LEN);
        if let Err(e) = store.write(KEY_PASSWORD, &password) {
            DiagnosticsLog::w(TAG, &format!("Could not seal the share password: {e}"));
        }
    }
    let creds = ShareCredentials {
        auth_required: store.read(KEY_REQUIRED) == "1",
        user,
        password,
    };
    set_auth(creds.auth_required, &creds.user, &creds.password);
    creds
}

/// رمز اشتراک را روشن/خاموش می‌کند.
pub fn set_auth_required(data_dir: &std::path::Path, required: bool) -> Result<ShareCredentials> {
    let store = crate::secret_store::SecretStore::new(data_dir);
    store.write(KEY_REQUIRED, if required { "1" } else { "" })?;
    DiagnosticsLog::i(
        TAG,
        if required {
            "Share authentication turned on."
        } else {
            "Share authentication turned off."
        },
    );
    Ok(load_credentials(data_dir))
}

/// نام کاربری و رمز دلخواه. خطاها: `badUser`، `shortPass`.
pub fn set_credentials(
    data_dir: &std::path::Path,
    user: &str,
    password: &str,
) -> std::result::Result<ShareCredentials, String> {
    let user = user.trim();
    let password = password.trim();
    if !share_guard::valid_user(user) {
        return Err("badUser".into());
    }
    if !share_guard::valid_password(password) {
        return Err("shortPass".into());
    }
    let store = crate::secret_store::SecretStore::new(data_dir);
    store
        .write(KEY_USER, user)
        .and_then(|_| store.write(KEY_PASSWORD, password))
        .map_err(|e| e.to_string())?;
    DiagnosticsLog::i(TAG, "Share username/password changed.");
    Ok(load_credentials(data_dir))
}

/// یک رمز تازهٔ تصادفی؛ دستگاه‌های قبلی باید رمز جدید را وارد کنند.
pub fn rotate_password(data_dir: &std::path::Path) -> Result<ShareCredentials> {
    let store = crate::secret_store::SecretStore::new(data_dir);
    store.write(
        KEY_PASSWORD,
        &share_guard::random_password(GENERATED_PASSWORD_LEN),
    )?;
    DiagnosticsLog::i(TAG, "Share password regenerated.");
    Ok(load_credentials(data_dir))
}

// ================================================================ the bridge

pub struct ShareBridge {
    running: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    lan_running: Arc<AtomicBool>,
    lan_threads: Vec<JoinHandle<()>>,
    lan_enabled: bool,
    lan_status: LanStatus,
    targets: Vec<LanTarget>,
    last_lan_check: Option<Instant>,
    lan_since: Option<Instant>,
    idle_hint_logged: bool,
    socks_port: u16,
    http_port: u16,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
}

impl Default for ShareBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareBridge {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
            lan_running: Arc::new(AtomicBool::new(false)),
            lan_threads: Vec::new(),
            lan_enabled: false,
            lan_status: LanStatus::Off,
            targets: Vec::new(),
            last_lan_check: None,
            lan_since: None,
            idle_hint_logged: false,
            socks_port: 0,
            http_port: 0,
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// شمارندهٔ ترافیک (دانلود، آپلود) بر حسب بایت — خوراک TrafficPanel.
    pub fn traffic(&self) -> (u64, u64) {
        (
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }

    /// معادل `ShareBridge.start()` — رلهٔ واقعی را بالا می‌آورد.
    ///
    /// `lan=false`: فقط 127.0.0.1 (مسیر دادهٔ پروکسی سیستمی خود دستگاه).
    /// `lan=true`: علاوه بر آن روی هر کارت Wi‑Fi/Ethernetِ واقعی.
    pub fn start(&mut self, socks_port: u16, http_port: u16, lan: bool) -> Result<()> {
        self.stop();
        self.running = Arc::new(AtomicBool::new(true));
        self.rx.store(0, Ordering::Relaxed);
        self.tx.store(0, Ordering::Relaxed);
        self.socks_port = socks_port;
        self.http_port = http_port;

        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let http = spawn_listener(
            local,
            http_port,
            BIND_RETRIES,
            self.running.clone(),
            self.rx.clone(),
            self.tx.clone(),
            None,
        );
        let localhost_http_up = http.is_some();
        self.threads.extend(http);
        self.threads.extend(spawn_listener(
            local,
            socks_port,
            BIND_RETRIES,
            self.running.clone(),
            self.rx.clone(),
            self.tx.clone(),
            None,
        ));
        if !localhost_http_up {
            DiagnosticsLog::e(
                TAG,
                "HTTP bridge could not bind on 127.0.0.1 — the system-proxy data path is down!",
            );
            self.running.store(false, Ordering::SeqCst);
            return Err(anyhow::anyhow!("http bridge bind failed"));
        }
        DiagnosticsLog::i(
            TAG,
            &format!("Bridge up: socks5={socks_port} http={http_port} (localhost)"),
        );
        self.lan_enabled = lan;
        if lan {
            STUN_NOTED.store(false, Ordering::Relaxed);
            self.ensure_lan();
        }
        Ok(())
    }

    /// LAN را روشن/خاموش می‌کند بی‌آنکه شنوندهٔ loopback (پروکسی سیستمی) قطع شود.
    pub fn set_lan(&mut self, lan: bool) {
        if !self.is_running() {
            self.lan_enabled = lan;
            return;
        }
        if lan == self.lan_enabled {
            return;
        }
        self.lan_enabled = lan;
        if lan {
            STUN_NOTED.store(false, Ordering::Relaxed);
            self.ensure_lan();
        } else {
            self.close_lan();
            DiagnosticsLog::i(TAG, "LAN sharing turned off.");
        }
    }

    /// از تیکِ کنترل‌گر: هر ۳ ثانیه کارت‌ها را دوباره می‌بیند (تغییرِ Wi‑Fi،
    /// وصل‌شدنِ کابل…) و در صورت نیاز دوباره bind می‌کند.
    pub fn refresh_lan(&mut self) {
        if !self.is_running() || !self.lan_enabled {
            return;
        }
        if self
            .last_lan_check
            .is_some_and(|t| t.elapsed() < LAN_WATCH_INTERVAL)
        {
            self.maybe_log_idle_hint();
            return;
        }
        self.last_lan_check = Some(Instant::now());
        let fresh = find_lan_targets();
        let changed = match self.lan_status {
            LanStatus::Ready => !same_targets(&fresh, &self.targets),
            _ => !fresh.is_empty(),
        };
        if changed {
            if self.lan_status == LanStatus::Ready {
                DiagnosticsLog::i(TAG, "Network changed — rebinding the share.");
            }
            self.close_lan();
            self.ensure_lan_with(fresh);
        }
        self.maybe_log_idle_hint();
    }

    fn ensure_lan(&mut self) {
        self.last_lan_check = Some(Instant::now());
        let found = find_lan_targets();
        self.ensure_lan_with(found);
    }

    fn ensure_lan_with(&mut self, found: Vec<LanTarget>) {
        if found.is_empty() {
            if self.lan_status != LanStatus::Waiting {
                DiagnosticsLog::w(
                    TAG,
                    "LAN sharing is on, but this PC is not on a Wi-Fi or Ethernet network yet — waiting.",
                );
            }
            self.lan_status = LanStatus::Waiting;
            self.targets.clear();
            lan_targets_slot().write().clear();
            return;
        }
        self.lan_running = Arc::new(AtomicBool::new(true));
        // پیش از اولین accept پر شود تا پذیرش، کارت‌ها را بشناسد.
        *lan_targets_slot().write() = found.clone();
        let mut bound = Vec::new();
        for target in &found {
            let ip = IpAddr::V4(target.address);
            let http = spawn_listener(
                ip,
                self.http_port,
                LAN_BIND_RETRIES,
                self.lan_running.clone(),
                self.rx.clone(),
                self.tx.clone(),
                Some(target.clone()),
            );
            let socks = spawn_listener(
                ip,
                self.socks_port,
                LAN_BIND_RETRIES,
                self.lan_running.clone(),
                self.rx.clone(),
                self.tx.clone(),
                Some(target.clone()),
            );
            let ok = http.is_some() && socks.is_some();
            self.lan_threads.extend(http);
            self.lan_threads.extend(socks);
            if ok {
                bound.push(target.clone());
            }
        }
        if bound.is_empty() {
            DiagnosticsLog::e(
                TAG,
                &format!(
                    "LAN sharing could not open ports {}/{} — another program is using them.",
                    self.socks_port, self.http_port
                ),
            );
            self.close_lan();
            self.lan_status = LanStatus::PortBusy;
            self.targets = found;
            return;
        }
        DiagnosticsLog::i(
            TAG,
            &format!(
                "LAN sharing ready on {} (socks5={} http={}).",
                describe_targets(&bound),
                self.socks_port,
                self.http_port
            ),
        );
        *lan_targets_slot().write() = bound.clone();
        self.targets = bound;
        self.lan_status = LanStatus::Ready;
        self.lan_since = Some(Instant::now());
        self.idle_hint_logged = false;
    }

    fn maybe_log_idle_hint(&mut self) {
        if self.lan_status != LanStatus::Ready
            || self.idle_hint_logged
            || LAN_SEEN.load(Ordering::Relaxed)
        {
            return;
        }
        if self
            .lan_since
            .is_some_and(|t| t.elapsed() >= IDLE_HINT_AFTER)
        {
            self.idle_hint_logged = true;
            DiagnosticsLog::i(
                TAG,
                "No device has used the share yet. Check that the other device is on the same \
                 network, that its proxy points at the address shown in the Share tab, and that \
                 Windows Firewall allows Aether on private networks.",
            );
        }
    }

    fn close_lan(&mut self) {
        self.lan_running.store(false, Ordering::SeqCst);
        for t in self.lan_threads.drain(..) {
            let _ = t.join();
        }
        lan_targets_slot().write().clear();
        self.targets.clear();
        self.lan_status = LanStatus::Off;
        self.lan_since = None;
    }

    pub fn stop(&mut self) {
        self.close_lan();
        if self.running.swap(false, Ordering::SeqCst) {
            DiagnosticsLog::i(TAG, "Bridge stopped.");
        }
        // شنونده‌ها حداکثر ~۸۰ms بعد پرچم را می‌بینند و خارج می‌شوند؛ join یعنی
        // وقتی برمی‌گردیم پورت‌ها واقعاً آزادند.
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        self.lan_enabled = false;
    }

    /// `off` / `waiting` / `ready` / `portBusy`.
    pub fn lan_status(&self) -> &'static str {
        if !self.is_running() || !self.lan_enabled {
            return LanStatus::Off.as_str();
        }
        self.lan_status.as_str()
    }

    /// همهٔ آدرس‌های اشتراک؛ اولی آدرس اصلی (مسیر پیش‌فرض) است.
    pub fn targets(&self) -> Vec<ShareTarget> {
        if self.lan_status() != "ready" {
            return Vec::new();
        }
        self.targets
            .iter()
            .map(|t| ShareTarget {
                address: t.address.to_string(),
                kind: t.kind.to_string(),
            })
            .collect()
    }

    /// تعداد اتصال‌های زندهٔ دستگاه‌های شبکه.
    pub fn lan_clients(&self) -> usize {
        if self.lan_status() != "ready" {
            return 0;
        }
        LAN_LIVE.load(Ordering::Relaxed)
    }

    fn primary(&self) -> Option<Ipv4Addr> {
        if self.lan_status() != "ready" {
            return None;
        }
        self.targets.first().map(|t| t.address)
    }

    /// آدرس اشتراک LAN — فقط وقتی اشتراک آماده است.
    pub fn socks_endpoint(&self) -> Option<String> {
        self.primary().map(|ip| format!("{ip}:{}", self.socks_port))
    }

    pub fn http_endpoint(&self) -> Option<String> {
        self.primary().map(|ip| format!("{ip}:{}", self.http_port))
    }
}

impl Drop for ShareBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

fn same_targets(a: &[LanTarget], b: &[LanTarget]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.address == y.address && x.prefix == y.prefix)
}

fn describe_targets(targets: &[LanTarget]) -> String {
    targets
        .iter()
        .map(|t| format!("{} {}/{}", t.kind, t.address, t.prefix))
        .collect::<Vec<_>>()
        .join(", ")
}

/// bind با تلاش مجدد — بلافاصله بعد از ری‌استارت، پورت ممکن است هنوز در
/// انتظار بستهٔ نسل قبل باشد (os error 10048).
fn bind_with_retry(ip: IpAddr, port: u16, retries: u32) -> Option<TcpListener> {
    let mut last_err = None;
    for attempt in 0..retries.max(1) {
        match TcpListener::bind((ip, port)) {
            Ok(l) => return Some(l),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < retries {
                    std::thread::sleep(BIND_RETRY_DELAY);
                }
            }
        }
    }
    if let Some(e) = last_err {
        DiagnosticsLog::e(TAG, &format!("Could not listen on {ip}:{port} — {e}"));
    }
    None
}

/// AETHER-APP-PATCH security-audit-1.3.0 (S-05): one thread per client, so cap them.
static ACTIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);
const MAX_CLIENTS: usize = 768;

fn is_loopback_peer(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// همتای شبکهٔ خصوصی (RFC1918/link-local) — هرگز آدرس عمومی.
fn is_private_peer(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(_) => false,
    }
}

/// پذیرش (موبایل `admit`): شنوندهٔ loopback فقط loopback؛ شنوندهٔ LAN فقط
/// همتایی که در زیرشبکهٔ یکی از کارت‌های اشتراک باشد.
fn admit(peer: IpAddr, lan: bool) -> bool {
    if !lan {
        return admit_with(peer, false, &[]);
    }
    let targets = lan_targets_slot().read();
    admit_with(peer, true, &targets)
}

fn admit_with(peer: IpAddr, lan: bool, targets: &[LanTarget]) -> bool {
    if !lan {
        if !is_loopback_peer(peer) {
            note_refusal("a non-loopback peer on the loopback listener");
            return false;
        }
        return true;
    }
    if targets.is_empty() {
        note_refusal("LAN sharing not being ready");
        return false;
    }
    let peer = peer.to_canonical();
    if !is_private_peer(peer)
        || !targets
            .iter()
            .any(|t| share_guard::same_subnet(peer, IpAddr::V4(t.address), t.prefix))
    {
        note_refusal("a peer outside the shared network");
        return false;
    }
    true
}

fn spawn_listener(
    ip: IpAddr,
    port: u16,
    retries: u32,
    running: Arc<AtomicBool>,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    via: Option<LanTarget>,
) -> Option<JoinHandle<()>> {
    let listener = bind_with_retry(ip, port, retries)?;
    let _ = listener.set_nonblocking(true);
    std::thread::Builder::new()
        .name(format!("aether-bridge-{port}"))
        .spawn(move || {
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, peer)) => {
                        // سوکت پذیرفته‌شده در ویندوز non-blocking بودنِ شنونده را
                        // به ارث می‌برد؛ صریحاً blocking می‌کنیم.
                        if client.set_nonblocking(false).is_err() {
                            let _ = client.shutdown(Shutdown::Both);
                            continue;
                        }
                        let lan = via.is_some();
                        if !admit(peer.ip(), lan) {
                            let _ = client.shutdown(Shutdown::Both);
                            continue;
                        }
                        if ACTIVE_CLIENTS.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                            ACTIVE_CLIENTS.fetch_sub(1, Ordering::SeqCst);
                            note_refusal("the simultaneous-connection limit");
                            let _ = client.shutdown(Shutdown::Both);
                            continue;
                        }
                        if let Some(target) = via.as_ref() {
                            LAN_LIVE.fetch_add(1, Ordering::SeqCst);
                            if !LAN_SEEN.swap(true, Ordering::Relaxed) {
                                DiagnosticsLog::i(
                                    TAG,
                                    &format!(
                                        "First device reached the share via {} ({}).",
                                        target.name, target.kind
                                    ),
                                );
                            }
                        }
                        let (rx, tx) = (rx.clone(), tx.clone());
                        std::thread::spawn(move || {
                            // آدرس bind مرجع است: همتای LAN نمی‌تواند سیاستِ
                            // دورزدنِ مستقیمِ میزبان را انتخاب کند.
                            handle_client(client, !lan, rx, tx);
                            ACTIVE_CLIENTS.fetch_sub(1, Ordering::SeqCst);
                            if lan {
                                LAN_LIVE.fetch_sub(1, Ordering::SeqCst);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(80));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
        })
        .ok()
}

/// هر دو پورت هر دو پروتکل را می‌پذیرند: SOCKS5 همیشه با 0x05 شروع می‌شود.
fn handle_client(client: TcpStream, host_listener: bool, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_millis(15_000)));
    let mut first = [0u8; 1];
    match client.peek(&mut first) {
        Ok(n) if n > 0 => {
            if first[0] == 0x05 {
                if host_listener {
                    handle_socks(client, rx, tx)
                } else {
                    handle_lan_socks(client, rx, tx)
                }
            } else {
                handle_http(client, host_listener, rx, tx)
            }
        }
        _ => {
            let _ = client.shutdown(Shutdown::Both);
        }
    }
}

/// SOCKS5 روی loopback: پس‌دهیِ خام به خروجیِ خط لوله (یا قواعدِ جلو).
fn handle_socks(client: TcpStream, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    // >>> AETHER-APP-PATCH bridge-smart-routes (mobile 1.4.0 `PsiphonSocksFront.setRoutes`)
    if let Some(rules) = crate::smart_routes::front_for_listener(true) {
        return handle_socks_front(client, &rules, rx, tx);
    }
    // <<< AETHER-APP-PATCH bridge-smart-routes
    let upstream_addr = SocketAddr::from(([127, 0, 0, 1], crate::engine::exit_socks_port()));
    match TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT) {
        Ok(upstream) => {
            let _ = upstream.set_nodelay(true);
            relay(client, upstream, rx, tx);
        }
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
        }
    }
}

// ================================================================ LAN SOCKS5

const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const SOCKS_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REP_NOT_ALLOWED: u8 = 0x02;
const SOCKS_REP_CONN_REFUSED: u8 = 0x05;
const SOCKS_REP_CMD_NOT_SUPPORTED: u8 = 0x07;

fn socks_reply(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

fn socks_reply_bound(address: IpAddr, port: u16) -> Vec<u8> {
    let mut out = vec![0x05, SOCKS_REP_SUCCEEDED, 0x00];
    match address {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn read_exact_vec(input: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    input.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// SOCKS5 برای دستگاهِ شبکه: پل خودش مذاکره را تمام می‌کند — احراز هویتِ
/// اختیاری RFC 1929، بعد درخواست بررسی می‌شود: CONNECT با
/// `destination_allowed` سنجیده و رله می‌شود؛ UDP ASSOCIATE یک رلهٔ واقعی روی
/// همان کارت می‌گیرد؛ هر چیز دیگر رد می‌شود.
fn handle_lan_socks(mut client: TcpStream, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let _ = client.set_read_timeout(Some(AUTH_TIMEOUT));
    if !negotiate_lan_socks(&mut client) {
        return;
    }
    let Some(request) = read_socks_request(&mut client) else {
        return;
    };
    match request.command {
        SOCKS_CMD_CONNECT => {
            // صفحهٔ بررسی همین‌جا پاسخ داده می‌شود؛ بالادست چنین نامی ندارد.
            if share_guard::is_check_target(&request.host) {
                serve_check_over_stream(client, request.port, true, &[]);
                return;
            }
            if !share_guard::destination_allowed(&request.host) {
                note_refusal("a LAN request for a non-public destination");
                let _ = client.write_all(&socks_reply(SOCKS_REP_NOT_ALLOWED));
                return;
            }
            if let Some(rules) = crate::smart_routes::front_for_listener(false) {
                if route_with_rules(&request.host, request.port, &rules).0
                    == crate::smart_routes::Action::Block
                {
                    let _ = client.write_all(&socks_reply(SOCKS_REP_NOT_ALLOWED));
                    return;
                }
            }
            let _ = client.set_read_timeout(None);
            let Some(mut upstream) = dial_upstream_greeted() else {
                let _ = client.write_all(&socks_reply(SOCKS_REP_GENERAL_FAILURE));
                return;
            };
            // درخواستِ خودِ دستگاه را به موتور می‌دهیم (نام‌ها نام می‌مانند تا DNS
            // داخل تونل حل شود)؛ پاسخ و بقیه مستقیم برمی‌گردد.
            if upstream.write_all(&request.raw).is_err() {
                let _ = client.write_all(&socks_reply(SOCKS_REP_GENERAL_FAILURE));
                return;
            }
            tx.fetch_add(request.raw.len() as u64, Ordering::Relaxed);
            relay(client, upstream, rx, tx);
        }
        SOCKS_CMD_UDP_ASSOCIATE if crate::smart_routes::front_udp_passthrough() => {
            serve_udp_associate(client, &request, rx, tx);
        }
        _ => {
            let _ = client.write_all(&socks_reply(SOCKS_REP_CMD_NOT_SUPPORTED));
        }
    }
}

/// مذاکرهٔ روش: با رمزِ روشن فقط 0x02 (کلاینتی که احراز نکند رد می‌شود، هرگز
/// تنزل داده نمی‌شود). با رمزِ خاموش 0x00 ترجیح دارد و کلاینتی که به‌هرحال
/// نام/رمز تنظیم کرده، بعد از یک تبادلِ صوریِ 0x02 رد می‌شود.
fn negotiate_lan_socks(client: &mut TcpStream) -> bool {
    let Some(greeting) = read_exact_vec(client, 2) else {
        return false;
    };
    if greeting[0] != 0x05 || greeting[1] == 0 {
        return false;
    }
    let Some(methods) = read_exact_vec(client, greeting[1] as usize) else {
        return false;
    };
    let offers_no_auth = methods.contains(&0x00);
    let offers_user_pass = methods.contains(&0x02);
    let auth = auth();
    if !auth.required && offers_no_auth {
        return client.write_all(&[0x05, 0x00]).is_ok();
    }
    if !offers_user_pass {
        let _ = client.write_all(&[0x05, 0xFF]);
        note_refusal("a LAN SOCKS5 client that did not offer username/password");
        return false;
    }
    if client.write_all(&[0x05, 0x02]).is_err() {
        return false;
    }
    let Some(header) = read_exact_vec(client, 2) else {
        return false;
    };
    if header[0] != 0x01 {
        return false;
    }
    let Some(user) = read_exact_vec(client, header[1] as usize) else {
        return false;
    };
    let Some(pass_len) = read_exact_vec(client, 1) else {
        return false;
    };
    let Some(pass) = read_exact_vec(client, pass_len[0] as usize) else {
        return false;
    };
    let offered_user = String::from_utf8_lossy(&user);
    let offered_pass = String::from_utf8_lossy(&pass);
    let ok = !auth.required
        || (!auth.password.trim().is_empty()
            && share_guard::secret_equals(&auth.user, &offered_user)
            && share_guard::secret_equals(&auth.password, &offered_pass));
    let _ = client.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]);
    if !ok {
        note_refusal("a wrong shared-proxy username or password");
    }
    ok
}

/// یک درخواست SOCKS5 تجزیه‌شده؛ `raw` همان بایت‌هاست برای پس‌دادن.
struct SocksRequest {
    command: u8,
    host: String,
    port: u16,
    raw: Vec<u8>,
}

fn read_socks_request(input: &mut TcpStream) -> Option<SocksRequest> {
    let head = read_exact_vec(input, 4)?;
    if head[0] != 0x05 {
        return None;
    }
    let mut raw = head.clone();
    let host = match head[3] {
        0x01 => {
            let a = read_exact_vec(input, 4)?;
            raw.extend_from_slice(&a);
            Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string()
        }
        0x04 => {
            let a = read_exact_vec(input, 16)?;
            raw.extend_from_slice(&a);
            let mut o = [0u8; 16];
            o.copy_from_slice(&a);
            std::net::Ipv6Addr::from(o).to_string()
        }
        0x03 => {
            let len = read_exact_vec(input, 1)?[0];
            let name = read_exact_vec(input, len as usize)?;
            raw.push(len);
            raw.extend_from_slice(&name);
            name.iter().map(|&b| b as char).collect()
        }
        _ => return None,
    };
    let port_bytes = read_exact_vec(input, 2)?;
    raw.extend_from_slice(&port_bytes);
    Some(SocksRequest {
        command: head[1],
        host,
        port: u16::from_be_bytes([port_bytes[0], port_bytes[1]]),
        raw,
    })
}

/// اتصال به SOCKS5 بالادست و تمام‌کردنِ سلامِ بدون‌احراز. بالادست «همیشه»
/// loopback است — پل هرگز خودش به اینترنت شماره نمی‌گیرد (بی‌نشتی).
fn dial_upstream_greeted() -> Option<TcpStream> {
    let addr = SocketAddr::from(([127, 0, 0, 1], crate::engine::exit_socks_port()));
    let result = (|| -> std::io::Result<TcpStream> {
        let mut s = TcpStream::connect_timeout(&addr, DIAL_TIMEOUT)?;
        let _ = s.set_nodelay(true);
        s.set_read_timeout(Some(DIAL_TIMEOUT))?;
        s.write_all(&[0x05, 0x01, 0x00])?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply)?;
        if reply != [0x05, 0x00] {
            return Err(std::io::Error::other("SOCKS5 greeting failed"));
        }
        s.set_read_timeout(None)?;
        Ok(s)
    })();
    match result {
        Ok(s) => Some(s),
        Err(e) => {
            DiagnosticsLog::e(
                TAG,
                &format!("Tunnel upstream not reachable - connection refused (fail closed): {e}"),
            );
            None
        }
    }
}

/// UDP ASSOCIATE برای دستگاهِ شبکه، از داخل تونل.
///
/// بالادست فقط یک رلهٔ loopback دارد که دستگاهِ شبکه به آن نمی‌رسد؛ پس:
///
///   دستگاه <-UDP-> [سوکت روی کارتِ اشتراک] <-> [سوکت loopback] <-UDP-> رلهٔ بالادست
///
/// فقط بسته‌های IPِ خودِ دستگاه پذیرفته می‌شوند، مقصدِ هر بسته سنجیده می‌شود،
/// تکه‌ها دور ریخته می‌شوند و عمرِ پیوند همان عمرِ اتصالِ کنترلیِ TCP است.
fn serve_udp_associate(
    mut client: TcpStream,
    request: &SocksRequest,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
) {
    let Some(mut upstream) = dial_upstream_greeted() else {
        let _ = client.write_all(&socks_reply(SOCKS_REP_GENERAL_FAILURE));
        return;
    };
    let fail = |c: &mut TcpStream| {
        let _ = c.write_all(&socks_reply(SOCKS_REP_GENERAL_FAILURE));
    };
    let _ = upstream.set_read_timeout(Some(DIAL_TIMEOUT));
    if upstream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .is_err()
    {
        return fail(&mut client);
    }
    let Some(rep) = read_exact_vec(&mut upstream, 4) else {
        return fail(&mut client);
    };
    if rep[1] != 0 {
        return fail(&mut client);
    }
    let relay_ip: IpAddr = match rep[3] {
        0x01 => match read_exact_vec(&mut upstream, 4) {
            Some(a) => IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
            None => return fail(&mut client),
        },
        0x04 => match read_exact_vec(&mut upstream, 16) {
            Some(a) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&a);
                IpAddr::V6(std::net::Ipv6Addr::from(o))
            }
            None => return fail(&mut client),
        },
        0x03 => {
            let Some(len) = read_exact_vec(&mut upstream, 1) else {
                return fail(&mut client);
            };
            if read_exact_vec(&mut upstream, len[0] as usize).is_none() {
                return fail(&mut client);
            }
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        _ => return fail(&mut client),
    };
    let Some(port_bytes) = read_exact_vec(&mut upstream, 2) else {
        return fail(&mut client);
    };
    let relay_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    // 0.0.0.0 یعنی «همان آدرسی که به من رسیدی». هر چیزِ غیرِ loopback رد
    // می‌شود: UDPِ دستگاه هرگز جایی جز تونلِ محلی نمی‌رود.
    let relay_ip = if relay_ip.is_unspecified() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        relay_ip
    };
    if !relay_ip.to_canonical().is_loopback() || relay_port == 0 {
        DiagnosticsLog::w(
            TAG,
            "UDP relay refused: upstream offered a non-loopback relay",
        );
        return fail(&mut client);
    }
    let upstream_relay = SocketAddr::new(relay_ip, relay_port);
    let _ = upstream.set_read_timeout(None);

    let Ok(share_addr) = client.local_addr().map(|a| a.ip()) else {
        return fail(&mut client);
    };
    let Ok(peer_ip) = client.peer_addr().map(|a| a.ip().to_canonical()) else {
        return fail(&mut client);
    };
    let (Ok(cs), Ok(us)) = (
        UdpSocket::bind(SocketAddr::new(share_addr, 0)),
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
    ) else {
        return fail(&mut client);
    };
    let Ok(cs_port) = cs.local_addr().map(|a| a.port()) else {
        return fail(&mut client);
    };
    let _ = cs.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = us.set_read_timeout(Some(Duration::from_millis(500)));
    if client
        .write_all(&socks_reply_bound(share_addr, cs_port))
        .is_err()
    {
        return;
    }
    let _ = client.set_read_timeout(None);

    let stop = Arc::new(AtomicBool::new(false));
    // RFC 1928: دستگاه ممکن است پورتِ مبدأش را از قبل اعلام کند.
    let client_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(
        (request.port != 0).then(|| SocketAddr::new(peer_ip, request.port)),
    ));
    let (Ok(cs_up), Ok(us_up), Ok(cs_down), Ok(us_down)) = (
        cs.try_clone(),
        us.try_clone(),
        cs.try_clone(),
        us.try_clone(),
    ) else {
        return;
    };

    // دستگاه -> تونل
    let up = {
        let stop = stop.clone();
        let client_peer = client_peer.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            let governor=crate::uplink::current();let mut flow=crate::uplink_policy::Flow::default();
            while !stop.load(Ordering::Relaxed) {
                let (n, from) = match cs_up.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e)
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => break,
                };
                if from.ip().to_canonical() != peer_ip {
                    continue; // فقط همان دستگاهِ پیوندشده
                }
                let peer = {
                    let mut known = client_peer.lock();
                    match *known {
                        Some(k) if k.port() != from.port() => continue,
                        Some(k) => k,
                        None => {
                            *known = Some(from);
                            from
                        }
                    }
                };
                let data = &buf[..n];
                // پرس‌وجوی DNS برای aether.check همین‌جا جواب می‌گیرد.
                if let Some(local) = share_guard::check_host_dns_reply(data) {
                    let _ = cs_up.send_to(&local, peer);
                    continue;
                }
                if !share_guard::udp_datagram_allowed(data) {
                    note_refusal("a LAN UDP datagram to a non-public or malformed destination");
                    continue;
                }
                if share_guard::is_stun_datagram(data) && !STUN_NOTED.swap(true, Ordering::Relaxed)
                {
                    DiagnosticsLog::i(
                        TAG,
                        "WebRTC (STUN) from a shared device is being carried through the tunnel - \
                         its WebRTC address is the exit, not this line.",
                    );
                }
                if let Some(s)=governor.as_ref(){if !s.acquire(&mut flow,n,false){break;}}
                if us_up.send_to(data, upstream_relay).is_ok() {
                    tx.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        })
    };
    // تونل -> دستگاه
    let down = {
        let stop = stop.clone();
        let client_peer = client_peer.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            while !stop.load(Ordering::Relaxed) {
                let (n, from) = match us_down.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e)
                        if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => break,
                };
                if from != upstream_relay {
                    continue;
                }
                let Some(peer) = *client_peer.lock() else {
                    continue;
                };
                if cs_down.send_to(&buf[..n], peer).is_ok() {
                    rx.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        })
    };
    // پیوند وقتی تمام می‌شود که «هر کدام» از دو اتصالِ کنترلی تمام شود.
    let watch = {
        let client2 = client.try_clone().ok();
        let mut upstream2 = upstream.try_clone().ok();
        std::thread::spawn(move || {
            if let Some(u) = upstream2.as_mut() {
                let mut sink = [0u8; 256];
                while matches!(u.read(&mut sink), Ok(n) if n > 0) {}
            }
            if let Some(c) = client2 {
                let _ = c.shutdown(Shutdown::Both);
            }
        })
    };
    let mut sink = [0u8; 256];
    while matches!(client.read(&mut sink), Ok(n) if n > 0) {}
    stop.store(true, Ordering::Relaxed);
    let _ = upstream.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    let _ = up.join();
    let _ = down.join();
    let _ = watch.join();
}

// ===================================================================== HTTP

const PROXY_AUTH_HEADER: &str = "proxy-authorization:";

/// درخواست `Proxy-Authorization: Basic` معتبر دارد؟
fn http_authorized(head: &str) -> bool {
    let auth = auth();
    if auth.password.trim().is_empty() {
        return false;
    }
    let Some(line) = head.split("\r\n").skip(1).find(|l| {
        l.len() > PROXY_AUTH_HEADER.len()
            && l.is_char_boundary(PROXY_AUTH_HEADER.len())
            && l[..PROXY_AUTH_HEADER.len()].eq_ignore_ascii_case(PROXY_AUTH_HEADER)
    }) else {
        return false;
    };
    let Some((user, pass)) = share_guard::parse_basic_credential(&line[PROXY_AUTH_HEADER.len()..])
    else {
        return false;
    };
    share_guard::secret_equals(&auth.user, &user)
        && share_guard::secret_equals(&auth.password, &pass)
}

/// `host:port`، `[v6]:port` یا نامِ تنها -> (host, port)؛ نادرست = None.
fn split_target(value: &str, default_port: u16) -> Option<(String, u16)> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let parse_port = |p: &str| p.parse::<u16>().ok().filter(|p| *p > 0);
    if let Some(rest) = v.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if tail.is_empty() => default_port,
            None => return None,
        };
        return (!host.is_empty()).then(|| (host.to_string(), port));
    }
    match v.matches(':').count() {
        0 => Some((v.to_string(), default_port)),
        1 => {
            let (h, p) = v.split_once(':')?;
            let port = parse_port(p)?;
            (!h.is_empty()).then(|| (h.to_string(), port))
        }
        _ => None, // IPv6 بی‌براکت مبهم است
    }
}

fn write_response(out: &mut TcpStream, status: &str, kind: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(body.as_bytes());
    let _ = out.flush();
}

fn write_page(out: &mut TcpStream, page: share_pages::Page) {
    let disposition = page
        .filename
        .map(|f| format!("Content-Disposition: attachment; filename=\"{f}\"\r\n"))
        .unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{disposition}\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        page.status,
        page.content_type,
        page.body.len()
    );
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(page.body.as_bytes());
    let _ = out.flush();
}

/// درخواستِ origin-form مستقیم به پورت اشتراک: PAC، صفحهٔ راه‌اندازی، بررسی،
/// و فایل‌های قفل WebRTC.
fn serve_local_page(out: &mut TcpStream, path: &str, remote: bool) {
    let local = out
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let shown = match local {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    let http_port = crate::engine::SHARE_HTTP_PORT;
    let socks_port = crate::engine::SHARE_SOCKS_PORT;
    if let Some(page) = share_pages::download(path) {
        return write_page(out, page);
    }
    if path.eq_ignore_ascii_case("/proxy.pac") || path.eq_ignore_ascii_case("/wpad.dat") {
        return write_response(
            out,
            "200 OK",
            "application/x-ns-proxy-autoconfig",
            &share_guard::pac_script(&shown, http_port),
        );
    }
    if path == "/" || path.eq_ignore_ascii_case("/index.html") {
        return write_response(
            out,
            "200 OK",
            "text/html; charset=utf-8",
            &share_pages::setup_page(&shown, http_port, socks_port, Some(auth().required)),
        );
    }
    if path.eq_ignore_ascii_case("/check") {
        return write_response(
            out,
            "200 OK",
            "text/html; charset=utf-8",
            &share_pages::check_page(None, current_exit_ip().as_deref(), !remote),
        );
    }
    write_response(
        out,
        "404 Not Found",
        "text/plain; charset=utf-8",
        "Not found\n",
    );
}

/// پاسخِ `http://aether.check/<path>` — فقط «از داخلِ» اشتراک می‌رسد.
fn serve_check_path(out: &mut TcpStream, path: &str, remote: bool, via: &str) {
    if let Some(page) = share_pages::download(path) {
        return write_page(out, page);
    }
    write_response(
        out,
        "200 OK",
        "text/html; charset=utf-8",
        &share_pages::check_page(Some(via), current_exit_ip().as_deref(), !remote),
    );
}

/// میزبانِ بررسی از راه تونلِ CONNECT (HTTP یا SOCKS5): همان یک درخواستی که
/// مرورگر داخلش می‌فرستد را می‌خواند و پاسخ می‌دهد. 443 فوراً رد می‌شود (هیچ
/// گواهی‌ای برای این نام معتبر نیست) تا مرورگر بی‌درنگ به http:// برگردد.
fn serve_check_over_stream(mut client: TcpStream, port: u16, socks: bool, early: &[u8]) {
    if socks {
        if port == 443 {
            let _ = client.write_all(&socks_reply(SOCKS_REP_CONN_REFUSED));
            return;
        }
        if client.write_all(&socks_reply(SOCKS_REP_SUCCEEDED)).is_err() {
            return;
        }
    }
    let _ = client.set_read_timeout(Some(AUTH_TIMEOUT));
    // بایت‌هایی که پشتِ سرِ CONNECT در همان بسته آمدند از دست نروند.
    let head = match find_subsequence(early, b"\r\n\r\n") {
        Some(pos) => early[..pos + 4].to_vec(),
        None => match read_head_after(&mut client, early) {
            Some((h, _)) => h,
            None => return,
        },
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let raw_path = text
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("")
        .to_string();
    let path = if raw_path.starts_with('/') {
        raw_path
    } else {
        let after = raw_path.split_once("://").map(|(_, r)| r).unwrap_or("");
        format!("/{}", after.split_once('/').map(|(_, p)| p).unwrap_or(""))
    };
    let path = path.split('?').next().unwrap_or("/").to_string();
    let remote = client
        .peer_addr()
        .map(|a| !is_loopback_peer(a.ip()))
        .unwrap_or(true);
    serve_check_path(
        &mut client,
        &path,
        remote,
        if socks { "SOCKS5" } else { "HTTP CONNECT" },
    );
}

const FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// مسیرِ یک مقصد: قواعدِ جلو (Block/Direct/Proxy) و اتصال.
fn open_routed(host: &str, port: u16, host_listener: bool) -> Result<TcpStream, &'static [u8]> {
    let (action, pinned) = route_of(host, port, host_listener);
    let routed = match action {
        Action::Block => return Err(FORBIDDEN),
        // دستگاه‌های شبکه هرگز مستقیم نمی‌روند (بی‌نشتی).
        Action::Direct if host_listener => direct_stream(host, port, pinned),
        Action::Direct | Action::Proxy => probe::socks5_stream(host, port, UPSTREAM_TIMEOUT),
    };
    routed.ok_or(BAD_GATEWAY)
}

/// پروکسی HTTP: CONNECT و absolute-form، هر دو از داخل SOCKS5 بالادست (نام
/// به‌صورت نام می‌رود تا DNS داخل تونل حل شود).
fn handle_http(mut client: TcpStream, host_listener: bool, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let remote = !host_listener;
    let _ = client.set_read_timeout(Some(if remote {
        AUTH_TIMEOUT
    } else {
        Duration::from_millis(15_000)
    }));
    let Some((head, remainder)) = read_head(&mut client) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let first_line = text.split("\r\n").next().unwrap_or("").to_string();
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        let _ = client.write_all(BAD_REQUEST);
        return;
    }
    let (method, target) = (parts[0], parts[1]);

    // origin-form مستقیم به پورت پروکسی: صفحه‌های راه‌اندازی.
    if target.starts_with('/') {
        let path = target.split('?').next().unwrap_or("/");
        serve_local_page(&mut client, path, remote);
        return;
    }

    if remote && auth().required && !http_authorized(&text) {
        note_refusal("an unauthenticated HTTP proxy request");
        let _ = client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"Aether\", charset=\"UTF-8\"\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    if remote {
        let _ = client.set_read_timeout(Some(Duration::from_millis(15_000)));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_target(target, 443) else {
            let _ = client.write_all(BAD_REQUEST);
            return;
        };
        // CONNECT aether.check (مرورگرهای HTTPS-اول) همین‌جا پاسخ می‌گیرد.
        if share_guard::is_check_target(&host) {
            if port == 443 {
                let _ = client.write_all(BAD_GATEWAY);
                return;
            }
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_ok()
            {
                serve_check_over_stream(client, port, false, &remainder);
            }
            return;
        }
        if remote && !share_guard::destination_allowed(&host) {
            note_refusal("a LAN request for a non-public destination");
            let _ = client.write_all(FORBIDDEN);
            return;
        }
        match open_routed(&host, port, host_listener) {
            Ok(upstream) => {
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                relay(client, upstream, rx, tx);
            }
            Err(reply) => {
                let _ = client.write_all(reply);
            }
        }
        return;
    }

    // HTTP خام: METHOD http://host[:port]/path HTTP/1.1
    let url_rest = if target.len() > 7 && target[..7].eq_ignore_ascii_case("http://") {
        &target[7..]
    } else {
        // https:// یا نادرست — TLS باید CONNECT باشد.
        let _ = client.write_all(BAD_REQUEST);
        return;
    };
    let (host_port, path) = match url_rest.find('/') {
        Some(i) => (&url_rest[..i], &url_rest[i..]),
        None => (url_rest, "/"),
    };
    let Some((host, port)) = split_target(host_port, 80) else {
        let _ = client.write_all(BAD_REQUEST);
        return;
    };
    if share_guard::is_check_target(&host) {
        let path = path.split('?').next().unwrap_or("/");
        serve_check_path(&mut client, path, remote, "HTTP proxy");
        return;
    }
    if remote && !share_guard::destination_allowed(&host) {
        note_refusal("a LAN request for a non-public destination");
        let _ = client.write_all(FORBIDDEN);
        return;
    }
    let mut upstream = match open_routed(&host, port, host_listener) {
        Ok(u) => u,
        Err(reply) => {
            let _ = client.write_all(reply);
            return;
        }
    };

    // خط اول به origin-form؛ سرآیندهای پروکسی، اتصال و هویتی حذف می‌شوند.
    let mut rebuilt = format!("{method} {path} {}\r\n", parts[2]);
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-connection:")
            || lower.starts_with("proxy-authorization:")
            || lower.starts_with("connection:")
            || lower.starts_with("keep-alive:")
            || share_guard::is_identity_header(line)
        {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    rebuilt.push_str("Connection: close\r\n\r\n");
    if upstream.write_all(rebuilt.as_bytes()).is_err() || upstream.write_all(&remainder).is_err() {
        let _ = client.write_all(BAD_GATEWAY);
        return;
    }
    tx.fetch_add((rebuilt.len() + remainder.len()) as u64, Ordering::Relaxed);
    relay(client, upstream, rx, tx);
}

// >>> AETHER-APP-PATCH bridge-smart-routes
use crate::smart_routes::{Action, RouteRules};

/// مهلتِ اتصالِ مستقیم (بدون تونل) — همان اندازهٔ دست‌دادنِ معمول.
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// DNS for CIDR decisions travels THROUGH the active tunnel. A host's normal
/// resolver could both leak arbitrary .com lookups and see a different CDN IP.
/// The tunnel's SOCKS endpoint resolves the DoH provider's own hostname.
fn tunnel_ipv4_answers(name: &str) -> Vec<IpAddr> {
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Vec::new();
    }
    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type=A");
    let Ok(response) = crate::mini_https::exchange(
        crate::mini_https::Dial::Socks(crate::engine::exit_socks_port()),
        "GET",
        &url,
        &[("Accept", "application/dns-json".to_string())],
        None,
        Duration::from_secs(5),
        64 * 1024,
    ) else {
        return Vec::new();
    };
    if response.code != 200 {
        return Vec::new();
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        return Vec::new();
    };
    if json.get("Status").and_then(|v| v.as_u64()) != Some(0) {
        return Vec::new();
    }
    json.get("Answer")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .filter(|a| a.get("type").and_then(|v| v.as_u64()) == Some(1))
        .filter_map(|a| {
            a.get("data")?
                .as_str()?
                .parse::<Ipv4Addr>()
                .ok()
                .map(IpAddr::V4)
        })
        .collect()
}

/// First pass is the hostname; second pass compares A answers against CIDRs.
/// Never send a Direct decision based on a name to the guest listener.
fn route_with_answers(
    host: &str,
    port: u16,
    rules: &RouteRules,
    answers: &[IpAddr],
) -> (Action, Option<SocketAddr>) {
    let parsed = host.parse::<IpAddr>().ok();
    let by_name = rules.decide_name_ip(Some(host), parsed, port);
    if by_name != Action::Proxy || parsed.is_some() {
        return (by_name, None);
    }
    // Block wins regardless of DNS answer order. A matched direct answer is
    // pinned for connect, preventing another DNS lookup from changing its IP.
    let mut direct = None;
    for ip in answers {
        match rules.decide_name_ip(Some(host), Some(*ip), port) {
            Action::Block => return (Action::Block, None),
            Action::Direct if direct.is_none() => direct = Some(SocketAddr::new(*ip, port)),
            _ => {}
        }
    }
    match direct {
        Some(addr) => (Action::Direct, Some(addr)),
        None => (Action::Proxy, None),
    }
}

/// DNS errors never turn unknown destinations into direct connections.
fn route_with_rules(host: &str, port: u16, rules: &RouteRules) -> (Action, Option<SocketAddr>) {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let first = route_with_answers(bare, port, rules, &[]);
    if first.0 != Action::Proxy || !rules.has_ip_rules() || bare.parse::<IpAddr>().is_ok() {
        return first;
    }
    route_with_answers(bare, port, rules, &tunnel_ipv4_answers(bare))
}

fn route_of(host: &str, port: u16, host_listener: bool) -> (Action, Option<SocketAddr>) {
    match crate::smart_routes::front_for_listener(host_listener) {
        Some(rules) => route_with_rules(host, port, &rules),
        None => (Action::Proxy, None),
    }
}

/// اتصالِ مستقیم از کارتِ شبکهٔ واقعی، برای قواعدِ «مستقیم» (مثلاً سایت‌های
/// ایرانی). IPv4 اول، همان ترتیبِ `mini_https`.
fn direct_stream(host: &str, port: u16, pinned: Option<SocketAddr>) -> Option<TcpStream> {
    let addrs: Vec<SocketAddr> = match pinned {
        Some(addr) => vec![addr],
        None => (host, port).to_socket_addrs().ok()?.collect(),
    };
    let mut ordered: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).cloned().collect();
    ordered.extend(addrs.iter().filter(|a| a.is_ipv6()).cloned());
    for addr in ordered {
        // هرگز به پورت‌های خودِ برنامه روی loopback برنگرد (حلقه).
        // S-04: `::ffff:127.0.0.1` and `0.0.0.0` reach this machine too.
        let ip = addr.ip().to_canonical();
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        if let Ok(s) = TcpStream::connect_timeout(&addr, DIRECT_CONNECT_TIMEOUT) {
            let _ = s.set_nodelay(true);
            return Some(s);
        }
    }
    None
}

/// SOCKS5 (RFC 1928) که این‌جا پایان می‌یابد تا قاعده‌ها اعمال شوند.
///
/// فقط CONNECT؛ UDP ASSOCIATE با `0x07` رد می‌شود — خروجیِ Psiphon اصلاً UDP
/// حمل نمی‌کند، پس چیزی از دست نمی‌رود. Block → `0x02` (ruleset)، همان کدی که
/// موتور برای قاعدهٔ block برمی‌گرداند.
fn handle_socks_front(
    mut client: TcpStream,
    rules: &RouteRules,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
) {
    fn reply(c: &mut TcpStream, rep: u8) -> bool {
        c.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .is_ok()
    }
    let mut head = [0u8; 2];
    if client.read_exact(&mut head).is_err() || head[0] != 0x05 {
        let _ = client.shutdown(Shutdown::Both);
        return;
    }
    let mut methods = vec![0u8; head[1] as usize];
    if client.read_exact(&mut methods).is_err() {
        return;
    }
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[0x05, 0xFF]);
        return;
    }
    if client.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    let mut req = [0u8; 4];
    if client.read_exact(&mut req).is_err() || req[0] != 0x05 {
        return;
    }
    let mut raw_addr = Vec::new();
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            if client.read_exact(&mut a).is_err() {
                return;
            }
            raw_addr.extend_from_slice(&a);
            Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            if client.read_exact(&mut len).is_err() {
                return;
            }
            let mut name = vec![0u8; len[0] as usize];
            if client.read_exact(&mut name).is_err() {
                return;
            }
            raw_addr.push(len[0]);
            raw_addr.extend_from_slice(&name);
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut a = [0u8; 16];
            if client.read_exact(&mut a).is_err() {
                return;
            }
            raw_addr.extend_from_slice(&a);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            let _ = reply(&mut client, 0x08);
            return;
        }
    };
    let mut port_bytes = [0u8; 2];
    if client.read_exact(&mut port_bytes).is_err() {
        return;
    }
    let port = u16::from_be_bytes(port_bytes);
    // ۱.۵.۰: صفحهٔ بررسی از مسیر SOCKS5 هم پاسخ می‌گیرد.
    if req[1] == 0x01 && share_guard::is_check_target(&host) {
        serve_check_over_stream(client, port, true, &[]);
        return;
    }
    if req[1] != 0x01 {
        // For the ordinary engine keep its UDP/BIND behavior even when the
        // host's TCP bypass is enabled; the chained Psiphon path is TCP-only.
        if crate::smart_routes::front_udp_passthrough() {
            let upstream_addr =
                SocketAddr::from(([127, 0, 0, 1], crate::engine::exit_socks_port()));
            if let Ok(mut upstream) = TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT) {
                let _ = upstream.set_read_timeout(Some(Duration::from_secs(15)));
                if upstream.write_all(&[5, 1, 0]).is_ok() {
                    let mut greeting = [0u8; 2];
                    if upstream.read_exact(&mut greeting).is_ok() && greeting == [5, 0] {
                        let mut raw_request = req.to_vec();
                        raw_request.extend_from_slice(&raw_addr);
                        raw_request.extend_from_slice(&port_bytes);
                        if upstream.write_all(&raw_request).is_ok() {
                            let mut response = [0u8; 4];
                            if upstream.read_exact(&mut response).is_ok() && response[0] == 5 {
                                let addr_len = match response[3] {
                                    1 => Some(4usize),
                                    4 => Some(16usize),
                                    3 => {
                                        let mut size = [0u8; 1];
                                        if upstream.read_exact(&mut size).is_ok() {
                                            Some(size[0] as usize + 1)
                                        } else {
                                            None
                                        }
                                    }
                                    _ => None,
                                };
                                if let Some(size) = addr_len {
                                    let mut rest = vec![0u8; size + 2];
                                    // For ATYP=DOMAIN the size byte was already read.
                                    if response[3] == 3 {
                                        rest[0] = (size - 1) as u8;
                                        if upstream.read_exact(&mut rest[1..]).is_err() {
                                            return;
                                        }
                                    } else if upstream.read_exact(&mut rest).is_err() {
                                        return;
                                    }
                                    let mut raw_response = response.to_vec();
                                    raw_response.extend_from_slice(&rest);
                                    if client.write_all(&raw_response).is_ok() {
                                        relay(client, upstream, rx, tx);
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = reply(&mut client, 0x07);
        return;
    }
    let (action, pinned) = route_with_rules(&host, port, rules);
    let upstream = match action {
        Action::Block => {
            let _ = reply(&mut client, 0x02);
            return;
        }
        Action::Direct => direct_stream(&host, port, pinned),
        Action::Proxy => probe::socks5_stream(&host, port, UPSTREAM_TIMEOUT),
    };
    match upstream {
        Some(up) => {
            if reply(&mut client, 0x00) {
                relay(client, up, rx, tx);
            }
        }
        None => {
            let _ = reply(&mut client, 0x05);
        }
    }
}
// <<< AETHER-APP-PATCH bridge-smart-routes

/// خواندن سرآیند HTTP تا `\r\n\r\n`؛ بایت‌های اضافه (شروع بدنه) جدا برمی‌گردند.
fn read_head(client: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    read_head_after(client, &[])
}

/// همان `read_head`، با بایت‌هایی که پیش‌تر خوانده شده‌اند.
fn read_head_after(client: &mut TcpStream, early: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    buf.extend_from_slice(early);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(pos + 4);
            return Some((buf, rest));
        }
        if buf.len() > 32_768 {
            return None;
        }
        match client.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// کپی دوطرفه با شمارش بایت‌ها — دانلود = سرور→کلاینت، آپلود = کلاینت→سرور.
fn relay(client: TcpStream, upstream: TcpStream, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    // هر مهلت خواندن/نوشتنی که در مرحلهٔ دست‌دادن روی سوکت‌ها مانده پاک شود؛
    // یک دانلود طولانی نباید بعد از ۱۰ ثانیه سکوتِ یک طرف قطع شود.
    let _ = client.set_read_timeout(Some(TCP_IDLE_TIMEOUT));
    let _ = client.set_write_timeout(Some(TCP_IDLE_TIMEOUT));
    let _ = upstream.set_read_timeout(Some(TCP_IDLE_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(TCP_IDLE_TIMEOUT));
    let client2 = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let upstream2 = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    // Only the finished Psiphon route is shaped. Direct/split/LAN traffic is not.
    let governor=upstream.peer_addr().ok().filter(|p|p.ip().is_loopback()&&p.port()==crate::engine::exit_socks_port()).and_then(|_|crate::uplink::current());
    let up = std::thread::spawn(move || copy_counted(client, upstream, tx, governor));
    copy_counted(upstream2, client2, rx, None);
    let _ = up.join();
}

/// Relay buffer for one direction of one connection.
///
/// 1.2.3-p3: raised from 16 KB. This is a blocking read/write pair on loopback,
/// so the buffer size sets how many syscalls a download costs: at the rates the
/// tunnel now reaches, 16 KB meant tens of thousands of round trips through the
/// kernel per second on both threads of every connection. 64 KB is a quarter of
/// the syscalls for four pages of stack, and it is heap-allocated once per
/// direction rather than living on the thread stack.
const RELAY_BUF_BYTES: usize = 64 * 1024;

fn copy_counted(mut from: TcpStream, mut to: TcpStream, counter: Arc<AtomicU64>, governor:Option<Arc<crate::uplink_policy::Shaper>>) {
    let mut flow=crate::uplink_policy::Flow::default();
    let _tracked=if let Some(s)=governor.as_ref(){match(s.cancel.track(&from),s.cancel.track(&to)){(Ok(a),Ok(b))=>Some((a,b)),_=>return}}else{None};
    let mut buf = vec![0u8; RELAY_BUF_BYTES];
    'copy: loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let slice=governor.as_ref().filter(|s|s.rate().is_finite()).map(|_|crate::uplink_policy::SLICE).unwrap_or(n);
                for chunk in buf[..n].chunks(slice){
                    if let Some(s)=governor.as_ref(){if !s.acquire(&mut flow,chunk.len(),false){break 'copy;}}
                    if to.write_all(chunk).is_err(){break 'copy;}
                    counter.fetch_add(chunk.len() as u64,Ordering::Relaxed);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Both);
    let _ = from.shutdown(Shutdown::Both);
}
/// معادل `ShareBridge.lanAddress()` — همان ترفند سوکت UDP.
fn detect_lan_ip() -> Option<IpAddr> {
    // UDP-connect trick: no packet is actually sent; the OS only picks the
    // source address it would route through. Probing a public anycast IP
    // first yields the default-route interface address on ANY subnet - the
    // old hard-coded 192.168.1.1 broke on 10.x / 172.16.x / 192.168.0.x
    // networks. Gateway-style fallbacks cover LANs without a default route.
    const PROBES: [(&str, u16); 4] = [
        ("1.1.1.1", 80),
        ("8.8.8.8", 80),
        ("192.168.1.1", 9),
        ("10.0.0.1", 9),
    ];
    for (host, port) in PROBES {
        let sock = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sock.connect((host, port)).is_err() {
            continue;
        }
        if let Ok(addr) = sock.local_addr() {
            let ip = addr.ip();
            if is_lan_address(ip) {
                return Some(ip);
            }
        }
    }
    None
}

/// True only for addresses other LAN devices can actually reach (site-local
/// IPv4) - mirrors the isSiteLocalAddress filter in the mobile ShareBridge.
fn is_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_unspecified() && (v4.is_private() || v4.is_link_local())
        }
        IpAddr::V6(_) => false,
    }
}

/// کارت‌های اشتراک: هر کارت Wi‑Fi/Ethernetِ فیزیکیِ روشن با IPv4 خصوصی.
/// اولی همان کارتی است که مسیر پیش‌فرض از آن می‌گذرد.
fn find_lan_targets() -> Vec<LanTarget> {
    let primary = detect_lan_ip();
    let mut found = match adapter_targets() {
        Some(list) => list,
        // API در دسترس نبود: همان ترفند UDP با زیرشبکهٔ /24.
        None => primary
            .and_then(|ip| match ip {
                IpAddr::V4(v4) => Some(LanTarget {
                    address: v4,
                    prefix: 24,
                    kind: "ethernet",
                    name: "network".to_string(),
                }),
                IpAddr::V6(_) => None,
            })
            .into_iter()
            .collect(),
    };
    if let Some(IpAddr::V4(p)) = primary {
        if let Some(i) = found.iter().position(|t| t.address == p) {
            let t = found.remove(i);
            found.insert(0, t);
        }
    }
    found.dedup_by(|a, b| a.address == b.address);
    found
}

/// کارت‌های مجازی (Hyper-V، VirtualBox، VMware، WireGuard، Wintun، TAP، Wi‑Fi
/// Direct/هات‌اسپات، بلوتوث…) هرگز مقصد اشتراک نیستند.
fn is_virtual_adapter(description: &str) -> bool {
    const MARKERS: [&str; 16] = [
        "hyper-v",
        "vethernet",
        "virtualbox",
        "vmware",
        "wintun",
        "wireguard",
        "tap-",
        "tap adapter",
        "openvpn",
        "bluetooth",
        "wi-fi direct",
        "hosted network",
        "loopback",
        "virtual",
        "npcap",
        "tailscale",
    ];
    let d = description.to_ascii_lowercase();
    MARKERS.iter().any(|m| d.contains(m))
}

#[cfg(windows)]
fn adapter_targets() -> Option<Vec<LanTarget>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
        IP_ADAPTER_ADDRESSES_LH,
    };
    const AF_INET: u32 = 2;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut ok = false;
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_INET,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc == 0 {
            ok = true;
            break;
        }
        if rc != ERROR_BUFFER_OVERFLOW {
            return None;
        }
    }
    if !ok {
        return None;
    }
    let mut out = Vec::new();
    let mut cursor = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cursor.is_null() {
        let adapter = unsafe { &*cursor };
        cursor = adapter.Next;
        let kind = match adapter.IfType {
            IF_TYPE_IEEE80211 => "wifi",
            IF_TYPE_ETHERNET_CSMACD => "ethernet",
            _ => continue,
        };
        if adapter.OperStatus.0 != 1 {
            continue; // IfOperStatusUp
        }
        let description = unsafe { adapter.Description.to_string() }.unwrap_or_default();
        let friendly = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        if is_virtual_adapter(&description) || is_virtual_adapter(&friendly) {
            continue;
        }
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            let entry = unsafe { &*unicast };
            unicast = entry.Next;
            let sockaddr = entry.Address.lpSockaddr as *const u8;
            if sockaddr.is_null() || entry.Address.iSockaddrLength < 8 {
                continue;
            }
            // SOCKADDR_IN: family(2) port(2) addr(4)
            let bytes = unsafe { std::slice::from_raw_parts(sockaddr, 8) };
            if u16::from_ne_bytes([bytes[0], bytes[1]]) != AF_INET as u16 {
                continue;
            }
            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            if !is_lan_address(IpAddr::V4(ip)) {
                continue;
            }
            out.push(LanTarget {
                address: ip,
                prefix: share_guard::sane_prefix(entry.OnLinkPrefixLength),
                kind,
                name: if friendly.is_empty() {
                    kind.to_string()
                } else {
                    friendly.clone()
                },
            });
        }
    }
    Some(out)
}

#[cfg(not(windows))]
fn adapter_targets() -> Option<Vec<LanTarget>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iranian_non_ir_dns_answer_and_guest_policy() {
        let host = RouteRules::parse(std::iter::empty::<&str>(), ["ir", "2.144.0.0/14"]);
        let guest = RouteRules::parse(std::iter::empty::<&str>(), std::iter::empty::<&str>());
        let ip: IpAddr = "2.145.1.1".parse().unwrap();
        assert_eq!(
            route_with_answers("shop.example.com", 443, &host, &[ip]),
            (Action::Direct, Some(SocketAddr::new(ip, 443)))
        );
        assert_eq!(
            route_with_answers("shop.example.com", 443, &guest, &[ip]).0,
            Action::Proxy
        );
        assert_eq!(
            route_with_answers(
                "shop.example.com",
                443,
                &host,
                &["8.8.8.8".parse().unwrap()]
            )
            .0,
            Action::Proxy
        );
        assert_eq!(
            route_with_answers("shop.ir", 443, &host, &[]).0,
            Action::Direct
        );
        let blocked = RouteRules::parse(["8.8.8.8"], ["2.144.0.0/14"]);
        assert_eq!(
            route_with_answers(
                "shop.example.com",
                443,
                &blocked,
                &[ip, "8.8.8.8".parse().unwrap()]
            )
            .0,
            Action::Block
        );
    }

    #[test]
    fn endpoints_are_none_until_started() {
        let b = ShareBridge::new();
        assert!(b.socks_endpoint().is_none());
        assert!(b.http_endpoint().is_none());
        assert!(!b.is_running());
        assert_eq!(b.lan_status(), "off");
        assert!(b.targets().is_empty());
        assert_eq!(b.lan_clients(), 0);
    }

    #[test]
    fn ports_match_the_android_values() {
        assert_eq!(crate::engine::SHARE_SOCKS_PORT, 10810);
        assert_eq!(crate::engine::SHARE_HTTP_PORT, 10811);
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(
            split_target("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            split_target("example.com:8443", 443),
            Some(("example.com".into(), 8443))
        );
        assert_eq!(
            split_target("[2001:db8::1]:443", 80),
            Some(("2001:db8::1".into(), 443))
        );
        assert_eq!(
            split_target("[2001:db8::1]", 80),
            Some(("2001:db8::1".into(), 80))
        );
        assert_eq!(split_target("2001:db8::1", 80), None);
        assert_eq!(split_target("host:0", 80), None);
        assert_eq!(split_target("", 80), None);
    }

    #[test]
    fn loopback_listener_only_admits_loopback() {
        assert!(admit("127.0.0.1".parse().unwrap(), false));
        assert!(admit("::1".parse().unwrap(), false));
        assert!(!admit("192.168.1.20".parse().unwrap(), false));
        assert!(!admit("8.8.8.8".parse().unwrap(), false));
    }

    #[test]
    fn lan_listener_admits_only_the_shared_subnet() {
        let targets = vec![LanTarget {
            address: Ipv4Addr::new(192, 168, 1, 10),
            prefix: 24,
            kind: "wifi",
            name: "Wi-Fi".into(),
        }];
        let ok = |ip: &str| admit_with(ip.parse().unwrap(), true, &targets);
        assert!(ok("192.168.1.20"));
        assert!(ok("::ffff:192.168.1.30"));
        assert!(!ok("192.168.2.20"));
        assert!(!ok("10.0.0.5"));
        assert!(!ok("8.8.8.8"));
        assert!(!admit_with("192.168.1.20".parse().unwrap(), true, &[]));
    }

    #[test]
    fn virtual_adapters_are_skipped() {
        assert!(is_virtual_adapter("Hyper-V Virtual Ethernet Adapter"));
        assert!(is_virtual_adapter(
            "Microsoft Wi-Fi Direct Virtual Adapter #2"
        ));
        assert!(is_virtual_adapter("WireGuard Tunnel"));
        assert!(is_virtual_adapter("vEthernet (WSL)"));
        assert!(!is_virtual_adapter("Intel(R) Wi-Fi 6 AX201 160MHz"));
        assert!(!is_virtual_adapter("Realtek PCIe GbE Family Controller"));
    }

    #[test]
    fn proxy_authorization_is_checked() {
        set_auth(true, "aether", "s3cret-pass");
        let ok = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {}\r\n",
            share_guard::base64_encode(b"aether:s3cret-pass")
        );
        assert!(http_authorized(&ok));
        let bad = format!(
            "GET http://example.com/ HTTP/1.1\r\nproxy-authorization: Basic {}\r\n",
            share_guard::base64_encode(b"aether:wrong")
        );
        assert!(!http_authorized(&bad));
        assert!(!http_authorized("GET http://example.com/ HTTP/1.1\r\n"));
        set_auth(false, "aether", "");
        assert!(!http_authorized(&ok));
    }

    #[test]
    fn restart_reuses_ports_without_10048() {
        let mut b = ShareBridge::new();
        b.start(48810, 48811, false).expect("first start");
        b.start(48810, 48811, false).expect("restart");
        b.stop();
    }
}
