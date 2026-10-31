//! پورت از `core/AetherController.kt` + `vpn/AetherVpnService.kt` + `model/ConnectionState.kt`.
//!
//! ریشهٔ باگ «هیچ پروتکلی کانکت نمی‌شود» در نسخهٔ قبلی دسکتاپ:
//! `connect()` بلافاصله بعد از اجرای موتور، `Tunnel::establish` را صدا می‌زد؛
//! ساخت آداپتور Wintun بدون دسترسی Administrator شکست می‌خورد، خطا از
//! `connect()` بیرون می‌رفت و ماشین حالت برای همیشه روی StartingEngine گیر
//! می‌کرد — در حالی که موتور واقعاً وصل می‌شد (لاگ کاربر: «socks5 server
//! listening on 127.0.0.1:1819» بدون هیچ «I/state: Connecting» بعد از آن).
//!
//! حالا دقیقاً ترتیب اندروید (`connectAttempt`) اجرا می‌شود:
//!   ۱. StartingEngine → آزادشدن پورت → اجرای موتور → Connecting
//!   ۲. انتظار برای بازشدن پورت SOCKS5 (ground truth — همان PortProbe)
//!   ۳. فقط بعد از آن، مسیر داده برپا می‌شود (معادل VpnService.establish):
//!      پل HTTP/SOCKS محلی + پروکسی سیستمی ویندوز؛ Wintun هم اگر ممکن بود
//!      (شکست Wintun دیگر کل اتصال را نمی‌کُشد — فقط یک هشدار لاگ می‌شود).
//!   ۴. Verifying: خودآزمای ۴ مرحله‌ای (Diagnostics.kt) در ترد پس‌زمینه
//!   ۵. فقط بعد از قبولی همهٔ بررسی‌ها، Connected اعلام می‌شود
//!   ۶. شکست هر پله ← پلهٔ بعدی نردبان (معادل runLadder)، نه گیرکردن ابدی.

use crate::diagnostics;
use crate::engine::{self, AetherProcess};
use crate::geoip;
use crate::leakguard::{self, LeakGuard};
use crate::log::DiagnosticsLog;
use crate::ping;
use crate::probe;
use crate::profile::{ConnectionProfile, Protocol};
use crate::share::ShareBridge;
use crate::smart_auto::{self, Candidate};
use crate::store::ProfileStore;
use crate::sysproxy;
use crate::tor_bootstrap;
use crate::tun::Tunnel;
use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TAG: &str = "state";

// >>> AETHER-APP-PATCH custom-configs
// نشستِ کانفیگِ سفارشی (پورتِ `connectCustom` اندروید ۱.۵.۰) — رجوع به
// `state_custom.rs`. زیرماژول است تا به فیلدهای خصوصیِ کنترلر برسد.
#[path = "state_custom.rs"]
mod state_custom;
// <<< AETHER-APP-PATCH custom-configs

/// همان مقادیر اندروید: MAX_RETRIES=3، BACKOFF = 2s/5s/10s.
const DEFAULT_MAX_RETRIES: u32 = 3;
const BACKOFF_MS: [u64; 3] = [2_000, 5_000, 10_000];
/// پنجرهٔ گریس خودآزما — همان `OUTBOUND_GRACE_MS` (شروع سرد warp-in-warp).
const OUTBOUND_GRACE_MS: u64 = 90_000;
/// معادل `PORT_RELEASE_WAIT_MS` اندروید.
const PORT_RELEASE_WAIT_MS: u64 = 3_000;
const WATCHDOG_INTERVAL_SECS: u64 = 30;
/// How often the live latency badge is refreshed.
///
/// It used to be 15s because each measurement dialled a brand new connection
/// through both hops. A measurement is now one keep-alive round trip on a warm
/// session (see [`crate::ping`]), so it costs a single packet each way and the
/// badge can afford to feel live.
const LATENCY_INTERVAL_SECS: u64 = 10;
// >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
/// پنجرهٔ انتخابِ مدار پس از اتصال — رجوع به
/// [`AetherController::consider_new_circuit`].
const CIRCUIT_HUNT_WINDOW: Duration = Duration::from_secs(20);
// <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
/// بودجهٔ کل استیج ۲ (دروازهٔ استیج ۱ + دو پاسِ برقراری Psiphon).
///
/// سخاوتمند است چون پاس دوم عمداً از صفر شروع می‌کند: datastore پاک می‌شود و
/// فیلتر کشور برداشته می‌شود. مهلتِ پلهٔ نردبان در این فاز کنار گذاشته می‌شود،
/// وگرنه یک نشست زنجیره‌ای که فقط کُند است پیش از آنکه شانسی داشته باشد رد
/// می‌شود — همان اشتباهی که مستند موبایل «بدترین نتیجهٔ ممکن» می‌خواندش.
const CHAIN_BUDGET_MS: u64 = 430_000;
// >>> AETHER-APP-PATCH tor-aether-fast-path
/// چند بار موتورِ مرده پشتِ همان tor.exeِ آماده دوباره اجرا شود، به‌جای کشتنِ
/// تور و شکستِ کلِ اتصال (لاگ: ثبت‌نامِ اول ۵ بار در ۱۰ ثانیه قطع شد و
/// bootstrapِ کاملِ تور دور ریخته شد).
const TOR_REVERSE_RESPAWNS: u8 = 2;
// <<< AETHER-APP-PATCH tor-aether-fast-path
// >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
/// Mobile `PsiphonTransport`: READY_TIMEOUT_MS / PROBE_INTERVAL_MS /
/// PROBE_TIMEOUT_MS — the same three numbers.
const PSIPHON_READY_TIMEOUT: Duration = Duration::from_millis(200_000);
const PSIPHON_PROBE_INTERVAL: Duration = Duration::from_millis(4_000);
const PSIPHON_PROBE_TIMEOUT: Duration = Duration::from_millis(5_000);
// <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
const WATCHDOG_FAILURE_THRESHOLD: u8 = 3;

/// معادل دقیق `ConnectionState.kt` — همان هشت حالت، همان ترتیب.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionState {
    Disconnected,
    StartingEngine,
    Connecting,
    Verifying,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

impl ConnectionState {
    pub fn is_busy(self) -> bool {
        matches!(
            self,
            Self::StartingEngine
                | Self::Connecting
                | Self::Verifying
                | Self::Reconnecting
                | Self::Disconnecting
        )
    }
    pub fn is_active(self) -> bool {
        self.is_busy() || self == Self::Connected
    }
}

/// معادل `IpInfo` در UI اندروید — خوراک نشان «IP + پرچم».
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEndpoint {
    pub ip: String,
    pub country_code: Option<String>,
    /// true = IP خروجی سرور (از دل تونل)، false = IP واقعی کاربر.
    pub via_tunnel: bool,
    #[serde(default)]
    pub alternate_ip: Option<String>,
}

/// حالت مشترک جست‌وجوی IP — معادل `ipInfo`/`ipLoading` در MainActivity.
struct IpSlot {
    info: Option<IpEndpoint>,
    loading: bool,
    /// شمارندهٔ نسل — نتیجهٔ جست‌وجوهای قدیمی دور ریخته می‌شود.
    session: u64,
}

/// معادل مجموع StateFlow‌هایی که HomeScreen.kt جمع می‌کرد.
/// `PartialEq` is load-bearing, not decoration: `main.rs` only pushes a snapshot
/// to the UI when it differs from the last one it sent. An idle app used to
/// re-serialise and repaint the entire home screen five times a second forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub state: ConnectionState,
    pub detail: String,
    pub error: Option<String>,
    pub endpoint: Option<String>,
    pub protocol: Option<String>,
    pub latency_ms: Option<u64>,
    pub uptime_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub share_socks: Option<String>,
    pub share_http: Option<String>,
    /// ۱.۵.۰ — وضعیت اشتراک LAN: `off` / `waiting` / `ready` / `portBusy`.
    pub share_status: String,
    /// ۱.۵.۰ — همهٔ آدرس‌های اشتراک (Wi‑Fi/Ethernet)؛ اولی آدرس اصلی.
    pub share_targets: Vec<crate::share::ShareTarget>,
    /// ۱.۵.۰ — اتصال‌های زندهٔ دستگاه‌های شبکه.
    pub share_clients: usize,
    /// ۱.۵.۰ — هسته منتظرِ کدِ ورودِ Zero Trust است (دیالوگ روی هر صفحه‌ای).
    pub login_code: Option<crate::login_code::Request>,
    pub ip_info: Option<IpEndpoint>,
    pub ip_loading: bool,
    /// v1.2.0 — نتیجهٔ آخرین سنجش نشتی WebRTC. `None` = هنوز سنجیده نشده.
    pub webrtc_leak: Option<bool>,
    /// v1.2.0 — گارد نشتی همین حالا فعال است؟
    pub leak_guard: bool,
    /// ۱.۲.۵ — درصدِ bootstrapِ تور، یا `None` وقتی تور در کار نیست/چیزی
    /// نگفته است.
    ///
    /// عدد جداگانه فرستاده می‌شود و نه فقط داخلِ `detail`، چون جملهٔ نهایی را
    /// باید لایهٔ رابط بسازد: `detail` انگلیسی است و ترجمه‌نشده به کاربر
    /// نشان داده می‌شود، پس کاربر فارسی پنج دقیقه به یک جملهٔ انگلیسی نگاه
    /// می‌کرد — همان‌جایی که برنامه بیشترین وقت را از او می‌گیرد.
    pub tor_percent: Option<u8>,
    // >>> AETHER-APP-PATCH custom-configs
    /// زنجیرهٔ کانفیگِ سفارشی به شکل‌های کوتاه‌شونده (اولی = `protocol`)؛
    /// کارتِ اتصال اولین شکلی را نشان می‌دهد که در یک خط جا شود. خالی وقتی
    /// کانفیگِ سفارشی در کار نیست.
    pub protocol_compact: Vec<String>,
    // <<< AETHER-APP-PATCH custom-configs
}

/// What the user asked for with the last tap on the big button.
///
/// # Why the tap no longer does the work itself
///
/// `toggle_connection` used to run the whole of `connect()` / `disconnect()`
/// while holding the controller mutex. Both are full of slow Windows calls —
/// a network fingerprint (up to 2.4s), waiting for the SOCKS port to be released
/// (up to 3s), `netsh` firewall rules, registry proxy writes, process teardown.
/// The 200ms snapshot tick wants the same mutex, so for several seconds after a
/// tap nothing repainted: the button did not change, the spinner did not start,
/// and the app read as frozen exactly when the user was watching hardest.
///
/// Now a tap records an intent, flips the visible state, and returns instantly.
/// The tick thread performs the work on the next beat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intent {
    Connect,
    Disconnect,
}

/// Which stage the off-lock preparation thread is preparing for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prep {
    /// A fresh session: fingerprint the network, then build the whole ladder.
    Plan,
    /// The next rung of an existing ladder: no fingerprinting needed.
    Candidate,
}

/// Result of the off-lock preparation thread.
struct PrepOutcome {
    /// What the pre-connect probes learned. Only meaningful for [`Prep::Plan`].
    fingerprint: smart_auto::NetFingerprint,
    /// Set when a local port the pipeline needs is held by another program.
    /// The attempt is abandoned with this exact reason instead of launching
    /// engines that can only die with `os error 10048`.
    blocked: Option<String>,
}

pub struct AetherController {
    data_dir: PathBuf,
    store: ProfileStore,
    profile: ConnectionProfile,
    state: ConnectionState,
    detail: String,
    error: Option<String>,
    endpoint: Option<String>,
    effective_protocol: Option<Protocol>,
    latency_ms: Option<u64>,
    connected_at: Option<Instant>,
    engine: AetherProcess,
    // >>> AETHER-APP-PATCH tor-native-carrier
    /// تورِ رسمی، وقتی این تلاش «تور تنها» است. `None` یعنی این تلاش از موتور
    /// می‌گذرد.
    native_tor: Option<crate::tor_native::TorNative>,
    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// کدام نیمهٔ یک نشستِ توری هنوز اجرا نشده است.
    tor_stage: TorStage,
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    // >>> AETHER-APP-PATCH tor-reverse-latch (mobile 1.4.0 `connect`: REVERSE takes the plain path)
    /// در `Tor → Aether`: tor.exe جلوی موتور آماده شده و موتور پشتش اجرا شده.
    ///
    /// از این لحظه دروازهٔ تور دیگر به درصدِ سراسریِ `tor_bootstrap` نگاه
    /// نمی‌کند. آن وضعیت سراسری است و دو منبعِ نوشتن دارد (سینکِ tor.exe و
    /// تردِ خروجیِ موتور) و هر `reset()`ای که بعد از `mark_done` برسد، دروازه را
    /// دوباره روی «Reaching the Tor network…» می‌برد — دقیقاً لاگِ `loge3`:
    /// `socks5 server listening on 127.0.0.1:1819`، `masque exit: …`، و بعد
    /// «Tor is not getting through directly — trying bridges…» تا قطعِ دستی.
    ///
    /// موبایل ۱.۴.۰ همین حالت را از مسیرِ معمولی می‌برد: پورتِ باز + خودآزمای
    /// واقعیِ مسیرِ داده، بی هیچ دروازهٔ درصدی. موتور هم SOCKS5 را فقط پس از
    /// `tunnel validated (end-to-end data confirmed)` باز می‌کند، پس پورتِ باز
    /// در این مرحله خودش اثباتِ عبور از تور است.
    tor_front_ready: bool,
    // <<< AETHER-APP-PATCH tor-reverse-latch
    // >>> AETHER-APP-PATCH tor-aether-fast-path
    /// رلهٔ صبورِ SOCKS بینِ موتور و tor.exe در `Tor → Aether` — رجوع به
    /// [`crate::tor_relay`].
    tor_relay: Option<crate::tor_relay::TorDialRelay>,
    /// چند بار موتور در این نشست پشتِ همان تور دوباره اجرا شده.
    tor_reverse_respawns: u8,
    // <<< AETHER-APP-PATCH tor-aether-fast-path
    // <<< AETHER-APP-PATCH tor-native-carrier
    /// The engine owns Psiphon; desktop only waits for its exit listener.
    chain_waiting: bool,
    // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
    /// `Tor → Psiphon`: when Psiphon was started behind the ready tor.exe —
    /// the start of the mobile `PsiphonTransport` readiness window.
    psiphon_gate_since: Option<Instant>,
    /// When the next real CONNECT probe through Psiphon may be sent.
    psiphon_next_probe: Option<Instant>,
    /// پورتِ سایفون یک بار باز دیده شد (`psiphon-port-latch`).
    psiphon_port_latched: bool,
    /// Result of the CONNECT probe in flight (`None` while it runs).
    psiphon_probe: Option<Arc<Mutex<Option<bool>>>>,
    // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
    tunnel: Option<Tunnel>,
    share: ShareBridge,
    uplink: Option<crate::uplink::Runtime>,
    sysproxy_on: bool,
    /// v1.2.0 — گارد نشتی WebRTC/UDP این نشست (Drop خودش آزادش می‌کند).
    guard: Option<LeakGuard>,
    /// v1.2.0 — آخرین نتیجهٔ سنجش نشتی، برای نشانِ صفحهٔ اصلی.
    webrtc_leak: Option<bool>,
    /// نردبان تلاش‌ها — معادل `runLadder` در AetherVpnService.kt.
    plan: Vec<Candidate>,
    plan_index: usize,
    /// تلاش‌های اتصال مجدد پشت‌سرهم — معادل `reconnectAttempts`.
    attempts: u32,
    deadline: Option<Instant>,
    reconnect_at: Option<Instant>,
    /// نتیجهٔ خودآزمای در حال اجرا (ترد پس‌زمینه — UI فریز نمی‌شود).
    verify_slot: Option<Arc<Mutex<Option<diagnostics::SelfTestOutcome>>>>,
    ip_slot: Arc<Mutex<IpSlot>>,
    /// پینگ زنده: نتیجهٔ آخرین اندازه‌گیری دوره‌ای در ترد پس‌زمینه.
    latency_slot: Arc<Mutex<Option<u64>>>,
    /// زمان اندازه‌گیری بعدی پینگ.
    latency_probe_at: Option<Instant>,
    // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
    /// تا کی اجازه داریم مدارِ تور را عوض کنیم؛ `None` یعنی نه.
    circuit_hunt_until: Option<Instant>,
    /// چند مدار در این نشست عوض شده.
    circuit_tries: u8,
    // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
    /// نتیجهٔ آخرین پروب واچداگ، خارج از حلقهٔ اصلی محاسبه می‌شود.
    watchdog_slot: Arc<Mutex<Option<bool>>>,
    watchdog_probe_at: Option<Instant>,
    watchdog_failures: u8,
    /// Firewall/registry work is deferred out of the IPC command path.
    security_refresh_pending: bool,
    /// The last tap, waiting for the next tick. See [`Intent`].
    pending_intent: Option<Intent>,
    /// Slow pre-launch work running off the controller lock. See [`Prep`].
    prep_slot: Option<Arc<Mutex<Option<PrepOutcome>>>>,
    prep_kind: Prep,
    /// Stage 2's listener once the chain is actually carrying traffic.
    ///
    /// This is what makes the PROTOCOL tile honest: it says `Aether → Psiphon`
    /// only once the Psiphon hop really is the exit, not merely because the
    /// chained backend is selected in Advanced.
    chain_exit_port: Option<u16>,
    // >>> AETHER-APP-PATCH custom-configs
    /// نشستِ کانفیگِ سفارشیِ فعلی؛ `None` = کلید خاموش، همه‌چیز مثل قبل.
    custom: Option<state_custom::CustomRun>,
    smart_plus: Option<crate::smart_plus::Session>,
    smart_plus_done: bool,
    fresh_selection: Option<crate::custom::realdelay::ProbeTask>,
    fresh_basis: Option<crate::custom::store::State>,
    // <<< AETHER-APP-PATCH custom-configs
}

/// جوابِ دروازهٔ تور — [`AetherController::tor_gate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TorGate {
    /// تور به شبکه رسیده (یا این نشست تور ندارد): مسیر داده می‌تواند بالا بیاید.
    Ready,
    /// هنوز در حال bootstrap و **در حرکت**. صبر کردن درست‌ترین کار است.
    Waiting,
    /// درصد از حرکت ایستاده. این شکلِ واقعیِ شبکه‌ای است که تور را فیلتر
    /// می‌کند، و تنها حالتی که تلاش را زودتر از بودجه می‌کشد.
    Stalled,
}

// >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
/// نیمهٔ اجرانشدهٔ یک نشستِ توریِ زنجیره‌ای.
///
/// # چرا اصلاً دو نیمه
///
/// تا امروز در `Tor → Aether` و `Aether → Tor` هر دو نیمه یک فرآیند بودند:
/// موتور با `--tor-reverse`/`--tor` تورِ داخلیِ خودش (arti) را بالا می‌آورد.
/// لاگِ ۱۷ سپتامبر روی همان شبکه هر دو مسیر را کنارِ هم نشان می‌دهد:
///
/// ```text
/// 13:45:58  [tor] Bootstrapped 100% (done)              ← tor.exe، ۲۲ ثانیه
/// 10:17:27  [engine] tor could not get through … 75s    ← arti، همان دقیقه
/// 10:23:02  [engine] Stuck at 15%: Can't bootstrap a Tor directory
/// 10:26:12  Engine still scanning — the SOCKS5 port never opened in time
/// ```
///
/// یعنی حاملِ تور همیشه باید `tor.exe` باشد و نیمهٔ دیگر مشتریِ آن. آن‌وقت
/// ترتیب اهمیت پیدا می‌کند و همین enum است که می‌گوید نوبتِ کیست.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TorStage {
    /// هیچ نیمه‌ای معلق نیست — نشستِ عادی، «تور تنها»، یا هر دو نیمه بالا.
    None,
    /// `Tor → Aether`: تور بالا است و موتور پس از آمادگیِ آن اجرا می‌شود.
    TorThenEngine,
    /// tor.exe reaches a circuit before core-managed Psiphon dials through it.
    TorThenPsiphon,
    /// `Aether → Tor`: موتور بالا است و تور از دلِ تونلش اجرا می‌شود.
    EngineThenTor,
}
// <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor

impl AetherController {
    pub fn new(data_dir: &Path) -> Self {
        let store = ProfileStore::new(data_dir);
        let mut profile = store.load();
        profile.normalize();
        let install_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| data_dir.to_path_buf());

        crate::procguard::set_own_roots(&[install_dir.clone(), data_dir.to_path_buf()]);

        // ۱.۵.۰ — رمز اشتراک LAN از انبار مهرشده، پیش از اولین شنونده.
        crate::share::load_credentials(data_dir);

        let ip_slot = Arc::new(Mutex::new(IpSlot {
            info: None,
            loading: false,
            session: 0,
        }));

        let me = Self {
            data_dir: data_dir.to_path_buf(),
            store,
            profile,
            state: ConnectionState::Disconnected,
            detail: String::new(),
            error: None,
            endpoint: None,
            effective_protocol: None,
            latency_ms: None,
            connected_at: None,
            engine: AetherProcess::new(&install_dir, data_dir),
            // >>> AETHER-APP-PATCH tor-native-carrier
            native_tor: None,
            tor_stage: TorStage::None,
            tor_front_ready: false,
            tor_relay: None,
            tor_reverse_respawns: 0,
            // <<< AETHER-APP-PATCH tor-native-carrier
            chain_waiting: false,
            psiphon_gate_since: None,
            psiphon_next_probe: None,
            psiphon_port_latched: false,
            psiphon_probe: None,
            tunnel: None,
            share: ShareBridge::new(),
            uplink:None,
            sysproxy_on: false,
            guard: None,
            webrtc_leak: None,
            plan: Vec::new(),
            plan_index: 0,
            attempts: 0,
            deadline: None,
            reconnect_at: None,
            verify_slot: None,
            ip_slot,
            latency_slot: Arc::new(Mutex::new(None)),
            latency_probe_at: None,
            circuit_hunt_until: None,
            circuit_tries: 0,
            watchdog_slot: Arc::new(Mutex::new(None)),
            watchdog_probe_at: None,
            watchdog_failures: 0,
            security_refresh_pending: false,
            pending_intent: None,
            prep_slot: None,
            prep_kind: Prep::Plan,
            chain_exit_port: None,
            custom: None,
            smart_plus:None,
            smart_plus_done:false,
            fresh_selection:None,
            fresh_basis:None,
        };

        // >>> AETHER-APP-PATCH the-flag-is-already-on-disk
        // پرچمِ خروجی از فایلِ کشورِ خودِ Tor خوانده می‌شود، نه از شبکه. اینجا
        // گفته می‌شود آن فایل کجاست — یک بار، پیش از هر جست‌وجوی IP.
        if let Some((_, support)) = me.engine.native_tor() {
            geoip::use_dir(&support);
        }
        // <<< AETHER-APP-PATCH the-flag-is-already-on-disk

        // Stale state from a previous crash is cleared on a worker thread.
        //
        // Both calls shell out: `recover_stale` writes the WinINET registry keys
        // and broadcasts a settings change, `purge_stale` runs several
        // `netsh advfirewall` deletions. Together they cost the better part of a
        // second, and they used to run inside the Tauri `setup` hook — which is
        // to say, before the window was allowed to appear. Nothing about them
        // needs to finish before the UI is on screen; they only have to happen
        // before a connection is brought up, and a connection needs a tap.
        std::thread::Builder::new()
            .name("aether-recover".into())
            .spawn(|| {
                sysproxy::recover_stale();
                leakguard::purge_stale();
                // Orphans of an earlier session (crash, End task, an upgrade
                // installed over a running copy) still sit on Aether's fixed
                // ports and would make every protocol fail with 10048.
                crate::procguard::sweep_orphans(&engine::FIXED_PORTS);
            })
            .ok();
        // Do not install network-blocking rules during ordinary app startup.
        // The old behavior blocked Windows before a tunnel/bridge existed,
        // which is why reopening the app could kill internet access. The
        // guard is installed only after the SOCKS bridge is ready.
        // معادل LaunchedEffect فاز idle در MainActivity: نمایش IP واقعی کاربر از لحظهٔ اجرا.
        spawn_ip_lookup(me.ip_slot.clone(), false);
        me
    }

    pub fn profile(&self) -> ConnectionProfile {
        // AETHER-APP-PATCH custom-configs: نسخهٔ کاربر، بی جایگزینیِ نشست.
        self.custom_user_profile()
    }

    pub fn set_profile(&mut self, profile: ConnectionProfile) -> Result<()> {
        let mut profile = profile;
        profile.normalize();
        // v10: فیلدهای محرمانه «write-only» هستند: get_profile هرگز آن‌ها را
        // برنمی‌گرداند، پس UI معمولاً رشتهٔ خالی می‌فرستد. خالی = «دست نزن»
        // تا رازِ در-حافظهٔ این نشست با هر تغییر تنظیم دیگر پاک نشود.
        if profile.access_secret.is_empty() {
            profile.access_secret = self.profile.access_secret.clone();
        }
        if profile.access_token.is_empty() {
            profile.access_token = self.profile.access_token.clone();
        }
        self.apply_profile(profile)
    }

    /// v10: «بازنشانی به تنظیمات پیش‌فرض» باید اسرارِ در-حافظه را هم واقعاً
    /// پاک کند. `set_profile` رشتهٔ خالی را «دست نزن» تفسیر می‌کند (چون UI
    /// اسرار را پس نمی‌گیرد)، پس Reset مسیر جداگانهٔ خودش را دارد؛ وگرنه
    /// توکن سازمانی پس از Reset بی‌صدا در حافظه زنده می‌ماند.
    pub fn reset_profile(&mut self) -> Result<ConnectionProfile> {
        crate::smart_plus::memory::clear(&self.data_dir);
        let fresh = ConnectionProfile::default();
        self.apply_profile(fresh.clone())?;
        DiagnosticsLog::i(
            TAG,
            "Profile reset to factory defaults (in-memory Zero Trust secrets cleared).",
        );
        Ok(fresh)
    }

    /// مسیر مشترک ذخیره‌سازی — هرچه از set_profile/reset_profile بیاید.
    fn apply_profile(&mut self, profile: ConnectionProfile) -> Result<()> {
        self.store.save(&profile)?;
        let lan_toggled = profile.lan_share != self.profile.lan_share;
        let guard_toggled = profile.leak_guard != self.profile.leak_guard;
        let kill_toggled = profile.kill_switch != self.profile.kill_switch;
        let ipv6_toggled = profile.ipv6_protection != self.profile.ipv6_protection;
        self.profile = profile;
        // AETHER-APP-PATCH custom-configs: زنجیرهٔ سفارشیِ نشستِ جاری می‌ماند.
        self.custom_reapply();
        // v1.2.0: خاموش/روشن‌کردن گارد نشتی وسط یک اتصالِ فعال باید فوراً
        // اثر کند — نه در اتصال بعدی. کاربری که سوییچ را می‌زند انتظار دارد
        // همان لحظه محافظت شود (یا آزاد شود).
        let safety_changed = guard_toggled || kill_toggled || ipv6_toggled;
        if safety_changed && self.state.is_active() {
            // Do not run reg.exe/netsh.exe while the UI IPC command is waiting.
            // The 200ms controller tick applies it outside the settings click,
            // preventing the white titlebar/freeze seen on safety toggles.
            self.security_refresh_pending = true;
            self.webrtc_leak = None;
        }
        // Root fix for "Share over LAN shows no IP:port": flipping the switch
        // while a connection is active must rebind the bridge immediately
        // (mobile restarts its ShareBridge the same way), so the UI gets the
        // fresh endpoints in the very next snapshot instead of never.
        // ۱.۵.۰: فقط شنونده‌های LAN باز/بسته می‌شوند؛ شنوندهٔ loopback (پروکسی
        // سیستمیِ همین رایانه) بی‌وقفه می‌ماند.
        if lan_toggled && self.state.is_active() {
            if self.share.is_running() {
                self.share.set_lan(self.profile.lan_share);
            } else if let Err(e) = self.share.start(
                engine::SHARE_SOCKS_PORT,
                engine::SHARE_HTTP_PORT,
                self.profile.lan_share,
            ) {
                DiagnosticsLog::e(TAG, &format!("Bridge restart after LAN toggle failed: {e}"));
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        let (tun_rx, tun_tx) = self.tunnel.as_ref().map(Tunnel::counters).unwrap_or((0, 0));
        let (br_rx, br_tx) = self.share.traffic();
        let (ip_info, ip_loading) = {
            let g = self.ip_slot.lock();
            (g.info.clone(), g.loading)
        };
        crate::share::note_exit_ip(
            ip_info
                .as_ref()
                .filter(|i| i.via_tunnel)
                .map(|i| i.ip.as_str()),
        );
        Snapshot {
            state: self.state,
            detail: self.detail.clone(),
            error: self.error.clone(),
            endpoint: self.endpoint.clone(),
            protocol: self.display_protocol(),
            latency_ms: self.latency_ms,
            uptime_secs: self
                .connected_at
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
            rx_bytes: tun_rx + br_rx,
            tx_bytes: tun_tx + br_tx,
            share_socks: self.share.socks_endpoint(),
            share_http: self.share.http_endpoint(),
            share_status: self.share.lan_status().to_string(),
            share_targets: self.share.targets(),
            share_clients: self.share.lan_clients(),
            login_code: crate::login_code::pending(),
            ip_info,
            ip_loading,
            webrtc_leak: self.webrtc_leak,
            leak_guard: leakguard::status().engaged,
            tor_percent: if self.tor_fronted() {
                tor_bootstrap::snapshot().percent
            } else {
                None
            },
            protocol_compact: self.custom_compact(),
        }
    }

    /// The label the PROTOCOL tile shows.
    ///
    /// ۱.۲.۵ — هر خط‌لوله‌ای که نامی دارد همان نام را نشان می‌دهد: در تصویرِ
    /// کاربر از «تور تنها» این خانه `SMART` می‌گفت؛ `SMART` روشِ پیداکردنِ
    /// تونل است و در این حالت هیچ تونلی وجود ندارد که با آن پیدا شود.
    ///
    /// شرطِ زنجیره سرجایش می‌ماند: در حالت‌های زنجیره‌ای نامِ خط‌لوله فقط
    /// وقتی گفته می‌شود که استیج ۲ واقعاً خروجی را در دست گرفته باشد؛
    /// نوشتنِ `Aether → Psiphon` پیش از آن، ادعای دروغ است.
    /// Resolves the protocol shown on the connection card. `Protocol::Smart` is a
    /// planning marker, not a transport: while the Smart ladder/race is still in
    /// flight (or after a reconnect restored the marker) fall back to the
    /// candidate that is currently running, then to the first rung the planner
    /// picks for this profile. The card therefore always shows a real transport.
    pub(super) fn resolved_effective_protocol(&self) -> Option<crate::profile::Protocol> {
        let eff = self.effective_protocol;
        if let Some(p) = eff {
            if p != crate::profile::Protocol::Smart {
                return Some(p);
            }
        }
        if let Some(cand) = self.plan.get(self.plan_index) {
            if cand.profile.protocol != crate::profile::Protocol::Smart {
                return Some(cand.profile.protocol);
            }
        }
        if self.profile.protocol != crate::profile::Protocol::Smart {
            return Some(self.profile.protocol);
        }
        let picked = crate::smart_auto::pick(&self.profile);
        if picked != crate::profile::Protocol::Smart {
            return Some(picked);
        }
        eff
    }

    fn display_protocol(&self) -> Option<String> {
        // AETHER-APP-PATCH custom-configs: زنجیرهٔ سفارشی نامِ خودش را دارد.
        if let Some(label) = self.custom_display() {
            return Some(label);
        }
        // `Tor` و `Tor → Psiphon` هیچ تونلِ WARPی ندارند، پس «پروتکل»شان
        // همان نامِ خط‌لوله است — مثل بقیهٔ کانکشن‌ها. پیش از این، `Tor → Psiphon`
        // چون زنجیره‌ای است منتظرِ `chain_exit_port` (پورتِ ۱۸۲۵ِ حالتِ
        // `Aether → Psiphon`) می‌ماند که در این خط‌لوله هرگز تنظیم نمی‌شود
        // (خروجی‌اش ۱۸۱۹ است)، و کارت به `effective_protocol` یعنی `SMART`
        // برمی‌گشت.
        let pipeline_name = self.profile.backend.protocol_label();
        if matches!(
            self.profile.backend,
            crate::profile::TransportBackend::Tor | crate::profile::TransportBackend::TorPsiphon
        ) {
            return pipeline_name.map(str::to_string);
        }
        // AETHER-APP-PATCH 1.4.0 smart-label: the card names the transport that
        // actually won the Smart ladder/race (WireGuard, MASQUE, …) — never the
        // generic `SMART` marker.
        let protocol = self
            .resolved_effective_protocol()
            .map(|p| format!("{p:?}").to_uppercase());
        let show_chain = !self.profile.is_chained() || self.chain_exit_port.is_some();
        if show_chain {
            let label = match self.profile.backend {
                crate::profile::TransportBackend::Aether => {
                    protocol.as_ref().map(|p| format!("Aether ({p})"))
                }
                crate::profile::TransportBackend::AetherPsiphon => protocol
                    .as_ref()
                    .map(|p| format!("Aether ({p}) \u{2192} Psiphon")),
                crate::profile::TransportBackend::AetherTor => protocol
                    .as_ref()
                    .map(|p| format!("Aether ({p}) \u{2192} Tor")),
                crate::profile::TransportBackend::TorAether => protocol
                    .as_ref()
                    .map(|p| format!("Tor \u{2192} Aether ({p})")),
                crate::profile::TransportBackend::Tor => Some("Tor".to_string()),
                crate::profile::TransportBackend::TorPsiphon => {
                    Some("Tor \u{2192} Psiphon".to_string())
                }
            };
            if label.is_some() {
                return label;
            }
        }
        protocol
    }

    /// معادل `onToggleConnection` — خطای اتصال دیگر به بیرون پرتاب نمی‌شود؛
    /// همیشه به حالت Failed ترجمه می‌شود تا UI هرگز در StartingEngine گیر نکند.
    ///
    /// Records the intent and repaints; the work happens on the next tick. See
    /// [`Intent`] for why this must not block.
    pub fn request_toggle(&mut self) {
        if self.state.is_active() {
            self.pending_intent = Some(Intent::Disconnect);
            self.set_state(ConnectionState::Disconnecting, "Disconnecting…");
        } else {
            self.error = None;
            self.pending_intent = Some(Intent::Connect);
            self.set_state(ConnectionState::StartingEngine, "Starting engine…");
        }
    }

    /// معادل `connect()` سرویس اندروید — فقط برنامه‌ریزی و اجرای پلهٔ اول؛
    /// بقیهٔ مراحل در tick() دنبال می‌شوند.
    fn connect(&mut self)->Result<()> {
        self.fresh_selection=None;self.fresh_basis=None;
        let snapshot=crate::custom::store::snapshot();
        if self.profile.custom_auto_select && snapshot.enabled {
            let install=std::env::current_exe().ok().and_then(|p|p.parent().map(Path::to_path_buf)).unwrap_or_else(||self.data_dir.clone());
            if let Some(binary)=crate::custom::process::locate(&install,&self.data_dir){
                let targets=crate::custom::selection::group_configs(&snapshot).into_iter().map(|c|crate::custom::realdelay::Target{id:c.id,name:c.name,outbound:c.outbound}).collect::<Vec<_>>();
                if !targets.is_empty(){self.fresh_basis=Some(snapshot);self.fresh_selection=Some(crate::custom::realdelay::ProbeTask::spawn(binary,self.data_dir.clone(),targets));self.set_state(ConnectionState::StartingEngine,"Testing configs in the active group…");return Ok(());}
            }
        }self.connect_after_selection()
    }
    fn connect_after_selection(&mut self) -> Result<()> {
        self.smart_plus=None;self.smart_plus_done=false;
        self.error = None;
        self.attempts = 0;
        self.chain_waiting = false;
        self.chain_exit_port = None;
        // هر نشست از موتور شروع می‌شود. اگر این جا بیفتد، یک نشست عادی به پورت
        // استیج ۲ که دیگر وجود ندارد وصل می‌ماند: «متصل ولی هیچ سایتی باز
        // نمی‌شود».
        engine::reset_exit_socks_port();
        // معادل DiagnosticsLog.clear + resetChecks در شروع اتصال اندروید.
        diagnostics::reset_checks();
        // The warm latency session belongs to the pipeline that is going away.
        ping::reset();
        // >>> AETHER-APP-PATCH custom-configs
        // خاموش (پیش‌فرض) = هیچ کاری. روشن = پروفایلِ در-حافظهٔ این نشست
        // زنجیرهٔ انتخاب‌شده را می‌گیرد؛ نسخهٔ کاربر دست نمی‌خورد.
        self.custom_begin()?;
        // <<< AETHER-APP-PATCH custom-configs
        // The visible state is already StartingEngine — request_toggle set it the
        // moment the user tapped, so the button never waits on this method.
        // ۱.۲.۵ — پیش از هر چیزِ دیگر: این بیلد کدام است؟ اگر موتورِ کهنه
        // اجرا شود، هر نتیجه‌گیری از این نشست دربارهٔ مسیرِ داده غلط است.
        crate::provenance::log_app_identity(&self.engine.core_version());
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Connect requested — protocol={:?} scan={:?} ip={:?}",
                self.profile.protocol, self.profile.scan_mode, self.profile.ip_version
            ),
        );
        // SmartAuto.kt parity: fingerprint the network before planning. On a
        // filtered network the ladder leads with the hardened anti-DPI
        // candidate, so the plain first pass can no longer waste 35-75s
        // (slow connects) or win with a tunnel that cannot carry real
        // browser traffic afterwards.
        if self.profile.backend == crate::profile::TransportBackend::TorPsiphon
            && !self.engine.caps().tor
            && !self.custom_psiphon_base()
        {
            return Err(anyhow::anyhow!(
                "Tor → Psiphon requires a Tor-capable engine; refusing to connect without Tor."
            ));
        }
        // Every Tor pipeline runs the bundled official tor.exe; the unmodified core
        // is never asked to bootstrap its own (arti) Tor. Without tor.exe the
        // pipeline would silently become a different one, so refuse clearly.
        if self.profile.backend.uses_tor()
            && !self.custom_psiphon_base()
            && self.engine.native_tor().is_none()
        {
            return Err(anyhow::anyhow!(
                "{} needs the bundled tor.exe (engine\\tor\\tor.exe), which this installation is missing. Reinstall Aether.",
                self.profile.backend.protocol_label().unwrap_or("Tor")
            ));
        }
        if self.profile.is_chained() {
            self.engine.psiphon_assets()?;
        }
        // AETHER-APP-FIX custom-pipeline-label: نشستِ سفارشی backend را فقط
        // برای آرگومان‌های موتور جایگزین می‌کند (پایهٔ Psiphon → TorPsiphon)؛
        // برچسبِ آن backend («Tor → Psiphon») زنجیرهٔ واقعی نبود.
        match self.custom_chain_label() {
            Some(chain) => DiagnosticsLog::i(
                TAG,
                &format!("Pipeline: {chain} (custom config chain)"),
            ),
            None => DiagnosticsLog::i(
                TAG,
                &format!("Pipeline: {}", self.profile.backend.pipeline_label()),
            ),
        }
        // >>> AETHER-APP-FIX pt-egress-not-blocked
        // A Tor pipeline reaches the network through `lyrebird.exe`, a separate
        // process. Leak-guard rules left behind by a session that was killed
        // rather than closed are still in the firewall at this point, and they
        // make that process fail with WSAEACCES instead of connecting — which
        // is what the 2026-09-16 log shows as `broker failure dial tcp …
        // forbidden by its access permissions`, with Tor frozen at 0-15%.
        // Nothing owns those rules here (`self.guard` is None until the data
        // path comes up), so anything still installed is a leftover.
        if self.profile.backend.uses_tor() && self.guard.is_none() {
            leakguard::purge_stale();
        }
        // <<< AETHER-APP-FIX pt-egress-not-blocked
        // Fingerprinting and waiting for the port to be released are the two slow
        // steps, and neither may run on the controller lock. They go to a worker
        // thread and the ladder is built when the tick sees the result.
        self.begin_prep(Prep::Plan);
        Ok(())
    }

    /// Runs the slow pre-launch steps off the controller lock.
    ///
    /// Both used to sit directly in the connect path: `network_looks_filtered`
    /// dials two IP literals with a 1.2s timeout each, and `wait_for_port_release`
    /// polls for up to 3s. Nearly six seconds of a held mutex, on every rung of
    /// the ladder — that is the stall the user felt when tapping Connect.
    fn begin_prep(&mut self, kind: Prep) {
        let slot: Arc<Mutex<Option<PrepOutcome>>> = Arc::new(Mutex::new(None));
        self.prep_slot = Some(slot.clone());
        self.prep_kind = kind;
        // «تور تنها» از اثرانگشت هیچ تصمیمی نمی‌سازد — خودِ برنامه‌ریز
        // می‌گوید «no tunnel to scan» — ولی تا امروز ~۲.۴ ثانیه صرفش می‌شد،
        // پیش از هر تلاش. انتظارِ آزادشدنِ پورت می‌ماند، چون tor.exe همان
        // ۱۸۱۹ را می‌خواهد.
        // >>> AETHER-APP-PATCH tor-aether-fast-path
        // `Tor → Aether` هم از اثرانگشت چیزی نمی‌گیرد: برنامه‌ریز در این حالت
        // همیشه «MASQUE روی HTTP/2 از داخلِ تور» می‌سازد (UDP از تور رد
        // نمی‌شود)، ولی اثرانگشت در لاگ ~۴.۶ ثانیه پیش از شروعِ تور می‌گرفت.
        let tor_reverse = self.profile.backend.tor_mode() == Some(crate::profile::TorMode::Reverse);
        let tor_only =
            self.profile.backend.tor_mode() == Some(crate::profile::TorMode::Only) || tor_reverse;
        // <<< AETHER-APP-PATCH tor-aether-fast-path
        let fingerprint = kind == Prep::Plan && !tor_only;
        if tor_only && kind == Prep::Plan {
            DiagnosticsLog::i(
                TAG,
                if self.custom_psiphon_base() {
                    "Psiphon (custom chain): skipping the network fingerprint — Psiphon picks its own transports."
                } else if tor_reverse {
                    "Tor → Aether: skipping the network fingerprint — the carrier through Tor is always MASQUE over HTTP/2."
                } else {
                    "Tor alone: skipping the network fingerprint — it decides nothing here."
                },
            );
        }
        std::thread::Builder::new()
            .name("aether-prep".into())
            .spawn(move || {
                // معادل PortProbe.awaitClosed — ریشهٔ باگ «تعویض پروتکل گیر می‌کند».
                //
                // 1.3.0 port-guard: «starting anyway» دیگر وجود ندارد. لاگ‌های
                // ۲۰۲۶-۱۰-۰۸ نشان دادند هر شش حالت روی همین سطر می‌مردند: یک
                // فرآیندِ یتیم ۱۸۱۹ را گرفته بود و هر تلاش با 10048 می‌افتاد.
                // حالا صاحبِ پورت پیدا می‌شود؛ یتیمِ خودِ اتر کشته می‌شود و
                // برنامهٔ غریبه با نام و PID گزارش می‌شود.
                let blocked = match crate::procguard::prepare_ports(
                    &[engine::LOCAL_SOCKS_PORT],
                    &[engine::TOR_SOCKS_PORT, engine::CHAIN_SOCKS_PORT],
                    Duration::from_millis(PORT_RELEASE_WAIT_MS),
                ) {
                    Ok(()) => {
                        if !engine::wait_for_port_release(
                            engine::LOCAL_SOCKS_PORT,
                            Duration::from_millis(500),
                        ) {
                            DiagnosticsLog::w(
                                TAG,
                                &format!(
                                    "Local port {} still answers after the port guard ran.",
                                    engine::LOCAL_SOCKS_PORT
                                ),
                            );
                        }
                        None
                    }
                    Err(reason) => Some(reason),
                };
                if blocked.is_some() {
                    *slot.lock() = Some(PrepOutcome {
                        fingerprint: smart_auto::NetFingerprint::default(),
                        blocked,
                    });
                    return;
                }
                // SmartAuto.kt parity: fingerprint the network before planning.
                // 1.2.3-p2 adds the UDP leg. Without it the planner could not
                // tell HTTP/3 from HTTP/2 and defaulted to the slow carrier.
                // Keep the two questions separate. WireGuard needs any usable
                // UDP path; MASQUE's HTTP/3 carrier needs QUIC on UDP:443. The
                // field log proves they can differ: UDP worked for WireGuard,
                // while Cloudflare QUIC was filtered. Conflating them made Smart
                // Auto classify the network as UDP-blocked and always lead with
                // MASQUE.
                let fp = if fingerprint {
                    smart_auto::NetFingerprint {
                        filtered: probe::network_looks_filtered(),
                        udp_ok: probe::udp_egress_ok(),
                        quic_ok: probe::quic_carrier_ok(),
                    }
                } else {
                    smart_auto::NetFingerprint::default()
                };
                *slot.lock() = Some(PrepOutcome {
                    fingerprint: fp,
                    blocked: None,
                });
            })
            .ok();
    }

    /// Builds the ladder once the fingerprint is in, then launches its first rung.
    fn launch_plan(&mut self, fingerprint: smart_auto::NetFingerprint) -> Result<()> {
        if !self.smart_plus_done && self.custom.is_none() && crate::smart_plus::eligible(&self.profile){
            self.smart_plus_done=true;self.smart_plus=Some(crate::smart_plus::Session::new(&self.profile,fingerprint,&self.data_dir));
            return self.smart_plus_next();
        }
        // استیج ۱ نردبانِ Smart Auto و سخت‌سازی ضد‌DPI را دست‌نخورده نگه می‌دارد،
        // پس یک نشست زنجیره‌ای همان اثر‌انگشت‌زنی و همان تلاش‌های مجدد نشست عادی
        // را می‌گیرد — ولی بدون مسیر داده و بدون پل.
        let planning_profile = if self.profile.is_chained()
            && self.profile.backend != crate::profile::TransportBackend::TorPsiphon
        {
            self.profile.chained_stage()
        } else {
            self.profile.clone()
        };
        self.plan = if self.custom_upstream_engine() {
            state_custom::custom_upstream_plan(&planning_profile)
        } else {smart_auto::build_plan(&planning_profile, fingerprint)};
        self.plan_index = 0;
        self.launch_candidate()
    }

    fn smart_plus_next(&mut self)->Result<()> {
        let step=self.smart_plus.as_mut().and_then(|s|s.steps.pop_front());
        match step {
            Some(crate::smart_plus::plan::Step::Remembered(t))=>{
                self.plan=vec![self.smart_plus.as_mut().unwrap().candidate(t,false)];self.plan_index=0;match self.launch_candidate(){Ok(())=>Ok(()),Err(e)=>{DiagnosticsLog::w("smart+",&e.to_string());self.smart_plus.as_mut().unwrap().failed(&self.data_dir);self.cleanup_native(true);self.smart_plus_next()}}
            },
            Some(crate::smart_plus::plan::Step::Race(lanes))=>{
                let s=self.smart_plus.as_mut().unwrap();s.current=None;
                s.race=Some(crate::smart_plus::RaceTask::spawn(s.user.clone(),lanes,&self.engine,self.data_dir.clone(),s.key.clone()));
                self.deadline=None;self.set_state(ConnectionState::Connecting,"Smart: racing independent connection tactics…");Ok(())
            },
            None=>{let fp=self.smart_plus.take().map(|s|s.fingerprint).unwrap_or_default();DiagnosticsLog::i("smart+","Race/confirmation exhausted; using the complete Smart ladder");self.launch_plan(fp)}
        }
    }
    fn smart_plus_poll(&mut self)->bool {
        let Some(race)=self.smart_plus.as_mut().and_then(|s|s.race.as_mut())else{return false;};
        let Some(winner)=race.poll()else{return true;};
        self.smart_plus.as_mut().unwrap().race=None;
        let result=if let Some(t)=winner {let s=self.smart_plus.as_mut().unwrap();self.plan=vec![s.candidate(t,true)];self.plan_index=0;self.launch_candidate()}else{self.smart_plus_next()};
        if let Err(e)=result{DiagnosticsLog::w("smart+",&e.to_string());if let Some(s)=self.smart_plus.as_mut(){s.failed(&self.data_dir);}self.cleanup_native(true);if let Err(e)=self.smart_plus_next(){self.fail(&e.to_string());}}true
    }

    /// اجرای یک پله از نردبان — معادل یک دور `runLadder`.
    ///
    /// Assumes [`begin_prep`] has already waited for the local port, so all this
    /// does is spawn the engine: fast enough to stay on the lock.
    fn launch_candidate(&mut self) -> Result<()> {
        let cand = self.plan[self.plan_index].clone();
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Attempt {}/{} → {}",
                self.plan_index + 1,
                self.plan.len(),
                cand.label
            ),
        );

        self.effective_protocol = Some(cand.profile.protocol);
        // >>> AETHER-APP-PATCH tor-native-carrier
        // «تور تنها» از tor.exe رسمی می‌گذرد. اگر این نصب باینری را نداشته
        // باشد، همان مسیرِ قبلی (arti داخلِ موتور) اجرا می‌شود: بیلدی که تور
        // را حمل نکند منتشر نمی‌شود، ولی نصبِ قدیمیِ روی دیسک ممکن است.
        if self.start_native_tor(&cand)? {
            return Ok(());
        }
        // <<< AETHER-APP-PATCH tor-native-carrier
        // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // `Aether → Tor`: ترتیب برعکس است — اول موتور، بعد tor.exe از دلِ همین
        // تونل. پس موتور باید پروفایلی بگیرد که `--tor` در آن نیست؛ وگرنه دو
        // تور روی یک زنجیر بالا می‌آمد و آن یکی همان arti بود که در لاگِ
        // ۱۷ سپتامبر روی ۱۵٪ ماند.
        let engine_profile = if self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Chain)
            && self.engine.native_tor().is_some()
        {
            self.tor_stage = TorStage::EngineThenTor;
            let mut stage = cand.profile.clone();
            stage.backend = crate::profile::TransportBackend::Aether;
            stage
        } else {
            cand.profile.clone()
        };
        // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        let engine_profile = if self.profile.is_chained() {
            let mut chain = engine_profile;
            chain.backend = self.profile.backend;
            chain.exit_region = self.profile.exit_region.clone();
            chain
        } else {
            engine_profile
        };
        // The engine is told how long this rung is allowed to take, so its own
        // endpoint scan is sized to fit inside that window instead of being
        // killed 78% of the way through it. See `engine::AetherProcess::start`.
        self.engine.set_custom_tcp_upstream(self.custom_upstream_engine());
        self.engine.start(&engine_profile, Some(cand.timeout_ms))?;
        // ۱.۲.۵ — مهلتِ دیوارِ ساعت برای نشست تور جداست، و **بودجهٔ اسکن نیست**.
        // آن یکی بالا به موتور رفت تا اسکن لبه را اندازه کند؛ این یکی می‌گوید
        // برنامه چقدر صبر می‌کند. تور اسکن نمی‌کند، bootstrap می‌کند — و روی
        // شبکه‌ای که فقط کند است همان یک مرحله ده‌ها ثانیه طول می‌کشد. بستنِ
        // این پنجره به مهلتِ اسکن، دقیقاً همان بریدنی بود که کاربر آن را
        // «وصل نمی‌شود» گزارش کرد. آنچه این بودجهٔ بلند را به سکوتِ بلند تبدیل
        // **نمی‌کند**، تشخیصِ گیرکردن در `tor_gate` است.
        let budget_ms = self.tor_budget_ms().unwrap_or(cand.timeout_ms);
        self.deadline = Some(Instant::now() + Duration::from_millis(budget_ms));
        self.set_state(ConnectionState::Connecting, "Connecting…");
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Waiting for SOCKS5 on 127.0.0.1:{}… (timeout={}s)",
                engine::LOCAL_SOCKS_PORT,
                budget_ms / 1000
            ),
        );
        Ok(())
    }

    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// تورِ زنجیره‌ای را **پشتِ** موتور بالا می‌آورد — حالتِ `Aether → Tor`.
    ///
    /// # چرا پل نمی‌گیرد
    ///
    /// پل برای رسیدن به توری است که خودش بسته است؛ اینجا تونلِ اِتِر همان چیزی
    /// است که ما را بیرون برده، پس آن پرسش قبلاً پاسخ گرفته. WhiteAesther هم
    /// همین را می‌کند و دلیلش را نوشته: تور `Socks5Proxy` و
    /// `ClientTransportPlugin` را با هم می‌پذیرد، ولی هرگز دیده نشده که
    /// lyrebird پلش را *از راهِ آن پراکسی* بگیرد — و ترابری که آن را نادیده
    /// بگیرد، نشانیِ پل را روی شبکهٔ سانسورشده لخت می‌گیرد.
    fn start_tor_behind_engine(&mut self) -> Result<()> {
        let upstream: std::net::SocketAddr = ([127, 0, 0, 1], engine::LOCAL_SOCKS_PORT).into();
        let socks = self.tor_listener_port();
        let budget_ms = self
            .tor_budget_ms()
            .unwrap_or(diagnostics::TOR_BOOTSTRAP_BUDGET_MS);
        self.spawn_native_tor(
            socks,
            Some(upstream),
            crate::tor_native::BridgeMode::None,
            String::new(),
            budget_ms,
            format!(
                "Aether → Tor: the tunnel is up; running the bundled tor.exe on 127.0.0.1:{socks} \
                 through it (no bridges — the tunnel already got us out)"
            ),
        )
    }

    /// موتور را **پشتِ** تورِ آماده اجرا می‌کند — حالتِ `Tor → Aether`.
    /// As on mobile, establish Tor first. Unlike the old `--tor-only --psiphon`
    /// invocation, this reuses the same tor.exe/obfs4 cache that succeeds in the
    /// Tor-only and reverse modes. Core 2.4.0 then owns ONLY Psiphon and uses
    /// AETHER_UPSTREAM for its server dials. No WARP hop is introduced.
    fn start_psiphon_behind_tor(&mut self) -> Result<()> {
        let cand = self.plan[self.plan_index].clone();
        let port = self.tor_listener_port();
        self.engine.set_upstream_socks(Some(port));
        self.engine.start(&cand.profile, Some(cand.timeout_ms))?;
        crate::tor_bootstrap::mark_done("tor.exe in front of Psiphon is ready");
        // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
        self.psiphon_gate_since = Some(Instant::now());
        self.psiphon_next_probe = Some(Instant::now() + PSIPHON_PROBE_INTERVAL);
        self.psiphon_probe = None;
        // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
        self.tor_front_ready = true;
        self.tor_stage = TorStage::None;
        self.deadline = Some(Instant::now() + Duration::from_millis(CHAIN_BUDGET_MS));
        self.set_state(ConnectionState::Connecting, "Starting Psiphon through Tor…");
        DiagnosticsLog::i(TAG, &format!("Tor → Psiphon: Tor is ready on 127.0.0.1:{port}; waiting for Psiphon egress on 127.0.0.1:{}", engine::LOCAL_SOCKS_PORT));
        Ok(())
    }

    fn start_engine_behind_tor(&mut self) -> Result<()> {
        let cand = self.plan[self.plan_index].clone();
        // >>> AETHER-APP-PATCH tor-aether-fast-path
        // موتور مستقیم به tor.exe وصل نمی‌شود، بلکه به رلهٔ صبوری که جلوی آن
        // است؛ اگر رله بالا نیاید، همان مسیرِ قبلی (خودِ پورتِ تور) می‌ماند.
        let tor_listener = self.tor_listener_port();
        let tor_port = self.patient_tor_dialer(tor_listener);
        // <<< AETHER-APP-PATCH tor-aether-fast-path
        // بدونِ این، موتور `--tor-reverse` می‌گرفت و تورِ داخلیِ خودش (arti) را
        // بالا می‌آورد — همان چیزی که در لاگِ ۱۷ سپتامبر ده دقیقه روی ۱۵٪ ماند
        // درحالی‌که tor.exe با همان پل‌ها ۲۲ ثانیه‌ای رسیده بود.
        let mut stage = cand.profile.clone();
        stage.backend = crate::profile::TransportBackend::Aether;
        // تور TCP حمل می‌کند و بس؛ MASQUE باید روی HTTP/2 برود. پرچمِ پروتکل و
        // متغیرِ `AETHER_MASQUE_HTTP2` هر دو گفته می‌شوند: نردبان از قبل همین را
        // انتخاب می‌کند، ولی صریح‌بودن اینجا ارزانتر از یک نشستِ ناممکن است.
        stage.protocol = crate::profile::Protocol::Masque;
        self.engine.set_upstream_socks(Some(tor_port));
        self.engine.start(&stage, Some(cand.timeout_ms))?;
        // >>> AETHER-APP-PATCH tor-reverse-gate
        // `engine.start` درصدِ تور را صفر می‌کند؛ ولی تورِ این حالت tor.exe است و
        // همین حالا به ۱۰۰٪ رسیده. بی این سطر دروازهٔ تور تا ابد منتظرِ درصدی
        // می‌ماند که موتورِ MASQUE هرگز نمی‌گوید (`loge3`).
        crate::tor_bootstrap::mark_done("tor.exe in front of the engine is ready");
        // <<< AETHER-APP-PATCH tor-reverse-gate
        // >>> AETHER-APP-PATCH tor-reverse-latch
        self.tor_front_ready = true;
        // <<< AETHER-APP-PATCH tor-reverse-latch
        self.tor_stage = TorStage::None;
        // بودجهٔ تازه: bootstrapِ تور تمام شده و از این‌جا کارِ موتور است. اگر
        // مهلتِ مرحلهٔ اول را نگه می‌داشتیم، توری که ۹ دقیقه bootstrap کرده
        // موتور را با یک ثانیه بودجه تحویل می‌داد.
        self.deadline = Some(Instant::now() + Duration::from_millis(cand.timeout_ms));
        self.set_state(
            ConnectionState::Connecting,
            "Starting the tunnel through Tor…",
        );
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Tor → Aether: tor is ready on 127.0.0.1:{tor_listener}; the engine dials out through \
                 it (AETHER_UPSTREAM=socks5://127.0.0.1:{tor_port}, http/2 carrier; the engine \
                 picks its own MASQUE edge, exactly as on mobile)."
            ),
        );
        Ok(())
    }

    // >>> AETHER-APP-PATCH tor-aether-fast-path
    /// پورتی که موتور باید به‌عنوانِ `AETHER_UPSTREAM` بگیرد: رلهٔ صبورِ جلوی
    /// tor.exe، یا در صورتِ خطا خودِ پورتِ تور.
    fn patient_tor_dialer(&mut self, tor_listener: u16) -> u16 {
        if let Some(relay) = self.tor_relay.as_ref() {
            if relay.tor_port() == tor_listener {
                return relay.port();
            }
        }
        self.tor_relay = None;
        match crate::tor_relay::TorDialRelay::start(tor_listener) {
            Ok(relay) => {
                let port = relay.port();
                self.tor_relay = Some(relay);
                port
            }
            Err(e) => {
                DiagnosticsLog::w(
                    TAG,
                    &format!("Patient Tor dialer could not start ({e}); the engine talks to tor directly."),
                );
                tor_listener
            }
        }
    }

    /// موتورِ `Tor → Aether` پیش از باز کردنِ SOCKS مُرد ولی tor.exe هنوز سالم و
    /// آماده است: به‌جای دور ریختنِ bootstrapِ تور و شکستِ کلِ اتصال، موتور
    /// پشتِ همان تور دوباره اجرا می‌شود.
    fn respawn_engine_behind_tor(&mut self) -> bool {
        let reverse = self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Reverse);
        let tor_alive = self
            .native_tor
            .as_ref()
            .map(|t| t.is_alive())
            .unwrap_or(false);
        if !reverse
            || !self.tor_front_ready
            || !tor_alive
            || !self.engine.was_started()
            || self.engine.is_alive()
            || self.tor_reverse_respawns >= TOR_REVERSE_RESPAWNS
            || self.past_deadline()
        {
            return false;
        }
        self.tor_reverse_respawns += 1;
        DiagnosticsLog::w(
            TAG,
            &format!(
                "Tor → Aether: the engine exited before its SOCKS5 port opened; tor is still up, so the engine is restarted behind it ({}/{}) instead of dropping the circuit.",
                self.tor_reverse_respawns, TOR_REVERSE_RESPAWNS
            ),
        );
        self.engine.stop();
        match self.start_engine_behind_tor() {
            Ok(()) => true,
            Err(e) => {
                DiagnosticsLog::w(TAG, &format!("Engine restart behind tor failed: {e}"));
                false
            }
        }
    }
    // <<< AETHER-APP-PATCH tor-aether-fast-path
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor

    // >>> AETHER-APP-PATCH tor-native-carrier
    /// تورِ رسمی را برای این تلاش بالا می‌آورد. `false` یعنی این تلاش جای
    /// دیگری دارد و مسیرِ موتور باید ادامه یابد.
    ///
    /// bootstrap تا سه دقیقه طول می‌کشد، پس روی یک ترد می‌نشیند و ماشینِ حالت
    /// مثل همیشه با `probe::socks_ready` و `tor_gate` پیش می‌رود. خطوطِ
    /// پیشرفت به همان لاگی می‌روند که `tor_bootstrap` می‌خواند، با همان قالبِ
    /// `tor reaching the network: N%` — پس درصد در UI و تشخیصِ گیرکردن
    /// بی‌هیچ تغییری کار می‌کنند.
    fn start_native_tor(&mut self, cand: &Candidate) -> Result<bool> {
        use crate::profile::{TorBridges, TorMode};

        // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // پیش‌تر تنها `Only` از این مسیر می‌گذشت و دو حالتِ دیگر به تورِ داخلیِ
        // موتور می‌رسیدند. `Reverse` هم از امروز اینجاست: تور جلوی موتور
        // می‌ایستد و موتور مشتریِ آن می‌شود. `Chain` اینجا نیست چون ترتیبش
        // برعکس است — اول موتور، بعد تور — و در `tick` انجام می‌شود.
        let tor_psiphon = self.profile.backend == crate::profile::TransportBackend::TorPsiphon;
        let socks = match self.tor_mode_of_attempt() {
            Some(TorMode::Only) if tor_psiphon => engine::TOR_SOCKS_PORT,
            Some(TorMode::Only) => {
                // قراردادِ برنامه: مرورگر و پراکسیِ سیستم و TUN همین عدد را
                // می‌شناسند.
                engine::LOCAL_SOCKS_PORT
            }
            Some(TorMode::Reverse) => self.tor_listener_port(),
            _ => return Ok(false),
        };
        // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        if self.engine.native_tor().is_none() {
            DiagnosticsLog::w(
                TAG,
                "This installation carries no tor binary; falling back to the engine's own tor.",
            );
            return Ok(false);
        }

        // >>> AETHER-APP-FIX tor-auto-like-mobile
        // پل، همان معنای موبایل (`TorBridges` در `tor.rs`ِ هسته): `Off` یعنی
        // مستقیم، `Always` یعنی فقط پل، و `Auto` (پیش‌فرض) یعنی *هم مستقیم و هم
        // پل* — که اینجا هم‌زمان اجرا می‌شوند (`BridgeMode::Auto`). تا این نسخه
        // `Auto` همان `Always` بود و ویندوز هرگز تورِ مستقیم را امتحان نمی‌کرد؛
        // روی وای‌فای‌ای که تورِ مستقیم باز است، موبایل زیرِ ۱۵ ثانیه وصل می‌شد
        // و ویندوز از راهِ obfs4 دقیقه‌ها دایرکتوری می‌کشید. پلِ دستی همیشه
        // بر هر دو مقدم است.
        let bridges = match cand.profile.tor_bridges {
            TorBridges::Off => crate::tor_native::BridgeMode::None,
            _ if cand.profile.has_custom_bridges() => crate::tor_native::BridgeMode::Custom,
            TorBridges::Always => crate::tor_native::BridgeMode::BuiltIn,
            TorBridges::Auto => crate::tor_native::BridgeMode::Auto,
        };
        // <<< AETHER-APP-FIX tor-auto-like-mobile
        let budget_ms = self.tor_budget_ms().unwrap_or(cand.timeout_ms);
        if tor_psiphon {
            self.tor_stage = TorStage::TorThenPsiphon;
        }
        let headline = if tor_psiphon {
            format!("Tor → Psiphon: preparing bundled tor.exe on 127.0.0.1:{socks} before Psiphon starts (timeout={}s)", budget_ms / 1000)
        } else if socks == engine::LOCAL_SOCKS_PORT {
            format!(
                "Tor alone: running the bundled tor.exe on 127.0.0.1:{socks}, bridges={bridges:?} \
                 (timeout={}s)",
                budget_ms / 1000
            )
        } else {
            // مرحلهٔ دوم (موتور) در `tick` و پس از آمادگیِ تور اجرا می‌شود.
            self.tor_stage = TorStage::TorThenEngine;
            format!(
                "Tor → Aether: running the bundled tor.exe on 127.0.0.1:{socks} in front of the \
                 engine, bridges={bridges:?} (timeout={}s)",
                budget_ms / 1000
            )
        };
        // AETHER-APP-PATCH custom-configs: در `Config → Tor…` تور از دلِ Xray
        // بیرون می‌رود؛ بی کانفیگِ سفارشی همان `None` و همان پل‌ها.
        let (upstream, bridges) = self.custom_tor_front(bridges);
        self.spawn_native_tor(
            socks,
            upstream,
            bridges,
            cand.profile.sanitized_bridges().join("\n"),
            budget_ms,
            headline,
        )?;
        Ok(true)
    }

    /// یک tor.exe را روی یک ترد بالا می‌آورد — تنها جایی که این کار انجام
    /// می‌شود، چه تور جلوی موتور باشد، چه پشتش، چه تنها.
    #[allow(clippy::too_many_arguments)]
    fn spawn_native_tor(
        &mut self,
        socks: u16,
        upstream: Option<std::net::SocketAddr>,
        bridges: crate::tor_native::BridgeMode,
        custom_bridges: String,
        budget_ms: u64,
        headline: String,
    ) -> Result<()> {
        let probe = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks))
            .map_err(|e| anyhow::anyhow!("Tor SOCKS port 127.0.0.1:{socks} is unavailable: {e}"))?;
        drop(probe);
        let Some((binary, support)) = self.engine.native_tor() else {
            return Err(anyhow::anyhow!("this installation carries no tor binary"));
        };
        let launch = crate::tor_native::TorLaunch {
            binary,
            support,
            home: self.engine.native_tor_home(),
            bridges,
            transport: String::new(),
            custom_bridges,
            upstream,
            socks: Some(socks),
            budget: Some(Duration::from_millis(budget_ms)),
        };

        // درصدِ نشستِ قبلی نباید این یکی را «در حرکت» نشان دهد.
        crate::tor_bootstrap::reset();
        // >>> AETHER-APP-PATCH tor-reverse-latch
        // تورِ تازه یعنی هنوز هیچ جلوداری آماده نیست.
        self.tor_front_ready = false;
        // <<< AETHER-APP-PATCH tor-reverse-latch

        let tor = crate::tor_native::TorNative::new(std::sync::Arc::new(|line: &str| {
            DiagnosticsLog::i("tor", line);
            crate::tor_bootstrap::ingest(line);
            // >>> AETHER-APP-PATCH tor-cold-cache-waves
            if crate::tor_bootstrap::is_native_headway(line) {
                crate::tor_bootstrap::touch();
            }
            // <<< AETHER-APP-PATCH tor-cold-cache-waves
            // در حالت‌های توری اندپوینتِ واقعی پلِ اول است؛ همین سینک می‌رساندش.
            crate::firsthop::ingest(line);
        }));
        // پیش از هر چیز: از این لحظه حامل «در حالِ راه‌اندازی» است. اگر این
        // سطر نباشد، تیکِ بعدی (۲۰۰ms بعد) حاملی می‌بیند که هنوز فرزندی
        // ندارد و تلاش را جمع می‌کند — همان شکستِ تلاشِ اولِ لاگِ ۲۰:۰۴.
        tor.mark_starting();
        self.native_tor = Some(tor.clone());

        self.deadline = Some(Instant::now() + Duration::from_millis(budget_ms));
        self.set_state(ConnectionState::Connecting, "Connecting…");
        DiagnosticsLog::i(TAG, &headline);

        std::thread::Builder::new()
            .name("tor-native".to_string())
            .spawn(move || match tor.start(&launch) {
                Ok(address) => DiagnosticsLog::i("tor", &format!("tor is ready on {address}")),
                Err(e) => {
                    // تنها جایی که شکستِ راه‌اندازی اعلام می‌شود: هر مسیرِ
                    // خطای `start` از این‌جا می‌گذرد.
                    tor.mark_dead();
                    DiagnosticsLog::e("tor", &format!("tor did not come up: {e}"));
                }
            })
            .map_err(|e| anyhow::anyhow!("could not start the tor thread: {e}"))?;
        Ok(())
    }

    /// آیا حاملِ این تلاش زنده است؟
    ///
    /// در «تور تنها» هیچ موتوری اجرا نشده، پس پرسیدنِ `engine.is_alive()`
    /// همیشه «مرده» جواب می‌دهد و تلاش را در همان تیکِ اول می‌کُشد. و در
    /// حالت‌های زنجیره‌ای هر دو نیمه باید زنده باشند — ولی فقط آن نیمه‌ای که
    /// واقعاً اجرا شده پرسیده می‌شود.
    fn carrier_alive(&mut self) -> bool {
        let tor = self.native_tor.as_ref().map(|tor| tor.is_alive());
        let engine = if self.engine.was_started() {
            Some(self.engine.is_alive())
        } else {
            None
        };
        // AETHER-APP-PATCH custom-configs: Xray هم بخشی از حامل است.
        let xray = self.custom_xray_alive();
        match (tor, engine, xray) {
            (None, None, Some(x)) => x,
            (_, _, Some(false)) => false,
            (Some(tor), Some(engine), _) => tor && engine,
            (Some(alive), None, _) | (None, Some(alive), _) => alive,
            // هیچ‌کدام اجرا نشده: در فازِ Connecting این وضع یعنی چیزی مرده است.
            (None, None, None) => false,
        }
    }
    // <<< AETHER-APP-PATCH tor-native-carrier

    /// آیا این نشست واقعاً تور را اجرا می‌کند؟ (با احتساب گیتِ نسخهٔ هسته)
    ///
    /// پروفایلِ **پله** پرسیده می‌شود، نه پروفایلِ کاربر: در نشست زنجیره‌ای
    /// استیج ۱ چیزی است که `chained_stage` ساخته، و همان است که اجرا می‌شود.
    fn tor_fronted(&self) -> bool {
        if !self.engine.caps().tor || self.custom_psiphon_base() {
            return false;
        }
        self.plan
            .get(self.plan_index)
            .map(|c| c.profile.backend)
            .unwrap_or(self.profile.backend)
            .uses_tor()
    }

    /// حالتِ توری که **این تلاش** اجرا می‌کند، با گیتِ نسخهٔ هسته.
    fn tor_mode_of_attempt(&self) -> Option<crate::profile::TorMode> {
        if !self.engine.caps().tor || self.custom_psiphon_base() {
            return None;
        }
        self.plan
            .get(self.plan_index)
            .map(|c| c.profile.backend)
            .unwrap_or(self.profile.backend)
            .tor_mode()
    }

    /// آیا پل در این تلاش واقعاً می‌تواند کاری کند؟
    ///
    /// # چرا این سؤال با «آیا کاربر پل را خاموش نکرده» یکی نیست
    ///
    /// سه شرط، و هر سه از لاگ میدانیِ ۱۵٪ درآمده‌اند:
    ///
    /// * **حالت.** در `Aether → Tor` تور از داخل تونل dial می‌شود.
    ///   `profile.rs` در این حالت هیچ فلگ پلی به موتور نمی‌فرستد و موتور هم
    ///   بی `forced` هرگز به پل برنمی‌گردد (`tor.rs::establish`:
    ///   `(_, Some(_)) => forced`). پس صبرِ ۴۲۰ ثانیه‌ای انتظار برای چیزی است
    ///   که اتفاق نمی‌افتد — و دقیقاً همان ۸۳ ثانیهٔ بی‌پیامِ لاگ.
    /// * **پروفایلِ همین تلاش،** نه پروفایل کاربر: در نردبان، پلهٔ در حال اجرا
    ///   می‌تواند بک‌اند دیگری داشته باشد — همان دلیلی که `tor_fronted` هم
    ///   پروفایلِ پله را می‌پرسد.
    /// * **ترابر.** بی ترابر هیچ obfs4ای در کار نیست که ۷ دقیقه ارزش انتظار
    ///   داشته باشد؛ فقط پلِ ساده می‌ماند، که مثل هر رله جواب می‌دهد یا بسته
    ///   است. سطرهای دستیِ کاربر هم اینجا کمکی نمی‌کنند:
    ///   `profile::is_bridge_line` فقط سطری را می‌پذیرد که با نام یک ترابر
    ///   شروع شود.
    fn tor_bridges_can_help(&self) -> bool {
        if self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Chain) {
            return false;
        }
        // `Config → Tor…`: تور از دلِ کانفیگِ سفارشی می‌رود و پل خاموش است؛
        // «trying bridges» دروغ بود و پنجرهٔ گیرِ ۴۲۰ ثانیه‌ایِ پل را می‌خرید.
        if self.custom_tor_behind_config() {
            return false;
        }
        if self.profile.tor_bridges == crate::profile::TorBridges::Off {
            return false;
        }
        self.engine.transport_installed()
    }

    /// شکلِ توری که این تلاش دارد — برای پیام شکست.
    fn tor_shape(&self) -> Option<diagnostics::TorShape> {
        match self.tor_mode_of_attempt()? {
            crate::profile::TorMode::Chain => Some(diagnostics::TorShape::ThroughTunnel),
            _ => Some(diagnostics::TorShape::FacingNetwork {
                bridges_allowed: self.profile.tor_bridges != crate::profile::TorBridges::Off,
                transport_installed: self.engine.transport_installed(),
            }),
        }
    }

    /// بودجهٔ دیوارِ ساعت برای یک تلاش تور، یا `None` وقتی تور در کار نیست.
    fn tor_budget_ms(&self) -> Option<u64> {
        if !self.tor_fronted() {
            return None;
        }
        Some(if self.tor_bridges_can_help() {
            diagnostics::TOR_BRIDGE_BUDGET_MS
        } else {
            diagnostics::TOR_BOOTSTRAP_BUDGET_MS
        })
    }

    /// چند وقت بی‌حرکتیِ درصد یعنی این تلاش مرده است.
    fn tor_stall_ms(&self) -> u64 {
        // Tor inside a custom-config chain (Config → Tor…, Config → Aether → Tor)
        // bootstraps through extra hops; wait for the whole budget instead of
        // declaring a stall after 45s.
        if self.custom.is_some() {
            return diagnostics::TOR_STALL_BRIDGED_MS;
        }
        if self.tor_bridges_can_help() {
            diagnostics::TOR_STALL_BRIDGED_MS
        } else {
            diagnostics::TOR_STALL_DIRECT_MS
        }
    }

    /// پورتی که مسیر داده باید به آن بچسبد — خروجیِ **واقعیِ** خط لوله.
    ///
    /// در `Aether → Tor` موتور دو لیسنر دارد: پورت همیشگی که خروجی WARP است و
    /// یک لیسنر دوم برای تور. مسیر داده باید به دومی برود، وگرنه کاربری که
    /// «Aether → Tor» را انتخاب کرده، از خروجی WARP بیرون می‌رفت و هرگز هم
    /// نمی‌فهمید: تونل بالا می‌آمد، خودآزما سبز می‌شد، و تور فقط بی‌مصرف
    /// می‌چرخید.
    ///
    /// گیت `tor_fronted` اینجا هم لازم است: روی هستهٔ قدیمی‌تر فلگ‌های تور
    /// اصلاً فرستاده نشده‌اند، پس لیسنر دومی وجود ندارد و اشاره به آن، مسیر
    /// داده را به پورتی می‌بست که کسی در آن گوش نمی‌دهد.
    fn data_path_exit_port(&self) -> u16 {
        if self.psiphon_exit_session() {
            return engine::LOCAL_SOCKS_PORT;
        }
        if !self.tor_fronted() {
            return engine::LOCAL_SOCKS_PORT;
        }
        self.profile.backend.exposed_socks_port()
    }

    /// پورتی که **حمل‌کننده** خودش باز می‌کند — تنها چیزی که دروازهٔ تور حق دارد منتطرش بماند.
    ///
    /// # چرا این همانِ `data_path_exit_port` نیست
    ///
    /// در زنجیره (`Tor → Psiphon`) خروجیِ خط لوله پورتِ استیج ۲ است و را فقط
    /// Psiphon باز می‌کند — و Psiphon فقط پس از عبور از این دروازه شروع
    /// می‌شود. لاگِ `loge4` دقیقاً همین قفلِ دوطرفه است: تور ۱۰۰٪ می‌شود، پیام
    /// «Tor is ready — opening its local proxy…» می‌آید، و بعد پنج دقیقه سکوت تا
    /// کاربر دستی قطع کند؛ در کلِ فایل یک سطر «Starting Psiphon» وجود ندارد.
    fn tor_listener_port(&self) -> u16 {
        if self.profile.backend == crate::profile::TransportBackend::TorPsiphon
            && self.native_tor.is_some()
        {
            return engine::TOR_SOCKS_PORT;
        }
        self.profile
            .backend
            .tor_socks_port()
            .unwrap_or(engine::LOCAL_SOCKS_PORT)
    }

    /// دروازهٔ تور: آیا می‌توان مسیر داده را بالا آورد؟
    ///
    /// # چرا پورتِ باز اثبات چیزی نیست
    ///
    /// موتور لیسنر SOCKS5 را همان لحظهٔ اجرا bind می‌کند، **پیش از** آنکه تور
    /// به شبکه رسیده باشد. تا ۱.۲.۴ همین حلقه پورتِ باز را آمادگیِ استیج ۱
    /// می‌گرفت و بی‌درنگ مسیر داده را بالا می‌آورد و خودآزما را می‌زد؛ روی
    /// حالت‌های تور آن خودآزما به توری می‌خورد که هنوز ۳۰٪ بود، شکست می‌خورد،
    /// و برنامه «تونل بالا آمد ولی خودآزما شکست خورد» می‌گفت — برای توری که
    /// هیچ ایرادی نداشت جز تمام‌نشدن.
    ///
    /// حالا سه جواب دارد: آماده، منتظر (با درصدی که روی صفحه می‌رود)، و
    /// گیرکرده — که تنها حالتی است که تلاش را می‌کشد، و پیامش علت واقعی را
    /// نام می‌برد.
    fn tor_gate(&mut self) -> TorGate {
        if !self.tor_fronted() {
            return TorGate::Ready;
        }
        // >>> AETHER-APP-PATCH tor-reverse-latch
        // `Tor → Aether` پس از اجرای موتور: تور قبلاً ثابت شده (۱۰۰٪ + مدار)، و
        // آنچه حالا منتظرش هستیم پورتِ موتور است که این تابع فقط وقتی باز است
        // صدا زده می‌شود. درصدِ سراسری این‌جا هیچ چیز را تعیین نمی‌کند.
        if self.tor_front_ready
            && (self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Reverse)
                || self.profile.backend == crate::profile::TransportBackend::TorPsiphon)
        {
            return TorGate::Ready;
        }
        // <<< AETHER-APP-PATCH tor-reverse-latch
        if tor_bootstrap::done() {
            // bootstrap تمام است، ولی در حالت‌های زنجیره‌ای/برعکس لیسنرِ دومِ
            // تور یک لحظه بعد از آن باز می‌شود. معادلِ `awaitOpen(torPort)`
            // اندروید: چسباندنِ مسیر داده به پورتی که هنوز نیامده، همان
            // «وصل شد ولی هیچ چیز باز نمی‌شود» است.
            let exit = self.tor_listener_port();
            if exit != engine::LOCAL_SOCKS_PORT && !probe::socks_ready(exit) {
                self.set_state(
                    ConnectionState::Connecting,
                    "Tor is ready — opening its local proxy…",
                );
                return TorGate::Waiting;
            }
            return TorGate::Ready;
        }
        if tor_bootstrap::stalled(self.tor_stall_ms()) {
            return TorGate::Stalled;
        }
        let snap = tor_bootstrap::snapshot();
        // درصدِ گیرکرده روی شبکه‌ای که تور را می‌اندازد، خودش محرکِ
        // برگشت‌به‌پلِ موتور است. کاربر باید همین را بخواند، نه یک درصدِ
        // بی‌حرکت که شبیه هنگ است.
        let stuck = tor_bootstrap::stalled(diagnostics::TOR_STALL_DIRECT_MS);
        let chained = self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Chain);
        let msg = if stuck && self.tor_bridges_can_help() {
            "Tor is not getting through directly — trying bridges…".to_string()
        } else if stuck && chained {
            // در این حالت تونل ثابت‌شده بالاست و تور از داخلش جلو نمی‌رود.
            // نگفتنش یعنی گذاشتنِ کاربر روبروی یک درصدِ یخ‌زده.
            "Tor is not moving inside the tunnel — trying the next strategy…".to_string()
        } else {
            match snap.percent {
                Some(p) => format!("Reaching the Tor network… {p}%"),
                None => "Reaching the Tor network…".to_string(),
            }
        };
        self.set_state(ConnectionState::Connecting, &msg);
        TorGate::Waiting
    }

    /// معادل بخش establish در connectAttempt — فقط بعد از بازشدن پورت SOCKS5.
    fn bring_up_data_path(&mut self) -> bool {
        let profile = self
            .plan
            .get(self.plan_index)
            .map(|c| c.profile.clone())
            .unwrap_or_else(|| self.profile.clone());

        // ۰) گارد نشتی — *قبل* از هر چیز دیگری. ترتیب امنیتی است، نه سلیقه‌ای:
        // تا وقتی مسیر UDP مستقیم باز است نباید مرورگر را به تونل وصل کنیم،
        // وگرنه بین «پروکسی روشن شد» و «گارد نصب شد» یک پنجرهٔ نشتی می‌ماند.
        if self.profile.leak_guard || self.profile.kill_switch || self.profile.ipv6_protection {
            if let Some(mut old_guard) = self.guard.take() {
                old_guard.disarm_without_cleanup();
            }
            self.guard = Some(LeakGuard::engage(&profile));
        } else {
            DiagnosticsLog::w(
                TAG,
                "Leak guard is disabled in the profile — WebRTC may expose your real IP over direct UDP.",
            );
        }

        // >>> AETHER-APP-PATCH bridge-smart-routes (mobile 1.4.0 `connectExternal`)
        // در حالت‌های Psiphon موتور مقصد را نمی‌بیند؛ قواعد (فهرست‌های داخلی +
        // قواعد دستیِ کاربر) پیش از بالا آمدنِ پل به آن داده می‌شوند. در بقیهٔ
        // حالت‌ها خالی = مسیرِ قدیمیِ پل، و قواعد در خودِ موتور اعمال می‌شوند.
        // Route at the front for ALL backends: Windows sends CONNECT hostnames
        // rather than destination IPs to the engine. The bridge alone can
        // resolve and compare .com destinations against the Iranian CIDRs.
        crate::smart_routes::set_front(Some(crate::smart_lists::front_rules(
            &self.data_dir,
            &self.profile,
        )));
        crate::smart_routes::set_guest_front(Some(crate::smart_lists::guest_rules(
            &self.data_dir,
            &self.profile,
        )));
        crate::smart_routes::set_front_udp_passthrough(!self.profile.is_chained());
        // <<< AETHER-APP-PATCH bridge-smart-routes

        // Activate BEFORE accepting application flows; every relay captures this generation.
        if matches!(self.profile.backend,crate::profile::TransportBackend::AetherPsiphon|crate::profile::TransportBackend::TorPsiphon)&&self.uplink.is_none(){self.uplink=Some(crate::uplink::Runtime::start(engine::exit_socks_port()));}

        // ۱) پل محلی HTTP/SOCKS — معادل hev-socks5-tunnel/ShareBridge (مسیر دادهٔ واقعی).
        if let Err(e) = self.share.start(
            engine::SHARE_SOCKS_PORT,
            engine::SHARE_HTTP_PORT,
            profile.lan_share,
        ) {
            DiagnosticsLog::e(TAG, &format!("Bridge failed to start: {e}"));
        }

        // ۲) پروکسی سیستمی ویندوز — معادل کارکرد VpnService (کل سیستم از تونل می‌رود).
        self.sysproxy_on = sysproxy::enable(engine::SHARE_HTTP_PORT, engine::SHARE_SOCKS_PORT);

        // ۳) Wintun — اختیاری. شکست آن دیگر اتصال را نمی‌کُشد (رفع ریشه‌ای گیر StartingEngine).
        if self.tunnel.is_none() {
            let wintun = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("engine").join("wintun.dll")))
                .unwrap_or_default();
            match Tunnel::establish(&profile, &wintun) {
                Ok(t) => self.tunnel = Some(t),
                Err(e) => {
                    // AETHER-APP-FIX no-sysproxy-fallback (1.4.0): without the TUN
                    // adapter the connection is NOT reported as working; it fails
                    // visibly instead of silently degrading to the system proxy.
                    let why = format!("Wintun/TUN failed: {e:#}");
                    self.fail(&why);
                    return false;
                }
            }
        }
        true
    }

    /// Core 2.1.0 starts and supervises the bundled Psiphon executable.
    /// The desktop only waits for its final SOCKS listener; it never spawns or
    /// rotates a second Psiphon process. End-to-end verification follows below.
    fn begin_chain(&mut self) {
        self.chain_waiting = true;
        self.deadline = Some(Instant::now() + Duration::from_millis(CHAIN_BUDGET_MS));
        self.set_state(
            ConnectionState::Connecting,
            "Waiting for engine-managed Psiphon…",
        );
    }

    fn poll_chain(&mut self) {
        if !self.engine.is_alive() {
            self.chain_waiting = false;
            self.advance_or_fail("The engine exited while starting Psiphon");
        } else if probe::socks_ready(engine::CHAIN_SOCKS_PORT) {
            self.chain_waiting = false;
            engine::set_exit_socks_port(engine::CHAIN_SOCKS_PORT);
            self.chain_exit_port = Some(engine::CHAIN_SOCKS_PORT);
            // AETHER-APP-PATCH custom-configs: `Aether → Psiphon → Config`.
            if self.custom_hold_for_last(engine::CHAIN_SOCKS_PORT) {
                return;
            }
            if !self.bring_up_data_path() {
                return;
            }
            self.begin_verification();
        } else if self.past_deadline() {
            self.chain_waiting = false;
            self.advance_or_fail("The engine-managed Psiphon listener did not come up in time");
        }
    }

    /// خودآزمای ۴ مرحله‌ای در ترد پس‌زمینه — حلقهٔ tick هرگز مسدود نمی‌شود.
    fn begin_verification(&mut self) {
        let slot: Arc<Mutex<Option<diagnostics::SelfTestOutcome>>> = Arc::new(Mutex::new(None));
        self.verify_slot = Some(slot.clone());
        let verify=if self.custom.is_some(){self.profile.custom_verify_connection}else{self.profile.verify_connection};
        if !verify {
            DiagnosticsLog::w(TAG,"Initial connection verification disabled by user; listener/data path only. Leak protection and ongoing health monitoring remain enabled.");
            *slot.lock()=Some(diagnostics::SelfTestOutcome{ok:true,exit:None,latency_ms:None,leak:None});
            self.set_state(ConnectionState::Verifying,"Initial verification skipped");
            return;
        }
        let remaining = self
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()).as_millis() as u64)
            .unwrap_or(OUTBOUND_GRACE_MS);
        // نشست زنجیره‌ای گرم‌شدنِ هر دو هاپ را می‌پردازد، پس پنجرهٔ بلندتر
        // `EXTERNAL_GRACE_MS` را می‌گیرد — همان تفکیک اندروید.
        // AETHER-APP-FIX tor-proves-its-exit: هر خط لوله‌ای که از تور می‌گذرد
        // (از جمله «تور تنها») همان پنجرهٔ بلند را می‌گیرد — موبایل در
        // `connectTor` برای همهٔ حالت‌های تور `EXTERNAL_GRACE_MS` می‌دهد. با ۹۰
        // ثانیه و سنجهٔ ۴/۶ ثانیه‌ای، اولین استریم‌های یک مدارِ تازه از پلِ کند
        // پیش از رسیدنِ پاسخ بریده می‌شدند.
        let ceiling = if self.profile.is_chained()
            || self.profile.backend == crate::profile::TransportBackend::TorAether
            || self.tor_fronted()
            || self.native_tor.is_some()
        {
            diagnostics::EXTERNAL_GRACE_MS
        } else {
            OUTBOUND_GRACE_MS
        };
        let grace = remaining.clamp(20_000, ceiling);
        std::thread::Builder::new()
            .name("aether-selftest".into())
            .spawn(move || {
                let outcome = diagnostics::self_test(grace);
                *slot.lock() = Some(outcome);
            })
            .ok();
        self.set_state(ConnectionState::Verifying, "Verifying…");
    }

    /// The visible state is already Disconnecting (see [`request_toggle`]); this
    /// runs the slow teardown on the tick thread, off the UI's IPC path.
    fn disconnect(&mut self) {
        self.cleanup_native(false);
        // AETHER-APP-PATCH custom-configs: پروفایلِ کاربر برمی‌گردد.
        self.custom_end();
        // v16: تیک‌های سبز Diagnostics باید بلافاصله بعد از دیسکانکت
        // ریست شوند تا برای اتصال بعدی آماده باشند (معادل resetChecks اندروید).
        diagnostics::reset_checks();
        self.latency_probe_at = None;
        self.watchdog_probe_at = None;
        self.watchdog_failures = 0;
        *self.watchdog_slot.lock() = None;
        *self.latency_slot.lock() = None;
        self.connected_at = None;
        self.endpoint = None;
        // اندپوینتِ نشستِ قبل در نشستِ تازه هیچ معنایی ندارد.
        crate::firsthop::reset();
        self.latency_ms = None;
        self.effective_protocol = None;
        self.deadline = None;
        self.reconnect_at = None;
        self.verify_slot = None;
        self.chain_waiting = false;
        self.prep_slot = None;
        self.plan.clear();
        self.plan_index = 0;
        self.set_state(ConnectionState::Disconnected, "");
    }

    /// ترتیب ۱.۲.۲: اول پروکسی سیستمی (تا مرورگر به پل مُرده نچسبد)، بعد
    /// اشتراک، بعد تونل، بعد موتور — بدون فریز.
    fn cleanup_native(&mut self, preserve_kill_switch: bool) {
        crate::custom::ai_policy::clear();
        self.uplink=None;
        self.fresh_selection=None;self.fresh_basis=None;
        if let Some(s)=self.smart_plus.as_mut(){s.race=None;}
        if !preserve_kill_switch{self.smart_plus=None;}
        self.custom_trace("cleanup", if preserve_kill_switch {"reconnect/rung transition; preserve kill switch"} else {"final teardown"});
        {let mut ip=self.ip_slot.lock();ip.session+=1;ip.loading=false;}
        // An abandoned attempt must not keep probing through the next one.
        diagnostics::cancel_self_test();
        if self.sysproxy_on {
            sysproxy::disable();
            self.sysproxy_on = false;
        }
        // گارد بعد از پروکسی آزاد می‌شود: تا آخرین لحظه‌ای که مرورگر ممکن است
        // به پل وصل باشد، مسیر UDP هم بسته می‌ماند.
        if preserve_kill_switch {
            if let Some(g) = self.guard.as_mut() {
                g.release_for_reconnect();
            }
        } else if let Some(mut g) = self.guard.take() {
            g.release();
        }
        self.webrtc_leak = None;
        self.share.stop();
        crate::smart_routes::set_front(None);
        crate::smart_routes::set_guest_front(None);
        crate::smart_routes::set_front_udp_passthrough(false);
        // استیج ۲ بعد از پل و پیش از موتور می‌رود: همان ترتیب معکوسِ بالا آمدن.
        // اگر پیش از پل برود، پل برای چند صد میلی‌ثانیه به یک پروکسی مرده وصل
        // می‌ماند و مرورگر خطای واقعی می‌بیند.
        // خروجی به موتور برمی‌گردد، وگرنه پلهٔ بعدی نردبان (یا نشست بعدی) به
        // پورت استیج ۲ که دیگر وجود ندارد وصل می‌ماند.
        engine::reset_exit_socks_port();
        self.chain_exit_port = None;
        self.chain_waiting = false;
        // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // دو نیمهٔ نشستِ قبلی نباید به نشستِ بعدی برسد: موتوری که با
        // `AETHER_UPSTREAM` به توری وصل می‌ماند که دیگر نیست، همان «وصل شد
        // ولی هیچ چیز باز نمی‌شود» است، و مرحلهٔ معلقِ باقی‌مانده یعنی
        // منتظرِ توری ماندن که هرگز اجرا نمی‌شود.
        self.tor_stage = TorStage::None;
        self.engine.set_upstream_socks(None);
        // >>> AETHER-APP-PATCH tor-reverse-latch
        self.tor_front_ready = false;
        // <<< AETHER-APP-PATCH tor-reverse-latch
        // پنجرهٔ مدار مالِ یک نشست است و با آن بسته می‌شود.
        self.circuit_hunt_until = None;
        self.circuit_tries = 0;
        // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        if let Some(mut t) = self.tunnel.take() {
            t.close();
        }
        self.engine.stop();
        // AETHER-APP-PATCH custom-configs: Xrayِ این پله هم می‌رود (نشست می‌ماند).
        self.custom_stop_xray();
        // >>> AETHER-APP-PATCH tor-native-carrier
        // پس از موتور، چون در نشستِ زنجیره‌ای موتور جلوترِ تور است و ترتیبِ
        // معکوسِ بالاآمدن یعنی هرکس آخر آمد، اول برود.
        if let Some(tor) = self.native_tor.take() {
            tor.stop();
        }
        // <<< AETHER-APP-PATCH tor-native-carrier
        // >>> AETHER-APP-PATCH tor-aether-fast-path
        self.tor_relay = None;
        self.tor_reverse_respawns = 0;
        // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
        self.psiphon_gate_since = None;
        self.psiphon_next_probe = None;
        self.psiphon_probe = None;
        self.psiphon_port_latched = false;
        // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
        // <<< AETHER-APP-PATCH tor-aether-fast-path
    }

    // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
    /// `Tor → Psiphon` readiness, as mobile `PsiphonTransport.start` decides it:
    /// ready once the engine has printed `[+] psiphon is ready`, or once a real
    /// CONNECT to 1.1.1.1:80 through Psiphon succeeds (one probe every 4 s, 5 s
    /// timeout, off the tick thread). `Some(false)` after 200 s without either;
    /// `None` = keep waiting. Engine/tor death is caught by `carrier_alive`.
    fn psiphon_hop_ready(&mut self) -> Option<bool> {
        let since = *self.psiphon_gate_since.get_or_insert_with(Instant::now);
        let ready_by = if engine::psiphon_ready() {
            Some("the engine reported psiphon ready")
        } else if self
            .psiphon_probe
            .as_ref()
            .and_then(|slot| slot.lock().take())
            == Some(true)
        {
            Some("a CONNECT through psiphon reached 1.1.1.1:80")
        } else {
            None
        };
        if let Some(why) = ready_by {
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "Tor → Psiphon: Psiphon is ready after {:.1}s ({why}) — bringing up the data path.",
                    since.elapsed().as_secs_f32()
                ),
            );
            self.psiphon_gate_since = None;
            self.psiphon_probe = None;
            self.psiphon_next_probe = None;
            return Some(true);
        }
        if since.elapsed() >= PSIPHON_READY_TIMEOUT {
            return Some(false);
        }
        let probe_finished = self
            .psiphon_probe
            .as_ref()
            .map(|slot| slot.lock().is_some())
            .unwrap_or(true);
        if probe_finished
            && self
                .psiphon_next_probe
                .map(|at| Instant::now() >= at)
                .unwrap_or(true)
        {
            self.psiphon_next_probe = Some(Instant::now() + PSIPHON_PROBE_INTERVAL);
            let slot: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
            self.psiphon_probe = Some(slot.clone());
            let port = engine::LOCAL_SOCKS_PORT;
            std::thread::Builder::new()
                .name("aether-psiphon-probe".into())
                .spawn(move || {
                    let ok = probe::socks5_stream_on(port, "1.1.1.1", 80, PSIPHON_PROBE_TIMEOUT)
                        .is_some();
                    *slot.lock() = Some(ok);
                })
                .ok();
        }
        None
    }
    // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon

    /// شکست یک پله → پلهٔ بعدی نردبان؛ تمام‌شدن نردبان → Failed با پیام روشن.
    fn advance_or_fail(&mut self, why: &str) {
        if let Some(s)=self.smart_plus.as_mut(){s.failed(&self.data_dir);}
        self.custom_trace("advance_or_fail",why);
        DiagnosticsLog::w(TAG, &format!("{why} — tearing down this attempt."));
        // >>> AETHER-APP-FIX forget-a-gateway-that-failed-its-proof
        // Plain Aether only: chains share the cache files with the direct modes,
        // and their failures are usually the other hop's. Decided before the
        // teardown (`stop` clears `was_started`), done after it (the engine must
        // not be writing the file). See `AetherProcess::forget_cached_gateways`.
        let forget_gateway = self.engine.was_started()
            && self
                .plan
                .get(self.plan_index)
                .map(|c| c.profile.backend == crate::profile::TransportBackend::Aether)
                .unwrap_or(false);
        // <<< AETHER-APP-FIX forget-a-gateway-that-failed-its-proof
        // فقط موتور/مسیر داده را جمع می‌کنیم، وضعیت UI همچنان busy می‌ماند.
        self.cleanup_native(true);
        // >>> AETHER-APP-FIX forget-a-gateway-that-failed-its-proof
        if forget_gateway {
            self.engine.forget_cached_gateways();
        }
        // <<< AETHER-APP-FIX forget-a-gateway-that-failed-its-proof
        self.verify_slot = None;
        diagnostics::reset_checks();
        if self.smart_plus.is_some(){if let Err(e)=self.smart_plus_next(){self.fail(&e.to_string());}return;}
        self.plan_index += 1;
        if self.plan_index < self.plan.len() {
            // The next rung also has to wait for the local port, so it goes back
            // through the off-lock prep instead of blocking the tick for 3s.
            self.set_state(ConnectionState::StartingEngine, "Starting engine…");
            self.begin_prep(Prep::Candidate);
        } else if let Some(chain) = self.custom_chain_label() {
            // AETHER-APP-PATCH custom-configs
            self.fail(&format!("{chain} could not be established: {why}"));
        } else if self.profile.backend == crate::profile::TransportBackend::TorPsiphon {
            self.fail(&format!("Tor → Psiphon could not be established: {why}"));
        } else if self.profile.protocol == Protocol::Smart {
            self.fail(
                "Smart Auto tried every strategy and none passed the self-test on this network.",
            );
        } else {
            self.fail(
                "This protocol could not establish a working tunnel on this network, even with anti-DPI hardening. Try Smart Auto or another protocol.",
            );
        }
    }

    fn apply_pending_security_refresh(&mut self) {
        if !self.security_refresh_pending {
            return;
        }
        self.security_refresh_pending = false;
        if self.profile.leak_guard || self.profile.kill_switch || self.profile.ipv6_protection {
            if let Some(mut old_guard) = self.guard.take() {
                old_guard.disarm_without_cleanup();
            }
            self.guard = Some(LeakGuard::engage(&self.profile));
        } else if let Some(mut guard) = self.guard.take() {
            guard.release();
        }
    }

    /// هر ۲۰۰ms از main.rs صدا زده می‌شود — معادل حلقهٔ نظارت اندروید.
    pub fn tick(&mut self) {
        // The last tap first. Both branches are slow, and both are why this runs
        // here instead of inside the IPC command. See [`Intent`].
        if let Some(intent) = self.pending_intent.take() {
            match intent {
                Intent::Connect => {
                    if let Err(e) = self.connect() {
                        let msg = e.to_string();
                        self.fail(&msg);
                    }
                }
                Intent::Disconnect => self.disconnect(),
            }
            return;
        }

        // ۱.۵.۰: کارت‌های شبکه برای اشتراک LAN (خودش هر ۳ ثانیه یک بار).
        self.share.refresh_lan();

        // >>> AETHER-APP-PATCH zt-login-code-prompt
        // «حالا نه» در دیالوگِ کدِ ورود: اتصال همین حالا متوقف می‌شود، نه
        // بعد از ۳۰۰ ثانیه انتظارِ هسته. (همین مسیر وقتی Cloudflare فقط از راهِ
        // پروکسیِ بالادستی در دسترس است هم صدق می‌کند.)
        if crate::login_code::take_abandon() && self.state.is_active() {
            DiagnosticsLog::w(
                TAG,
                "Zero Trust: no login code was given (Not now); stopping the connection.",
            );
            self.disconnect();
            self.error = Some(
                "Zero Trust sign-in was cancelled, so the connection was stopped. Sign in under Settings → Zero Trust, or connect again when you have the code."
                    .to_string(),
            );
            return;
        }
        // تا وقتی هسته منتظرِ کد است، بودجهٔ اتصال نباید موتور را بکُشد: کاربر
        // دارد ایمیلش را می‌خواند. هسته خودش بعد از ۳۰۰ ثانیه منصرف می‌شود.
        if crate::login_code::pending().is_some() {
            let floor = Instant::now() + Duration::from_secs(20);
            if self.deadline.is_some_and(|d| d < floor) {
                self.deadline = Some(floor);
            }
        }
        // <<< AETHER-APP-PATCH zt-login-code-prompt

        self.apply_pending_security_refresh();

        match self.state {
            // Waiting for the off-lock prep thread (port release + fingerprint).
            ConnectionState::StartingEngine => {
                if let Some(task)=self.fresh_selection.as_mut(){
                    let Some(rows)=task.poll()else{return;};self.fresh_selection=None;
                    let current=crate::custom::store::snapshot();let unchanged=self.fresh_basis.take().as_ref()==Some(&current);
                    let result=if unchanged{crate::custom::selection::record(&rows);if let Some(id)=crate::custom::selection::cached_choice(&current){crate::custom::store::update(|s|s.select(&id));}self.connect_after_selection()}else{self.connect()};
                    if let Err(e)=result{self.fail(&e.to_string());}return;
                }
                let outcome = self.prep_slot.as_ref().and_then(|s| s.lock().take());
                if let Some(outcome) = outcome {
                    self.prep_slot = None;
                    if let Some(reason) = outcome.blocked {
                        // Every rung would bind the same port: retrying is futile.
                        self.fail(&reason);
                        return;
                    }
                    // AETHER-APP-PATCH custom-configs: نشستِ سفارشی پله را خودش
                    // اجرا می‌کند (Xray جلوتر، یا سایفونِ خالص)؛ بقیه مثل قبل.
                    let result = if self.custom.is_some() {
                        self.custom_launch(self.prep_kind, outcome.fingerprint)
                    } else {
                        match self.prep_kind {
                            Prep::Plan => self.launch_plan(outcome.fingerprint),
                            Prep::Candidate => self.launch_candidate(),
                        }
                    };
                    if let Err(e) = result {
                        let msg = e.to_string();
                        self.fail(&msg);
                    }
                }
            }
            ConnectionState::Connecting => {
                if self.smart_plus_poll(){return;}
                // AETHER-APP-PATCH custom-configs: فازهای Xray (جلو/پشت).
                if self.custom_poll() {
                    return;
                }
                // >>> AETHER-APP-PATCH tor-native-carrier
                if !self.carrier_alive() {
                    // >>> AETHER-APP-PATCH tor-aether-fast-path
                    if self.respawn_engine_behind_tor() {
                        return;
                    }
                    // <<< AETHER-APP-PATCH tor-aether-fast-path
                    // در «تور تنها» هیچ موتوری اجرا نشده، پس گفتنِ «Engine exited»
                    // عیب‌یاب را دنبالِ موتوری می‌فرستاد که وجود ندارد: در لاگِ
                    // ۱۷ سپتامبر همین سطر کنارِ خطای واقعیِ تور نشسته بود و
                    // خواننده را به موتور مشکوک می‌کرد.
                    let carrier = if self.engine.was_started() && !self.engine.is_alive() {
                        "Engine exited before it opened the SOCKS5 port"
                    } else if self.native_tor.is_some() {
                        "tor exited before it opened the SOCKS5 port"
                    } else {
                        "Engine exited before it opened the SOCKS5 port"
                    };
                    self.advance_or_fail(carrier);
                    return;
                }
                // <<< AETHER-APP-PATCH tor-native-carrier
                // >>> AETHER-APP-FIX tor-fresh-circuit-for-the-engine
                // «تور → اتر»: موتور گفت درخواستش از راهِ تور بی‌جواب ماند (ثبت‌نامِ
                // WARP یا اسکنِ MASQUE). مدارِ وصل‌شده‌ای که خروجی‌اش داده را خفه
                // می‌کند هرگز خودبه‌خود عوض نمی‌شود — تور فقط مدارِ *وصل‌نشده* را
                // کنار می‌گذارد — پس تلاشِ بعدیِ موتور روی همان مدار می‌افتاد. حالا
                // یک NEWNYM تلاشِ بعدی را روی مدارِ تازه می‌برد.
                if self.tor_front_ready && crate::tor_native::take_fresh_circuit_request() {
                    if let Some(tor) = self.native_tor.as_ref() {
                        match tor.new_circuit(Duration::from_secs(3)) {
                            Ok(()) => DiagnosticsLog::i(
                                TAG,
                                "Tor → Aether: the engine's request through tor went unanswered; \
                                 tor now puts its next ones on fresh circuits (NEWNYM).",
                            ),
                            Err(e) => DiagnosticsLog::w(
                                TAG,
                                &format!(
                                    "Tor → Aether: NEWNYM after an unanswered request failed: {e}"
                                ),
                            ),
                        }
                    }
                }
                // <<< AETHER-APP-FIX tor-fresh-circuit-for-the-engine
                // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
                // یک نشستِ توریِ دونیمه، پیش از هر چیزِ دیگر: تا نیمهٔ دوم اجرا
                // نشده، پورتِ همیشگی (۱۸۱۹) مالِ هیچ‌کس نیست و منتظرِ آن ماندن
                // یعنی انتظارِ چیزی که قرار نیست بیاید.
                match self.tor_stage {
                    TorStage::TorThenPsiphon => {
                        match self.tor_gate() {
                            TorGate::Ready => {
                                if let Err(e) = self.start_psiphon_behind_tor() {
                                    self.advance_or_fail(&e.to_string());
                                }
                            }
                            TorGate::Waiting if self.past_deadline() => {
                                let msg = diagnostics::stage_failure_message(self.tor_shape());
                                self.advance_or_fail(&msg);
                            }
                            TorGate::Stalled => {
                                let msg = diagnostics::stage_failure_message(self.tor_shape());
                                self.advance_or_fail(&msg);
                            }
                            TorGate::Waiting => {}
                        }
                        return;
                    }
                    TorStage::TorThenEngine => {
                        match self.tor_gate() {
                            TorGate::Ready => {
                                if let Err(e) = self.start_engine_behind_tor() {
                                    let msg = e.to_string();
                                    self.advance_or_fail(&msg);
                                }
                            }
                            TorGate::Waiting => {
                                if self.past_deadline() {
                                    let msg = diagnostics::stage_failure_message(self.tor_shape());
                                    DiagnosticsLog::e(
                                        TAG,
                                        &format!(
                                            "Tor did not finish within its budget ({}).",
                                            tor_bootstrap::describe()
                                        ),
                                    );
                                    self.advance_or_fail(&msg);
                                }
                            }
                            TorGate::Stalled => {
                                let msg = diagnostics::stage_failure_message(self.tor_shape());
                                DiagnosticsLog::e(
                                    TAG,
                                    &format!(
                                        "Tor stopped making progress for {}s ({}).",
                                        self.tor_stall_ms() / 1_000,
                                        tor_bootstrap::describe()
                                    ),
                                );
                                self.advance_or_fail(&msg);
                            }
                        }
                        return;
                    }
                    TorStage::EngineThenTor => {
                        if probe::socks_ready(engine::LOCAL_SOCKS_PORT) {
                            if let Some(reason) =
                                crate::procguard::stranger_on(engine::LOCAL_SOCKS_PORT)
                            {
                                self.fail(&reason);
                                return;
                            }
                            self.tor_stage = TorStage::None;
                            if let Err(e) = self.start_tor_behind_engine() {
                                let msg = e.to_string();
                                self.advance_or_fail(&msg);
                            }
                        } else if self.past_deadline() {
                            self.advance_or_fail(
                                "Engine still scanning — the SOCKS5 port never opened in time",
                            );
                        }
                        return;
                    }
                    TorStage::None => {}
                }
                // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
                // یک زنجیرهٔ در حال بالا آمدن، فاز خودش را دارد: استیج ۱ آماده
                // است و استیج ۲ در ترد پس‌زمینه برقرار می‌شود.
                if self.chain_waiting {
                    self.poll_chain();
                    return;
                }
                // >>> AETHER-APP-FIX psiphon-port-latch
                // `Psiphon → Config` / `Tor → Psiphon`: پورتِ ۱۸۱۹ لیسنرِ خودِ
                // psiphon-tunnel-core است. هر تیک (۲۰۰ms) یک connect/close روی آن
                // باز می‌کرد و سایفون هر بار «SOCKS proxy accept error:
                // socksPeekByte() failed: EOF» می‌نوشت — ۵ خط در ثانیه در لاگ،
                // پارس و رندرِ بی‌فایده. یک بار باز دیده شد، تا پایانِ تلاش باز
                // حساب می‌شود؛ مرگِ موتور بالاتر با `is_alive` گرفته می‌شود.
                let psiphon_gate = self.psiphon_exit_session();
                let port_up = if psiphon_gate && self.psiphon_port_latched {
                    true
                } else {
                    let up = probe::socks_ready(engine::LOCAL_SOCKS_PORT);
                    if up && psiphon_gate {
                        self.psiphon_port_latched = true;
                    }
                    up
                };
                // <<< AETHER-APP-FIX psiphon-port-latch
                if port_up {
                    // ۱.۲.۵ — روی حالت‌های تور، پورتِ باز هنوز چیزی را اثبات
                    // نمی‌کند: bootstrap باید تمام شده باشد.
                    match self.tor_gate() {
                        TorGate::Waiting => {
                            // همچنان منتظر، و همچنان در حرکت. تنها چیزی که
                            // این انتظار را پایان می‌دهد گیرکردنِ درصد است یا
                            // مردنِ موتور — هر دو بالاتر بررسی می‌شوند.
                            if self.past_deadline() {
                                let msg = diagnostics::stage_failure_message(self.tor_shape());
                                DiagnosticsLog::e(
                                    TAG,
                                    &format!(
                                        "Tor did not finish within its budget ({}).",
                                        tor_bootstrap::describe()
                                    ),
                                );
                                self.advance_or_fail(&msg);
                            }
                            return;
                        }
                        TorGate::Stalled => {
                            let msg = diagnostics::stage_failure_message(self.tor_shape());
                            DiagnosticsLog::e(
                                TAG,
                                &format!(
                                    "Tor stopped making progress for {}s ({}). Abandoning this \
                                     attempt instead of waiting out the whole budget.",
                                    self.tor_stall_ms() / 1_000,
                                    tor_bootstrap::describe()
                                ),
                            );
                            self.advance_or_fail(&msg);
                            return;
                        }
                        TorGate::Ready => {}
                    }
                    // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
                    // 127.0.0.1:1819 is psiphon-tunnel-core's own listener: it
                    // answers the SOCKS5 handshake seconds after the engine
                    // starts, long before Psiphon has a server. Field log
                    // 2026-10-08 (Tor → Psiphon, run 2): the data path and the
                    // self-test started on that open port, the probes went out
                    // before Psiphon was up, and the session was failed
                    // ("self-test failed") although Psiphon became ready later.
                    // Mobile (`PsiphonTransport.start`) waits for exactly this.
                    if self.psiphon_exit_session() {
                        match self.psiphon_hop_ready() {
                            Some(true) => {}
                            Some(false) => {
                                self.advance_or_fail(&format!(
                                    "Psiphon found no usable server through Tor within {}s",
                                    PSIPHON_READY_TIMEOUT.as_secs()
                                ));
                                return;
                            }
                            None => return,
                        }
                    }
                    // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
                    if self.profile.is_chained() && !self.psiphon_exit_session() {
                        self.begin_chain();
                    } else {
                        // ۱.۲.۵ — خروجی خط لوله همیشه پورت همیشگی نیست. هر چیزی
                        // که مسیر داده را می‌سازد (پل محلی، Wintun، خودآزما،
                        // پروبِ IP) از `engine::exit_socks_port` می‌پرسد، پس
                        // همین یک جا ست کردن کافی است.
                        let exit = self.data_path_exit_port();
                        if exit != engine::exit_socks_port() {
                            engine::set_exit_socks_port(exit);
                            DiagnosticsLog::i(
                                TAG,
                                &format!(
                                    "Pipeline exit is 127.0.0.1:{exit} ({}).",
                                    self.profile.backend.pipeline_label()
                                ),
                            );
                        }
                        // 1.3.0 port-guard: a port that answers is not proof that
                        // *our* engine answers. In the 2026-10-08 log a leftover
                        // listener passed the SOCKS5 handshake 4ms after spawn
                        // while the real engine had already died with 10048.
                        if let Some(reason) =
                            crate::procguard::stranger_on(engine::LOCAL_SOCKS_PORT)
                        {
                            self.fail(&reason);
                            return;
                        }
                        // AETHER-APP-PATCH custom-configs: `… → Config` — Xray از دلِ
                        // همین خروجی؛ مسیرِ داده پس از آمدنِ پورتِ آن.
                        if self.custom_hold_for_last(exit) {
                            return;
                        }
                        DiagnosticsLog::i(TAG, "SOCKS5 port is up — bringing up the data path.");
                        if !self.bring_up_data_path() {
                            return;
                        }
                        self.begin_verification();
                    }
                } else if self.past_deadline() {
                    self.advance_or_fail(
                        "Engine still scanning — the SOCKS5 port never opened in time",
                    );
                }
            }
            ConnectionState::Verifying => {
                let outcome = self.verify_slot.as_ref().and_then(|s| s.lock().take());
                if let Some(out) = outcome {
                    self.verify_slot = None;
                    if out.ok {
                        if let Some(exit) = &out.exit {
                            // >>> AETHER-APP-PATCH endpoint-is-the-first-hop
                            // ردیفِ Endpoint نشانیِ هاپِ اول است، نه تکرارِ ردیفِ
                            // بالایی. تا وقتی هاپِ اول ثابت نشده، رفتارِ قبلی می‌ماند —
                            // چیزی جایِ اندپوینت جعل نمی‌شود.
                            self.endpoint = crate::firsthop::get().or_else(|| {
                                Some(match &exit.country_code {
                                    Some(cc) => format!("{} · {cc}", exit.ip),
                                    None => exit.ip.clone(),
                                })
                            });
                            // <<< AETHER-APP-PATCH endpoint-is-the-first-hop
                            // IP خروجی از خودآزما مستقیماً به نشان IP می‌رود —
                            // معادل offerTunnelIpInfo در Diagnostics.kt.
                            let mut g = self.ip_slot.lock();
                            g.session += 1;
                            g.info = Some(IpEndpoint {
                                ip: exit.ip.clone(),
                                country_code: exit.country_code.clone(),
                                via_tunnel: true,
                                alternate_ip: exit.alternate_ip.clone(),
                            });
                            g.loading = false;
                        }
                        // v1.2.0: نتیجهٔ سنجش نشتی مستقیم به نشانِ صفحهٔ اصلی می‌رود.
                        self.webrtc_leak = out.leak.as_ref().map(|l| l.leaking);
                        if self.webrtc_leak == Some(true) {
                            DiagnosticsLog::w(
                                TAG,
                                "Tunnel is up but WebRTC still reached a STUN server directly. Restart the browser so the WebRTC policy applies, or run Aether as administrator for the firewall layer.",
                            );
                        }
                        // `out.latency_ms` is how long the self-test's own HTTP
                        // fetch took, on a brand new dial, in the busiest second
                        // of the session. Through a chained pipeline that reads
                        // as 1600-3000 ms on a path that is actually fine, and it
                        // then sat frozen on screen — the reported bug. The badge
                        // now waits for the first real warm round trip instead of
                        // opening with a number nobody can reproduce.
                        if let Some(setup) = out.latency_ms {
                            DiagnosticsLog::i(
                                TAG,
                                &format!(
                                    "Self-test egress fetch took {setup} ms (dial + TLS + HTTP during \
                                     connect). Not shown as latency; the badge uses a warm round trip."
                                ),
                            );
                        }
                        self.latency_ms = None;
                        // A fresh pipeline needs a fresh probe session, and the
                        // first measurement should land immediately, not in 10s.
                        ping::reset();
                        self.latency_probe_at = None;
                        *self.latency_slot.lock() = None;
                        self.watchdog_probe_at =
                            Some(Instant::now() + Duration::from_secs(WATCHDOG_INTERVAL_SECS));
                        self.watchdog_failures = 0;
                        self.connected_at = Some(Instant::now());
                        self.attempts = 0;
                        // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                        // پنجرهٔ مدار فقط در همین لحظه باز می‌شود — رجوع به
                        // [`Self::consider_new_circuit`].
                        self.circuit_tries = 0;
                        self.circuit_hunt_until = self
                            .native_tor
                            .is_some()
                            .then(|| Instant::now() + CIRCUIT_HUNT_WINDOW);
                        // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                        if let Some(s)=self.smart_plus.as_mut(){s.succeeded(&self.data_dir,self.profile.verify_connection);}
                        self.smart_plus=None;
                        self.set_state(ConnectionState::Connected, "");
                        // ۱.۴.۰ — به‌روزرسانیِ هفتگیِ فهرست‌ها، از داخلِ همین تونل، روی ترد پس‌زمینه.
                        crate::smart_lists::refresh_if_due(
                            &self.data_dir,
                            &self.profile,
                            engine::exit_socks_port(),
                        );
                        DiagnosticsLog::i(TAG, if (self.custom.is_some() && self.profile.custom_verify_connection) || (self.custom.is_none() && self.profile.verify_connection) {"All checks passed — tunnel is ready."} else {"Initial verification skipped — data path is up; health monitoring continues."});
                        // Refresh even when verification supplied an IP: prefer IPv4 and enrich missing country.
                        spawn_ip_lookup(self.ip_slot.clone(), true);
                    } else if out.leak.as_ref().map(|l| l.leaking).unwrap_or(false) {
                        // Fail closed. A tunnel that exposes the real IP is not
                        // a successful connection, even when TCP/DNS passed.
                        self.fail(
                            "Connection refused: WebRTC can still reach the real IP over direct UDP. Browser and system protection could not be verified.",
                        );
                    } else {
                        self.advance_or_fail("Tunnel started, but the end-to-end self-test failed");
                    }
                // >>> AETHER-APP-PATCH tor-native-carrier
                } else if !self.carrier_alive() {
                    self.advance_or_fail("The engine stopped during verification");
                    // <<< AETHER-APP-PATCH tor-native-carrier
                }
            }
            ConnectionState::Connected => {
                // v1.2.0 watchdog: every 30s run three end-to-end probes in a
                // worker thread. Three consecutive failed rounds are required
                // before restarting, so short network jitter is tolerated.
                let watchdog_result = { self.watchdog_slot.lock().take() };
                if let Some(result) = watchdog_result {
                    if result {
                        self.watchdog_failures = 0;
                        DiagnosticsLog::i(TAG, "Watchdog probe passed (at least 2 of 3 targets reachable through SOCKS5).");
                    } else {
                        self.watchdog_failures = self.watchdog_failures.saturating_add(1);
                        DiagnosticsLog::w(
                            TAG,
                            &format!(
                                "Watchdog probe failed ({}/{})",
                                self.watchdog_failures, WATCHDOG_FAILURE_THRESHOLD
                            ),
                        );
                        if self.watchdog_failures >= WATCHDOG_FAILURE_THRESHOLD {
                            DiagnosticsLog::e(TAG, "Watchdog confirmed a persistent upstream failure — restarting the engine.");
                            self.cleanup_native(true);
                            self.watchdog_failures = 0;
                            self.connected_at = None;
                            self.reconnect_at = Some(Instant::now() + Duration::from_secs(2));
                            self.set_state(ConnectionState::Reconnecting, "Watchdog reconnect…");
                            return;
                        }
                    }
                }
                let watchdog_due = self
                    .watchdog_probe_at
                    .map(|t| Instant::now() >= t)
                    .unwrap_or(true);
                let watchdog_busy = { self.watchdog_slot.lock().is_some() };
                if watchdog_due && !watchdog_busy {
                    self.watchdog_probe_at =
                        Some(Instant::now() + Duration::from_secs(WATCHDOG_INTERVAL_SECS));
                    let slot = self.watchdog_slot.clone();
                    std::thread::Builder::new()
                        .name("aether-watchdog".into())
                        .spawn(move || {
                            let ok = probe::watchdog_probe();
                            *slot.lock() = Some(ok);
                        })
                        .ok();
                }

                // v16: پینگ نمایشی قبلاً فقط یک‌بار هنگام خودآزمای اتصال اندازه
                // گرفته می‌شد (شامل زمان دریافت HTTP در شلوغی لحظهٔ اتصال)
                // و دیگر به‌روز نمی‌شد — برای همین عددی مثل ۸۰۰۰ms می‌ماند.
                // حالا هر ۱۵ ثانیه یک اتصال TCP سبک از داخل تونل زمان‌گیری
                // می‌شود تا پینگ واقعی و زنده نمایش داده شود (بدون فریز UI).
                // قرضِ قفل پیش از تصمیم بسته می‌شود: `consider_new_circuit`
                // خودش به همان اسلات دست می‌زند.
                let fresh = self.latency_slot.lock().take();
                if let Some(ms) = fresh {
                    self.latency_ms = Some(ms);
                    // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                    self.consider_new_circuit(ms);
                    // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                }
                let latency_due = self
                    .latency_probe_at
                    .map(|t| Instant::now() >= t)
                    .unwrap_or(true);
                if latency_due {
                    self.latency_probe_at =
                        Some(Instant::now() + Duration::from_secs(LATENCY_INTERVAL_SECS));
                    let slot = self.latency_slot.clone();
                    std::thread::Builder::new()
                        .name("aether-latency".into())
                        .spawn(move || {
                            // One keep-alive round trip on a warm session — no
                            // dial, no SSH channel open. See [`crate::ping`].
                            if let Some(ms) = ping::measure() {
                                *slot.lock() = Some(ms);
                            }
                        })
                        .ok();
                }
                // The core owns and retries its Psiphon child. The desktop's
                // normal end-to-end watchdog still verifies the finished route.
                // AETHER-APP-PATCH custom-configs: پایشِ Xray (راه‌اندازیِ دوبارهٔ درجا).
                if self.custom_monitor() {
                    return;
                }
                // >>> AETHER-APP-PATCH tor-native-carrier
                if !self.carrier_alive() {
                    // <<< AETHER-APP-PATCH tor-native-carrier
                    // معادل superviseEngine: بک‌آف پلکانی ۲/۵/۱۰ ثانیه، حداکثر ۳ تلاش.
                    let max_retries = self.profile.reconnect_attempts.max(DEFAULT_MAX_RETRIES);
                    if self.attempts >= max_retries {
                        self.fail("The engine keeps dying — giving up after repeated restarts.");
                        return;
                    }
                    let backoff = BACKOFF_MS[(self.attempts as usize).min(BACKOFF_MS.len() - 1)];
                    self.attempts += 1;
                    self.connected_at = None;
                    self.reconnect_at = Some(Instant::now() + Duration::from_millis(backoff));
                    DiagnosticsLog::w(
                        TAG,
                        &format!(
                            "Engine died while connected — restarting in {}s.",
                            backoff / 1000
                        ),
                    );
                    let detail = format!("Attempt {} of {}", self.attempts, max_retries);
                    self.set_state(ConnectionState::Reconnecting, &detail);
                }
            }
            ConnectionState::Reconnecting => {
                if let Some(at) = self.reconnect_at {
                    if Instant::now() >= at {
                        self.reconnect_at = None;
                        self.cleanup_native(true);
                        // همان پلهٔ برنده دوباره اجرا می‌شود — معادل restart در
                        // superviseEngine. The fingerprint and the port wait go
                        // to the prep thread, so a reconnect no longer freezes
                        // the UI for several seconds either.
                        let mut kind = if self.plan.is_empty() {
                            Prep::Plan
                        } else {
                            Prep::Candidate
                        };
                        // ۱.۴.۰: اگر نشستِ سفارشی/زنجیره فعال بود ولی در مسیرِ
                        // reconnect (سوییچِ خودکار، watchdog، مرگِ موتور) بسته
                        // شده، خطِ لولهٔ سفارشی از نو برپا می‌شود — با همان
                        // پورت‌های مجزا (tor.exe روی 1820، موتور روی 1819، استیجِ
                        // زنجیره روی 1825). پیش از این، نشست به «اترِ تک‌کانفیگ»
                        // (پروفایلِ پیش‌فرض) ریست می‌شد و زنجیره از بین می‌رفت.
                        let custom_selected = crate::custom::store::selection().is_some();
                        if custom_selected && self.custom.is_none() {
                            if let Err(e) = self.custom_begin() {
                                self.fail(&e.to_string());
                                return;
                            }
                            self.plan.clear();
                            kind = Prep::Plan;
                        }
                        if let Some(label) = self.custom_chain_label() {
                            DiagnosticsLog::i(
                                TAG,
                                &format!(
                                    "Reconnect keeps the custom pipeline «{label}» — tor.exe stays on 127.0.0.1:{}, the engine on 127.0.0.1:{}, the chain stage on 127.0.0.1:{}.",
                                    engine::TOR_SOCKS_PORT, engine::LOCAL_SOCKS_PORT, engine::CHAIN_SOCKS_PORT
                                ),
                            );
                        }
                        self.set_state(ConnectionState::StartingEngine, "Reconnecting…");
                        self.begin_prep(kind);
                    }
                }
            }
            _ => {}
        }
    }

    fn past_deadline(&self) -> bool {
        self.deadline.map(|d| Instant::now() > d).unwrap_or(false)
    }

    fn fail(&mut self, why: &str) {
        self.custom_trace("fail",why);
        DiagnosticsLog::e(TAG, why);
        self.cleanup_native(true);
        // AETHER-APP-PATCH custom-configs: پروفایلِ کاربر برمی‌گردد.
        self.custom_end();
        self.error = Some(why.to_string());
        self.connected_at = None;
        self.deadline = None;
        self.reconnect_at = None;
        self.verify_slot = None;
        self.prep_slot = None;
        self.pending_intent = None;
        self.latency_ms = None;
        ping::reset();
        self.set_state(ConnectionState::Failed, "Connection failed");
    }

    fn set_state(&mut self, state: ConnectionState, detail: &str) {
        if state==ConnectionState::Connected{crate::custom::ai_policy::note(self.custom.as_ref().map(|r|r.sel.mode),engine::exit_socks_port());}else{crate::custom::ai_policy::clear();}
        let prev = self.state;
        // >>> AETHER-APP-FIX no-duplicate-status-events
        // این متد از دلِ حلقهٔ tick صدا زده می‌شود و پیش از این هر بار — یعنی
        // هر ۲۰۰ms — یک خط لاگ می‌نوشت و یک snapshot به UI می‌داد، حتی وقتی
        // نه وضعیت عوض شده بود و نه متن. در لاگ ۲۰۲۶-۰۹-۱۶ نتیجه‌اش ~۳۷۵ بار
        // «Reaching the Tor network… 15%» در ۷۵ ثانیه است: همان یک جمله، که
        // هر بارش یک نوشتنِ دیسک، یک عبور از IPC و یک رندر در WebView است.
        // آن کار هیچ‌چیز به کاربر نمی‌گوید و مستقیم روی CPU می‌نشیند.
        //
        // تغییرِ واقعی هنوز فوراً دیده می‌شود؛ فقط تکرارِ بی‌خبر حذف شده است.
        let unchanged = prev == state && self.detail == detail;
        self.state = state;
        self.detail = detail.to_string();
        if unchanged {
            return;
        }
        DiagnosticsLog::i(TAG, &format!("{state:?} {detail}"));
        // <<< AETHER-APP-FIX no-duplicate-status-events
        if prev != state {
            self.on_phase_change(state);
        }
    }

    /// معادل LaunchedEffect فازهای IP در MainActivity.kt:
    ///   connected → IP سرور از دل تونل — idle/failed → IP واقعی کاربر — busy → خالی.
    fn on_phase_change(&mut self, state: ConnectionState) {
        match state {
            ConnectionState::Connected => { /* خودآزما قبلاً IP را تحویل داده است */
            }
            ConnectionState::Disconnected | ConnectionState::Failed => {
                spawn_ip_lookup(self.ip_slot.clone(), false);
            }
            _ => {
                let mut g = self.ip_slot.lock();
                g.session += 1;
                g.info = None;
                g.loading = false;
            }
        }
    }

    // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
    /// اگر این خواندنِ تأخیر روی مقیاسِ تور «ضعیف» است، یک مدارِ تازه می‌خواهد.
    ///
    /// پنجره کوتاه و شمارش محدود است، و هر دو عدد دلیل دارند:
    ///
    /// * تنها در نشستی که تور در آن هست. روی خطِ لولهٔ معمولی مدار وجود ندارد
    ///   و چیزی هم برای عوض‌کردن نیست.
    /// * تنها در ~۲۰ ثانیهٔ اولِ اتصال. کاربری که ده دقیقه است وصل است و در
    ///   حالِ بارگیری، نباید مدارش را زیرِ پایش عوض کنیم چون یک نمونه بد شد.
    /// * حداکثر سه بار. `NEWNYM` مجانی نیست (ساختِ مدارِ تازه چند ثانیه) و
    ///   شبکه‌ای که هر سه مدارش کند است، با مدارِ چهارم هم کند می‌ماند.
    /// * و به‌محضِ رسیدن به عددِ قابل‌قبول، پنجره بسته می‌شود.
    fn consider_new_circuit(&mut self, ms: u64) {
        // همان آستانهٔ «ضعیف» در مقیاسِ توریِ UI (`PING_BANDS_TOR.fair` در
        // `connectioncard.js`). یک عدد در دو جا بد است، ولی بدتر آن است که
        // برنامه بر پایهٔ آستانه‌ای تصمیم بگیرد که با آنچه کاربر می‌بیند یکی
        // نباشد — پس همان عدد، با ارجاعِ صریح.
        const POOR_MS: u64 = 800;
        const MAX_ROTATIONS: u8 = 3;
        /// فرصت به تور برای ساختِ مدارِ تازه، پیش از اندازه‌گیریِ بعدی.
        const SETTLE: Duration = Duration::from_secs(3);

        if self.native_tor.is_none() || !self.tor_fronted() {
            return;
        }
        let Some(until) = self.circuit_hunt_until else {
            return;
        };
        if Instant::now() >= until {
            self.circuit_hunt_until = None;
            return;
        }
        if ms <= POOR_MS {
            DiagnosticsLog::i(
                TAG,
                &format!("Tor circuit is good enough at {ms} ms — keeping it."),
            );
            self.circuit_hunt_until = None;
            return;
        }
        if self.circuit_tries >= MAX_ROTATIONS {
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "Still {ms} ms after {} new circuits — this is the network, not the circuit; \
                     keeping the current one.",
                    self.circuit_tries
                ),
            );
            self.circuit_hunt_until = None;
            return;
        }

        let Some(tor) = self.native_tor.clone() else {
            return;
        };
        self.circuit_tries += 1;
        match tor.new_circuit(Duration::from_secs(5)) {
            Ok(()) => {
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "{ms} ms is poor for Tor — asked tor for a new circuit \
                         (attempt {}/{MAX_ROTATIONS}).",
                        self.circuit_tries
                    ),
                );
                // نشستِ گرمِ پینگ روی مدارِ قدیم است و باید بیفتد، وگرنه
                // اندازه‌گیریِ بعدی همان مدار را می‌سنجد.
                ping::reset();
                self.latency_ms = None;
                *self.latency_slot.lock() = None;
                self.latency_probe_at = Some(Instant::now() + SETTLE);
                // مدارِ تازه یعنی خروجیِ تازه: هم نشانی، هم پرچم، هم اولین هاپ.
                crate::firsthop::reset();
                spawn_ip_lookup(self.ip_slot.clone(), true);
            }
            Err(error) => {
                // شکستِ NEWNYM نشست را نمی‌کُشد: مدارِ فعلی کار می‌کند و فقط
                // کند است. یک سطرِ لاگ، و پنجره بسته می‌شود.
                DiagnosticsLog::w(
                    TAG,
                    &format!("Could not ask tor for a new circuit: {error}"),
                );
                self.circuit_hunt_until = None;
            }
        }
    }
    // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network

    /// ۱.۴.۰ — پوشه‌هایی که هویتِ تیمِ Zero Trust ممکن است در آن‌ها باشد.
    pub fn identity_dirs(&self) -> Vec<PathBuf> {
        vec![self.engine.run_dir(), self.data_dir.clone()]
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

impl Drop for AetherController {
    fn drop(&mut self) {
        // خروج برنامه هرگز نباید پروکسی سیستمی را فعال رها کند.
        self.cleanup_native(false);
    }
}

/// جست‌وجوی IP در ترد پس‌زمینه — همان تعداد تلاش/تأخیرهای NetProbe اندروید:
/// مستقیم ۶×۲۰۰۰ms، از دل تونل ۱۲×۱۰۰۰ms.
fn spawn_ip_lookup(slot: Arc<Mutex<IpSlot>>, via_tunnel: bool) {
    let session = {
        let mut g = slot.lock();
        g.session += 1;
        g.loading = true;
        if !via_tunnel {
            g.info = None;
        }
        g.session
    };
    let port=engine::exit_socks_port();
    std::thread::Builder::new()
        .name("aether-ipinfo".into())
        .spawn(move || {
            if via_tunnel {
                for _ in 0..12 {
                    if slot.lock().session!=session {return;}
                    let mut published_ip:Option<String>=None;
                    let result=probe::fetch_ip_via_socks_enriched(6_000,port,|i| {
                        let mut g=slot.lock();
                        if g.session!=session {return;}
                        // Once this lookup published an IP, enrichment may only update that IP.
                        if published_ip.as_ref().map(|ip|ip!=&i.ip).unwrap_or(false) {return;}
                        published_ip=Some(i.ip.clone());
                        g.info=Some(IpEndpoint{ip:i.ip.clone(),country_code:i.country_code.clone(),via_tunnel:true,alternate_ip:i.alternate_ip.clone()});g.loading=false;
                    });
                    if result.is_some(){return;}
                    std::thread::sleep(Duration::from_secs(1));
                }
                let mut g=slot.lock();if g.session==session {g.loading=false;}return;
            }
            let result=probe::fetch_ip_direct_retry(6,2_000,6_000);
            let mut g=slot.lock();if g.session!=session {return;}
            g.info=result.map(|i|IpEndpoint{ip:i.ip,country_code:i.country_code,via_tunnel:false,alternate_ip:i.alternate_ip});
            g.loading=false;
        }).ok();
}
