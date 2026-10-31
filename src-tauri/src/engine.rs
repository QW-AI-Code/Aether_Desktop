//! پورت ۱:۱ از `core/AetherProcess.kt`.
//!
//! تمام رفتارهایی که در ۱.۲.۲ روی اندروید درست شدند عیناً حفظ شده‌اند:
//!   * درنگ کردن (drain) خروجی موتور تا لوله پر نشود
//!   * انتظار قابل‌قطع (interruptible) به‌جای polling
//!   * SIGTERM کوتاه (250ms) و سپس kill قطعی
//!   * منتظر ماندن برای آزادشدن پورت SOCKS5 محلی پیش از اجرای بعدی

use crate::log::DiagnosticsLog;
use crate::profile::{ConnectionProfile, CoreCaps};
use anyhow::{anyhow, Result};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// همان پورتی که موتور در اندروید باز می‌کند. استیج ۱ همیشه همین است.
pub const LOCAL_SOCKS_PORT: u16 = 1819;

/// پورتی که کل خط لولهٔ زنجیره‌ای `Aether → Psiphon` بیرون می‌دهد.
///
/// همان عددِ `TunnelConfig.CHAIN_SOCKS_PORT` اندروید است تا لاگ و مستندات دو
/// سکو یکی بمانند — ولی **معنایش کمی متفاوت است، و این عمدی است**: در اندروید
/// این پورت را `PsiphonSocksFront` می‌گیرد (لایه‌ای که UDP/udpgw/DNS را حمل
/// می‌کند و Psiphon خودش روی ۱۸۲۷ می‌نشیند)، چون tun2socks آن‌جا
/// `UDP ASSOCIATE` می‌خواهد. مسیر دادهٔ ویندوز پروکسی سیستمی WinINET است، یعنی
/// از بنیاد TCP-only، و فقط `CONNECT` لازم دارد؛ پس Psiphon مستقیم همین پورت را
/// می‌گیرد و آن لایهٔ میانی وجود ندارد. اجرای فرزند در `native/aether/aether/src/psiphon.rs` است.
pub const CHAIN_SOCKS_PORT: u16 = 1825;

/// ۱.۲.۵ — لیسنر SOCKS5 خودِ تور در موتور (هستهٔ ۲.۰.۰).
///
/// همان عددِ `TunnelConfig.TOR_SOCKS_PORT` اندروید، و همان چیزی که هستهٔ ۲.۰.۰
/// در `tor.rs` به‌عنوان پیش‌فرض دارد. با این حال برنامه همیشه `--tor-bind` را
/// صریح می‌فرستد: پیش‌فرضِ هسته مالِ هسته است و اگر روزی عوض شود، مسیر دادهٔ
/// ویندوز به پورتی وصل می‌ماند که کسی در آن گوش نمی‌دهد.
///
/// در `--tor-only` این پورت استفاده نمی‌شود؛ آنجا تور تنها پروکسیِ موتور است و
/// روی [LOCAL_SOCKS_PORT] می‌نشیند — [crate::profile::TransportBackend::tor_socks_port].
pub const TOR_SOCKS_PORT: u16 = 1820;
/// ۱.۲.۲: 10808/10809 با v2rayNG تداخل داشت، پس به 10810/10811 منتقل شد.
pub const SHARE_SOCKS_PORT: u16 = 10810;
pub const SHARE_HTTP_PORT: u16 = 10811;

const GRACEFUL_EXIT_MS: u64 = 250;

/// پورتی که **خروجی** خط لولهٔ فعال است: هرچه مسیر داده و خودآزما باید به آن
/// وصل شوند.
///
/// در نشست عادی همان [LOCAL_SOCKS_PORT] است. در نشست زنجیره‌ای، پس از بالا
/// آمدن استیج ۲، روی [CHAIN_SOCKS_PORT] تنظیم می‌شود.
///
/// ریشه‌ای که این متغیر برایش وجود دارد: پیش از این، `share.rs`، `probe.rs` و
/// `diagnostics.rs` هر سه مستقیم به `LOCAL_SOCKS_PORT` سیم‌کشی شده بودند. در یک
/// نشست زنجیره‌ای این یعنی پل و خودآزما به **استیج ۱** وصل می‌شدند — یعنی تونل
/// بالا می‌آمد، نشانِ IP کشور هاپ اول را نشان می‌داد و کاربر از خروجی اِتِر
/// بیرون می‌رفت، درست همان چیزی که زنجیره برای عوض‌کردنش هست. یک منبع حقیقت،
/// یک بار تنظیم، بدون تغییر امضای هیچ تابعی.
/// Every fixed local port an Aether pipeline binds. The port guard
/// (`procguard.rs`) clears orphans from all of them at start-up.
pub const FIXED_PORTS: [u16; 3] = [LOCAL_SOCKS_PORT, TOR_SOCKS_PORT, CHAIN_SOCKS_PORT];

static EXIT_SOCKS_PORT: AtomicU16 = AtomicU16::new(LOCAL_SOCKS_PORT);

// >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
/// Set when the engine prints `[+] psiphon is ready` (core `psiphon.rs`,
/// `run_only`/`run_chain`/`start_reverse`): the moment Psiphon has an
/// established tunnel. Cleared on every engine start. Mobile reads the same
/// line (`PsiphonEngine.snapshot.ready`) before it lets the data path up.
static PSIPHON_READY: AtomicBool = AtomicBool::new(false);

pub fn psiphon_ready() -> bool {
    PSIPHON_READY.load(Ordering::SeqCst)
}

// >>> AETHER-APP-FIX psiphon-wsaeacces-hint
/// یک بار در هر نشست: psiphon-tunnel-core.exe با WSAEACCES (10013) رد شد.
static PSIPHON_ACCESS_HINT: AtomicBool = AtomicBool::new(false);

/// پیش از هر اجرای سایفون صدا زده می‌شود تا راهنما دوباره یک بار گفته شود.
pub fn reset_psiphon_access_hint() {
    PSIPHON_ACCESS_HINT.store(false, Ordering::SeqCst);
}

/// WSAEACCES خطای خودِ ویندوز است، نه سانسور: یک قاعدهٔ فایروال (ماندهٔ یک
/// نشستِ کشته‌شده، یا برنامهٔ امنیتیِ دیگری) اجازهٔ connect نداد. لاگ‌های
/// ۲۰۲۶-۱۰-۱۰ صدها سطرِ «forbidden by its access permissions» داشتند و هیچ
/// توضیحی؛ این یک سطرِ قابل‌اقدام می‌گذارد و قواعدِ اتر را بررسی می‌کند.
fn ingest_access_denied(line: &str) {
    if !line.contains("forbidden by its access permissions") || !line.contains("psiphon") {
        return;
    }
    if PSIPHON_ACCESS_HINT.swap(true, Ordering::SeqCst) {
        return;
    }
    DiagnosticsLog::w(
        "engine",
        "Windows refused a socket of psiphon-tunnel-core.exe (WSAEACCES 10013): a local firewall rule blocks it, not the censor. Checking for leftover Aether rules…",
    );
    std::thread::Builder::new()
        .name("aether-wsaeacces".into())
        .spawn(crate::leakguard::diagnose_access_denied)
        .ok();
}
// <<< AETHER-APP-FIX psiphon-wsaeacces-hint

fn ingest_psiphon_ready(line: &str) {
    if line.contains("[+] psiphon is ready") {
        PSIPHON_READY.store(true, Ordering::SeqCst);
    }
}
// <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon

/// پورت خروجیِ خط لولهٔ فعال.
pub fn exit_socks_port() -> u16 {
    EXIT_SOCKS_PORT.load(Ordering::Relaxed)
}

/// پورت خروجی را تنظیم می‌کند (استیج ۲ بالا آمد).
pub fn set_exit_socks_port(port: u16) {
    let previous = EXIT_SOCKS_PORT.swap(port, Ordering::Relaxed);
    if previous != port {
        // The latency probe's warm connection belongs to the OLD pipeline. Keeping
        // it would time a dead path and publish its timeout as the user's ping.
        crate::ping::reset();
        DiagnosticsLog::i(
            "engine",
            &format!("Pipeline exit SOCKS5 port: {previous} -> {port}"),
        );
    }
}

/// بازگشت به موتور تنها — در هر قطع اتصال، شکست و چرخش نردبان صدا زده می‌شود.
///
/// اگر جا بیفتد، یک نشست عادیِ بعدی به پورت استیج ۲ که دیگر وجود ندارد وصل
/// می‌ماند و «متصل ولی هیچ سایتی باز نمی‌شود» برمی‌گردد.
pub fn reset_exit_socks_port() {
    set_exit_socks_port(LOCAL_SOCKS_PORT);
}

/// نسخهٔ هستهٔ همراه برنامه — از فایل CORE_VERSION کنار aether.exe خوانده
/// می‌شود (همان فایلی که پنل About نشان می‌دهد). در صورت هر ابهامی (0،0)
/// برمی‌گردد تا رفتار محافظه‌کارانه باشد.
fn engine_core_version(exe: &Path) -> (u32, u32) {
    let Some(dir) = exe.parent() else {
        return (0, 0);
    };
    let Ok(raw) = std::fs::read_to_string(dir.join("CORE_VERSION")) else {
        return (0, 0);
    };
    let mut parts = raw.trim().trim_start_matches('v').split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// نسخهٔ هسته به‌صورت رشته — همان چیزی که پنل About و سطرِ هویتِ ساخت
/// نشان می‌دهند. در صورت نبودِ فایل، `unknown` تا هیچ عددی ساخته نشود.
pub fn core_version_label(exe: &Path) -> String {
    exe.parent()
        .and_then(|dir| std::fs::read_to_string(dir.join("CORE_VERSION")).ok())
        .map(|raw| raw.trim().trim_start_matches('v').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// آیا هستهٔ همراه برنامه سوییچ --log-level (نسخهٔ 1.4.0 به بعد) را می‌فهمد؟
/// در صورت هر ابهامی محافظه‌کارانه false برمی‌گردد تا هسته‌های قدیمی با
/// فلگ ناشناخته از کار نیفتند.
fn engine_supports_log_level(exe: &Path) -> bool {
    engine_core_version(exe) >= (1, 4)
}

/// v10: قابلیت‌های هستهٔ همراه — Zero Trust / routing / --dns فقط از 1.5.0.
/// v11: پروکسی بالادست، تشخیص نام میزبان و بازثبت هویت فقط از 1.7.0.
pub fn engine_caps(exe: &Path) -> CoreCaps {
    let (major, minor) = engine_core_version(exe);
    CoreCaps::for_version(major, minor)
}

// >>> AETHER-APP-FIX perf-tier-matches-the-machine
/// چند هستهٔ پردازنده در دسترس است؟
fn detected_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// آیا باید سطح کارایی را به هسته تحمیل کنیم — و کدام؟
///
/// `None` یعنی «هیچ‌چیز نفرست»: هستهٔ ۲.۰.۰ خودش هم CPU و هم RAM را می‌بیند و
/// در `sysprofile.rs` سطح را انتخاب می‌کند. تنها حالتی که ارزش تحمیل دارد
/// ماشینی است که آشکارا سطح بالا را می‌کشد؛ آنجا فرستادنِ high تضمین می‌کند
/// که یک تشخیصِ محافظه‌کارانهٔ RAM سرعت را پایین نیاورد.
fn forced_perf_tier(cpus: usize) -> Option<&'static str> {
    if cpus >= 8 {
        Some("high")
    } else {
        None
    }
}
// <<< AETHER-APP-FIX perf-tier-matches-the-machine

pub struct AetherProcess {
    exe: PathBuf,
    working_dir: PathBuf,
    bundled_dir: PathBuf,
    child: Option<Child>,
    /// قابلیت‌های هستهٔ همراه، یک‌بار خوانده‌شده.
    ///
    /// ۱.۲.۵: `state.rs` در هر تیکِ حلقهٔ اتصال می‌پرسد آیا این نشست تور دارد،
    /// و پاسخ به `caps.tor` بند است. خواندنِ `CORE_VERSION` از دیسک چند بار در
    /// ثانیه برای مقداری که تا پایان عمر فرآیند عوض نمی‌شود، کارِ بی‌جهت است —
    /// مسیر `exe` بعد از `new` ثابت است، پس پاسخ هم ثابت است.
    caps: CoreCaps,
    /// آیا فرآیندِ *فعلاً در حال اجرا* تور دارد — از `start()` نوشته می‌شود.
    ///
    /// ۱.۲.۶ — دلیلِ وجودش در [`AetherProcess::stop`] است: تور (arti) روی
    /// پوشهٔ کش دایرکتوری‌اش قفل نگه می‌دارد. `TerminateProcess`/`kill()` بدون
    /// قید هیچ فرصتی برای آزادکردنِ تمیز آن قفل نمی‌دهد، و نتیجه‌اش تلاشِ بعدی
    /// است که به «Didn't get usable directory from cache» می‌رسد و همان‌جا در
    /// حدود ۱۵٪ گیر می‌کند — دقیقاً چیزی که در هر چهار تلاشِ یک لاگِ میدانی با
    /// AETHER_TOR_DIR مشترک دیده شد. غیرِ تور نیازی به این فرصت ندارد و
    /// رفتار سریع قبلی‌اش را نگه می‌دارد.
    uses_tor: bool,
    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// پراکسیِ SOCKS5ی که موتور باید **از دلِ آن** بیرون برود — پورتِ
    /// tor.exe در حالتِ `Tor → Aether`، و `None` در هر حالتِ دیگر.
    ///
    /// # چرا این فیلد به جای `--tor-reverse`
    ///
    /// در لاگِ ۱۷ سپتامبر، tor.exe در ۲۲ ثانیه با obfs4 به مدار رسید، و
    /// همان دقیقه تورِ داخلیِ موتور (arti) با همان پل‌ها ده دقیقه روی
    /// ۱۵٪ ماند (`directory timed out`, `Partial response`) تا بودجه تمام شد.
    /// پس حاملِ تور همیشه tor.exe است و موتور فقط مشتریِ آن می‌شود —
    /// همان کاری که خودِ هسته در `lib.rs` در حالتِ reverse می‌کند:
    /// `AETHER_UPSTREAM=socks5://…` و `AETHER_MASQUE_HTTP2=1`، منتها با توری که
    /// خودش بالا می‌آورد. این‌جا همان دو متغیر را می‌دهیم و پرچم را نه.
    upstream_socks: Option<u16>,
    custom_tcp_upstream: bool,
    probe_port: Option<u16>,
    chain_trace: Option<String>,
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// 1.3.0 port-guard: the engine's whole process tree (aether.exe plus the
    /// psiphon-tunnel-core.exe it spawns). `TerminateProcess` on aether.exe
    /// alone left Psiphon orphaned on 127.0.0.1:1819, and an app crash left
    /// aether.exe itself there — see `procguard.rs`.
    tree: Option<crate::procguard::KillTree>,
    // >>> AETHER-APP-PATCH custom-configs-psiphon-only
    /// زنجیره‌های کانفیگِ سفارشیِ `Psiphon → Config`: هستهٔ موتور با
    /// `--psiphon-only` و **بی** upstream اجرا می‌شود (سایفون مستقیم، Xray از
    /// دلِ 1819). فقط وقتی کانفیگِ سفارشی روشن است `true` می‌شود.
    psiphon_only: bool,
    // <<< AETHER-APP-PATCH custom-configs-psiphon-only
}

impl AetherProcess {
    pub fn new(install_dir: &Path, working_dir: &Path) -> Self {
        let bundled_dir = install_dir.join("engine");
        let exe = match prepare_runtime_engine(&bundled_dir, working_dir) {
            Ok(exe) => exe,
            Err(e) => {
                DiagnosticsLog::w(
                    "engine",
                    &format!("Could not stage the engine in a writable folder ({e}); running it from the install folder."),
                );
                bundled_dir.join("aether.exe")
            }
        };
        Self {
            caps: engine_caps(&exe),
            exe,
            working_dir: working_dir.to_path_buf(),
            bundled_dir,
            child: None,
            uses_tor: false,
            upstream_socks: None,
            custom_tcp_upstream:false,
            probe_port:None,
            chain_trace:None,
            tree: None,
            psiphon_only: false,
        }
    }

    /// Race children share only immutable executable metadata, not staging or UI sinks.
    pub fn set_chain_trace(&mut self,id:Option<String>){self.chain_trace=id;}
    pub fn owns_probe_listener(&self,port:u16)->bool{self.child.as_ref().map(|c|crate::procguard::listener_pid(port)==Some(c.id())).unwrap_or(false)}
    pub fn probe_bind_port(&self)->Option<u16>{self.probe_port}
    pub fn fork_probe(&self,port:u16)->Self{Self{exe:self.exe.clone(),working_dir:self.working_dir.clone(),bundled_dir:self.bundled_dir.clone(),caps:self.caps,child:None,uses_tor:false,upstream_socks:None,custom_tcp_upstream:false,probe_port:Some(port),chain_trace:None,tree:None,psiphon_only:false}}
    /// The engine, not the desktop, launches this bundled client. Runtime staging
    /// can fall back to the installation directory; both paths are checked.
    pub fn psiphon_assets(&self) -> Result<(PathBuf, PathBuf)> {
        if engine_core_version(&self.exe) < (2, 1) {
            return Err(anyhow!("Psiphon chains require Aether Core 2.1.0 or newer"));
        }
        let install = self.working_dir.join("engine");
        let candidates = [
            self.exe.parent().unwrap_or(install.as_path()),
            install.as_path(),
            self.bundled_dir.as_path(),
        ];
        let find = |name: &str| -> Result<PathBuf> {
            candidates
                .iter()
                .map(|d| d.join(name))
                .find(|p| p.is_file())
                .ok_or_else(|| anyhow!("Bundled Psiphon asset missing: {name}"))
        };
        Ok((
            find("psiphon-tunnel-core.exe")?,
            find("server_entries.txt")?,
        ))
    }

    /// قابلیت‌های هستهٔ همراه — همان چیزی که [`AetherProcess::start`] برای
    /// گِیت‌کردن فلگ‌ها استفاده می‌کند.
    pub fn caps(&self) -> CoreCaps {
        self.caps
    }

    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// موتور را از دلِ یک پروکسیِ SOCKS5ِ محلی بیرون می‌فرستد — رجوع به فیلدِ
    /// `upstream_socks`. پیش از `start` صدا زده می‌شود؛ `None` رفتار عادی است.
    pub fn set_upstream_socks(&mut self, port: Option<u16>) {
        self.upstream_socks = port;
    }

    // >>> AETHER-APP-PATCH custom-configs-psiphon-only
    /// رجوع به فیلدِ `psiphon_only`. پیش از `start`؛ پیش‌فرض `false`.
    pub fn set_psiphon_only(&mut self, on: bool) {
        self.psiphon_only = on;
    }

    /// این اجرا مسیرِ «فقط سایفون»ِ هسته است؟ پیش از این قابلیت تنها شرط
    /// `TorPsiphon && upstream_socks.is_some()` بود و با `psiphon_only=false`
    /// دقیقاً همان می‌ماند.
    fn psiphon_only_run(&self, profile: &ConnectionProfile) -> bool {
        profile.backend == crate::profile::TransportBackend::TorPsiphon
            && (self.upstream_socks.is_some() || self.psiphon_only)
    }
    // <<< AETHER-APP-PATCH custom-configs-psiphon-only

    /// آیا این موتور در این نشست اصلاً اجرا شده؟
    ///
    /// «هرگز اجرا نشده» با «مرده» یکی نیست: در `Tor → Aether` موتور تا آماده
    /// شدنِ تور اجرا نمی‌شود، و پرسیدنِ زنده‌بودنش در آن فاصله همان تخریبِ
    /// نابه‌جایی است که `poll_chain` را گمراه می‌کرد.
    pub fn was_started(&self) -> bool {
        self.child.is_some()
    }
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor

    /// نسخهٔ هستهٔ همین موتور — برای سطرِ هویتِ ساخت.
    pub fn core_version(&self) -> String {
        core_version_label(&self.exe)
    }

    /// آیا ترابرِ افزونه‌ای نصب است؟ — یعنی آیا فازِ پل واقعاً obfs4 دارد.
    ///
    /// هر اتصال یک بار پرسیده می‌شود، نه در هر تیکِ حلقه: کاربری که موتور را
    /// همین حالا بست و ترابر را کنارش گذاشت، با اتصال بعدی پاسخ تازه می‌گیرد،
    /// و حلقهٔ اتصال چند بار در ثانیه به دیسک نمی‌رود.
    pub fn transport_installed(&self) -> bool {
        crate::pt::installed(&self.working_dir)
    }

    /// Launches the engine for one rung of the ladder.
    ///
    /// `rung_budget_ms` is how long the caller ([`crate::state`]) will wait for
    /// the SOCKS5 port before it tears this attempt down.
    ///
    /// ## 1.2.3-p3: the budget has to be told to the engine, not kept secret
    ///
    /// It was not passed before, and the two sides disagreed badly. The app gave
    /// the first rung 35 s (`FIRST_PASS_MAX_MS`); the engine's own turbo scan
    /// budget is 45 s and it only STARTS after loading the identity, an optional
    /// ECH lookup and a cached-gateway verification. So on any network that
    /// needed a real scan, the first rung was mathematically guaranteed to be
    /// killed - with the scan roughly three quarters finished and its results
    /// thrown away - and the second rung started the same doomed scan from
    /// scratch. The field log shows precisely that: two attempts, 97 seconds,
    /// `scan deadline reached with no gateway`, nothing learned.
    ///
    /// Now the engine gets the deadline it is actually being held to and shortens
    /// its scan to fit, so a rung either finishes its scan or reports honestly
    /// that it could not - and the ladder advances immediately instead of after
    /// a stopwatch runs out.
    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// دو متغیری که موتور را از دلِ تورِ جلویی بیرون می‌فرستند.
    ///
    /// عیناً همان دو خطی که هستهٔ ۲.۰.۰ در `lib.rs` برای `--tor-reverse` خودش
    /// اجرا می‌کند:
    ///
    /// ```text
    /// std::env::set_var("AETHER_UPSTREAM", format!("socks5://{socks}"));
    /// std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    /// ```
    ///
    /// `AETHER_MASQUE_HTTP2` اختیاری نیست: تور فقط TCP حمل می‌کند و QUIC/UDP
    /// از دلش رد نمی‌شود، پس MASQUE باید روی HTTP/2 برود. لاگِ ۱۷ سپتامبر هم
    /// مستقل به همین رسیده بود («QUIC is filtered here, so HTTP/2 is the only
    /// carrier that can connect»)، ولی تکیه بر تشخیصِ شبکه برای چیزی که از
    /// ساختِ زنجیره قطعی است، یعنی گذاشتنِ یک شکستِ ممکن روی مسیرِ اصلی.
    pub fn set_custom_tcp_upstream(&mut self,enabled:bool){self.custom_tcp_upstream=enabled;}
    fn upstream_env(&self) -> Vec<(String, String)> {
        match self.upstream_socks {
            None => Vec::new(),
            Some(port) => vec![
                (
                    "AETHER_UPSTREAM".to_string(),
                    format!("socks5://127.0.0.1:{port}"),
                ),
                ("AETHER_MASQUE_HTTP2".to_string(), "1".to_string()),
                // >>> AETHER-APP-PATCH tor-reverse-latch
                // سنجشِ گیت‌وِیِ کش‌شده به‌طورِ پیش‌فرض ۲ ثانیه است (۱۵۰۰ms +
                // ۵۰۰ms). از داخلِ یک مدارِ تور فقط دست‌دادنِ SOCKS و TLS بیش از
                // این طول می‌کشد، پس در `loge2`/`loge3` هر بار هر دو گیت‌وِیِ
                // سالمِ قبلی «no longer answers» شدند و اسکنِ تازه راه افتاد.
                // `0` یعنی «بی‌بودجه»: سقفِ خودِ هسته (۵ ثانیه) می‌ماند، و
                // کندیِ مدارِ تور به حسابِ لبهٔ WARP گذاشته نمی‌شود.
                // HTTP/2 PING over Tor may take much longer than on a direct
                // socket. Avoid dropping a working circuit after the default
                // 20s without PONG; the session watchdog still checks egress.
                (
                    "AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS".to_string(),
                    "60".to_string(),
                ),
                // <<< AETHER-APP-PATCH tor-reverse-latch
            ],
        }
    }
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor

    /// پوشه‌ای که موتور در آن اجرا می‌شود و فایل‌های هویتش (`aether-team-*.toml`)
    /// را می‌نویسد. ورودِ Zero Trust با آن می‌فهمد دستگاه عضوِ تیم هست یا نه.
    pub fn run_dir(&self) -> PathBuf {
        self.exe
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.working_dir.clone())
    }

    // >>> AETHER-APP-FIX forget-a-gateway-that-failed-its-proof
    /// Deletes the engine's "last working gateway" caches (`*-lastconn.toml`:
    /// `aether-lastconn.toml` for WireGuard/gool, `aether-masque-lastconn.toml`,
    /// and the `aether-team-…-lastconn.toml` variants) from the run folder.
    ///
    /// ROOT CAUSE (field log 2026-10-08, Aether mode, first connect after
    /// install). The core saves a gateway to `lastconn` as soon as it picks it —
    /// before the tunnel has carried a single byte (`lib.rs`: `lastconn::save`
    /// right after "using cloudflare edge"). Its quick-reconnect check only
    /// re-does the handshake. So an edge that handshakes but carries no data
    /// (`188.114.96.125:878`: "no valid data from peer", HTTPS probes failed)
    /// was reused by the NEXT rung ("cached endpoint … still works; skipping
    /// scan") and again by the NEXT session — two full rungs and a whole second
    /// connect burnt on the same dead edge. The rescan that finally ran found a
    /// working edge in seconds. The core cannot be patched here (CI keeps it
    /// byte-identical to upstream), so the app forgets the cache whenever an
    /// attempt fails its end-to-end proof; a successful session re-creates it.
    /// Must only be called while the engine is stopped.
    pub fn forget_cached_gateways(&self) {
        let mut dirs = vec![self.run_dir()];
        if !dirs.contains(&self.working_dir) {
            dirs.push(self.working_dir.clone());
        }
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_gateway_cache_file(&name) && std::fs::remove_file(entry.path()).is_ok() {
                    DiagnosticsLog::i(
                        "engine",
                        &format!("Forgot the cached gateway {name}: the attempt that used it failed its self-test, so the next attempt scans afresh."),
                    );
                }
            }
        }
    }
    // <<< AETHER-APP-FIX forget-a-gateway-that-failed-its-proof

    pub fn start(
        &mut self,
        profile: &ConnectionProfile,
        rung_budget_ms: Option<u64>,
    ) -> Result<()> {
        if !self.exe.exists() {
            return Err(anyhow!("Engine binary missing: {}", self.exe.display()));
        }
        // The rung budget is the app's own deadline (see `state.rs`); the unmodified
        // core takes no budget variable, so it is only recorded for the log.
        if let Some(ms) = rung_budget_ms {
            DiagnosticsLog::i(
                "engine",
                &format!("Rung budget {}s (scan sized by --scan).", ms / 1000),
            );
        }

        // v10: فلگ‌های هستهٔ 1.5.0 (Zero Trust / routing / dns) فقط وقتی
        // فرستاده می‌شوند که هستهٔ همراه واقعاً آن‌ها را بفهمد.
        let caps = self.caps;
        let mut engine_profile = profile.clone();
        // Direct routes belong to the local bridge only. The engine is the shared
        // upstream for both localhost and LAN peers, so it must never route direct.
        engine_profile.route_direct.clear();
        if self.probe_port.is_some(){engine_profile.bypass_iran=false;engine_profile.block_ads=false;engine_profile.lan_share=false;engine_profile.route_block.clear();}
        let mut args = engine_profile.to_args_with_caps(caps);
        if let Some(port)=self.probe_port{args.extend(["--bind".into(),format!("127.0.0.1:{port}")]);}
        if self.psiphon_only_run(profile) {
            // Core's Psiphon-only path binds the primary SOCKS listener (1819).
            // Never ask it to bootstrap a second, internal arti process: the
            // native Tor circuit is already up on 1820. The bundled Psiphon
            // child and its server entries are still supplied below.
            args.retain(|arg| arg != "--tor-only" && arg != "--psiphon");
            if let Some(at) = args.iter().position(|arg| arg == "--psiphon-bind") {
                args.drain(at..at + 2);
            }
            args.insert(0, "--psiphon-only".into());
        }
        // لاگر جدید هستهٔ 1.4.0 متغیر RUST_LOG را نادیده می‌گیرد و فقط از
        // سوییچ رسمی خودش دستور می‌گیرد (لاگ v12 این را ثابت کرد: هیچ
        // خط debug چاپ نشد). سطح trace تنها راه دیدن عملیاتی است که
        // بلافاصله بعد از sysprofile با code 5 می‌میرد.
        // v16 (سرعت/پینگ): سطح trace فقط برای شکار باگ code 5 لازم بود و در
        // مسیر داده سربار جدی دارد؛ حالا که ریشه رفع شد به info (پیش‌فرضی که
        // v9 با آن سریع بود) برمی‌گردیم. همچنین sysprofile خودکار هستهٔ
        // 1.4.0 روی این سیستم پروفایل Medium با بافرهای کوچک
        // (netstack 256KB/64KB) انتخاب می‌کند که نسبت به هستهٔ 1.3.0 سرعت را
        // پایین می‌آورد؛ با --perf high بافرهای بزرگ و همروندی کامل اسکن
        // برمی‌گردد. (هر دو فلاگ فقط برای هستهٔ 1.4 به بالا فرستاده می‌شود.)
        if engine_supports_log_level(&self.exe) {
            args.insert(0, "--log-level".into());
            args.insert(1, "info".into());
            // >>> AETHER-APP-FIX perf-tier-matches-the-machine
            // پیش‌تر اینجا بی‌قید و شرط `--perf high` فرستاده می‌شد. لاگ
            // ۲۰۲۶-۰۹-۱۶ روی یک ماشین ۴ هسته‌ای/۵۸۶۵MB نتیجه‌اش را نشان
            // می‌دهد:
            //
            //     performance profile: High (cpus=4 mem=5865MB);
            //     scan concurrency cap=unlimited, udp socket rcv/snd=7168KB/384KB,
            //     netstack tcp buffers=2048KB rx/512KB tx, h2 windows=16384KB/32768KB
            //
            // یعنی همروندیِ بی‌سقف روی ۲۸۵ کاندید × ۵۴ پورت روی چهار هسته، و
            // بافرهایی به اندازهٔ یک ماشین دیگر — همان مصرف CPU/RAMی که
            // کاربر گزارش کرد. خودِ هسته در sysprofile.rs برای همین ماشین
            // Medium انتخاب می‌کرد (قاعدهٔ `cpus <= 4`)، و ما این تشخیص را
            // دور می‌زدیم.
            //
            // دلیلِ اولیهٔ این فلگ (بافرهای netstack کوچکِ هستهٔ ۱.۴.۰) دیگر
            // موضوعیت ندارد: Medium امروز ۱MB rx/۲۵۶KB tx و پنجرهٔ h2
            // ۸/۱۶MB می‌دهد. پس high فقط روی ماشینی که واقعاً می‌کشد، و در
            // بقیه تصمیم به خودِ هسته — که RAM را هم می‌بیند — واگذار می‌شود.
            if let Some(tier) = forced_perf_tier(detected_cpus()) {
                args.insert(2, "--perf".into());
                args.insert(3, tier.into());
            }
            // <<< AETHER-APP-FIX perf-tier-matches-the-machine
        }
        // ریشهٔ قطعی خطای Access is denied (code 5): تست‌های تشخیصی روی
        // سیستم کاربر ثابت کرد هستهٔ 1.4.0 با CWD=ریشهٔ پوشهٔ داده می‌میرد
        // (T1/T2) ولی با CWD=پوشهٔ خود موتور کامل وصل می‌شود (T3).
        // پس موتور را در پوشهٔ خودش اجرا می‌کنیم؛ فایل‌های هویت/کانفیگ هم
        // در prepare_runtime_engine به همین پوشه منتقل می‌شوند.
        let run_dir = self
            .exe
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.working_dir.clone());
        // ----- تور (هستهٔ ۲.۰.۰) ----------------------------------------
        //
        // دو مسیری که موتور نمی‌تواند خودش حدس بزند، پس این‌جا تحویل داده
        // می‌شوند نه در موتور:
        //
        //  * **کشِ دایرکتوری.** تور یک consensus می‌گیرد و نگهبان‌هایش را به
        //    یاد می‌سپارد؛ بدون پوشه‌ای نوشتنی و **ماندگار** هر بار از صفر
        //    bootstrap می‌کرد — همان شروعِ کندی که کاربر آن را هنگ می‌خواند.
        //    برخلاف اندروید که پوشهٔ کاری برنامه‌خصوصی است، این‌جا پوشهٔ دادهٔ
        //    برنامه است، نه کنار `aether.exe`: پوشهٔ نصب در Program Files
        //    برای کاربر عادی نوشتنی نیست و تور آن‌جا هیچ چیزی را کش نمی‌کرد.
        //  * **ترانسپورت‌های افزودنی.** `bridges.rs` خودش کنار موتور و در
        //    زیرپوشهٔ `pt` را می‌گردد، پس در بیلد عادی نیازی به معرفی نیست؛
        //    ولی وقتی موتور از پوشهٔ نصب اجرا می‌شود و PTها کنار دادهٔ برنامه‌اند
        //    (نصبِ per-user، یا PTهایی که بعداً کنار هم گذاشته شده‌اند) این
        //    متغیر تنها راهِ یافتنشان است.
        let tor_dirs = if caps.tor
            && profile.backend.uses_tor()
            && !self.psiphon_only_run(profile)
        {
            tor_runtime_dirs(&self.working_dir)
        } else {
            Vec::new()
        };
        // ۱.۲.۶ — stop() باید بداند این نشست تور دارد قبل از اینکه TerminateProcess
        // بزند — رجوع به توضیحِ فیلد `uses_tor` در تعریفِ struct.
        self.uses_tor = !tor_dirs.is_empty();

        // >>> AETHER-APP-PATCH smart-lists-routes-file (mobile 1.4.0 `SmartLists.engineRoutesFile`)
        // «دور زدن سایت‌های ایرانی» / «مسدودسازی تبلیغات»: موتور در نشست‌های
        // تک‌هاپی مقصد را می‌بیند، پس فهرست‌های داخلی به‌صورت فایل مسیرها به او
        // می‌رسند (`routing.rs::RuleSet::from_env`). در استیجِ ۱ِ Psiphon هر دو
        // پرچم خاموش‌اند (`chained_stage`) و این‌جا هیچ فایلی ساخته نمی‌شود؛
        // آن‌جا پل قواعد را اعمال می‌کند.
        let mut smart_env: Vec<(String, String)> = Vec::new();
        if self.custom_tcp_upstream && profile.protocol==crate::profile::Protocol::Masque && profile.masque_http2 {
            smart_env.push(("AETHER_CUSTOM_TCP_UPSTREAM".into(),"1".into()));
        }
        if caps.routing {
            if let Some(path) = crate::smart_lists::engine_routes_file(&self.working_dir, profile) {
                smart_env.push(("AETHER_ROUTES_FILE".into(), path.display().to_string()));
            }
        }
        // <<< AETHER-APP-PATCH smart-lists-routes-file
        // >>> AETHER-APP-PATCH zt-preconnect-handoff (mobile 1.4.0 `TeamSignInHandoff`)
        // ورودِ پیش از اتصال: اگر کاربر در تنظیمات با کدِ ایمیل وارد شده و
        // دستگاه هنوز عضوِ این تیم نیست، JWT به‌صورت `AETHER_ACCESS_TOKEN` می‌رود؛
        // موتور توکن را بر ایمیل مقدم می‌دارد و دیگر وسطِ اتصال کدی نمی‌خواهد.
        if caps.zero_trust
            && profile.uses_zero_trust()
            && profile.access_mode == crate::profile::AccessMode::Email
        {
            let record = crate::zt_signin::load_record(&self.working_dir);
            let dirs: Vec<&Path> = [Some(run_dir.as_path()), Some(self.working_dir.as_path())]
                .into_iter()
                .flatten()
                .collect();
            match crate::zt_signin::decide(
                record.as_ref(),
                &profile.team,
                &profile.access_email,
                |t| crate::zt_signin::is_enrolled(&dirs, t),
                crate::zt_signin::now_secs(),
            ) {
                crate::zt_signin::Decision::Use(token) => {
                    DiagnosticsLog::i(
                        "zerotrust",
                        "Handing the pre-connect sign-in to the engine.",
                    );
                    smart_env.push(("AETHER_ACCESS_TOKEN".into(), token));
                }
                crate::zt_signin::Decision::AlreadyEnrolled
                | crate::zt_signin::Decision::Unusable => {
                    // مصرف‌شده یا منقضی: نگه‌داشتنش فقط یک رازِ خفته است.
                    crate::zt_signin::save_record(&self.working_dir, None);
                }
                _ => {}
            }
        }
        // <<< AETHER-APP-PATCH zt-preconnect-handoff

        if profile.is_chained() {
            let (binary, servers) = self.psiphon_assets()?;
            args.push("--psiphon-bin".into());
            args.push(binary.display().to_string());
            smart_env.push((
                "AETHER_PSIPHON_SERVER_ENTRIES".into(),
                servers.display().to_string(),
            ));
            smart_env.push((
                "AETHER_PSIPHON_DIR".into(),
                self.working_dir.join("psiphon").display().to_string(),
            ));
        }
        let mut cmd = Command::new(&self.exe);
        cmd.env_remove("AETHER_CUSTOM_TCP_UPSTREAM");
        cmd.env_remove("AETHER_CHAIN_TRACE");
        if let Some(id)=&self.chain_trace{cmd.env("AETHER_CHAIN_TRACE",id);}
        cmd.args(&args)
            .envs(smart_env)
            .envs(tor_dirs.clone())
            .current_dir(&run_dir)
            // v11: متغیرهای هستهٔ 1.7.0 هم مثل فلگ‌ها گِیت شده‌اند.
            .envs(
                if self.psiphon_only_run(profile) {
                    // No arti bootstrap is performed by this process.
                    let mut env = profile.to_env_with_caps(caps);
                    env.retain(|key, _| !key.starts_with("AETHER_TOR"));
                    env
                } else {
                    profile.to_env_with_caps(caps)
                },
            )
            // >>> AETHER-APP-PATCH tor-reverse-latch
            // بعد از پروفایل، تا هیچ مقدارِ پروفایلی (مثلاً `AETHER_MASQUE_HTTP2=0`
            // یا بودجهٔ fast_endpoint_only) حاملِ داخلِ تور را پس نزند.
            .envs(self.upstream_env())
            // <<< AETHER-APP-PATCH tor-reverse-latch
            // Core 2.4.0 (upstream, unmodified) sizes its own endpoint scan from
            // `--scan` and has no rung-budget variable; the ladder in
            // `smart_auto.rs` sizes every rung to fit that scan instead.
            .env("HOME", &run_dir)
            .env("TMPDIR", &run_dir)
            // هستهٔ 1.4.0 بلافاصله بعد از مرحلهٔ جدید sysprofile با
            // Error: Io(code 5, Access is denied) خارج می‌شود. این دو متغیر
            // backtrace کامل از خود هسته در صورت خطا در کنسول لاگ برنامه ثبت شود؛
            // سطح عادی info از تولید هزاران خط TLS در مسیر موفق جلوگیری می‌کند.
            // (برای نسخه‌های قدیمی‌تر هسته بی‌ضررند و نادیده گرفته می‌شوند.)
            .env("RUST_BACKTRACE", "full")
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // معادل ویندوزیِ اینکه در اندروید فرآیند headless است: پنجرهٔ کنسول
        // نباید جلوی کاربر بالا بیاید.
        //
        // و همین «بی‌کنسول بودن» است که هر رخدادِ کنترلیِ کنسول را روی ویندوز
        // ناممکن می‌کند — دلیلِ برداشتنِ مسیر Ctrl+Break از stop(). آنجا را ببینید.
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);

        // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
        if self.probe_port.is_none(){PSIPHON_READY.store(false, Ordering::SeqCst);}
        // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
        let mut child = cmd.spawn()?;
        // Before anything else: from here on the engine and every process it
        // starts die with this app, however the app ends.
        self.tree = Some(crate::procguard::KillTree::adopt(&child, "aether.exe"));

        // >>> AETHER-APP-PATCH zt-login-code-prompt
        // موتور بدون کنسول اجرا می‌شود (CREATE_NO_WINDOW) و stdinش یک لولهٔ
        // معتبر است (نه دستگیرهٔ کنسولی که Access is denied می‌داد). هستهٔ ۲.۴.۰
        // از stdinِ غیرترمینال فقط یک چیز می‌خواند: کدِ ورودِ Zero Trust
        // (`[zerotrust] login-code-needed`). پس لوله باز می‌ماند و به
        // `login_code` سپرده می‌شود؛ دیگر «y\n»ی نوشته نمی‌شود که هسته آن را
        // اولین کد بگیرد. پورت از LoginCodePrompt.kt موبایل ۱.۵.۰.
        let stdin_sink: Option<Box<dyn std::io::Write + Send>> = child
            .stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Write + Send>);
        let generation = if self.probe_port.is_none(){Some(crate::login_code::attach(stdin_sink))}else{None};
        // <<< AETHER-APP-PATCH zt-login-code-prompt

        DiagnosticsLog::i(
            "engine",
            &format!("Spawned aether.exe {}", redact_args(&args).join(" ")),
        );
        for (key, value) in &tor_dirs {
            DiagnosticsLog::i("engine", &format!("{key}={value}"));
        }

        // موتور تازه یعنی bootstrap تازه: درصدِ اجرای قبلی نباید این یکی را
        // «در حال پیشرفت» نشان دهد. حتی وقتی این نشست تور ندارد هم صفر
        // می‌شود، وگرنه درصدِ کهنه از یک نشست تورِ قبلی روی صفحه می‌ماند.
        if self.probe_port.is_none(){crate::tor_bootstrap::reset();}

        // درنگ کردن stdout و stderr — دقیقاً مثل ترد «aether-log» در اندروید.
        if let Some(out) = child.stdout.take() {
            if self.probe_port.is_some(){spawn_probe_drain(out);}else{spawn_drain(out, generation);}
        }
        if let Some(err) = child.stderr.take() {
            if self.probe_port.is_some(){spawn_probe_drain(err);}else{spawn_drain(err, None);}
        }

        self.child = Some(child);
        Ok(())
    }

    // >>> AETHER-APP-PATCH tor-native-carrier
    /// باینریِ تورِ رسمی و پوشهٔ کنارش، اگر این نصب آن را دارد.
    ///
    /// جفتِ (باینری، پوشهٔ پشتیبان) برگردانده می‌شود چون هر دو لازم‌اند و
    /// نبودنِ یکی بی‌دیگری معنایی ندارد: خودِ tor.exe بی `geoip` و
    /// `pt_config.json` کنارش، نیمی از تنظیماتش را ندارد.
    pub fn native_tor(&self) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let support = self.working_dir.join("engine").join("tor");
        let binary = support.join(crate::tor_native::TOR_FILENAME);
        if binary.is_file() {
            Some((binary, support))
        } else {
            None
        }
    }

    /// پوشهٔ دادهٔ تورِ بومی.
    ///
    /// جدا از پوشه‌ای که به arti داده می‌شود (`<working>/tor`): دو پیاده‌سازیِ
    /// تور با یک کَشِ دایرکتوری و یک فایلِ گاردِ مشترک، حالتِ همدیگر را
    /// می‌خوانند و هیچ‌کدام انتظارش را ندارند.
    pub fn native_tor_home(&self) -> std::path::PathBuf {
        self.working_dir.join("tor-native")
    }
    // <<< AETHER-APP-PATCH tor-native-carrier

    pub fn is_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => match c.try_wait(){Ok(None)=>true,Ok(Some(status))=>{DiagnosticsLog::w("ChainTrace",&format!("engine pid={} exited status={status}",c.id()));false},Err(e)=>{DiagnosticsLog::w("ChainTrace",&format!("engine wait failed: {e}"));false}},
            None => false,
        }
    }

    /// معادل `awaitExit`: مسدود می‌ماند تا خروج موتور یا اتمام مهلت.
    /// برخلاف نسخهٔ قبلی اندروید، هیچ polling دومّینی‌ای در کار نیست.
    pub fn await_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.as_mut().map(|c| c.try_wait()) {
                None | Some(Ok(Some(_))) => return true,
                Some(Ok(None)) => std::thread::sleep(Duration::from_millis(20)),
                Some(Err(_)) => return false,
            }
        }
        false
    }

    /// معادل `stop()`: kill قطعی، سپس reap.
    /// برگشت از این تابع یعنی فرآیند واقعاً reap شده است.
    ///
    /// ۱.۲.۶ — تلاشِ «خاتمهٔ مؤدبانه با Ctrl+Break» که در دور قبل اضافه شده بود
    /// از این‌جا **برداشته شد**، چون لاگ میدانی ثابت کرد هرگز کار نمی‌کند:
    ///
    /// ```text
    ///   W/engine: GenerateConsoleCtrlEvent failed — falling back to a forced kill.
    /// ```
    ///
    /// و علتش ساختاری است، نه یک باگِ قابل‌اصلاح: AetherDesktop یک برنامهٔ
    /// گرافیکی بدون کنسول است و موتور هم با CREATE_NO_WINDOW اجرا می‌شود، پس
    /// هیچ کنسولی وجود ندارد که رخدادِ کنترلی به آن تحویل داده شود. یعنی آن
    /// مسیر از روز اول کدِ مرده بود و فقط یک خط هشدارِ گمراه‌کننده در لاگ
    /// می‌گذاشت.
    ///
    /// همان‌قدر مهم: آن تغییر بر این فرض بنا شده بود که گیرکردنِ تور روی ۱۵٪ از
    /// قفل‌ماندنِ کشِ دایرکتوری می‌آید. لاگِ کامل این فرض را هم رد کرد — تلاشِ
    /// مستقیم چون به هیچ guardای نمی‌رسد شکست می‌خورد و بعد از آن هر پلِ obfs4
    /// با `SocksError(GENERAL_FAILURE)` رد می‌شود. مسئله دسترسی به شبکه است، نه
    /// نحوهٔ خاتمهٔ پردازه. پس این تابع دوباره همان چیزی است که بود: سریع و صریح.
    pub fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            self.tree = None;
            return;
        };
        self.uses_tor = false;

        // The whole tree first (aether.exe + psiphon-tunnel-core.exe), then the
        // direct kill as a fallback for a tree that could not be adopted.
        if let Some(tree) = self.tree.as_ref() {
            tree.terminate();
        }
        let _ = child.kill(); // در ویندوز TerminateProcess فوری است
        let deadline = Instant::now() + Duration::from_millis(GRACEFUL_EXIT_MS);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.wait();
        self.tree = None;
        DiagnosticsLog::w("engine", "Engine stopped and reaped.");
    }
}

impl Drop for AetherProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// ریشهٔ باگ «روی هیچ پروتکلی کانکت نمی‌شود» (هستهٔ 1.4.x):
/// هستهٔ جدید بلافاصله بعد از شروع، وضعیت خودش (کش quick-reconnect و…) را
/// کنار فایل اجرایی‌اش می‌نویسد. وقتی موتور از `C:\Program Files\…\engine`
/// اجرا شود، آن پوشه برای فرآیندِ بدون Administrator فقط‌خواندنی است و موتور
/// در همان میلی‌ثانیهٔ اول با `Io(Os { code: 5 … Access is denied })` می‌میرد
/// — دقیقاً امضای لاگ کاربر (همهٔ پروتکل‌ها، خروج فوری، قبل از بازشدن SOCKS5).
///
/// رفع ریشه‌ای: موتور در اولین اجرا به پوشهٔ دادهٔ کاربر (قابل‌نوشتن) کپی و
/// همیشه از همان‌جا اجرا می‌شود تا هر نوشتنِ «کنار exe» مجاز باشد. این کار
/// نسخه‌های آیندهٔ هسته را هم در برابر همین کلاس خطا بیمه می‌کند.
/// اگر کپی به هر دلیلی شکست بخورد، رفتار قدیمی (اجرای مستقیم از پوشهٔ نصب)
/// حفظ می‌شود تا هیچ‌وقت وضع بدتر از قبل نشود.
fn prepare_runtime_engine(bundled_dir: &Path, working_dir: &Path) -> Result<PathBuf> {
    let runtime_dir = working_dir.join("engine");
    if runtime_dir == *bundled_dir {
        let exe = runtime_dir.join("aether.exe");
        return if exe.exists() {
            Ok(exe)
        } else {
            Err(anyhow!("Engine binary missing: {}", exe.display()))
        };
    }
    std::fs::create_dir_all(&runtime_dir)?;
    for entry in std::fs::read_dir(bundled_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let src = entry.path();
        let dst = runtime_dir.join(entry.file_name());
        if !runtime_copy_is_fresh(&src, &dst) {
            std::fs::copy(&src, &dst)?;
        }
    }
    // ۱.۲.۵ — زیرپوشهٔ `pt` هم باید بیاید.
    //
    // حلقهٔ بالا عمداً فقط فایل کپی می‌کند، و تا ۱.۲.۴ چیزی هم برای کپی‌کردن
    // در زیرپوشه‌ها نبود. ترابرِ افزودنی که کنارِ موتور نصب می‌شود
    // (`engine/pt/lyrebird.exe`) با همان حلقه **هرگز** به پوشهٔ اجرای موتور
    // نمی‌رسید و پل‌ها بی‌هیچ نشانه‌ای شکست می‌خوردند — چون هستهٔ ۲.۰.۰
    // `<پوشهٔ موتور>/pt` را می‌گردد، یعنی جایی که فایل هرگز به آن نرسیده بود.
    // >>> AETHER-APP-PATCH tor-native-carrier
    // پوشهٔ `tor` (tor.exe، lyrebird.exe، pt_config.json، geoip، geoip6) هم مثل
    // `pt` به پوشهٔ اجراییِ قابل‌نوشتن می‌آید: تور فایلِ torrc و DataDirectory
    // خودش را می‌نویسد و مسیرِ نصب زیرِ `C:\Program Files` نوشتنی نیست.
    let tor_src = bundled_dir.join("tor");
    if tor_src.is_dir() {
        let tor_dst = runtime_dir.join("tor");
        std::fs::create_dir_all(&tor_dst)?;
        for entry in std::fs::read_dir(&tor_src)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let _ = std::fs::copy(entry.path(), tor_dst.join(entry.file_name()));
            }
        }
    }
    // <<< AETHER-APP-PATCH tor-native-carrier

    let pt_src = bundled_dir.join("pt");
    if pt_src.is_dir() {
        let pt_dst = runtime_dir.join("pt");
        if let Err(e) = std::fs::create_dir_all(&pt_dst) {
            DiagnosticsLog::w(
                "engine",
                &format!(
                    "Could not create the transport directory ({e}); Tor bridges will have \
                     no transport to run."
                ),
            );
        } else if let Ok(entries) = std::fs::read_dir(&pt_src) {
            for entry in entries.flatten() {
                if !entry.file_type().map(|k| k.is_file()).unwrap_or(false) {
                    continue;
                }
                let src = entry.path();
                let dst = pt_dst.join(entry.file_name());
                if !runtime_copy_is_fresh(&src, &dst) {
                    if let Err(e) = std::fs::copy(&src, &dst) {
                        DiagnosticsLog::w(
                            "engine",
                            &format!(
                                "Could not install {}: {e}",
                                entry.file_name().to_string_lossy()
                            ),
                        );
                    }
                }
            }
        }
    }

    // هویت ثبت‌شدهٔ قبلی کاربر (اگر در ریشهٔ پوشهٔ داده باشد) یک‌بار به
    // پوشهٔ اجرای موتور منتقل می‌شود تا دوباره ثبت‌نام لازم نشود.
    // (فایل‌های دیگر مثل masque/lastconn عمداً کپی نمی‌شوند؛ هستهٔ
    // جدید خودش نسخهٔ سالم می‌سازد.)
    for name in ["aether.toml", "aether-secondary.toml"] {
        let src = working_dir.join(name);
        let dst = runtime_dir.join(name);
        if src.is_file() && !dst.exists() {
            let _ = std::fs::copy(&src, &dst);
        }
    }
    let exe = runtime_dir.join("aether.exe");
    if !exe.exists() {
        return Err(anyhow!(
            "Engine binary missing: {}",
            bundled_dir.join("aether.exe").display()
        ));
    }
    Ok(exe)
}

/// فقط وقتی دوباره کپی می‌کنیم که نسخهٔ نصب‌شده عوض شده باشد (آپدیت برنامه).
fn runtime_copy_is_fresh(src: &Path, dst: &Path) -> bool {
    let (Ok(a), Ok(b)) = (std::fs::metadata(src), std::fs::metadata(dst)) else {
        return false;
    };
    if a.len() != b.len() {
        return false;
    }
    // AETHER-APP-PATCH security-audit-1.3.0 (S-01): the runtime folder is
    // user-writable and its binaries run elevated, so size+mtime is not proof.
    // Compare the bytes against the protected install copy every time.
    match (std::fs::read(src), std::fs::read(dst)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// v10 سخت‌سازی امنیتی: مقدار فلگ‌های محرمانه در لاگ ماندگار پوشانده می‌شود.
/// خود فلگ دیده می‌شود (برای عیب‌یابی) ولی راز/توکن/ایمیل هرگز در
/// فایل لاگ چرخان ثبت نمی‌شود (همان قاعدهٔ ماسک IP در diagnostics.rs).
fn redact_args(args: &[String]) -> Vec<String> {
    // v11: مقدار --upstream می‌تواند user:pass پروکسی کاربر را داشته باشد.
    const SENSITIVE: [&str; 6] = [
        "--tor-bridge",
        "--access-id",
        "--access-secret",
        "--access-token",
        "--access-email",
        "--upstream",
    ];
    let mut out = Vec::with_capacity(args.len());
    let mut mask_next = false;
    for a in args {
        if mask_next {
            out.push("••••••".to_string());
            mask_next = false;
            continue;
        }
        if SENSITIVE.contains(&a.as_str()) {
            mask_next = true;
        }
        out.push(a.clone());
    }
    out
}

/// متغیرهای محیطیِ مسیرهای تور: پوشهٔ کشِ ماندگار، و پوشهٔ PT اگر پیدا شود.
///
/// پوشهٔ کش زیر پوشهٔ دادهٔ برنامه ساخته می‌شود. اگر ساختنش ممکن نبود، متغیر
/// **فرستاده نمی‌شود**: تور آن‌وقت به پیش‌فرض خودش برمی‌گردد و کند وصل می‌شود،
/// که بی‌نهایت بهتر از پاس‌دادن مسیری است که در آن نمی‌تواند بنویسد و
/// bootstrap را با خطایی دربارهٔ دیسک می‌شکند.
fn tor_runtime_dirs(working_dir: &Path) -> Vec<(String, String)> {
    let mut env = Vec::new();

    let dir = working_dir.join("tor");
    match std::fs::create_dir_all(&dir) {
        Ok(()) => env.push(("AETHER_TOR_DIR".into(), dir.to_string_lossy().into_owned())),
        Err(e) => DiagnosticsLog::w(
            "engine",
            &format!(
                "Could not create the Tor cache directory ({e}); Tor will bootstrap from \
                 scratch on every connect."
            ),
        ),
    }

    // پوشه‌های ترابر، به ترتیبِ اولویت.
    //
    // اولی جایی است که ترابرِ همراهِ نصب می‌نشیند (`engine/pt`، همان‌جا که
    // `prepare_runtime_engine` آن را می‌گذارد). هستهٔ ۲.۰.۰ خودش هم
    // `<پوشهٔ موتور>/pt` را می‌گردد، ولی صریح فرستادنش این را از یک رفتارِ
    // ضمنیِ بالادست به یک قراردادِ نوشته‌شده تبدیل می‌کند.
    //
    // دومی برای ترابری است که کاربر خودش می‌گذارد (مثلاً
    // `snowflake-client.exe` از Tor Browser). این پوشه را برنامه نمی‌سازد؛
    // فقط اگر باشد، معرفی می‌شود.
    let mut pt_dirs: Vec<String> = Vec::new();
    for dir in crate::pt::dirs(working_dir) {
        if dir.is_dir() {
            pt_dirs.push(dir.to_string_lossy().into_owned());
        }
    }
    // ۱.۲.۵-p2: شرطِ هشدار «ترابری هست؟» است، نه «پوشه‌ای هست؟».
    //
    // در لاگ میدانی همین تفاوت خودش را نشان داد: `AETHER_TOR_PT_DIR` فرستاده
    // شده بود — پس پوشه وجود داشت — ولی هیچ ترابری داخلش نبود. برنامه در آن
    // حالت فکر می‌کرد پل ممکن است و ۴۲۰ ثانیه صبر را روی همان بنا کرد.
    if !crate::pt::installed(working_dir) {
        // پیامِ نسخهٔ اندروید، چون وضعیت همان است: تور کار می‌کند، پل نه.
        DiagnosticsLog::w(
            "engine",
            "No pluggable transport installed: Tor can still connect directly and through \
             the tunnel, but bridges have no transport to run.",
        );
    } else {
        // هستهٔ ۲.۰.۰ چند پوشه را با `;` می‌پذیرد (bridges.rs:173).
        env.push(("AETHER_TOR_PT_DIR".into(), pt_dirs.join(";")));
    }

    env
}

fn spawn_drain<R: std::io::Read + Send + 'static>(reader: R, prompt_generation: Option<u64>) {
    std::thread::Builder::new()
        .name("aether-log".into())
        .spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                // مثل اندروید: خروجی موتور فقط به لاگ خصوصیِ برنامه می‌رود،
                // نه به جایی که بقیهٔ سیستم بخواند (معادل ممنوعیت Logcat).
                DiagnosticsLog::d("engine", &line);
                // ۱.۲.۵ — پیشرفت bootstrap تور از همین سطرها خوانده می‌شود؛
                // برای هر سطر دیگری بی‌اثر است و پیش از هر تخصیص حافظه‌ای
                // برمی‌گردد.
                crate::tor_bootstrap::ingest(&line);
                // ۱.۲.۵ — اندپوینتِ واقعی (لبهٔ WARP) هم در همین سطرها است.
                crate::firsthop::ingest(&line);
                // ۱.۲.۵ — مهرِ ساختِ موتور در همین سطرها می‌آید. مثل بالا،
                // برای هر سطرِ دیگری با یک `contains` برمی‌گردد.
                crate::provenance::ingest(&line);
                // AETHER-APP-FIX tor-fresh-circuit-for-the-engine: درخواستِ بی‌جواب از راهِ تور.
                crate::tor_native::ingest_engine_line(&line);
                // >>> AETHER-APP-FIX tor-psiphon-waits-for-psiphon
                ingest_psiphon_ready(&line);
                // <<< AETHER-APP-FIX tor-psiphon-waits-for-psiphon
                // AETHER-APP-FIX psiphon-wsaeacces-hint
                ingest_access_denied(&line);
                // AETHER-APP-PATCH zt-login-code-prompt: درخواستِ کدِ ورود در stdout می‌آید.
                if prompt_generation.is_some() {
                    crate::login_code::ingest(&line);
                }
            }
            if let Some(generation) = prompt_generation {
                crate::login_code::detach(generation);
            }
            DiagnosticsLog::w("engine", "Engine output stream closed.");
        })
        .ok();
}

/// معادل `PortProbe.kt`: پیش از اجرای موتور جدید، منتظر آزادشدن پورت می‌مانیم.
/// این همان ریشهٔ باگ «تعویض پروتکل طول می‌کشد» در ۱.۲.۱ بود.
pub fn wait_for_port_release(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// >>> AETHER-APP-FIX perf-tier-matches-the-machine
#[cfg(test)]
mod perf_tier_tests {
    use super::forced_perf_tier;

    /// ماشینِ کاربر در لاگ ۲۰۲۶-۰۹-۱۶: چهار هسته. پیش از این اصلاح، همین
    /// ماشین `--perf high` می‌گرفت و هسته با «scan concurrency cap=unlimited»
    /// و بافرهای ۷MB/۱۶MB/۳۲MB بالا می‌آمد.
    #[test]
    fn a_four_core_machine_is_left_to_the_engines_own_judgement() {
        assert_eq!(forced_perf_tier(4), None);
        assert_eq!(forced_perf_tier(2), None);
        assert_eq!(forced_perf_tier(6), None);
    }

    /// روی ماشینی که واقعاً می‌کشد، تحمیلِ high سرِ جایش می‌ماند — این اصلاح
    /// دربارهٔ گرفتنِ سرعت نیست، دربارهٔ ندادنِ بارِ یک ماشینِ دیگر است.
    #[test]
    fn a_big_machine_still_gets_the_high_tier() {
        assert_eq!(forced_perf_tier(8), Some("high"));
        assert_eq!(forced_perf_tier(16), Some("high"));
    }
}
// <<< AETHER-APP-FIX perf-tier-matches-the-machine

// >>> AETHER-APP-FIX forget-a-gateway-that-failed-its-proof
/// `aether[-masque|-team-…|-secondary]-lastconn.toml` — the core's
/// `derive_sibling_path(config, "lastconn")` names, and nothing else.
fn is_gateway_cache_file(name: &str) -> bool {
    name.starts_with("aether") && name.ends_with("-lastconn.toml")
}

#[cfg(test)]
mod gateway_cache_tests {
    use super::is_gateway_cache_file;

    #[test]
    fn only_the_cores_lastconn_files_are_forgotten() {
        assert!(is_gateway_cache_file("aether-lastconn.toml"));
        assert!(is_gateway_cache_file("aether-masque-lastconn.toml"));
        assert!(is_gateway_cache_file("aether-team-acme-lastconn.toml"));
        assert!(!is_gateway_cache_file("aether.toml"));
        assert!(!is_gateway_cache_file("aether-masque.toml"));
        assert!(!is_gateway_cache_file("aether-team-acme.toml"));
    }

    /// The exact line core 2.4.0 prints in `run_only` (field log 2026-10-08).
    #[test]
    fn the_psiphon_ready_line_is_recognised() {
        super::PSIPHON_READY.store(false, std::sync::atomic::Ordering::SeqCst);
        super::ingest_psiphon_ready("[2026-10-08T12:39:52Z INFO  aether::psiphon] [*] psiphon dials out through the upstream proxy");
        assert!(!super::psiphon_ready());
        super::ingest_psiphon_ready("[2026-10-08T12:39:53.969Z INFO  aether::psiphon] [+] psiphon is ready; 127.0.0.1:1819 leaves through psiphon");
        assert!(super::psiphon_ready());
    }
}
// <<< AETHER-APP-FIX forget-a-gateway-that-failed-its-proof

fn spawn_probe_drain<R:std::io::Read+Send+'static>(reader:R){std::thread::spawn(move||{for line in BufReader::new(reader).lines().map_while(Result::ok){DiagnosticsLog::d("smart+-engine",&crate::custom::process::redact(&line));}});}
