//! پورت از `core/Diagnostics.kt`.
//!
//! همان خودآزمای ۴ مرحله‌ای اندروید که اعلام «Connected» را دروازه‌بانی می‌کند:
//!   ۱. پورت SOCKS5 باز است؟
//!   ۲. دست‌دادن SOCKS5 جواب می‌دهد؟
//!   ۳. TCP از دل پروکسی به IP خام (1.1.1.1:80) برقرار می‌شود؟
//!   ۴. DNS + HTTP واقعی از دل تونل (همراه با IP خروجی و کد کشور)؟
//!
//! مثل اندروید، مراحل ۳ و ۴ در یک پنجرهٔ گریس با تلاش مجدد هر ۷۵۰ms اجرا
//! می‌شوند (شروع سرد warp-in-warp چند ثانیه طول می‌کشد تا مسیر خروجی
//! واقعاً باز شود). نتیجهٔ هر مرحله زنده در `DiagnosticsLog::checks` منتشر
//! می‌شود تا پنل عیب‌یابی دقیقاً مثل موبایل رنگ عوض کند.

use crate::engine;
use crate::leakguard;
use crate::log::DiagnosticsLog;
use crate::probe;
use crate::profile::ConnectionProfile;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

const TAG: &str = "diag";

/// 1.3.0: generation of the running self-test. A teardown bumps it so the
/// retry loop of an abandoned attempt stops at once. Before this, the loop of
/// a dead rung kept probing for its whole grace window and overlapped the next
/// rung's probes — the doubled `proxied geo … failed` lines in the field log.
static SELF_TEST_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Abandons any self-test still running (called from every teardown).
pub fn cancel_self_test() {
    SELF_TEST_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn self_test_cancelled(generation: u64) -> bool {
    SELF_TEST_GEN.load(std::sync::atomic::Ordering::SeqCst) != generation
}

// شناسهٔ بررسی‌ها — همان مقادیر Diagnostics.kt.
pub const C_PORT: &str = "socks_port";
pub const C_HANDSHAKE: &str = "socks_handshake";
pub const C_TCP: &str = "tcp_via_proxy";
pub const C_DNS: &str = "dns_http_via_tunnel";
/// v1.2.0 — پنجمین بررسی: هیچ آی‌پی واقعی‌ای از راه UDP/WebRTC بیرون نرود.
pub const C_LEAK: &str = "webrtc_udp_leak";

/// تلاش مجدد هر ۷۵۰ms — همان مقدار اندروید.
const RETRY_DELAY_MS: u64 = 750;

/// پنجرهٔ گریس خودآزما برای نشست زنجیره‌ای `Aether → Psiphon`.
///
/// عمداً بلندتر از ۹۰ ثانیهٔ نشست عادی. دست‌دادن و انتخاب سرورِ خود Psiphon
/// چند ثانیه می‌برد و RTT اش چند برابر یک لبهٔ اِتِر است، و یک نشست زنجیره‌ای
/// گرم‌شدنِ **هر دو** هاپ را می‌پردازد. پنجرهٔ ۹۰ ثانیه نشست‌هایی را رد می‌کرد
/// که فقط کُند بودند — بدترین نتیجهٔ ممکن: همه‌چیز کار می‌کند و برنامه دورش
/// می‌ریزد. همان `Diagnostics.EXTERNAL_GRACE_MS` اندروید.
pub const EXTERNAL_GRACE_MS: u64 = 150_000;

/// فاصلهٔ تلاش‌های دست‌دادن در پنجرهٔ انتظار — همان ۱٫۵ ثانیهٔ اندروید
/// (`Diagnostics.HANDSHAKE_RETRY_DELAY_MS`).
const HANDSHAKE_RETRY_DELAY_MS: u64 = 1_500;

/// بودجهٔ یک تلاشِ تور، وقتی پل مجاز **نیست** — همان
/// `TOR_BOOTSTRAP_TIMEOUT_MS` اندروید.
///
/// نخستین bootstrap تور یک consensus کامل و توصیف رله‌ها را می‌گیرد و روی
/// شبکه‌ای که فقط کند است ده‌ها ثانیه طول می‌کشد. بریدنِ زودهنگامِ همین یک
/// مرحله بود که بک‌اند تورِ ۱.۲.۷ موبایل را «هنگ‌کن» معروف کرد: هنگ نکرده
/// بود، وسط تنها مرحلهٔ کندش کشته می‌شد.
pub const TOR_BOOTSTRAP_BUDGET_MS: u64 = 300_000;

/// همان بودجه، برای توری که اجازه دارد به پل برگردد — `TOR_BRIDGE_BUDGET_MS`.
///
/// موتور پیش از آنکه اصلاً پل بخواهد، `AETHER_TOR_BRIDGE_SECS` (پیش‌فرض ۳۶۰
/// ثانیه) مستقیم تلاش می‌کند. پس بودجهٔ ۳۰۰ ثانیه‌ای تضمین می‌کرد که
/// برگشت‌به‌پل — تنها فرار خودکار روی شبکه‌ای که تور را فیلتر می‌کند — هرگز
/// حتی یک بار رخ ندهد.
pub const TOR_BRIDGE_BUDGET_MS: u64 = 600_000;

/// چند وقت درصدِ bootstrap می‌تواند بی‌حرکت بماند پیش از آنکه تلاش رها شود.
///
/// با پلِ خاموش، bootstrapِ گیرکرده چیزی برای آزمودن ندارد، پس صبر کردن تا
/// پایان بودجه فقط شکستی را عقب می‌اندازد که کاربر از همین حالا می‌توانست
/// کاری برایش بکند. با پلِ مجاز، خودِ گیرکردن **محرکِ** برگشت‌به‌پلِ موتور
/// است، پس صبر باید آن را پوشش بدهد.
pub const TOR_STALL_DIRECT_MS: u64 = 45_000;
pub const TOR_STALL_BRIDGED_MS: u64 = 420_000;

/// دست‌دادن SOCKS5 با یک **پنجرهٔ انتظار** به جای یک تلاش تنها.
///
/// # رفعِ باگِ میدانیِ ۱.۲.۵ (گزارش «تور روی شبکهٔ من وصل نمی‌شود»)
///
/// استیج ۱ِ تور پورتش را همان لحظهٔ اجرا bind می‌کند ولی تا وقتی تور به شبکه
/// نرسیده نمی‌تواند به دست‌دادن جواب بدهد. برنامه پورتِ باز را دلیلِ آمادگی
/// می‌گرفت و یک تلاشِ ۴ ثانیه‌ای می‌زد؛ پس **هر** اتصال تور در ثانیهٔ ۴ شکست
/// می‌خورد، در حالی که لاگ خود موتور bootstrap را روی ۳۰٪ و در حال بالا رفتن
/// نشان می‌داد — و برنامه برای توری که تنها تمام نشده بود، «خودآزما شکست
/// خورد» گزارش می‌کرد.
///
/// `grace_ms == 0` رفتار قدیمی و تک‌ضربه‌ای را نگه می‌دارد، که برای استیجی
/// درست است که با باز شدن پورتش آماده است: تونل اِتِری که فوراً دست نمی‌دهد
/// خراب است و صبر کردن روی آن فقط پلهٔ بعدیِ نردبان را عقب می‌اندازد.
///
/// `alive` می‌گذارد موتورِ مرده انتظار را فوراً تمام کند، و `abort` راهی است
/// که فراخواننده با آن دست از bootstrapی می‌شوید که از حرکت ایستاده — بدون
/// آن، شبکه‌ای که بی‌صدا تور را می‌اندازد رابط کاربری را تمام بودجه روی
/// «در حال اتصال» نگه می‌داشت.
pub fn await_socks_handshake(
    port: u16,
    grace_ms: u64,
    alive: &dyn Fn() -> bool,
    abort: &dyn Fn() -> bool,
) -> bool {
    if probe::socks_handshake_ok_on(port) {
        return true;
    }
    if grace_ms == 0 {
        return false;
    }
    DiagnosticsLog::i(
        TAG,
        &format!(
            "stage 1: 127.0.0.1:{port} is listening but not answering yet — waiting up to {}s \
             for it ({}).",
            grace_ms / 1_000,
            crate::tor_bootstrap::describe()
        ),
    );
    let deadline = Instant::now() + Duration::from_millis(grace_ms);
    while Instant::now() < deadline {
        if !alive() {
            DiagnosticsLog::e(
                TAG,
                "stage 1: the engine exited while its proxy was still coming up.",
            );
            return false;
        }
        if abort() {
            DiagnosticsLog::e(
                TAG,
                &format!(
                    "stage 1: giving up early — {}.",
                    crate::tor_bootstrap::describe()
                ),
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(HANDSHAKE_RETRY_DELAY_MS));
        if probe::socks_handshake_ok_on(port) {
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "stage 1: proxy answered ({}).",
                    crate::tor_bootstrap::describe()
                ),
            );
            return true;
        }
    }
    DiagnosticsLog::e(
        TAG,
        &format!(
            "stage 1: 127.0.0.1:{port} never answered within {}s ({}).",
            grace_ms / 1_000,
            crate::tor_bootstrap::describe()
        ),
    );
    false
}

/// دلیلِ شکست استیج ۱، به زبان خودِ کاربر.
///
/// «تونل بالا آمد ولی خودآزما شکست خورد» گمراه‌کننده‌ترین رشتهٔ نسخهٔ قبل
/// بود: برای استیجی که رویش تور است، همان پیام برای توری نشان داده می‌شد که
/// هرگز حتی به شبکه نرسیده بود — و کاربر (و دستیارِ داخلِ برنامه که لاگ را
/// می‌خواند) را به دنبال مشکلی در تونل می‌فرستاد که وجود نداشت.
/// شکلِ توری که شکست خورد — همان چیزی که تعیین می‌کند چه توصیه‌ای درست است.
///
/// بدون این، هر سه وضعیت یک پیام می‌گرفتند: توری که خودش روبروی شبکه است و
/// می‌تواند به پل برگردد، توری که ترابر ندارد و پس فقط پلِ ساده دارد، و توری
/// که از داخل تونل dial می‌شود و پل در آن هیچ نقشی ندارد. پیامِ «پل را روشن
/// کنید» برای حالت سوم صرفاً غلط است.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorShape {
    /// تور خودش با شبکهٔ محلی طرف است — `Tor` و `Tor → Aether`.
    FacingNetwork {
        /// تنظیمِ کاربر پل را منع نکرده.
        bridges_allowed: bool,
        /// ترابری نصب است، پس فازِ پل obfs4/webtunnel هم دارد.
        transport_installed: bool,
    },
    /// تور از داخل تونل dial می‌شود — `Aether → Tor`.
    ThroughTunnel,
}

pub fn stage_failure_message(tor: Option<TorShape>) -> String {
    let Some(shape) = tor else {
        return "The tunnel started but the self-test failed.".to_string();
    };
    // تورِ داخلِ تونل: تونل ثابت‌شده کار می‌کند (خودآزمای استیج ۱ سبز شده)، پس
    // توصیهٔ «پل» یا «از تونل استفاده کن» بی‌معناست — کاربر همان‌جا هست.
    if shape == TorShape::ThroughTunnel {
        let snap = crate::tor_bootstrap::snapshot();
        return match snap.percent {
            None => "The tunnel is up, but Tor never reported any progress from inside it. \
                     Try Tor on its own, which lets Tor pick its own way to the network."
                .to_string(),
            Some(p) => format!(
                "The tunnel is up, but Tor stopped at {p}% inside it and did not reach the Tor \
                 network. Try another protocol for the tunnel, or Tor on its own with bridges."
            ),
        };
    }
    let snap = crate::tor_bootstrap::snapshot();
    // بی ترابر، فازِ پل فقط پلِ ساده دارد — همان چیزی که شبکهٔ فیلترکنندهٔ تور
    // معمولاً هم‌زمان بسته است. گفتنِ «پل را روشن کنید» بی گفتنِ این، کاربر را
    // به تنظیمی می‌فرستد که همین حالا هم روشن است و کاری نمی‌کند.
    let no_transport = matches!(
        shape,
        TorShape::FacingNetwork {
            transport_installed: false,
            ..
        }
    );
    if no_transport {
        return match snap.percent {
            Some(p) if !snap.done => format!(
                "Tor stopped at {p}% and could not reach the Tor network. No pluggable transport \
                 is installed, so only plain bridges can be tried — and a network that filters \
                 Tor usually blocks those too. Use the Aether \u{2192} Tor mode: Tor is then \
                 dialled through the tunnel, where the operator cannot see or block it."
            ),
            _ => "The engine started but Tor never reported any progress towards the Tor \
                  network, and no pluggable transport is installed. Use the Aether \u{2192} Tor \
                  mode, which builds Tor inside the tunnel."
                .to_string(),
        };
    }
    match snap.percent {
        // `err_tor_no_progress` — موتور اجرا شد و تور یک کلمه هم نگفت.
        None => "The engine started but Tor never reported any progress towards the Tor \
                 network. Check that the connection is up, then try the Aether \u{2192} Tor \
                 mode, which builds Tor inside the tunnel."
            .to_string(),
        // `err_tor_blocked` — عددی که تور روی آن ایستاد، مهم‌ترین چیزی است که
        // کاربر می‌تواند بگوید؛ حذفش پیام را به یک «نشد» تبدیل می‌کرد.
        Some(p) if !snap.done => format!(
            "Tor stopped at {p}% and could not reach the Tor network. This is what a network \
             that filters Tor looks like. Turn bridges on under Tor settings, or use the \
             Aether \u{2192} Tor mode: Tor is then dialled through the tunnel, where the \
             operator cannot see or block it."
        ),
        _ => "Tor reached the network but no stream would open through it. Try again, or pick \
              another exit country."
            .to_string(),
    }
}

/// مقاصدِ سنجهٔ استیج ۱ — عمداً **نام**، نه نشانی. رجوع به توضیحِ
/// درونِ [`run_proxy_stage_with_grace`].
const STAGE_ONE_TARGETS: [(&str, u16); 2] = [("cloudflare.com", 80), ("www.gstatic.com", 80)];

/// دروازهٔ استیج ۱ — معادل `Diagnostics.runProxyStage` اندروید.
///
/// پیش از اجرای Psiphon باید ثابت شود که موتور روی [port] یک پروکسی SOCKS5
/// **کارکنده** است: پورت باز، دست‌دادن درست، و یک TCP واقعی به بیرون.
///
/// عمداً خودآزمای کامل نیست: خروجی، DNS و نشانِ پرچم همه به استیج ۲ تعلق دارند،
/// و اجرای یک geo lookup اینجا هم هر اتصال را کُند می‌کرد و هم کشور **هاپ اول**
/// را روی نشان می‌کشید — یعنی همان چیزی که کاربر زنجیره را برای عوض‌کردنش
/// انتخاب کرده.
pub fn run_proxy_stage(port: u16) -> bool {
    run_proxy_stage_with_grace(port, 0, &|| true, &|| false)
}

/// همان دروازه، با پنجرهٔ انتظارِ [`await_socks_handshake`].
///
/// نشست زنجیره‌ای `Tor → Psiphon` بدون این کار نمی‌کرد: استیج ۱ آنجا تور است
/// و Psiphon از داخلش dial می‌کند، پس شروع Psiphon پیش از آماده شدن تور یعنی
/// سه دقیقه تلاش در تاریکی و شکستی که در جای اشتباه ظاهر می‌شود.
pub fn run_proxy_stage_with_grace(
    port: u16,
    grace_ms: u64,
    alive: &dyn Fn() -> bool,
    abort: &dyn Fn() -> bool,
) -> bool {
    DiagnosticsLog::i(
        TAG,
        &format!("Stage 1 check: is 127.0.0.1:{port} a working SOCKS5 proxy?"),
    );
    if !probe::socks_ready(port) {
        DiagnosticsLog::e(
            TAG,
            &format!("stage 1: nothing listening on 127.0.0.1:{port}"),
        );
        return false;
    }
    if !await_socks_handshake(port, grace_ms, alive, abort) {
        DiagnosticsLog::e(
            TAG,
            &format!("stage 1: 127.0.0.1:{port} is open but does not speak SOCKS5"),
        );
        return false;
    }
    // >>> AETHER-APP-PATCH stage-one-check-asks-by-name
    // پیش‌تر این‌جا `tcp_via_proxy_on(port, "1.1.1.1", 80)` بود — یک آی‌پیِ خام از
    // دلِ تور. خودِ تور در لاگِ ۱۷ سپتامبر به همین اعتراض کرد:
    //
    //     Your application (using socks5 to port 80) is giving Tor only an IP
    //     address. Applications that do DNS resolves themselves may leak
    //     information.
    //
    // پس مقصد در یک سنجهٔ استیج ۱ باید نام باشد، نه نشانی:
    // `socks5_stream_on` برای نام `ATYP=DOMAIN` می‌فرستد، پس resolve از راهِ
    // دور و درونِ همان حامل انجام می‌شود — هم بی‌نشتی، هم همان چیزی که
    // استیج ۲ لحزه‌ای بعد لازم دارد. دو مقصد، چون یک خروجیِ تور می‌تواند
    // یکیِ معین را رد کند و آن دربارهٔ حامل چیزی نمی‌گوید.
    // After Tor reports 100%, a circuit may still reject its first stream.
    // The field log showed two 4s probes failing immediately after bootstrap,
    // while later Tor-only traffic through the same installation succeeded.
    // Retry ONLY the Tor-fronted chain: non-Tor stages keep the original fast gate.
    // Every target is sent as SOCKS5 ATYP=DOMAIN; no local DNS resolution.
    let tor_targets: [(&str, u16); 3] = [
        ("cloudflare.com", 443),
        ("www.gstatic.com", 443),
        ("cloudflare.com", 80),
    ];
    let targets: &[(&str, u16)] = if grace_ms > 0 {
        &tor_targets
    } else {
        &STAGE_ONE_TARGETS
    };
    let stream_deadline = Instant::now() + Duration::from_secs(25);
    let mut working = false;
    loop {
        for (host, dest) in targets {
            if !alive() || abort() {
                break;
            }
            if probe::tcp_via_proxy_on(port, host, *dest) {
                working = true;
                break;
            }
            if grace_ms > 0 && Instant::now() >= stream_deadline {
                break;
            }
        }
        if working || grace_ms == 0 || !alive() || abort() || Instant::now() >= stream_deadline {
            break;
        }
        DiagnosticsLog::w(
            TAG,
            "Tor has a circuit but its exit did not open a stream yet; retrying a fresh stream.",
        );
        std::thread::sleep(Duration::from_millis(750));
    }
    if !working {
        DiagnosticsLog::e(
            TAG,
            &format!("stage 1: 127.0.0.1:{port} speaks SOCKS5 but cannot reach the internet"),
        );
        return false;
    }
    // <<< AETHER-APP-PATCH stage-one-check-asks-by-name
    DiagnosticsLog::i(TAG, "Stage 1 is a working SOCKS5 proxy — starting stage 2.");
    true
}

/// معادل `Diagnostics.resetChecks()`.
pub fn reset_checks() {
    DiagnosticsLog::set_checks(vec![
        (
            C_PORT,
            format!("SOCKS5 port 127.0.0.1:{}", engine::exit_socks_port()),
        ),
        (C_HANDSHAKE, "SOCKS5 handshake".to_string()),
        (C_TCP, "TCP via proxy (1.1.1.1:80)".to_string()),
        (C_DNS, "DNS + HTTP via tunnel".to_string()),
        (C_LEAK, "WebRTC / UDP leak".to_string()),
    ]);
}

#[derive(Debug, Clone)]
pub struct SelfTestOutcome {
    pub ok: bool,
    pub exit: Option<probe::IpInfo>,
    pub latency_ms: Option<u64>,
    /// v1.2.0 — نتیجهٔ سنجش نشتی WebRTC در همان خودآزما.
    pub leak: Option<LeakReport>,
}

/// گزارش نشتی WebRTC/UDP — هم در خودآزما و هم با دکمهٔ اختصاصی پنل عیب‌یابی.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakReport {
    /// true یعنی یک آی‌پیِ غیرِ تونل از راه UDP مستقیم دیده شد.
    pub leaking: bool,
    /// آی‌پی‌ای که یک صفحهٔ وب می‌توانست ببیند (ماسک‌نشده — فقط برای UI).
    pub ip: Option<String>,
    pub server: Option<String>,
    pub detail: String,
}

/// مهلت پاسخ STUN — WebRTC هم بیشتر از این صبر نمی‌کند.
const STUN_TIMEOUT_MS: u64 = 2_500;

/// همان کاری که مرورگر هنگام ساختن نامزد srflx می‌کند: یک درخواست STUN روی
/// UDP خام. اگر جواب بیاید یعنی مسیر مستقیم باز است و آی‌پی برگشته همان چیزی
/// است که سایت‌ها می‌بینند؛ اگر با آی‌پی خروجی تونل یکی نباشد، نشتی است.
pub fn webrtc_leak_check(exit_ip: Option<&str>) -> LeakReport {
    let guard = leakguard::status();
    match probe::stun_reflexive_ip(Duration::from_millis(STUN_TIMEOUT_MS)) {
        None => LeakReport {
            leaking: false,
            ip: None,
            server: None,
            detail: if guard.firewall_rules > 0 {
                "no reply — Windows firewall kill-switch blocked direct UDP".to_string()
            } else if guard.browser_policies > 0 {
                "no reply — browser policy blocked direct UDP".to_string()
            } else {
                "no reply — direct UDP is blocked".to_string()
            },
        },
        Some(r) => {
            let via_tunnel = exit_ip.map(|e| e == r.reflexive_ip).unwrap_or(false);
            // Aether's raw UDP probe is not a browser process. A browser policy
            // intentionally does not affect this probe; when the policy is active
            // we must not mislabel a browser as leaking just because Aether itself
            // can open UDP. The firewall path is the hard, process-independent
            // guarantee and is handled above when it blocks the probe.
            let browser_policy_only = guard.firewall_rules == 0 && guard.browser_policies > 0;
            // خطِ لولهٔ تور: بلوکِ UDP **آگاهانه** فقط روی مرورگرها بسته شده،
            // چون بلوکِ سیستمی ترابرهای خودِ برنامه را هم می‌کشد. پس جوابِ
            // STUN به پروبِ خودمان انتظارِ طرح است، نه نشتی. لاگِ ۱۶ سپتامبر
            // ۲۰:۰۶ نشستی را نشان می‌دهد که تا `TCP via proxy: OK` رفت و بعد
            // با همین داوری رد شد — نشستی که خودمان این‌طور خواسته بودیم.
            //
            // شرطِ `browser_policies > 0` عمدی است: اگر هیچ حفاظتی نصب نشده
            // باشد، این تخفیف داده نمی‌شود و اتصال مثل قبل بسته می‌شود.
            let udp_open_by_design = guard.udp_browser_scoped && guard.browser_policies > 0;
            let leaking = !via_tunnel && !browser_policy_only && !udp_open_by_design;
            LeakReport {
                leaking,
                ip: Some(r.reflexive_ip.clone()),
                server: Some(r.server.clone()),
                detail: if via_tunnel {
                    format!("STUN answered with the tunnel exit ({})", r.reflexive_ip)
                } else if browser_policy_only {
                    "browser WebRTC policy is active; restart the browser to reload it".to_string()
                } else if udp_open_by_design {
                    format!(
                        "UDP is open for this app's own transports by design (Tor pipeline); the \
                         browser WebRTC policy is what covers the browser. {} answered from {}; \
                         restart the browser if it was already running.",
                        r.server, r.reflexive_ip
                    )
                } else {
                    format!("real IP {} reachable via {}", r.reflexive_ip, r.server)
                },
            }
        }
    }
}

/// معادل `Diagnostics.run()` — دروازهٔ اعلام Connected.
pub fn self_test(grace_ms: u64) -> SelfTestOutcome {
    let generation = SELF_TEST_GEN.load(std::sync::atomic::Ordering::SeqCst);
    reset_checks();
    DiagnosticsLog::i(TAG, "Starting connectivity self-test…");

    // ۱) پورت SOCKS5
    DiagnosticsLog::update_check(C_PORT, "RUNNING", None);
    let port_open = probe::socks_ready(engine::exit_socks_port());
    if port_open {
        DiagnosticsLog::update_check(C_PORT, "PASS", Some("listening"));
        DiagnosticsLog::i(TAG, "SOCKS5 port check: open");
    } else {
        DiagnosticsLog::update_check(C_PORT, "FAIL", Some("no listener"));
        DiagnosticsLog::e(
            TAG,
            "SOCKS5 port check: nothing is listening — the engine is not up.",
        );
        DiagnosticsLog::update_check(C_HANDSHAKE, "FAIL", Some("skipped"));
        DiagnosticsLog::update_check(C_TCP, "FAIL", Some("skipped"));
        DiagnosticsLog::update_check(C_DNS, "FAIL", Some("skipped"));
        DiagnosticsLog::update_check(C_LEAK, "FAIL", Some("skipped"));
        return SelfTestOutcome {
            ok: false,
            exit: None,
            latency_ms: None,
            leak: None,
        };
    }

    // ۲) دست‌دادن SOCKS5
    DiagnosticsLog::update_check(C_HANDSHAKE, "RUNNING", None);
    let hs = probe::socks_handshake_ok();
    if hs {
        DiagnosticsLog::update_check(C_HANDSHAKE, "PASS", Some("method accepted"));
        DiagnosticsLog::i(TAG, "SOCKS5 handshake: OK");
    } else {
        DiagnosticsLog::update_check(C_HANDSHAKE, "FAIL", Some("no SOCKS5 reply"));
        DiagnosticsLog::e(
            TAG,
            "SOCKS5 handshake failed — the port is open but it is not a SOCKS5 server.",
        );
    }

    // ۳+۴) TCP و DNS/HTTP — با تلاش مجدد در پنجرهٔ گریس (معادل اجرای هم‌زمان موبایل)
    DiagnosticsLog::update_check(C_TCP, "RUNNING", None);
    DiagnosticsLog::update_check(C_DNS, "RUNNING", None);
    let deadline = Instant::now() + Duration::from_millis(grace_ms);
    let mut tcp_ok = false;
    let mut dns: Option<(probe::IpInfo, u64)> = None;
    loop {
        if !tcp_ok {
            // AETHER-APP-FIX tor-proves-its-exit: در پنجرهٔ بلند (تور/زنجیره) سنجهٔ
            // TCP هم مهلتِ بلندتر می‌گیرد؛ اینجا سنجه‌ها پشتِ‌سرِ‌هم‌اند، نه
            // هم‌زمان مثلِ موبایل، پس ۴ ثانیه روی مدارِ تازه یعنی بریدنِ استریمی
            // که داشت می‌رسید.
            tcp_ok = if grace_ms >= EXTERNAL_GRACE_MS {
                probe::tcp_via_proxy_within("1.1.1.1", 80, Duration::from_secs(12))
            } else {
                probe::tcp_via_proxy("1.1.1.1", 80)
            };
            if tcp_ok {
                DiagnosticsLog::update_check(C_TCP, "PASS", Some("connected"));
                DiagnosticsLog::i(TAG, "TCP via proxy: OK");
            }
        }
        if dns.is_none() {
            let started = Instant::now();
            // A Tor -> Aether route crosses Tor, TLS and the WARP carrier;
            // the former 6s budget could reject a verified data-plane solely
            // because the HTTPS geo request was still in its handshake.
            // Keep the shorter budget for a normal single-hop connection.
            let geo_timeout_ms = if grace_ms >= EXTERNAL_GRACE_MS {
                15_000
            } else {
                6_000
            };
            if let Some(info) = probe::fetch_ip_via_socks(geo_timeout_ms) {
                let ms = started.elapsed().as_millis() as u64;
                let cc = info
                    .country_code
                    .clone()
                    .unwrap_or_else(|| "??".to_string());
                DiagnosticsLog::update_check(
                    C_DNS,
                    "PASS",
                    Some(&format!("exit {} {}", info.ip, cc)),
                );
                // v8 audit: the full IP stays in the UI check detail only; the
                // persistent log gets a masked last octet.
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "DNS+HTTP via tunnel: OK — exit {} {} ({} ms)",
                        mask_ip(&info.ip),
                        cc,
                        ms
                    ),
                );
                dns = Some((info, ms));
            }
        }
        if tcp_ok && dns.is_some() {
            break;
        }
        if Instant::now() >= deadline || self_test_cancelled(generation) {
            break;
        }
        std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
    }

    if !tcp_ok {
        DiagnosticsLog::update_check(
            C_TCP,
            "FAIL",
            Some("could not reach 1.1.1.1:80 through the proxy"),
        );
        DiagnosticsLog::e(
            TAG,
            "TCP via proxy failed — the engine accepted the connection but no upstream is flowing.",
        );
    }
    let ok = dns.is_some();
    if !ok {
        DiagnosticsLog::update_check(C_DNS, "FAIL", Some("no HTTP response through the tunnel"));
        if tcp_ok {
            DiagnosticsLog::w(
                TAG,
                "Raw TCP works, but the HTTPS exit-IP probe failed (DNS, TLS, HTTP or remote service); cause not yet known.",
            );
        } else {
            DiagnosticsLog::w(
                TAG,
                "No outbound path at all — the tunnel has no upstream yet.",
            );
        }
    }

    let (exit, latency_ms) = match dns {
        Some((info, ms)) => (Some(info), Some(ms)),
        None => (None, None),
    };

    // ۵) نشتی WebRTC — رفع ریشه‌ای ۱.۲.۰ باید *اثبات* شود، نه ادعا.
    DiagnosticsLog::update_check(C_LEAK, "RUNNING", None);
    let leak = webrtc_leak_check(exit.as_ref().map(|e| e.ip.as_str()));
    if leak.leaking {
        let masked = leak.ip.as_deref().map(mask_ip).unwrap_or_default();
        DiagnosticsLog::update_check(C_LEAK, "FAIL", Some("real IP still reachable over UDP"));
        DiagnosticsLog::e(
            TAG,
            &format!(
                "WebRTC leak: a STUN server answered with {masked} over direct UDP. Enable the leak guard, or restart the browser so the new policy is picked up."
            ),
        );
    } else if leakguard::status().udp_browser_scoped && leak.ip.is_some() {
        // نشتی نیست، ولی «تمیزِ» بی‌قید هم نیست: در این حالت مرورگرِ از قبل
        // بازمانده تا وقتی بسته و باز نشود سیاست را نخوانده است.
        DiagnosticsLog::update_check(C_LEAK, "PASS", Some(&leak.detail));
        DiagnosticsLog::w(TAG, &format!("WebRTC / UDP leak check: {}", leak.detail));
    } else {
        DiagnosticsLog::update_check(C_LEAK, "PASS", Some(&leak.detail));
        DiagnosticsLog::i(
            TAG,
            &format!("WebRTC / UDP leak check: clean — {}", leak.detail),
        );
    }

    // Never report CONNECTED when the leak check failed. The previous build
    // only painted the warning red while still declaring the tunnel healthy.
    // That was the most dangerous part of the bug.
    let ok = ok && !leak.leaking;
    SelfTestOutcome {
        ok,
        exit,
        latency_ms,
        leak: Some(leak),
    }
}

/// v8 audit: "1.2.3.4" -> "1.2.3.xxx" for the persistent rotating log so a
/// leaked log file cannot reveal the exact exit IP. IPv6 keeps only the /48.
fn mask_ip(ip: &str) -> String {
    if let Some((head, _)) = ip.rsplit_once('.') {
        return format!("{head}.xxx");
    }
    if ip.contains(':') {
        let parts: Vec<&str> = ip.split(':').take(3).collect();
        return format!("{}::xxxx", parts.join(":"));
    }
    ip.to_string()
}

// ---------------------------------------------------------------------------
// گزارش محیطی دسکتاپ (مکمل، مخصوص ویندوز) — همان گزارش قبلی حفظ شده
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub name: String,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub checks: Vec<Check>,
    pub summary: String,
}

fn check(name: &str, verdict: Verdict, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        verdict,
        detail: detail.into(),
    }
}

/// گزارش سلامت محیط نصب — دکمهٔ «Environment check».
pub fn run(profile: &ConnectionProfile) -> Report {
    let mut checks = Vec::new();

    // ۱) باینری موتور
    let engine_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("engine").join("aether.exe")));
    checks.push(match &engine_exe {
        Some(p) if p.exists() => check("Engine binary", Verdict::Pass, p.display().to_string()),
        Some(p) => check(
            "Engine binary",
            Verdict::Fail,
            format!("Missing: {}", p.display()),
        ),
        None => check(
            "Engine binary",
            Verdict::Fail,
            "Could not resolve the install directory",
        ),
    });

    // ۲) درایور Wintun — اختیاری؛ مسیر دادهٔ اصلی پروکسی سیستمی است
    let wintun = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("engine").join("wintun.dll")));
    checks.push(match &wintun {
        Some(p) if p.exists() => check("Wintun driver", Verdict::Pass, "Present"),
        _ => check(
            "Wintun driver",
            Verdict::Warn,
            "wintun.dll missing — system-proxy mode still works",
        ),
    });

    // ۳) دسترسی مدیر — فقط برای آداپتور Wintun لازم است، نه برای اتصال
    checks.push(if is_elevated() {
        check("Administrator rights", Verdict::Pass, "Running elevated")
    } else {
        check(
            "Administrator rights",
            Verdict::Warn,
            "Not elevated — connection uses the Windows system proxy instead of a TUN adapter",
        )
    });

    // ۴) پورت SOCKS5 محلی
    checks.push(if probe::socks_ready(engine::exit_socks_port()) {
        check(
            "Local SOCKS5",
            Verdict::Pass,
            format!("127.0.0.1:{}", engine::exit_socks_port()),
        )
    } else {
        check(
            "Local SOCKS5",
            Verdict::Warn,
            "Not listening (expected while disconnected)",
        )
    });

    // ۵) خروج واقعی
    checks.push(match probe::verify_egress() {
        Some(r) => check(
            "Tunnel egress",
            Verdict::Pass,
            format!("{} in {} ms", r.endpoint, r.latency_ms),
        ),
        None => check("Tunnel egress", Verdict::Warn, "No verified egress yet"),
    });

    // ۶) سلامت پروفایل
    checks.push(if profile.mtu >= 576 && profile.mtu <= 9000 {
        check("Profile", Verdict::Pass, format!("MTU {}", profile.mtu))
    } else {
        check(
            "Profile",
            Verdict::Warn,
            format!("Unusual MTU: {}", profile.mtu),
        )
    });

    // ۶.۵) هویتِ ساخت — ۱.۲.۵
    //
    // بی این سطر، «کدام بیلد؟» یک پرسشِ بی‌پاسخ در هر گزارشِ خطاست. موتور سطحِ
    // پچِ خودش را در دومین سطرِ خروجی‌اش چاپ می‌کند و `provenance.rs` آن را با
    // سطحِ پچِ برنامه می‌سنجد؛ این‌جا همان حکم به گزارشِ محیط می‌آید.
    checks.push(match crate::provenance::engine_patch_level() {
        Some(engine) if crate::provenance::consistent() => check(
            "Build identity",
            Verdict::Pass,
            format!(
                "app {} runs the bundled, unmodified Aether core {engine}",
                crate::provenance::APP_PATCH_LEVEL
            ),
        ),
        Some(engine) => check(
            "Build identity",
            Verdict::Fail,
            format!(
                "WRONG ENGINE: this app ships Aether core {} but aether.exe reports {engine}. \
                 Reinstall so the engine and the app match.",
                crate::provenance::expected_core_version()
            ),
        ),
        // موتور هنوز حرف نزده — پیش از نخستین اتصال حالتِ عادی است.
        None => check(
            "Build identity",
            Verdict::Warn,
            format!(
                "app patch level {}; the engine has not reported its core version yet",
                crate::provenance::APP_PATCH_LEVEL
            ),
        ),
    });

    // ۷) گارد نشتی WebRTC — v1.2.0
    let guard = leakguard::status();
    checks.push(if guard.engaged && guard.firewall_rules > 0 {
        check(
            "Leak guard",
            Verdict::Pass,
            format!(
                "{} firewall rule(s) + {} browser policy value(s) active",
                guard.firewall_rules, guard.browser_policies
            ),
        )
    } else if guard.engaged {
        check(
            "Leak guard",
            Verdict::Warn,
            format!(
                "{} browser policy value(s) active; firewall layer needs administrator rights",
                guard.browser_policies
            ),
        )
    } else {
        check(
            "Leak guard",
            Verdict::Warn,
            "Not engaged (expected while disconnected)",
        )
    });

    let failed = checks.iter().filter(|c| c.verdict == Verdict::Fail).count();
    let warned = checks.iter().filter(|c| c.verdict == Verdict::Warn).count();
    let summary = if failed > 0 {
        format!("{failed} blocking problem(s) found")
    } else if warned > 0 {
        format!("{warned} warning(s), nothing blocking")
    } else {
        "Everything looks healthy".to_string()
    };

    Report { checks, summary }
}

#[cfg(windows)]
pub(crate) fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub(crate) fn is_elevated() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ۱.۲.۵: این تست فقط یک عدد را می‌شمرد (۷)، و عددِ برهنه نمی‌گوید کدام
    /// بررسی گم شده است. حالا نام‌ها را می‌سنجد — پس افزودنِ «هویتِ ساخت» یک
    /// تغییرِ آگاهانه است و حذفِ بی‌صدای یک بررسیِ دیگر هم گرفته می‌شود.
    #[test]
    fn report_always_has_every_check() {
        let r = run(&ConnectionProfile::default());
        let names: Vec<&str> = r.checks.iter().map(|c| c.name.as_str()).collect();
        for expected in ["Build identity", "Profile", "Leak guard", "Tunnel egress"] {
            assert!(
                names.contains(&expected),
                "check `{expected}` is missing from {names:?}"
            );
        }
        assert_eq!(r.checks.len(), 8, "checks were {names:?}");
        assert!(!r.summary.is_empty());
    }

    #[test]
    fn reset_populates_every_live_check() {
        reset_checks();
        let checks = DiagnosticsLog::checks();
        // ۴ بررسی اندروید + بررسی نشتی WebRTC که در ۱.۲.۰ اضافه شد.
        assert_eq!(checks.len(), 5);
        assert!(checks.iter().any(|c| c.id == C_LEAK));
        assert!(checks.iter().all(|c| c.state == "PENDING"));
    }

    /// سطرِ واقعیِ لاگ میدانیِ ۱۵ سپتامبر — همان‌جا که تور ایستاد.
    const FIELD_LINE_15: &str = "1789462449037 D/engine: [2026-09-15T08:54:09.037Z INFO  \
                                 aether::tor::with_tor] [*] tor reaching the network: 15%: \
                                 connecting successfully; directory is fetching a consensus";

    fn at_15() {
        crate::tor_bootstrap::reset();
        crate::tor_bootstrap::ingest(FIELD_LINE_15);
        assert_eq!(crate::tor_bootstrap::snapshot().percent, Some(15));
    }

    /// بی تور، همان پیام قدیمی — این مسیر عوض نشده.
    #[test]
    fn without_tor_the_message_is_the_tunnel_self_test() {
        let msg = stage_failure_message(None);
        assert!(msg.contains("self-test"), "{msg}");
        assert!(!msg.contains("Tor"), "{msg}");
    }

    /// `Aether → Tor`: تونل ثابت‌شده بالاست. توصیهٔ «پل را روشن کن» اینجا غلط
    /// است — پل در این حالت هیچ نقشی ندارد؛ و درصدِ گیرکرده باید در پیام باشد،
    /// چون تنها چیزی است که کاربر می‌تواند گزارش کند.
    #[test]
    fn tor_inside_the_tunnel_never_advises_bridges() {
        at_15();
        let msg = stage_failure_message(Some(TorShape::ThroughTunnel));
        assert!(msg.contains("15%"), "{msg}");
        assert!(msg.contains("tunnel is up"), "{msg}");
        assert!(!msg.to_lowercase().contains("bridges on"), "{msg}");
        // و نباید همان چیزی را پیشنهاد کند که کاربر همین حالا در آن است.
        assert!(!msg.contains("Aether \u{2192} Tor"), "{msg}");
    }

    /// تورِ روبروی شبکه، با ترابرِ نصب‌شده: پل واقعاً گزینه است، پس پیام آن را
    /// پیشنهاد می‌دهد.
    #[test]
    fn tor_facing_the_network_with_a_transport_advises_bridges() {
        at_15();
        let msg = stage_failure_message(Some(TorShape::FacingNetwork {
            bridges_allowed: true,
            transport_installed: true,
        }));
        assert!(msg.contains("15%"), "{msg}");
        assert!(msg.contains("bridges on"), "{msg}");
        assert!(!msg.contains("No pluggable transport"), "{msg}");
    }

    /// همان تور، بی ترابر: «پل را روشن کن» به تنظیمی می‌فرستد که کاری نمی‌کند.
    /// پیام باید بگوید فقط پلِ ساده می‌ماند و راهِ واقعی کدام است.
    #[test]
    fn tor_without_a_transport_says_bridges_cannot_run_properly() {
        at_15();
        let msg = stage_failure_message(Some(TorShape::FacingNetwork {
            bridges_allowed: true,
            transport_installed: false,
        }));
        assert!(msg.contains("15%"), "{msg}");
        assert!(msg.contains("No pluggable transport"), "{msg}");
        assert!(msg.contains("plain bridges"), "{msg}");
        assert!(msg.contains("Aether \u{2192} Tor"), "{msg}");
    }

    /// موتور اجرا شد و تور یک کلمه هم نگفت — سه شکل، سه پیام، و هیچ‌کدام
    /// نباید درصدِ ساختگی بسازد.
    #[test]
    fn a_silent_tor_never_invents_a_percentage() {
        for shape in [
            TorShape::ThroughTunnel,
            TorShape::FacingNetwork {
                bridges_allowed: true,
                transport_installed: true,
            },
            TorShape::FacingNetwork {
                bridges_allowed: false,
                transport_installed: false,
            },
        ] {
            crate::tor_bootstrap::reset();
            let msg = stage_failure_message(Some(shape));
            assert!(!msg.contains('%'), "{shape:?}: {msg}");
            assert!(
                msg.contains("never reported any progress"),
                "{shape:?}: {msg}"
            );
        }
    }

    /// وقتی هیچ پاسخی از STUN نیاید، یعنی UDP مستقیم بسته است — نشتی نداریم.
    #[test]
    fn no_stun_reply_is_not_a_leak() {
        let r = LeakReport {
            leaking: false,
            ip: None,
            server: None,
            detail: "no reply — direct UDP is blocked".to_string(),
        };
        assert!(!r.leaking);
    }
}
