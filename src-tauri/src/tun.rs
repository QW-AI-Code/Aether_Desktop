//! معادل ویندوزیِ `vpn/AetherVpnService.kt` + `core/HevTunnel.kt`.
//!
//! در اندروید:  VpnService.Builder → دسکریپتور TUN → hev-socks5-tunnel → SOCKS5 موتور
//! در ویندوز:   Wintun adapter    → نشست Wintun    → ipstack        → SOCKS5 موتور
//!
//! رفتارهای امنیتی ۱.۲.۲ که باید عیناً حفظ شوند:
//!   * DNS اجباراً از داخل تونل می‌رود و پیش از اعلام «متصل» راستی‌آزمایی می‌شود.
//!   * Split tunnelling پیش‌فرض خاموش است.
//!   * MTU پیش‌فرض 1280.
//!
//! # اصلاح ۱.۲.۰ — لاگی که دروغ می‌گفت
//! تا ۱.۱.۰ این فایل بی‌قید‌و‌شرط می‌نوشت:
//!   «Default routes captured: 0.0.0.0/0 and ::/0»
//! در حالی که هیچ آدرس، مسیر یا DNS ای واقعاً نصب نمی‌شد — فقط یک آداپتور
//! Wintun ساخته می‌شد. همین سطرِ نادرست باعث شد نشتی WebRTC ماه‌ها در لاگ
//! نامرئی بماند: کاربر «مسیر پیش‌فرض گرفته شد» می‌دید ولی UDP همچنان از
//! کارت فیزیکی بیرون می‌رفت.
//!
//! حالا این فایل فقط چیزی را گزارش می‌کند که واقعاً انجام داده است؛ و تا
//! وقتی رلهٔ فضای‌کاربرِ TUN→SOCKS5 وصل نشده، عمداً مسیر پیش‌فرض را نمی‌گیرد
//! (گرفتنش بدون رله یعنی سیاه‌چالهٔ کامل ترافیک). مهارِ UDP — یعنی همان چیزی
//! که جلوی نشت WebRTC را می‌گیرد — بر عهدهٔ `leakguard.rs` است.

use crate::log::DiagnosticsLog;
use crate::profile::{ConnectionProfile, SplitMode};
use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// همان آدرس‌های داخلیِ TunnelConfig.kt.
pub const TUN_IPV4: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);
pub const TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1);
pub const TUN_DNS_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
pub const TUN_DNS_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

const ADAPTER_NAME: &str = "Aether";
const ADAPTER_TYPE: &str = "Aether Tunnel";
/// GUID ثابت: ویندوز با این GUID همیشه همان آداپتور را بازشناسی می‌کند،
/// پس تنظیمات شبکهٔ کاربر بین اجراها پاک نمی‌شود.
const ADAPTER_GUID: u128 = 0x7f1e_3c22_9a54_4d61_b0f3_9c2e_1a8d_47b5;

pub struct Tunnel {
    adapter: Arc<wintun::Adapter>,
    session: Option<Arc<wintun::Session>>,
    /// معادل شمارنده‌های TrafficPanel.kt (دریافت/ارسال).
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
}

impl Tunnel {
    /// معادل `VpnService.Builder.establish()`.
    ///
    /// نیازمند دسترسی Administrator است — دقیقاً معادل دیالوگ مجوز VPN
    /// در اندروید. برنامه در صورت نیاز خودش درخواست ارتقا می‌دهد.
    pub fn establish(profile: &ConnectionProfile, wintun_dll: &std::path::Path) -> Result<Self> {
        // AETHER-APP-FIX wintun-root-cause (1.4.0): the old code printed
        // "administrator rights required" for EVERY failure -- even though the
        // manifest is requireAdministrator -- and `{e}` hid the real OS error.
        // Now: (1) the DLL must exist and load; (2) an adapter left over from a
        // previous/crashed session is REUSED (Wintun refuses to create a second
        // one with the same name -> ERROR_ALREADY_EXISTS); (3) creation is
        // retried because the driver install races with SetupAPI right after
        // boot/update; (4) the final error carries the whole cause chain, the
        // raw OS code and the real elevation state.
        if !wintun_dll.is_file() {
            anyhow::bail!("wintun.dll not found at {}", wintun_dll.display());
        }
        let lib = unsafe { wintun::load_from_path(wintun_dll) }
            .with_context(|| format!("could not load {}", wintun_dll.display()))?;

        let adapter = match wintun::Adapter::open(&lib, ADAPTER_NAME) {
            Ok(a) => {
                DiagnosticsLog::i("tun", "Re-using the existing Aether Wintun adapter");
                a
            }
            Err(_) => {
                let mut last: Option<wintun::Error> = None;
                let mut made = None;
                for attempt in 0..3u32 {
                    match wintun::Adapter::create(&lib, ADAPTER_NAME, ADAPTER_TYPE, Some(ADAPTER_GUID))
                    {
                        Ok(a) => {
                            made = Some(a);
                            break;
                        }
                        Err(e) => {
                            DiagnosticsLog::w(
                                "tun",
                                &format!("Wintun create attempt {} failed: {e}", attempt + 1),
                            );
                            last = Some(e);
                            std::thread::sleep(std::time::Duration::from_millis(400));
                            // The adapter may have appeared meanwhile.
                            if let Ok(a) = wintun::Adapter::open(&lib, ADAPTER_NAME) {
                                made = Some(a);
                                break;
                            }
                        }
                    }
                }
                match made {
                    Some(a) => a,
                    None => {
                        let e = last.map(|e| e.to_string()).unwrap_or_default();
                        let code = os_code_of(&e);
                        return Err(anyhow::anyhow!(
                            "{}",
                            describe_create_failure(&e, code, crate::diagnostics::is_elevated())
                        ));
                    }
                }
            }
        };

        // ۱.۲.۵-perf — ظرفیتِ رینگ از بزرگ‌ترین مقدارِ ممکن به کوچک‌ترین آمد.
        //
        // `MAX_RING_CAPACITY` بزرگ‌ترین ظرفیتی است که Wintun می‌پذیرد و برای
        // *هر جهت* یک بافر جدا تخصیص می‌شود. سؤال درست این نبود که «چقدر
        // بگیریم» بلکه این بود که «چه کسی از آن می‌خواند» — و پاسخ، در تمامِ
        // `src-tauri/src/`، هیچ‌کس است: تنها راهِ رسیدن به نشست، `session()`
        // است و هیچ فراخوانی‌ای برای آن وجود ندارد؛ نه حلقهٔ خواندنی هست، نه
        // `receive_blocking`ی.
        //
        // و این اتفاقی نیست: خودِ همین فایل چند سطر پایین‌تر می‌گوید مسیر
        // دادهٔ فعلی پروکسی سیستمی (TCP) است و مسیر پیش‌فرض گرفته نمی‌شود.
        // آداپتور فقط برای آدرس و DNS داخلی بالا می‌آید. پس آن بافرها حافظه‌ای
        // بودند که گرفته می‌شد، پُر می‌شد (آداپتور آدرس دارد، پس ویندوز به آن
        // بسته تحویل می‌دهد) و هرگز تخلیه نمی‌شد.
        //
        // کوچک‌ترین ظرفیت و نه حذفِ کاملِ نشست: `session()` یک API عمومی است و
        // برداشتنش تصمیمِ دیگری است. رجوع به یادداشتِ بالای این فایل.
        let session = adapter
            .start_session(wintun::MIN_RING_CAPACITY)
            .context("could not start the Wintun session")?;

        DiagnosticsLog::i(
            "tun",
            &format!(
                "Wintun adapter up, mtu={} (default {})",
                profile.mtu,
                crate::profile::DEFAULT_MTU
            ),
        );

        let me = Self {
            adapter,
            session: Some(Arc::new(session)),
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
        };
        me.configure_routes(profile)?;
        Ok(me)
    }

    /// معادل `addAddress` / `addRoute` / `addDnsServer` / `addDisallowedApplication`.
    ///
    /// فقط کارهایی انجام و گزارش می‌شود که واقعاً روی سیستم اثر دارند.
    fn configure_routes(&self, profile: &ConnectionProfile) -> Result<()> {
        // آدرس داخلی و DNS آداپتور — بی‌خطر و برگشت‌پذیر (آداپتور با پایان
        // نشست از بین می‌رود). به دسترسی Administrator نیاز دارد؛ شکستش
        // کشنده نیست، فقط صادقانه لاگ می‌شود.
        let addr_ok = netsh(&[
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={ADAPTER_NAME}"),
            "source=static",
            &format!("address={TUN_IPV4}"),
            "mask=255.255.255.0",
        ]);
        let dns_ok = netsh(&[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={ADAPTER_NAME}"),
            "source=static",
            &format!("address={TUN_DNS_V4}"),
            "register=none",
            "validate=no",
        ]);
        DiagnosticsLog::i(
            "tun",
            &format!(
                "Adapter address {}: {} · in-tunnel DNS {}: {}",
                TUN_IPV4,
                if addr_ok {
                    "applied"
                } else {
                    "not applied (needs administrator)"
                },
                TUN_DNS_V4,
                if dns_ok {
                    "applied"
                } else {
                    "not applied (needs administrator)"
                },
            ),
        );

        // ⚠ صداقت: مسیر پیش‌فرض گرفته نمی‌شود. مسیر دادهٔ فعلی پروکسی سیستمی
        // است (TCP)، و نصب 0.0.0.0/0 روی آداپتوری که رله ندارد یعنی قطع کامل
        // اینترنت. مهار UDP با گارد نشتی انجام می‌شود، نه با یک لاگ خوش‌بینانه.
        DiagnosticsLog::i(
            "tun",
            "Default routes NOT captured — data path is the system proxy (TCP). UDP containment is handled by the leak guard.",
        );
        if profile.ipv6_protection {
            DiagnosticsLog::i("tun", "IPv6 protection: global unicast is forced through the protected path or blocked by the kill-switch — no IPv6 leak.");
        } else {
            DiagnosticsLog::w(
                "tun",
                "IPv6 is enabled in the profile: IPv6 egress is left open, so only IPv4 is covered by the proxy path.",
            );
        }

        match profile.split_mode {
            SplitMode::Off => DiagnosticsLog::i("tun", "Split tunnelling: off (default)"),
            SplitMode::Include => DiagnosticsLog::i(
                "tun",
                &format!(
                    "Split tunnelling: only {} go through the tunnel",
                    profile.split_apps.len()
                ),
            ),
            SplitMode::Exclude => DiagnosticsLog::i(
                "tun",
                &format!(
                    "Split tunnelling: {} bypass the tunnel",
                    profile.split_apps.len()
                ),
            ),
        }
        Ok(())
    }

    pub fn session(&self) -> Option<Arc<wintun::Session>> {
        self.session.clone()
    }

    /// بایت‌های دریافتی و ارسالی — همان عددهایی که پنل ترافیک نشان می‌دهد.
    pub fn counters(&self) -> (u64, u64) {
        (
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }

    /// معادل teardown در `AetherVpnService`.
    ///
    /// ترتیب عمداً همان ترتیبی است که در ۱.۲.۲ معکوس شد تا فریز ۳۰–۵۰ ثانیه‌ای
    /// موقع قطع اتصال رفع شود: اول کنسل، بعد کشتن نیتیوها، بعد UI به idle،
    /// و در آخر جمع‌کردن خارج از مسیر بحرانی.
    pub fn close(&mut self) {
        // `Drop` هم همین را صدا می‌زند، پس بارِ دوم باید ساکت باشد: در لاگِ
        // ۱۶ سپتامبر «Wintun adapter torn down» دوبار در یک میلی‌ثانیه چاپ شد،
        // یک‌بار از این‌جا و یک‌بار از Drop، و خواندنِ لاگ را گمراه می‌کرد.
        let had_session = self.session.take().is_some();
        let _ = self.adapter.get_luid();
        if had_session {
            DiagnosticsLog::i("tun", "Wintun adapter torn down");
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.close();
    }
}

/// Pulls N out of an `... (os error N)` Display string (std::io::Error format).
pub fn os_code_of(text: &str) -> i32 {
    text.rsplit("(os error ")
        .next()
        .filter(|_| text.contains("(os error "))
        .and_then(|t| t.split(')').next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Honest failure text: names the elevation state and the raw error instead of
/// always blaming administrator rights. Pure function -> unit-testable.
pub fn describe_create_failure(err: &str, os_code: i32, elevated: bool) -> String {
    let hint = if !elevated {
        "the process is NOT elevated - run Aether as administrator"
    } else if os_code == 183 || err.contains("already exists") {
        "an adapter with this name is still registered - it will be reused on the next attempt; if it persists, remove the stale 'Aether' adapter in Device Manager"
    } else if os_code == 5 || err.to_lowercase().contains("access is denied") {
        "access denied although elevated - security software or a driver policy is blocking the Wintun driver install"
    } else {
        "the Wintun driver could not be installed/started (check antivirus, Core Isolation, and that wintun.dll matches the app architecture)"
    };
    format!("could not create the Wintun adapter: {err} (os error {os_code}, elevated={elevated}) - {hint}")
}

/// اجرای یک دستور netsh بدون بازکردن پنجرهٔ کنسول.
fn netsh(args: &[&str]) -> bool {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;
    #[cfg(windows)]
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("netsh.exe"),
    );
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(test)]
mod failure_text_tests {
    use super::describe_create_failure;
    #[test]
    fn not_elevated_is_the_only_case_that_blames_admin() {
        assert!(describe_create_failure("x", 5, false).contains("NOT elevated"));
        assert!(!describe_create_failure("x", 5, true).contains("NOT elevated"));
    }
    #[test]
    fn parses_os_code() {
        assert_eq!(super::os_code_of("Access is denied. (os error 5)"), 5);
        assert_eq!(super::os_code_of("nothing"), 0);
    }
    #[test]
    fn already_exists_and_denied_are_distinguished() {
        assert!(describe_create_failure("x", 183, true).contains("still registered"));
        assert!(describe_create_failure("x", 5, true).contains("access denied although elevated"));
        assert!(describe_create_failure("boom", 1, true).contains("os error 1"));
    }
}
