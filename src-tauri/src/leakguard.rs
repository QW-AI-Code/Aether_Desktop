//! Leak Guard — رفع ریشه‌ای نشت آی‌پی از راه WebRTC (نسخهٔ ۱.۲.۰).
//!
//! # ریشهٔ باگ
//! مسیر دادهٔ ویندوز در ۱.۱.۰ فقط «پروکسی سیستمی» بود: sysproxy.rs رجیستری
//! WinINET را به پل محلی HTTP↔SOCKS5 اشاره می‌داد. پروکسی WinINET **فقط
//! TCP** را می‌گیرد. WebRTC اما برای ساختن نامزد srflx یک دیتاگرام **UDP
//! خام** به سرور STUN می‌فرستد؛ این بسته هرگز از پروکسی رد نمی‌شود و مستقیم
//! از کارت شبکهٔ فیزیکی بیرون می‌رود. نتیجه: نوار آی‌پی برنامه «آلمان» را
//! نشان می‌داد و همان لحظه WebRTC Leak Test آی‌پی واقعی کاربر (ایران /
//! Asiatech) را لو می‌داد.
//!
//! tun.rs هم کمکی نمی‌کرد: آداپتور Wintun ساخته می‌شد ولی هیچ مسیری نصب
//! نمی‌شد؛ فقط جملهٔ «Default routes captured: 0.0.0.0/0 and ::/0» در لاگ
//! چاپ می‌شد. همین سطرِ نادرست باعث شده بود نشتی در لاگ نامرئی بماند.
//!
//! # درمان (سه لایهٔ مستقل)
//! ۱. **سیاست رسمی مرورگر (بدون نیاز به Administrator).** برای خانوادهٔ
//!    کرومیوم WebRtcIPHandling = disable_non_proxied_udp و برای
//!    فایرفاکس media.peerconnection.ice.proxy_only = 1 زیر
//!    HKCU\Software\Policies نوشته می‌شود: WebRTC حق ندارد UDP غیرپروکسی
//!    بفرستد، پس نامزد srflx اصلاً ساخته نمی‌شود.
//! ۲. **کلید قطع فایروال (در صورت Administrator).** قواعد netsh advfirewall
//!    زیر یک نام مشترک: بستن UDP خروجی خود مرورگرها، بستن پورت‌های STUN/TURN
//!    برای همهٔ برنامه‌ها (اپ‌های الکترون هم پوشش داده می‌شوند) و بستن IPv6
//!    عمومی وقتی پروفایل فقط IPv4 است.
//! ۳. **راستی‌آزمایی (probe.rs + diagnostics.rs).** خود برنامه یک درخواست
//!    STUN واقعی می‌فرستد و اگر پاسخی برگشت، بررسی «WebRTC / UDP leak» قرمز
//!    می‌شود. ادعا نمی‌کنیم — اثبات می‌کنیم.
//!
//! همهٔ تغییرها برگشت‌پذیرند: مقدار قبلی هر کلید در حافظه نگه داشته و هنگام
//! قطع اتصال بازگردانده می‌شود، و purge_stale() در استارتاپ باقی‌ماندهٔ یک
//! کرش را پاک می‌کند — هرگز نباید قاعده‌ای بعد از بستن برنامه بماند.

use crate::log::DiagnosticsLog;
use crate::profile::ConnectionProfile;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const TAG: &str = "leakguard";

/// نام مشترک همهٔ قواعد فایروال — پاک‌سازی با یک دستور انجام می‌شود.
pub const FW_RULE: &str = "Aether Leak Guard";
/// Kill-switch rules intentionally have a separate name so they survive a
/// disconnect while the app is alive, but can be removed independently.
pub const KILL_RULE: &str = "Aether Kill Switch";

/// پورت‌های استاندارد STUN/TURN به‌علاوهٔ بازهٔ سرورهای گوگل — همان پورت‌هایی
/// که ابزارهای «WebRTC Leak Test» از آن‌ها استفاده می‌کنند.
pub const STUN_TURN_PORTS: &str = "3478,3479,5349,5350,19302-19309";

/// نام فایل اجرایی مرورگرها — برای یافتن مسیر کامل از رجیستری App Paths.
const BROWSER_EXES: [&str; 8] = [
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
    "browser.exe",
];

/// مسیرهای نصب متعارف — وقتی App Paths چیزی نداشت.
const BROWSER_PATHS: [&str; 11] = [
    r"Google\Chrome\Application\chrome.exe",
    r"Microsoft\Edge\Application\msedge.exe",
    r"Mozilla Firefox\firefox.exe",
    r"BraveSoftware\Brave-Browser\Application\brave.exe",
    r"Vivaldi\Application\vivaldi.exe",
    r"Chromium\Application\chrome.exe",
    r"Yandex\YandexBrowser\Application\browser.exe",
    r"Opera\opera.exe",
    r"Opera GX\opera.exe",
    r"Programs\Opera\opera.exe",
    r"Programs\Opera GX\opera.exe",
];

/// کلیدهای سیاستِ خانوادهٔ کرومیوم — همگی همان نام سیاست را می‌فهمند.
const CHROMIUM_POLICY_KEYS: [&str; 7] = [
    r"HKCU\Software\Policies\Google\Chrome",
    r"HKCU\Software\Policies\Microsoft\Edge",
    r"HKCU\Software\Policies\BraveSoftware\Brave",
    r"HKCU\Software\Policies\Vivaldi",
    r"HKCU\Software\Policies\Chromium",
    r"HKCU\Software\Policies\Opera Software\Opera",
    r"HKCU\Software\Policies\Yandex\YandexBrowser",
];
const CHROMIUM_POLICY_NAME: &str = "WebRtcIPHandling";
const CHROMIUM_POLICY_VALUE: &str = "disable_non_proxied_udp";

const FIREFOX_PREFS_KEY: &str = r"HKCU\Software\Policies\Mozilla\Firefox\Preferences";
const FIREFOX_PREF_NAME: &str = "media.peerconnection.ice.proxy_only";

/// نشانهٔ «این مقدار را ما گذاشته‌ایم» — بدون آن purge_stale() هرگز به سیاستی
/// که خود کاربر یا سازمانش تنظیم کرده دست نمی‌زند.
const SENTINEL_NAME: &str = "AetherLeakGuardManaged";

/// وضعیت زندهٔ گارد — پنل عیب‌یابی از همین می‌خواند.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardStatus {
    pub engaged: bool,
    /// تعداد قواعد فایروالی که واقعاً نصب شدند (۰ = بدون دسترسی مدیر).
    pub firewall_rules: u32,
    /// تعداد سیاست‌های مرورگر که نوشته شدند.
    pub browser_policies: u32,
    /// آیا بلوکِ UDP فقط به مرورگرها بسته شده است؟
    ///
    /// در خطِ لولهٔ تور جواب «بله» است و این یک تصمیمِ آگاهانه است: بلوکِ
    /// سیستمیِ STUN/UDP، ترابرهای خودِ برنامه را هم می‌کشد (snowflake به
    /// UDP:3478 و بروکرش به IPv6 نیاز دارد). پس در این حالت، بازبودنِ UDP
    /// برای **فرآیندهای خودمان** انتظارِ طرح است، نه نشتی — و داوریِ نشتی
    /// باید همین را بداند، وگرنه نشستی را رد می‌کند که خودش این‌طور خواسته.
    pub udp_browser_scoped: bool,
}

fn status_cell() -> &'static parking_lot::Mutex<GuardStatus> {
    static CELL: OnceLock<parking_lot::Mutex<GuardStatus>> = OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(GuardStatus::default()))
}

/// وضعیت فعلی گارد نشتی.
pub fn status() -> GuardStatus {
    *status_cell().lock()
}

/// یک تغییر برگشت‌پذیر در رجیستری.
#[derive(Debug, Clone)]
struct PolicyEdit {
    key: String,
    name: String,
    kind: &'static str,
    previous: Option<String>,
}

/// گاردِ فعال. Drop هم آزادش می‌کند تا هیچ مسیر خروجی‌ای قاعده جا نگذارد.
#[derive(Debug, Default)]
pub struct LeakGuard {
    rules: u32,
    kill_rules: u32,
    /// ببینید `GuardStatus::udp_browser_scoped`.
    udp_browser_scoped: bool,
    /// Policies already correct count as active even when this session did not write them.
    policies: u32,
    edits: Vec<PolicyEdit>,
}

impl LeakGuard {
    /// گارد خاموش — وقتی کاربر گزینه را غیرفعال کرده است.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// برپاکردن هر سه لایه. هیچ‌وقت خطا پرتاب نمی‌کند: نبودِ دسترسی مدیر فقط
    /// یعنی لایهٔ فایروال نصب نمی‌شود و لایهٔ سیاست مرورگر — که ریشهٔ نشتی را
    /// می‌بندد — همچنان کار می‌کند، چون HKCU به Administrator نیاز ندارد.
    pub fn engage(profile: &ConnectionProfile) -> Self {
        // باقی‌ماندهٔ نشست قبلی هرگز نباید با قواعد جدید قاطی شود.
        delete_firewall_rules();
        delete_kill_switch_rules();

        let mut me = Self::default();
        // این تصمیم پیش از هر قاعده گرفته می‌شود، چون خودِ `apply_kill_switch`
        // بر اساسِ همین است که بلوکِ UDP را سیستمی می‌بندد یا فقط روی
        // مرورگرها: خطِ لولهٔ تور به UDP خروجیِ خودش نیاز دارد
        // (snowflake → UDP:3478، بروکرش روی IPv6).
        me.udp_browser_scoped = needs_pluggable_transport_egress(profile);
        me.apply_browser_policies();
        me.apply_firewall(profile);
        me.apply_kill_switch(profile);

        *status_cell().lock() = GuardStatus {
            engaged: true,
            firewall_rules: me.rules + me.kill_rules,
            browser_policies: me.policies,
            udp_browser_scoped: me.udp_browser_scoped,
        };

        if me.rules == 0 {
            if me.edits.is_empty() {
                DiagnosticsLog::e(
                    TAG,
                    "Leak guard could not install any protection. The connection must fail closed; administrator rights are required for the firewall kill-switch.",
                );
            } else {
                DiagnosticsLog::w(
                    TAG,
                    "Firewall layer not installed (administrator rights required) — browser policy protection is active for newly started browsers.",
                );
            }
        }
        let protection = if me.rules > 0 && needs_pluggable_transport_egress(profile) {
            "browser-scoped UDP kill-switch active (Tor pipeline)"
        } else if me.rules > 0 {
            "system-wide UDP kill-switch active"
        } else if me.policies > 0 {
            "browser policy active for newly started browsers"
        } else {
            "NO PROTECTION ACTIVE"
        };
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Leak guard engaged — {} firewall rule(s), {} browser policy value(s): {protection}.",
                me.rules,
                me.policies
            ),
        );
        me
    }

    /// لایهٔ ۱ — سیاست رسمی خود مرورگرها (بدون نیاز به دسترسی مدیر).
    fn apply_browser_policies(&mut self) {
        for key in CHROMIUM_POLICY_KEYS {
            let previous = reg_read(key, CHROMIUM_POLICY_NAME);
            if previous.as_deref() == Some(CHROMIUM_POLICY_VALUE) {
                self.policies += 1;
                continue; // از قبل درست بوده — دست نمی‌زنیم.
            }
            if reg_write(key, CHROMIUM_POLICY_NAME, "REG_SZ", CHROMIUM_POLICY_VALUE) {
                reg_write(key, SENTINEL_NAME, "REG_DWORD", "1");
                self.policies += 1;
                self.edits.push(PolicyEdit {
                    key: key.to_string(),
                    name: CHROMIUM_POLICY_NAME.to_string(),
                    kind: "REG_SZ",
                    previous,
                });
            }
        }

        let previous = reg_read(FIREFOX_PREFS_KEY, FIREFOX_PREF_NAME);
        if previous.as_deref() == Some("0x1") {
            self.policies += 1;
        } else if reg_write(FIREFOX_PREFS_KEY, FIREFOX_PREF_NAME, "REG_DWORD", "1") {
            reg_write(FIREFOX_PREFS_KEY, SENTINEL_NAME, "REG_DWORD", "1");
            self.policies += 1;
            self.edits.push(PolicyEdit {
                key: FIREFOX_PREFS_KEY.to_string(),
                name: FIREFOX_PREF_NAME.to_string(),
                kind: "REG_DWORD",
                previous,
            });
        }
    }

    /// لایهٔ ۲ — کلید قطع فایروال. بدون دسترسی مدیر بی‌صدا رد می‌شود.
    fn apply_firewall(&mut self, profile: &ConnectionProfile) {
        // >>> AETHER-APP-FIX pt-egress-not-blocked
        // چرا این شرط اینجاست (لاگ ۲۰۲۶-۰۹-۱۶، حالت «Tor alone»):
        //
        //     [pt lyrebird] broker failure dial tcp …: connectex: An attempt was
        //     made to access a socket in a way forbidden by its access permissions.
        //
        // این WSAEACCES است — خطای خودِ ویندوز، نه رفتار سانسور. سانسور با
        // reset یا سکوت جواب می‌دهد؛ این پیام یعنی فیلترِ محلی اجازهٔ connect
        // را نداد. در همان لحظه خودِ موتور می‌توانست مستقیم به گاردهای تور
        // وصل شود (تا ۱۵٪ رفت) و فقط `lyrebird.exe` نمی‌توانست، که یعنی
        // فیلتر per-application — و تنها فیلتر per-application روی آن مسیر،
        // همین دو قاعدهٔ زیر بود.
        //
        // پل‌های snowflakeِ داخلیِ هسته (`bridges.rs`) همه‌شان
        // `ice=stun:…:3478` هستند و ۳۴۷۸ داخل STUN_TURN_PORTS است؛ brokerشان
        // هم domain-fronted روی cdn77 است که AAAA دارد، پس قاعدهٔ 2000::/3 هم
        // روی همان dial می‌افتد. با هر دو قاعده در جای خود، snowflake هرگز
        // نمی‌توانست وصل شود — نه روی این شبکه، نه روی هیچ شبکه‌ای.
        //
        // راه‌حل: این دو قاعده به‌جای «همهٔ برنامه‌ها» فقط به مرورگرها بسته
        // می‌شوند وقتی خط لوله ترانسپورتِ افزودنی لازم دارد. بردارِ واقعیِ
        // نشتی WebRTC همان مرورگر است (قاعدهٔ ۲.۱ هم از اول program-scoped
        // بود)، پس پوشش امنیتی از دست نمی‌رود؛ چیزی که از دست می‌رفت، تور بود.
        //
        // یک قاعدهٔ block در WFP بر هر قاعدهٔ allow برتری دارد، پس «allow برای
        // lyrebird» راه‌حل نبود: باید خودِ block باریک شود.
        let pt_egress = needs_pluggable_transport_egress(profile);
        if pt_egress {
            DiagnosticsLog::w(
                TAG,
                "Tor pipeline: the STUN/TURN and IPv6 blocks are scoped to browsers instead of the whole system, because a system-wide block also blocks this app's own pluggable transports (snowflake needs UDP 3478 and its broker answers over IPv6).",
            );
        }
        // <<< AETHER-APP-FIX pt-egress-not-blocked
        // ۲.۱ — UDP خروجیِ خودِ مرورگرها. مرورگر پشت پروکسی هیچ UDP مشروعی
        // ندارد (QUIC هم با پروکسی خاموش می‌شود و به TCP برمی‌گردد)، پس بستن
        // کامل UDP همهٔ نامزدهای host/srflx را از بین می‌برد.
        for exe in discover_browsers() {
            let program = exe.to_string_lossy().to_string();
            let ok = fw_add(
                &[
                    "dir=out",
                    "action=block",
                    "protocol=udp",
                    "profile=any",
                    "enable=yes",
                ],
                Some(&program),
            );
            if ok {
                self.rules += 1;
            }
        }

        // ۲.۲ — پورت‌های STUN/TURN برای هر برنامه‌ای (اپ‌های الکترون، بازی‌ها،
        // هر چیزی که کرومیوم را جاسازی کرده). موتور خودمان هرگز روی این
        // پورت‌ها حرف نمی‌زند، پس تونل آسیبی نمی‌بیند.
        let ports = format!("remoteport={STUN_TURN_PORTS}");
        for proto in ["protocol=udp", "protocol=tcp"] {
            let args = [
                "dir=out",
                "action=block",
                proto,
                &ports,
                "profile=any",
                "enable=yes",
            ];
            if pt_egress {
                for exe in discover_browsers() {
                    let program = exe.to_string_lossy().to_string();
                    if fw_add(&args, Some(&program)) {
                        self.rules += 1;
                    }
                }
            } else if fw_add(&args, None) {
                self.rules += 1;
            }
        }

        // ۲.۳ — IPv6 عمومی وقتی تونل فقط IPv4 است: کلاسیک‌ترین نشتی کنار
        // WebRTC. فقط 2000::/3 بسته می‌شود تا link-local و ULA شبکهٔ محلی
        // (کشف چاپگر، mDNS و…) سالم بماند.
        if profile.ipv6_protection {
            let args = [
                "dir=out",
                "action=block",
                "protocol=any",
                "remoteip=2000::/3",
                "profile=any",
                "enable=yes",
            ];
            if pt_egress {
                for exe in discover_browsers() {
                    let program = exe.to_string_lossy().to_string();
                    if fw_add(&args, Some(&program)) {
                        self.rules += 1;
                    }
                }
            } else if fw_add(&args, None) {
                self.rules += 1;
            }
        }
    }

    /// Browser-scoped kill-switch: browser traffic can only reach localhost
    /// (the local HTTP/SOCKS bridge) while Aether is connected. When the
    /// tunnel drops, the same rules remain and browsers cannot fall back to
    /// the physical interface. Engine traffic is not blocked.
    fn apply_kill_switch(&mut self, profile: &ConnectionProfile) {
        if !profile.kill_switch {
            return;
        }
        for exe in discover_browsers() {
            let program = exe.to_string_lossy().to_string();
            if fw_add_named(
                KILL_RULE,
                &[
                    "dir=out",
                    "action=block",
                    "protocol=any",
                    "remoteip=any",
                    "profile=any",
                    "enable=yes",
                ],
                Some(&program),
            ) {
                self.kill_rules += 1;
            }
        }
        // IPv6 protection is process-independent: block global IPv6 on the
        // physical path because the current system-proxy bridge is TCP-only.
        // If a real IPv6 TUN route is available, the engine owns it; this rule
        // remains the fail-closed fallback for the physical adapter.
        // The Wintun route is installed when available; otherwise blocking is
        // the safe fail-closed behavior, never a silent IPv6 leak.
        // >>> AETHER-APP-FIX pt-egress-not-blocked
        // همان دلیلِ apply_firewall: در خط لولهٔ تور این قاعده هم اگر
        // سیستم‌گسترده بسته شود، dialِ IPv6ِ خودِ ترانسپورت را می‌بندد.
        if profile.ipv6_protection {
            let args = [
                "dir=out",
                "action=block",
                "protocol=any",
                "remoteip=2000::/3",
                "profile=any",
                "enable=yes",
            ];
            if needs_pluggable_transport_egress(profile) {
                for exe in discover_browsers() {
                    let program = exe.to_string_lossy().to_string();
                    if fw_add_named(KILL_RULE, &args, Some(&program)) {
                        self.kill_rules += 1;
                    }
                }
            } else if fw_add_named(KILL_RULE, &args, None) {
                self.kill_rules += 1;
            }
        }
        // <<< AETHER-APP-FIX pt-egress-not-blocked
    }

    /// Transfer ownership without deleting the process-wide rules. This is
    /// required when replacing a guard during a reconnect/profile update:
    /// dropping the old guard must not remove rules installed by the new one.
    pub fn disarm_without_cleanup(&mut self) {
        self.rules = 0;
        self.kill_rules = 0;
        self.policies = 0;
        self.edits.clear();
    }

    /// Clean only the per-session leak-guard layer while preserving the
    /// kill-switch during an automatic reconnect. The next guard takes over
    /// the same process-wide kill rules without a safety gap.
    pub fn release_for_reconnect(&mut self) {
        if self.rules > 0 {
            delete_firewall_rules();
        }
        self.rules = 0;
        restore_policies(std::mem::take(&mut self.edits));
        *status_cell().lock() = GuardStatus {
            engaged: self.kill_rules > 0,
            firewall_rules: self.kill_rules,
            browser_policies: 0,
            udp_browser_scoped: self.udp_browser_scoped,
        };
    }

    /// بازگرداندن همه‌چیز به حالت قبل — در قطع اتصال، خطا و خروج برنامه.
    pub fn release(&mut self) {
        // >>> AETHER-APP-FIX instant-disconnect
        // هر `netsh advfirewall` روی ویندوز نیم تا دو ثانیه می‌گیرد و قطعِ اتصال
        // دو تا از آن‌ها را پشتِ هم، به‌اضافهٔ بازگردانیِ رجیستری، صبر می‌کرد.
        // سه کار مستقل‌اند (نامِ قاعده‌ها جداست)، پس هم‌زمان اجرا می‌شوند و این
        // تابع هنوز فقط پس از پایانِ همه برمی‌گردد — اتصالِ بعدی هرگز قاعده‌ای
        // نمی‌سازد که یک حذفِ در-راه پاکش کند.
        let (rules, kill_rules) = (self.rules > 0, self.kill_rules > 0);
        let edits = std::mem::take(&mut self.edits);
        let had_edits = !edits.is_empty();
        std::thread::scope(|scope| {
            if rules {
                scope.spawn(delete_firewall_rules);
            }
            // Explicit disconnect/exit restores the user's network. Automatic
            // reconnect uses release_for_reconnect() and intentionally preserves it.
            if kill_rules {
                scope.spawn(delete_kill_switch_rules);
            }
            restore_policies(edits);
        });
        // <<< AETHER-APP-FIX instant-disconnect
        self.kill_rules = 0;
        let had_rules = self.rules > 0;
        self.rules = 0;
        *status_cell().lock() = GuardStatus::default();
        if had_rules || had_edits {
            DiagnosticsLog::i(
                TAG,
                "Leak guard released — firewall rules and browser policies restored.",
            );
        }
    }
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// پاک‌سازی باقی‌ماندهٔ یک کرش — در استارتاپ صدا زده می‌شود. فقط چیزی پاک
/// می‌شود که نشانهٔ AetherLeakGuardManaged داشته باشد، پس سیاست سازمانی خود
/// کاربر هرگز قربانی نمی‌شود.
pub fn purge_stale() {
    // دو `netsh` مستقل (نام‌های جدا) هم‌زمان؛ پیش از هر اتصالِ توری روی مسیرِ
    // Connect اجرا می‌شود و پشتِ هم چند ثانیه می‌گرفت.
    std::thread::scope(|scope| {
        scope.spawn(delete_kill_switch_rules);
        delete_firewall_rules();
    });
    let mut cleaned = 0;
    for key in CHROMIUM_POLICY_KEYS {
        if reg_read(key, SENTINEL_NAME).is_some() {
            reg_delete_value(key, CHROMIUM_POLICY_NAME);
            reg_delete_value(key, SENTINEL_NAME);
            cleaned += 1;
        }
    }
    if reg_read(FIREFOX_PREFS_KEY, SENTINEL_NAME).is_some() {
        reg_delete_value(FIREFOX_PREFS_KEY, FIREFOX_PREF_NAME);
        reg_delete_value(FIREFOX_PREFS_KEY, SENTINEL_NAME);
        cleaned += 1;
    }
    if cleaned > 0 {
        DiagnosticsLog::w(
            TAG,
            &format!(
                "Cleared {cleaned} leak-guard policy value(s) left behind by a previous session."
            ),
        );
    }
    *status_cell().lock() = GuardStatus::default();
}

// >>> AETHER-APP-FIX psiphon-wsaeacces-hint
/// پس از نخستین WSAEACCESِ سایفون (روی رشتهٔ جدا): آیا قاعده‌ای از اتر مانده؟
/// اگر هیچ گاردی درگیر نیست، باقی‌مانده پاک می‌شود؛ وگرنه علت بیرون از اتر است
/// (فایروالِ دیگری، یا سیاستِ «BlockOutbound» در پروفایلِ ویندوز).
pub fn diagnose_access_denied() {
    let present = |name: &str| {
        netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "show".into(),
            "rule".into(),
            format!("name={name}"),
        ])
    };
    let kill = present(KILL_RULE);
    let guard = present(FW_RULE);
    let engaged = status().engaged;
    if (kill || guard) && !engaged {
        purge_stale();
        DiagnosticsLog::w(
            TAG,
            "Leftover Aether firewall rules were still installed with no session owning them (a previous session was killed) — removed. Psiphon retries on its own.",
        );
    } else if kill || guard {
        DiagnosticsLog::i(
            TAG,
            "Aether's own firewall rules are active for this session; their STUN/TURN and IPv6 blocks are scoped to browsers in Psiphon chains.",
        );
    } else {
        let outbound_blocked = netsh_output(&["advfirewall", "show", "currentprofile"])
            .map(|t| t.contains("BlockOutbound"))
            .unwrap_or(false);
        DiagnosticsLog::w(
            TAG,
            &format!(
                "No Aether firewall rule is installed, so the refusal comes from outside Aether{} — allow psiphon-tunnel-core.exe in %LOCALAPPDATA%\\studio.cluvex.aether.desktop\\engine in that firewall/antivirus, or use Config → Psiphon, where Psiphon only talks to 127.0.0.1.",
                if outbound_blocked {
                    " (the active Windows Firewall profile blocks outbound connections by default)"
                } else {
                    " (another firewall, VPN kill switch or antivirus)"
                }
            ),
        );
    }
}

fn netsh_output(args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("netsh.exe"),
    );
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}
// <<< AETHER-APP-FIX psiphon-wsaeacces-hint

// ---------------------------------------------------------------------------
//  کمکی‌ها
// ---------------------------------------------------------------------------

// >>> AETHER-APP-FIX pt-egress-not-blocked
/// آیا این خط لوله برای رسیدن به شبکه به یک ترانسپورتِ افزودنی نیاز دارد؟
///
/// فقط حالت‌های تور — و در آن‌ها فقط وقتی پل به کلی خاموش نشده باشد.
/// مسیر WARP خودِ موتور است و به STUN یا IPv6 خروجی کاری ندارد، پس آنجا
/// قاعدهٔ سیستم‌گسترده می‌ماند — کمترین تغییر در پوششِ امنیتی، فقط
/// جایی که باید.
pub(crate) fn needs_pluggable_transport_egress(profile: &ConnectionProfile) -> bool {
    (profile.backend.uses_tor() && profile.tor_bridges != crate::profile::TorBridges::Off)
        // AETHER-APP-PATCH custom-configs
        || CUSTOM_EGRESS.load(std::sync::atomic::Ordering::Relaxed)
}

// >>> AETHER-APP-PATCH custom-configs
/// کانفیگِ سفارشی‌ای که Xray مستقیم به آن dial می‌کند (تنها یا هاپِ اول) و
/// سرورش روی IPv6 یا یکی از پورت‌های STUN/TURN است. همان باریک‌سازیِ تور:
/// بلوک‌های STUN و IPv6 فقط روی مرورگرها می‌نشینند، وگرنه خودِ Xray هم بسته
/// می‌شد. پیش‌فرض `false` = همان قاعدهٔ سیستم‌گسترده.
static CUSTOM_EGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn set_custom_egress(on: bool) {
    CUSTOM_EGRESS.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// آیا `port` داخلِ [`STUN_TURN_PORTS`] است؟
pub(crate) fn port_is_stun(port: u16) -> bool {
    STUN_TURN_PORTS.split(',').any(|part| match part.split_once('-') {
        Some((a, b)) => match (a.parse::<u16>(), b.parse::<u16>()) {
            (Ok(a), Ok(b)) => (a..=b).contains(&port),
            _ => false,
        },
        None => part.parse::<u16>().ok() == Some(port),
    })
}
// <<< AETHER-APP-PATCH custom-configs
// <<< AETHER-APP-FIX pt-egress-not-blocked

fn fw_add(args: &[&str], program: Option<&str>) -> bool {
    fw_add_named(FW_RULE, args, program)
}

fn fw_add_named(rule_name: &str, args: &[&str], program: Option<&str>) -> bool {
    let mut argv: Vec<String> = vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={rule_name}"),
    ];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    if let Some(p) = program {
        argv.push(format!("program={p}"));
    }
    netsh(&argv)
}

fn delete_firewall_rules() {
    let argv: Vec<String> = vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={FW_RULE}"),
    ];
    // نبودِ قاعده هم «موفق» حساب می‌شود؛ netsh در آن حالت کد ۱ برمی‌گرداند.
    let _ = netsh(&argv);
}

fn delete_kill_switch_rules() {
    let argv: Vec<String> = vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={KILL_RULE}"),
    ];
    let _ = netsh(&argv);
}

fn netsh(args: &[String]) -> bool {
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

/// همهٔ سیاست‌ها را با هم برمی‌گرداند.
///
/// هر ویرایش، مقدارِ خودش را در کلیدِ خودش دست می‌زند، پس ترتیبشان بی‌اثر
/// است — ولی هر `reg.exe` یک فرآیندِ تازه است و سریالی‌بودنشان در لاگِ
/// ۱۶ سپتامبر ۱٫۹۶ ثانیه از قطعِ اتصال خورد (فاصلهٔ بازگردانیِ پراکسی تا
/// توقفِ پل، جایی که تنها همین کار در آن است). حالا همه با هم شروع می‌شوند و
/// بعد منتظرشان می‌مانیم: وقتی این تابع برمی‌گردد، رجیستری واقعاً برگشته
/// است — همان تضمینی که نسخهٔ سریالی می‌داد.
fn restore_policies(edits: Vec<PolicyEdit>) {
    let mut kids = Vec::with_capacity(edits.len() * 2);
    for edit in &edits {
        match &edit.previous {
            Some(v) => kids.extend(reg_spawn(&[
                "add", &edit.key, "/v", &edit.name, "/t", edit.kind, "/d", v, "/f",
            ])),
            None => kids.extend(reg_spawn(&["delete", &edit.key, "/v", &edit.name, "/f"])),
        }
        kids.extend(reg_spawn(&["delete", &edit.key, "/v", SENTINEL_NAME, "/f"]));
    }
    for mut kid in kids {
        let _ = kid.wait();
    }
}

/// مثل `reg`، ولی منتظر نمی‌ماند.
fn reg_spawn(args: &[&str]) -> Option<std::process::Child> {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("reg.exe"),
    );
    cmd.args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.spawn().ok()
}

fn reg_write(key: &str, name: &str, kind: &str, data: &str) -> bool {
    reg(&["add", key, "/v", name, "/t", kind, "/d", data, "/f"]).is_some()
}

fn reg_delete_value(key: &str, name: &str) -> bool {
    reg(&["delete", key, "/v", name, "/f"]).is_some()
}

/// خواندن یک مقدار — None یعنی وجود ندارد.
fn reg_read(key: &str, name: &str) -> Option<String> {
    let out = reg(&["query", key, "/v", name])?;
    parse_reg_value(&out, name)
}

/// خروجی `reg query` را به مقدار خام تبدیل می‌کند.
/// نمونه: "    WebRtcIPHandling    REG_SZ    disable_non_proxied_udp"
fn parse_reg_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(name) {
            continue;
        }
        let rest = trimmed[name.len()..].trim_start();
        let mut it = rest.splitn(2, "REG_");
        let _ = it.next()?;
        let typed = it.next()?;
        // typed = "SZ    disable_non_proxied_udp" یا "DWORD    0x1"
        let value = typed
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ");
        return Some(value);
    }
    None
}

fn reg(args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("reg.exe"),
    );
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// مسیر کامل مرورگرهای نصب‌شده — netsh فقط مسیر کامل را می‌پذیرد، نه نام فایل.
fn discover_browsers() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();

    for exe in BROWSER_EXES {
        let key = format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
        if let Some(out) = reg(&["query", &key, "/ve"]) {
            if let Some(v) = parse_default_value(&out) {
                push_unique(&mut found, PathBuf::from(v.trim_matches('"')));
            }
        }
    }

    for root in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        let base = match std::env::var(root) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for rel in BROWSER_PATHS {
            push_unique(&mut found, PathBuf::from(&base).join(rel));
        }
    }

    found
}

fn push_unique(list: &mut Vec<PathBuf>, path: PathBuf) {
    if path.exists() && !list.iter().any(|x| x == &path) {
        list.push(path);
    }
}

fn parse_default_value(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("(Default)") {
            let mut it = trimmed.splitn(2, "REG_");
            let _ = it.next()?;
            let typed = it.next()?;
            let value = typed
                .split_whitespace()
                .skip(1)
                .collect::<Vec<_>>()
                .join(" ");
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_string_registry_value() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome\r\n    WebRtcIPHandling    REG_SZ    disable_non_proxied_udp\r\n";
        assert_eq!(
            parse_reg_value(out, CHROMIUM_POLICY_NAME).as_deref(),
            Some(CHROMIUM_POLICY_VALUE)
        );
    }

    #[test]
    fn parses_a_dword_registry_value() {
        let out = "    media.peerconnection.ice.proxy_only    REG_DWORD    0x1\r\n";
        assert_eq!(
            parse_reg_value(out, FIREFOX_PREF_NAME).as_deref(),
            Some("0x1")
        );
    }

    #[test]
    fn missing_value_is_none() {
        assert!(
            parse_reg_value("ERROR: The system was unable to find", CHROMIUM_POLICY_NAME).is_none()
        );
    }

    #[test]
    fn parses_app_paths_default_value() {
        let out = "    (Default)    REG_SZ    C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\r\n";
        assert_eq!(
            parse_default_value(out).as_deref(),
            Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
        );
    }

    /// قرارداد امنیتی: پورت‌هایی که ابزارهای نشت‌سنجی عمومی از آن‌ها استفاده
    /// می‌کنند باید در فهرست مسدودی باشند.
    #[test]
    fn custom_egress_port_matcher() {
        assert!(port_is_stun(3478));
        assert!(port_is_stun(19305));
        assert!(!port_is_stun(443));
        assert!(!port_is_stun(19310));
    }

    #[test]
    fn stun_port_list_covers_the_public_test_servers() {
        for p in ["3478", "5349", "19302-19309"] {
            assert!(STUN_TURN_PORTS.contains(p), "missing {p}");
        }
    }

    /// گارد خاموش نباید هیچ اثری روی سیستم بگذارد.
    #[test]
    fn disabled_guard_touches_nothing() {
        let g = LeakGuard::disabled();
        assert_eq!(g.rules, 0);
        assert_eq!(g.kill_rules, 0);
        assert_eq!(g.policies, 0);
        assert!(g.edits.is_empty());
    }

    // >>> AETHER-APP-FIX pt-egress-not-blocked
    /// این تست همان چیزی را می‌بندد که لاگ ۲۰۲۶-۰۹-۱۶ نشان داد: تور روی ۰–۱۵٪
    /// می‌ماند و `lyrebird.exe` با WSAEACCES رد می‌شود، چون قاعده‌های
    /// سیستم‌گستردهٔ خودِ ما پورت STUN و مسیر IPv6 را برای **هر** برنامه‌ای
    /// بسته بودند — و پل‌های snowflake هسته همه `ice=stun:…:3478` هستند.
    #[test]
    fn a_tor_pipeline_does_not_get_a_system_wide_block() {
        let mut p = ConnectionProfile::default();

        // WARP: هیچ ترانسپورت افزودنی‌ای در کار نیست، پس قاعده سیستم‌گسترده
        // می‌ماند و پوشش امنیتی دست‌نخورده است.
        p.backend = crate::profile::TransportBackend::Aether;
        assert!(!needs_pluggable_transport_egress(&p));

        // تور با پل: قاعده باید به مرورگرها محدود شود.
        for backend in [
            crate::profile::TransportBackend::Tor,
            crate::profile::TransportBackend::AetherTor,
            crate::profile::TransportBackend::TorPsiphon,
            crate::profile::TransportBackend::TorAether,
        ] {
            p.backend = backend;
            p.tor_bridges = crate::profile::TorBridges::Auto;
            assert!(
                needs_pluggable_transport_egress(&p),
                "{backend:?} needs its pluggable transport to be able to dial"
            );
        }

        // تورِ بدون پل هیچ lyrebird‌ای اجرا نمی‌کند، پس دلیلی برای باریک‌کردن
        // قاعده نیست.
        p.backend = crate::profile::TransportBackend::Tor;
        p.tor_bridges = crate::profile::TorBridges::Off;
        assert!(!needs_pluggable_transport_egress(&p));
    }

    /// پورت ICE پل‌های داخلیِ هسته باید داخل فهرست مسدودی باشد — این همان
    /// همپوشانی‌ای است که باگ را می‌ساخت. اگر روزی یکی از دو طرف عوض شد، این
    /// تست می‌گوید که تصمیمِ باریک‌کردن قاعده هنوز لازم است یا نه.
    #[test]
    fn the_snowflake_ice_port_really_is_in_the_blocked_list() {
        assert!(
            STUN_TURN_PORTS.contains("3478"),
            "the built-in snowflake bridges use ice=stun:…:3478"
        );
    }
    // <<< AETHER-APP-FIX pt-egress-not-blocked
}
