//! پورت ۱:۱ از `app/src/main/java/studio/cluvex/aether/model/Profile.kt`
//!
//! هر تغییری در سمت اندروید باید دقیقاً همین‌جا هم اعمال شود؛ منطق ساخت
//! آرگومان‌های خط فرمان و متغیرهای محیطیِ موتور باید بایت‌به‌بایت یکسان بماند.
//!
//! v10 (هسته‌ی 1.5.0): سه قابلیت جدیدِ کاربرمحورِ هسته اضافه شد و هر کدام
//! پشت یک «قابلیت نسخه» (CoreCaps) گِیت شده‌اند تا هسته‌ی قدیمی‌تر هرگز فلگ
//! ناشناخته نگیرد و اتصال نشکند:
//!   * Zero Trust / WARP سازمانی  (--team, --access-*, --gateway)
//!   * قوانین مسیریابی            (--route-block, --route-direct)
//!   * DNS داخل تونل              (--dns)
//!
//! v11 (هسته‌ی 1.7.0): سه قابلیت جدید هسته اضافه شد و مثل قبل هر کدام پشت
//! «قابلیت نسخه» (CoreCaps) گِیت شده‌اند تا هسته‌ی 1.6.0 یا قدیمی‌تر هرگز
//! فلگ یا متغیرِ ناشناخته نبیند:
//!   * پروکسی بالادست            (--upstream / AETHER_UPSTREAM)
//!   * تشخیص نام از بایت‌های اول  (AETHER_ROUTE_SNIFF, AETHER_ROUTE_SNIFF_MS)
//!   * جایگزینی هویتِ ردشده       (AETHER_REPROVISION)
//!
//! v12 (۱.۲.۳): بک‌اند ترابرد ([TransportBackend]) اضافه شد — انتخاب بین موتور
//! تنها و زنجیرهٔ `Aether → Psiphon`. آرگومان‌ها و متغیرهای موتور دست‌نخورده
//! می‌مانند: زنجیره یک لایهٔ سمتِ ویندوز است، نه یک فلگ هسته.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    /// v8: "Auto" renamed to "Smart" (same as mobile). The serde alias keeps
    /// old profile.json files that stored "AUTO" loading fine.
    #[serde(alias = "AUTO")]
    Smart,
    Masque,
    Wireguard,
    Gool,
    /// Core 2.0.0: MASQUE inside MASQUE (two hops).
    Mim,
}

/// Core 2.4.0 GOOL variant. Modern is the new default (`--gool`), while
/// Classic preserves the older WireGuard-inside-WireGuard path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum GoolMode {
    #[default]
    Modern,
    Classic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IpVersion {
    V4,
    V6,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Noize {
    Off,
    Light,
    Firewall,
    Balanced,
    Gfw,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndpointMode {
    Auto,
    ManualPeer,
    ManualRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SplitMode {
    Off,
    Include,
    Exclude,
}

/// v12 (۱.۲.۳) — پورت ۱:۱ از `model/TransportBackend.kt`.
///
/// پشتهٔ شبکه‌ای که یک نشست روی آن ساخته می‌شود:
///
/// * [TransportBackend::Aether] — تنها موتور اِتِر. خروجی یک لبهٔ anycast
///   کلادفلر (WARP) است؛ رفتار پیش‌فرض و عیناً همان ۱.۲.۲.
/// * [TransportBackend::AetherPsiphon] — زنجیرهٔ دو استیجی. استیج ۱ موتور اِتِر
///   روی [crate::engine::LOCAL_SOCKS_PORT] (عمداً بدون مسیر داده و بدون پل)، و
///   استیج ۲ Psiphon روی [crate::engine::CHAIN_SOCKS_PORT] که از راه استیج ۱
///   dial می‌کند و خروجیِ نهاییِ خط لوله است.
///
/// نام‌های serde همان کدهایی‌اند که رابط کاربری می‌فرستد و در `profile.json`
/// ذخیره می‌شوند (`AETHER` / `AETHER_PSIPHON` — دقیقاً فهرست `BACKENDS` در
/// `src/views/advanced.js`). پروفایل‌های پیش از ۱.۲.۳ این فیلد را ندارند و
/// [default_backend] آن‌ها را بی‌صدا روی `AETHER` می‌گذارد.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportBackend {
    #[default]
    Aether,
    AetherPsiphon,
    /// ۱.۲.۵ — سه حالت تازه، معادل دقیق نسخهٔ موبایل. عمداً به **ته** فهرست
    /// اضافه شده‌اند: `profile.json` نام را ذخیره می‌کند، نه ترتیب را، ولی
    /// درج در میانهٔ فهرست ترتیب نمایش رابط کاربری را هم جابه‌جا می‌کرد.
    Tor,
    AetherTor,
    TorPsiphon,
    TorAether,
}

/// ۱.۲.۵ (هستهٔ ۲.۰.۰) — پورت ۱:۱ از `TransportBackend.kt::TorMode`.
///
/// نگاشت مستقیم روی فلگ‌های خود هسته: [TorMode::Chain] همان `--tor`،
/// [TorMode::Only] همان `--tor-only`، [TorMode::Reverse] همان `--tor-reverse`.
///
/// تفاوت سه‌تا در یک پرسش است — **اول چه چیزی به شبکه می‌رسد** — و هر تفاوت
/// دیگری از همان درمی‌آید:
///
/// ```text
///   Chain    اول تونل، تور داخلش      شبکهٔ محلی می‌بیند: اِتِر
///   Only     تور، بی هیچ تونلی        شبکهٔ محلی می‌بیند: تور (یا یک پل)
///   Reverse  اول تور، تونل داخلش      شبکهٔ محلی می‌بیند: تور (یا یک پل)
/// ```
///
/// پس پل‌ها فقط در [TorMode::Only] و [TorMode::Reverse] معنا دارند — همان دو
/// حالتی که تور خودش روبروی شبکهٔ محلی است — و در حالت زنجیره‌ای، که تور از
/// داخل تونل dial می‌شود، هیچ کاری نمی‌کنند.
///
/// [TorMode::Reverse] یک محدودیت اضافه هم دارد و انتخاب این برنامه نیست: تور
/// فقط TCP حمل می‌کند و لبه‌های WireGuard وارپ فقط روی UDP جواب می‌دهند، پس
/// هسته در این حالت MASQUE روی HTTP/2 را اجرا می‌کند و **`--wg` و `--gool` را
/// رد می‌کند**. برنامه هم به جای فرستادن ترکیبی که هسته ردش می‌کند، خودش
/// پروتکل را بازنویسی می‌کند — [ConnectionProfile::effective_protocol].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TorMode {
    Chain,
    Only,
    Reverse,
}

/// آیا تور از راه پل به شبکه برسد؟ (هستهٔ ۲.۰.۰ — پورت `TorBridges`).
///
/// [TorBridges::Auto] رفتار خود هسته است: کمی مستقیم تلاش کن و اگر به جایی
/// نرسید، پل‌هایی که از bridgedb گرفته را بیازما. [TorBridges::Always] تلاش
/// مستقیم را رد می‌کند (`--tor-bridges`) — انتخاب درست روی شبکه‌ای که
/// می‌دانیم تور را می‌بندد. [TorBridges::Off] هرگز پل برنمی‌دارد
/// (`--no-tor-bridges`).
///
/// در حالت `Aether → Tor` بی‌اثر است و رابط کاربری همین را می‌گوید: تور آنجا
/// از داخل تونل dial می‌شود، پس شبکهٔ محلی هرگز تور را نمی‌بیند و پل چیزی
/// برای پنهان کردن ندارد.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TorBridges {
    #[default]
    Auto,
    Always,
    Off,
}

impl TransportBackend {
    /// آیا این بک‌اند استیج ۲ (Psiphon) را لازم دارد؟
    ///
    /// تنها دروازهٔ تصمیم در `state.rs`: اگر true باشد، نشست پیش از هر چیز
    /// وجود استیج ۲ را بررسی می‌کند و استیج ۱ بدون مسیر داده بالا می‌آید.
    /// تور داخل خود موتور اجرا می‌شود، پس یک حالت تور به این معنا زنجیره‌ای
    /// نیست مگر Psiphon هم در آن باشد.
    pub fn is_chained(self) -> bool {
        matches!(
            self,
            TransportBackend::AetherPsiphon | TransportBackend::TorPsiphon
        )
    }

    /// موتور چگونه تور را با تونل ترکیب کند، یا `None` وقتی تور در کار نیست.
    pub fn tor_mode(self) -> Option<TorMode> {
        match self {
            TransportBackend::Aether | TransportBackend::AetherPsiphon => None,
            TransportBackend::AetherTor => Some(TorMode::Chain),
            TransportBackend::Tor | TransportBackend::TorPsiphon => Some(TorMode::Only),
            TransportBackend::TorAether => Some(TorMode::Reverse),
        }
    }

    /// آیا تور به هر شکلی در کار است؟
    pub fn uses_tor(self) -> bool {
        self.tor_mode().is_some()
    }

    /// آیا این حالت اصلاً یک تونل WARP بالا می‌آورد؟
    ///
    /// برای دو حالت `--tor-only` نه — و همین است که هر تنظیم WARP‌شکل را در
    /// آن دو بی‌معنا می‌کند: نه لبه‌ای برای اسکن، نه پروتکلی برای انتخاب، نه
    /// هویتی برای ثبت. رابط کاربری آن سطرها را بر مبنای همین خاموش می‌کند، نه
    /// بر مبنای نام بک‌اند.
    pub fn uses_warp(self) -> bool {
        self.tor_mode() != Some(TorMode::Only)
    }

    /// پورت SOCKS5 محلی‌ای که **خروجیِ خط لولهٔ تمام‌شده** است.
    ///
    /// # چرا لایهٔ `TorSocksFront` نسخهٔ موبایل در ویندوز لازم نیست
    ///
    /// در اندروید tun2socks هر جریان UDP — و پس هر پرس‌وجوی DNS دستگاه — را با
    /// `UDP ASSOCIATE` می‌فرستد و تور فقط TCP حمل می‌کند؛ پس آنجا یک front لازم
    /// است که خودش به `UDP ASSOCIATE` جواب بدهد، DNS را روی TCP داخل تور حل کند
    /// و باقی را بیندازد. مسیر دادهٔ ویندوز پروکسی سیستمی WinINET است — از بنیاد
    /// TCP-only و فقط `CONNECT` — و UDP مستقیم را `leakguard.rs` می‌بندد. پس
    /// هیچ UDP‌ای به موتور سپرده نمی‌شود و مسیر داده مستقیم به لیسنر خودِ موتور
    /// می‌چسبد.
    pub fn exposed_socks_port(self) -> u16 {
        if self.is_chained() {
            crate::engine::CHAIN_SOCKS_PORT
        } else if self.tor_mode() == Some(TorMode::Chain) {
            // در `--tor` لیسنر اصلی خروجی WARP را نگه می‌دارد و تور لیسنر دومِ
            // خودش را دارد؛ مسیر دستگاه باید به دومی برود، وگرنه کاربری که
            // «Aether → Tor» را انتخاب کرده از خروجی WARP بیرون می‌رفت.
            crate::engine::TOR_SOCKS_PORT
        } else {
            crate::engine::LOCAL_SOCKS_PORT
        }
    }

    /// لیسنر تورِ خودِ موتور در این حالت، یا `None` وقتی تور خاموش است.
    ///
    /// با `--tor-only` تنها پروکسی موتور خودش تور است، پس روی پورت همیشگی
    /// می‌نشیند. با `--tor` پورت همیشگی خروجی WARP را نگه می‌دارد و تور لیسنر
    /// جداگانه می‌گیرد.
    pub fn tor_socks_port(self) -> Option<u16> {
        match self.tor_mode() {
            None => None,
            Some(TorMode::Only) => Some(crate::engine::LOCAL_SOCKS_PORT),
            Some(TorMode::Chain) | Some(TorMode::Reverse) => Some(crate::engine::TOR_SOCKS_PORT),
        }
    }

    /// برچسب خط لوله برای لاگ تشخیصی — عمداً می‌گوید خروجی **کدام** هاپ است.
    pub fn pipeline_label(self) -> &'static str {
        match self {
            TransportBackend::Aether => "Aether only (exit = Cloudflare WARP edge)",
            TransportBackend::AetherPsiphon => "Aether → Psiphon (chained; exit = Psiphon server)",
            TransportBackend::Tor => "Tor alone, no tunnel under it (exit = Tor)",
            TransportBackend::AetherTor => {
                "Aether → Tor (tor is dialled through the tunnel; exit = Tor)"
            }
            TransportBackend::TorPsiphon => {
                "Tor → Psiphon (chained through tor; exit = Psiphon server)"
            }
            TransportBackend::TorAether => {
                "Tor → Aether (the tunnel goes out through tor; exit = WARP edge)"
            }
        }
    }

    /// The label the home screen's PROTOCOL tile shows, identical to the mobile
    /// edition's `TransportBackend.pipelineLabel`.
    ///
    /// # Why the chained mode needs its own label
    ///
    /// The tile used to render `effective_protocol` alone, so a chained session
    /// said `MASQUE` — the protocol of the FIRST hop — and a user connected
    /// through `Aether → Psiphon` had no way to tell that from a plain Aether
    /// session. Two very different exits, one word. `None` for the plain backend
    /// means "keep showing the concrete protocol, exactly as before".
    pub fn protocol_label(self) -> Option<&'static str> {
        match self {
            TransportBackend::Aether => None,
            TransportBackend::AetherPsiphon => Some("Aether \u{2192} Psiphon"),
            TransportBackend::Tor => Some("Tor"),
            TransportBackend::AetherTor => Some("Aether \u{2192} Tor"),
            TransportBackend::TorPsiphon => Some("Tor \u{2192} Psiphon"),
            TransportBackend::TorAether => Some("Tor \u{2192} Aether"),
        }
    }
}

/// v10 (هسته‌ی 1.5.0): روش ورود به سازمان Cloudflare Zero Trust.
///   Off          → ثبت‌نام معمولی (کاربر ناشناس WARP) — رفتار قبلی، پیش‌فرض.
///   Email        → کد یک‌بارمصرف به ایمیل (`--access-email`).
///   ServiceToken → توکن سرویس Access برای ماشین‌های بدون تعامل / CI
///                  (`--access-id` + `--access-secret`).
///   Token        → یک JWT از پیش‌گرفته‌شده (`--access-token`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessMode {
    Off,
    Email,
    ServiceToken,
    Token,
}

/// قابلیت‌های هسته‌ی همراه — تعیین می‌کند کدام فلگ‌ها امن‌اند که فرستاده شوند.
///
/// قاعده‌ی همیشگیِ مخزن: «ارتقای خودکار هسته هرگز نباید یک انتشار را بشکند».
/// فلگ‌های مخصوص 1.5.0 فقط وقتی به موتور می‌روند که نسخه‌ی واقعیِ سینک‌شده
/// آن‌ها را بفهمد؛ اگر کاربر هسته‌ی قدیمی‌تری را پین کرده باشد این گزینه‌ها
/// بی‌صدا نادیده گرفته می‌شوند تا یک فلگ ناشناخته موتور را نکشد.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreCaps {
    pub zero_trust: bool,
    pub routing: bool,
    pub custom_dns: bool,
    /// v11 — پروکسی بالادست (`--upstream`) از هسته‌ی 1.7.0.
    pub upstream: bool,
    /// v11 — تشخیص نام میزبان از بایت‌های اول برای قواعد دامنه‌ای و
    /// جایگزینی خودکار هویتی که Cloudflare قبولش ندارد. هر دو از 1.7.0.
    pub route_sniff: bool,
    /// ۱.۲.۵ — تور داخل موتور (arti، پشت فیچر `tor`)، از هستهٔ 2.0.0.
    ///
    /// چهار حالت تور فقط وقتی به موتور می‌روند که هستهٔ همراهِ نصب واقعاً
    /// آن‌ها را بشناسد. روی هستهٔ پین‌شدهٔ قدیمی‌تر — یا هسته‌ای که CI بدون
    /// فیچر `tor` ساخته و به آن برگشته — `--tor-only` یک آرگومان ناشناخته است
    /// و موتور همان‌جا می‌مُرد؛ با این گیت، بک‌اند تور بی‌صدا نادیده گرفته
    /// می‌شود و نشست به جای مُردن، ساده وصل می‌شود.
    pub tor: bool,
    /// Core 2.0.0: `--mim` / MASQUE inside MASQUE.
    pub mim: bool,
    /// Core 2.4.0: TLS fingerprint / API-routing environment knobs
    /// (`AETHER_TLS_*`, `AETHER_API_*`, `AETHER_MASQUE_SNI`, ...).
    pub tls24: bool,
}

impl CoreCaps {
    /// همه‌ی قابلیت‌ها خاموش — پیش‌فرضِ محافظه‌کار وقتی نسخه‌ی هسته نامعلوم است.
    pub fn none() -> Self {
        Self {
            zero_trust: false,
            routing: false,
            custom_dns: false,
            upstream: false,
            route_sniff: false,
            tor: false,
            mim: false,
            tls24: false,
        }
    }

    /// همه‌ی قابلیت‌ها فعال — برای تست‌ها و مسیرهایی که نسخه‌ی هسته اهمیت ندارد.
    pub fn all() -> Self {
        Self {
            zero_trust: true,
            routing: true,
            custom_dns: true,
            upstream: true,
            route_sniff: true,
            tor: true,
            mim: true,
            tls24: true,
        }
    }

    /// نگاشت نسخه‌ی هسته به قابلیت‌ها. Zero Trust / routing / --dns از 1.5.0
    /// و پروکسی بالادست / تشخیص نام / بازثبت هویت از 1.7.0.
    pub fn for_version(major: u32, minor: u32) -> Self {
        let v15 = (major, minor) >= (1, 5);
        let v17 = (major, minor) >= (1, 7);
        // تور از 2.0.0. مقایسه روی (major, minor) است، پس هستهٔ 2.1 هم پاس
        // می‌شود و هستهٔ 1.9 نه — دقیقاً همان قاعدهٔ دو ردیف بالاتر.
        let v20 = (major, minor) >= (2, 0);
        Self {
            zero_trust: v15,
            routing: v15,
            custom_dns: v15,
            upstream: v17,
            route_sniff: v17,
            tor: v20,
            mim: v20,
            tls24: (major, minor) >= (2, 4),
        }
    }
}

/// v11 (هسته‌ی 1.7.0) — نوع پروکسی بالادست.
///
/// SOCKS5 با UDP associate هر سه پروتکل را حمل می‌کند؛ HTTP CONNECT فقط
/// TCP است، پس تنها مسیرِ کارآمد از آن، MASQUE روی HTTP/2 است (همان جدولِ
/// `Docs/DOCS.en.md` خودِ هسته).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    Socks5,
    Http,
}

/// آینه‌ی `upstream::Upstream::parse` هسته‌ی 1.7.0.
///
/// چرا اینجا تکرار شده: اگر رشته‌ی کاربر بی‌معنا باشد هسته فقط یک خط خطا
/// لاگ می‌کند و **بی‌صدا** بدون پروکسی ادامه می‌دهد؛ آن‌وقت کاربر خیال
/// می‌کند ترافیکش از پروکسی می‌رود. با این تابع، مقدار نامعتبر هرگز به
/// آرگومان‌ها راه پیدا نمی‌کند و UI هم می‌تواند همان لحظه هشدار بدهد.
///
/// قواعد دقیقاً مثل هسته: طرح‌واره‌ی خالی = `socks5`، پورت الزامی،
/// IPv6 داخل `[]`، و `user:pass@` اختیاری با آخرین `@` به‌عنوان مرز.
pub fn parse_upstream(raw: &str) -> Option<(UpstreamKind, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("socks5".to_string(), raw),
    };

    let kind = match scheme.as_str() {
        "socks5" | "socks5h" | "socks" => UpstreamKind::Socks5,
        "http" | "https" => UpstreamKind::Http,
        _ => return None,
    };

    let endpoint = match rest.rsplit_once('@') {
        Some((_credentials, endpoint)) => endpoint,
        None => rest,
    };
    let endpoint = endpoint.trim_end_matches('/');

    let (host, port) = if let Some(tail) = endpoint.strip_prefix('[') {
        let (host, tail) = tail.split_once(']')?;
        (host, tail.strip_prefix(':')?)
    } else {
        endpoint.rsplit_once(':')?
    };

    if host.is_empty() {
        return None;
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => None,
        Ok(_) => Some((kind, raw.to_string())),
    }
}

pub const DEFAULT_MTU: u32 = 1280;
pub const MTU_PRESETS: [u32; 5] = [1280, 1380, 1420, 1500, 8500];
pub const KEEPALIVE_PRESETS: [u32; 4] = [0, 10, 25, 45];

fn default_verify() -> bool { true }
fn default_health_secs()->u64 {300}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ConnectionProfile {
    /// پشتهٔ شبکه: موتور تنها، یا زنجیرهٔ `Aether → Psiphon`.
    #[serde(default = "default_backend")]
    pub backend: TransportBackend,
    /// کد ISO کشور خروج برای استیج ۲. `""` = خودکار.
    ///
    /// فیلتر **سخت** Psiphon است؛ اگر خروجی آن کشور موجود نباشد
    /// هسته برای آن انتخاب متصل نمی‌شود. حالت خالی انتخاب خودکار است.
    #[serde(default)]
    pub exit_region: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub gool_mode: GoolMode,
    pub scan_mode: ScanMode,
    pub ip_version: IpVersion,
    pub quick_reconnect: bool,
    #[serde(default = "default_verify")]
    pub verify_connection: bool,
    #[serde(default = "default_verify")]
    pub custom_verify_connection: bool,
    #[serde(default)]
    pub custom_auto_select: bool,
    #[serde(default="default_health_secs")]
    pub custom_health_secs: u64,
    /// بازاستفاده از اندپوینتِ کش‌شده فقط در صورتی که همچنان سریع باشد (پیش‌فرض خاموش).
    pub fast_endpoint_only: bool,
    /// پیکربندی سفارشی ECH (یک ECHConfigList با فرمت base64). خالی = خودکار.
    pub ech_config: String,
    pub masque_http2: bool,
    /// اشتراک تونل با دستگاه‌های دیگر روی همان شبکه (پورت‌های 10810/10811).
    #[serde(default)]
    pub lan_share: bool,
    /// v1.2.0 — هنگام قطع تونل، ترافیک مستقیم مرورگرها را قطع می‌کند.
    pub kill_switch: bool,
    /// v1.2.0 — IPv6 عمومی فقط از مسیر حفاظت‌شده عبور کند؛ پیش‌فرض روشن.
    pub ipv6_protection: bool,
    /// v1.2.0 — سقف تلاش‌های اتصال مجدد خودکار، بین ۳ تا ۲۰.
    pub reconnect_attempts: u32,
    /// v1.2.0 — گارد نشتی WebRTC/UDP. پیش‌فرض **روشن**.
    ///
    /// مسیر دادهٔ ویندوز پروکسی است و پروکسی فقط TCP را می‌گیرد؛ بدون این
    /// گارد، WebRTC با UDP خام به سرور STUN می‌رود و آی‌پی واقعی کاربر را لو
    /// می‌دهد (همان چیزی که در «WebRTC Leak Test» دیده می‌شد). فقط برای
    /// موارد خیلی خاص — مثل تماس تصویری داخلِ شبکهٔ سازمانی — خاموش می‌شود.
    pub leak_guard: bool,
    pub noize: Noize,
    pub endpoint_mode: EndpointMode,
    pub manual_peer: String,
    pub manual_range: String,
    pub keepalive: u32,
    pub fragment: bool,
    pub ech: bool,
    pub mtu: u32,
    // ---------------------------------------------------------------------
    // عمداً حذف شده نسبت به اندروید: `proxyMode`.
    // در ویندوز هیچ اپلیکیشنی به SOCKS5 محلی «به‌جای» VPN نیاز ندارد چون
    // Wintun کل سیستم را می‌گیرد و پروکسی سیستمی هم بومی است؛ نگه داشتنش
    // فقط یک مسیر کد بلااستفاده و یک حالت خطای اضافه می‌ساخت.
    // ---------------------------------------------------------------------
    pub split_mode: SplitMode,
    /// در ویندوز به‌جای package name، مسیر یا نام فرآیند (`chrome.exe`).
    pub split_apps: Vec<String>,

    // ====================================================================
    //  v10 — قابلیت‌های هسته‌ی 1.5.0 (هم‌ترازی با نسخه‌ی اندروید)
    // ====================================================================
    /// Zero Trust: نام سازمان (تیم) Cloudflare. خالی = ثبت‌نام معمولی WARP.
    pub team: String,
    /// روش احراز هویتِ Zero Trust.
    pub access_mode: AccessMode,
    /// ایمیل برای دریافت کد یک‌بارمصرف (فقط AccessMode::Email).
    pub access_email: String,
    /// شناسه‌ی توکن سرویس Access (فقط AccessMode::ServiceToken). غیرمحرمانه.
    pub access_id: String,
    /// عبور تمام HTTP/HTTPS از پراکسیِ Gateway سازمان (فیلترینگ/لاگِ سازمانی).
    /// پیش‌فرض خاموش — دقیقاً مثل هسته: یک هاپ اضافه و لاگ مرور را می‌افزاید.
    pub gateway: bool,

    /// قوانین مسیریابی: مقصدهایی که کاملاً مسدود می‌شوند (`--route-block`).
    pub route_block: Vec<String>,
    /// قوانین مسیریابی: مقصدهایی که از مسیر مستقیم (نه تونل) می‌روند
    /// (`--route-direct`) — برای بانک، سرویس‌های LAN و سایت‌های داخلی.
    pub route_direct: Vec<String>,

    /// ۱.۴.۰ (#66) — «دور زدن سایت‌های ایرانی»: هر نام `.ir`، سرویس‌های شناختهٔ
    /// ایرانی روی دامنه‌های دیگر و همهٔ بلوک‌های IPv4 ایران مستقیم بیرون
    /// می‌روند، نه از تونل. در اشتراکِ LAN اعمال نمی‌شود. پیش‌فرض خاموش.
    #[serde(default)]
    pub bypass_iran: bool,
    /// ۱.۴.۰ (#67) — «مسدودسازی تبلیغات و ردیاب‌ها» در همهٔ حالت‌ها. پیش‌فرض خاموش.
    #[serde(default)]
    pub block_ads: bool,

    /// DNS داخل تونل (`--dns`). خالی = پیش‌فرض هسته.
    pub dns: Vec<String>,

    // ====================================================================
    //  v11 — قابلیت‌های هسته‌ی 1.7.0
    // ====================================================================
    /// پروکسی بالادست (`--upstream`): هسته همه‌ی اتصال‌های بیرونی‌اش را از
    /// این پروکسی می‌گیرد تا بتوان اِتِر را پشت یک VPN یا پروکسیِ در حال
    /// اجرا روی همین ویندوز زنجیره کرد. خالی = اتصال مستقیم (پیش‌فرض).
    pub upstream: String,
    /// تشخیص نام میزبان از بایت‌های اول (`AETHER_ROUTE_SNIFF`).
    ///
    /// در ویندوز مسیر داده همیشه Wintun است؛ یعنی وقتی قاعده‌ی دامنه‌ای
    /// داریم پروکسی فقط یک آی‌پی می‌بیند و قواعد دامنه بی‌اثر می‌شدند.
    /// هسته‌ی 1.7.0 نام را از SNI یا هدر Host می‌خواند. پیش‌فرض **روشن** —
    /// دقیقاً مثل خود هسته.
    pub route_sniff: bool,
    /// Core 2.4.0 — TLS / API tuning. Empty string or `false` = core default
    /// (nothing is sent). All values are sanitised in `to_env_with_caps`.
    pub tls_verify: bool,
    pub api_address: String,
    pub api_sni: String,
    pub api_host: String,
    pub masque_sni: String,
    pub tls_ciphers: String,
    pub tls13_ciphers: String,
    pub tls_groups: String,
    pub tls_key_shares: String,
    pub tls_sigalgs: String,
    pub tls_cert_compression: String,
    /// `""`, `"new"` or `"old"`.
    pub tls_alps: String,
    pub tls_trust_anchors: String,
    pub tls_server_padding: String,
    pub disable_grease: bool,
    pub enable_grease_sigalgs: bool,
    pub enable_ech_grease: bool,
    pub disable_ocsp_stapling: bool,
    pub disable_sct: bool,
    pub disable_session_ticket: bool,
    pub disable_extension_permutation: bool,
    /// Revision of the settings *defaults* this profile was written against.
    ///
    /// Not a user setting and not shown anywhere. It exists so a default that
    /// turns out to be wrong can be corrected on profiles that are already on
    /// disk. Old files have no such key, so they deserialise as `0` (see
    /// [`settings_rev_legacy`]) and get migrated once by `ProfileStore::load`.
    #[serde(default = "settings_rev_legacy")]
    pub settings_rev: u32,
    /// جایگزینی خودکار هویتی که Cloudflare دیگر نمی‌پذیرد
    /// (`AETHER_REPROVISION`). پیش‌فرض روشن: وگرنه تونل دست می‌دهد ولی
    /// هیچ ترافیکی عبور نمی‌کند.
    pub reprovision: bool,

    // ----- اسرارِ در-حافظه (هرگز روی دیسک نوشته نمی‌شوند) ----------------
    // سخت‌سازی امنیتی: توکن سرویس و JWT حساس‌اند و مثل رفتار خودِ هسته
    // (کش در حافظه برای طول عمر فرآیند) فقط در حافظه نگه‌داری می‌شوند.
    // `skip_serializing` یعنی UI می‌تواند مقدار را بفرستد (deserialize مجاز)
    // ولی هیچ‌وقت در profile.json یا پاسخ get_profile برنمی‌گردد — نه هنگام
    // ذخیرهٔ معمول، نه هنگام Reset، نه در خروجی لاگ.
    // ====================================================================
    //  ۱.۲.۵ — تور (هستهٔ ۲.۰.۰)
    // ====================================================================
    /// آیا تور از راه پل به شبکه برسد. فقط وقتی خوانده می‌شود که خودِ تور
    /// روبروی شبکهٔ محلی باشد، یعنی در دو حالت `--tor-only`.
    #[serde(default)]
    pub tor_bridges: TorBridges,
    /// سطرهای پلی که کاربر دستی چسبانده، یکی در هر خط، به جای پل‌هایی که
    /// موتور از bridgedb می‌گیرد.
    ///
    /// یک سطر چنین شکلی دارد:
    /// `obfs4 192.0.2.55:38114 <FINGERPRINT> cert=... iat-mode=0`. هر چیزی که
    /// با نام یک ترانسپورت شناخته‌شده شروع نشود، [Self::sanitized_bridges] آن را
    /// می‌اندازد و نمی‌فرستد — وگرنه یک سطر بدشکل به آرگومان دومِ موتور تبدیل
    /// می‌شد.
    #[serde(default)]
    pub tor_bridge_lines: String,
    /// کد دوحرفی کشور برای bridgedb، یا خالی تا موتور خودش تشخیص دهد.
    ///
    /// ارزش دستی‌گذاشتن دارد: تشخیص خود موتور (`detect_country` در
    /// `bridges.rs`) از endpoint‌ِ trace کلادفلر می‌پرسد کجاست — و درست روی
    /// شبکه‌هایی که پل بیشترین اهمیت را دارد، همان درخواست شکست می‌خورد یا
    /// مکان اشتباه می‌دهد.
    ///
    /// موتور دقیقاً دو حرف می‌خواهد و خودش کوچکشان می‌کند؛ هر چیز دیگری را
    /// [Self::sanitized_tor_country] می‌اندازد و نمی‌فرستد، چون مقدارِ ردشده
    /// بی‌صدا به تشخیص خودکار برمی‌گشت و شبیه این می‌شد که تنظیم کاری نکرد.
    #[serde(default)]
    pub tor_country: String,
    /// چند ثانیه تور اجازه دارد مستقیم تلاش کند پیش از آنکه پل بیاید.
    /// `0` = همان ۷۵ ثانیهٔ خودِ موتور.
    #[serde(default)]
    pub tor_direct_secs: u32,
    /// `host:port` که تور باید بتواند به آن برسد تا موتور bootstrap را
    /// موفق بداند. خالی = همان `check.torproject.org:443` موتور.
    ///
    /// پیش‌فرض خودش هدف سانسور است: شبکه‌ای که check.torproject.org را
    /// می‌بندد، یک مدار تورِ کاملاً سالم را در این اثبات ناموفق نشان می‌دهد و
    /// برنامه برای توری که مشکلی نداشت شکست bootstrap گزارش می‌کند.
    #[serde(default)]
    pub tor_check: String,

    /// راز توکن سرویس Access (فقط AccessMode::ServiceToken).
    #[serde(skip_serializing, default)]
    pub access_secret: String,
    /// JWT از پیش‌گرفته‌شده (فقط AccessMode::Token).
    #[serde(skip_serializing, default)]
    pub access_token: String,
}

/// پیش‌فرضِ `serde` برای پروفایل‌هایی که پیش از ۱.۲.۳ ذخیره شده‌اند.
fn default_backend() -> TransportBackend {
    TransportBackend::Aether
}

/// Current settings-defaults revision. Bump this whenever a default changes in
/// a way that must also reach profiles already saved on disk.
// rev 4: کاربر در آزمونِ ۱۶ سپتامبر «تور تنها» را انتخاب کرده بود و همان
// ماند، چون مهاجرت یک‌بار در rev 3 اجرا شده بود. این نسخه یک‌بارِ دیگر
// بک‌اند را به Aether برمی‌گرداند — نسخهٔ برنامه (۱.۲.۵) دست نمی‌خورد.
pub const SETTINGS_REV: u32 = 4;

/// A profile file with no `settingsRev` key predates the mechanism.
fn settings_rev_legacy() -> u32 {
    0
}

impl Default for ConnectionProfile {
    fn default() -> Self {
        Self {
            backend: TransportBackend::Aether,
            exit_region: String::new(),
            protocol: Protocol::Smart,
            gool_mode: GoolMode::Modern,
            // 1.2.5: BALANCED, byte for byte the mobile 1.3.0 default.
            //
            // Turbo used to sit here to imitate the mobile ladder, which scans
            // every rung in Turbo. That imitation was in the wrong place: on
            // mobile the ladder sets TURBO per attempt (SmartAuto.kt) while the
            // stored profile stays BALANCED, so a user on a MANUAL protocol --
            // who has no ladder -- gets the full 150 s scan budget there and got
            // only 60 s here. `auto_plan` now sets Turbo per rung, which is
            // where it belongs, and this value is the mobile one.
            scan_mode: ScanMode::Balanced,
            ip_version: IpVersion::V4,
            quick_reconnect: true,
            verify_connection: true,
            custom_verify_connection: true,
            custom_auto_select:false,
            custom_health_secs:300,
            fast_endpoint_only: false,
            ech_config: String::new(),
            masque_http2: false,
            lan_share: false,
            kill_switch: true,
            ipv6_protection: true,
            // مثل موبایل ۱.۳.۰ (`reconnectRetryLimit = 5`). سقف پایینِ ۳ در
            // `sanitize` سرِ جایش می‌ماند.
            reconnect_attempts: 5,
            leak_guard: true,
            noize: Noize::Off,
            endpoint_mode: EndpointMode::Auto,
            manual_peer: String::new(),
            manual_range: String::new(),
            keepalive: 0,
            fragment: false,
            ech: false,
            mtu: DEFAULT_MTU,
            split_mode: SplitMode::Off,
            split_apps: Vec::new(),
            team: String::new(),
            access_mode: AccessMode::Off,
            access_email: String::new(),
            access_id: String::new(),
            gateway: false,
            route_block: Vec::new(),
            route_direct: Vec::new(),
            bypass_iran: false,
            block_ads: false,
            dns: Vec::new(),
            upstream: String::new(),
            route_sniff: true,
            tls_verify: false,
            api_address: String::new(),
            api_sni: String::new(),
            api_host: String::new(),
            masque_sni: String::new(),
            tls_ciphers: String::new(),
            tls13_ciphers: String::new(),
            tls_groups: String::new(),
            tls_key_shares: String::new(),
            tls_sigalgs: String::new(),
            tls_cert_compression: String::new(),
            tls_alps: String::new(),
            tls_trust_anchors: String::new(),
            tls_server_padding: String::new(),
            disable_grease: false,
            enable_grease_sigalgs: false,
            enable_ech_grease: false,
            disable_ocsp_stapling: false,
            disable_sct: false,
            disable_session_ticket: false,
            disable_extension_permutation: false,
            reprovision: true,
            settings_rev: SETTINGS_REV,
            // ۱.۲.۵ — هر پنج تنظیم تور روی «همان کاری که موتور خودش می‌کند»
            // است، پس یک پروفایل پیش‌فرض هیچ متغیر توری نمی‌فرستد.
            tor_bridges: TorBridges::Auto,
            tor_bridge_lines: String::new(),
            tor_country: String::new(),
            tor_direct_secs: 0,
            tor_check: String::new(),
            access_secret: String::new(),
            access_token: String::new(),
        }
    }
}

impl ConnectionProfile {
    /// Clamp user-controlled resilience settings at the trust boundary.
    pub fn normalize(&mut self) {
        self.reconnect_attempts = self.reconnect_attempts.clamp(3, 20);
        // Leak protection is mandatory and intentionally not user-editable.
        self.leak_guard = true;
        // تنها دروازهٔ اعتبارسنجی کشور خروج. مقدار مستقیم داخل JSON کانفیگ
        // Psiphon می‌نشیند، پس هر کد ناشناخته‌ای به «خودکار» تبدیل می‌شود.
        self.exit_region = crate::exit_regions::normalize(&self.exit_region);
        // ۱.۲.۵ — کرانِ ثانیه‌های تلاش مستقیم تور. `0` معنای خودش را دارد
        // («پیش‌فرض موتور») و باید از کران پایین رد شود، پس فقط مقدارهای
        // ناصفر بسته می‌شوند.
        if self.tor_direct_secs > 0 {
            self.tor_direct_secs = self.tor_direct_secs.clamp(5, 600);
        }
    }

    /// آیا از تور خواسته شده که از راه پل به شبکه برسد؟
    pub fn has_custom_bridges(&self) -> bool {
        !self.tor_bridge_lines.trim().is_empty() && !self.sanitized_bridges().is_empty()
    }

    /// پروتکلی که واقعاً از موتور خواسته می‌شود.
    ///
    /// دقیقاً در یک حالت با [Self::protocol] تفاوت دارد: زنجیرهٔ برعکس. تور
    /// فقط TCP حمل می‌کند و لبه‌های WireGuardِ وارپ تنها روی UDP جواب می‌دهند،
    /// پس هستهٔ ۲.۰.۰ حالت `--tor-reverse` را روی MASQUE/HTTP-2 اجرا می‌کند و
    /// **`--wg` و `--gool` را رد می‌کند**. فرستادن انتخابِ WireGuardِ کاربر در
    /// این حالت باعث می‌شد موتور بی‌درنگ خارج شود — که از دید برنامه از یک
    /// شبکهٔ بسته قابل تفکیک نیست و همان‌طور هم تشخیص داده می‌شد. پس بازنویسی
    /// همین‌جا، یک‌جا، انجام می‌شود؛ جایی که هر argv ساخته می‌شود، نه در هر
    /// فراخواننده. رابط کاربری هم کنار انتخابگرِ غیرفعالِ پروتکل همین را
    /// می‌گوید.
    pub fn effective_protocol(&self) -> Protocol {
        if self.backend.tor_mode() == Some(TorMode::Reverse) {
            Protocol::Masque
        } else {
            self.protocol
        }
    }

    /// کد کشور به شکلی که موتور می‌پذیرد، یا `None`.
    ///
    /// دو حرف ASCII، کوچک‌شده. هر چیز دیگری `None` است و چیزی فرستاده
    /// نمی‌شود: موتور خودش هم نادیده‌اش می‌گرفت، و متغیری که هست ولی نادیده
    /// گرفته می‌شود سخت‌تر از متغیری است که هرگز ست نشده.
    pub fn sanitized_tor_country(&self) -> Option<String> {
        let code = self.tor_country.trim().to_ascii_lowercase();
        (code.len() == 2 && code.bytes().all(|b| b.is_ascii_lowercase())).then_some(code)
    }

    /// هدفِ دسترسی‌پذیری به شکل `host:port`، یا `None` وقتی قابل استفاده نیست.
    ///
    /// عمداً سخت‌گیر است. موتور این را با `rsplit_once(':')` می‌خواند و روی
    /// پورت بد بی‌صدا به ۴۴۳ برمی‌گردد، پس یک غلط تایپی به هدفی **دیگر**
    /// تبدیل می‌شد نه به خطا — و این تنها کاری است که این تنظیم نباید بکند،
    /// چون کل وظیفه‌اش تشخیص تورِ سالم از تورِ خراب است.
    pub fn sanitized_tor_check(&self) -> Option<String> {
        let raw = self.tor_check.trim();
        if raw.is_empty() || raw.chars().any(char::is_whitespace) {
            return None;
        }
        let (host, port) = match raw.rsplit_once(':') {
            // دنبالهٔ عددی = پورت. غیرعددی یعنی این کولون مالِ یک آدرس IPv6
            // است و پورتی در کار نیست — که تنها وقتی پذیرفته می‌شود که واقعاً
            // چند کولون داشته باشد.
            Some((head, tail)) => match tail.parse::<u32>() {
                Ok(p) if (1..=65_535).contains(&p) => (head, Some(p)),
                Ok(_) => return None,
                Err(_) if raw.matches(':').count() > 1 => (raw, None),
                Err(_) => return None,
            },
            None => (raw, None),
        };
        if host.is_empty() || host.len() > 253 {
            return None;
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
        {
            return None;
        }
        Some(match port {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        })
    }

    /// سطرهای پلِ اعتبارسنجی‌شده برای `--tor-bridge`، هر ورودی یک آرگومان.
    pub fn sanitized_bridges(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in self.tor_bridge_lines.split(['\n', ';']) {
            let line = line.trim();
            if line.is_empty() || !is_bridge_line(line) || out.iter().any(|k| k == line) {
                continue;
            }
            out.push(line.to_string());
            if out.len() == MAX_BRIDGE_LINES {
                break;
            }
        }
        out
    }

    /// آیا این نشست استیج ۲ را لازم دارد؟
    pub fn is_chained(&self) -> bool {
        self.backend.is_chained()
    }

    /// پروفایلِ **استیج ۱** یک نشست زنجیره‌ای.
    ///
    /// معادل `connectAetherStage` اندروید. استیج ۱ نه مسیر داده دارد و نه پل:
    /// آن‌ها مال زنجیرهٔ تمام‌شده‌اند، و اگر استیج ۱ بسازدشان ترافیک خود موتور
    /// را می‌گیرند و تونل داخل خودش قفل می‌شود.
    ///
    /// `upstream` هم پاک می‌شود: پروکسی بالادستِ کاربر مال موتور است و باید
    /// همان‌جا بماند، ولی `lan_share` نباید روی استیج ۱ چیزی باز کند.
    pub fn chained_stage(&self) -> Self {
        let mut stage = self.clone();
        // ۱.۲.۵ — در `Tor → Psiphon` استیج ۱ **خود تور** است، نه اِتِر. اگر
        // این‌جا مثل قبل روی `Aether` می‌افتاد، Psiphon از یک تونل WARP بیرون
        // می‌رفت و کاربری که تور را انتخاب کرده بود اصلاً از تور رد نمی‌شد —
        // یک نشستِ به‌ظاهر موفق با خروجیِ کاملاً اشتباه.
        stage.backend = if self.backend.tor_mode() == Some(TorMode::Only) {
            TransportBackend::Tor
        } else {
            TransportBackend::Aether
        };
        stage.lan_share = false;
        // >>> AETHER-APP-PATCH psiphon-stage-has-no-routing-rules (mobile 1.4.0 `connectAetherStage`)
        // در حالت Psiphon موتورِ استیج ۱ فقط اتصال‌های Psiphon به سرورهایش را
        // می‌بیند؛ قواعد block/direct آن‌جا یا بی‌اثرند یا — بدتر — یک سرورِ
        // Psiphon را مستقیم بیرون می‌فرستند. همهٔ قواعد در پل اعمال می‌شوند
        // (`smart_lists::front_rules` → `smart_routes::set_front`).
        stage.route_block.clear();
        stage.route_direct.clear();
        stage.bypass_iran = false;
        stage.block_ads = false;
        // <<< AETHER-APP-PATCH psiphon-stage-has-no-routing-rules
        stage
    }

    /// آدرسی که Psiphon به‌عنوان `UpstreamProxyUrl` می‌گیرد — یعنی استیج ۱.
    pub fn chain_upstream_url() -> String {
        format!("socks5://127.0.0.1:{}", crate::engine::LOCAL_SOCKS_PORT)
    }

    pub fn has_manual_peer(&self) -> bool {
        self.endpoint_mode == EndpointMode::ManualPeer && !self.manual_peer.trim().is_empty()
    }

    /// آیا این پروفایل قصد ورود به یک سازمان Zero Trust را دارد؟
    pub fn uses_zero_trust(&self) -> bool {
        !self.team.trim().is_empty()
    }

    /// v11 — پروکسی بالادستِ معتبر، یا None اگر خالی/نامعتبر باشد.
    pub fn upstream_proxy(&self) -> Option<(UpstreamKind, String)> {
        parse_upstream(&self.upstream)
    }

    /// v11 — آیا پروکسی بالادست فقط TCP است؟ HTTP CONNECT نمی‌تواند UDP
    /// حمل کند، پس MASQUE باید روی HTTP/2 برود و WireGuard/WARP×2 از این
    /// نوع پروکسی رد نمی‌شوند.
    pub fn upstream_is_tcp_only(&self) -> bool {
        matches!(self.upstream_proxy(), Some((UpstreamKind::Http, _)))
    }

    /// معادل `Profile.kt::toArgs()` — رفتار قدیمی حفظ می‌شود.
    /// همه‌ی قابلیت‌ها فعال فرض می‌شوند؛ چون فیلدهای جدید به‌طور پیش‌فرض
    /// خالی‌اند، خروجی برای پروفایل پیش‌فرض دقیقاً مثل قبل است (قرارداد اندروید).
    pub fn to_args(&self) -> Vec<String> {
        self.to_args_with_caps(CoreCaps::all())
    }

    /// نسخه‌ی گِیت‌شده‌ی `toArgs()` — فلگ‌های 1.5.0 فقط با هسته‌ی سازگار.
    pub fn to_args_with_caps(&self, caps: CoreCaps) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();

        // ----- تور (هستهٔ ۲.۰.۰) ----------------------------------------
        //
        // **اول** فرستاده می‌شود، چون در حالت‌های `--tor-only` تعیین می‌کند که
        // بیشترِ آنچه بعد می‌آید نباید فرستاده شود: تونلی نیست، پس لبه‌ای برای
        // اسکن، ترانسپورتی برای مبهم‌سازی و هویت WARPی برای گرفتن هم نیست.
        // فرستادنشان یعنی از موتور کاری بخواهیم که نتیجه‌اش را چیزی نمی‌خواند.
        //
        // گِیتِ `caps.tor`: روی هستهٔ قدیمی‌تر — یا هسته‌ای که بدون فیچر `tor`
        // ساخته شده — این فلگ‌ها آرگومان ناشناخته‌اند و موتور همان‌جا خارج
        // می‌شود. آن‌وقت بک‌اند تور بی‌صدا به نشست ساده تبدیل می‌شود، که رفتار
        // درست است: مسیر rollback هرگز نباید انتشار را بکشد.
        let tor_mode = if caps.tor {
            self.backend.tor_mode()
        } else {
            None
        };
        match tor_mode {
            None => {}
            Some(TorMode::Chain) => {
                args.push("--tor".into());
                args.push("--tor-bind".into());
                args.push(format!("127.0.0.1:{}", crate::engine::TOR_SOCKS_PORT));
            }
            Some(TorMode::Only) => args.push("--tor-only".into()),
            Some(TorMode::Reverse) => {
                args.push("--tor-reverse".into());
                args.push("--tor-bind".into());
                args.push(format!("127.0.0.1:{}", crate::engine::TOR_SOCKS_PORT));
            }
        }
        if tor_mode.is_some() {
            // پل فقط وقتی معنا دارد که تور خودش باید به شبکه برسد، یعنی هر دو
            // حالتی که تور روبروی شبکهٔ محلی است. در حالت زنجیره‌ای تور از
            // داخل تونل dial می‌شود، پس چیزی برای پنهان کردن از شبکه نیست.
            if tor_mode != Some(TorMode::Chain) {
                match self.tor_bridges {
                    TorBridges::Auto => {}
                    TorBridges::Always => args.push("--tor-bridges".into()),
                    TorBridges::Off => args.push("--no-tor-bridges".into()),
                }
                for line in self.sanitized_bridges() {
                    args.push("--tor-bridge".into());
                    args.push(line);
                }
            }
        }
        if self.backend.is_chained() {
            args.push("--psiphon".into());
            args.push("--psiphon-bind".into());
            args.push(format!("127.0.0.1:{}", crate::engine::CHAIN_SOCKS_PORT));
            let region = self.exit_region.trim().to_ascii_uppercase();
            if region.len() == 2 && region.bytes().all(|b| b.is_ascii_alphabetic()) {
                args.push("--psiphon-region".into());
                args.push(region);
            }
        }
        if !self.backend.uses_warp() && tor_mode.is_some() {
            // تورِ تنها: resolverها هنوز اثر دارند (همان چیزی‌اند که SOCKS
            // خودِ موتور تحویل می‌دهد)، ولی هیچ‌چیز دیگری از این تابع نه.
            if caps.custom_dns {
                let dns = clean_list(&self.dns);
                if !dns.is_empty() {
                    args.push("--dns".into());
                    args.push(dns.join(","));
                }
            }
            return args;
        }

        match self.effective_protocol() {
            // AUTO هرگز به موتور نمی‌رسد: SmartAuto قبل از اجرا آن را به یک
            // پروتکل مشخص تبدیل می‌کند (دقیقاً مثل اندروید).
            Protocol::Smart => {}
            Protocol::Masque => args.push("--masque".into()),
            Protocol::Wireguard => args.push("--wg".into()),
            Protocol::Gool => args.push(
                match self.gool_mode {
                    GoolMode::Modern => "--gool",
                    GoolMode::Classic => "--gool-classic",
                }
                .into(),
            ),
            Protocol::Mim => {
                if caps.mim {
                    args.push("--mim".into())
                }
            }
        }

        if !self.has_manual_peer() {
            args.push(
                match self.scan_mode {
                    ScanMode::Turbo => "--turbo",
                    ScanMode::Balanced => "--balanced",
                    ScanMode::Thorough => "--thorough",
                    ScanMode::Stealth => "--stealth",
                    ScanMode::Ironclad => "--ironclad",
                }
                .into(),
            );
        }

        args.push(
            match self.ip_version {
                IpVersion::V4 => "-4",
                IpVersion::V6 => "-6",
                IpVersion::Both => "--dual",
            }
            .into(),
        );

        args.push(
            if self.quick_reconnect {
                "--quick-reconnect"
            } else {
                "--no-quick-reconnect"
            }
            .into(),
        );

        // 1.2.3: `Off` has to be SENT, not omitted.
        //
        // The engine's own fallback when `AETHER_NOIZE` is absent is `firewall`
        // (`lib.rs::noize_config`), so leaving the flag out never turned
        // obfuscation off - it silently selected a heavier profile than the panel
        // was displaying. The logs show it plainly: the panel said Noize = Off
        // and the engine answered `[+] obfuscation profile: firewall`. Every
        // junk packet and every padded handshake that profile adds was being
        // paid on a connection the user believed was clean.
        args.push("--noize".into());
        args.push(format!("{:?}", self.noize).to_lowercase());

        if self.has_manual_peer() {
            args.push("--peer".into());
            args.push(self.manual_peer.trim().to_string());
        }

        if self.fragment {
            args.push("--fragment".into());
        }
        if self.ech {
            args.push("--ech".into());
            let pasted = self.ech_config.trim();
            if !pasted.is_empty() && looks_like_base64(pasted) {
                args.push(pasted.to_string());
            } else {
                args.push("auto".into());
            }
        }
        if self.keepalive > 0 {
            args.push("--keepalive".into());
            args.push(self.keepalive.to_string());
        }

        // ----- Zero Trust / WARP سازمانی (هسته‌ی 1.5.0) -----------------
        if caps.zero_trust && self.uses_zero_trust() {
            args.push("--team".into());
            args.push(self.team.trim().to_string());
            match self.access_mode {
                AccessMode::Email if !self.access_email.trim().is_empty() => {
                    args.push("--access-email".into());
                    args.push(self.access_email.trim().to_string());
                }
                AccessMode::ServiceToken
                    if !self.access_id.trim().is_empty()
                        && !self.access_secret.trim().is_empty() =>
                {
                    args.push("--access-id".into());
                    args.push(self.access_id.trim().to_string());
                    args.push("--access-secret".into());
                    args.push(self.access_secret.trim().to_string());
                }
                AccessMode::Token if !self.access_token.trim().is_empty() => {
                    args.push("--access-token".into());
                    args.push(self.access_token.trim().to_string());
                }
                _ => {}
            }
            if self.gateway {
                args.push("--gateway".into());
            }
        }

        // ----- قوانین مسیریابی (هسته‌ی 1.5.0) ---------------------------
        if caps.routing {
            let block: Vec<String> = clean_list(&self.route_block);
            if !block.is_empty() {
                args.push("--route-block".into());
                args.push(block.join(","));
            }
            let direct: Vec<String> = clean_list(&self.route_direct);
            if !direct.is_empty() {
                args.push("--route-direct".into());
                args.push(direct.join(","));
            }
        }

        // ----- DNS داخل تونل (هسته‌ی 1.5.0) -----------------------------
        if caps.custom_dns {
            let dns: Vec<String> = clean_list(&self.dns);
            if !dns.is_empty() {
                args.push("--dns".into());
                args.push(dns.join(","));
            }
        }

        // ----- پروکسی بالادست (هسته‌ی 1.7.0) ----------------------------
        // مقدار نامعتبر عمداً فرستاده نمی‌شود؛ هسته آن را بی‌صدا نادیده
        // می‌گیرد و کاربر گمان می‌کند زنجیره برقرار است.
        if caps.upstream {
            if let Some((_, value)) = self.upstream_proxy() {
                args.push("--upstream".into());
                args.push(value);
            }
        }

        args
    }

    /// معادل دقیق `Profile.kt::toEnv()` — رفتار قدیمی حفظ می‌شود.
    pub fn to_env(&self) -> BTreeMap<String, String> {
        self.to_env_with_caps(CoreCaps::all())
    }

    /// v11 — نسخه‌ی گِیت‌شده‌ی `toEnv()`. متغیرهای 1.7.0 فقط به هسته‌ای
    /// فرستاده می‌شوند که آن‌ها را می‌فهمد؛ همان قاعده‌ی همیشگیِ «هیچ‌چیز
    /// ناشناخته‌ای به موتور نفرست».
    pub fn to_env_with_caps(&self, caps: CoreCaps) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();

        // Core 2.4.0 TLS / API knobs — never sent to an older pinned core.
        if caps.tls24 {
            env.extend(self.tls24_env());
        }

        // HTTP CONNECT هیچ UDP‌ای حمل نمی‌کند؛ با پروکسی بالادستِ HTTP تنها
        // مسیر کارآمد MASQUE روی HTTP/2 است. پس همان چیزی که هسته با
        // `--h2` می‌فهمد را خودمان روشن می‌کنیم تا کاربر با یک تونلِ خاموش
        // تنها نماند.
        // زنجیرهٔ برعکس هم چاره‌ای ندارد: تور فقط TCP حمل می‌کند، پس MASQUE
        // باید روی HTTP/2 برود — همان دلیلی که `effective_protocol` را دارد.
        let force_h2 = (caps.upstream && self.upstream_is_tcp_only())
            || (caps.tor && self.backend.tor_mode() == Some(TorMode::Reverse));
        env.insert(
            "AETHER_MASQUE_HTTP2".into(),
            if self.masque_http2 || force_h2 {
                "1".into()
            } else {
                "0".into()
            },
        );

        // بازه‌هایی که اسکنر موتور اجازه دارد در نظر بگیرد.
        //
        // 1.2.4: تا اینجا این سه متغیر فرستاده می‌شد و هستهٔ دسکتاپ هیچ‌کدام را
        // نمی‌خواند — «بازهٔ آدرس» تنظیمی بود که فقط ادای کار کردن درمی‌آورد.
        // پچِ `AETHER-APP-PATCH scan-cidrs` در prober.rs / wg_prober.rs /
        // wireguard.rs همین‌ها را می‌خواند: متغیرِ مخصوصِ پروتکل مقدم است و
        // AETHER_SCAN_CIDRS پشتیبانِ هر دو. دانه‌های توکارِ بیرون از بازه هم
        // پروب نمی‌شوند، وگرنه تونل روی آدرسی بسته می‌شد که کاربر نخواسته.
        //
        // این متغیرها گِیتِ نسخه ندارند: هسته‌ای که همراه برنامه می‌آید همیشه
        // همین بیلدِ پچ‌خورده است. روی هستهٔ پین‌شدهٔ قدیمی‌تر بی‌اثر می‌مانند.
        let range = self.manual_range.trim();
        if self.endpoint_mode == EndpointMode::ManualRange && !range.is_empty() {
            env.insert("AETHER_SCAN_CIDRS".into(), range.to_string());
            env.insert("AETHER_MASQUE_CIDRS".into(), range.to_string());
            env.insert("AETHER_WG_CIDRS".into(), range.to_string());
        }

        // ----- تور (هستهٔ ۲.۰.۰) ----------------------------------------
        //
        // فقط وقتی فرستاده می‌شود که بک‌اند واقعاً تور را اجرا کند، و فقط وقتی
        // کاربر از پیش‌فرض موتور فاصله گرفته باشد. فرستادنِ همیشگی یعنی برنامه
        // مالکِ مقدارهایی شود که باید مالِ موتور بمانند.
        if caps.tor && self.backend.uses_tor() {
            if let Some(check) = self.sanitized_tor_check() {
                env.insert("AETHER_TOR_CHECK".into(), check);
            }
            if self.backend.tor_mode() != Some(TorMode::Chain) {
                // هر دو فقط تا وقتی معنا دارند که تور خودش روبروی شبکه است:
                // در حالت زنجیره‌ای bridgedb پرسیده نمی‌شود و پروبِ مستقیم
                // داخل تونل اجرا می‌شود، جایی که آن چیزی نیست که گیر می‌کند.
                if let Some(country) = self.sanitized_tor_country() {
                    env.insert("AETHER_TOR_COUNTRY".into(), country);
                }
                if self.tor_direct_secs > 0 {
                    env.insert(
                        "AETHER_TOR_DIRECT_SECS".into(),
                        self.tor_direct_secs.clamp(5, 600).to_string(),
                    );
                }
                // ۱.۲.۶ — تا پلِ دومی هم نوبت بگیرد، پیش از آنکه کاربر تسلیم شود.
                //
                // این عدد از حساب کردنِ خودِ لاگ میدانی آمد، نه از حدس. موتور
                // ترانسپورت‌ها را به ترتیبِ `obfs4 → snowflake → meek_lite`
                // می‌آزماید و هر کدام `WAVE_TRIES = 2` دور دارد، هر دور با
                // `AETHER_TOR_STALL_SECS` (پیش‌فرض ۷۵ ثانیه) رها می‌شود. یعنی با
                // پیش‌فرض، snowflake پیش از ثانیهٔ ۱۵۰ حتی شروع نمی‌شود:
                //
                // ```text
                //   obfs4: go 1 of 2, dropped after 75s without headway
                //   Could not connect to guard … via obfs4 … (هر شش‌تا)
                //   No usable guards. Rejected 6/6 as down
                // ```
                //
                // در آن لاگ کاربر ۵۸ ثانیه بعد قطع کرد، پس نه snowflake و نه
                // meek_lite هرگز آزموده نشدند — درست همان دو ترانسپورتی که
                // domain-fronted هستند و روی شبکه‌ای که obfs4ِ عمومیِ توکار را
                // شمارش و بسته است، تنها شانسِ باقی‌مانده‌اند. با ۴۰ ثانیه،
                // obfs4 در ~۸۰ ثانیه تمام می‌شود و کل نردبان (۳ ترانسپورت × ۲
                // دور × ۴۰) ۲۴۰ ثانیه می‌گیرد؛ هم زیر `AETHER_TOR_BRIDGE_SECS`
                // (۳۶۰) می‌ماند و هم زیر بودجهٔ خودِ برنامه
                // ([crate::diagnostics::TOR_BRIDGE_BUDGET_MS] = ۶۰۰ ثانیه).
                //
                // شکستِ obfs4 در همان ثانیه‌های اول رخ می‌دهد (لاگ: ۰.۱ تا ۳.۵
                // ثانیه)، پس ۴۰ ثانیه هیچ تلاشِ *در حال پیشرفتی* را قطع نمی‌کند:
                // معیارِ موتور «بی‌پیشرفت بودن» است، نه سپری‌شدنِ زمان.
                //
                // این تضمین نمی‌کند تور وصل شود — اگر هر سه ترابر روی این شبکه
                // بسته باشند، هیچ ترتیبی نجاتش نمی‌دهد. کاری که می‌کند این است
                // که فرصتِ آزمودنشان را داخل زمانی می‌آورد که کاربر واقعاً صبر
                // می‌کند.
                if self.tor_bridges != TorBridges::Off {
                    env.insert(
                        "AETHER_TOR_STALL_SECS".into(),
                        TOR_BRIDGE_STALL_SECS.to_string(),
                    );
                }
            }
        }

        // ----- هسته‌ی 1.7.0 ---------------------------------------------
        if caps.route_sniff {
            if !self.route_sniff {
                env.insert("AETHER_ROUTE_SNIFF".into(), "0".into());
            }
            if !self.reprovision {
                env.insert("AETHER_REPROVISION".into(), "0".into());
            }
        }

        // ----- بودجه‌ی سنجش اندپوینت کش‌شده (fast_endpoint_only) ---------
        // معادل دقیق نسخه موبایل ۱.۴.۰: فقط اگر کاربر سوییچ را روشن کرده باشد
        // ارسال می‌شود تا هسته در حالت پیش‌فرض اندپوینت سالم را دوباره استفاده کند.
        if self.fast_endpoint_only {
            let is_chained = self.backend.is_chained();
            let rtt_budget = if is_chained { "1200" } else { "2000" };
            let hs_budget = if is_chained { "3500" } else { "5000" };
            env.insert(
                "AETHER_QUICK_RECONNECT_MAX_RTT_MS".into(),
                rtt_budget.into(),
            );
            env.insert(
                "AETHER_QUICK_RECONNECT_MAX_HANDSHAKE_MS".into(),
                hs_budget.into(),
            );
            env.insert("AETHER_SCAN_GOOD_RTT_MS".into(), rtt_budget.into());
        }

        env
    }

    /// معادل دقیق `Profile.kt::connectTimeoutMs()`
    pub fn connect_timeout_ms(&self) -> u64 {
        if self.has_manual_peer() {
            return 45_000;
        }
        match self.scan_mode {
            ScanMode::Turbo => 60_000,
            ScanMode::Balanced => 150_000,
            ScanMode::Stealth => 240_000,
            ScanMode::Thorough => 300_000,
            ScanMode::Ironclad => 360_000,
        }
    }
}

/// ۱.۲.۶ — سقفِ «بی‌پیشرفتی» هر دورِ پل، که به موتور فرستاده می‌شود
/// (`AETHER_TOR_STALL_SECS`). پیش‌فرضِ موتور ۷۵ ثانیه است و با آن، دومین
/// ترانسپورت پیش از ثانیهٔ ۱۵۰ نوبت نمی‌گیرد. مفصل در
/// [ConnectionProfile::to_env_with_caps].
pub const TOR_BRIDGE_STALL_SECS: u32 = 75;

/// بیشترین تعداد سطر پلی که به موتور می‌رود — همان عددِ نسخهٔ موبایل.
pub const MAX_BRIDGE_LINES: usize = 12;

/// یک سطر پلِ تور: نام ترانسپورتی شناخته‌شده، یک آدرس، اثر انگشت، و هر تعداد
/// پارامتر `key=value`.
///
/// عمداً روی **نخستین توکن** سخت‌گیر است. هر سطر پل به‌عنوان یک ورودی argv به
/// موتور می‌رود، پس هیچ‌چیز این‌جا نمی‌تواند آرگومان دومی تزریق کند — ولی سطری
/// که ترانسپورتی را نام می‌برد که برنامه هیچ باینری‌اش را همراه ندارد، هنگام
/// اتصال با پیامی دربارهٔ ترانسپورت شکست می‌خورد نه دربارهٔ سطر، و آن نوع
/// خطایی است که کسی نمی‌تواند کاری با آن بکند.
///
/// چرا با دست نوشته شده و نه با regex: کلِ برنامه هیچ وابستگی regex ندارد و
/// افزودنش برای یک الگو، یک crate تازه در مسیر اعتماد است.
fn is_bridge_line(line: &str) -> bool {
    const TRANSPORTS: [&str; 6] = [
        "obfs4",
        "meek_lite",
        "webtunnel",
        "snowflake",
        "scramblesuit",
        "obfs3",
    ];
    let mut parts = line.split_whitespace();
    let Some(transport) = parts.next() else {
        return false;
    };
    if !TRANSPORTS.contains(&transport) {
        return false;
    }
    // آدرس: بدون فاصله، ۳ تا ۱۲۰ نویسه.
    let Some(addr) = parts.next() else {
        return false;
    };
    if !(3..=120).contains(&addr.chars().count()) {
        return false;
    }
    // بقیهٔ توکن‌ها: اثر انگشت هگزِ ۴۰ نویسه‌ای و/یا پارامترها. مجموعهٔ نویسه
    // همان چیزی است که نسخهٔ موبایل می‌پذیرد.
    for token in parts {
        if token.chars().count() > 400
            || !token.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '_' | '.' | '=' | '/' | '+' | ':' | ',' | '-')
            })
        {
            return false;
        }
    }
    true
}

/// حذف فاصله‌های اضافی و ورودی‌های خالی از یک فهرست (route/dns).
/// Characters a core-2.4 list/name option may contain. Anything else
/// (whitespace, quotes, control chars, `=`, `;`, `&`, `|`, `$`) makes the
/// value be dropped rather than passed to the engine environment.
fn safe_opt(raw: &str, extra: &str, max: usize) -> Option<String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > max {
        return None;
    }
    if v.chars()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    {
        Some(v.to_string())
    } else {
        None
    }
}

impl ConnectionProfile {
    /// Core 2.4.0 environment (`AETHER_TLS_*`, `AETHER_API_*`, ...).
    pub fn tls24_env(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        let mut put = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                env.insert(k.to_string(), v);
            }
        };
        put("AETHER_TLS_VERIFY", self.tls_verify.then(|| "1".to_string()));
        put("AETHER_API_ADDRESS", safe_opt(&self.api_address, ".-:[]_", 255));
        put("AETHER_API_SNI", safe_opt(&self.api_sni, ".-_", 253));
        put("AETHER_API_HOST", safe_opt(&self.api_host, ".-_", 253));
        put("AETHER_MASQUE_SNI", safe_opt(&self.masque_sni, ".-_", 253));
        put("AETHER_TLS_CIPHERS", safe_opt(&self.tls_ciphers, "-_:!+", 1024));
        put("AETHER_TLS13_CIPHERS", safe_opt(&self.tls13_ciphers, "_:", 512));
        put("AETHER_TLS_GROUPS", safe_opt(&self.tls_groups, "-_:", 256));
        put("AETHER_TLS_KEY_SHARES", safe_opt(&self.tls_key_shares, "-_:", 256));
        put("AETHER_TLS_SIGALGS", safe_opt(&self.tls_sigalgs, "_:", 1024));
        put(
            "AETHER_TLS_CERT_COMPRESSION",
            safe_opt(&self.tls_cert_compression, ":", 64).filter(|v| {
                v.split(':').all(|p| matches!(p, "zlib" | "brotli" | "zstd"))
            }),
        );
        put(
            "AETHER_TLS_ALPS",
            match self.tls_alps.trim() {
                "new" => Some("new".to_string()),
                "old" => Some("old".to_string()),
                _ => None,
            },
        );
        put(
            "AETHER_TLS_TRUST_ANCHORS",
            safe_opt(&self.tls_trust_anchors, ".:", 512).filter(|v| {
                v.split(':').all(|id| {
                    !id.is_empty() && id.split('.').all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                })
            }),
        );
        put(
            "AETHER_TLS_SERVER_PADDING",
            self.tls_server_padding
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|n| *n <= 65_535)
                .map(|n| n.to_string()),
        );
        for (on, key) in [
            (self.disable_grease, "AETHER_DISABLE_GREASE"),
            (self.enable_grease_sigalgs, "AETHER_ENABLE_GREASE_SIGALGS"),
            (self.enable_ech_grease, "AETHER_ENABLE_ECH_GREASE"),
            (self.disable_ocsp_stapling, "AETHER_DISABLE_OCSP_STAPLING"),
            (self.disable_sct, "AETHER_DISABLE_SCT"),
            (self.disable_session_ticket, "AETHER_DISABLE_SESSION_TICKET"),
            (self.disable_extension_permutation, "AETHER_DISABLE_EXTENSION_PERMUTATION"),
        ] {
            if on {
                env.insert(key.to_string(), "1".to_string());
            }
        }
        env
    }
}

fn clean_list(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mim_uses_core_2_0_flag_and_is_gated_before_it() {
        let p = ConnectionProfile {
            protocol: Protocol::Mim,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        assert!(p
            .to_args_with_caps(CoreCaps::for_version(2, 0))
            .iter()
            .any(|a| a == "--mim"));
        assert!(!p
            .to_args_with_caps(CoreCaps::for_version(1, 9))
            .iter()
            .any(|a| a == "--mim"));
        assert!(CoreCaps::for_version(2, 0).mim);
        assert!(!CoreCaps::for_version(1, 9).mim);
    }

    /// این تست همان «قرارداد» بین اندروید و ویندوز است. اگر روزی خروجی فرق
    /// کند، CI باید قرمز شود.
    #[test]
    fn default_profile_matches_android_argv() {
        let p = ConnectionProfile::default();
        assert_eq!(
            p.to_args(),
            vec!["--balanced", "-4", "--quick-reconnect", "--noize", "off"]
        );
        // v11: پروفایل پیش‌فرض هیچ متغیر جدیدی هم اضافه نمی‌کند.
        assert_eq!(
            p.to_env().keys().cloned().collect::<Vec<String>>(),
            vec!["AETHER_MASQUE_HTTP2".to_string()]
        );
    }

    /// 1.2.3: the shipped Advanced-panel defaults. Pinned as a test because
    /// these are the values the panel shows on a fresh install and a silent
    /// drift here is invisible until someone reads a log.
    #[test]
    fn shipped_defaults_match_the_advanced_panel() {
        let p = ConnectionProfile::default();
        assert_eq!(p.backend, TransportBackend::Aether);
        assert_eq!(p.exit_region, "");
        assert_eq!(p.protocol, Protocol::Smart);
        // همان مقدارِ موبایل ۱.۳.۰ — نردبان خودش Turbo را می‌گذارد.
        assert_eq!(p.scan_mode, ScanMode::Balanced);
        assert_eq!(p.ip_version, IpVersion::V4);
        assert_eq!(p.noize, Noize::Off);
        assert_eq!(p.endpoint_mode, EndpointMode::Auto);
        // The carrier toggle stays off: HTTP/3 is the fast MASQUE data plane.
        assert!(!p.masque_http2);
        assert_eq!(p.settings_rev, SETTINGS_REV);
    }

    /// v1.2.0: گارد نشتی باید پیش‌فرض روشن باشد و روی آرگومان‌های موتور
    /// اثری نگذارد (یک قابلیت کاملاً سمتِ ویندوز است).
    #[test]
    fn safety_defaults_are_on_and_retry_limit_is_bounded() {
        let mut p = ConnectionProfile::default();
        assert!(p.kill_switch);
        assert!(p.ipv6_protection);
        assert_eq!(p.reconnect_attempts, 5);
        p.reconnect_attempts = 99;
        p.normalize();
        assert_eq!(p.reconnect_attempts, 20);
    }

    #[test]
    fn leak_guard_is_on_by_default_and_never_reaches_the_engine() {
        let p = ConnectionProfile::default();
        assert!(p.leak_guard);
        assert!(!p.to_args().iter().any(|a| a.contains("leak")));
    }

    #[test]
    fn manual_peer_skips_scan_mode() {
        let p = ConnectionProfile {
            endpoint_mode: EndpointMode::ManualPeer,
            manual_peer: "188.114.96.1:2408".into(),
            protocol: Protocol::Masque,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        // 1.2.3: `--noize` is ALWAYS sent, `off` included (see `to_args_with_caps`).
        // Leaving it out made the engine fall back to `firewall`, so it is pinned
        // here as well: a manual peer only skips the SCAN-mode flag, nothing else.
        assert_eq!(
            p.to_args(),
            vec![
                "--masque",
                "-4",
                "--quick-reconnect",
                "--noize",
                "off",
                "--peer",
                "188.114.96.1:2408"
            ]
        );
        assert_eq!(p.connect_timeout_ms(), 45_000);
    }

    #[test]
    fn noize_and_hardening_flags() {
        let p = ConnectionProfile {
            protocol: Protocol::Wireguard,
            gool_mode: GoolMode::Modern,
            noize: Noize::Gfw,
            fragment: true,
            ech: true,
            keepalive: 25,
            ..Default::default()
        };
        assert_eq!(
            p.to_args(),
            vec![
                "--wg",
                "--balanced",
                "-4",
                "--quick-reconnect",
                "--noize",
                "gfw",
                "--fragment",
                "--ech",
                "auto",
                "--keepalive",
                "25"
            ]
        );
    }

    // --- v10: قابلیت‌های هسته‌ی 1.5.0 -------------------------------------

    #[test]
    fn zero_trust_email_flags() {
        let p = ConnectionProfile {
            team: "acme".into(),
            access_mode: AccessMode::Email,
            access_email: "user@acme.com".into(),
            gateway: true,
            ..Default::default()
        };
        let args = p.to_args_with_caps(CoreCaps::all());
        assert!(args.windows(2).any(|w| w == ["--team", "acme"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["--access-email", "user@acme.com"]));
        assert!(args.contains(&"--gateway".to_string()));
    }

    #[test]
    fn zero_trust_service_token_flags() {
        let p = ConnectionProfile {
            team: "acme".into(),
            access_mode: AccessMode::ServiceToken,
            access_id: "id-123".into(),
            access_secret: "shh-secret".into(),
            ..Default::default()
        };
        let args = p.to_args_with_caps(CoreCaps::all());
        assert!(args.windows(2).any(|w| w == ["--access-id", "id-123"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["--access-secret", "shh-secret"]));
    }

    #[test]
    fn routing_and_dns_flags() {
        let p = ConnectionProfile {
            route_block: vec!["ads.example".into(), "  ".into()],
            route_direct: vec!["bank.ir".into(), "192.168.0.0/16".into()],
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            ..Default::default()
        };
        let args = p.to_args_with_caps(CoreCaps::all());
        assert!(args
            .windows(2)
            .any(|w| w == ["--route-block", "ads.example"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["--route-direct", "bank.ir,192.168.0.0/16"]));
        assert!(args.windows(2).any(|w| w == ["--dns", "1.1.1.1,8.8.8.8"]));
    }

    #[test]
    fn old_core_never_gets_15_flags() {
        // هسته‌ی 1.4: هیچ‌کدام از فلگ‌های 1.5.0 نباید فرستاده شوند.
        let p = ConnectionProfile {
            team: "acme".into(),
            access_mode: AccessMode::Email,
            access_email: "user@acme.com".into(),
            route_block: vec!["ads.example".into()],
            dns: vec!["1.1.1.1".into()],
            ..Default::default()
        };
        let caps = CoreCaps::for_version(1, 4);
        let args = p.to_args_with_caps(caps);
        assert!(!args.iter().any(|a| a.starts_with("--team")));
        assert!(!args.iter().any(|a| a.starts_with("--access")));
        assert!(!args.iter().any(|a| a.starts_with("--route")));
        assert!(!args.iter().any(|a| a == "--dns"));
        // ولی فلگ‌های پایه باید باشند.
        assert!(args.contains(&"--balanced".to_string()));
    }

    #[test]
    fn caps_gate_maps_versions() {
        assert!(!CoreCaps::for_version(1, 4).zero_trust);
        assert!(CoreCaps::for_version(1, 5).zero_trust);
        assert!(CoreCaps::for_version(1, 5).routing);
        assert!(CoreCaps::for_version(2, 0).custom_dns);
        // v11: قابلیت‌های هستهٔ 1.7.0 روی هستهٔ 1.6.0 خاموش‌اند.
        assert!(!CoreCaps::for_version(1, 6).upstream);
        assert!(!CoreCaps::for_version(1, 6).route_sniff);
        assert!(CoreCaps::for_version(1, 7).upstream);
        assert!(CoreCaps::for_version(1, 7).route_sniff);
        assert!(CoreCaps::for_version(2, 0).upstream);
    }

    // --- v11: قابلیت‌های هستهٔ 1.7.0 -------------------------------------

    #[test]
    fn upstream_parser_mirrors_the_core() {
        assert_eq!(
            parse_upstream("127.0.0.1:1080").map(|(k, _)| k),
            Some(UpstreamKind::Socks5)
        );
        assert_eq!(
            parse_upstream("socks5://alice:s3cret@127.0.0.1:1080").map(|(k, _)| k),
            Some(UpstreamKind::Socks5)
        );
        assert_eq!(
            parse_upstream("HTTP://proxy.example:8080/").map(|(k, _)| k),
            Some(UpstreamKind::Http)
        );
        assert_eq!(
            parse_upstream("socks5h://[::1]:1080").map(|(k, _)| k),
            Some(UpstreamKind::Socks5)
        );
        // بی‌پورت، طرح‌وارهٔ ناشناس، پورت صفر و پورت غیرعددی رد می‌شوند.
        assert!(parse_upstream("127.0.0.1").is_none());
        assert!(parse_upstream("ftp://127.0.0.1:21").is_none());
        assert!(parse_upstream("127.0.0.1:0").is_none());
        assert!(parse_upstream("127.0.0.1:https").is_none());
        assert!(parse_upstream("   ").is_none());
    }

    #[test]
    fn upstream_flag_only_reaches_a_17_core_and_only_when_valid() {
        let p = ConnectionProfile {
            upstream: " socks5://127.0.0.1:1080 ".into(),
            ..Default::default()
        };
        let args = p.to_args_with_caps(CoreCaps::all());
        assert!(args
            .windows(2)
            .any(|w| w == ["--upstream", "socks5://127.0.0.1:1080"]));
        // هستهٔ 1.6.0 این فلگ را نمی‌شناسد.
        assert!(!p
            .to_args_with_caps(CoreCaps::for_version(1, 6))
            .iter()
            .any(|a| a == "--upstream"));
        // مقدار بی‌معنا هرگز فرستاده نمی‌شود.
        let bad = ConnectionProfile {
            upstream: "not a proxy".into(),
            ..Default::default()
        };
        assert!(!bad.to_args().iter().any(|a| a == "--upstream"));
    }

    #[test]
    fn an_http_upstream_forces_masque_over_http2() {
        let p = ConnectionProfile {
            upstream: "http://proxy.example:8080".into(),
            ..Default::default()
        };
        assert!(p.upstream_is_tcp_only());
        assert_eq!(
            p.to_env().get("AETHER_MASQUE_HTTP2").map(String::as_str),
            Some("1")
        );
        // با پروکسی SOCKS5 انتخاب کاربر دست‌نخورده می‌ماند (UDP عبور می‌کند).
        let s = ConnectionProfile {
            upstream: "socks5://127.0.0.1:1080".into(),
            ..Default::default()
        };
        assert!(!s.upstream_is_tcp_only());
        assert_eq!(
            s.to_env().get("AETHER_MASQUE_HTTP2").map(String::as_str),
            Some("0")
        );
        // روی هستهٔ 1.6.0 اجباری در کار نیست چون --upstream هم فرستاده نمی‌شود.
        assert_eq!(
            p.to_env_with_caps(CoreCaps::for_version(1, 6))
                .get("AETHER_MASQUE_HTTP2")
                .map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn sniffing_and_reprovision_are_on_by_default_and_opt_out_only() {
        let p = ConnectionProfile::default();
        assert!(p.route_sniff);
        assert!(p.reprovision);
        let env = p.to_env();
        assert!(!env.contains_key("AETHER_ROUTE_SNIFF"));
        assert!(!env.contains_key("AETHER_REPROVISION"));

        let off = ConnectionProfile {
            route_sniff: false,
            reprovision: false,
            ..Default::default()
        };
        let env = off.to_env();
        assert_eq!(env.get("AETHER_ROUTE_SNIFF").map(String::as_str), Some("0"));
        assert_eq!(env.get("AETHER_REPROVISION").map(String::as_str), Some("0"));
        // روی هستهٔ 1.6.0 هیچ‌کدام فرستاده نمی‌شوند.
        let old = off.to_env_with_caps(CoreCaps::for_version(1, 6));
        assert!(!old.contains_key("AETHER_ROUTE_SNIFF"));
        assert!(!old.contains_key("AETHER_REPROVISION"));
    }

    // --- v12: بک‌اند ترابرد (۱.۲.۳) ----------------------------------

    /// پیش‌فرض باید موتور تنها بماند، وگرنه یک ارتقا رفتار کاربر را عوض می‌کند.
    #[test]
    fn backend_defaults_to_aether_and_is_not_chained() {
        let p = ConnectionProfile::default();
        assert_eq!(p.backend, TransportBackend::Aether);
        assert!(!p.is_chained());
        assert!(TransportBackend::AetherPsiphon.is_chained());
    }

    /// کدهای serde همان چیزی‌اند که `src/views/advanced.js` می‌فرستد.
    #[test]
    fn backend_wire_codes_match_the_ui() {
        assert_eq!(
            serde_json::to_string(&TransportBackend::Aether).unwrap(),
            "\"AETHER\""
        );
        assert_eq!(
            serde_json::to_string(&TransportBackend::AetherPsiphon).unwrap(),
            "\"AETHER_PSIPHON\""
        );
        let p: ConnectionProfile = serde_json::from_str(r#"{"backend":"AETHER_PSIPHON"}"#).unwrap();
        assert!(p.is_chained());
    }

    /// پروفایل ذخیره‌شدهٔ ۱.۲.۲ (بدون کلید `backend`) باید دست‌نخورده بار شود.
    #[test]
    fn a_pre_123_profile_loads_as_aether() {
        let p: ConnectionProfile =
            serde_json::from_str(r#"{"protocol":"MASQUE","scanMode":"TURBO"}"#).unwrap();
        assert_eq!(p.backend, TransportBackend::Aether);
        assert!(!p.is_chained());
    }

    /// استیج ۱ یک نشست زنجیره‌ای هرگز نباید خودش زنجیره‌ای باشد (وگرنه
    /// بازگشت بی‌پایان) و نباید روی شبکهٔ محلی چیزی باز کند.
    #[test]
    fn chained_stage_falls_back_to_the_engine_alone() {
        let p = ConnectionProfile {
            backend: TransportBackend::AetherPsiphon,
            lan_share: true,
            exit_region: "DE".into(),
            ..Default::default()
        };
        let stage = p.chained_stage();
        assert_eq!(stage.backend, TransportBackend::Aether);
        assert!(!stage.is_chained());
        assert!(!stage.lan_share);
    }

    /// Both chains ask core 2.1.0 to own the Psiphon process and its listener.
    #[test]
    fn chained_backends_enable_core_managed_psiphon() {
        for backend in [
            TransportBackend::AetherPsiphon,
            TransportBackend::TorPsiphon,
        ] {
            let p = ConnectionProfile {
                backend,
                exit_region: "NL".into(),
                ..Default::default()
            };
            let args = p.to_args();
            assert!(args.contains(&"--psiphon".to_string()));
            assert!(args
                .windows(2)
                .any(|v| v == ["--psiphon-bind", "127.0.0.1:1825"]));
            assert!(args.windows(2).any(|v| v == ["--psiphon-region", "NL"]));
            assert_eq!(
                backend == TransportBackend::TorPsiphon,
                args.contains(&"--tor-only".to_string())
            );
        }
        let plain = ConnectionProfile::default();
        assert!(!plain.to_args().contains(&"--psiphon".to_string()));
    }

    /// The chained tile has to read exactly like the mobile edition's, arrow and
    /// all, and the plain backend must keep deferring to the concrete protocol.
    #[test]
    fn the_chained_backend_labels_the_whole_pipeline() {
        assert_eq!(TransportBackend::Aether.protocol_label(), None);
        assert_eq!(
            TransportBackend::AetherPsiphon.protocol_label(),
            Some("Aether \u{2192} Psiphon")
        );
        // Same glyph the mobile edition uses (U+2192), never "->" and never "+".
        assert!(TransportBackend::AetherPsiphon
            .protocol_label()
            .unwrap()
            .contains('\u{2192}'));
    }

    /// برچسب خط لوله برای لاگ باید دو حالت را از هم جدا کند.
    #[test]
    fn pipeline_labels_are_distinct() {
        assert_ne!(
            TransportBackend::Aether.pipeline_label(),
            TransportBackend::AetherPsiphon.pipeline_label()
        );
    }

    #[test]
    fn secrets_are_never_serialised_to_disk() {
        // سخت‌سازی امنیتی: access_secret / access_token با serde(skip) هرگز
        // در profile.json ذخیره نمی‌شوند.
        let p = ConnectionProfile {
            access_secret: "top-secret".into(),
            access_token: "jwt-token".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("top-secret"));
        assert!(!json.contains("jwt-token"));
        assert!(!json.contains("accessSecret"));
        assert!(!json.contains("accessToken"));
    }

    // ====================================================================
    //  ۱.۲.۵ — تور (هستهٔ ۲.۰.۰)
    // ====================================================================

    /// حالت زنجیره‌ای: تور از داخل تونل dial می‌شود و روی لیسنر دوم می‌نشیند.
    #[test]
    fn chain_mode_binds_tor_to_its_own_listener() {
        let p = ConnectionProfile {
            backend: TransportBackend::AetherTor,
            ..Default::default()
        };
        let args = p.to_args();
        assert_eq!(args[0], "--tor");
        assert_eq!(args[1], "--tor-bind");
        assert_eq!(
            args[2],
            format!("127.0.0.1:{}", crate::engine::TOR_SOCKS_PORT)
        );
        // تونل هنوز ساخته می‌شود، پس اسکن و پروتکل هم باید بیایند.
        assert!(args.contains(&"--balanced".to_string()));
        // مسیر داده باید به لیسنر تور برود، نه به خروجی WARP.
        assert_eq!(
            TransportBackend::AetherTor.exposed_socks_port(),
            crate::engine::TOR_SOCKS_PORT
        );
    }

    /// `--tor-only` هیچ تونلی ندارد، پس هیچ فلگ WARPی هم نباید بفرستد.
    #[test]
    fn tor_only_sends_no_tunnel_flags() {
        let p = ConnectionProfile {
            backend: TransportBackend::Tor,
            dns: vec!["1.1.1.1".into()],
            ..Default::default()
        };
        let args = p.to_args();
        assert_eq!(args[0], "--tor-only");
        // resolverها هنوز اثر دارند؛ SOCKS خود موتور آن‌ها را تحویل می‌دهد.
        assert!(args.windows(2).any(|w| w == ["--dns", "1.1.1.1"]));
        for flag in [
            "--masque",
            "--wg",
            "--gool",
            "--turbo",
            "-4",
            "--noize",
            "--quick-reconnect",
            "--tor-bind",
        ] {
            assert!(
                !args.contains(&flag.to_string()),
                "{flag} به یک نشستِ بدون تونل رفت: {args:?}"
            );
        }
        assert!(!TransportBackend::Tor.uses_warp());
        // تنها پروکسیِ موتور خودِ تور است، پس روی پورت همیشگی می‌نشیند.
        assert_eq!(
            TransportBackend::Tor.tor_socks_port(),
            Some(crate::engine::LOCAL_SOCKS_PORT)
        );
    }

    /// زنجیرهٔ برعکس: انتخاب WireGuardِ کاربر بازنویسی می‌شود، نه فرستاده.
    ///
    /// هستهٔ ۲.۰.۰ ترکیب `--tor-reverse --wg` را رد می‌کند و بی‌درنگ خارج
    /// می‌شود؛ از دید برنامه این از یک شبکهٔ بسته قابل تفکیک نبود.
    #[test]
    fn reverse_chain_rewrites_wireguard_to_masque_over_h2() {
        let p = ConnectionProfile {
            backend: TransportBackend::TorAether,
            protocol: Protocol::Wireguard,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        assert_eq!(p.effective_protocol(), Protocol::Masque);
        let args = p.to_args();
        assert_eq!(args[0], "--tor-reverse");
        assert!(args.contains(&"--masque".to_string()));
        assert!(!args.contains(&"--wg".to_string()));
        assert!(!args.contains(&"--gool".to_string()));
        // MASQUE باید روی HTTP/2 برود، حتی وقتی کاربر آن کلید را نزده.
        assert_eq!(p.to_env().get("AETHER_MASQUE_HTTP2").unwrap(), "1");
    }

    /// پل فقط در دو حالتی معنا دارد که تور روبروی شبکهٔ محلی است.
    #[test]
    fn bridges_are_only_sent_when_tor_faces_the_network() {
        let base = ConnectionProfile {
            tor_bridges: TorBridges::Always,
            tor_bridge_lines: "obfs4 192.0.2.55:38114 \
                0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0"
                .into(),
            tor_country: "IR".into(),
            tor_direct_secs: 30,
            ..Default::default()
        };

        // حالت زنجیره‌ای: تور از داخل تونل می‌رود، پس هیچ پلی و هیچ تنظیم
        // bridgedb‌ای فرستاده نمی‌شود.
        let chain = ConnectionProfile {
            backend: TransportBackend::AetherTor,
            ..base.clone()
        };
        let args = chain.to_args();
        assert!(!args.contains(&"--tor-bridges".to_string()));
        assert!(!args.contains(&"--tor-bridge".to_string()));
        let env = chain.to_env();
        assert!(!env.contains_key("AETHER_TOR_COUNTRY"));
        assert!(!env.contains_key("AETHER_TOR_DIRECT_SECS"));

        // تورِ تنها: هر دو می‌روند.
        let only = ConnectionProfile {
            backend: TransportBackend::Tor,
            ..base
        };
        let args = only.to_args();
        assert!(args.contains(&"--tor-bridges".to_string()));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--tor-bridge" && w[1].starts_with("obfs4 192.0.2.55:38114")));
        let env = only.to_env();
        assert_eq!(env.get("AETHER_TOR_COUNTRY").unwrap(), "ir");
        assert_eq!(env.get("AETHER_TOR_DIRECT_SECS").unwrap(), "30");
    }

    /// سطر پلِ بدشکل انداخته می‌شود، نه اینکه به argv برود.
    #[test]
    fn malformed_bridge_lines_are_dropped() {
        let p = ConnectionProfile {
            backend: TransportBackend::Tor,
            tor_bridge_lines: [
                "notatransport 192.0.2.1:443",    // ترانسپورت ناشناخته
                "obfs4",                          // بدون آدرس
                "obfs4 1.2.3.4:1 cert=$(whoami)", // نویسهٔ غیرمجاز
                "obfs4 192.0.2.9:9001 cert=ok",   // درست
                "obfs4 192.0.2.9:9001 cert=ok",   // تکراری
            ]
            .join("\n"),
            ..Default::default()
        };
        assert_eq!(p.sanitized_bridges(), vec!["obfs4 192.0.2.9:9001 cert=ok"]);
        assert!(p.has_custom_bridges());
    }

    /// هدفِ دسترسی‌پذیری باید سخت‌گیرانه بررسی شود.
    ///
    /// موتور با `rsplit_once(':')` می‌خواند و روی پورت بد به ۴۴۳ برمی‌گردد، پس
    /// یک غلط تایپی به هدفی دیگر تبدیل می‌شد نه به خطا.
    #[test]
    fn tor_check_target_is_validated_strictly() {
        let mk = |v: &str| ConnectionProfile {
            tor_check: v.into(),
            ..Default::default()
        };
        assert_eq!(
            mk("example.com").sanitized_tor_check().unwrap(),
            "example.com"
        );
        assert_eq!(
            mk(" example.com:8443 ").sanitized_tor_check().unwrap(),
            "example.com:8443"
        );
        assert_eq!(mk("").sanitized_tor_check(), None);
        assert_eq!(mk("example.com:70000").sanitized_tor_check(), None);
        assert_eq!(mk("example.com:0").sanitized_tor_check(), None);
        assert_eq!(mk("example.com:https").sanitized_tor_check(), None);
        assert_eq!(mk("exam ple.com").sanitized_tor_check(), None);
        assert_eq!(mk("a;b.com").sanitized_tor_check(), None);
        // آدرس IPv6 کولون‌های خودش را دارد و پورتی در کار نیست.
        assert_eq!(
            mk("2606:4700:4700::1111").sanitized_tor_check().unwrap(),
            "2606:4700:4700::1111"
        );
    }

    /// کد کشور: دقیقاً دو حرف، وگرنه چیزی فرستاده نمی‌شود.
    #[test]
    fn tor_country_needs_exactly_two_letters() {
        let mk = |v: &str| ConnectionProfile {
            tor_country: v.into(),
            ..Default::default()
        };
        assert_eq!(mk("IR").sanitized_tor_country().unwrap(), "ir");
        assert_eq!(mk(" de ").sanitized_tor_country().unwrap(), "de");
        assert_eq!(mk("irn").sanitized_tor_country(), None);
        assert_eq!(mk("i").sanitized_tor_country(), None);
        assert_eq!(mk("i1").sanitized_tor_country(), None);
        assert_eq!(mk("").sanitized_tor_country(), None);
    }

    /// نردبانِ پل باید داخلِ زمانی که کاربر صبر می‌کند به ترانسپورتِ دوم برسد.
    ///
    /// سه حالت سنجیده می‌شود، چون هر سه در لاگ معنا داشتند: تورِ روبروی شبکه با
    /// پلِ مجاز (باید فرستاده شود)، پلِ خاموش (چیزی برای زمان‌بندی نیست) و حالتِ
    /// زنجیره‌ای (تور از داخل تونل dial می‌شود، پس پل بی‌اثر است).
    #[test]
    fn the_bridge_ladder_gets_a_stall_budget_only_where_bridges_can_act() {
        let caps = CoreCaps::for_version(2, 0);

        let facing = ConnectionProfile {
            backend: TransportBackend::Tor,
            tor_bridges: TorBridges::Auto,
            ..Default::default()
        };
        assert_eq!(
            facing
                .to_env_with_caps(caps)
                .get("AETHER_TOR_STALL_SECS")
                .map(String::as_str),
            Some("75"),
        );

        let no_bridges = ConnectionProfile {
            tor_bridges: TorBridges::Off,
            ..facing.clone()
        };
        assert!(!no_bridges
            .to_env_with_caps(caps)
            .contains_key("AETHER_TOR_STALL_SECS"));

        let chained = ConnectionProfile {
            backend: TransportBackend::AetherTor,
            ..facing.clone()
        };
        assert!(!chained
            .to_env_with_caps(caps)
            .contains_key("AETHER_TOR_STALL_SECS"));

        // و روی هستهٔ پیش از ۲.۰.۰ هیچ متغیرِ توری فرستاده نمی‌شود.
        assert!(!facing
            .to_env_with_caps(CoreCaps::for_version(1, 9))
            .contains_key("AETHER_TOR_STALL_SECS"));
    }

    #[test]
    fn tor_direct_secs_is_clamped_but_zero_stays_zero() {
        let mut p = ConnectionProfile {
            tor_direct_secs: 0,
            ..Default::default()
        };
        p.normalize();
        assert_eq!(p.tor_direct_secs, 0, "صفر یعنی پیش‌فرض موتور");

        p.tor_direct_secs = 1;
        p.normalize();
        assert_eq!(p.tor_direct_secs, 5);

        p.tor_direct_secs = 9_999;
        p.normalize();
        assert_eq!(p.tor_direct_secs, 600);
    }

    /// روی هسته‌ای که تور را نمی‌شناسد، نشست ساده می‌شود — نه اینکه بمیرد.
    #[test]
    fn tor_flags_are_withheld_from_an_older_core() {
        let p = ConnectionProfile {
            backend: TransportBackend::Tor,
            tor_check: "example.com".into(),
            ..Default::default()
        };
        let caps = CoreCaps::for_version(1, 9);
        assert!(!caps.tor);
        let args = p.to_args_with_caps(caps);
        assert!(!args.iter().any(|a| a.starts_with("--tor")));
        // و به جای یک argv نصفه‌کاره، یک نشست کاملِ اِتِر ساخته می‌شود.
        assert!(args.contains(&"--balanced".to_string()));
        assert!(!p.to_env_with_caps(caps).contains_key("AETHER_TOR_CHECK"));

        assert!(CoreCaps::for_version(2, 0).tor);
        assert!(CoreCaps::for_version(2, 1).tor);
    }

    /// در `Tor → Psiphon` استیج ۱ خودِ تور است، نه اِتِر.
    #[test]
    fn tor_psiphon_stage_one_is_tor() {
        let p = ConnectionProfile {
            backend: TransportBackend::TorPsiphon,
            ..Default::default()
        };
        assert!(p.is_chained());
        let stage = p.chained_stage();
        assert_eq!(stage.backend, TransportBackend::Tor);
        assert!(!stage.lan_share);
        assert_eq!(stage.to_args()[0], "--tor-only");
        assert!(!stage.to_args().contains(&"--psiphon".to_string()));
        // و خروجیِ زنجیره همان لیسنر Psiphon است.
        assert_eq!(
            TransportBackend::TorPsiphon.exposed_socks_port(),
            crate::engine::CHAIN_SOCKS_PORT
        );
    }

    /// یک پروفایل پیش‌فرض هیچ متغیر یا فلگ توری نمی‌فرستد.
    #[test]
    fn a_default_profile_is_unchanged_by_the_tor_work() {
        let p = ConnectionProfile::default();
        assert!(!p.backend.uses_tor());
        assert!(p.to_args().iter().all(|a| !a.starts_with("--tor")));
        assert!(p.to_env().keys().all(|k| !k.starts_with("AETHER_TOR")));
        assert_eq!(p.effective_protocol(), p.protocol);
    }

    #[test]
    fn tls24_default_profile_sends_nothing() {
        let p = ConnectionProfile::default();
        assert!(p.tls24_env().is_empty());
        let a = p.to_env_with_caps(CoreCaps::all());
        assert!(a.keys().all(|k| !k.starts_with("AETHER_TLS") && !k.starts_with("AETHER_API")));
    }

    #[test]
    fn tls24_gated_by_core_version() {
        assert!(!CoreCaps::for_version(2, 3).tls24);
        assert!(CoreCaps::for_version(2, 4).tls24);
        let mut p = ConnectionProfile::default();
        p.api_sni = "example.com".into();
        p.disable_sct = true;
        assert!(!p.to_env_with_caps(CoreCaps::for_version(2, 3)).contains_key("AETHER_API_SNI"));
        let e = p.to_env_with_caps(CoreCaps::for_version(2, 4));
        assert_eq!(e.get("AETHER_API_SNI").map(String::as_str), Some("example.com"));
        assert_eq!(e.get("AETHER_DISABLE_SCT").map(String::as_str), Some("1"));
    }

    #[test]
    fn tls24_values_are_sanitised() {
        let mut p = ConnectionProfile::default();
        p.api_host = "evil host; rm".into();
        p.tls_ciphers = "A B".into();
        p.tls_alps = "bogus".into();
        p.tls_cert_compression = "brotli:gzip".into();
        p.tls_trust_anchors = "11129.9.1:abc".into();
        p.tls_server_padding = "70000".into();
        assert!(p.tls24_env().is_empty());
        p.tls_alps = "new".into();
        p.tls_cert_compression = "zlib:brotli".into();
        p.tls_trust_anchors = "11129.9.1:11129.9.4".into();
        p.tls_server_padding = "6000".into();
        p.tls_verify = true;
        p.tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256".into();
        let e = p.tls24_env();
        assert_eq!(e.len(), 6);
        assert_eq!(e["AETHER_TLS_SERVER_PADDING"], "6000");
        assert_eq!(e["AETHER_TLS_VERIFY"], "1");
    }

    #[test]
    fn tls24_profile_json_roundtrip_and_old_profile_loads() {
        let old = r#"{"upstream":"","routeSniff":true}"#;
        let p: ConnectionProfile = serde_json::from_str(old).unwrap();
        assert!(!p.tls_verify && p.api_sni.is_empty());
        let mut q = ConnectionProfile::default();
        q.masque_sni = "a.example".into();
        q.disable_grease = true;
        let j = serde_json::to_string(&q).unwrap();
        assert!(j.contains("\"masqueSni\"") && j.contains("\"disableGrease\":true"));
        assert_eq!(serde_json::from_str::<ConnectionProfile>(&j).unwrap(), q);
    }
}

fn looks_like_base64(text: &str) -> bool {
    text.len() >= 4
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}
