//! ۱.۳.۰ — **کانفیگ‌های سفارشی** (Custom configs)، پورت از `custom/*.kt` نسخهٔ
//! اندروید ۱.۵.۰.
//!
//! یک کانفیگ سفارشی (لینکِ V2Ray/Xray، کانفیگ JSONِ Xray، یا فایلِ `.npvt`
//! ناپسترنت) با هستهٔ Xray-core همراهِ برنامه اجرا می‌شود — یا تنها، یا در یک
//! زنجیره با موتورهای خودِ اِتِر (Aether/Psiphon/Tor).
//!
//! # «خاموش» یعنی هیچ تغییری
//!
//! هیچ چیز در این ماژول وارد یک نشست نمی‌شود مگر کاربر در «تنظیمات ← کانفیگ‌های
//! سفارشی» آن را روشن کرده و یک کانفیگ را انتخاب کرده باشد. با کلیدِ خاموش
//! (پیش‌فرض) شش حالتِ قبلی دقیقاً مثل قبل اجرا می‌شوند — `state.rs` فقط وقتی
//! [`store::selection`] چیزی برگرداند به این ماژول دست می‌زند.
//!
//! # QR در ویندوز وجود ندارد
//!
//! نسخهٔ اندروید QR را با دوربین و از تصویر می‌خواند. نسخهٔ ویندوز عمداً هیچ
//! مسیری برای QR ندارد (نه دوربین، نه تصویر، نه کتابخانهٔ zxing): ورود فقط با
//! چسباندنِ متن/لینک، دانلودِ اشتراکِ `https://`، و انتخاب یا کشیدنِ فایل است.
//!
//! ساختار:
//!  * [`parser`]  — پورتِ ۱:۱ از `ConfigParser.kt` (+ `NpvtLock`)
//!  * [`npvt`]    — پورتِ بایت‌به‌بایتِ `NpvtCodec.kt` (AES-CTR جعبه‌سفید)
//!  * [`store`]   — انبارِ مهرشده با DPAPI (`custom_configs.bin`)
//!  * [`xray`]    — پورتِ `XrayConfigBuilder.kt`
//!  * [`process`] — اجرای `xray.exe` (پورتِ `XrayProcess.kt`)
//!  * [`import`]  — دانلودِ اشتراک و خواندنِ فایل (پورتِ `ConfigImporter.kt`، بی‌QR)

pub mod cleanip;
pub mod import;
pub mod npvt;
pub mod npvo;
pub mod present;
pub mod npvs;
pub mod selection;
pub mod ai_policy;
pub mod parser;
pub mod process;
pub mod realdelay;
pub mod speedtest;
pub mod store;
pub mod xray;

use serde::{Deserialize, Serialize};

/// سقفِ طولِ نامِ یک کانفیگ — همان `MAX_NAME` موبایل.
pub const MAX_NAME: usize = 80;
/// سقفِ طولِ پیامِ نویسندهٔ یک npvt — همان `MAX_NOTE` موبایل.
pub const MAX_NOTE: usize = 600;

/// کانفیگ از کجا آمد. فقط در فهرست دیده می‌شود و رفتار را عوض نمی‌کند.
///
/// `Qr` شامل ورود محلی QR از تصویر است؛ به مجوز دوربین نیاز ندارد.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfigSource {
    Link,
    File,
    Qr,
}

impl ConfigSource {
    pub fn name(self) -> &'static str {
        match self {
            ConfigSource::Link => "LINK",
            ConfigSource::File => "FILE",
            ConfigSource::Qr => "QR",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "LINK" => Some(Self::Link),
            "FILE" => Some(Self::File),
            "QR" => Some(Self::Qr),
            _ => None,
        }
    }
}

/// متنِ ذخیره‌شده چیست، تا ویرایش همان‌طور دوباره پارس شود.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfigFormat {
    Uri,
    XrayJson,
    Npvt,
}

impl ConfigFormat {
    pub fn name(self) -> &'static str {
        match self {
            ConfigFormat::Uri => "URI",
            ConfigFormat::XrayJson => "XRAY_JSON",
            ConfigFormat::Npvt => "NPVT",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "URI" => Some(Self::Uri),
            "XRAY_JSON" => Some(Self::XrayJson),
            "NPVT" => Some(Self::Npvt),
            _ => None,
        }
    }
}

/// پروتکلِ outboundِ کانفیگ. [`ConfigProtocol::short`] همان چیزی است که برچسبِ زنجیره نشان می‌دهد.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfigProtocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Socks,
    Http,
    Wireguard,
    Hysteria,
    Other,
}

impl ConfigProtocol {
    pub const ALL: [ConfigProtocol; 9] = [
        Self::Vless,
        Self::Vmess,
        Self::Trojan,
        Self::Shadowsocks,
        Self::Socks,
        Self::Http,
        Self::Wireguard,
        Self::Hysteria,
        Self::Other,
    ];

    pub fn short(self) -> &'static str {
        match self {
            Self::Vless => "VLESS",
            Self::Vmess => "VMess",
            Self::Trojan => "Trojan",
            Self::Shadowsocks => "SS",
            Self::Socks => "SOCKS",
            Self::Http => "HTTP",
            Self::Wireguard => "WireGuard",
            Self::Hysteria => "Hysteria",
            Self::Other => "Xray",
        }
    }

    /// نام ذخیره‌شده (همان `name` در Kotlin).
    pub fn name(self) -> &'static str {
        match self {
            Self::Vless => "VLESS",
            Self::Vmess => "VMESS",
            Self::Trojan => "TROJAN",
            Self::Shadowsocks => "SHADOWSOCKS",
            Self::Socks => "SOCKS",
            Self::Http => "HTTP",
            Self::Wireguard => "WIREGUARD",
            Self::Hysteria => "HYSTERIA",
            Self::Other => "OTHER",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }

    /// مقدارِ `protocol` یک outboundِ Xray را به خانواده‌اش نگاشت می‌کند.
    pub fn from_xray(protocol: Option<&str>) -> Self {
        match protocol.map(|p| p.to_ascii_lowercase()).as_deref() {
            Some("vless") => Self::Vless,
            Some("vmess") => Self::Vmess,
            Some("trojan") => Self::Trojan,
            Some("shadowsocks") | Some("ss") => Self::Shadowsocks,
            Some("socks") => Self::Socks,
            Some("http") => Self::Http,
            Some("wireguard") => Self::Wireguard,
            Some("hysteria") | Some("hysteria2") => Self::Hysteria,
            _ => Self::Other,
        }
    }
}

/// یک کانفیگِ ذخیره‌شده — همان `CustomConfig` موبایل.
///
/// `outbound` همان outboundِ آمادهٔ اجرای Xray است (JSON، بی‌tag)؛ یک بار هنگامِ
/// ورود ساخته می‌شود، پس نشست هرگز متنِ کاربر را دوباره پارس نمی‌کند و کانفیگی
/// که پارس نشود اصلاً ذخیره نمی‌شود.
///
/// `raw` متنِ قابلِ ویرایش است (لینک یا JSON). برای یک npvtِ **قفل‌شده خالی**
/// است: نویسنده خواسته جزئیاتِ سرور پنهان بماند. کانفیگِ قفل‌شده را فقط می‌توان
/// انتخاب، در زنجیره استفاده، تغییرِ نام و حذف کرد — نشانی و کلیدهایش هرگز
/// نشان داده، ویرایش، کپی یا در لاگ نوشته نمی‌شوند.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomConfig {
    pub id: String,
    pub name: String,
    pub protocol: ConfigProtocol,
    pub format: ConfigFormat,
    pub source: ConfigSource,
    pub outbound: String,
    pub raw: String,
    /// `host:port` برای فهرست. وقتی قفل است خالی است.
    pub server: String,
    pub locked: bool,
    pub note: String,
    /// میلی‌ثانیهٔ epoch که پس از آن کانفیگ منقضی است؛ ۰ = هرگز.
    pub expires_at: i64,
    /// قفلِ npvt: نویسنده فقط اینترنتِ موبایل را اجازه داده. ویندوز چنین
    /// کانفیگی را **هنگام ورود رد می‌کند**؛ فیلد فقط برای انبارِ قدیمی است.
    pub mobile_only: bool,
    pub added_at: i64,
}

impl CustomConfig {
    pub const NPVT_LABEL: &'static str = "Npvt";

    /// نامِ هاپ در برچسبِ زنجیره: `VLESS`، `Trojan`، … یا `Npvt`.
    pub fn chain_label(&self) -> &'static str {
        if self.format == ConfigFormat::Npvt {
            Self::NPVT_LABEL
        } else {
            self.protocol.short()
        }
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at >= 1 && self.expires_at < now
    }
}

/// کانفیگ کجای زنجیره می‌نشیند.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainPlacement {
    /// کانفیگ تنها: `شما ← کانفیگ ← اینترنت`.
    Solo,
    /// کانفیگ هاپِ **اول** است و موتور از دلِ آن dial می‌کند: `کانفیگ ← موتور`.
    First,
    /// کانفیگ هاپِ **آخر** است و از دلِ موتور dial می‌شود: `موتور ← کانفیگ`.
    Last,
}

/// بخشِ موتوریِ یک زنجیره. همه به‌جز [`ChainBase::Psiphon`] یکی از شش حالتِ
/// موجودند و دقیقاً مثل امروز اجرا می‌شوند. `Psiphon` حالتِ `--psiphon-only`
/// خودِ موتور است.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainBase {
    Aether,
    Psiphon,
    Tor,
    AetherPsiphon,
    AetherTor,
    TorPsiphon,
    TorAether,
}

impl ChainBase {
    /// برچسبِ خط لوله (همان `pipelineLabel` موبایل).
    pub fn pipeline_label(self) -> &'static str {
        match self {
            Self::Aether => "Aether",
            Self::Psiphon => "Psiphon",
            Self::Tor => "Tor",
            Self::AetherPsiphon => "Aether \u{2192} Psiphon",
            Self::AetherTor => "Aether \u{2192} Tor",
            Self::TorPsiphon => "Tor \u{2192} Psiphon",
            Self::TorAether => "Tor \u{2192} Aether",
        }
    }

    /// آیا این خط لوله تونلِ WARP دارد (تا ترابری در پرانتز بیاید)؟
    pub fn uses_warp(self) -> bool {
        matches!(
            self,
            Self::Aether | Self::AetherPsiphon | Self::AetherTor | Self::TorAether
        )
    }

    /// متن، با ترابریِ موتور داخلِ پرانتز همان‌جا که جایش است (`Aether(WireGuard)`).
    pub fn label(self, transport: Option<&str>) -> String {
        let pipeline = self.pipeline_label();
        let name = transport
            .map(|t| t.split('\u{2192}').next().unwrap_or(t))
            .map(|t| t.split("->").next().unwrap_or(t))
            .map(str::trim)
            .filter(|t| !t.is_empty());
        match name {
            Some(n) if self.uses_warp() => pipeline.replacen("Aether", &format!("Aether({n})"), 1),
            _ => pipeline.to_string(),
        }
    }

    /// آیا خروجیِ این خط لوله (پورتی که هاپِ آخر به آن dial می‌کند) خودِ tor.exe است؟
    pub fn exit_is_tor(self) -> bool {
        matches!(self, Self::Tor | Self::AetherTor)
    }

    /// آیا تور در این خط لوله هست؟
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn uses_tor(self) -> bool {
        matches!(
            self,
            Self::Tor | Self::AetherTor | Self::TorPsiphon | Self::TorAether
        )
    }
}

/// هر زنجیره‌ای که برنامه می‌سازد، به همان ترتیبی که انتخابگر نشان می‌دهد.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainMode {
    Solo,
    ConfigAether,
    AetherConfig,
    ConfigPsiphon,
    PsiphonConfig,
    ConfigTor,
    TorConfig,
    ConfigAetherPsiphon,
    ConfigAetherTor,
    ConfigTorPsiphon,
    ConfigTorAether,
    AetherPsiphonConfig,
    AetherTorConfig,
    TorPsiphonConfig,
    TorAetherConfig,
}

impl ChainMode {
    pub const ARROW: &'static str = " \u{2192} ";
    pub const TIGHT_ARROW: &'static str = "\u{2192}";

    pub const ALL: [ChainMode; 15] = [
        Self::Solo,
        Self::ConfigAether,
        Self::AetherConfig,
        Self::ConfigPsiphon,
        Self::PsiphonConfig,
        Self::ConfigTor,
        Self::TorConfig,
        Self::ConfigAetherPsiphon,
        Self::ConfigAetherTor,
        Self::ConfigTorPsiphon,
        Self::ConfigTorAether,
        Self::AetherPsiphonConfig,
        Self::AetherTorConfig,
        Self::TorPsiphonConfig,
        Self::TorAetherConfig,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Solo => "SOLO",
            Self::ConfigAether => "CONFIG_AETHER",
            Self::AetherConfig => "AETHER_CONFIG",
            Self::ConfigPsiphon => "CONFIG_PSIPHON",
            Self::PsiphonConfig => "PSIPHON_CONFIG",
            Self::ConfigTor => "CONFIG_TOR",
            Self::TorConfig => "TOR_CONFIG",
            Self::ConfigAetherPsiphon => "CONFIG_AETHER_PSIPHON",
            Self::ConfigAetherTor => "CONFIG_AETHER_TOR",
            Self::ConfigTorPsiphon => "CONFIG_TOR_PSIPHON",
            Self::ConfigTorAether => "CONFIG_TOR_AETHER",
            Self::AetherPsiphonConfig => "AETHER_PSIPHON_CONFIG",
            Self::AetherTorConfig => "AETHER_TOR_CONFIG",
            Self::TorPsiphonConfig => "TOR_PSIPHON_CONFIG",
            Self::TorAetherConfig => "TOR_AETHER_CONFIG",
        }
    }

    /// نامِ ذخیره‌شده؛ هر چیزِ ناشناخته `SOLO` می‌شود (همان `fromStoredName`).
    pub fn from_stored_name(raw: Option<&str>) -> Self {
        let wanted = raw.map(|r| r.trim().to_ascii_uppercase()).unwrap_or_default();
        Self::ALL
            .into_iter()
            .find(|m| m.name() == wanted)
            .unwrap_or(Self::Solo)
    }

    pub fn placement(self) -> ChainPlacement {
        match self {
            Self::Solo => ChainPlacement::Solo,
            Self::ConfigAether
            | Self::ConfigPsiphon
            | Self::ConfigTor
            | Self::ConfigAetherPsiphon
            | Self::ConfigAetherTor
            | Self::ConfigTorPsiphon
            | Self::ConfigTorAether => ChainPlacement::First,
            _ => ChainPlacement::Last,
        }
    }

    pub fn base(self) -> Option<ChainBase> {
        Some(match self {
            Self::Solo => return None,
            Self::ConfigAether | Self::AetherConfig => ChainBase::Aether,
            Self::ConfigPsiphon | Self::PsiphonConfig => ChainBase::Psiphon,
            Self::ConfigTor | Self::TorConfig => ChainBase::Tor,
            Self::ConfigAetherPsiphon | Self::AetherPsiphonConfig => ChainBase::AetherPsiphon,
            Self::ConfigAetherTor | Self::AetherTorConfig => ChainBase::AetherTor,
            Self::ConfigTorPsiphon | Self::TorPsiphonConfig => ChainBase::TorPsiphon,
            Self::ConfigTorAether | Self::TorAetherConfig => ChainBase::TorAether,
        })
    }

    /// تعدادِ هاپ‌ها: ۱، ۲ یا ۳.
    pub fn hops(self) -> u8 {
        match self.base() {
            None => 1,
            Some(ChainBase::Aether) | Some(ChainBase::Psiphon) | Some(ChainBase::Tor) => 2,
            Some(_) => 3,
        }
    }

    /// زنجیره همان‌طور که کاربر می‌خواند، به ترتیبی که ترافیک از رایانه بیرون
    /// می‌رود: `VLESS → Aether(WireGuard)` یا `Aether → Psiphon → Npvt`.
    pub fn label(self, config: &str, transport: Option<&str>) -> String {
        let Some(base) = self.base() else {
            return config.to_string();
        };
        let engine = base.label(transport);
        match self.placement() {
            ChainPlacement::First => format!("{config}{}{engine}", Self::ARROW),
            ChainPlacement::Last => format!("{engine}{}{config}", Self::ARROW),
            ChainPlacement::Solo => config.to_string(),
        }
    }

    /// شکل‌های کوتاه‌ترِ [`ChainMode::label`] برای یک ردیفِ باریک: بی‌پرانتزِ
    /// ترابری، و بعد با پیکان‌های چسبیده.
    pub fn compact_labels(self, config: &str, transport: Option<&str>) -> Vec<String> {
        let full = self.label(config, transport);
        let plain = self.label(config, None);
        let tight = plain.replace(Self::ARROW, Self::TIGHT_ARROW);
        let mut out: Vec<String> = Vec::new();
        for l in [full, plain, tight] {
            if !out.contains(&l) {
                out.push(l);
            }
        }
        out
    }
}

/// آنچه یک نشستِ سفارشی اجرا می‌کند: کانفیگ و زنجیره‌ای که در آن می‌نشیند.
#[derive(Debug, Clone)]
pub struct CustomSelection {
    pub config: CustomConfig,
    pub mode: ChainMode,
}

/// زمانِ فعلی به میلی‌ثانیهٔ epoch.
pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// یک شناسهٔ تصادفیِ UUID-شکل (v4). از هشِ تصادفیِ کتابخانهٔ استاندارد، زمان و
/// یک شمارنده ساخته می‌شود؛ فقط باید یکتا باشد، نه رمزنگارانه.
pub fn new_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut words = [0u64; 2];
    for (i, w) in words.iter_mut().enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(n);
        h.write_u64(i as u64);
        h.write_i64(now_millis());
        h.write_u32(std::process::id());
        *w = h.finish();
    }
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&words[0].to_be_bytes());
    b[8..].copy_from_slice(&words[1].to_be_bytes());
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifteen_modes_have_the_mobile_names_hops_and_placements() {
        assert_eq!(ChainMode::ALL.len(), 15);
        let firsts = ChainMode::ALL
            .iter()
            .filter(|m| m.placement() == ChainPlacement::First)
            .count();
        let lasts = ChainMode::ALL
            .iter()
            .filter(|m| m.placement() == ChainPlacement::Last)
            .count();
        assert_eq!((firsts, lasts), (7, 7));
        assert_eq!(ChainMode::Solo.hops(), 1);
        for m in [ChainMode::ConfigAether, ChainMode::AetherConfig, ChainMode::ConfigPsiphon, ChainMode::PsiphonConfig, ChainMode::ConfigTor, ChainMode::TorConfig] {
            assert_eq!(m.hops(), 2, "{m:?}");
        }
        for m in [ChainMode::ConfigAetherPsiphon, ChainMode::ConfigAetherTor, ChainMode::ConfigTorPsiphon, ChainMode::ConfigTorAether, ChainMode::AetherPsiphonConfig, ChainMode::AetherTorConfig, ChainMode::TorPsiphonConfig, ChainMode::TorAetherConfig] {
            assert_eq!(m.hops(), 3, "{m:?}");
        }
        for m in ChainMode::ALL {
            assert_eq!(ChainMode::from_stored_name(Some(m.name())), m);
            assert_eq!(ChainMode::from_stored_name(Some(&m.name().to_lowercase())), m);
        }
        assert_eq!(ChainMode::from_stored_name(Some("nonsense")), ChainMode::Solo);
        assert_eq!(ChainMode::from_stored_name(None), ChainMode::Solo);
    }

    #[test]
    fn labels_read_in_run_order() {
        let cases = [
            (ChainMode::Solo, "VLESS"),
            (ChainMode::ConfigAether, "VLESS \u{2192} Aether(WireGuard)"),
            (ChainMode::AetherConfig, "Aether(WireGuard) \u{2192} VLESS"),
            (ChainMode::ConfigPsiphon, "VLESS \u{2192} Psiphon"),
            (ChainMode::PsiphonConfig, "Psiphon \u{2192} VLESS"),
            (ChainMode::ConfigTor, "VLESS \u{2192} Tor"),
            (ChainMode::TorConfig, "Tor \u{2192} VLESS"),
            (ChainMode::ConfigAetherPsiphon, "VLESS \u{2192} Aether(WireGuard) \u{2192} Psiphon"),
            (ChainMode::ConfigAetherTor, "VLESS \u{2192} Aether(WireGuard) \u{2192} Tor"),
            (ChainMode::ConfigTorPsiphon, "VLESS \u{2192} Tor \u{2192} Psiphon"),
            (ChainMode::ConfigTorAether, "VLESS \u{2192} Tor \u{2192} Aether(WireGuard)"),
            (ChainMode::AetherPsiphonConfig, "Aether(WireGuard) \u{2192} Psiphon \u{2192} VLESS"),
            (ChainMode::AetherTorConfig, "Aether(WireGuard) \u{2192} Tor \u{2192} VLESS"),
            (ChainMode::TorPsiphonConfig, "Tor \u{2192} Psiphon \u{2192} VLESS"),
            (ChainMode::TorAetherConfig, "Tor \u{2192} Aether(WireGuard) \u{2192} VLESS"),
        ];
        for (mode, want) in cases {
            assert_eq!(mode.label("VLESS", Some("WireGuard")), want, "{mode:?}");
        }
        assert_eq!(ChainMode::TorConfig.label("Npvt", None), "Tor \u{2192} Npvt");
        assert_eq!(
            ChainMode::AetherPsiphonConfig.label("Trojan", None),
            "Aether \u{2192} Psiphon \u{2192} Trojan"
        );
        // A composite transport must not name the second hop twice.
        assert_eq!(
            ChainMode::ConfigAetherPsiphon.label("SS", Some("WIREGUARD \u{2192} PSIPHON")),
            "SS \u{2192} Aether(WIREGUARD) \u{2192} Psiphon"
        );
    }

    #[test]
    fn compact_labels_shrink_step_by_step() {
        let l = ChainMode::ConfigAetherTor.compact_labels("VLESS", Some("MASQUE"));
        assert_eq!(
            l,
            vec![
                "VLESS \u{2192} Aether(MASQUE) \u{2192} Tor".to_string(),
                "VLESS \u{2192} Aether \u{2192} Tor".to_string(),
                "VLESS\u{2192}Aether\u{2192}Tor".to_string(),
            ]
        );
        assert_eq!(ChainMode::Solo.compact_labels("Npvt", None), vec!["Npvt".to_string()]);
        for m in ChainMode::ALL {
            let l = m.compact_labels("Trojan", Some("WireGuard"));
            assert!(!l.is_empty() && l.len() <= 3);
            assert!(l.windows(2).all(|w| w[0] != w[1]));
        }
    }

    #[test]
    fn ids_are_unique_and_uuid_shaped() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
    }
}

pub mod cancel;
