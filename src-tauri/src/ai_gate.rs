//! پورت ۱:۱ از `ai/AiGate.kt` — چرا هوش مصنوعی همین حالا در دسترس است یا نه.
//!
//! # کل دلیل وجود این فایل
//!
//! `generativelanguage.googleapis.com` از ایران قابل دسترسی نیست، و از داخل
//! این برنامه هم تصادفاً قابل دسترسی نیست: در اندروید سرویس VPN روی پکیج خودمان
//! `addDisallowedApplication` صدا می‌زند. در ویندوز شکلِ همان واقعیت است، فقط
//! از راهی دیگر — مسیر دادهٔ ما پروکسی سیستمی + Wintun است و فرآیند خودِ
//! برنامه، مثل هر کلاینت دیگری، به پروکسی سیستم اعتماد نمی‌کند و
//! `reqwest`-وارِ مستقیم بیرون می‌رود. پس یک درخواست HTTPS عادی از این فرآیند
//! روی شبکهٔ اپراتور و بی‌رمز بیرون می‌رفت، شکست می‌خورد، و در همان مسیر به
//! اپراتور می‌گفت این دستگاه سراغ یک سرویس هوش مصنوعیِ بلاک‌شده رفته است.
//!
//! بنابراین هر درخواست هوش مصنوعی در این برنامه از پروکسی SOCKS5 محلیِ خودِ
//! تونل شماره‌گیری می‌شود، و هوش مصنوعی فقط وقتی پیشنهاد می‌شود که تونلی
//! *برای* شماره‌گیری وجود داشته باشد. این یک سیاست نیست که بعداً نرم شود: با
//! تونلِ پایین، هیچ مسیری به گوگل وجود ندارد.
//!
//! شرط حالت، نیمهٔ دومِ همین واقعیت است. اِتِرِ تنها از یک نشانی Cloudflare
//! WARP بیرون می‌رود و سرویس‌های هوش مصنوعی گوگل آن نشانی‌ها را رد یا چلنج
//! می‌کنند — همان نشانه‌ای که یادداشت ۱.۲.۸ درباره‌اش نوشت. حالت زنجیره‌ای
//! `Aether → Psiphon` از یک نشانی Psiphon بیرون می‌رود که آن نقاط پایانی
//! می‌پذیرند.

use crate::engine::{CHAIN_SOCKS_PORT, LOCAL_SOCKS_PORT};
use crate::profile::{ConnectionProfile, TransportBackend};
use crate::state::ConnectionState;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AiGate {
    /// آماده: کلید هست، تونل بالاست، حالت زنجیره‌ای است.
    Ready,
    /// هنوز کلید API وارد نشده.
    NoKey,
    /// مدلی انتخاب نشده و برای این کلید هم مدلی کشف نشده.
    NoModel,
    /// تونل پایین است (یا هنوز بالا نیامده)، پس گوگل دست‌نیافتنی است.
    Disconnected,
    /// متصل، ولی روی اِتِرِ تنها و نه حالت زنجیره‌ای.
    WrongMode,
}

impl AiGate {
    pub fn ready(self) -> bool {
        matches!(self, AiGate::Ready)
    }

    /// شناسهٔ ماشین‌خوان برای رابط کاربری — تا صفحه دکمهٔ *درستِ* رفع مشکل را
    /// نشان بدهد، نه یک «مشکلی پیش آمد» عمومی.
    pub fn code(self) -> &'static str {
        match self {
            AiGate::Ready => "READY",
            AiGate::NoKey => "NO_KEY",
            AiGate::NoModel => "NO_MODEL",
            AiGate::Disconnected => "DISCONNECTED",
            AiGate::WrongMode => "WRONG_MODE",
        }
    }
}

/// وضعیت دروازه را حل می‌کند.
///
/// ترتیب شرط‌ها اهمیت دارد و همان ترتیب اندروید است: کاربری که روی اِتِرِ تنها
/// است و وصل نیست باید اول «وصل شو» بشنود، چون عوض‌کردن بک‌اند در هر حال فقط
/// در حالت قطع ممکن است.
pub fn evaluate(
    state: ConnectionState,
    backend: TransportBackend,
    has_key: bool,
    has_model: bool,
) -> AiGate {
    if !has_key {
        return AiGate::NoKey;
    }
    if state != ConnectionState::Connected {
        return AiGate::Disconnected;
    }
    let route=crate::custom::ai_policy::active();
    let eligible=route.map(|r|r.mode.map(crate::custom::ai_policy::custom_eligible).unwrap_or(backend.is_chained())).unwrap_or(false);
    if !eligible {
        return AiGate::WrongMode;
    }
    if !has_model {
        return AiGate::NoModel;
    }
    AiGate::Ready
}

/// پورت SOCKS5 محلی که ترافیک هوش مصنوعی را حمل می‌کند.
///
/// در حالت زنجیره‌ای، استیج ۱ (اِتِر) مالکِ [`LOCAL_SOCKS_PORT`] است و استیج ۲
/// مالکِ [`CHAIN_SOCKS_PORT`] — و *استیج ۲* همان است که گوگل آی‌پی خروجی‌اش را
/// می‌بیند. حرف‌زدن با استیج ۱ از WARP بیرون می‌رفت و رد می‌شد، یعنی دقیقاً
/// همان شکستی که این دروازه برای پرهیز از آن نوشته شده؛ پس پورت از *حالت*
/// مشتق می‌شود و ثابت نوشته نشده است.
pub fn socks_port(backend: TransportBackend) -> u16 {
    if backend.is_chained() {
        CHAIN_SOCKS_PORT
    } else {
        LOCAL_SOCKS_PORT
    }
}

/// راحتیِ فراخوان‌ها: هر دو مقدارِ لازم از یک پروفایل.
pub fn socks_port_for(profile: &ConnectionProfile) -> Result<u16,String> {
    let route=crate::custom::ai_policy::active().ok_or_else(||"Connect a tunnel before using AI.".to_string())?;
    if !route.mode.map(crate::custom::ai_policy::custom_eligible).unwrap_or(profile.backend.is_chained()){return Err("This active exit is not eligible for AI.".into());}
    Ok(route.port)
}
