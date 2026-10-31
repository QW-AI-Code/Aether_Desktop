//! پورت ۱:۱ از `ai/AiSession.kt` — تنها مالکِ حالتِ لایهٔ هوش مصنوعی.
//!
//! # چرا یک لایهٔ نشست وجود دارد و رابط کاربری مستقیم کلاینت را صدا نمی‌زند
//!
//! هر فراخوان هوش مصنوعی از دو تونل رد می‌شود و می‌تواند ده‌ها ثانیه طول بکشد.
//! فراخوانی‌اش از رشتهٔ فرمانِ Tauri یعنی پنجره تا برگشتنِ پاسخ جواب نمی‌دهد —
//! همان اشتباهی که `AppState::latest` در `main.rs` برای درست‌کردنش وجود دارد،
//! فقط این‌بار با تأخیرِ صد‌برابر. پس هر کارِ شبکه روی یک رشتهٔ کارگر می‌رود، و
//! رابط کاربری فقط دو چیز می‌بیند: یک عملِ آنی که کار را *شروع* می‌کند، و رخداد
//! `aether://ai` که وقتی چیزی عوض شد می‌رسد. همان قالبِ snapshot که کل بقیهٔ
//! برنامه از آن استفاده می‌کند.
//!
//! دو قاعدهٔ دیگر که اینجا زندگی می‌کنند:
//!
//! * **یک درخواستِ در پرواز، در هر زمان.** نه به‌خاطر پیچیدگیِ همروندی، بلکه
//!   چون سهمیهٔ کلید رایگان کاربر واقعی است: صفحه‌ای که با هر بازشدن یک
//!   `models.list` می‌فرستد، و دکمه‌ای که دوبار کلیک شود، همان ۴۲۹هایی هستند که
//!   لاگ میدانی نشان می‌داد. درخواست دوم رد می‌شود، نه صف.
//! * **کَشِ توضیحات.** «این تنظیم چه کار می‌کند؟» برای یک تنظیمِ ثابت همیشه همان
//!   پاسخ را می‌دهد. بازکردنِ دوبارهٔ یک صفحه نباید سهمیه بسوزاند.

use crate::ai_client::{self, AiError, AiErrorKind, GeminiModel, GeminiTurn};
use crate::ai_gate::{self, AiGate};
use crate::ai_model_policy as policy;
use crate::ai_patch::{self, PatchOutcome, Problem, Refusal, Scope};
use crate::ai_prompts::{self, Lang};
use crate::ai_redaction;
use crate::log::DiagnosticsLog;
use crate::profile::{ConnectionProfile, TransportBackend};
use crate::secret_store::{SecretStore, GEMINI_KEY};
use crate::state::ConnectionState;
use crate::store::PrefsStore;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// یک نوبت گفت‌وگو، همان‌طور که رابط کاربری می‌بیند.
///
/// # ۱.۲.۴-p4 — چرا این ساختار چهار فیلد بیشتر گرفت
///
/// چون «کپی/ویرایش/تلاش مجدد/حذف» بدون آن‌ها قابل پیاده‌سازی نیست. پورت ۱:۱ از
/// `AiMessage` در `ai/AiSession.kt`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessage {
    /// شناسهٔ پایدارِ نوبت.
    ///
    /// اندیس کافی نیست: با یک حذف یا ویرایش فهرست زیر دستِ رابط کاربری جابه‌جا
    /// می‌شود و دکمهٔ «تلاش مجدد»ِ یک حباب به حبابِ دیگری اشاره می‌کند.
    pub id: u64,
    pub from_user: bool,
    pub text: String,
    /// وقتی این نوبت یک شکست بود — تا حباب با رنگ خطا رندر شود.
    pub failed: bool,
    /// پرسشی که این حباب را ساخت، تا «تلاش مجدد» همان را دوباره بفرستد.
    ///
    /// روی **خودِ شکست** ذخیره می‌شود و با راه‌رفتنِ عقب در فهرست پیدا نمی‌شود:
    /// بعد از یک ویرایش یا حذف، حبابِ بالای یک شکست لزوماً همان پرسشی نیست که
    /// شکست را ساخته، و فرستادنِ پیامِ اشتباه از نبودنِ دکمه بدتر است.
    pub source_prompt: Option<String>,
    /// نوعِ شکست، تا رابط کاربری جملهٔ ترجمه‌شده بنویسد و نه متنِ خامِ گوگل.
    pub error_kind: Option<AiErrorKind>,
    /// کاربر پیامِ خودش را پس از فرستادن ویرایش کرده است.
    pub edited: bool,
    /// تغییراتِ تنظیماتی که این پاسخ پیشنهاد می‌دهد، از پیش اعتبارسنجی‌شده.
    ///
    /// اعتبارسنجی **پیش از رسیدن به رابط کاربری** انجام می‌شود و نه وقتی
    /// کاربر دکمه را می‌زند: تغییری که نگهبان رد می‌کند نباید اول به شکلِ یک
    /// دکمهٔ «اعمال» دیده شود و بعد با زدنش هیچ اتفاقی نیفتد. همان ترتیبِ
    /// `AiPatch.apply(profile, proposed).applied` در `ai/AiSession.kt`.
    pub changes: Vec<ProposedChange>,
    /// کاربر روی همین حباب دکمهٔ «اعمال» را زده است.
    pub applied: bool,
}

/// یک تغییرِ پیشنهادی، آمادهٔ نمایش در کارتِ تأیید.
///
/// `before` همراه می‌رود چون «mtu: 1500 → 1380» چیزی است که کاربر می‌تواند
/// تأیید کند، و «mtu: 1380» چیزی نیست. در لحظهٔ ساختِ کارت خوانده می‌شود و نه
/// در لحظهٔ رندر، تا کارتِ قدیمی در گفت‌وگو همان مقایسه‌ای را نشان دهد که
/// وقتی نوشته شد درست بود.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedChange {
    pub key: String,
    /// مقدارِ تازه، همان‌گونه که نگهبان نرمالایزش کرد — نه متنِ خامِ مدل.
    pub value: String,
    /// مقدارِ کنونی، برای نمایش `قدیم → جدید`.
    pub before: String,
    /// دلیلِ خودِ مدل، که پیش از هر نوشتنی به کاربر نشان داده می‌شود.
    pub why: String,
}

impl ChatMessage {
    fn user(id: u64, text: String) -> Self {
        Self {
            id,
            from_user: true,
            text,
            failed: false,
            source_prompt: None,
            error_kind: None,
            edited: false,
            changes: Vec::new(),
            applied: false,
        }
    }

    fn model(id: u64, text: String, changes: Vec<ProposedChange>) -> Self {
        Self {
            id,
            from_user: false,
            text,
            failed: false,
            source_prompt: None,
            error_kind: None,
            edited: false,
            changes,
            applied: false,
        }
    }

    fn failure(id: u64, text: String, kind: AiErrorKind, prompt: &str) -> Self {
        Self {
            id,
            from_user: false,
            text,
            failed: true,
            source_prompt: Some(prompt.to_string()),
            error_kind: Some(kind),
            edited: false,
            changes: Vec::new(),
            applied: false,
        }
    }
}

/// آنچه مشاور پیشنهاد داد و آنچه نگهبان از آن پذیرفت.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisorResult {
    /// جمله‌ای که مدل دربارهٔ لاگ نوشت.
    pub reason: String,
    /// تغییراتی که واقعاً نشستند: `(کلید، مقدار تازه)`.
    pub applied: Vec<(String, String)>,
    /// پیشنهادهایی که رد شدند: `(کلید، دلیل)`.
    ///
    /// **نمایش داده می‌شود** و پنهان نمی‌شود. یک مشاور که بی‌صدا نیمی از
    /// پیشنهادش را می‌خورد، ابزاری است که نمی‌توان به آن اعتماد کرد.
    pub rejected: Vec<(String, String)>,
}

/// کلِ حالتِ دیدنیِ لایهٔ هوش مصنوعی — یک snapshot، مثل بقیهٔ برنامه.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiSnapshot {
    pub gate: AiGate,
    pub gate_code: String,
    /// Current tunnel state; independent of key/model and exit-mode policy.
    pub tunnel_connected: bool,
    /// کلید ذخیره شده است یا نه. **هرگز خودِ کلید.**
    pub has_key: bool,
    /// چهار نویسهٔ آخرِ کلید، برای اینکه کاربر بفهمد کدام کلید ذخیره است.
    ///
    /// چهار نویسه و از **انتها**: به هیچ‌کس اجازهٔ بازسازی نمی‌دهد و به کاربری
    /// که سه کلید دارد اجازه می‌دهد بگوید کدام یکی است.
    pub key_hint: String,
    pub models: Vec<GeminiModel>,
    pub selected_model: String,
    /// شمارهٔ ردیفِ ثابتِ مدل در فهرست مجاز ([`policy::display_number`]).
    pub model_number: usize,
    pub busy: bool,
    /// آخرین شکست، به‌صورت جمله‌ای قابل‌نمایش.
    pub error: Option<String>,
    pub error_kind: Option<AiErrorKind>,
    pub messages: Vec<ChatMessage>,
    pub advisor: Option<AdvisorResult>,
    /// نتیجهٔ آخرین تست اتصال. رجوع به [`AiProbe`].
    pub probe: AiProbe,
}

/// نتیجهٔ «تست اتصال به API» — پورت از `AiSession.testConnection` در موبایل.
///
/// # چرا نتیجه *ذخیره* می‌شود و فقط برگردانده نمی‌شود
///
/// چون کاربر بعد از تست به تبِ دیگری می‌رود و برمی‌گردد، و باید همان جوابی را
/// ببیند که گرفته بود. تستی که نتیجه‌اش با هر رندر پاک شود، کاربر را مجبور می‌کند
/// دوباره سهمیه بسوزاند تا چیزی را ببیند که پنج ثانیه پیش دیده بود.
///
/// `via` برچسبِ مسیری است که درخواست از آن رفت (نامِ خوانای بک‌اند، نه شمارهٔ
/// پورت): یک کلیدِ سالم روی «اِتِر تنها» و یک کلیدِ سالم روی «اِتِر → سایفون» دو
/// خبرِ متفاوت‌اند، و کاربری که ISPش Gemini را می‌بندد باید بداند کدام مسیر جواب
/// داد.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiProbe {
    /// `IDLE` | `RUNNING` | `OK` | `FAILED` — رشته و نه enum، چون رابط کاربری
    /// فقط با آن مقایسه می‌کند و یک enum سریال‌شده اینجا هیچ چیزی اضافه نمی‌کرد.
    pub state: &'static str,
    /// چند مدلِ مجاز پیدا شد. صفر با `OK` ممکن است: کلید سالم است ولی این حساب
    /// به هیچ مدلِ Flash دسترسی ندارد — و آن هم خبرِ مفیدی است.
    pub model_count: usize,
    /// مسیرِ موفق، به‌صورت خوانا.
    pub via: String,
    /// پیامِ شکست، همان جمله‌ای که کاربر باید ببیند.
    pub message: String,
}

impl Default for AiProbe {
    fn default() -> Self {
        Self {
            state: "IDLE",
            model_count: 0,
            via: String::new(),
            message: String::new(),
        }
    }
}

impl AiProbe {
    fn running() -> Self {
        Self {
            state: "RUNNING",
            ..Default::default()
        }
    }

    fn ok(model_count: usize, via: String) -> Self {
        Self {
            state: "OK",
            model_count,
            via,
            message: String::new(),
        }
    }

    fn failed(message: String) -> Self {
        Self {
            state: "FAILED",
            model_count: 0,
            via: String::new(),
            message,
        }
    }
}

/// نامِ خوانای مسیر، برای نشان‌دادن در نتیجهٔ تست.
///
/// همان رشته‌ای که رابط کاربری در انتخابگرِ بک‌اند نشان می‌دهد؛ فرستادنِ
/// `AETHER_PSIPHON` به کاربر یک نامِ داخلی است و نه یک جواب.
///
/// ۱.۲.۵: این تابع پیش‌تر جدولِ نام‌ها را **تکرار** می‌کرد، و افزودن چهار
/// بک‌اند تور همان‌جا به خطای کامپایل خورد — که در این مورد بهترین اتفاق بود:
/// یک `_ =>` به‌جایش، بی‌صدا «Aether» را برای یک نشستِ تور می‌نوشت. حالا تنها
/// منبعِ حقیقت [`TransportBackend::protocol_label`] است، که `None` اش دقیقاً
/// یعنی «همان اِتِرِ ساده».
fn backend_label(backend: TransportBackend) -> &'static str {
    backend.protocol_label().unwrap_or("Aether")
}

/// حالتِ درونی، پشت یک قفل.
#[derive(Default)]
struct Inner {
    models: Vec<GeminiModel>,
    selected_model: String,
    busy: bool,
    error: Option<String>,
    error_kind: Option<AiErrorKind>,
    messages: Vec<ChatMessage>,
    advisor: Option<AdvisorResult>,
    probe: AiProbe,
    /// `(عنوان تنظیم, زبان)` → توضیح. رجوع به مستند بالای فایل.
    explain_cache: HashMap<(String, &'static str), String>,
    /// شمارندهٔ شناسهٔ نوبت‌ها. یکنواخت افزایشی و هرگز بازاستفاده نمی‌شود.
    next_id: u64,
    /// دورهٔ گفت‌وگو؛ با «توقف» و «پاک‌کردن» یکی بالا می‌رود.
    ///
    /// درخواستِ در پرواز روی یک رشتهٔ blocking نشسته و لغو نمی‌شود؛ آنچه می‌توان
    /// لغو کرد **نشاندنِ نتیجه** است. کارگر پیش از نوشتنِ پاسخ این عدد را با
    /// عددی که با آن شروع کرده مقایسه می‌کند و اگر عوض شده باشد پاسخ را می‌اندازد
    /// — همان کاری که `chatJob?.cancel()` در موبایل عملاً می‌کند.
    epoch: u64,
}

impl Inner {
    /// شناسهٔ بعدی. از ۱ شروع می‌شود تا `0` بتواند «هیچ» باشد.
    fn take_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

pub struct AiSession {
    inner: Mutex<Inner>,
    secrets: SecretStore,
    settings: Arc<PrefsStore>,
}

/// سقفِ نوبت‌هایی که با هر درخواستِ چت فرستاده می‌شود.
///
/// REST API بی‌حالت است، پس هر نوبت هر بار **دوباره** فرستاده می‌شود؛ یک
/// گفت‌وگوی بلند به‌آرامی درخواستی می‌سازد که هم کند است و هم بودجهٔ ورودی مدل را
/// پر می‌کند تا جایی که پاسخ‌ها بی‌صدا بریده شوند. دنبالهٔ ۱۶ نوبت، زمینهٔ کافی
/// برای «همان را دوباره ولی کوتاه‌تر بگو» است.
const MAX_HISTORY_TURNS: usize = 16;
/// ۱.۴.۰ (پورت از موبایل): ۰٫۷ → ۰٫۳۵. دقت مهم‌تر از تنوع است: مدلی که
/// «خلاقانه» یک تنظیمِ ناموجود یا یک مقدارِ تکراری پیشنهاد کند، اعتماد را می‌سوزاند.
const CHAT_TEMPERATURE: f64 = 0.35;
const CHAT_MAX_TOKENS: u32 = 1_400;
/// بودجهٔ دورِ بازنویسی: پاسخِ کامل دوباره نوشته می‌شود، پس کمی جای بیشتر.
const CHAT_REVISION_MAX_TOKENS: u32 = 2_000;
const EXPLAIN_TEMPERATURE: f64 = 0.3;
const EXPLAIN_MAX_TOKENS: u32 = 600;
/// مشاور با دمای صفر: این مسیر باید تصمیمِ *یکسان* را برای همان لاگ بگیرد.
const ADVISOR_TEMPERATURE: f64 = 0.0;
const ADVISOR_MAX_TOKENS: u32 = 2_000;

impl AiSession {
    pub fn new(data_dir: &Path, settings: Arc<PrefsStore>) -> Self {
        let selected = settings.get_string("aiModel").unwrap_or_default();
        let cached_ids: Vec<String> = settings
            .get_string("aiModelCache")
            .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
            .unwrap_or_default();
        // فهرستِ کَش‌شده هم از فهرست مجاز رد می‌شود — رجوع به مستند
        // [`crate::ai_model_policy`]: مسیرِ کَش دقیقاً همان مسیری بود که
        // مدل‌های فیلترشده را به انتخابگر برمی‌گرداند.
        let allowed_ids = policy::filter_ids(&cached_ids);
        let models: Vec<GeminiModel> = allowed_ids
            .iter()
            .map(|id| GeminiModel {
                id: id.clone(),
                display_name: id.clone(),
                description: String::new(),
                input_token_limit: 0,
                output_token_limit: 0,
                chat_capable: true,
            })
            .collect();
        let selected = if policy::is_allowed(&selected) {
            policy::normalise(&selected)
        } else {
            // ۱.۴.۰-r5: Flash-Lite پیش‌فرض است، نه اولین مدلِ فهرست.
            policy::pick_default_id(&allowed_ids).unwrap_or_default()
        };
        Self {
            inner: Mutex::new(Inner {
                models,
                selected_model: selected,
                ..Default::default()
            }),
            secrets: SecretStore::new(data_dir),
            settings,
        }
    }

    // ---- خواندن‌ها -------------------------------------------------------

    pub fn snapshot(
        &self,
        state: crate::state::ConnectionState,
        profile: &ConnectionProfile,
    ) -> AiSnapshot {
        let inner = self.inner.lock().unwrap();
        let key = self.secrets.read(GEMINI_KEY);
        let gate = ai_gate::evaluate(
            state,
            profile.backend,
            !key.is_empty(),
            !inner.selected_model.is_empty(),
        );
        AiSnapshot {
            gate,
            gate_code: gate.code().to_string(),
            tunnel_connected: state == ConnectionState::Connected,
            has_key: !key.is_empty(),
            key_hint: key
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            models: inner.models.clone(),
            selected_model: inner.selected_model.clone(),
            model_number: policy::display_number(&inner.selected_model),
            busy: inner.busy,
            error: inner.error.clone(),
            error_kind: inner.error_kind,
            messages: inner.messages.clone(),
            advisor: inner.advisor.clone(),
            probe: inner.probe.clone(),
        }
    }

    // ---- نوشتن‌های آنی ---------------------------------------------------

    /// کلید API را ذخیره می‌کند. رشتهٔ خالی یعنی فراموشش کن.
    ///
    /// فهرست مدل‌های کَش‌شده هم پاک می‌شود: مدل‌هایی که یک کلید می‌بیند مالِ
    /// **همان** کلید است، و نگه‌داشتنشان بعد از عوض‌شدن کلید یعنی انتخابگر
    /// مدل‌هایی را نشان دهد که کلید تازه با ۴۰۴ ردشان می‌کند.
    pub fn set_api_key(&self, key: &str) -> Result<(), String> {
        self.secrets
            .write(GEMINI_KEY, key)
            .map_err(|e| e.to_string())?;
        let mut inner = self.inner.lock().unwrap();
        // نتیجهٔ تستِ کلیدِ قبلی دربارهٔ کلیدِ تازه هیچ چیزی نمی‌گوید. نگه‌داشتنش
        // یعنی «سالم» نشان دادنِ کلیدی که هرگز آزمایش نشده.
        inner.probe = AiProbe::default();
        inner.models.clear();
        inner.selected_model.clear();
        inner.error = None;
        inner.error_kind = None;
        let _ = self.settings.set_string("aiModelCache", "[]");
        let _ = self.settings.set_string("aiModel", "");
        DiagnosticsLog::i(
            "ai",
            if key.trim().is_empty() {
                "API key cleared."
            } else {
                "API key stored (sealed)."
            },
        );
        Ok(())
    }

    /// مدل را انتخاب می‌کند. فقط شناسه‌های مجاز پذیرفته می‌شوند.
    pub fn select_model(&self, id: &str) -> Result<(), String> {
        if !policy::is_allowed(id) {
            return Err(format!(
                "Model \"{id}\" is not one of the models this app supports."
            ));
        }
        let normalised = policy::normalise(id);
        self.inner.lock().unwrap().selected_model = normalised.clone();
        let _ = self.settings.set_string("aiModel", &normalised);
        Ok(())
    }

    pub fn clear_chat(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.messages.clear();
        inner.error = None;
        inner.error_kind = None;
        // دورهٔ تازه: پاسخی که همین حالا در راه است به گفت‌وگوی پاک‌شده تعلق دارد
        // و نباید در گفت‌وگوی خالیِ بعدی ظاهر شود.
        inner.epoch += 1;
        inner.busy = false;
    }

    pub fn dismiss_error(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.error = None;
        inner.error_kind = None;
    }

    pub fn dismiss_advisor(&self) {
        self.inner.lock().unwrap().advisor = None;
    }

    // ---- کارِ شبکه (روی رشتهٔ کارگر صدا زده می‌شود) -----------------------

    /// درخواست را نگه می‌دارد اگر یکی در پرواز است.
    ///
    /// `Err` یعنی «شروع نشد» و به رابط کاربری برمی‌گردد تا دکمه بتواند وضعیت را
    /// نگه دارد. صف‌کردن به‌جای رد‌کردن یعنی سه کلیکِ بی‌حوصله، سه درخواست به
    /// سهمیه‌ای که کاربر ۵۰ تا در روز دارد.
    fn begin(&self) -> Result<(String, String), String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.busy {
            return Err("A request is already running.".into());
        }
        let key = self.secrets.read(GEMINI_KEY);
        if key.is_empty() {
            return Err("No API key stored.".into());
        }
        let model = inner.selected_model.clone();
        inner.busy = true;
        inner.error = None;
        inner.error_kind = None;
        Ok((key, model))
    }

    fn finish(&self, failure: Option<AiError>) {
        let mut inner = self.inner.lock().unwrap();
        inner.busy = false;
        if let Some(error) = failure {
            inner.error = Some(error.message);
            inner.error_kind = Some(error.kind);
        }
    }

    /// مدل‌های موجود برای این کلید را کشف و کَش می‌کند.
    pub fn refresh_models(&self, profile: &ConnectionProfile) -> Result<(), String> {
        let (key, _) = self.begin()?;
        let port = match ai_gate::socks_port_for(profile){Ok(port)=>port,Err(e)=>{self.finish(None);return Err(e);}};
        // برچسبِ مسیر پیش از درخواست ساخته می‌شود: بعد از موفقیت، قفل دستِ ما است
        // و خواندنِ پروفایل زیر قفل، همان قرضِ دوگانه‌ای است که کامپایلر رد می‌کند.
        let via = backend_label(profile.backend).to_string();
        let result = ai_client::list_models(&key, port);
        match result {
            Ok(models) => {
                let ids: Vec<String> = models.iter().map(|m| m.id.clone()).collect();
                let _ = self.settings.set_string(
                    "aiModelCache",
                    &serde_json::to_string(&ids).unwrap_or_else(|_| "[]".into()),
                );
                let mut inner = self.inner.lock().unwrap();
                // انتخابِ فعلی اگر دیگر پیشنهاد نمی‌شود، به تازه‌ترین مدل
                // برمی‌گردد؛ یک انتخابِ ناموجود یعنی هر پرسشِ بعدی ۴۰۴ بگیرد.
                if inner.selected_model.is_empty() || !ids.contains(&inner.selected_model) {
                    inner.selected_model = policy::pick_default(&models).unwrap_or_default();
                    let _ = self.settings.set_string("aiModel", &inner.selected_model);
                }
                // همین رفت‌وبرگشت *هست* تستِ اتصال، پس نتیجه‌اش هم ثبت می‌شود:
                // کاربری که مدل‌ها را کشف کرده، نباید برای دیدنِ «سالم» یک
                // درخواستِ دیگر بفرستد.
                inner.probe = AiProbe::ok(models.len(), via.clone());
                inner.models = models;
                inner.busy = false;
                Ok(())
            }
            Err(error) => {
                let message = error.message.clone();
                self.inner.lock().unwrap().probe = AiProbe::failed(message.clone());
                self.finish(Some(error));
                Err(message)
            }
        }
    }

    /// «تست اتصال به API» — پورت ۱:۱ از `testConnection` در موبایل.
    ///
    /// عمداً همان مسیرِ کشفِ مدل را می‌رود و نه یک درخواستِ ساختگیِ سبک‌تر: چیزی
    /// که کاربر می‌خواهد بداند این است که «آیا این کلید از این تونل کار می‌کند»،
    /// و تنها پاسخِ صادق به آن، همان درخواستی است که برنامه واقعاً می‌فرستد.
    /// نتیجه در [`AiProbe`] می‌نشیند و `Err` هم برگردانده می‌شود تا فرمان بتواند
    /// آن را لاگ کند.
    pub fn test_connection(&self, profile: &ConnectionProfile) -> Result<(), String> {
        self.mark_probe_running();
        self.refresh_models(profile)
    }

    /// `probe.state = RUNNING`، بدون هیچ کار شبکه‌ای.
    ///
    /// جدا از [`Self::test_connection`] وجود دارد چون فرمانِ Tauri باید *پیش از*
    /// رفتن به رشتهٔ کارگر یک snapshot با «در حال تست…» منتشر کند؛ اگر منتظرِ خودِ
    /// `test_connection` بمانیم، دکمه تا پایان درخواست بی‌واکنش می‌ماند.
    pub fn mark_probe_running(&self) {
        self.inner.lock().unwrap().probe = AiProbe::running();
    }

    /// «این تنظیم چه کار می‌کند؟» — با کَش.
    pub fn explain(
        &self,
        profile: &ConnectionProfile,
        lang_code: &str,
        title: &str,
        subtitle: &str,
        value: &str,
    ) -> Result<String, String> {
        let lang = Lang::from_code(lang_code);
        let lang_key = if matches!(lang, Lang::Fa) { "fa" } else { "en" };
        let cache_key = (title.to_string(), lang_key);
        if let Some(hit) = self.inner.lock().unwrap().explain_cache.get(&cache_key) {
            return Ok(hit.clone());
        }
        let (key, model) = self.begin()?;
        let port = match ai_gate::socks_port_for(profile){Ok(port)=>port,Err(e)=>{self.finish(None);return Err(e);}};
        let turns = [GeminiTurn {
            from_user: true,
            text: ai_prompts::explain_user(title, subtitle, value),
        }];
        let result = ai_client::generate(
            &key,
            port,
            &model,
            &ai_prompts::explain_system(lang),
            &turns,
            EXPLAIN_TEMPERATURE,
            EXPLAIN_MAX_TOKENS,
            false,
        );
        match result {
            Ok(text) => {
                let mut inner = self.inner.lock().unwrap();
                inner.explain_cache.insert(cache_key, text.clone());
                inner.busy = false;
                Ok(text)
            }
            Err(error) => {
                let message = error.message.clone();
                self.finish(Some(error));
                Err(message)
            }
        }
    }

    /// حبابِ کاربر را **همگام** می‌نشاند، بی‌آنکه چیزی به شبکه برود.
    ///
    /// # چرا این از `dispatch` جدا شده — ریشهٔ «پیام بعد از پاسخ ظاهر می‌شد»
    ///
    /// نسخهٔ قبل هر دو کار را در `send_chat` انجام می‌داد و `main.rs` کلِ آن را با
    /// `spawn_blocking` به یک رشتهٔ کارگر می‌داد و بعد فوراً `publish_ai` می‌زد.
    /// آن `publish_ai` با افزودنِ حباب **مسابقه** می‌داد و تقریباً همیشه برنده
    /// می‌شد: snapshot پیش از نشستنِ حباب گرفته می‌شد، پس پرسشِ کاربر تا رسیدنِ
    /// پاسخ روی صفحه نبود. یعنی کاربر متن را می‌فرستاد و یک جعبهٔ خالی می‌دید.
    ///
    /// حالا حباب روی همان رشتهٔ فرمان و **پیش از** رفتن به کارگر می‌نشیند، پس
    /// وقتی `publish_ai` اجرا می‌شود دیگر چیزی برای مسابقه نمانده. ترتیب، خودش
    /// تضمین است؛ یک `sleep` نیست.
    pub fn append_user_message(&self, text: &str) -> Result<String, String> {
        let text = text.trim().to_string();
        if text.is_empty() {
            return Err("Nothing to send.".into());
        }
        let mut inner = self.inner.lock().unwrap();
        let id = inner.take_id();
        inner.messages.push(ChatMessage::user(id, text.clone()));
        Ok(text)
    }

    /// یک نوبت چت می‌فرستد: حبابِ کاربر را می‌نشاند و بعد می‌پرسد.
    ///
    /// روی رشتهٔ کارگر صدا زده می‌شود. `main.rs` حبابِ کاربر را پیش‌تر و همگام با
    /// [`append_user_message`](Self::append_user_message) نشانده است؛ این تابع فقط
    /// برای مسیرهایی مانده که کلِ کار را یک‌جا می‌خواهند.
    pub fn send_chat(
        &self,
        profile: &ConnectionProfile,
        status: ConnectionState,
        lang_code: &str,
        text: &str,
    ) -> Result<(), String> {
        let text = self.append_user_message(text)?;
        self.dispatch(profile, status, lang_code, &text)
    }

    /// همان پرسش را **بدون** افزودنِ حبابِ تازه برای آن می‌فرستد — رجوع به
    /// [`AiSession::dispatch`].
    pub fn ask_existing(
        &self,
        profile: &ConnectionProfile,
        status: ConnectionState,
        lang_code: &str,
        prompt: &str,
    ) -> Result<(), String> {
        self.dispatch(profile, status, lang_code, prompt)
    }

    /// همان پرسش را **بدون** افزودنِ حبابِ تازه برای آن می‌فرستد.
    ///
    /// از `send_chat` جدا شد چون «تلاش مجدد» و «ویرایش» هر دو باید با حبابِ
    /// کاربرِ موجود بپرسند: تلاش مجدد نباید پرسش را دو بار روی صفحه بگذارد و
    /// ویرایش همین حالا خودش آن را بازنویسی کرده است. همان تفکیکِ `dispatch` در
    /// `ai/AiSession.kt`.
    fn dispatch(
        &self,
        profile: &ConnectionProfile,
        status: ConnectionState,
        lang_code: &str,
        prompt: &str,
    ) -> Result<(), String> {
        let (key, model) = match self.begin() {
            Ok(pair) => pair,
            Err(message) => {
                // دروازهٔ بسته یا نبودِ کلید هم یک حبابِ شکستِ قابلِ «تلاش مجدد»
                // است، نه یک استثنا که در کنسول گم شود.
                let mut inner = self.inner.lock().unwrap();
                let id = inner.take_id();
                inner.messages.push(ChatMessage::failure(
                    id,
                    message.clone(),
                    AiErrorKind::Blocked,
                    prompt,
                ));
                return Err(message);
            }
        };
        let (epoch, history) = {
            let inner = self.inner.lock().unwrap();
            let start = inner.messages.len().saturating_sub(MAX_HISTORY_TURNS);
            let history: Vec<GeminiTurn> = inner.messages[start..]
                .iter()
                .filter(|m| !m.failed) // نوبت‌های شکست‌خورده زمینه نیستند، سر و صدا هستند.
                .map(|m| GeminiTurn {
                    from_user: m.from_user,
                    text: m.text.clone(),
                })
                .collect();
            (inner.epoch, history)
        };
        let lang = Lang::from_code(lang_code);
        let port = match ai_gate::socks_port_for(profile){Ok(port)=>port,Err(e)=>{self.finish(None);return Err(e);}};
        // ۱.۴.۰-r4: snapshotِ حاشیه‌دار + نامِ مدل + وضعیتِ زندهٔ اتصال.
        let system = ai_prompts::chat_system(
            lang,
            &ai_patch::chat_snapshot(profile),
            &model,
            status_for_prompt(status),
        );
        let result = ai_client::generate(
            &key,
            port,
            &model,
            &system,
            &history,
            CHAT_TEMPERATURE,
            CHAT_MAX_TOKENS,
            false,
        );
        match result {
            Ok(reply) => {
                // بلوکِ پیشنهاد از متن جدا و **پیش از رسم حباب** اعتبارسنجی
                // می‌شود؛ رجوع به `ChatMessage::changes`.
                let (mut visible, mut changes, refusals) =
                    self.vet_changes_verified(profile, &reply);

                // ۱.۴.۰-r4: بررسی، و بعد یک بار خوداصلاحیِ مدل (پورت از
                // `AiSession.kt`). حذفِ دکمهٔ تکراری کافی نبود: متنِ بالای آن هنوز
                // می‌گفت «MTU را ۱۲۸۰ کن» به کاربری که ۱۲۸۰ داشت. پس وقتی چیزی از
                // پیشنهاد رد شود، مدل واقعیت‌های سنجیده را می‌گیرد و کلِ پاسخ را پیش
                // از آنکه کاربر چیزی ببیند بازنویسی می‌کند. پاسخِ بازنویسی‌شده از همان
                // فیلتر رد می‌شود؛ دورِ دومی وجود ندارد.
                if let Some(feedback) =
                    ai_patch::verification_feedback(profile, &refusals, Scope::Chat)
                {
                    let stopped = self.inner.lock().unwrap().epoch != epoch;
                    if !stopped {
                        DiagnosticsLog::i(
                            "ai",
                            &format!(
                                "chat: {} proposal(s) failed verification; asking the model to revise",
                                refusals.len()
                            ),
                        );
                        let mut turns = history.clone();
                        turns.push(GeminiTurn {
                            from_user: false,
                            text: reply.clone(),
                        });
                        turns.push(GeminiTurn {
                            from_user: true,
                            text: ai_prompts::chat_revision(&feedback),
                        });
                        match ai_client::generate(
                            &key,
                            port,
                            &model,
                            &system,
                            &turns,
                            CHAT_TEMPERATURE,
                            CHAT_REVISION_MAX_TOKENS,
                            false,
                        ) {
                            Ok(revised) => {
                                let (v, c, _) = self.vet_changes_verified(profile, &revised);
                                if !v.trim().is_empty() {
                                    visible = v;
                                    changes = c;
                                }
                            }
                            Err(error) => DiagnosticsLog::w(
                                "ai",
                                &format!(
                                    "chat: revision round failed ({:?}); showing the verified original",
                                    error.kind
                                ),
                            ),
                        }
                    }
                }
                if visible.trim().is_empty() {
                    // پاسخی که فقط بلوک بود: حباب خالی نمی‌ماند (همان `ifBlank` موبایل).
                    visible = reply.trim().to_string();
                }
                let mut inner = self.inner.lock().unwrap();
                inner.busy = false;
                if inner.epoch != epoch {
                    // کاربر «توقف» زده یا گفت‌وگو را پاک کرده: پاسخ انداخته می‌شود.
                    return Ok(());
                }
                let id = inner.take_id();
                inner
                    .messages
                    .push(ChatMessage::model(id, visible, changes));
                Ok(())
            }
            // یک پاسخِ بریده هنوز یک پاسخ است: متنِ نیمه نشان داده می‌شود و
            // علامت‌گذاری می‌شود، چون انداختنش کاربر را با سهمیهٔ سوخته و هیچ
            // چیزی روی صفحه رها می‌کرد.
            Err(error)
                if error.kind == AiErrorKind::Truncated && !error.message.trim().is_empty() =>
            {
                let mut inner = self.inner.lock().unwrap();
                inner.busy = false;
                if inner.epoch != epoch {
                    return Ok(());
                }
                let id = inner.take_id();
                inner.messages.push(ChatMessage::failure(
                    id,
                    error.message,
                    AiErrorKind::Truncated,
                    prompt,
                ));
                inner.error_kind = Some(AiErrorKind::Truncated);
                Ok(())
            }
            Err(error) => {
                let message = error.message.clone();
                let mut inner = self.inner.lock().unwrap();
                inner.busy = false;
                if inner.epoch != epoch {
                    return Ok(());
                }
                let id = inner.take_id();
                inner.messages.push(ChatMessage::failure(
                    id,
                    message.clone(),
                    error.kind,
                    prompt,
                ));
                // `error` سراسری **نشانده نمی‌شود**: شکستِ چت مالِ همان حباب است و
                // نشاندنش در نوار بالای صفحه یعنی یک خطا دو بار گفته شود.
                inner.error_kind = Some(error.kind);
                Err(message)
            }
        }
    }

    /// حبابِ شکست را برمی‌دارد و پرسشی که ساخته بودش را برمی‌گرداند.
    ///
    /// # چرا این نیمه از خودِ فرستادن جدا است
    ///
    /// همان دلیلِ [`AiSession::append_user_message`]: `main.rs` باید بتواند
    /// **پیش از** رفتن به شبکه یک snapshot منتشر کند. اگر برداشتنِ حبابِ قرمز
    /// داخل رشتهٔ کارگر بماند، آن انتشار با آن مسابقه می‌دهد و حبابِ قرمز تا
    /// رسیدنِ پاسخِ تازه سرِ جایش می‌ماند — یعنی کاربر «تلاش مجدد» می‌زند و هیچ
    /// نشانه‌ای نمی‌بیند که کلیکش کاری کرده.
    ///
    /// حبابِ شکست **برداشته می‌شود** تا تلاشی که باز هم شکست بخورد جای آن را
    /// بگیرد و ستونی از حباب‌های قرمزِ یکسان نسازد.
    pub fn take_failed_prompt(&self, message_id: u64) -> Result<String, String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.busy {
            return Err("A request is already running.".into());
        }
        let index = match inner.messages.iter().position(|m| m.id == message_id) {
            Some(index) => index,
            None => return Err("That message is no longer in the conversation.".into()),
        };
        if !inner.messages[index].failed {
            return Err("Only a failed message can be sent again.".into());
        }
        let prompt = inner.messages[index]
            .source_prompt
            .clone()
            // حباب‌هایی که نسخهٔ قبلی نوشته بود `sourcePrompt` ندارند؛ برای
            // آن‌ها نزدیک‌ترین نوبتِ کاربرِ بالاتر بهترین حدسِ موجود است.
            .or_else(|| {
                inner.messages[..index]
                    .iter()
                    .rev()
                    .find(|m| m.from_user)
                    .map(|m| m.text.clone())
            });
        let prompt = match prompt {
            Some(text) if !text.trim().is_empty() => text.trim().to_string(),
            _ => return Err("There is nothing to send again.".into()),
        };
        inner.messages.retain(|m| m.id != message_id);
        Ok(prompt)
    }

    /// همان پرسشِ شکست‌خورده را دوباره می‌فرستد — هر دو نیمه، یک‌جا.
    ///
    /// `main.rs` دو نیمه را جدا صدا می‌زند تا بتواند بینشان منتشر کند؛ این تابع
    /// برای تست‌ها و هر فراخوانی مانده که کلِ کار را یک‌جا می‌خواهد.
    pub fn retry(
        &self,
        profile: &ConnectionProfile,
        status: ConnectionState,
        lang_code: &str,
        message_id: u64,
    ) -> Result<(), String> {
        let prompt = self.take_failed_prompt(message_id)?;
        self.dispatch(profile, status, lang_code, &prompt)
    }

    /// یکی از پیام‌های خودِ کاربر را بازنویسی می‌کند و از همان نقطه دوباره می‌پرسد.
    ///
    /// هر چیزی **بعد از** پیامِ ویرایش‌شده حذف می‌شود، چون گفت‌وگویی است که به
    /// پرسشی جواب داده که دیگر وجود ندارد؛ نگه‌داشتنِ پاسخِ قدیمی زیر پرسشِ
    /// عوض‌شده، همان جایی است که یک صفحهٔ چت شروع می‌کند دربارهٔ گفته‌ها دروغ بگوید.
    pub fn edit_message(
        &self,
        profile: &ConnectionProfile,
        status: ConnectionState,
        lang_code: &str,
        message_id: u64,
        new_text: &str,
    ) -> Result<(), String> {
        let prompt = new_text.trim().to_string();
        if prompt.is_empty() {
            return Err("Nothing to send.".into());
        }
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.busy {
                return Err("A request is already running.".into());
            }
            let index = match inner.messages.iter().position(|m| m.id == message_id) {
                Some(index) => index,
                None => return Err("That message is no longer in the conversation.".into()),
            };
            if !inner.messages[index].from_user {
                return Err("Only your own message can be edited.".into());
            }
            if inner.messages[index].text == prompt {
                return Ok(());
            }
            inner.messages.truncate(index + 1);
            inner.messages[index].text = prompt.clone();
            inner.messages[index].edited = true;
        }
        self.dispatch(profile, status, lang_code, &prompt)
    }

    /// چند حباب را در یک رفت حذف می‌کند.
    ///
    /// یک مجموعه و نه حلقه‌ای از حذف‌های تکی: انتخابِ یازده پیام و حذفِ یکی‌یکی،
    /// یازده snapshot به رابط کاربری می‌فرستاد و یازده بار همان فهرست را از نو
    /// می‌ساخت.
    pub fn delete_messages(&self, ids: &[u64]) {
        if ids.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.messages.retain(|m| !ids.contains(&m.id));
        if inner.messages.is_empty() {
            inner.epoch += 1;
            inner.busy = false;
        }
    }

    /// پاسخِ در راه را رها می‌کند.
    ///
    /// درخواستِ HTTP روی رشتهٔ blocking تا آخر می‌رود — چیزی که «توقف» تضمین
    /// می‌کند این است که **نتیجه‌اش نوشته نشود** و صفحه فوراً از حالت انتظار
    /// بیرون بیاید. همان تضمینی که `chatJob?.cancel()` در موبایل می‌دهد.
    pub fn stop(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.epoch += 1;
        inner.busy = false;
    }

    // ---- اعمالِ تنظیماتِ پیشنهادیِ یک حباب --------------------------------

    /// بلوکِ پیشنهاد را از پاسخ جدا می‌کند و آن را از نگهبان می‌گذراند.
    ///
    /// روی یک **کپی** از پروفایل کار می‌کند و هیچ چیزی نمی‌نویسد: این یک اجرای
    /// خشک است که فقط می‌گوید کدام تغییرها *می‌توانستند* بنشینند. کلیدی که رد
    /// شود اصلاً به رابط کاربری نمی‌رسد، پس هرگز به شکل یک دکمهٔ بی‌اثر دیده
    /// نمی‌شود؛ و در همان حال در لاگ ثبت می‌شود، چون مدلی که چیزی خارج از فهرست
    /// می‌خواهد رخدادی است که ارزش دیده‌شدن دارد.
    fn vet_changes(
        &self,
        profile: &ConnectionProfile,
        reply: &str,
    ) -> (String, Vec<ProposedChange>) {
        let (visible, vetted, _) = self.vet_changes_verified(profile, reply);
        (visible, vetted)
    }

    /// همان [`Self::vet_changes`]، به‌علاوهٔ فهرستِ ردشده‌ها برای بازخورد به مدل.
    ///
    /// ۱.۴.۰-r4: سه نوع رد که قبلاً بی‌صدا گم می‌شدند حالا ثبت می‌شوند — مقداری
    /// که کاربر از قبل دارد، کلیدی که دو بار آمده، و (مثل قبل) کلید/مقدارِ
    /// نامعتبر — تا [`ai_patch::verification_feedback`] بتواند به مدل بگوید.
    /// تکراری بودن با پروفایلِ **اصلی** سنجیده می‌شود، نه با کپیِ در حالِ تغییر.
    fn vet_changes_verified(
        &self,
        profile: &ConnectionProfile,
        reply: &str,
    ) -> (String, Vec<ProposedChange>, Vec<Refusal>) {
        let (visible, proposed) = ai_prompts::split_chat_reply(reply);
        if proposed.is_empty() {
            return (visible, Vec::new(), Vec::new());
        }
        let mut trial = profile.clone();
        let mut vetted = Vec::new();
        let mut refusals = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        // کلیدبه‌کلید و نه یک‌کاسه: یک پیشنهادِ چهارتایی که یکی‌اش بد است، باید
        // سه دکمهٔ درست بدهد و نه هیچ.
        for change in proposed {
            let key = change.key.trim().to_string();
            // یک پیشنهاد، یک مقدار برای هر کلید. مدلی که `mtu` را دو بار می‌آورد
            // با خودش تناقض دارد؛ اعمالِ هر دو بی‌صدا آخری را نگه می‌داشت.
            if seen.contains(&key) {
                refusals.push(Refusal {
                    key,
                    proposed: change.value.clone(),
                    problem: Problem::Duplicate,
                });
                continue;
            }
            seen.push(key.clone());
            let patch = serde_json::json!({ key.clone(): change.value.clone() });
            let before = ai_patch::read_key(&trial, &key);
            let outcome = ai_patch::apply_chat(&mut trial, &patch);
            match outcome.applied.first() {
                Some((applied_key, value)) => vetted.push(ProposedChange {
                    key: applied_key.clone(),
                    // مقدارِ **نرمال‌شدهٔ** نگهبان و نه متنِ خامِ مدل: «on» در کارت
                    // باید همان چیزی باشد که واقعاً نوشته می‌شود.
                    value: value.clone(),
                    before,
                    why: change.why.clone(),
                }),
                None => {
                    let refusal = if !outcome.redundant.is_empty() {
                        Refusal {
                            key: key.clone(),
                            proposed: change.value.clone(),
                            problem: Problem::AlreadySet,
                        }
                    } else {
                        let reason = outcome
                            .rejected
                            .first()
                            .map(|(_, reason)| reason.clone())
                            .unwrap_or_else(|| "no change".to_string());
                        Refusal::from_rejection(&key, &change.value, &reason)
                    };
                    DiagnosticsLog::i(
                        "ai",
                        &format!(
                            "chat proposed \"{}\" = \"{}\" — not offered to the user: {:?}",
                            change.key, change.value, refusal.problem,
                        ),
                    );
                    refusals.push(refusal);
                }
            }
        }
        (visible, vetted, refusals)
    }

    /// تغییراتِ یک حباب را روی پروفایل می‌نشاند و پروفایلِ تازه را برمی‌گرداند.
    ///
    /// **خودش ذخیره نمی‌کند** — به همان دلیلِ [`AiSession::advise`]: نوشتن مالِ
    /// کنترلر است. اینجا فقط پچ ساخته و از نگهبان رد می‌شود؛ `main.rs` نتیجه را
    /// از همان یک دروازهٔ `set_profile` عبور می‌دهد و بعد حباب را «اعمال‌شده»
    /// علامت می‌زند.
    ///
    /// نگهبان **دوباره** اجرا می‌شود و به اعتبارسنجیِ لحظهٔ رسیدنِ پاسخ اعتماد
    /// نمی‌شود: بین آن لحظه و زدنِ دکمه، کاربر می‌توانسته خودش تنظیمات را عوض
    /// کند، و یک اعتبارسنجیِ کهنه دقیقاً همان جایی است که یک مقدارِ نامعتبر
    /// می‌نشیند.
    pub fn changes_for(
        &self,
        profile: &ConnectionProfile,
        message_id: u64,
    ) -> Result<(ConnectionProfile, Vec<(String, String)>), String> {
        let changes = {
            let inner = self.inner.lock().unwrap();
            let message = inner
                .messages
                .iter()
                .find(|m| m.id == message_id)
                .ok_or("That message is no longer in the conversation.")?;
            if message.applied {
                return Err("Those changes are already applied.".into());
            }
            if message.changes.is_empty() {
                return Err("That message does not propose any settings.".into());
            }
            message.changes.clone()
        };

        let mut patch = serde_json::Map::new();
        for change in &changes {
            patch.insert(change.key.clone(), Value::String(change.value.clone()));
        }
        let mut patched = profile.clone();
        let outcome = ai_patch::apply_chat(&mut patched, &Value::Object(patch));
        if !outcome.rejected.is_empty() {
            DiagnosticsLog::w(
                "ai",
                &format!(
                    "applying chat changes: {} refused at the second gate",
                    outcome.rejected.len()
                ),
            );
        }
        if outcome.applied.is_empty() {
            // یعنی همه‌شان از قبل همان‌طور بوده‌اند یا کاربر خودش عوضشان کرده.
            // حباب همچنان «اعمال‌شده» علامت می‌خورد، چون از دید کاربر نتیجه
            // همان است: تنظیمات همان چیزی است که پیشنهاد شده بود.
            return Ok((patched, Vec::new()));
        }
        DiagnosticsLog::i(
            "ai",
            &format!("chat applied {} setting(s)", outcome.applied.len()),
        );
        Ok((patched, outcome.applied))
    }

    /// حباب را «اعمال‌شده» علامت می‌زند، تا کارت به‌جای دکمه، تیک نشان دهد.
    pub fn mark_applied(&self, message_id: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(message) = inner.messages.iter_mut().find(|m| m.id == message_id) {
            message.applied = true;
        }
    }

    /// مشاورِ ضد‌DPI: لاگ را می‌خواند، یک پچ پیشنهاد می‌گیرد، از نگهبان ردش
    /// می‌کند، و پروفایلِ نتیجه را برمی‌گرداند تا فراخوان ذخیره‌اش کند.
    ///
    /// **خودش ذخیره نمی‌کند**: نوشتنِ پروفایل مالِ کنترلر است و از این‌جا
    /// دست‌درازی به آن یعنی یک نوشتن که قفل کنترلر را نمی‌گیرد.
    pub fn advise(
        &self,
        profile: &ConnectionProfile,
        lang_code: &str,
    ) -> Result<(ConnectionProfile, AdvisorResult), String> {
        let (key, model) = self.begin()?;
        let port = match ai_gate::socks_port_for(profile){Ok(port)=>port,Err(e)=>{self.finish(None);return Err(e);}};

        // پاک‌سازی **پیش از** ساختنِ پرامپت انجام می‌شود، نه بعدش: هیچ مسیری
        // نباید وجود داشته باشد که لاگ خام حتی وارد یک رشته شود که به شبکه برود.
        let digest = ai_redaction::digest(
            &DiagnosticsLog::export_text(),
            &key,
            ai_redaction::DEFAULT_MAX_LINES,
        );
        // تنظیماتِ فرستاده‌شده هم فیلتر می‌شوند: پروفایلِ کامل شامل
        // `accessSecret`/`accessToken` است و مدل هرگز نباید یک اعتبارنامه ببیند.
        let settings_json = redacted_settings(profile);

        // ۱.۴.۰-r4: snapshotِ حاشیه‌دار تا گام‌های GROUNDING چیزی برای مقایسه داشته باشند.
        let user_text = ai_prompts::advisor_user(
            &ai_patch::advisor_snapshot(profile),
            &settings_json,
            &digest,
        );
        let system = ai_prompts::advisor_system(Lang::from_code(lang_code));
        let turns = [GeminiTurn {
            from_user: true,
            text: user_text.clone(),
        }];
        let reply = match ai_client::generate(
            &key,
            port,
            &model,
            &system,
            &turns,
            ADVISOR_TEMPERATURE,
            ADVISOR_MAX_TOKENS,
            true,
        ) {
            Ok(text) => text,
            Err(error) => {
                let message = error.message.clone();
                self.finish(Some(error));
                return Err(message);
            }
        };

        let (object, parsed) = match parse_advisor_reply(&reply) {
            Ok(pair) => pair,
            Err(message) => {
                self.finish(Some(AiError {
                    message: message.into(),
                    kind: AiErrorKind::Protocol,
                    retry_after_seconds: None,
                }));
                return Err(message.into());
            }
        };

        let (mut reason, mut patched, mut outcome) = judge_advice(profile, &parsed);

        // ۱.۴.۰-r4: همان دورِ «بررسی و بازنویسی» چت. پیشنهادی که مقدارِ فعلیِ
        // کاربر را تکرار کند (یا مقدارِ نامعتبر بدهد) یک بار با مقادیرِ واقعی به
        // مدل برمی‌گردد؛ پاسخِ اصلاح‌شده اگر خوانا بود جای اولی را می‌گیرد.
        let refusals = advisor_refusals(&parsed, &outcome);
        if let Some(feedback) = ai_patch::verification_feedback(profile, &refusals, Scope::Advisor)
        {
            DiagnosticsLog::i(
                "ai",
                &format!(
                    "advisor: {} proposal(s) failed verification; re-asking",
                    refusals.len()
                ),
            );
            let revision_turns = [
                GeminiTurn {
                    from_user: true,
                    text: user_text,
                },
                GeminiTurn {
                    from_user: false,
                    text: object,
                },
                GeminiTurn {
                    from_user: true,
                    text: ai_prompts::advisor_revision(&feedback),
                },
            ];
            match ai_client::generate(
                &key,
                port,
                &model,
                &system,
                &revision_turns,
                ADVISOR_TEMPERATURE,
                ADVISOR_MAX_TOKENS,
                true,
            ) {
                Ok(revised) => match parse_advisor_reply(&revised) {
                    Ok((_, reparsed)) => {
                        let judged = judge_advice(profile, &reparsed);
                        reason = judged.0;
                        patched = judged.1;
                        outcome = judged.2;
                    }
                    Err(_) => DiagnosticsLog::w(
                        "ai",
                        "advisor: revised answer was unreadable; keeping the verified original",
                    ),
                },
                Err(error) => DiagnosticsLog::w(
                    "ai",
                    &format!(
                        "advisor: revision round failed ({:?}); keeping the verified original",
                        error.kind
                    ),
                ),
            }
        }

        let result = AdvisorResult {
            reason,
            applied: outcome.applied,
            rejected: outcome.rejected,
        };
        DiagnosticsLog::i(
            "ai",
            &format!(
                "advisor: {} change(s) applied, {} refused",
                result.applied.len(),
                result.rejected.len()
            ),
        );
        let mut inner = self.inner.lock().unwrap();
        inner.advisor = Some(result.clone());
        inner.busy = false;
        drop(inner);
        Ok((patched, result))
    }
}

/// پروفایل را برای پرامپت سریالایز می‌کند، بدون هر چیزی که راز است.
///
/// روی نمایشِ JSONِ خودِ پروفایل کار می‌کند و یک ساختارِ دوم نمی‌سازد، به همان
/// دلیلِ [`crate::ai_patch::apply`]: `serde` تنها مرجعِ نام‌ها بماند.
/// وضعیتِ اتصال، به زبانی که مدل می‌فهمد (پورت از `statusForPrompt` موبایل).
pub fn status_for_prompt(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Connected => "connected",
        ConnectionState::Reconnecting => "reconnecting",
        ConnectionState::Verifying => "tunnel up, end-to-end self-test still running",
        ConnectionState::StartingEngine | ConnectionState::Connecting => "connecting",
        ConnectionState::Disconnecting => "disconnecting",
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::Failed => "error",
    }
}

/// پاسخِ مشاور را به `(متنِ JSON، مقدارِ پارس‌شده)` تبدیل می‌کند.
fn parse_advisor_reply(reply: &str) -> Result<(String, Value), &'static str> {
    let object = ai_prompts::extract_json_object(reply)
        .ok_or("The advisor's answer was not in the expected form.")?;
    let parsed: Value =
        serde_json::from_str(&object).map_err(|_| "The advisor's answer was not valid JSON.")?;
    Ok((object, parsed))
}

/// پچِ مشاور را روی یک کپی از پروفایل داوری می‌کند: `(reason، پروفایلِ نتیجه، نتیجه)`.
fn judge_advice(
    profile: &ConnectionProfile,
    parsed: &Value,
) -> (String, ConnectionProfile, PatchOutcome) {
    let reason = parsed
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let mut patched = profile.clone();
    let outcome: PatchOutcome = match parsed.get("patch") {
        Some(patch) => ai_patch::apply(&mut patched, patch),
        // پچِ خالی پاسخِ **درست** است وقتی لاگ یک اتصال سالم را نشان می‌دهد.
        None => PatchOutcome::default(),
    };
    (reason, patched, outcome)
}

/// ردشده‌ها و تکراری‌های یک پچِ مشاور، با مقداری که مدل خواسته بود.
fn advisor_refusals(parsed: &Value, outcome: &PatchOutcome) -> Vec<Refusal> {
    let proposed = |key: &str| -> String {
        match parsed.get("patch").and_then(|p| p.get(key)) {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        }
    };
    let mut out: Vec<Refusal> = outcome
        .redundant
        .iter()
        .map(|(key, _)| Refusal {
            key: key.clone(),
            proposed: proposed(key),
            problem: Problem::AlreadySet,
        })
        .collect();
    out.extend(
        outcome
            .rejected
            .iter()
            .filter(|(key, _)| !key.starts_with('<'))
            .map(|(key, reason)| Refusal::from_rejection(key, &proposed(key), reason)),
    );
    out
}

fn redacted_settings(profile: &ConnectionProfile) -> String {
    let mut value = match serde_json::to_value(profile) {
        Ok(v) => v,
        Err(_) => return "{}".to_string(),
    };
    if let Some(object) = value.as_object_mut() {
        for secret in ["accessSecret", "accessToken"] {
            object.remove(secret);
        }
        // فهرست فرآیندهای split هم می‌رود: نامِ برنامه‌های نصب‌شدهٔ کاربر برای
        // تنظیم ضد‌DPI بی‌ربط است و در همان حال یک نمای دقیق از این ماشین است.
        object.remove("splitApps");
        // >>> AETHER-APP-PATCH security-audit-1.3.0 (S-03)
        // Upstream URL may embed user:pass; Zero Trust identity, private bridge
        // lines and routing lists identify the user. Presence only, never values.
        for key in [
            "upstream",
            "team",
            "accessEmail",
            "accessId",
            "torBridgeLines",
            "routeDirect",
            "routeBlock",
            "manualPeer",
        ] {
            if let Some(v) = object.get_mut(key) {
                let set = match v {
                    serde_json::Value::String(s) => !s.trim().is_empty(),
                    serde_json::Value::Array(a) => !a.is_empty(),
                    _ => false,
                };
                *v = serde_json::Value::String(if set { "(set)".into() } else { "(none)".into() });
            }
        }
        // <<< AETHER-APP-PATCH security-audit-1.3.0
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_sent_to_the_model_carry_no_credentials() {
        let mut profile = ConnectionProfile::default();
        profile.access_secret = "super-secret".into();
        profile.access_token = "tok-123".into();
        profile.split_apps = vec!["chrome.exe".into()];
        let json = redacted_settings(&profile);
        assert!(!json.contains("super-secret"), "{json}");
        assert!(!json.contains("tok-123"), "{json}");
        assert!(!json.contains("chrome.exe"), "{json}");
        // ولی چیزهایی که مشاور واقعاً لازم دارد باید باشند.
        assert!(json.contains("\"mtu\""), "{json}");
        assert!(json.contains("\"noize\""), "{json}");
    }

    // ---- نیمه‌های همگام: اثباتِ رفعِ «پیام بعد از پاسخ ظاهر می‌شد» ---------

    /// فهرست نوبت‌ها، برای تست‌ها. `AiSnapshot` کامل به یک `ConnectionState`
    /// نیاز دارد که این تست‌ها کاری با آن ندارند.
    fn messages_of(ai: &AiSession) -> Vec<ChatMessage> {
        ai.inner.lock().unwrap().messages.clone()
    }

    fn session() -> AiSession {
        let dir = std::env::temp_dir().join(format!("aether-ai-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        AiSession::new(&dir, Arc::new(PrefsStore::new(&dir)))
    }

    #[test]
    fn the_user_bubble_exists_the_moment_the_call_returns() {
        // قلبِ اشکالِ ۳: این تابع **نباید** به شبکه دست بزند و باید پیش از هر
        // کارِ ناهمگامی حباب را نشانده باشد. اگر روزی کسی نشاندنِ حباب را به
        // `dispatch` برگرداند، این تست می‌شکند — و همان اشکال برمی‌گشت.
        let ai = session();
        assert!(messages_of(&ai).is_empty());

        let prompt = ai
            .append_user_message("  why is my connection slow?  ")
            .unwrap();
        assert_eq!(
            prompt, "why is my connection slow?",
            "the prompt must come back trimmed"
        );

        let messages = messages_of(&ai);
        assert_eq!(messages.len(), 1, "the bubble must be there already");
        assert!(messages[0].from_user);
        assert_eq!(messages[0].text, "why is my connection slow?");
        assert!(!messages[0].failed);
        assert!(messages[0].changes.is_empty());
    }

    #[test]
    fn an_empty_message_seats_no_bubble() {
        let ai = session();
        assert!(ai.append_user_message("   ").is_err());
        assert!(
            messages_of(&ai).is_empty(),
            "an empty send must leave no trace"
        );
    }

    #[test]
    fn taking_a_failed_prompt_removes_the_red_bubble_and_returns_the_question() {
        let ai = session();
        ai.append_user_message("make it harder to detect").unwrap();
        // یک حبابِ شکست دستی، همان‌طور که `dispatch` می‌سازد.
        let failure_id = {
            let mut inner = ai.inner.lock().unwrap();
            let id = inner.take_id();
            inner.messages.push(ChatMessage::failure(
                id,
                "Google failed".into(),
                AiErrorKind::ServerError,
                "make it harder to detect",
            ));
            id
        };

        let prompt = ai.take_failed_prompt(failure_id).unwrap();
        assert_eq!(prompt, "make it harder to detect");
        let messages = messages_of(&ai);
        assert_eq!(messages.len(), 1, "the red bubble must be gone already");
        assert!(messages[0].from_user);
        // و دو بار گرفتنِ همان شکست ممکن نیست.
        assert!(ai.take_failed_prompt(failure_id).is_err());
    }

    #[test]
    fn only_a_failed_bubble_can_be_retried() {
        let ai = session();
        ai.append_user_message("hello").unwrap();
        let id = messages_of(&ai)[0].id;
        assert!(
            ai.take_failed_prompt(id).is_err(),
            "a user turn is not a failure"
        );
    }

    // ---- اعتبارسنجیِ پیشنهادها پیش از رسیدن به رابط کاربری ----------------

    #[test]
    fn a_reply_without_a_block_proposes_nothing() {
        let ai = session();
        let (visible, changes) =
            ai.vet_changes(&ConnectionProfile::default(), "MTU is packet size.");
        assert_eq!(visible, "MTU is packet size.");
        assert!(changes.is_empty());
    }

    #[test]
    fn a_vetted_change_carries_the_old_value_and_the_normalised_new_one() {
        let ai = session();
        let profile = ConnectionProfile::default();
        let reply = format!(
            "Lowering the MTU.\n```{}\n{{\"changes\":[{{\"key\":\"mtu\",\"value\":1380,\"why\":\"timeouts\"}},\
             {{\"key\":\"fragment\",\"value\":\"yes\",\"why\":\"splits the hello\"}}]}}\n```",
            ai_prompts::APPLY_FENCE
        );
        let (visible, changes) = ai.vet_changes(&profile, &reply);
        assert_eq!(visible, "Lowering the MTU.");
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].key, "mtu");
        assert_eq!(changes[0].before, crate::profile::DEFAULT_MTU.to_string());
        assert_eq!(changes[0].value, "1380");
        assert_eq!(changes[0].why, "timeouts");
        // «yes» به همان چیزی تبدیل می‌شود که واقعاً نوشته می‌شود.
        assert_eq!(changes[1].value, "on");
    }

    #[test]
    fn a_refused_key_never_becomes_a_button() {
        // یک پیشنهادِ مخلوط: یکی مجاز، یکی از آن‌هایی که فهرستِ چت حذف کرده.
        let ai = session();
        let reply = format!(
            "Try this.\n```{}\n{{\"changes\":[{{\"key\":\"upstream\",\"value\":\"socks5://10.0.0.9:1080\"}},\
             {{\"key\":\"noize\",\"value\":\"GFW\"}}]}}\n```",
            ai_prompts::APPLY_FENCE
        );
        let (_, changes) = ai.vet_changes(&ConnectionProfile::default(), &reply);
        assert_eq!(changes.len(), 1, "only the allowed one may reach the card");
        assert_eq!(changes[0].key, "noize");
    }

    #[test]
    fn applying_writes_only_what_the_card_showed() {
        let ai = session();
        let profile = ConnectionProfile::default();
        let reply = format!(
            "Ok.\n```{}\n{{\"changes\":[{{\"key\":\"mtu\",\"value\":\"1380\"}}]}}\n```",
            ai_prompts::APPLY_FENCE
        );
        let (visible, changes) = ai.vet_changes(&profile, &reply);
        let id = {
            let mut inner = ai.inner.lock().unwrap();
            let id = inner.take_id();
            inner
                .messages
                .push(ChatMessage::model(id, visible, changes));
            id
        };

        let (patched, applied) = ai.changes_for(&profile, id).unwrap();
        assert_eq!(patched.mtu, 1380);
        assert_eq!(applied.len(), 1);
        // پیش از علامت‌خوردن، دوباره‌اعمال ممکن است؛ پس از آن، نه. این ترتیب مهم
        // است: `main.rs` فقط پس از یک نوشتنِ موفق علامت می‌زند.
        assert!(ai.changes_for(&profile, id).is_ok());
        ai.mark_applied(id);
        assert!(ai.changes_for(&profile, id).is_err());
    }

    #[test]
    fn a_redundant_or_duplicate_proposal_is_refused_with_a_reason() {
        let ai = session();
        let profile = ConnectionProfile::default();
        let reply = format!(
            "Set the MTU.\n```{}\n{{\"changes\":[{{\"key\":\"mtu\",\"value\":\"{}\"}},\
             {{\"key\":\"fragment\",\"value\":\"true\"}},{{\"key\":\"fragment\",\"value\":\"false\"}},\
             {{\"key\":\"upstream\",\"value\":\"socks5://1.2.3.4:1\"}}]}}\n```",
            ai_prompts::APPLY_FENCE,
            crate::profile::DEFAULT_MTU
        );
        let (_, changes, refusals) = ai.vet_changes_verified(&profile, &reply);
        assert_eq!(changes.len(), 1, "only the real change becomes a button");
        assert_eq!(changes[0].key, "fragment");
        let problems: Vec<_> = refusals
            .iter()
            .map(|r| (r.key.as_str(), r.problem.clone()))
            .collect();
        assert!(
            problems.contains(&("mtu", Problem::AlreadySet)),
            "{problems:?}"
        );
        assert!(
            problems.contains(&("fragment", Problem::Duplicate)),
            "{problems:?}"
        );
        assert!(
            problems.contains(&("upstream", Problem::NotChangeable)),
            "{problems:?}"
        );
        let feedback = ai_patch::verification_feedback(&profile, &refusals, Scope::Chat).unwrap();
        assert!(feedback.contains("REDUNDANT"), "{feedback}");
    }

    #[test]
    fn the_advisor_reports_a_value_the_user_already_has() {
        let profile = ConnectionProfile::default();
        let parsed = serde_json::json!({
            "reason": "x",
            "patch": { "mtu": crate::profile::DEFAULT_MTU, "fragment": true, "leakGuard": false }
        });
        let (reason, patched, outcome) = judge_advice(&profile, &parsed);
        assert_eq!(reason, "x");
        assert!(patched.fragment);
        let refusals = advisor_refusals(&parsed, &outcome);
        assert!(refusals
            .iter()
            .any(|r| r.key == "mtu" && r.problem == Problem::AlreadySet));
        assert!(refusals
            .iter()
            .any(|r| r.key == "leakGuard" && r.problem == Problem::NotChangeable));
        assert!(!refusals.iter().any(|r| r.key == "fragment"));
    }

    #[test]
    fn the_status_line_covers_every_state() {
        assert_eq!(status_for_prompt(ConnectionState::Connected), "connected");
        assert_eq!(
            status_for_prompt(ConnectionState::Disconnected),
            "disconnected"
        );
        assert_eq!(
            status_for_prompt(ConnectionState::StartingEngine),
            "connecting"
        );
    }

    #[test]
    fn a_message_that_proposes_nothing_cannot_be_applied() {
        let ai = session();
        ai.append_user_message("hello").unwrap();
        let id = messages_of(&ai)[0].id;
        assert!(ai.changes_for(&ConnectionProfile::default(), id).is_err());
        assert!(ai
            .changes_for(&ConnectionProfile::default(), 9_999)
            .is_err());
    }
}
