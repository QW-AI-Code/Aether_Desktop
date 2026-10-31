//! ۱.۴.۰ (پورت از `ZeroTrustSignIn.kt`، `TeamSignInRecord.kt`،
//! `TeamSignInHandoff.kt` و `TeamMembership.kt` موبایل) — ورودِ Zero Trust
//! **پیش از اتصال**.
//!
//! کاربر در تنظیمات نام تیم و ایمیل را می‌دهد، «ارسال کد» را می‌زند، کدِ ایمیل
//! را وارد می‌کند و یک JWTِ ثبت‌نام می‌گیرد. آن JWT مهرشده با DPAPI در
//! [`SecretStore`] می‌ماند و در اتصالِ بعدی به‌صورت `AETHER_ACCESS_TOKEN` به
//! موتور داده می‌شود؛ موتور (`zerotrust.rs::sign_in`) توکن را بر ایمیل مقدم
//! می‌دارد، پس دیگر هیچ کدی وسطِ اتصال پرسیده نمی‌شود.
//!
//! # بازنویسی در این مرحله
//!
//! نسخهٔ قبلی به `HttpClient`، `regex`، `urlencoding` و `async` تکیه داشت که هیچ‌کدام
//! در این پروژه نیستند (کامپایل نمی‌شد). این نسخه همگام است، فقط
//! [`crate::mini_https::exchange`] را صدا می‌زند، و فرمانِ Tauriاش آن را روی
//! یک ترد کارگر اجرا می‌کند تا UI هرگز قفل نشود.
//!
//! # امنیت
//!
//!  * فقط HTTPS، فقط میزبانِ تیم برای کوکی‌ها، حداکثر ۱۰ ریدایرکت.
//!  * توکن هرگز در لاگ نمی‌آید (`Debug`ِ رکورد فقط طولش را می‌گوید).
//!  * رکوردِ تیم/ایمیلِ دیگر نگه داشته می‌شود ولی هرگز فرستاده نمی‌شود.

use crate::log::DiagnosticsLog;
use crate::mini_https::{self, Dial};
use crate::secret_store::SecretStore;
use crate::zt_web;
use parking_lot::Mutex;
use serde::Serialize;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TAG: &str = "zerotrust";
const MAX_REDIRECTS: usize = 10;
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_BODY: usize = 512 * 1024;
const USER_AGENT: &str = "WARP for Windows";
/// نام کلید در انبارِ رازِ DPAPI.
pub const SIGNIN_KEY: &str = "ztSignIn";

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- HTTP با ریدایرکت و کوکی‌جار -------------------------------------------

#[derive(Debug, Clone)]
struct Request {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    form: Option<Vec<(String, String)>>,
}

struct Followed {
    code: u16,
    url: String,
    body: String,
    /// JWT از یک ریدایرکتِ غیرِ HTTPS (`com.cloudflare.warp://…?token=`).
    app_token: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct CookieJar {
    host: String,
    cookies: Vec<(String, String)>,
}

impl CookieJar {
    fn new(host: &str) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            cookies: Vec::new(),
        }
    }

    fn same_host(&self, url: &str) -> bool {
        mini_https::split_https_url(url)
            .map(|(h, _, _)| h == self.host)
            .unwrap_or(false)
    }

    fn remember(&mut self, url: &str, set_cookies: &[&str]) {
        if !self.same_host(url) {
            return;
        }
        for header in set_cookies {
            let mut parts = header.split(';');
            let pair = parts.next().unwrap_or("").trim();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.is_empty() {
                continue;
            }
            let expired = parts.any(|a| {
                let a = a.trim().to_ascii_lowercase();
                a.strip_prefix("max-age=")
                    .map(|v| v.trim().parse::<i64>().unwrap_or(1) <= 0)
                    .unwrap_or(false)
            });
            self.cookies.retain(|(k, _)| k != &name);
            if !expired && !value.is_empty() {
                self.cookies.push((name, value));
            }
        }
    }

    fn header(&self, url: &str) -> Option<String> {
        if !self.same_host(url) || self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// نشانیِ `Location` نسبت به `base`.
fn resolve(base: &str, location: &str) -> Option<String> {
    let loc = location.trim();
    if loc.contains("://") {
        return Some(loc.to_string());
    }
    let (host, port, path) = mini_https::split_https_url(base)?;
    let origin = if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    };
    if loc.starts_with("//") {
        return Some(format!("https:{loc}"));
    }
    if loc.starts_with('/') {
        return Some(format!("{origin}{loc}"));
    }
    let path_only = path.split('?').next().unwrap_or("/");
    let dir = match path_only.rfind('/') {
        Some(i) => &path_only[..=i],
        None => "/",
    };
    Some(format!("{origin}{dir}{loc}"))
}

fn follow(first: Request, jar: &mut CookieJar) -> Result<Followed, Failure> {
    let mut request = first;
    for _ in 0..=MAX_REDIRECTS {
        let mut headers: Vec<(&str, String)> = vec![
            ("User-Agent", USER_AGENT.to_string()),
            (
                "Accept",
                "text/html,application/xhtml+xml,*/*;q=0.8".to_string(),
            ),
        ];
        for (k, v) in &request.headers {
            headers.push((k.as_str(), v.clone()));
        }
        if let Some(c) = jar.header(&request.url) {
            headers.push(("Cookie", c));
        }
        let form: Option<Vec<(&str, String)>> = request
            .form
            .as_ref()
            .map(|f| f.iter().map(|(k, v)| (k.as_str(), v.clone())).collect());
        let response = mini_https::exchange(
            Dial::Direct,
            &request.method,
            &request.url,
            &headers,
            form.as_deref(),
            TIMEOUT,
            MAX_BODY,
        )
        .map_err(|e| {
            let detail: String = e.to_string().chars().take(160).collect();
            DiagnosticsLog::w(
                TAG,
                &format!("Cloudflare Access could not be reached: {detail}"),
            );
            Failure::Network(detail)
        })?;
        jar.remember(&request.url, &response.all("set-cookie"));
        let location = response.header("location").map(str::to_string);
        let is_redirect = matches!(response.code, 301 | 302 | 303 | 307 | 308);
        let Some(location) = location.filter(|l| is_redirect && !l.trim().is_empty()) else {
            return Ok(Followed {
                code: response.code,
                url: request.url,
                body: response.text(),
                app_token: None,
            });
        };
        match resolve(&request.url, &location) {
            Some(next) if next.starts_with("https://") => {
                request = if matches!(response.code, 307 | 308) {
                    Request {
                        url: next,
                        ..request
                    }
                } else {
                    Request {
                        method: "GET".into(),
                        url: next,
                        headers: request.headers,
                        form: None,
                    }
                };
            }
            _ => {
                return Ok(Followed {
                    code: response.code,
                    url: request.url,
                    body: response.text(),
                    app_token: zt_web::extract_jwt_from_html(&location),
                })
            }
        }
    }
    Err(Failure::Network("too many redirects".into()))
}

// ---- جریانِ ورود ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    BadTeam,
    BadEmail,
    NoEmailCode,
    Refused(u16),
    NoNonce,
    NoSession,
    /// آزمایشِ توکنِ سرویس: سازمان توکنِ عضویتی نداد (کدِ HTTP پاسخ).
    NoToken(u16),
    Network(String),
}

impl Failure {
    /// پیامِ کاربر (انگلیسی؛ UI ترجمه‌اش را از i18n می‌گیرد).
    pub fn message(&self) -> String {
        match self {
            Failure::BadTeam => "That team name is not valid.".into(),
            Failure::BadEmail => "That e-mail address is not valid.".into(),
            Failure::NoEmailCode => {
                "This team does not offer sign-in with an e-mail code.".into()
            }
            Failure::Refused(code) => format!("Cloudflare refused the request (HTTP {code})."),
            Failure::NoNonce => "Cloudflare did not start a code session. Try again.".into(),
            Failure::NoSession => "Ask for a code first.".into(),
            Failure::NoToken(code) => format!(
                "Not accepted (HTTP {code}). Check the client ID and secret, and that the service token is allowed to enrol devices (Service Auth)."
            ),
            Failure::Network(d) => format!("Cloudflare Access could not be reached: {d}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub team: String,
    pub email: String,
    verify_url: String,
    nonce: String,
    jar: CookieJar,
}

pub enum CodeOutcome {
    Token(String),
    Rejected(u16),
}

fn post_email(
    verify_url: &str,
    email: &str,
    jar: &mut CookieJar,
) -> Result<Option<String>, Failure> {
    DiagnosticsLog::i(TAG, "Asking Cloudflare to e-mail a login code.");
    let sent = follow(
        Request {
            method: "POST".into(),
            url: verify_url.to_string(),
            headers: Vec::new(),
            form: Some(vec![
                ("email".into(), email.to_string()),
                ("client_id".into(), String::new()),
                ("connector_id".into(), String::new()),
                ("connector_type".into(), String::new()),
                ("redirect_url".into(), String::new()),
            ]),
        },
        jar,
    )?;
    if !(200..300).contains(&sent.code) {
        DiagnosticsLog::w(
            TAG,
            &format!(
                "Cloudflare refused to send a login code (status {}).",
                sent.code
            ),
        );
        return Err(Failure::Refused(sent.code));
    }
    Ok(zt_web::query_value(&sent.url, "nonce"))
}

pub fn request_code(raw_team: &str, raw_email: &str) -> Result<Session, Failure> {
    let team = zt_web::normalize_team(raw_team).ok_or(Failure::BadTeam)?;
    let email = raw_email.trim().to_string();
    if !zt_web::plausible_email(&email) {
        return Err(Failure::BadEmail);
    }
    let mut jar = CookieJar::new(&zt_web::team_host(&team));
    DiagnosticsLog::i(
        TAG,
        &format!("Opening the device enrolment page for team {team}."),
    );
    let landing = follow(
        Request {
            method: "GET".into(),
            url: zt_web::login_url(&team),
            headers: Vec::new(),
            form: None,
        },
        &mut jar,
    )?;
    if !(200..300).contains(&landing.code) {
        return Err(Failure::Refused(landing.code));
    }
    let verify_url = zt_web::extract_totp_form_action(&landing.body).ok_or(Failure::NoEmailCode)?;
    let nonce = post_email(&verify_url, &email, &mut jar)?
        .or_else(|| zt_web::query_value(&landing.url, "nonce"))
        .ok_or(Failure::NoNonce)?;
    Ok(Session {
        team,
        email,
        verify_url,
        nonce,
        jar,
    })
}

pub fn resend_code(session: &mut Session) -> Result<(), Failure> {
    let verify_url = session.verify_url.clone();
    let email = session.email.clone();
    if let Some(n) = post_email(&verify_url, &email, &mut session.jar)? {
        session.nonce = n;
    }
    Ok(())
}

pub fn submit_code(session: &mut Session, code: &str) -> Result<CodeOutcome, Failure> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return Ok(CodeOutcome::Rejected(0));
    }
    let r = follow(
        Request {
            method: "POST".into(),
            url: zt_web::callback_url(&session.team),
            headers: Vec::new(),
            form: Some(vec![
                ("code".into(), trimmed.to_string()),
                ("nonce".into(), session.nonce.clone()),
            ]),
        },
        &mut session.jar,
    )?;
    match r
        .app_token
        .or_else(|| zt_web::extract_jwt_from_html(&r.body))
    {
        Some(token) => {
            DiagnosticsLog::i(
                TAG,
                &format!("Signed in to team {} with the e-mail code.", session.team),
            );
            Ok(CodeOutcome::Token(token))
        }
        None => Ok(CodeOutcome::Rejected(r.code)),
    }
}

// ---- TeamSignInRecord.kt ----------------------------------------------------

const RECORD_VERSION: &str = "zt-signin-v1";

#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    pub team: String,
    pub email: String,
    token: String,
    pub signed_in_at: i64,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Record(team={}, email={}, token=<{} chars>, signed_in_at={})",
            self.team,
            self.email,
            self.token.len(),
            self.signed_in_at
        )
    }
}

impl Record {
    pub fn of(raw_team: &str, email: &str, token: &str, now: i64) -> Option<Self> {
        let team = zt_web::normalize_team(raw_team)?;
        let email = email.trim();
        let token = token.trim();
        if email.is_empty() || token.is_empty() {
            return None;
        }
        if email.contains(['\n', '\r']) || token.contains(['\n', '\r']) {
            return None;
        }
        Some(Self {
            team,
            email: email.to_string(),
            token: token.to_string(),
            signed_in_at: now,
        })
    }

    pub fn encode(&self) -> String {
        [
            RECORD_VERSION,
            &self.team,
            &self.email,
            &self.signed_in_at.to_string(),
            &self.token,
        ]
        .join("\n")
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let lines: Vec<&str> = raw.split('\n').collect();
        if lines.len() != 5 || lines[0] != RECORD_VERSION {
            return None;
        }
        let at = lines[3].parse::<i64>().ok()?;
        Self::of(lines[1], lines[2], lines[4], at).filter(|r| r.team == lines[1])
    }

    pub fn matches(&self, raw_team: &str, raw_email: &str) -> bool {
        match zt_web::normalize_team(raw_team) {
            Some(team) => team == self.team && raw_email.trim().eq_ignore_ascii_case(&self.email),
            None => false,
        }
    }

    /// ثانیه‌های باقی‌مانده تا `exp`؛ `None` اگر توکن تاریخی ندارد.
    pub fn seconds_left(&self, now: i64) -> Option<i64> {
        zt_web::expiry_seconds(&self.token).map(|exp| exp - now)
    }

    pub fn verdict(&self, now: i64) -> zt_web::Verdict {
        zt_web::inspect(&self.token, now)
    }

    pub fn usable_token(&self, raw_team: &str, raw_email: &str, now: i64) -> Option<String> {
        if !self.matches(raw_team, raw_email) {
            return None;
        }
        matches!(self.verdict(now), zt_web::Verdict::Usable(_)).then(|| self.token.clone())
    }
}

// ---- TeamMembership.kt ------------------------------------------------------

/// آیا موتور هویتی برای این تیم دارد؟ (`aether-team-<team>.toml` در هر یک از
/// پوشه‌ها، مهرشده یا نه.)
pub fn is_enrolled(dirs: &[&Path], team: &str) -> bool {
    if team.is_empty() {
        return false;
    }
    let base = format!("aether-team-{team}.toml");
    dirs.iter()
        .any(|d| d.join(&base).is_file() || d.join(format!("{base}.sealed")).is_file())
}

/// `aether-team-<team>[-secondary][-lastconn].toml[.corrupt][.sealed]` — همهٔ
/// نام‌هایی که هسته (و مهرِ DPAPI این برنامه) برای عضویتِ یک تیم می‌سازد، و
/// هیچ چیزِ دیگر. نام تیم دقیق مقایسه می‌شود، پس «acme» هرگز فایل‌های تیمِ
/// «acme-eu» را نمی‌گیرد. (`TeamMembership.patternFor` موبایل.)
pub fn is_membership_file(name: &str, team: &str) -> bool {
    if team.is_empty() {
        return false;
    }
    let Some(rest) = name
        .strip_prefix("aether-team-")
        .and_then(|r| r.strip_prefix(team))
    else {
        return false;
    };
    let rest = rest.strip_prefix("-secondary").unwrap_or(rest);
    let rest = rest.strip_prefix("-lastconn").unwrap_or(rest);
    let Some(rest) = rest.strip_prefix(".toml") else {
        return false;
    };
    let rest = rest.strip_prefix(".corrupt").unwrap_or(rest);
    let rest = rest.strip_prefix(".sealed").unwrap_or(rest);
    rest.is_empty()
}

/// فایل‌های عضویتِ `team` در همهٔ پوشه‌ها.
pub fn membership_files(dirs: &[&Path], team: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let named = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| is_membership_file(n, team));
            if named && path.is_file() {
                out.push(path);
            }
        }
    }
    out
}

/// رونویسی با صفر و بعد حذف — همان `EncryptedLogFile.shred` موبایل.
fn shred(path: &Path) {
    use std::io::Write;
    if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 8192];
            let mut left = len;
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

/// عضویتِ همین دستگاه در `team` پاک می‌شود؛ اتصالِ بعدی دوباره عضو می‌شود.
/// شمارِ فایل‌های حذف‌شده برمی‌گردد. WARPِ شخصی و تیم‌های دیگر دست نمی‌خورند.
pub fn forget_membership(dirs: &[&Path], team: &str) -> usize {
    let mut removed = 0;
    for file in membership_files(dirs, team) {
        shred(&file);
        if !file.exists() {
            removed += 1;
        }
    }
    DiagnosticsLog::i(
        TAG,
        &format!("Removed this device's enrolment in team {team} ({removed} file(s)); the next connect enrols again."),
    );
    removed
}

/// آزمایشِ توکنِ سرویس — دقیقاً همان مبادله‌ای که موتور هنگامِ اتصال می‌کند
/// (`fetch_token_with_service_token`): یک GET به `/warp` با دو سرآیندِ
/// `CF-Access-Client-*`، و توکن از کوکی یا HTML. هیچ چیز ذخیره نمی‌شود.
pub fn test_service_token(
    raw_team: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<(), Failure> {
    let team = zt_web::normalize_team(raw_team).ok_or(Failure::BadTeam)?;
    DiagnosticsLog::i(
        TAG,
        &format!("Testing the service token against team {team}."),
    );
    let headers: Vec<(&str, String)> = vec![
        ("User-Agent", USER_AGENT.to_string()),
        (
            "Accept",
            "text/html,application/xhtml+xml,*/*;q=0.8".to_string(),
        ),
        ("CF-Access-Client-Id", client_id.trim().to_string()),
        ("CF-Access-Client-Secret", client_secret.trim().to_string()),
    ];
    let response = mini_https::exchange(
        Dial::Direct,
        "GET",
        &zt_web::login_url(&team),
        &headers,
        None,
        TIMEOUT,
        MAX_BODY,
    )
    .map_err(|e| Failure::Network(e.to_string().chars().take(160).collect()))?;
    let token = response
        .all("set-cookie")
        .iter()
        .find_map(|c| zt_web::extract_jwt_from_cookie(c))
        .or_else(|| zt_web::extract_jwt_from_html(&response.text()));
    match token {
        Some(_) => {
            DiagnosticsLog::i(
                TAG,
                &format!("The service token was accepted by team {team}."),
            );
            Ok(())
        }
        None => {
            DiagnosticsLog::w(
                TAG,
                &format!(
                    "Team {team} did not issue an enrolment token for the service token (status {}).",
                    response.code
                ),
            );
            Err(Failure::NoToken(response.code))
        }
    }
}

// ---- TeamSignInHandoff.kt ---------------------------------------------------

pub enum Decision {
    NoSignIn,
    OtherProfile,
    AlreadyEnrolled,
    Unusable,
    Use(String),
}

// Never derive Debug for a credential-carrying decision (mobile Use.toString).
impl std::fmt::Debug for Decision {
 fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(match self{Self::NoSignIn=>"NoSignIn",Self::OtherProfile=>"OtherProfile",Self::AlreadyEnrolled=>"AlreadyEnrolled",Self::Unusable=>"Unusable",Self::Use(_)=>"Use([REDACTED])"})}
}

pub fn decide(
    record: Option<&Record>,
    raw_team: &str,
    raw_email: &str,
    enrolled: impl Fn(&str) -> bool,
    now: i64,
) -> Decision {
    let Some(record) = record else {
        return Decision::NoSignIn;
    };
    if !record.matches(raw_team, raw_email) {
        return Decision::OtherProfile;
    }
    if enrolled(&record.team) {
        return Decision::AlreadyEnrolled;
    }
    match record.usable_token(raw_team, raw_email, now) {
        Some(t) => Decision::Use(t),
        None => Decision::Unusable,
    }
}

// ---- ذخیره و حالتِ UI -------------------------------------------------------

pub fn load_record(data_dir: &Path) -> Option<Record> {
    Record::decode(&SecretStore::new(data_dir).read(SIGNIN_KEY))
}

pub fn save_record(data_dir: &Path, record: Option<&Record>) {
    let value = record.map(Record::encode).unwrap_or_default();
    if let Err(e) = SecretStore::new(data_dir).write(SIGNIN_KEY, &value) {
        DiagnosticsLog::w(TAG, &format!("Could not store the Zero Trust sign-in: {e}"));
    }
}

/// نشستِ «کد فرستاده شد، منتظرِ کد» بین دو فرمانِ UI.
static PENDING: OnceLock<Mutex<Option<Session>>> = OnceLock::new();

pub fn pending() -> &'static Mutex<Option<Session>> {
    PENDING.get_or_init(|| Mutex::new(None))
}

/// آنچه پنلِ Zero Trust نشان می‌دهد. هرگز خودِ توکن.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// "none" | "otherProfile" | "enrolled" | "expired" | "ready" | "codeSent"
    pub state: String,
    pub team: String,
    pub email: String,
    pub days_left: Option<i64>,
    /// ۱.۵.۰ — برای خطِ «تا … دیگر معتبر است» (دقیقه/ساعت/روز).
    pub seconds_left: Option<i64>,
    /// آیا اصلاً ورودی ذخیره شده (برای «ورود دوباره» و «فراموش کردن این ورود»).
    pub has_record: bool,
    pub error: Option<String>,
}

pub fn status(data_dir: &Path, engine_dirs: &[&Path], raw_team: &str, raw_email: &str) -> Status {
    let now = now_secs();
    let record = load_record(data_dir);
    let mut st = Status::default();
    if let Some(s) = pending().lock().as_ref() {
        if s.team == zt_web::normalize_team(raw_team).unwrap_or_default() {
            st.state = "codeSent".into();
            st.team = s.team.clone();
            st.email = s.email.clone();
            return st;
        }
    }
    if let Some(r) = &record {
        st.team = r.team.clone();
        st.email = r.email.clone();
        st.has_record = true;
        if let zt_web::Verdict::Usable(days) = r.verdict(now) {
            st.days_left = days;
            st.seconds_left = r.seconds_left(now);
        }
    }
    st.state = match decide(
        record.as_ref(),
        raw_team,
        raw_email,
        |t| is_enrolled(engine_dirs, t),
        now,
    ) {
        Decision::NoSignIn => "none",
        Decision::OtherProfile => "otherProfile",
        Decision::AlreadyEnrolled => "enrolled",
        Decision::Unusable => "expired",
        Decision::Use(_) => "ready",
    }
    .into();
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.c2lnbmF0dXJlLXNpZ25hdHVyZQ";

    #[test]
    fn record_round_trips_and_hides_the_token() {
        let r = Record::of("ACME", "me@x.io", JWT, 100).unwrap();
        assert_eq!(Record::decode(&r.encode()), Some(r.clone()));
        assert!(!format!("{r:?}").contains(JWT));
        assert!(Record::decode("zt-signin-v0\na\nb\n1\nt").is_none());
    }

    #[test]
    fn handoff_order_matches_mobile() {
        let r = Record::of("acme", "me@x.io", JWT, 0).unwrap();
        assert!(matches!(
            decide(None, "acme", "me@x.io", |_| false, 0),
            Decision::NoSignIn
        ));
        assert!(matches!(
            decide(Some(&r), "other", "me@x.io", |_| false, 0),
            Decision::OtherProfile
        ));
        assert!(matches!(
            decide(Some(&r), "acme", "ME@x.io", |_| true, 0),
            Decision::AlreadyEnrolled
        ));
        assert!(matches!(
            decide(Some(&r), "acme", "me@x.io", |_| false, 4_102_444_800),
            Decision::Unusable
        ));
        assert!(matches!(
            decide(Some(&r), "acme", "me@x.io", |_| false, 0),
            Decision::Use(_)
        ));
    }

    #[test]
    fn membership_files_are_exactly_the_teams_own() {
        for ok in [
            "aether-team-acme.toml",
            "aether-team-acme.toml.sealed",
            "aether-team-acme-secondary.toml",
            "aether-team-acme-lastconn.toml",
            "aether-team-acme-secondary-lastconn.toml",
            "aether-team-acme.toml.corrupt",
            "aether-team-acme.toml.corrupt.sealed",
        ] {
            assert!(is_membership_file(ok, "acme"), "{ok}");
        }
        for no in [
            "aether-team-acme-eu.toml",
            "aether-team-acme.tomlx",
            "aether-team-acme.toml.bak",
            "aether.toml",
            "aether-masque.toml",
            "aether-team-.toml",
            "xaether-team-acme.toml",
        ] {
            assert!(!is_membership_file(no, "acme"), "{no}");
        }
        assert!(!is_membership_file("aether-team-.toml", ""));
    }

    #[test]
    fn forgetting_a_membership_leaves_other_teams_and_warp_alone() {
        let dir = std::env::temp_dir().join(format!("aether-zt-forget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "aether-team-acme.toml",
            "aether-team-acme-lastconn.toml",
            "aether-team-acme-eu.toml",
            "aether.toml",
        ] {
            std::fs::write(dir.join(name), b"secret").unwrap();
        }
        let dirs = [dir.as_path()];
        assert!(is_enrolled(&dirs, "acme"));
        assert_eq!(forget_membership(&dirs, "acme"), 2);
        assert!(!is_enrolled(&dirs, "acme"));
        assert!(is_enrolled(&dirs, "acme-eu"));
        assert!(dir.join("aether.toml").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seconds_left_follow_the_tokens_exp() {
        let r = Record::of("acme", "me@x.io", JWT, 0).unwrap();
        assert_eq!(r.seconds_left(4_102_444_000), Some(800));
    }

    #[test]
    fn cookies_stay_on_the_team_host() {
        let mut jar = CookieJar::new("acme.cloudflareaccess.com");
        jar.remember(
            "https://acme.cloudflareaccess.com/warp",
            &["a=1; Path=/", "b=2"],
        );
        jar.remember("https://evil.example/", &["c=3"]);
        assert_eq!(
            jar.header("https://acme.cloudflareaccess.com/x").as_deref(),
            Some("a=1; b=2")
        );
        assert_eq!(jar.header("https://evil.example/"), None);
        jar.remember("https://acme.cloudflareaccess.com/", &["a=; Max-Age=0"]);
        assert_eq!(
            jar.header("https://acme.cloudflareaccess.com/").as_deref(),
            Some("b=2")
        );
    }

    #[test]
    fn locations_resolve() {
        let base = "https://acme.cloudflareaccess.com/cdn-cgi/access/login?x=1";
        assert_eq!(
            resolve(base, "/warp").as_deref(),
            Some("https://acme.cloudflareaccess.com/warp")
        );
        assert_eq!(
            resolve(base, "callback").as_deref(),
            Some("https://acme.cloudflareaccess.com/cdn-cgi/access/callback")
        );
        assert_eq!(
            resolve(base, "com.cloudflare.warp://x?token=1").as_deref(),
            Some("com.cloudflare.warp://x?token=1")
        );
    }
}

#[cfg(test)]mod handoff_privacy_tests{use super::*;#[test]fn decision_debug_never_reveals_token(){let debug=format!("{:?}",Decision::Use("sensitive-access-token".into()));assert_eq!(debug,"Use([REDACTED])");assert!(!debug.contains("sensitive-access-token"));}}
