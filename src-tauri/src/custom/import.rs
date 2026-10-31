//! ورودِ کانفیگ از متن، نشانیِ اشتراکِ https، یا فایل — پورتِ بخشِ ورودِ
//! `CustomConfigsPage.kt` نسخهٔ اندروید ۱.۵.۰، **بدونِ QR** (ویندوز دوربین و
//! اسکنرِ تصویر ندارد).
//!
//! - متن: یک یا چند لینک، JSONِ کاملِ Xray، بدنهٔ base64ِ یک اشتراک، یا npvt.
//! - نشانیِ اشتراک: اگر کلِ متن یک سطرِ `https://` باشد دانلود می‌شود (فقط
//!   https، حداکثر ۵ ریدایرکت، حداکثر ۲ مگابایت). وقتی تونل وصل است دانلود از
//!   داخلِ خودِ تونل می‌رود، وگرنه مستقیم.
//! - فایل: `.npvt`، `.txt`، `.json`، `.conf` تا ۲ مگابایت، UTF-8.

use super::npvt;
use super::parser::{self, ImportError};
use super::{now_millis, ConfigSource, CustomConfig};
use crate::mini_https::{self, Dial};
use std::path::Path;
use std::time::Duration;

pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const FILE_EXTENSIONS: [&str; 5] = ["npvt", "npvs", "txt", "json", "conf"];
const MAX_REDIRECTS: usize = 5;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20);

fn invalid<T>(msg: impl Into<String>) -> Result<T, ImportError> {
    Err(ImportError::Invalid(msg.into()))
}

/// اگر متن فقط یک نشانیِ https باشد، همان نشانی.
pub fn subscription_url(text: &str) -> Option<&str> {
    let t = text.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    if t.len() > 8 && t.get(..8).map(|s|s.eq_ignore_ascii_case("https://")).unwrap_or(false) {
        Some(t)
    } else {
        None
    }
}

fn resolve_location(base: &str, location: &str) -> Option<String> {
    let loc = location.trim();
    if loc.len() > 8 && loc.get(..8).map(|s|s.eq_ignore_ascii_case("https://")).unwrap_or(false) {
        return Some(loc.to_string());
    }
    if loc.to_ascii_lowercase().starts_with("http://") {
        return None; // هرگز به http پایین نمی‌آییم.
    }
    let (host, port, _) = mini_https::split_https_url(base)?;
    let authority = if port == 443 { host } else { format!("{host}:{port}") };
    if loc.starts_with('/') {
        Some(format!("https://{authority}{loc}"))
    } else {
        None
    }
}

/// بدنهٔ یک اشتراکِ https را (به‌صورت متن) دانلود می‌کند.
pub fn download(url: &str, dial: Dial) -> Result<String, ImportError> {
    let bytes = download_bytes(url, dial)?;
    String::from_utf8(bytes).map_err(|_| ImportError::Invalid("subscription is not UTF-8 text".into()))
}

/// آیا خطای انتقال از نوعِ «ویندوز اجازهٔ سوکت را نداد» (WSAEACCES، 10013) یا
/// مشابهِ آن است؟ این خطا از فایروال، آنتی‌ویروس یا یک VPN/پراکسیِ دیگر می‌آید و
/// به قاعدهٔ «به ازای هر برنامه» وابسته است؛ پس فرایندِ دیگری ممکن است اجازه داشته باشد.
pub fn is_access_denied(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("10013") || m.contains("forbidden by its access permissions") || m.contains("access is denied")
        || m.contains("permission denied")
}

/// دریافتِ باینری‌امن (فایل میزبانی‌شدهٔ NPVS هم باینری است). ابتدا سوکتِ خودِ
/// برنامه؛ اگر شبکه/فایروال آن را بست، به ابزارهای خودِ ویندوز (`curl.exe` و
/// سپس PowerShell با پراکسیِ سیستم) برمی‌گردد که هویتِ برنامهٔ دیگری دارند.
pub fn download_bytes(url: &str, dial: Dial) -> Result<Vec<u8>, ImportError> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let headers = [("User-Agent", "Aether".to_string()), ("Accept", "*/*".to_string())];
        let first = mini_https::exchange(dial, "GET", &current, &headers, None, DOWNLOAD_TIMEOUT, MAX_INPUT_BYTES);
        let resp = match first {
            Ok(r) => r,
            Err(e) => {
                let why = e.to_string();
                if is_access_denied(&why) {
                    crate::log::DiagnosticsLog::w("custom", "Windows refused this app's own socket (WSAEACCES) while downloading a subscription; retrying through the system downloader.");
                }
                // کل زنجیرهٔ ریدایرکت‌ها را ابزارِ سیستم از همین نقطه ادامه می‌دهد.
                return match system_fetch(&current) {
                    Ok(body) => Ok(body),
                    Err(sys) => {
                        let extra = if sys.is_empty() { String::new() } else { format!(" | {sys}") };
                        Err(ImportError::Invalid(format!("subscription download failed: {why}{extra}")))
                    }
                };
            }
        };
        match resp.code {
            200..=299 => {
                if resp.body.len() > MAX_INPUT_BYTES {
                    return invalid("subscription is larger than 2 MB");
                }
                return Ok(resp.body);
            }
            301 | 302 | 303 | 307 | 308 => {
                let Some(next) = resp.header("location").and_then(|l| resolve_location(&current, l))
                else {
                    return invalid("subscription redirected to a non-https address");
                };
                current = next;
            }
            code => return invalid(format!("subscription server answered HTTP {code}")),
        }
    }
    invalid("subscription redirected too many times")
}

/// پشتیبانِ دریافت از فرایندِ سیستمی. در غیرِ ویندوز همیشه خطا برمی‌گرداند.
#[cfg(not(windows))]
fn system_fetch(_url: &str) -> Result<Vec<u8>, String> {
    Err(String::new())
}

#[cfg(windows)]
fn system_fetch(url: &str) -> Result<Vec<u8>, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    if !url.to_ascii_lowercase().starts_with("https://") || url.contains(['\'', '"', '`', '\r', '\n', ' ']) {
        return Err(String::new());
    }
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let sys32 = Path::new(&sys).join("System32");
    // ۱) curl.exe (ویندوز ۱۰ به بعد در System32 است)
    let curl = sys32.join("curl.exe");
    if curl.is_file() {
        let out = Command::new(&curl)
            .args(["-sS", "-L", "--max-redirs", "5", "--proto", "=https", "--proto-redir", "=https",
                   "--ssl-no-revoke", "-m", "25", "--max-filesize", "2097152", "-A", "Aether",
                   "-w", "\n%{http_code}", url])
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                if let Some(pos) = o.stdout.iter().rposition(|b| *b == b'\n') {
                    let code = String::from_utf8_lossy(&o.stdout[pos + 1..]).trim().to_string();
                    if code.starts_with('2') {
                        return Ok(o.stdout[..pos].to_vec());
                    }
                    return Err(format!("system curl answered HTTP {code}"));
                }
            }
        }
    }
    // ۲) PowerShell با پراکسی/اعتبارِ سیستم
    let ps = sys32.join("WindowsPowerShell").join("v1.0").join("powershell.exe");
    if ps.is_file() {
        let script = format!(
            "$ErrorActionPreference='Stop';[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;\
             $p=[Net.WebRequest]::DefaultWebProxy;if($p){{$p.Credentials=[Net.CredentialCache]::DefaultCredentials}};\
             $r=Invoke-WebRequest -UseBasicParsing -Uri '{url}' -TimeoutSec 25 -UserAgent 'Aether';\
             [Convert]::ToBase64String($r.RawContentStream.ToArray())"
        );
        let out = Command::new(&ps)
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let b64 = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if let Some(body) = super::npvt::decode_base64(&b64) {
                    if body.len() <= MAX_INPUT_BYTES {
                        return Ok(body);
                    }
                }
            }
        }
    }
    Err("the system downloader also failed".into())
}

/// نویسه‌هایی که روی صفحه دیده نمی‌شوند ولی لینک را می‌شکنند — همان فهرستِ
/// `ConfigParser.cleanInput` اندروید: RLM/LRM و جداکننده‌های bidi که پیام‌رسان‌های
/// راست‌به‌چپ دورِ متنِ لاتین می‌گذارند، فاصلهٔ صفرعرض، word joiner، BOM و
/// soft hyphen. ZWNJ/ZWJ می‌مانند: بخشی از واژهٔ فارسی و ایموجیِ نامِ کانفیگ‌اند.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// متنِ چسبانده یا دانلودشده، پیش از هر پارسی: پایانِ خط یکسان، نویسه‌های
/// نامرئی حذف، فاصلهٔ نشکن ساده.
pub fn clean_input(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|c| !is_invisible(*c))
        .map(|c| if c == '\u{00A0}' || c == '\u{202F}' { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// متنِ چسبانده‌شده (یا نشانیِ اشتراک) را پارس می‌کند. اشتراک با همان `dial`
/// دانلود می‌شود: وقتی وصل است، از دلِ تونل (پورتِ خروجیِ نشست)، نه شبکهٔ خام.
pub fn from_text(
    text: &str,
    password: Option<&str>,
    dial: Dial,
) -> Result<Vec<CustomConfig>, ImportError> {
    if text.len() > MAX_INPUT_BYTES {
        return invalid("input is larger than 2 MB");
    }
    let text = clean_input(text);
    if let Some(url) = subscription_url(&text) {
        let raw = download_bytes(url, dial)?;
        // یک فایل میزبانی‌شدهٔ NPVS باینری است و نباید به متن تبدیل شود.
        if npvt::is_binary(&raw) {
            return parser::parse_bytes(&raw, ConfigSource::Link, password, now_millis());
        }
        let body = String::from_utf8(raw)
            .map(|t| clean_input(&t))
            .map_err(|_| ImportError::Invalid("subscription is not UTF-8 text".into()))?;
        return parser::parse(&body, ConfigSource::Link, password, now_millis());
    }
    parser::parse(&text, ConfigSource::Link, password, now_millis())
}

/// یک فایل را می‌خواند و پارس می‌کند.
pub fn from_file(path: &Path, password: Option<&str>) -> Result<Vec<CustomConfig>, ImportError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if !FILE_EXTENSIONS.contains(&ext.as_str()) {
        return invalid("unsupported file type (use .npvt, .npvs, .txt, .json or .conf)");
    }
    let meta = std::fs::metadata(path).map_err(|e| ImportError::Invalid(format!("file could not be read: {e}")))?;
    if !meta.is_file() {
        return invalid("not a file");
    }
    if meta.len() as usize > MAX_INPUT_BYTES {
        return invalid("file is larger than 2 MB");
    }
    let bytes = std::fs::read(path).map_err(|e| ImportError::Invalid(format!("file could not be read: {e}")))?;
    parser::parse_bytes(&bytes, ConfigSource::File, password, now_millis())
}

/// فایلی که رابط کاربری خودش خوانده (`<input type="file">`): نام برای
/// بررسیِ پسوند، متن همان محتوای UTF-8.
pub fn from_file_text(
    name: &str,
    text: &str,
    password: Option<&str>,
) -> Result<Vec<CustomConfig>, ImportError> {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if !FILE_EXTENSIONS.contains(&ext.as_str()) {
        return invalid("unsupported file type (use .npvt, .npvs, .txt, .json or .conf)");
    }
    if text.len() > MAX_INPUT_BYTES {
        return invalid("file is larger than 2 MB");
    }
    // A binary NPVS envelope is not text: converting it to a String would corrupt it.
    if text.starts_with("NPVS") {
        return invalid("binary NPVS files must be imported as bytes");
    }
    parser::parse(text, ConfigSource::File, password, now_millis())
}

/// ویرایش: متنِ تازه را جای کانفیگِ قدیمی می‌گذارد و شناسه، نام و زمانِ
/// افزودن را نگه می‌دارد. کانفیگِ قفل‌شده ویرایش‌پذیر نیست.
pub fn reparse(
    old: &CustomConfig,
    new_raw: &str,
    password: Option<&str>,
) -> Result<CustomConfig, ImportError> {
    if old.locked {
        return invalid("locked configs cannot be edited");
    }
    let mut parsed = parser::parse(new_raw, old.source, password, now_millis())?;
    if parsed.len() != 1 {
        return invalid("an edit must contain exactly one config");
    }
    let mut next = parsed.remove(0);
    next.id = old.id.clone();
    next.name = old.name.clone();
    next.added_at = old.added_at;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invisible_marks_are_stripped_but_persian_joiners_stay() {
        let pasted = "\u{200F}\u{2067}vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@\u{200B}203.0.113.9:443?security=tls&sni=a.example#\u{0645}\u{200C}\u{0646}\u{2069}\u{FEFF}";
        let clean = clean_input(pasted);
        assert!(clean.starts_with("vless://aaaaaaaa"));
        assert!(clean.contains("@203.0.113.9:443"));
        assert!(clean.contains('\u{200C}'));
        assert!(!clean.chars().any(is_invisible));
        assert_eq!(clean_input("a\u{00A0}b\r\nc"), "a b\nc");
        let configs = from_text(pasted, None, Dial::Direct).unwrap();
        assert_eq!(configs.len(), 1);
    }

    #[test]
    fn subscription_url_only_for_single_https_line() {
        assert_eq!(subscription_url("  https://x.example/sub \n"), Some("https://x.example/sub"));
        assert_eq!(subscription_url("http://x.example/sub"), None);
        assert_eq!(subscription_url("https://a/1\nhttps://b/2"), None);
        assert_eq!(subscription_url("vless://u@h:443"), None);
    }

    #[test]
    fn redirects_never_downgrade() {
        assert_eq!(
            resolve_location("https://a.example/x", "/y?z"),
            Some("https://a.example/y?z".into())
        );
        assert_eq!(
            resolve_location("https://a.example:8443/x", "/y"),
            Some("https://a.example:8443/y".into())
        );
        assert_eq!(resolve_location("https://a.example/x", "http://b/"), None);
        assert_eq!(resolve_location("https://a.example/x", "relative"), None);
    }

    #[test]
    fn reparse_keeps_identity_and_refuses_locked() {
        let link = "trojan://pw@example.com:443?sni=example.com#one";
        let mut old = parser::parse(link, ConfigSource::Link, None, 1).unwrap().remove(0);
        old.name = "Mine".into();
        let next = reparse(&old, "trojan://pw2@example.org:8443?sni=example.org#two", None).unwrap();
        assert_eq!(next.id, old.id);
        assert_eq!(next.name, "Mine");
        assert_eq!(next.added_at, old.added_at);
        assert!(next.server.contains("example.org"));
        old.locked = true;
        assert!(reparse(&old, link, None).is_err());
    }

    #[test]
    fn file_extension_and_size_are_checked() {
        let dir = std::env::temp_dir().join(format!("aether-cc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("a.exe");
        std::fs::write(&bad, "trojan://pw@example.com:443#x").unwrap();
        assert!(from_file(&bad, None).is_err());
        let good = dir.join("a.txt");
        std::fs::write(&good, "trojan://pw@example.com:443?sni=example.com#x").unwrap();
        let got = from_file(&good, None).unwrap();
        assert_eq!(got[0].source, ConfigSource::File);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]mod unicode_url_tests {use super::*;#[test]fn multibyte_input_never_slices_mid_codepoint(){for s in ["🌍🌍🌍hello","سلامسلامسلام","abcdefg🌍.invalid"]{assert_eq!(subscription_url(s),None);assert_eq!(resolve_location("https://example.invalid/",s),None);}}}
