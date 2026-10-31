//! پورت از `core/LoginCodePrompt.kt` موبایل ۱.۵.۰ — کدِ ورودِ Zero Trust
//! وسطِ اتصال.
//!
//! هستهٔ ۲.۴.۰ (دست‌نخورده) وقتی stdin ترمینال نیست، به جای پرسیدن در کنسول
//! یک سطرِ ماشین‌خوان چاپ می‌کند:
//!
//! ```text
//! [zerotrust] login-code-needed attempt=1 email=someone@example.com
//! ```
//!
//! و یک سطر از **stdin** می‌خواند (حداکثر ۳۰۰ ثانیه، ۳ تلاش). کلِ پروتکل همین
//! است: آن سطر دیده شود، از کاربر پرسیده شود، کد با یک `\n` به stdin برگردد.
//!
//! پیش از این، برنامه یک `y\n` در stdin می‌نوشت و لوله را می‌بست؛ هستهٔ ۲.۴.۰
//! هیچ پرسشِ دیگری از stdinِ غیرترمینال ندارد (`prompt_line` آن را `None`
//! می‌گیرد)، پس آن `y` اولین «کد» می‌شد و تلاشِ دوم EOF می‌گرفت. حالا stdin
//! برای عمرِ همان یک موتور نگه داشته می‌شود.
//!
//! خودِ کد هرگز در لاگ نوشته نمی‌شود: یک اعتبارنامهٔ یک‌بارمصرف است.

use crate::log::DiagnosticsLog;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::OnceLock;

/// باید با `zerotrust::CODE_PROMPT_MARKER` هسته یکی باشد.
pub const MARKER: &str = "[zerotrust] login-code-needed";
/// محدودیت‌های سمتِ هسته، تا رابط کاربری آن‌ها را درست بگوید.
pub const CODE_WAIT_SECONDS: u64 = 300;
pub const MAX_ATTEMPTS: u32 = 3;

const TAG: &str = "zerotrust";

/// درخواستِ بازِ یک کدِ ورود.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub email: String,
    /// از ۱، همان‌طور که هسته می‌شمارد. بیشتر از ۱ یعنی کدِ قبلی رد شد.
    pub attempt: u32,
    pub max_attempts: u32,
    pub wait_seconds: u64,
}

struct Inner {
    sink: Option<Box<dyn Write + Send>>,
    pending: Option<Request>,
    /// «حالا نه» زده شد: حلقهٔ کنترلر اتصال را همین حالا قطع می‌کند.
    abandon: bool,
    /// شمارهٔ موتورِ فعلی، تا بسته‌شدنِ خروجیِ یک موتورِ کهنه stdinِ موتورِ تازه را جدا نکند.
    generation: u64,
}

fn inner() -> &'static Mutex<Inner> {
    static I: OnceLock<Mutex<Inner>> = OnceLock::new();
    I.get_or_init(|| {
        Mutex::new(Inner {
            sink: None,
            pending: None,
            abandon: false,
            generation: 0,
        })
    })
}

/// موتورِ تازه: stdinش نگه داشته و هر درخواستِ کهنه‌ای پاک می‌شود.
pub fn attach(stdin: Option<Box<dyn Write + Send>>) -> u64 {
    let mut g = inner().lock();
    g.sink = stdin;
    g.pending = None;
    g.abandon = false;
    g.generation = g.generation.wrapping_add(1);
    g.generation
}

/// موتور رفت: دیالوگ نباید از فرآیندی که آن را خواست بیشتر عمر کند.
pub fn detach(generation: u64) {
    let mut g = inner().lock();
    if g.generation != generation {
        return;
    }
    g.sink = None;
    g.pending = None;
}

/// درخواستِ باز، برای snapshot.
pub fn pending() -> Option<Request> {
    inner().lock().pending.clone()
}

/// `key=value` تا فاصلهٔ بعدی.
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let at = text.find(key)?;
    let rest = &text[at + key.len()..];
    let value = rest.split(' ').next().unwrap_or("").trim();
    (!value.is_empty()).then_some(value)
}

/// سطرِ هسته را می‌خواند؛ `None` اگر این سطر درخواستِ کد نیست.
pub fn parse(line: &str) -> Option<Request> {
    let at = line.find(MARKER)?;
    let tail = &line[at + MARKER.len()..];
    let email = field(tail, "email=").unwrap_or("").to_string();
    let attempt = field(tail, "attempt=")
        .and_then(|a| a.parse().ok())
        .unwrap_or(1);
    Some(Request {
        email,
        attempt,
        max_attempts: MAX_ATTEMPTS,
        wait_seconds: CODE_WAIT_SECONDS,
    })
}

/// برای هر سطرِ خروجیِ موتور صدا زده می‌شود؛ برای سطرهای دیگر با یک `contains` برمی‌گردد.
pub fn ingest(line: &str) -> bool {
    if !line.contains(MARKER) {
        return false;
    }
    let Some(request) = parse(line) else {
        return false;
    };
    DiagnosticsLog::i(
        TAG,
        &format!(
            "The organization e-mailed a login code to {} (attempt {} of {MAX_ATTEMPTS}). Waiting up to {CODE_WAIT_SECONDS}s for it.",
            if request.email.is_empty() { "your address" } else { &request.email },
            request.attempt
        ),
    );
    inner().lock().pending = Some(request);
    true
}

/// کد به موتور داده می‌شود. `false` اگر کد خالی بود یا موتوری نمانده.
pub fn submit(code: &str) -> bool {
    let trimmed = code.trim();
    if trimmed.is_empty() || trimmed.contains(['\n', '\r']) {
        return false;
    }
    let mut g = inner().lock();
    let Some(out) = g.sink.as_mut() else {
        DiagnosticsLog::w(
            TAG,
            "A login code was entered but the engine is no longer running.",
        );
        g.pending = None;
        return false;
    };
    let ok = out
        .write_all(format!("{trimmed}\n").as_bytes())
        .and_then(|_| out.flush())
        .is_ok();
    if ok {
        DiagnosticsLog::i(TAG, "Login code sent to the engine.");
        g.pending = None;
    } else {
        DiagnosticsLog::e(TAG, "Could not hand the login code to the engine.");
    }
    ok
}

/// «حالا نه»: یک سطرِ خالی به موتور (هسته ورود را با «no login code was
/// entered» تمام می‌کند) و اتصال همین حالا قطع می‌شود — نه بعد از ۳۰۰ ثانیه.
pub fn dismiss() {
    let mut g = inner().lock();
    if g.pending.is_none() {
        return;
    }
    if let Some(out) = g.sink.as_mut() {
        let _ = out.write_all(b"\n").and_then(|_| out.flush());
    }
    g.pending = None;
    g.abandon = true;
    DiagnosticsLog::w(
        TAG,
        "The login code prompt was dismissed (Not now); the connection is stopped now.",
    );
}

/// آیا «حالا نه» زده شده؟ یک‌بار مصرف: خواندنش پرچم را پاک می‌کند.
pub fn take_abandon() -> bool {
    std::mem::take(&mut inner().lock().abandon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cores_exact_line_is_parsed() {
        let line = crate::login_code::MARKER.to_string() + " attempt=2 email=someone@example.com";
        let r = parse(&line).expect("marker");
        assert_eq!(r.attempt, 2);
        assert_eq!(r.email, "someone@example.com");
        assert_eq!(r.max_attempts, 3);
    }

    #[test]
    fn a_log_prefixed_line_is_still_recognised() {
        let r = parse("[2026-10-08T12:00:00Z INFO aether] [zerotrust] login-code-needed attempt=1 email=a@b.co").unwrap();
        assert_eq!(r.attempt, 1);
        assert_eq!(r.email, "a@b.co");
    }

    #[test]
    fn missing_fields_fall_back_safely() {
        let r = parse("[zerotrust] login-code-needed").unwrap();
        assert_eq!(r.attempt, 1);
        assert_eq!(r.email, "");
        let r = parse("[zerotrust] login-code-needed attempt=x email=").unwrap();
        assert_eq!(r.attempt, 1);
    }

    #[test]
    fn other_lines_are_ignored() {
        assert!(parse("[*] waiting for the login code emailed to a@b.co").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn a_code_reaches_the_engine_with_a_newline_and_never_twice() {
        use std::sync::{Arc, Mutex as StdMutex};
        #[derive(Clone)]
        struct Buf(Arc<StdMutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf(Arc::new(StdMutex::new(Vec::new())));
        let gen = attach(Some(Box::new(buf.clone())));
        assert!(ingest(
            "[zerotrust] login-code-needed attempt=1 email=a@b.co"
        ));
        assert!(pending().is_some());
        assert!(!submit("   "));
        assert!(submit(" 123456 "));
        assert!(pending().is_none());
        assert_eq!(&*buf.0.lock().unwrap(), b"123456\n");
        // «حالا نه» بی‌درخواست کاری نمی‌کند.
        dismiss();
        assert!(!take_abandon());
        assert!(ingest(
            "[zerotrust] login-code-needed attempt=2 email=a@b.co"
        ));
        dismiss();
        assert!(take_abandon());
        assert!(!take_abandon());
        assert_eq!(&*buf.0.lock().unwrap(), b"123456\n\n");
        detach(gen.wrapping_add(7));
        assert!(
            inner().lock().sink.is_some(),
            "a stale engine must not detach the current one"
        );
        detach(gen);
        assert!(!submit("1"));
    }
}
