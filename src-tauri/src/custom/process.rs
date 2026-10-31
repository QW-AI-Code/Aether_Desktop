//! فرآیندِ Xray-core برای کانفیگِ سفارشی — معادلِ `XrayRunner.kt` اندروید.
//!
//! اندروید Xray را به‌صورتِ کتابخانه (libv2ray) درونِ فرآیند اجرا می‌کند؛
//! ویندوز همان هسته (Xray-core v25.12.8، بدونِ تغییر) را به‌صورتِ
//! `engine\xray\xray.exe` کنارِ موتور نصب می‌کند و به‌عنوانِ فرزند اجرا
//! می‌کند — درست مثل tor.exe و aether.exe:
//!
//! - بی‌کنسول (`CREATE_NO_WINDOW`)؛
//! - داخلِ Job Objectِ «با مرگِ برنامه، بمیر» (`procguard::KillTree`)؛
//! - با متغیرهای پراکسیِ پاک‌شده، تا Xray هرگز از پراکسیِ سیستمیِ خودِ ما
//!   (که بعد از وصل‌شدن روشن می‌شود) dial نکند و حلقه نسازد؛
//! - کانفیگ در `<data>\xray\config-<tag>.json` نوشته و هنگامِ توقف پاک
//!   می‌شود؛ خروجیِ لاگ پیش از ثبت، نشانی‌های IPv4ِ غیرِ loopback را می‌پوشاند.
//!
//! شنونده فقط روی `127.0.0.1` است (SOCKS5 با UDP)، هیچ‌وقت روی LAN.

use crate::log::DiagnosticsLog;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub const TAG: &str = "xray";
#[cfg(windows)]
pub const XRAY_FILENAME: &str = "xray.exe";
#[cfg(not(windows))]
pub const XRAY_FILENAME: &str = "xray";
/// فرصتِ بالا آمدنِ شنوندهٔ Xray.
pub const XRAY_START_TIMEOUT: Duration = Duration::from_secs(15);
/// فاصلهٔ پایشِ زنده‌بودن در حالتِ وصل.
pub const MONITOR_INTERVAL: Duration = Duration::from_secs(1);
/// حداکثرِ راه‌اندازیِ دوباره پشتِ‌سرِهم.
pub const MAX_RESTARTS: u32 = 5;
/// اگر این مدت سالم بماند، شمارندهٔ راه‌اندازیِ دوباره صفر می‌شود.
pub const HEALTHY_RESET: Duration = Duration::from_secs(120);
/// چند بار پشتِ‌سرِهم پورتِ مرده تا نشست از نو ساخته شود.
pub const DEAD_PORT_CONFIRMATIONS: u32 = 5;

const FIRST_PORT: u16 = 18830;
/// پورت‌هایی که بقیهٔ برنامه ثابت گرفته‌اند (موتور، سایفون، رله، اشتراکِ LAN).
const RESERVED: [u16; 5] = [1819, 1820, 1825, 10810, 10811];
const PROXY_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// باینریِ نصب‌شده: `<پوشهٔ برنامه>\engine\xray\xray.exe`.
pub fn locate(install_dir: &Path, working_dir: &Path) -> Option<PathBuf> {
    [install_dir, working_dir]
        .iter()
        .map(|d| d.join("engine").join("xray").join(XRAY_FILENAME))
        .find(|p| p.is_file())
}

/// اولین پورتِ آزادِ loopback از ۱۸۸۳۰ به بالا، به‌جز پورت‌های رزروشده و
/// `avoid`.
pub fn pick_port(avoid: &[u16]) -> u16 {
    let mut port = FIRST_PORT;
    while port < FIRST_PORT + 200 {
        if !RESERVED.contains(&port)
            && !avoid.contains(&port)
            && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
        port += 1;
    }
    FIRST_PORT
}

/// هر چیزی که سرورِ کاربر را لو می‌دهد از سطرِ لاگ پاک می‌شود — همان قاعدهٔ
/// اندروید ۱.۵.۰، برای کانفیگ‌های قفل‌شده هم که نویسنده‌شان سرور را پنهان کرده:
///
/// * IPv4ِ غیرِ loopback → `a.b.x.x`
/// * IPv6 → `<ipv6>`
/// * UUID (شناسهٔ کاربرِ VLESS/VMess) → `<uuid>`
/// * نامِ میزبان → `<host>`؛ به‌جز مقصدهای سنجشِ خودِ برنامه، نامِ فایل‌ها
///   (`.json`، `.dat`، …) و تکه‌های یک مسیرِ ویندوز (`…\studio.cluvex.aether.desktop\…`).
pub fn redact(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut token = String::new();
    let mut prev: Option<char> = None;
    let mut token_prev: Option<char> = None;
    for ch in line.chars() {
        if is_token_char(ch) {
            if token.is_empty() {
                token_prev = prev;
            }
            token.push(ch);
        } else {
            if !token.is_empty() {
                out.push_str(&redact_token(&token, token_prev, Some(ch)));
                token.clear();
            }
            out.push(ch);
        }
        prev = Some(ch);
    }
    if !token.is_empty() {
        out.push_str(&redact_token(&token, token_prev, None));
    }
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')
}

/// میزبان‌هایی که خودِ برنامه می‌سنجد؛ چیزی از کاربر لو نمی‌دهند.
const KEEP_HOSTS: [&str; 4] = ["www.gstatic.com", "cp.cloudflare.com", "www.cloudflare.com", "localhost"];
/// پسوندهای فایل که شبیهِ دامنه‌اند ولی نیستند.
const FILE_SUFFIXES: [&str; 12] = ["json", "dat", "go", "so", "exe", "dll", "txt", "log", "toml", "yaml", "rs", "kt"];

fn redact_token(token: &str, before: Option<char>, after: Option<char>) -> String {
    if is_ipv6(token) {
        return "<ipv6>".into();
    }
    // تکه‌ای از یک مسیرِ ویندوز: دست نمی‌خورد. (`/` نه: نشانیِ URL همان‌جاست.)
    let in_path = before == Some('\\') || after == Some('\\');
    token
        .split(':')
        .map(|seg| redact_segment(seg, in_path))
        .collect::<Vec<_>>()
        .join(":")
}

fn redact_segment(seg: &str, in_path: bool) -> String {
    if seg.is_empty() {
        return String::new();
    }
    if is_uuid(seg) {
        return "<uuid>".into();
    }
    let trimmed = seg.trim_end_matches('.');
    let tail = &seg[trimmed.len()..];
    let parts: Vec<&str> = trimmed.split('.').collect();
    let is_ip = parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false));
    if is_ip {
        return if parts[0] == "127" {
            seg.to_string()
        } else {
            format!("{}.{}.x.x{tail}", parts[0], parts[1])
        };
    }
    if !in_path && is_hostname(trimmed) {
        return format!("<host>{tail}");
    }
    seg.to_string()
}

fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups.iter().map(|g| g.len()).eq([8usize, 4, 4, 4, 12])
        && groups.iter().all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_ipv6(s: &str) -> bool {
    let colons = s.matches(':').count();
    if colons < 2 || !(s.contains("::") || colons == 7) {
        return false;
    }
    s.split(':').all(|g| g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit()))
        && s.chars().any(|c| c.is_ascii_hexdigit())
}

fn is_hostname(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if KEEP_HOSTS.contains(&lower.as_str()) {
        return false;
    }
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) || FILE_SUFFIXES.contains(&tld) {
        return false;
    }
    labels
        .iter()
        .all(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

pub struct XrayProcess {
    child: Child,
    _tree: crate::procguard::KillTree,
    config_path: PathBuf,
    pub port: u16,
    pub tag: String,
}

impl XrayProcess {
    /// Xray را با `config` (JSONِ کاملِ ساخته‌شده با `xray::build`) اجرا می‌کند.
    pub fn start(
        binary: &Path,
        data_dir: &Path,
        tag: &str,
        port: u16,
        config: &str,
    ) -> Result<XrayProcess, String> {
        let run_dir = data_dir.join("xray");
        std::fs::create_dir_all(&run_dir).map_err(|e| format!("xray folder: {e}"))?;
        let config_path = run_dir.join(format!("config-{tag}.json"));
        std::fs::write(&config_path, config).map_err(|e| format!("xray config: {e}"))?;
        let asset_dir = binary.parent().unwrap_or(&run_dir).to_path_buf();
        let mut cmd = Command::new(binary);
        cmd.arg("run")
            .arg("-c")
            .arg(&config_path)
            .current_dir(&run_dir)
            .env("XRAY_LOCATION_ASSET", &asset_dir)
            .env("XRAY_LOCATION_CONFIG", &run_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for var in PROXY_VARS {
            cmd.env_remove(var);
        }
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&config_path);
                return Err(format!("xray.exe could not be started: {e}"));
            }
        };
        let tree = crate::procguard::KillTree::adopt(&child, XRAY_FILENAME);
        if let Some(out) = child.stdout.take() {
            drain(out);
        }
        if let Some(err) = child.stderr.take() {
            drain(err);
        }
        DiagnosticsLog::i(
            TAG,
            &format!("Spawned {XRAY_FILENAME} [{tag}] (pid {}) listening on 127.0.0.1:{port}", child.id()),
        );
        Ok(XrayProcess {
            child,
            _tree: tree,
            config_path,
            port,
            tag: tag.to_string(),
        })
    }

    pub fn is_alive(&mut self) -> bool {
        match self.child.try_wait(){Ok(None)=>true,Ok(Some(status))=>{DiagnosticsLog::w("ChainTrace",&format!("Xray [{}] pid={} exited status={status}",self.tag,self.child.id()));false},Err(_)=>false}
    }

    /// شنونده آماده است؟
    pub fn ready(&mut self) -> bool {
        self.is_alive() && crate::probe::socks_ready(self.port)
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let _ = self.child.kill();
        if let Ok(status)=self.child.wait(){DiagnosticsLog::i("ChainTrace",&format!("Xray [{}] pid={} stopped status={status}",self.tag,self.child.id()));}
        let _ = std::fs::remove_file(&self.config_path);
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            DiagnosticsLog::i(TAG, &format!("Stopping {XRAY_FILENAME} [{}].", self.tag));
        }
        self.shutdown();
    }
}

fn drain<R: std::io::Read + Send + 'static>(reader: R) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let safe = redact(line);
            if safe.contains("[Error]") || safe.contains("failed to") {
                DiagnosticsLog::w(TAG, &safe);
            } else {
                DiagnosticsLog::d(TAG, &safe);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_keeps_loopback_and_hides_servers() {
        assert_eq!(
            redact("dial tcp 203.0.113.9:443 via 127.0.0.1:18830"),
            "dial tcp 203.0.x.x:443 via 127.0.0.1:18830"
        );
        assert_eq!(redact("v25.12.8 started"), "v25.12.8 started");
        assert_eq!(redact("to 8.8.8.8."), "to 8.8.x.x.");
        assert_eq!(redact("پورت 1.2.3.4"), "پورت 1.2.x.x");
    }

    #[test]
    fn redaction_hides_uuid_hosts_and_ipv6_but_keeps_paths() {
        let line = "2026/10/10 07:46:58.696363 [Info] proxy/vless/outbound: tunneling request to tcp:www.google.com:443 via tcp:rusbid.de:2063 user aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let r = redact(line);
        assert!(r.contains("07:46:58.696363"), "{r}");
        assert!(r.contains("tcp:<host>:443") && r.contains("tcp:<host>:2063"), "{r}");
        assert!(r.contains("<uuid>") && !r.contains("aaaaaaaa"), "{r}");
        assert_eq!(redact("dial [2001:db8::1]:443"), "dial [<ipv6>]:443");
        assert_eq!(redact("fe80::1%eth0"), "<ipv6>%eth0");
        let path = r"Reading config: &{Name:C:\Users\U\AppData\Local\studio.cluvex.aether.desktop\xray\config-18830.json Format:json}";
        assert_eq!(redact(path), path);
        assert_eq!(redact("GET http://www.gstatic.com/generate_204"), "GET http://www.gstatic.com/generate_204");
        assert_eq!(redact("Xray 25.12.8 (Xray, Penetrates Everything.) 81f8f39 (go1.25.5 windows/amd64)"),
            "Xray 25.12.8 (Xray, Penetrates Everything.) 81f8f39 (go1.25.5 windows/amd64)");
    }

    #[test]
    fn port_picker_skips_reserved_and_busy() {
        let p = pick_port(&[]);
        assert!(p >= FIRST_PORT && !RESERVED.contains(&p));
        let held = std::net::TcpListener::bind(("127.0.0.1", p)).unwrap();
        let q = pick_port(&[]);
        assert_ne!(p, q);
        drop(held);
        assert_ne!(pick_port(&[p]), p);
    }
}
