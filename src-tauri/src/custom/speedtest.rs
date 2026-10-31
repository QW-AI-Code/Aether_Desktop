//! تست سرعت دانلود/آپلود یک کانفیگ سفارشی — پورتِ `ConfigSpeedTest.kt` و `SpeedRate.kt`
//! نسخهٔ موبایل ۱.۶.۰.
//!
//! روش (همان موبایل): یک Xrayِ موقت فقط با همین کانفیگ بالا می‌آید، یک ورودی SOCKS
//! رمزدارِ loopback دارد؛ بایت‌های واقعی از دل کانفیگ دانلود/آپلود می‌شوند و نرخ
//! `بایت ÷ زمان` است. چیزی که اندازه‌گیری نشود `-1` می‌ماند، نه عددِ ساختگی.
//!
//! * دانلود: تا ۸ MiB یا ۵ ثانیه، اول Hetzner (با Range) و در صورت شکست Cloudflare.
//! * آپلود: ۲ MiB به `speed.cloudflare.com/__up`؛ فقط پس از پاسخِ موفقِ سرور شمرده می‌شود.

use super::cancel::Cancel;
use super::process::{self as xproc, XrayProcess};
use super::realdelay::batch_config;
use super::xray::direct_outbound;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DOWN_LIMIT: u64 = 8 * 1024 * 1024;
const DOWN_WINDOW: Duration = Duration::from_secs(5);
const UP_BYTES: usize = 2 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(6);
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const START_TIMEOUT: Duration = Duration::from_secs(6);
const DOWN_URLS: [(&str, &str); 2] = [
    ("fsn1-speed.hetzner.com", "/100MB.bin"),
    ("speed.cloudflare.com", "/__down?bytes=8388608"),
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub download_bps: i64,
    pub upload_bps: i64,
}

impl Report {
    pub fn none() -> Self {
        Report { download_bps: -1, upload_bps: -1 }
    }
    pub fn usable(&self) -> bool {
        self.download_bps > 0 || self.upload_bps > 0
    }
}

/// بایت بر ثانیه؛ نامعتبر = −1 (همان `SpeedRate.bytesPerSecond`).
pub fn bytes_per_second(bytes: u64, elapsed: Duration) -> i64 {
    let nanos = elapsed.as_nanos();
    if bytes == 0 || nanos == 0 {
        return -1;
    }
    ((bytes as f64) * 1_000_000_000.0 / (nanos as f64)) as i64
}

fn token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    format!("{:016x}", h.finish())
}

type Tls = native_tls::TlsStream<TcpStream>;

/// SOCKS5 (user/pass) → CONNECT host:443 → TLS.
fn open(port: u16, user: &str, pass: &str, host: &str, cancel: &Arc<Cancel>) -> Result<Tls, String> {
    let e = |m: &str| m.to_string();
    let mut s = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2)).map_err(|_| e("proxy"))?;
    let _tracked = cancel.track(&s).map_err(|_| e("cancelled"))?;
    s.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| e("socket"))?;
    s.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| e("socket"))?;
    let _ = s.set_nodelay(true);
    s.write_all(&[5, 1, 2]).map_err(|_| e("socks"))?;
    let mut b = [0u8; 2];
    s.read_exact(&mut b).map_err(|_| e("socks"))?;
    if b != [5, 2] {
        return Err(e("socks"));
    }
    let mut req = vec![1, user.len() as u8];
    req.extend(user.as_bytes());
    req.push(pass.len() as u8);
    req.extend(pass.as_bytes());
    s.write_all(&req).map_err(|_| e("socks"))?;
    s.read_exact(&mut b).map_err(|_| e("socks"))?;
    if b != [1, 0] {
        return Err(e("socks"));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend(host.as_bytes());
    req.extend(443u16.to_be_bytes());
    s.write_all(&req).map_err(|_| e("socks"))?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).map_err(|_| e("socks"))?;
    if head[0] != 5 || head[1] != 0 {
        return Err(e("connect"));
    }
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).map_err(|_| e("socks"))?;
            l[0] as usize + 2
        }
        _ => return Err(e("socks")),
    };
    s.read_exact(&mut vec![0u8; rest]).map_err(|_| e("socks"))?;
    let connector = native_tls::TlsConnector::new().map_err(|_| e("tls"))?;
    let tls = connector.connect(host, s).map_err(|_| e("tls"))?;
    Ok(tls)
}

/// تا پایانِ هدر می‌خواند؛ کدِ وضعیت و بایت‌های اضافهٔ بدنه را برمی‌گرداند.
fn read_head(tls: &mut Tls, deadline: Instant) -> Result<(u16, usize), String> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if Instant::now() > deadline || buf.len() > 16 * 1024 {
            return Err("head".into());
        }
        let n = tls.read(&mut chunk).map_err(|_| "head".to_string())?;
        if n == 0 {
            return Err("head".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let line = std::str::from_utf8(&buf[..buf.iter().position(|b| *b == b'\r').unwrap_or(0)]).map_err(|_| "head".to_string())?;
            let code: u16 = line.split(' ').nth(1).and_then(|c| c.parse().ok()).ok_or("head")?;
            return Ok((code, buf.len() - (pos + 4)));
        }
    }
}

fn download(port: u16, user: &str, pass: &str, host: &str, path: &str, cancel: &Arc<Cancel>) -> Result<i64, String> {
    let call_deadline = Instant::now() + CALL_TIMEOUT;
    let mut tls = open(port, user, pass, host, cancel)?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nRange: bytes=0-{}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        DOWN_LIMIT - 1
    );
    tls.write_all(req.as_bytes()).map_err(|_| "write".to_string())?;
    let (code, already) = read_head(&mut tls, call_deadline)?;
    if !(200..300).contains(&code) {
        return Err(format!("status {code}"));
    }
    let start = Instant::now();
    let mut count = already as u64;
    let mut buf = vec![0u8; 32 * 1024];
    while count < DOWN_LIMIT && start.elapsed() < DOWN_WINDOW {
        if cancel.stopped() || Instant::now() > call_deadline {
            break;
        }
        let want = ((DOWN_LIMIT - count) as usize).min(buf.len());
        match tls.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => count += n as u64,
            Err(_) => break,
        }
    }
    let rate = bytes_per_second(count, start.elapsed());
    if rate > 0 { Ok(rate) } else { Err("empty".into()) }
}

fn upload(port: u16, user: &str, pass: &str, cancel: &Arc<Cancel>) -> Result<i64, String> {
    let host = "speed.cloudflare.com";
    let call_deadline = Instant::now() + CALL_TIMEOUT;
    let mut tls = open(port, user, pass, host, cancel)?;
    let head = format!(
        "POST /__up HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/octet-stream\r\nContent-Length: {UP_BYTES}\r\nConnection: close\r\n\r\n"
    );
    let start = Instant::now();
    tls.write_all(head.as_bytes()).map_err(|_| "write".to_string())?;
    let chunk = vec![0u8; 32 * 1024];
    let mut sent = 0usize;
    while sent < UP_BYTES {
        if cancel.stopped() || Instant::now() > call_deadline {
            return Err("cancelled".into());
        }
        tls.write_all(&chunk).map_err(|_| "write".to_string())?;
        sent += chunk.len();
    }
    tls.flush().map_err(|_| "write".to_string())?;
    // «پاسخِ تأییدشده» لازم است: نوشتنِ بافرشده آپلود شمرده نمی‌شود.
    let (code, _) = read_head(&mut tls, call_deadline)?;
    if !(200..300).contains(&code) {
        return Err(format!("status {code}"));
    }
    Ok(bytes_per_second(UP_BYTES as u64, start.elapsed()))
}

fn wait_listening(x: &mut XrayProcess, port: u16, cancel: &Arc<Cancel>) -> bool {
    let started = Instant::now();
    while started.elapsed() < START_TIMEOUT {
        if cancel.stopped() || !x.is_alive() {
            return false;
        }
        if TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(150)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// کانفیگ را می‌سنجد؛ هر شکستی `Report::none()` است (رابط «نتیجه‌ای دریافت نشد» نشان می‌دهد).
pub fn measure(binary: &Path, data_dir: &Path, outbound: &str, cancel: &Arc<Cancel>) -> Report {
    let Ok(out) = direct_outbound(outbound, "ping-out-0") else { return Report::none() };
    let port = xproc::pick_port(&[]);
    let (user, pass) = (token(), format!("{}{}", token(), token()));
    let config = batch_config(&[(0, out)], &[port], &[(user.clone(), pass.clone())]);
    let Ok(mut x) = XrayProcess::start(binary, data_dir, &format!("speed-{port}"), port, &config) else { return Report::none() };
    if !wait_listening(&mut x, port, cancel) {
        x.stop();
        return Report::none();
    }
    let mut down = -1;
    for (host, path) in DOWN_URLS {
        if cancel.stopped() {
            break;
        }
        if let Ok(rate) = download(port, &user, &pass, host, path, cancel) {
            down = rate;
            break;
        }
    }
    let up = if cancel.stopped() { -1 } else { upload(port, &user, &pass, cancel).unwrap_or(-1) };
    x.stop();
    Report { download_bps: down, upload_bps: up }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rate_is_bytes_over_time_and_never_invented() {
        assert_eq!(bytes_per_second(1_000_000, Duration::from_secs(1)), 1_000_000);
        assert_eq!(bytes_per_second(2_000_000, Duration::from_millis(500)), 4_000_000);
        assert_eq!(bytes_per_second(0, Duration::from_secs(1)), -1);
        assert_eq!(bytes_per_second(10, Duration::ZERO), -1);
        assert!(!Report::none().usable());
    }
}
