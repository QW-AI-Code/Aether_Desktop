//! ۱.۴.۰ — یک تبادلِ HTTPS کوچک و کران‌دار، برای دو مصرف‌کنندهٔ تازه:
//!
//!  * [`crate::smart_lists`] — دریافتِ هفتگیِ فهرست‌های ایران/تبلیغات **از داخل
//!    تونل** (پراکسی SOCKS5 محلیِ خط لوله، با `ATYP=DOMAIN` تا نام هم آن‌طرفِ
//!    تونل حل شود)؛
//!  * [`crate::zt_signin`] — ورودِ پیش از اتصالِ Zero Trust، روی شبکهٔ مستقیم
//!    (تونل در آن لحظه پایین است) به `https://<team>.cloudflareaccess.com`.
//!
//! همان دلیلِ [`crate::ai_http`] برای دست‌ساز بودن: برنامه کتابخانهٔ HTTP ندارد
//! و `native-tls` (SChannel ویندوز) از قبل هست. `connect(host, …)` نامِ روی
//! گواهی را هم بررسی می‌کند.
//!
//! عمداً **هیچ** ریدایرکتی را خودش دنبال نمی‌کند: ورود Zero Trust باید هر هاپ را
//! ببیند تا کوکی‌ها را فقط برای میزبانِ تیم نگه دارد و ریدایرکتِ
//! `com.cloudflare.warp://` را بخواند، نه اینکه دنبالش کند.

use crate::probe;
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// از کجا شماره‌گیری شود.
#[derive(Debug, Clone, Copy)]
pub enum Dial {
    /// شبکهٔ واقعی (فقط وقتی تونل پایین است یا عمداً مستقیم).
    Direct,
    /// از داخل پراکسی SOCKS5 روی `127.0.0.1:<port>`.
    Socks(u16),
}

#[derive(Debug, Clone)]
pub struct Response {
    pub code: u16,
    /// نام‌ها با حروف کوچک.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// `https://host[:port]/path?query` → (host, port, path-and-query).
pub fn split_https_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("https://")?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, path) = match rest.find(|c: char| c == '/' || c == '?') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => match p.parse::<u16>() {
            Ok(port) if port > 0 => (h.to_string(), port),
            _ => return None,
        },
        _ => (authority.to_string(), 443),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Some((host.to_ascii_lowercase(), port, path))
}

fn dial(how: Dial, host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    match how {
        Dial::Socks(socks) => probe::socks5_stream_on(socks, host, port, timeout)
            .ok_or_else(|| anyhow!("the tunnel's SOCKS5 proxy did not open a path to {host}")),
        Dial::Direct => {
            let addrs: Vec<_> = (host, port)
                .to_socket_addrs()
                .map_err(|e| anyhow!("could not resolve {host}: {e}"))?
                .collect();
            // IPv4 اول: مسیر IPv6 روی بسیاری از شبکه‌های اینجا ناقص است. نشانی‌های
            // بی‌معنی (0.0.0.0، پخش همگانی 255.255.255.255، multicast) حذف می‌شوند:
            // اتصال به آن‌ها در ویندوز دقیقاً با WSAEACCES (10013) رد می‌شود و یک DNS
            // خراب/پاک‌سازی‌شده را به «فایروال مرا بست» تبدیل می‌کرد.
            let usable = |a: &&std::net::SocketAddr| {
                let ip = a.ip();
                !(ip.is_unspecified() || ip.is_multicast()
                    || matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast()))
            };
            let mut ordered: Vec<_> = addrs.iter().filter(usable).filter(|a| a.is_ipv4()).cloned().collect();
            ordered.extend(addrs.iter().filter(usable).filter(|a| a.is_ipv6()).cloned());
            if ordered.is_empty() && !addrs.is_empty() {
                return Err(anyhow!("{host} resolves only to unusable addresses (a DNS block page or a broken resolver)"));
            }
            let mut last = None;
            for addr in ordered {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(match last {
                Some(e) => anyhow!("could not reach {host}: {e}"),
                None => anyhow!("{host} has no address"),
            })
        }
    }
}

/// یک درخواست، یک پاسخ. `Connection: close`، بدون ریدایرکتِ خودکار.
///
/// `form` اگر باشد به‌صورت `application/x-www-form-urlencoded` فرستاده می‌شود.
pub fn exchange(
    how: Dial,
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    form: Option<&[(&str, String)]>,
    timeout: Duration,
    max_body: usize,
) -> Result<Response> {
    let (host, port, path) =
        split_https_url(url).ok_or_else(|| anyhow!("refusing a non-https or malformed URL"))?;
    let stream = dial(how, &host, port, timeout)?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let connector = native_tls::TlsConnector::new()
        .map_err(|e| anyhow!("TLS could not be initialised: {e}"))?;
    let mut tls = connector
        .connect(&host, stream)
        .map_err(|e| anyhow!("TLS handshake with {host} failed: {e}"))?;

    let payload = form.map(encode_form);
    let mut head = String::with_capacity(512);
    head.push_str(method);
    head.push(' ');
    head.push_str(&path);
    head.push_str(" HTTP/1.1\r\nHost: ");
    head.push_str(&host);
    if port != 443 {
        head.push_str(&format!(":{port}"));
    }
    head.push_str("\r\nConnection: close\r\nAccept-Encoding: identity\r\n");
    for (name, value) in headers {
        if value.contains('\r') || value.contains('\n') {
            return Err(anyhow!("refusing a header value with a line break"));
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if let Some(body) = &payload {
        head.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    } else if method != "GET" && method != "HEAD" {
        head.push_str("Content-Length: 0\r\n");
    }
    head.push_str("\r\n");
    tls.write_all(head.as_bytes())
        .map_err(|e| anyhow!("could not send the request: {e}"))?;
    if let Some(body) = &payload {
        tls.write_all(body.as_bytes())
            .map_err(|e| anyhow!("could not send the request body: {e}"))?;
    }
    let _ = tls.flush();

    // تا EOF خوانده می‌شود، با سقف. خطای خواندن پس از دریافتِ پاسخِ کامل
    // (سرورهایی که close_notify نمی‌فرستند) خطا حساب نمی‌شود؛ کامل‌بودن را
    // `parse_response` با Content-Length / chunked می‌سنجد.
    let cap = max_body.saturating_add(64 * 1024);
    let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut chunk = vec![0u8; 16 * 1024];
    let mut read_error = None;
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > cap {
                    return Err(anyhow!("the answer is larger than {max_body} bytes"));
                }
                if response_complete(&raw) {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                read_error = Some(e);
                break;
            }
        }
    }
    match parse_response(&raw, max_body) {
        Some(r) => Ok(r),
        None => Err(match read_error {
            Some(e) => anyhow!("the answer was cut off: {e}"),
            None => anyhow!("the answer was cut off or malformed"),
        }),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn response_complete(raw: &[u8]) -> bool {
    let Some(end) = find(raw, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
    let body = &raw[end + 4..];
    for line in head.split("\r\n") {
        if let Some(v) = line.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                return body.len() >= n;
            }
        }
        if line.starts_with("transfer-encoding:") && line.contains("chunked") {
            return dechunk(body).is_some();
        }
    }
    false
}

fn parse_response(raw: &[u8], max_body: usize) -> Option<Response> {
    let end = find(raw, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next()?;
    let code = status.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let mut headers = Vec::new();
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim().to_string();
        if k == "content-length" {
            length = v.parse::<usize>().ok();
        }
        if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
        headers.push((k, v));
    }
    let rest = &raw[end + 4..];
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(n) = length {
        if rest.len() < n {
            return None;
        }
        rest[..n].to_vec()
    } else {
        rest.to_vec()
    };
    if body.len() > max_body {
        return None;
    }
    Some(Response {
        code,
        headers,
        body,
    })
}

/// `Transfer-Encoding: chunked` → بدنه، یا `None` اگر هنوز ناقص است.
fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(data, b"\r\n")?;
        let size_line = String::from_utf8_lossy(&data[..line_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if data.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// `application/x-www-form-urlencoded`، UTF-8.
pub fn encode_form(form: &[(&str, String)]) -> String {
    form.iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn url_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_split_and_non_https_refused() {
        assert_eq!(
            split_https_url("https://Acme.cloudflareaccess.com/warp"),
            Some(("acme.cloudflareaccess.com".into(), 443, "/warp".into()))
        );
        assert_eq!(
            split_https_url("https://h.example:8443?x=1"),
            Some(("h.example".into(), 8443, "/?x=1".into()))
        );
        assert_eq!(split_https_url("http://h.example/"), None);
        assert_eq!(split_https_url("https://user@h.example/"), None);
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert!(response_complete(raw));
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.code, 200);
        assert_eq!(r.body, b"Wikipedia");
    }

    #[test]
    fn content_length_is_honoured() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 3\r\n\r\nabc";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.code, 302);
        assert_eq!(r.header("location"), Some("/x"));
        assert_eq!(r.body, b"abc");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc", 1024).is_none());
    }

    #[test]
    fn forms_are_encoded() {
        let f = encode_form(&[
            ("email", "a b@x.io".to_string()),
            ("client_id", String::new()),
        ]);
        assert_eq!(f, "email=a+b%40x.io&client_id=");
    }
}
