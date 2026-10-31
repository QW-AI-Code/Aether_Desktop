//! اسکنر IP تمیز Cloudflare — پورت `scanner/*.kt` موبایل ۱.۶.۰.
//!
//! فقط «نشانی» و پورتِ یک کانفیگِ CDN-محور (VLESS/VMess/Trojan روی ws/httpupgrade/xhttp)
//! عوض می‌شود؛ SNI، Host، مسیر، UUID و انتقال هرگز دست نمی‌خورند. نتیجهٔ کاوش (TLS +
//! `/cdn-cgi/trace`) فقط ترتیب نامزدها را می‌دهد؛ برنده باید سه بار ترافیکِ واقعیِ
//! Xray را (Real Delay) رد کند تا ذخیره شود.
//!
//! این فایل به Tauri وابسته نیست تا روی Linux آزمون شود.

use super::cancel::Cancel;
use super::CustomConfig;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const HTTPS_PORTS: [u16; 6] = [443, 8443, 2053, 2083, 2087, 2096];
pub const HTTP_PORTS: [u16; 7] = [80, 8080, 2052, 2082, 2086, 2095, 8880];
pub const DEFAULT_PORTS: [u16; 6] = HTTPS_PORTS;
pub const MAX_RANGES_TEXT: usize = 8_000;
pub const MAX_ENTRIES: usize = 100;
pub const ENUMERATE_LIMIT: u64 = 50_000;
pub const CONFIRM_ROUNDS: usize = 3;
pub const VALIDATE_BATCH: usize = 5;
pub const MAX_CANDIDATES: usize = 10;
pub const VALIDATE_BUDGET: Duration = Duration::from_secs(90);
const MAX_ACCEPTABLE_LATENCY_MS: i64 = 1200;
const NEIGHBOR_RADIUS: i64 = 32;

// ───────────────────────────── پروفایل و گزینه‌ها ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Fast,
    Balanced,
    Deep,
}

impl ScanProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fast => "FAST",
            Self::Balanced => "BALANCED",
            Self::Deep => "DEEP",
        }
    }
    pub fn from_name(s: Option<&str>) -> Self {
        match s.map(|v| v.trim().to_ascii_uppercase()).as_deref() {
            Some("FAST") => Self::Fast,
            Some("DEEP") => Self::Deep,
            _ => Self::Balanced,
        }
    }
    pub fn candidate_budget(self) -> usize {
        match self { Self::Fast => 120, Self::Balanced => 300, Self::Deep => 600 }
    }
    pub fn timeout_ms(self) -> u64 {
        match self { Self::Fast => 3500, Self::Balanced => 5000, Self::Deep => 6000 }
    }
    pub fn probes_per_ip(self) -> usize {
        match self { Self::Fast => 1, Self::Balanced => 2, Self::Deep => 3 }
    }
    pub fn parallelism(self) -> usize {
        match self { Self::Fast => 60, Self::Balanced => 50, Self::Deep => 40 }
    }
    pub fn neighbor_per_hit(self) -> usize {
        match self { Self::Fast => 6, Self::Balanced => 12, Self::Deep => 16 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub profile: ScanProfile,
    /// سقف دستیِ پینگ فعال است؟
    pub manual: bool,
    pub ceiling: u32,
    pub custom_enabled: bool,
    pub custom_ranges: String,
}

impl Default for Options {
    fn default() -> Self {
        Options { profile: ScanProfile::Balanced, manual: true, ceiling: 2000, custom_enabled: false, custom_ranges: String::new() }
    }
}

impl Options {
    pub fn to_json(&self) -> Value {
        json!({
            "profile": self.profile.name(),
            "manual": self.manual,
            "ceiling": self.ceiling,
            "customEnabled": self.custom_enabled,
            "customRanges": self.custom_ranges,
        })
    }
    /// ورودی نامعتبر هرگز خطا نمی‌دهد؛ مقدار امن می‌گیرد (همان رفتار SharedPreferences موبایل).
    pub fn from_json(v: &Value) -> Self {
        let d = Options::default();
        Options {
            profile: ScanProfile::from_name(v.get("profile").and_then(Value::as_str)),
            manual: v.get("manual").and_then(Value::as_bool).unwrap_or(d.manual),
            ceiling: v.get("ceiling").and_then(Value::as_u64).map(|n| n.clamp(50, 5000) as u32).unwrap_or(d.ceiling),
            custom_enabled: v.get("customEnabled").and_then(Value::as_bool).unwrap_or(false),
            custom_ranges: v.get("customRanges").and_then(Value::as_str).unwrap_or("").chars().take(MAX_RANGES_TEXT).collect(),
        }
    }
    /// برای ذخیرهٔ رابط: سقف خارج از ۵۰..۵۰۰۰ رد می‌شود (`require` موبایل).
    pub fn validate_strict(v: &Value) -> Result<Self, &'static str> {
        if let Some(c) = v.get("ceiling") {
            match c.as_u64() {
                Some(n) if (50..=5000).contains(&n) => {}
                _ => return Err("ceiling must be between 50 and 5000"),
            }
        }
        Ok(Self::from_json(v))
    }
}

// ───────────────────────────── رنج‌های سفارشی ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}
impl Range {
    pub fn size(&self) -> u64 { self.end - self.start + 1 }
    pub fn contains(&self, v: u64) -> bool { v >= self.start && v <= self.end }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub ranges: Vec<Range>,
    pub invalid: Vec<String>,
}

const RESERVED: [Range; 7] = [
    Range { start: 0x0000_0000, end: 0x00FF_FFFF },
    Range { start: 0x0A00_0000, end: 0x0AFF_FFFF },
    Range { start: 0x7F00_0000, end: 0x7FFF_FFFF },
    Range { start: 0xA9FE_0000, end: 0xA9FE_FFFF },
    Range { start: 0xAC10_0000, end: 0xAC1F_FFFF },
    Range { start: 0xC0A8_0000, end: 0xC0A8_FFFF },
    Range { start: 0xE000_0000, end: 0xFFFF_FFFF },
];

fn normalize_digits(text: &str) -> String {
    text.chars()
        .map(|c| if (c as u32) > 127 { c.to_digit(10).and_then(|d| char::from_digit(d, 10)).unwrap_or(c) } else { c })
        .map(|c| match c {
            // ارقام فارسی (۰-۹) و عربی-هندی (٠-٩) که to_digit نمی‌شناسد
            '\u{06F0}'..='\u{06F9}' => char::from_digit(c as u32 - 0x06F0, 10).unwrap(),
            '\u{0660}'..='\u{0669}' => char::from_digit(c as u32 - 0x0660, 10).unwrap(),
            _ => c,
        })
        .collect::<String>()
        .to_lowercase()
}

pub fn ip_to_u64(ip: &str) -> Option<u64> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return None; }
    let mut v = 0u64;
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) { return None; }
        let n: u64 = p.parse().ok()?;
        if n > 255 { return None; }
        v = (v << 8) | n;
    }
    Some(v)
}

pub fn u64_to_ip(v: u64) -> String {
    let v = v & 0xFFFF_FFFF;
    format!("{}.{}.{}.{}", (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255)
}

fn parse_cidr(token: &str) -> Option<Range> {
    let (ip, pre) = token.split_once('/')?;
    if pre.contains('/') { return None; }
    let base = ip_to_u64(ip)?;
    if pre.is_empty() || pre.len() > 2 || !pre.bytes().all(|b| b.is_ascii_digit()) { return None; }
    let prefix: u32 = pre.parse().ok()?;
    if !(8..=32).contains(&prefix) { return None; }
    let host_bits = 32 - prefix;
    let mask = (0xFFFF_FFFFu64 << host_bits) & 0xFFFF_FFFF;
    let first = base & mask;
    let last = first | (0xFFFF_FFFF & !mask);
    Some(if prefix <= 30 { Range { start: first + 1, end: last - 1 } } else { Range { start: first, end: last } })
}

fn parse_span(token: &str) -> Option<Range> {
    let (a, b) = token.split_once('-')?;
    if b.contains('-') { return None; }
    let (a, b) = (ip_to_u64(a)?, ip_to_u64(b)?);
    if a <= b { Some(Range { start: a, end: b }) } else { None }
}

fn parse_entry(token: &str) -> Option<Range> {
    let r = if token.contains('/') {
        parse_cidr(token)
    } else if token.contains('-') {
        parse_span(token)
    } else {
        ip_to_u64(token).map(|v| Range { start: v, end: v })
    }?;
    if RESERVED.iter().any(|x| x.start <= r.end && r.start <= x.end) { None } else { Some(r) }
}

fn merge(mut input: Vec<Range>) -> Vec<Range> {
    input.sort_by_key(|r| r.start);
    let mut out: Vec<Range> = Vec::new();
    for r in input {
        match out.last_mut() {
            Some(last) if r.start <= last.end + 1 => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

pub fn parse_ranges(text: &str) -> Parsed {
    let norm = normalize_digits(text);
    let tokens: Vec<&str> = norm
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '\u{060C}'))
        .filter(|t| !t.is_empty())
        .collect();
    let mut ranges = Vec::new();
    let mut invalid = Vec::new();
    for t in tokens.iter().take(MAX_ENTRIES) {
        match parse_entry(t) { Some(r) => ranges.push(r), None => invalid.push((*t).to_string()) }
    }
    if tokens.len() > MAX_ENTRIES {
        invalid.extend(tokens[MAX_ENTRIES..].iter().map(|s| s.to_string()));
    }
    Parsed { ranges: merge(ranges), invalid }
}

pub fn total(ranges: &[Range]) -> u64 { ranges.iter().map(Range::size).sum() }

pub fn address_at(ranges: &[Range], index: u64) -> Option<u64> {
    let mut left = index;
    for r in ranges {
        if left < r.size() { return Some(r.start + left); }
        left -= r.size();
    }
    None
}

// ───────────────────────────── فضای Cloudflare ─────────────────────────────

const WEIGHTED_CIDRS: [(&str, u32); 9] = [
    ("188.114.96.0/20", 5), ("162.159.0.0/16", 4), ("104.16.0.0/13", 3), ("104.24.0.0/14", 3),
    ("172.64.0.0/13", 2), ("198.41.128.0/17", 1), ("173.245.48.0/20", 1), ("103.21.244.0/22", 1),
    ("141.101.64.0/18", 1),
];

fn cidr_bounds(cidr: &str) -> (u64, u64) {
    let (b, p) = cidr.split_once('/').unwrap();
    let prefix: u32 = p.parse().unwrap();
    let base = ip_to_u64(b).unwrap();
    let mask = (0xFFFF_FFFFu64 << (32 - prefix)) & 0xFFFF_FFFF;
    (base & mask, (base & mask) | (0xFFFF_FFFF & !mask))
}

fn in_builtin(v: u64) -> bool {
    WEIGHTED_CIDRS.iter().any(|(c, _)| { let (a, b) = cidr_bounds(c); v >= a && v <= b })
}

/// فضایی که اسکن از آن نامزد برمی‌دارد: درون‌ساخت یا فقط رنج‌های کاربر.
#[derive(Debug, Clone, Default)]
pub struct Space {
    pub custom: Vec<Range>,
}

impl Space {
    pub fn contains(&self, v: u64) -> bool {
        if self.custom.is_empty() { in_builtin(v) } else { self.custom.iter().any(|r| r.contains(v)) }
    }
    pub fn is_cloudflare_ip(&self, ip: &str) -> bool {
        ip_to_u64(ip).map(|v| in_builtin(v) || self.custom.iter().any(|r| r.contains(v))).unwrap_or(false)
    }
    pub fn random_ip(&self) -> String {
        if !self.custom.is_empty() {
            let idx = rand_below(total(&self.custom));
            return u64_to_ip(address_at(&self.custom, idx).unwrap());
        }
        let pool: Vec<&str> = WEIGHTED_CIDRS.iter().flat_map(|(c, w)| std::iter::repeat(*c).take(*w as usize)).collect();
        let (a, b) = cidr_bounds(pool[rand_below(pool.len() as u64) as usize]);
        // شبکه و broadcast کنار گذاشته می‌شوند
        u64_to_ip(a + 1 + rand_below(b - a - 1))
    }
    pub fn sample_candidates(&self, n: usize, seen: &HashSet<String>) -> Vec<String> {
        if self.custom.is_empty() {
            let mut out = Vec::new();
            let mut local = HashSet::new();
            let mut tries = 0;
            while out.len() < n && tries < n * 200 {
                tries += 1;
                let ip = self.random_ip();
                if !seen.contains(&ip) && local.insert(ip.clone()) { out.push(ip); }
            }
            return out;
        }
        let t = total(&self.custom);
        if t <= ENUMERATE_LIMIT {
            let mut all: Vec<String> = self.custom.iter()
                .flat_map(|r| r.start..=r.end)
                .map(u64_to_ip)
                .filter(|ip| !seen.contains(ip))
                .collect();
            shuffle(&mut all);
            all.truncate(n);
            return all;
        }
        let mut out = Vec::new();
        let mut local = HashSet::new();
        let mut attempts = 0;
        while out.len() < n && attempts < n * 40 {
            attempts += 1;
            let ip = self.random_ip();
            if !seen.contains(&ip) && local.insert(ip.clone()) { out.push(ip); }
        }
        out
    }
    pub fn neighbors_around(&self, ip: &str, radius: i64, limit: usize) -> Vec<String> {
        let Some(base) = ip_to_u64(ip) else { return vec![] };
        let mut out = Vec::new();
        if limit == 0 || radius <= 0 { return out; }
        let mut delta = 1i64;
        while delta <= radius && out.len() < limit {
            for signed in [delta, -delta] {
                let next = base as i64 + signed;
                if !(0..=0xFFFF_FFFFi64).contains(&next) { continue; }
                if !self.contains(next as u64) { continue; }
                out.push(u64_to_ip(next as u64));
                if out.len() >= limit { break; }
            }
            delta += 1;
        }
        out
    }
}

// ───────────────────────────── تصادفی بی crate ─────────────────────────────

static RNG: AtomicU64 = AtomicU64::new(0);

fn splitmix() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    if RNG.load(Ordering::Relaxed) == 0 {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1));
        let _ = RNG.compare_exchange(0, h.finish() | 1, Ordering::SeqCst, Ordering::SeqCst);
    }
    let mut z = RNG.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub fn rand_below(n: u64) -> u64 { if n <= 1 { 0 } else { splitmix() % n } }

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() { v.swap(i, rand_below(i as u64 + 1) as usize); }
}

// ───────────────────────────── Endpoint ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
    pub tls: bool,
}

/// فقط وقتی `Some` است که تعویض نشانی امن باشد (REALITY و غیر-CDN رد می‌شوند).
pub fn describe(outbound: &str) -> Option<Endpoint> {
    let root: Value = serde_json::from_str(outbound).ok()?;
    let protocol = root.get("protocol")?.as_str()?;
    if !matches!(protocol, "vless" | "vmess" | "trojan") { return None; }
    let stream = root.get("streamSettings")?;
    let network = stream.get("network")?.as_str()?;
    if !matches!(network, "ws" | "httpupgrade" | "xhttp") { return None; }
    let security = stream.get("security").and_then(Value::as_str).unwrap_or("none");
    if !matches!(security, "tls" | "none" | "") { return None; }
    let tls = security == "tls";
    let transport = stream.get(format!("{network}Settings"));
    let s = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or("").to_string();
    let mut host = s(stream.get("tlsSettings").and_then(|t| t.get("serverName")));
    if host.is_empty() { host = s(transport.and_then(|t| t.get("headers")).and_then(|h| h.get("Host"))); }
    if host.is_empty() { host = s(transport.and_then(|t| t.get("host"))); }
    if host.is_empty() || host.contains('/') || host.contains(':') { return None; }
    let key = if protocol == "trojan" { "servers" } else { "vnext" };
    let list = root.get("settings")?.get(key)?.as_array()?;
    if list.len() != 1 { return None; }
    let port = list[0].get("port")?.as_u64()? as u16;
    let ok = if tls { HTTPS_PORTS.contains(&port) } else { HTTP_PORTS.contains(&port) };
    if !ok { return None; }
    Some(Endpoint { ip: list[0].get("address")?.as_str()?.to_string(), port, tls })
}

/// پورتِ اسکن‌شده فقط برای TLS و فقط از فهرست HTTPS مجاز است.
pub fn applicable_port(e: &Endpoint, scanned: u16) -> u16 {
    if e.tls && HTTPS_PORTS.contains(&scanned) { scanned } else { e.port }
}

pub fn replace_endpoint(space: &Space, outbound: &str, ip: &str, port: u16) -> Result<String, &'static str> {
    if !space.is_cloudflare_ip(ip) { return Err("not a Cloudflare IP"); }
    let e = describe(outbound).ok_or("unsupported config")?;
    let allowed = if e.tls { HTTPS_PORTS.contains(&port) } else { port == e.port };
    if !allowed { return Err("port not allowed"); }
    let mut root: Value = serde_json::from_str(outbound).map_err(|_| "bad json")?;
    let key = if root["protocol"] == "trojan" { "servers" } else { "vnext" };
    let first = root["settings"][key][0].as_object_mut().ok_or("bad json")?;
    first.insert("address".into(), json!(ip));
    first.insert("port".into(), json!(port));
    Ok(root.to_string())
}

/// کانفیگ تازه پس از تعویض نشانی: همان هویت، `raw` = Xray JSON تک-outbound.
pub fn rewritten(space: &Space, expected: &CustomConfig, pick: &Pick) -> Result<CustomConfig, &'static str> {
    let outbound = replace_endpoint(space, &expected.outbound, &pick.ip, pick.port)?;
    let ob: Value = serde_json::from_str(&outbound).map_err(|_| "bad json")?;
    let mut next = expected.clone();
    next.raw = json!({ "outbounds": [ob] }).to_string();
    next.outbound = outbound;
    next.server = format!("{}:{}", pick.ip, pick.port);
    next.format = super::ConfigFormat::XrayJson;
    Ok(next)
}

pub fn supported(c: &CustomConfig, now: i64) -> bool {
    !c.locked && !c.is_expired(now) && describe(&c.outbound).is_some()
}


// ───────────────────────────── کاوش (probe) ─────────────────────────────

const SNI_HOSTS: [&str; 5] = [
    "speed.cloudflare.com", "www.cloudflare.com", "cloudflare.com", "blog.cloudflare.com", "1.1.1.1.cdn.cloudflare.net",
];
const TRACE_HOSTS: [&str; 3] = ["speed.cloudflare.com", "www.cloudflare.com", "cloudflare.com"];
const HTTP_HOST: &str = "speed.cloudflare.com";
const MICRO_BYTES: u64 = 1_000_000;

pub fn budget_dial(t: u64) -> u64 { (t / 4).max(2000.min(t)) }
pub fn budget_handshake(t: u64) -> u64 { (t / 2).max(3000.min(t)) }
pub fn budget_http(t: u64) -> u64 { (t / 4).max(1500) }

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeResult {
    pub ip: String,
    pub latency_ms: i64,
    pub port: u16,
    pub success_rate: f32,
    pub jitter_ms: i64,
    pub download_bps: u64,
    pub colo: String,
}

pub fn latency_bucket(ms: i64) -> u8 {
    if ms < 0 { 3 } else if ms < 600 { 0 } else if ms < 1000 { 1 } else { 2 }
}

/// اول سطل تأخیر، بعد نرخ موفقیت، سرعت دانلود، تأخیر و jitter.
pub fn rank(a: &ProbeResult, b: &ProbeResult) -> std::cmp::Ordering {
    latency_bucket(a.latency_ms).cmp(&latency_bucket(b.latency_ms))
        .then(b.success_rate.partial_cmp(&a.success_rate).unwrap_or(std::cmp::Ordering::Equal))
        .then(b.download_bps.cmp(&a.download_bps))
        .then(a.latency_ms.cmp(&b.latency_ms))
        .then(a.jitter_ms.cmp(&b.jitter_ms))
}

pub fn parse_colo_ray(ray: &str) -> String {
    let parts: Vec<&str> = ray.split('-').collect();
    if parts.len() < 2 { return String::new(); }
    let c = parts[parts.len() - 1].trim();
    if c.len() >= 3 && c.is_char_boundary(3) { c[..3].to_uppercase() } else { String::new() }
}

pub fn parse_colo_body(body: &str) -> String {
    for line in body.split('\n') {
        let l = line.trim_end_matches('\r');
        if let Some(v) = l.strip_prefix("colo=") { return v.trim().to_string(); }
    }
    String::new()
}

fn header_value(headers: &str, name: &str) -> String {
    for line in headers.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) { return v.trim().to_string(); }
        }
    }
    String::new()
}

type Tls = native_tls::TlsStream<TcpStream>;

/// اتصال TCP + TLS (SNI=host، بدون اعتبارسنجی گواهی؛ سلامت با colo اثبات می‌شود).
fn open_tls(cancel: &Arc<Cancel>, ip: &str, port: u16, host: &str, timeout_ms: u64) -> Option<(Tls, super::cancel::Tracked)> {
    if cancel.stopped() { return None; }
    let addr: SocketAddr = format!("{ip}:{port}").parse().ok()?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_millis(budget_dial(timeout_ms))).ok()?;
    let guard = cancel.track(&tcp).ok()?;
    let hs = Duration::from_millis(budget_handshake(timeout_ms));
    tcp.set_read_timeout(Some(hs)).ok()?;
    tcp.set_write_timeout(Some(hs)).ok()?;
    let _ = tcp.set_nodelay(true);
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let tls = connector.connect(host, tcp).ok()?;
    Some((tls, guard))
}

fn read_headers(s: &mut Tls) -> String {
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while head.len() < 16384 {
        match s.read(&mut one) {
            Ok(1) => {
                head.push(one[0]);
                if head.ends_with(b"\r\n\r\n") { break; }
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn request(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows) Aether/CleanIpScanner\r\nAccept: */*\r\nConnection: close\r\n\r\n")
}

#[derive(Debug, Default, Clone)]
struct Trace { latency_ms: i64, tls_ok: bool, status: u16, colo: String }

fn probe_trace(cancel: &Arc<Cancel>, ip: &str, port: u16, host: &str, timeout_ms: u64) -> Trace {
    let start = Instant::now();
    let Some((mut tls, _g)) = open_tls(cancel, ip, port, host, timeout_ms) else { return Trace::default() };
    let http = Duration::from_millis(budget_http(timeout_ms));
    let _ = tls.get_ref().set_read_timeout(Some(http));
    let _ = tls.get_ref().set_write_timeout(Some(http));
    if tls.write_all(request(host, "/cdn-cgi/trace").as_bytes()).and_then(|_| tls.flush()).is_err() {
        return Trace { tls_ok: true, ..Default::default() };
    }
    let head = read_headers(&mut tls);
    if head.is_empty() { return Trace { tls_ok: true, ..Default::default() }; }
    let status = head.split("\r\n").next().unwrap_or("").split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut colo = parse_colo_ray(&header_value(&head, "CF-Ray"));
    let mut body = Vec::new();
    let mut buf = [0u8; 1024];
    while body.len() < 4096 {
        match tls.read(&mut buf) { Ok(n) if n > 0 => body.extend_from_slice(&buf[..n]), _ => break }
    }
    let from_body = parse_colo_body(&String::from_utf8_lossy(&body));
    if !from_body.is_empty() { colo = from_body; }
    Trace { latency_ms: start.elapsed().as_millis() as i64, tls_ok: true, status, colo }
}

/// نگه‌داشتن ~۱.۵ ثانیه بی‌داده: timeout = زنده؛ RST/EOF = DPI کشته.
fn probe_stability(cancel: &Arc<Cancel>, ip: &str, port: u16, host: &str, timeout_ms: u64) -> bool {
    let Some((mut tls, _g)) = open_tls(cancel, ip, port, host, timeout_ms) else { return false };
    let _ = tls.get_ref().set_read_timeout(Some(Duration::from_millis(1500)));
    let mut b = [0u8; 1];
    match tls.read(&mut b) {
        Ok(n) => n > 0,
        Err(e) => matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
    }
}

/// بایت‌های واقعاً دریافتی تقسیم بر زمان؛ شکست = ۰ (هرگز عدد ساختگی).
fn probe_download(cancel: &Arc<Cancel>, ip: &str, port: u16, timeout_ms: u64, bytes: u64) -> u64 {
    let Some((mut tls, _g)) = open_tls(cancel, ip, port, HTTP_HOST, timeout_ms) else { return 0 };
    let _ = tls.get_ref().set_read_timeout(Some(Duration::from_millis(budget_http(timeout_ms))));
    if tls.write_all(request(HTTP_HOST, &format!("/__down?bytes={bytes}")).as_bytes()).is_err() { return 0; }
    let head = read_headers(&mut tls);
    let status: u16 = head.split("\r\n").next().unwrap_or("").split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    if !(200..400).contains(&status) { return 0; }
    let window = Duration::from_millis(timeout_ms);
    let start = Instant::now();
    let mut got = 0u64;
    let mut buf = [0u8; 32 * 1024];
    while got < bytes && start.elapsed() < window && !cancel.stopped() {
        match tls.read(&mut buf) { Ok(n) if n > 0 => got += n as u64, _ => break }
    }
    let el = start.elapsed().as_nanos() as f64;
    if got == 0 || el <= 0.0 { 0 } else { (got as f64 * 1e9 / el) as u64 }
}

#[derive(Default)]
pub struct Counters { pub tls_ok: AtomicUsize, pub trace_ok: AtomicUsize }

/// کاوش کامل یک IP روی پورت‌های داده‌شده؛ اولین پورت سالم برنده است.
pub fn probe_best(cancel: &Arc<Cancel>, ip: &str, ports: &[u16], timeout_ms: u64, tries: usize, c: &Counters) -> Option<ProbeResult> {
    let mut saw_tls = false;
    let mut best = None;
    for (pi, &port) in ports.iter().enumerate() {
        if cancel.stopped() { return None; }
        let mut lats: Vec<i64> = Vec::new();
        let mut colo = String::new();
        let mut port_tls = false;
        for t in 0..tries {
            let sni = SNI_HOSTS[(pi + t) % SNI_HOSTS.len()];
            let mut hosts = vec![sni];
            hosts.extend(TRACE_HOSTS.iter().copied().filter(|h| *h != sni));
            let mut winner: Option<(&str, Trace)> = None;
            for h in hosts {
                if cancel.stopped() { return None; }
                let tr = probe_trace(cancel, ip, port, h, timeout_ms);
                port_tls |= tr.tls_ok;
                if (200..400).contains(&tr.status) && !tr.colo.is_empty() { winner = Some((h, tr)); break; }
            }
            if let Some((h, tr)) = winner {
                if probe_stability(cancel, ip, port, h, timeout_ms) {
                    lats.push(tr.latency_ms);
                    if colo.is_empty() { colo = tr.colo; }
                }
            }
            if t == 0 && !port_tls { break; }
        }
        saw_tls |= port_tls;
        if lats.is_empty() { continue; }
        let mean = lats.iter().sum::<i64>() as f64 / lats.len() as f64;
        let jitter = if lats.len() > 1 {
            (lats.iter().map(|l| (*l as f64 - mean).powi(2)).sum::<f64>() / lats.len() as f64).sqrt() as i64
        } else { 0 };
        let bps = probe_download(cancel, ip, port, (timeout_ms * 2).max(8000), MICRO_BYTES);
        best = Some(ProbeResult {
            ip: ip.to_string(), latency_ms: mean as i64, port,
            success_rate: lats.len() as f32 / tries as f32, jitter_ms: jitter, download_bps: bps, colo,
        });
        break;
    }
    if saw_tls { c.tls_ok.fetch_add(1, Ordering::Relaxed); }
    if best.is_some() { c.trace_ok.fetch_add(1, Ordering::Relaxed); }
    best
}

/// کاوش موازی (حداکثر `parallelism` رشته)؛ `on_one` پس از هر IP صدا زده می‌شود.
pub fn probe_batch<F>(
    cancel: &Arc<Cancel>, ips: &[String], parallelism: usize,
    prober: &(dyn Fn(&str) -> Option<ProbeResult> + Sync), on_one: F,
) -> Vec<ProbeResult>
where F: Fn(Option<&ProbeResult>) + Sync {
    let next = AtomicUsize::new(0);
    let out = Mutex::new(Vec::new());
    let workers = parallelism.clamp(1, 64).min(ips.len().max(1));
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| loop {
                if cancel.stopped() { break; }
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= ips.len() { break; }
                let r = prober(&ips[i]);
                on_one(r.as_ref());
                if let Some(r) = r { out.lock().unwrap_or_else(|e| e.into_inner()).push(r); }
            });
        }
    });
    out.into_inner().unwrap_or_else(|e| e.into_inner())
}


// ───────────────────────────── استخر اسکن ─────────────────────────────

pub struct PoolParams {
    pub count: usize,
    pub ports: Vec<u16>,
    pub parallelism: usize,
    pub candidate_budget: usize,
    pub neighbor_per_hit: usize,
    pub max_rounds: usize,
}

/// تا `count` IP سالم و متمایز، بهترین اول. پیشرفت ۰..۹۹ با max(سالم/کف، کاوش‌شده/بودجه).
pub fn scan_pool(
    cancel: &Arc<Cancel>, space: &Space, p: &PoolParams, exclude: &HashSet<String>,
    prober: &(dyn Fn(&str) -> Option<ProbeResult> + Sync), on_progress: &(dyn Fn(u32) + Sync),
) -> Vec<ProbeResult> {
    if p.count == 0 || p.ports.is_empty() || !p.ports.iter().all(|x| DEFAULT_PORTS.contains(x)) { return vec![]; }
    let budget = p.candidate_budget.clamp(48, 600).max(p.count);
    let floor = p.count.max((p.count * 2).min(24));
    let mut healthy: Vec<ProbeResult> = Vec::new();
    let known = Mutex::new(HashSet::<String>::new());
    let mut seen: HashSet<String> = exclude.clone();
    let batch_size = (p.count * 6).clamp(48, budget);
    let probed_total = AtomicUsize::new(0);
    let unique = AtomicUsize::new(0);
    let report = || {
        let by_h = if floor > 0 { unique.load(Ordering::Relaxed) * 100 / floor } else { 0 };
        let by_b = probed_total.load(Ordering::Relaxed) * 100 / budget;
        on_progress(by_h.max(by_b).min(99) as u32);
    };
    let collect = |r: Option<&ProbeResult>| {
        probed_total.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = r {
            if known.lock().unwrap_or_else(|e| e.into_inner()).insert(r.ip.clone()) { unique.fetch_add(1, Ordering::Relaxed); }
        }
        report();
    };
    let mut probed = 0usize;
    let mut round = 0usize;
    while healthy.len() < floor && probed < budget && round < p.max_rounds && !cancel.stopped() {
        round += 1;
        let remaining = budget - probed;
        let cands = space.sample_candidates(batch_size.min(remaining).max(1), &seen);
        if cands.is_empty() { break; }
        seen.extend(cands.iter().cloned());
        probed += cands.len();
        let results = probe_batch(cancel, &cands, p.parallelism, prober, &collect);
        for r in &results { if !healthy.iter().any(|h| h.ip == r.ip) { healthy.push(r.clone()); } }
        let room = budget.saturating_sub(probed);
        if healthy.len() < floor && room > 0 && !results.is_empty() && !cancel.stopped() {
            let mut neigh: Vec<String> = Vec::new();
            for r in &results {
                for n in space.neighbors_around(&r.ip, NEIGHBOR_RADIUS, p.neighbor_per_hit) {
                    if !seen.contains(&n) && !neigh.contains(&n) { neigh.push(n); }
                }
            }
            neigh.truncate(room);
            seen.extend(neigh.iter().cloned());
            probed += neigh.len();
            if !neigh.is_empty() {
                for r in probe_batch(cancel, &neigh, p.parallelism, prober, &collect) {
                    if !healthy.iter().any(|h| h.ip == r.ip) { healthy.push(r); }
                }
            }
        }
        report();
    }
    healthy.sort_by(rank);
    let (fast, slow): (Vec<_>, Vec<_>) = healthy.into_iter().partition(|r| (0..=MAX_ACCEPTABLE_LATENCY_MS).contains(&r.latency_ms));
    fast.into_iter().chain(slow).take(p.count).collect()
}

// ───────────────────────────── اعتبارسنجی نهایی ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Candidate { pub ip: String, pub port: u16 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick { pub ip: String, pub port: u16, pub ping_ms: i64 }

/// کاوش فقط ترتیب می‌دهد؛ برنده باید `CONFIRM_ROUNDS` بار ترافیک واقعی را رد کند (میانه = پینگ).
pub fn select(
    cancel: &Arc<Cancel>, candidates: &[Candidate], manual_ceiling: Option<u32>,
    measure: &mut dyn FnMut(&[Candidate]) -> Vec<i64>, progress: &mut dyn FnMut(usize, usize),
) -> Option<Pick> {
    let deadline = Instant::now() + VALIDATE_BUDGET;
    let ceiling: i64 = manual_ceiling.map(|c| c.clamp(50, 5000) as i64).unwrap_or(i64::MAX);
    let mut list: Vec<Candidate> = Vec::new();
    for c in candidates { if !list.contains(c) { list.push(c.clone()); } }
    list.truncate(MAX_CANDIDATES);
    let confirm = |c: &Candidate, measure: &mut dyn FnMut(&[Candidate]) -> Vec<i64>| -> Option<Pick> {
        let mut readings = Vec::new();
        for _ in 0..CONFIRM_ROUNDS {
            if cancel.stopped() || Instant::now() > deadline { return None; }
            let r = *measure(std::slice::from_ref(c)).first()?;
            if r < 0 || r > ceiling { return None; }
            readings.push(r);
        }
        readings.sort();
        Some(Pick { ip: c.ip.clone(), port: c.port, ping_ms: readings[readings.len() / 2] })
    };
    let mut passing: Vec<(Candidate, i64)> = Vec::new();
    let mut done = 0;
    for batch in list.chunks(VALIDATE_BATCH) {
        if cancel.stopped() || Instant::now() > deadline { return None; }
        let readings = measure(batch);
        for (i, c) in batch.iter().enumerate() {
            let ms = readings.get(i).copied().unwrap_or(-1);
            if (0..=ceiling).contains(&ms) {
                if manual_ceiling.is_some() {
                    if let Some(p) = confirm(c, measure) { return Some(p); }
                } else {
                    passing.push((c.clone(), ms));
                }
            }
            done += 1;
            progress(done, list.len());
        }
    }
    passing.sort_by_key(|(_, ms)| *ms);
    for (c, _) in passing {
        if let Some(p) = confirm(&c, measure) { return Some(p); }
    }
    None
}

// ───────────────────────────── موتور چرخهٔ اسکن ─────────────────────────────

pub trait Backend {
    fn current(&self) -> Vec<CustomConfig>;
    fn allowed(&self) -> bool;
    fn discover(&self, config: &CustomConfig, excluded: &HashSet<String>, progress: &(dyn Fn(u32) + Sync)) -> Vec<Candidate>;
    fn measure(&self, config: &CustomConfig, candidates: &[Candidate]) -> Vec<i64>;
    fn commit(&self, expected: &CustomConfig, pick: &Pick) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome { Applied, Unchanged, Failed, Cancelled }
impl Outcome {
    pub fn name(self) -> &'static str {
        match self { Self::Applied => "applied", Self::Unchanged => "unchanged", Self::Failed => "failed", Self::Cancelled => "cancelled" }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub config_id: String,
    pub protocol: String,
    pub previous: String,
    pub next: Option<String>,
    pub ping_ms: Option<i64>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone)]
pub struct Progress { pub target_id: String, pub percent: u32, pub validating: bool, pub completed: usize, pub total: usize }

pub fn run(
    cancel: &Arc<Cancel>, backend: &dyn Backend, targets: &[CustomConfig], manual_ceiling: Option<u32>,
    on_progress: &(dyn Fn(Progress) + Sync), on_result: &dyn Fn(Report),
) {
    let mut servers: Vec<&CustomConfig> = Vec::new();
    for t in targets { if !servers.iter().any(|s| s.id == t.id) { servers.push(t); } }
    let mut assigned: HashSet<String> = HashSet::new();
    let total = servers.len();
    for (index, server) in servers.iter().enumerate() {
        let prog = |v: u32, validating: bool| on_progress(Progress {
            target_id: server.id.clone(), percent: v.min(100), validating, completed: index, total,
        });
        let report = |outcome: Outcome, pick: Option<&Pick>| Report {
            config_id: server.id.clone(),
            protocol: server.protocol.short().to_string(),
            previous: if server.locked { String::new() } else {
                describe(&server.outbound).map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_else(|| server.server.clone())
            },
            next: pick.map(|p| format!("{}:{}", p.ip, p.port)),
            ping_ms: pick.map(|p| p.ping_ms),
            outcome,
        };
        if cancel.stopped() { on_result(report(Outcome::Cancelled, None)); return; }
        prog(0, false);
        let attempt = || -> Result<Option<Pick>, String> {
            if server.locked || server.is_expired(super::now_millis()) { return Err("not editable".into()); }
            let current = backend.current();
            if current.iter().find(|c| c.id == server.id) != Some(*server) { return Err("changed before scan".into()); }
            let mut excluded: HashSet<String> = current.iter().filter(|c| c.id != server.id)
                .filter_map(|c| describe(&c.outbound).map(|e| e.ip)).collect();
            excluded.extend(assigned.iter().cloned());
            let cands: Vec<Candidate> = backend.discover(server, &excluded, &|p| prog(p.min(100) * 70 / 100, false))
                .into_iter().filter(|c| !excluded.contains(&c.ip)).collect();
            if cancel.stopped() { return Ok(None); }
            prog(70, true);
            let mut measure = |b: &[Candidate]| backend.measure(server, b);
            let mut progress = |d: usize, t: usize| prog(70 + (d * 29 / t.max(1)) as u32, true);
            Ok(select(cancel, &cands, manual_ceiling, &mut measure, &mut progress))
        };
        match attempt() {
            Err(_) => on_result(report(Outcome::Failed, None)),
            Ok(_) if cancel.stopped() => { on_result(report(Outcome::Cancelled, None)); return; }
            Ok(None) => { prog(100, false); on_result(report(Outcome::Unchanged, None)); }
            Ok(Some(pick)) => {
                // موفقیت و پینگ جدید فقط پس از ذخیرهٔ موفق منتشر می‌شود.
                match backend.commit(server, &pick) {
                    Ok(()) => { assigned.insert(pick.ip.clone()); prog(100, false); on_result(report(Outcome::Applied, Some(&pick))); }
                    Err(_) => on_result(report(Outcome::Failed, None)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom::{ConfigFormat, ConfigProtocol, ConfigSource};
    use std::cell::RefCell;

    fn ob(addr: &str, port: u16, security: &str) -> String {
        json!({"protocol":"vless","settings":{"vnext":[{"address":addr,"port":port,"users":[{"id":"u"}]}]},
          "streamSettings":{"network":"ws","security":security,
            "tlsSettings":{"serverName":"a.example.com"},"wsSettings":{"path":"/x","headers":{"Host":"a.example.com"}}}}).to_string()
    }
    fn cfg(id: &str, outbound: String) -> CustomConfig {
        CustomConfig { id: id.into(), name: id.into(), protocol: ConfigProtocol::Vless, format: ConfigFormat::Uri,
            source: ConfigSource::Link, outbound, raw: String::new(), server: "h:443".into(), locked: false,
            note: String::new(), expires_at: 0, mobile_only: false, added_at: 1 }
    }

    #[test]
    fn ranges_parse_cidr_span_single_and_reject_private() {
        let p = parse_ranges("104.16.0.0/30, 1.1.1.1-1.1.1.3 ۱.۰.۰.۱ 10.0.0.1 192.168.1.0/24 bad 1.2.3.4/7");
        assert_eq!(total(&p.ranges), 2 + 3 + 1);
        assert_eq!(p.invalid, vec!["10.0.0.1", "192.168.1.0/24", "bad", "1.2.3.4/7"]);
        assert_eq!(parse_ranges("104.16.0.0/32").ranges, vec![Range { start: 0x68100000, end: 0x68100000 }]);
        assert!(parse_ranges("127.0.0.1 224.0.0.1 0.0.0.0").ranges.is_empty());
        assert_eq!(parse_ranges("1.1.1.1 1.1.1.2 1.1.1.2").ranges.len(), 1, "adjacent/overlap merge");
        let many = (0..150).map(|i| format!("8.8.{}.1", i)).collect::<Vec<_>>().join(" ");
        let q = parse_ranges(&many);
        assert_eq!(q.ranges.len(), MAX_ENTRIES);
        assert_eq!(q.invalid.len(), 50);
    }

    #[test]
    fn endpoint_describe_replace_never_touches_identity() {
        let o = ob("1.2.3.4", 443, "tls");
        let e = describe(&o).unwrap();
        assert_eq!((e.ip.as_str(), e.port, e.tls), ("1.2.3.4", 443, true));
        let sp = Space::default();
        let n = replace_endpoint(&sp, &o, "104.16.1.1", 2053).unwrap();
        let v: Value = serde_json::from_str(&n).unwrap();
        assert_eq!(v["settings"]["vnext"][0]["address"], "104.16.1.1");
        assert_eq!(v["settings"]["vnext"][0]["port"], 2053);
        assert_eq!(v["streamSettings"]["tlsSettings"]["serverName"], "a.example.com");
        assert_eq!(v["settings"]["vnext"][0]["users"][0]["id"], "u");
        assert!(replace_endpoint(&sp, &o, "8.8.8.8", 443).is_err(), "non-Cloudflare");
        assert!(replace_endpoint(&sp, &o, "104.16.1.1", 80).is_err(), "http port on tls");
        assert!(describe(&ob("1.2.3.4", 443, "reality")).is_none());
        assert!(describe(&ob("1.2.3.4", 1234, "tls")).is_none());
        assert_eq!(applicable_port(&e, 8443), 8443);
        let plain = describe(&ob("1.2.3.4", 80, "none")).unwrap();
        assert_eq!(applicable_port(&plain, 8443), 80);
        let custom = Space { custom: parse_ranges("8.8.8.0/24").ranges };
        assert!(replace_endpoint(&custom, &o, "8.8.8.8", 443).is_ok(), "user range is allowed");
    }

    #[test]
    fn space_samples_stay_inside_and_enumerate_small_ranges() {
        let sp = Space::default();
        let s = sp.sample_candidates(100, &HashSet::new());
        assert_eq!(s.len(), 100);
        assert!(s.iter().all(|ip| sp.is_cloudflare_ip(ip)));
        let small = Space { custom: parse_ranges("9.9.9.1-9.9.9.5").ranges };
        let mut seen = HashSet::new();
        seen.insert("9.9.9.2".to_string());
        let c = small.sample_candidates(50, &seen);
        assert_eq!(c.len(), 4, "exhausts instead of looping forever");
        assert!(!c.contains(&"9.9.9.2".to_string()));
        let n = sp.neighbors_around("104.16.0.10", 32, 12);
        assert_eq!(n.len(), 12);
        assert!(n.iter().all(|x| sp.contains(ip_to_u64(x).unwrap())));
        assert!(small.neighbors_around("9.9.9.3", 32, 12).len() <= 4);
    }

    #[test]
    fn colo_and_budgets_and_rank() {
        assert_eq!(parse_colo_ray("8abc-fra"), "FRA");
        assert_eq!(parse_colo_ray("none"), "");
        assert_eq!(parse_colo_body("a=1\r\ncolo=AMS\r\nx=2"), "AMS");
        assert_eq!((budget_dial(5000), budget_handshake(5000), budget_http(5000)), (2000, 3000, 1500));
        assert_eq!(budget_dial(1000), 1000);
        let mk = |ms, dl| ProbeResult { ip: "x".into(), latency_ms: ms, port: 443, success_rate: 1.0, jitter_ms: 0, download_bps: dl, colo: "A".into() };
        let mut v = vec![mk(900, 9_000_000), mk(100, 1), mk(550, 5)];
        v.sort_by(rank);
        // همان سطل تأخیر: سرعت دانلود بیشتر مقدم؛ سطل کندتر همیشه آخر.
        assert_eq!(v.iter().map(|r| r.latency_ms).collect::<Vec<_>>(), vec![550, 100, 900]);
    }

    #[test]
    fn options_roundtrip_and_strict_ceiling() {
        let o = Options::from_json(&json!({"profile":"deep","manual":false,"ceiling":99999,"customEnabled":true,"customRanges":"1.1.1.1"}));
        assert_eq!((o.profile, o.manual, o.ceiling, o.custom_enabled), (ScanProfile::Deep, false, 5000, true));
        assert_eq!(Options::from_json(&o.to_json()), o);
        assert_eq!(Options::from_json(&json!({"profile":"???"})).profile, ScanProfile::Balanced);
        assert!(Options::validate_strict(&json!({"ceiling":10})).is_err());
        assert!(Options::validate_strict(&json!({"ceiling":2000})).is_ok());
        assert_eq!(ScanProfile::Fast.candidate_budget(), 120);
        assert_eq!(ScanProfile::Deep.timeout_ms(), 6000);
    }

    fn cand(ip: &str) -> Candidate { Candidate { ip: ip.into(), port: 443 } }

    #[test]
    fn select_requires_three_real_confirmations() {
        let c = Cancel::new();
        let calls = RefCell::new(0);
        // نامزد اول در دور اول خوب است ولی در تأیید می‌افتد؛ دومی پایدار است.
        let mut m = |b: &[Candidate]| -> Vec<i64> {
            *calls.borrow_mut() += 1;
            b.iter().map(|x| match x.ip.as_str() {
                "1.0.0.1" => if *calls.borrow() <= 1 { 100 } else { -1 },
                _ => 300,
            }).collect()
        };
        let pick = select(&c, &[cand("1.0.0.1"), cand("1.0.0.2")], None, &mut m, &mut |_, _| {}).unwrap();
        assert_eq!(pick.ip, "1.0.0.2");
        assert_eq!(pick.ping_ms, 300);
        // سقف دستی: همه بالاتر → هیچ
        let mut slow = |b: &[Candidate]| b.iter().map(|_| 900).collect::<Vec<i64>>();
        assert!(select(&c, &[cand("1.0.0.1")], Some(500), &mut slow, &mut |_, _| {}).is_none());
        assert!(select(&c, &[cand("1.0.0.1")], Some(1000), &mut slow, &mut |_, _| {}).is_some());
        // لغو
        c.cancel();
        assert!(select(&c, &[cand("1.0.0.1")], None, &mut slow, &mut |_, _| {}).is_none());
    }

    #[test]
    fn scan_pool_respects_budget_exclusion_and_progress() {
        let c = Cancel::new();
        let sp = Space::default();
        let prober = |ip: &str| -> Option<ProbeResult> {
            let last: u64 = ip_to_u64(ip).unwrap() & 3;
            if last == 0 { Some(ProbeResult { ip: ip.into(), latency_ms: 200 + last as i64, port: 443, success_rate: 1.0, jitter_ms: 0, download_bps: 1, colo: "X".into() }) } else { None }
        };
        let max = AtomicUsize::new(0);
        let prog = |p: u32| { assert!(p <= 99); max.fetch_max(p as usize, Ordering::Relaxed); };
        let mut ex = HashSet::new();
        ex.insert("104.16.0.4".to_string());
        let p = PoolParams { count: 3, ports: DEFAULT_PORTS.to_vec(), parallelism: 8, candidate_budget: 300, neighbor_per_hit: 12, max_rounds: 10 };
        let pool = scan_pool(&c, &sp, &p, &ex, &prober, &prog);
        assert_eq!(pool.len(), 3);
        assert!(pool.iter().all(|r| r.ip != "104.16.0.4"));
        let mut ips: Vec<_> = pool.iter().map(|r| r.ip.clone()).collect();
        ips.dedup();
        assert_eq!(ips.len(), 3);
        assert!(max.load(Ordering::Relaxed) > 0);
        // پورت نامعتبر → خالی
        let bad = PoolParams { ports: vec![80], ..p };
        assert!(scan_pool(&c, &sp, &bad, &ex, &prober, &|_| {}).is_empty());
    }

    struct Fake { configs: Mutex<Vec<CustomConfig>>, fail_commit: bool, pings: Vec<(String, i64)>, allowed: bool }
    impl Backend for Fake {
        fn current(&self) -> Vec<CustomConfig> { self.configs.lock().unwrap().clone() }
        fn allowed(&self) -> bool { self.allowed }
        fn discover(&self, _c: &CustomConfig, ex: &HashSet<String>, progress: &(dyn Fn(u32) + Sync)) -> Vec<Candidate> {
            progress(50);
            ["104.16.0.1", "104.16.0.2", "104.16.0.3"].iter().filter(|i| !ex.contains(**i)).map(|i| cand(i)).collect()
        }
        fn measure(&self, _c: &CustomConfig, cs: &[Candidate]) -> Vec<i64> {
            cs.iter().map(|c| self.pings.iter().find(|(i, _)| *i == c.ip).map(|(_, m)| *m).unwrap_or(-1)).collect()
        }
        fn commit(&self, expected: &CustomConfig, pick: &Pick) -> Result<(), String> {
            if self.fail_commit { return Err("disk".into()); }
            let mut g = self.configs.lock().unwrap();
            let c = g.iter_mut().find(|c| c.id == expected.id).ok_or("gone")?;
            c.outbound = replace_endpoint(&Space::default(), &c.outbound, &pick.ip, pick.port).map_err(|e| e.to_string())?;
            Ok(())
        }
    }

    fn run_fake(f: &Fake, ids: &[&str]) -> Vec<Report> {
        let targets: Vec<CustomConfig> = f.current().into_iter().filter(|c| ids.contains(&c.id.as_str())).collect();
        let out = RefCell::new(Vec::new());
        let last = Mutex::new(0u32);
        let c = Cancel::new();
        struct W<'a>(&'a Fake);
        impl<'a> Backend for W<'a> {
            fn current(&self) -> Vec<CustomConfig> { self.0.current() }
            fn allowed(&self) -> bool { self.0.allowed }
            fn discover(&self, c: &CustomConfig, e: &HashSet<String>, p: &(dyn Fn(u32) + Sync)) -> Vec<Candidate> { self.0.discover(c, e, p) }
            fn measure(&self, c: &CustomConfig, x: &[Candidate]) -> Vec<i64> { self.0.measure(c, x) }
            fn commit(&self, a: &CustomConfig, b: &Pick) -> Result<(), String> { self.0.commit(a, b) }
        }
        run(&c, &W(f), &targets, None, &|p| { assert!(p.percent <= 100); *last.lock().unwrap() = p.percent; }, &|r| out.borrow_mut().push(r));
        out.into_inner()
    }

    #[test]
    fn engine_gives_each_server_its_own_ip_and_reports_honestly() {
        let f = Fake {
            configs: Mutex::new(vec![cfg("a", ob("1.2.3.4", 443, "tls")), cfg("b", ob("1.2.3.5", 443, "tls")), cfg("c", ob("9.9.9.9", 1234, "tls"))]),
            fail_commit: false, allowed: true,
            pings: vec![("104.16.0.1".into(), 100), ("104.16.0.2".into(), 150), ("104.16.0.3".into(), 200)],
        };
        let r = run_fake(&f, &["a", "b", "c"]);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].outcome, Outcome::Applied);
        assert_eq!(r[0].next.as_deref(), Some("104.16.0.1:443"));
        assert_eq!(r[1].next.as_deref(), Some("104.16.0.2:443"), "unique per server");
        assert_eq!(r[2].outcome, Outcome::Failed);
        assert_eq!(r[0].previous, "1.2.3.4:443");
        let g = f.current();
        assert_eq!(describe(&g[0].outbound).unwrap().ip, "104.16.0.1");
        assert_eq!(describe(&g[2].outbound), None);
    }

    #[test]
    fn engine_does_not_publish_success_when_persistence_fails() {
        let f = Fake { configs: Mutex::new(vec![cfg("a", ob("1.2.3.4", 443, "tls"))]), fail_commit: true, allowed: true, pings: vec![("104.16.0.1".into(), 100)] };
        let r = run_fake(&f, &["a"]);
        assert_eq!(r[0].outcome, Outcome::Failed);
        assert!(r[0].next.is_none() && r[0].ping_ms.is_none());
        let none = Fake { configs: Mutex::new(vec![cfg("a", ob("1.2.3.4", 443, "tls"))]), fail_commit: false, allowed: true, pings: vec![] };
        assert_eq!(run_fake(&none, &["a"])[0].outcome, Outcome::Unchanged);
        assert_eq!(describe(&none.current()[0].outbound).unwrap().ip, "1.2.3.4");
    }

    #[test]
    fn rewritten_config_reparses_to_same_outbound_and_keeps_identity() {
        let c = cfg("a", ob("1.2.3.4", 443, "tls"));
        let pick = Pick { ip: "104.16.9.9".into(), port: 8443, ping_ms: 120 };
        let n = rewritten(&Space::default(), &c, &pick).unwrap();
        assert_eq!((n.id.as_str(), n.name.as_str(), n.added_at), ("a", "a", 1));
        assert_eq!(n.server, "104.16.9.9:8443");
        assert_eq!(n.format, ConfigFormat::XrayJson);
        let again = crate::custom::parser::parse(&n.raw, ConfigSource::Link, None, 1).unwrap();
        let (a, b): (Value, Value) = (serde_json::from_str(&again[0].outbound).unwrap(), serde_json::from_str(&n.outbound).unwrap());
        assert_eq!(a["settings"]["vnext"][0]["address"], b["settings"]["vnext"][0]["address"]);
        assert_eq!(a["settings"]["vnext"][0]["port"], 8443);
        assert_eq!(a["streamSettings"]["tlsSettings"]["serverName"], "a.example.com");
    }

    #[test]
    fn probe_of_closed_port_fails_fast_and_honestly() {
        let c = Cancel::new();
        let counters = Counters::default();
        let t = Instant::now();
        assert!(probe_best(&c, "127.0.0.1", &[1], 1000, 1, &counters).is_none());
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(counters.trace_ok.load(Ordering::Relaxed), 0);
        c.cancel();
        assert!(probe_best(&c, "127.0.0.1", &[443], 1000, 1, &counters).is_none());
    }

    #[test]
    fn engine_skips_locked_and_expired() {
        let mut l = cfg("l", ob("1.2.3.4", 443, "tls"));
        l.locked = true;
        assert!(!supported(&l, 0));
        let mut e = cfg("e", ob("1.2.3.4", 443, "tls"));
        e.expires_at = 5;
        assert!(!supported(&e, 10));
        assert!(supported(&cfg("ok", ob("1.2.3.4", 443, "tls")), 10));
    }
}
