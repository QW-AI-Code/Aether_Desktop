//! هر چیزی که کاربر می‌چسباند یا بارگذاری می‌کند را به کانفیگِ ذخیره‌شدنی تبدیل
//! می‌کند — پورتِ **۱:۱** از `ConfigParser.kt` (و `NpvtLock`) نسخهٔ اندروید ۱.۵.۰.
//!
//! ورودیِ پذیرفته‌شده (خودکار تشخیص داده می‌شود):
//!  * لینک‌های اشتراک: `vless://`، `vmess://` (JSONِ base64ِ v2rayN و شکلِ URI)،
//!    `trojan://`، `ss://` (SIP002 و قدیمی)، `socks://` / `socks5://`،
//!    `wireguard://` / `wg://` — هر سطر یکی، به هر تعداد؛
//!  * بدنهٔ base64ِ یک اشتراک که چنین لینک‌هایی دارد؛
//!  * یک کانفیگِ JSONِ Xray / V2Ray (outboundِ پراکسی‌اش برداشته می‌شود) یا یک outboundِ تنها؛
//!  * فایلِ `.npvt` ناپسترنت (`NPVT1...`)، و نیز `npvt://<base64 یا متن>`.
//!
//! تنها تفاوتِ عمدی با موبایل: کانفیگِ npvtی که نویسنده‌اش آن را «فقط اینترنتِ
//! موبایل» کرده، در ویندوز **هنگامِ ورود رد می‌شود** (رایانه اینترنتِ موبایل
//! ندارد و برنامه نمی‌تواند قفلِ نویسنده را رعایت کند).
//!
//! بدونِ هیچ وابستگیِ ویندوزی، تا همهٔ قاعده‌ها با `cargo test` روی هر ماشینی آزموده شوند.

use super::npvt;
use super::{ConfigFormat, ConfigProtocol, ConfigSource, CustomConfig, MAX_NAME, MAX_NOTE};
use serde_json::{json, Map, Value};

/// کانفیگی که پذیرفته نشد، با دلیلی که رابط کاربری همان‌طور نشان می‌دهد.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    Invalid(String),
    /// فایلِ npvtِ رمزدار وقتی رمز داده نشده (`wrong=false`) یا غلط است (`wrong=true`).
    Password { wrong: bool },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Invalid(m) => f.write_str(m),
            ImportError::Password { wrong: true } => f.write_str("wrong password for this npvt config"),
            ImportError::Password { wrong: false } => {
                f.write_str("this npvt config is password protected")
            }
        }
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, ImportError> {
    Err(ImportError::Invalid(msg.into()))
}

type R<T> = Result<T, ImportError>;

/// سطرهایی که این واردکننده به‌عنوانِ لینکِ اشتراک می‌شناسد.
const LINK_SCHEMES: [&str; 8] = [
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "socks://",
    "socks5://",
    "wireguard://",
    "wg://",
];

pub fn is_share_link(text: &str) -> bool {
    let t = text.trim().to_lowercase();
    LINK_SCHEMES.iter().any(|s| t.starts_with(s))
}

// ------------------------------------------------------------ helpers (Kotlin)

fn before<'a>(s: &'a str, d: &str) -> &'a str {
    s.split_once(d).map(|x| x.0).unwrap_or(s)
}
fn after<'a>(s: &'a str, d: &str) -> &'a str {
    s.split_once(d).map(|x| x.1).unwrap_or(s)
}
fn after_or<'a>(s: &'a str, d: &str, missing: &'a str) -> &'a str {
    s.split_once(d).map(|x| x.1).unwrap_or(missing)
}
fn trim_end_char(s: &str, c: char) -> &str {
    s.trim_end_matches(c)
}
fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
/// `String.lines()` در Kotlin: `\r\n`، `\n` و `\r`.
fn kotlin_lines(s: &str) -> Vec<&str> {
    s.split("\r\n").flat_map(|l| l.split(['\n', '\r'])).collect()
}

/// `JsonPrimitive.contentOrNull`: رشته همان، عدد/بولی به متن، null و غیرپرایمیتیو → None.
fn prim(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn prim_int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// `URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")`، با بازگشت به خودِ متن در صورتِ خطا.
fn decode(s: &str) -> String {
    url_decode(s).unwrap_or_else(|| s.to_string())
}

fn url_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn is_iso_control(c: char) -> bool {
    let u = c as u32;
    u <= 0x1F || (0x7F..=0x9F).contains(&u)
}

fn looks_base64(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

/// base64ِ استاندارد یا URL-safe، با یا بی پَدینگ؛ `None` وقتی متنِ base64 نیست.
pub fn decode_loose(text: &str) -> Option<String> {
    let clean: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || !looks_base64(&clean) {
        return None;
    }
    let core = clean.trim_end_matches('=');
    let padded = format!("{core}{}", "=".repeat((4 - core.len() % 4) % 4));
    let normal = padded.replace('-', "+").replace('_', "/");
    let bytes = npvt::b64_decode_strict(&normal, npvt::STD_ALPHABET)?;
    let s = String::from_utf8_lossy(&bytes).into_owned();
    if s
        .chars()
        .any(|c| c == '\u{FFFD}' || (is_iso_control(c) && c != '\n' && c != '\r' && c != '\t'))
    {
        return None;
    }
    Some(s)
}

pub fn split_host_port(text: &str) -> R<(String, u16)> {
    let t = text.trim();
    let (host, port_text) = if let Some(rest) = t.strip_prefix('[') {
        let Some(close) = t.find(']').filter(|i| *i > 0) else {
            return err("bad IPv6 address");
        };
        let _ = rest;
        (t[1..close].to_string(), after_or(t, "]:", "").to_string())
    } else {
        match t.rfind(':') {
            Some(i) => (t[..i].to_string(), t[i + 1..].to_string()),
            None => (t.to_string(), String::new()),
        }
    };
    let port = match port_text.trim().parse::<i64>() {
        Ok(p) if (1..=65535).contains(&p) => p as u16,
        _ => return err("link has no valid port"),
    };
    if host.trim().is_empty() {
        return err("link has no server address");
    }
    Ok((host.trim().to_string(), port))
}

pub fn host_port(host: &str, port: i64) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn is_domain(host: &str) -> bool {
    host.chars().any(char::is_alphabetic) && !host.contains(':')
}

fn require_uuid_like(id: &str) -> R<()> {
    if id.trim().is_empty() {
        return err("link has no user id");
    }
    Ok(())
}

// ------------------------------------------------------------------ parse

/// Binary input must be dispatched before UTF-8 conversion (NPVS contains arbitrary bytes).
pub fn parse_bytes(bytes: &[u8], source: ConfigSource, password: Option<&str>, now: i64) -> R<Vec<CustomConfig>> {
    if bytes.len() > 2 * 1024 * 1024 { return err("file is larger than 2 MB"); }
    // BOM یا فاصله‌ای که برخی ابزارها/انتقال‌ها پیش از سرآیند می‌گذارند.
    let trimmed: &[u8] = {
        let mut b = bytes;
        if b.starts_with(&[0xEF, 0xBB, 0xBF]) { b = &b[3..]; }
        while let [first, rest @ ..] = b { if first.is_ascii_whitespace() { b = rest } else { break } }
        b
    };
    if npvt::is_binary(trimmed) {
        return parse_decoded_npvt(npvt::decode_bytes(trimmed,password)?, "", source,password,now);
    }
    let text=std::str::from_utf8(bytes).map_err(|_|ImportError::Invalid("file is not UTF-8 text".into()))?;
    // Base64-wrapped binary NPVS (some messengers/exports re-encode the file as text).
    let compact: String = text.chars().filter(|c| !c.is_whitespace() && *c != '\u{feff}').collect();
    if compact.len() >= 12 && compact.len() % 4 != 1 && compact.starts_with("TlBWU") {
        if let Some(raw) = npvt::decode_base64(&compact) {
            if npvt::is_binary(&raw) {
                return parse_decoded_npvt(npvt::decode_bytes(&raw,password)?, "", source,password,now);
            }
        }
    }
    parse(text,source,password,now)
}

/// `input` را پارس می‌کند. دست‌کم یک کانفیگ برمی‌گرداند یا خطا. سطرهایی که
/// کانفیگ نیستند رد می‌شوند به شرطی که دست‌کم یک سطر کانفیگ بوده باشد.
pub fn parse(
    input: &str,
    source: ConfigSource,
    npvt_password: Option<&str>,
    now: i64,
) -> R<Vec<CustomConfig>> {
    let text = input.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return err("empty input");
    }

    if text.to_lowercase().starts_with("npvt://") {
        let body = text["npvt://".len()..].trim();
        let decoded = decode_loose(body)
            .filter(|d| npvt::looks_like(d))
            .or_else(|| url_decode(body).filter(|d| npvt::looks_like(d)));
        let Some(decoded) = decoded else {
            return err("npvt link does not contain an npvt config");
        };
        return parse_npvt(&decoded, source, npvt_password, now);
    }
    if super::npvo::looks_like(text) {
        let decoded = super::npvo::decode(text)?;
        return parse_decoded_npvt(decoded, text, source, npvt_password, now);
    }
    if npvt::looks_like(text) {
        return parse_npvt(text, source, npvt_password, now);
    }
    if text.starts_with('{') || text.starts_with('[') {
        return parse_json(text, source, now);
    }

    let lines: Vec<&str> = kotlin_lines(text)
        .into_iter()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let links: Vec<&str> = lines.iter().copied().filter(|l| is_share_link(l)).collect();
    if links.is_empty() {
        // بدنهٔ یک اشتراک: کلِ متن base64ِ فهرستی از لینک‌هاست.
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(decoded) = decode_loose(&compact) {
            let lower = decoded.to_lowercase();
            if decoded != text
                && (LINK_SCHEMES.iter().any(|s| lower.contains(s))
                    || npvt::looks_like(&decoded)
                    || decoded.trim_start().starts_with('{'))
            {
                return parse(&decoded, source, npvt_password, now);
            }
        }
        return err("no supported config found");
    }
    let mut out = Vec::new();
    let mut first_error: Option<String> = None;
    for link in links {
        match parse_link(link, source, now) {
            Ok(c) => out.push(c),
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        return err(first_error.unwrap_or_else(|| "no supported config found".into()));
    }
    Ok(out)
}

// ------------------------------------------------------------------ links

struct Built {
    protocol: ConfigProtocol,
    outbound: Value,
    host: String,
    port: u16,
    name: String,
}

/// یک لینکِ اشتراک → یک کانفیگ.
pub fn parse_link(link: &str, source: ConfigSource, now: i64) -> R<CustomConfig> {
    let trimmed = link.trim();
    let scheme = before(trimmed, "://").to_lowercase();
    let built = match scheme.as_str() {
        "vless" => vless(&UriParts::of(trimmed, true)?)?,
        "vmess" => vmess(trimmed)?,
        "trojan" => trojan(&UriParts::of(trimmed, true)?)?,
        "ss" => shadowsocks(trimmed)?,
        "socks" | "socks5" => socks(&UriParts::of(trimmed, true)?)?,
        "wireguard" | "wg" => wireguard(&UriParts::of(trimmed, true)?)?,
        other => return err(format!("unsupported link type: {other}://")),
    };
    let name = if built.name.trim().is_empty() {
        format!("{} {}", built.protocol.short(), built.host)
    } else {
        built.name.clone()
    };
    Ok(CustomConfig {
        id: super::new_id(),
        name: take_chars(&name, MAX_NAME),
        protocol: built.protocol,
        format: ConfigFormat::Uri,
        source,
        outbound: built.outbound.to_string(),
        raw: trimmed.to_string(),
        server: host_port(&built.host, built.port as i64),
        locked: false,
        note: String::new(),
        expires_at: 0,
        mobile_only: false,
        added_at: now,
    })
}

/// `scheme://userinfo@host:port?query#fragment`، بی سخت‌گیریِ `java.net.URI`.
struct UriParts {
    user: String,
    host: String,
    port: u16,
    query: Vec<(String, String)>,
    name: String,
}

impl UriParts {
    fn get(&self, k: &str) -> Option<&str> {
        self.query.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }

    fn q(&self, keys: &[&str]) -> String {
        keys.iter()
            .find_map(|k| self.get(k).filter(|v| !v.is_empty()))
            .unwrap_or("")
            .to_string()
    }

    fn of(link: &str, need_user: bool) -> R<UriParts> {
        let mut rest = after(link, "://");
        let name = if rest.contains('#') {
            decode(after(rest, "#"))
        } else {
            String::new()
        };
        rest = before(rest, "#");
        let query_text = if rest.contains('?') { after(rest, "?") } else { "" };
        rest = trim_end_char(before(rest, "?"), '/');
        let at = rest.rfind('@');
        if need_user && at.is_none() {
            return err("link has no user id / password");
        }
        let user = at.map(|i| decode(&rest[..i])).unwrap_or_default();
        let (host, port) = split_host_port(match at {
            Some(i) => &rest[i + 1..],
            None => rest,
        })?;
        let mut query: Vec<(String, String)> = Vec::new();
        for pair in query_text.split('&') {
            if pair.is_empty() {
                continue;
            }
            let k = decode(before(pair, "=")).trim().to_string();
            let v = if pair.contains('=') {
                decode(after(pair, "="))
            } else {
                String::new()
            };
            if !k.is_empty() && !query.iter().any(|(key, _)| *key == k) {
                query.push((k, v));
            }
        }
        Ok(UriParts {
            user,
            host,
            port,
            query,
            name,
        })
    }

    fn query_map(&self) -> Vec<(String, String)> {
        self.query.clone()
    }
}

fn vless(u: &UriParts) -> R<Built> {
    require_uuid_like(&u.user)?;
    let mut user = Map::new();
    user.insert("id".into(), json!(u.user));
    let enc = u.q(&["encryption"]);
    user.insert(
        "encryption".into(),
        json!(if enc.is_empty() { "none".to_string() } else { enc }),
    );
    let flow = u.q(&["flow"]);
    if !flow.is_empty() {
        user.insert("flow".into(), json!(flow));
    }
    user.insert("level".into(), json!(8));
    let outbound = json!({
        "protocol": "vless",
        "settings": { "vnext": [ { "address": u.host, "port": u.port, "users": [ Value::Object(user) ] } ] },
        "streamSettings": stream(&u.query_map(), &u.host, "none")?,
    });
    Ok(Built {
        protocol: ConfigProtocol::Vless,
        outbound,
        host: u.host.clone(),
        port: u.port,
        name: u.name.clone(),
    })
}

fn trojan(u: &UriParts) -> R<Built> {
    if u.user.is_empty() {
        return err("trojan link has no password");
    }
    let mut server = Map::new();
    server.insert("address".into(), json!(u.host));
    server.insert("port".into(), json!(u.port));
    server.insert("password".into(), json!(u.user));
    let flow = u.q(&["flow"]);
    if !flow.is_empty() {
        server.insert("flow".into(), json!(flow));
    }
    server.insert("level".into(), json!(8));
    let outbound = json!({
        "protocol": "trojan",
        "settings": { "servers": [ Value::Object(server) ] },
        "streamSettings": stream(&u.query_map(), &u.host, "tls")?,
    });
    Ok(Built {
        protocol: ConfigProtocol::Trojan,
        outbound,
        host: u.host.clone(),
        port: u.port,
        name: u.name.clone(),
    })
}

fn vmess(link: &str) -> R<Built> {
    let body = after(link, "://").trim();
    let decoded = decode_loose(before(body, "#"));
    let decoded = match decoded {
        Some(d) if d.trim_start().starts_with('{') => d,
        _ => {
            // شکلِ URI: vmess://uuid@host:port?type=ws&security=tls...
            let u = UriParts::of(link, true)?;
            require_uuid_like(&u.user)?;
            let aid = u.q(&["alterId", "aid"]).parse::<i64>().unwrap_or(0);
            let scy = u.q(&["encryption", "scy"]);
            let scy = if scy.is_empty() { "auto".to_string() } else { scy };
            return vmess_outbound(&u.user, &u.host, u.port, aid, &scy, &u.query_map(), &u.name);
        }
    };
    let o: Map<String, Value> = match serde_json::from_str::<Value>(&decoded) {
        Ok(Value::Object(o)) => o,
        _ => return err("vmess link is not valid JSON"),
    };
    let s = |key: &str| -> String { prim(o.get(key)).map(|v| v.trim().to_string()).unwrap_or_default() };
    let host = s("add");
    let Ok(port_i) = s("port").parse::<i64>() else {
        return err("vmess link has no port");
    };
    if host.is_empty() {
        return err("vmess link has no address");
    }
    let id = s("id");
    require_uuid_like(&id)?;
    let net = {
        let n = s("net");
        if n.is_empty() {
            "tcp".to_string()
        } else {
            n
        }
    };
    let mut q: Vec<(String, String)> = vec![
        ("type".into(), net.clone()),
        ("headerType".into(), s("type")),
        ("host".into(), s("host")),
        ("path".into(), s("path")),
        ("security".into(), s("tls")),
        ("sni".into(), s("sni")),
        ("alpn".into(), s("alpn")),
        ("fp".into(), s("fp")),
        ("allowInsecure".into(), {
            let a = s("allowInsecure");
            if a.is_empty() {
                s("insecure")
            } else {
                a
            }
        }),
    ];
    if net == "grpc" {
        q.push(("serviceName".into(), s("path")));
        q.push((
            "mode".into(),
            if s("type") == "multi" { "multi" } else { "gun" }.into(),
        ));
    }
    if net == "kcp" {
        q.push(("seed".into(), s("path")));
    }
    if net == "xhttp" || net == "splithttp" {
        let t = s("type");
        q.push(("mode".into(), if t.is_empty() { "auto".into() } else { t }));
    }
    let aid = s("aid").parse::<i64>().unwrap_or(0);
    let scy = {
        let v = s("scy");
        if v.is_empty() {
            "auto".to_string()
        } else {
            v
        }
    };
    // Kotlin's `q["k"] = v` overwrites; keep the LAST value per key.
    let mut dedup: Vec<(String, String)> = Vec::new();
    for (k, v) in q {
        if let Some(slot) = dedup.iter_mut().find(|(key, _)| *key == k) {
            slot.1 = v;
        } else {
            dedup.push((k, v));
        }
    }
    let _ = port_i;
    let port = match u16::try_from(port_i) {
        Ok(p) => p,
        Err(_) => return err("vmess link has no port"),
    };
    vmess_outbound(&id, &host, port, aid, &scy, &dedup, &s("ps"))
}

fn vmess_outbound(
    id: &str,
    host: &str,
    port: u16,
    aid: i64,
    scy: &str,
    q: &[(String, String)],
    name: &str,
) -> R<Built> {
    let outbound = json!({
        "protocol": "vmess",
        "settings": { "vnext": [ { "address": host, "port": port, "users": [
            { "id": id, "alterId": aid, "security": scy, "level": 8 }
        ] } ] },
        "streamSettings": stream(q, host, "none")?,
    });
    Ok(Built {
        protocol: ConfigProtocol::Vmess,
        outbound,
        host: host.to_string(),
        port,
        name: name.to_string(),
    })
}

fn shadowsocks(link: &str) -> R<Built> {
    let mut body = after(link, "://");
    let name = if body.contains('#') {
        decode(after(body, "#"))
    } else {
        String::new()
    };
    body = before(body, "#");
    let query = if body.contains('?') { after(body, "?") } else { "" };
    body = trim_end_char(before(body, "?"), '/');
    let (method, password, host_port_text): (String, String, String);
    if body.contains('@') {
        // SIP002: base64(method:password)@host:port، یا method:password@host:port ساده.
        let at = body.rfind('@').unwrap();
        let userinfo = &body[..at];
        host_port_text = body[at + 1..].to_string();
        let plain = decode(userinfo);
        let creds = if plain.contains(':') && !looks_base64(&plain) {
            plain
        } else {
            decode_loose(userinfo).unwrap_or(plain)
        };
        method = before(&creds, ":").to_string();
        password = after_or(&creds, ":", "").to_string();
    } else {
        // قدیمی: base64(method:password@host:port).
        let Some(whole) = decode_loose(body) else {
            return err("shadowsocks link is not valid");
        };
        let at = whole.rfind('@');
        let creds = &whole[..at.unwrap_or(0)];
        host_port_text = match at {
            Some(i) => whole[i + 1..].to_string(),
            None => whole.clone(),
        };
        method = before(creds, ":").to_string();
        password = after_or(creds, ":", "").to_string();
    }
    if method.is_empty() || password.is_empty() {
        return err("shadowsocks link has no method or password");
    }
    let plugin = query
        .split('&')
        .find(|p| p.starts_with("plugin="))
        .map(|p| decode(after(p, "=")));
    if let Some(p) = plugin {
        if !p.trim().is_empty() && !p.starts_with("none") {
            return err(format!("shadowsocks plugins ({p}) are not supported"));
        }
    }
    let (host, port) = split_host_port(&host_port_text)?;
    let outbound = json!({
        "protocol": "shadowsocks",
        "settings": { "servers": [ {
            "address": host, "port": port, "method": method.to_lowercase(), "password": password, "level": 8
        } ] },
        "streamSettings": { "network": "raw" },
    });
    Ok(Built {
        protocol: ConfigProtocol::Shadowsocks,
        outbound,
        host,
        port,
        name,
    })
}

fn socks(u0: &UriParts) -> R<Built> {
    let mut user = String::new();
    let mut pass = String::new();
    if !u0.user.is_empty() {
        let creds = if u0.user.contains(':') {
            u0.user.clone()
        } else {
            decode_loose(&u0.user).unwrap_or_else(|| u0.user.clone())
        };
        user = before(&creds, ":").to_string();
        pass = after_or(&creds, ":", "").to_string();
    }
    let mut server = Map::new();
    server.insert("address".into(), json!(u0.host));
    server.insert("port".into(), json!(u0.port));
    if !user.is_empty() {
        server.insert(
            "users".into(),
            json!([ { "user": user, "pass": pass, "level": 8 } ]),
        );
    }
    let outbound = json!({
        "protocol": "socks",
        "settings": { "servers": [ Value::Object(server) ] },
    });
    Ok(Built {
        protocol: ConfigProtocol::Socks,
        outbound,
        host: u0.host.clone(),
        port: u0.port,
        name: u0.name.clone(),
    })
}

fn wireguard(u: &UriParts) -> R<Built> {
    if u.user.is_empty() {
        return err("wireguard link has no private key");
    }
    let peer_key = u.q(&["publickey", "publicKey", "public_key"]);
    if peer_key.is_empty() {
        return err("wireguard link has no peer public key");
    }
    let addr_text = {
        let a = u.q(&["address", "ip"]);
        if a.is_empty() {
            "10.0.0.2/32".to_string()
        } else {
            a
        }
    };
    let addresses: Vec<String> = addr_text
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let mut settings = Map::new();
    settings.insert("secretKey".into(), json!(u.user));
    settings.insert("address".into(), json!(addresses));
    settings.insert(
        "mtu".into(),
        json!(u.q(&["mtu"]).parse::<i64>().unwrap_or(1280)),
    );
    let reserved = u.q(&["reserved"]);
    if !reserved.is_empty() {
        let r: Vec<i64> = reserved
            .split(',')
            .filter_map(|x| x.trim().parse().ok())
            .collect();
        settings.insert("reserved".into(), json!(r));
    }
    let mut peer = Map::new();
    peer.insert("publicKey".into(), json!(peer_key));
    let psk = u.q(&["presharedkey", "preSharedKey"]);
    if !psk.is_empty() {
        peer.insert("preSharedKey".into(), json!(psk));
    }
    peer.insert("endpoint".into(), json!(host_port(&u.host, u.port as i64)));
    peer.insert("allowedIPs".into(), json!(["0.0.0.0/0", "::/0"]));
    settings.insert("peers".into(), json!([Value::Object(peer)]));
    let outbound = json!({ "protocol": "wireguard", "settings": Value::Object(settings) });
    Ok(Built {
        protocol: ConfigProtocol::Wireguard,
        outbound,
        host: u.host.clone(),
        port: u.port,
        name: u.name.clone(),
    })
}

/// `streamSettings` از پارامترهای رایجِ لینکِ اشتراک (استانداردِ v2rayN / Xray):
/// `type`، `security`، `sni`، `fp`، `alpn`، `host`، `path`، `serviceName`، `mode`،
/// `headerType`، `pbk`، `sid`، `spx`، `pqv`، `allowInsecure` / `insecure`، `seed`،
/// `extra`، `authority`.
pub fn stream(q: &[(String, String)], address: &str, default_security: &str) -> R<Value> {
    let v = |keys: &[&str]| -> String {
        keys.iter()
            .find_map(|k| {
                q.iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, val)| val.trim())
                    .filter(|val| !val.is_empty())
            })
            .unwrap_or("")
            .to_string()
    };
    let t = {
        let t = v(&["type", "net"]).to_lowercase();
        if t.is_empty() {
            "tcp".to_string()
        } else {
            t
        }
    };
    let net = match t.as_str() {
        "tcp" | "raw" => "raw",
        "ws" | "websocket" => "ws",
        "grpc" | "gun" => "grpc",
        "httpupgrade" => "httpupgrade",
        "xhttp" | "splithttp" => "xhttp",
        "kcp" | "mkcp" => "kcp",
        "h2" | "http" => {
            return err("the HTTP/2 (h2) transport was removed from Xray; ask for an XHTTP config")
        }
        "quic" => return err("the QUIC transport was removed from Xray"),
        other => return err(format!("unsupported transport: {other}")),
    };
    let security = {
        let s = v(&["security"]).to_lowercase();
        let s = if s.is_empty() {
            default_security.to_string()
        } else {
            s
        };
        if s == "xtls" {
            "tls".to_string()
        } else {
            s
        }
    };
    let host = v(&["host"]);
    let path = v(&["path"]);
    let sni = {
        let s = v(&["sni", "serverName", "peer"]);
        if !s.is_empty() {
            s
        } else {
            let h = before(&host, ",").to_string();
            if !h.is_empty() {
                h
            } else if is_domain(address) {
                address.to_string()
            } else {
                String::new()
            }
        }
    };
    let insecure = matches!(
        v(&["allowInsecure", "insecure"]).to_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    let alpn: Vec<String> = v(&["alpn"])
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let mut out = Map::new();
    out.insert("network".into(), json!(net));
    match security.as_str() {
        "tls" => {
            out.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            if !sni.is_empty() {
                tls.insert("serverName".into(), json!(sni));
            }
            tls.insert("allowInsecure".into(), json!(insecure));
            let fp = v(&["fp", "fingerprint"]);
            if !fp.is_empty() {
                tls.insert("fingerprint".into(), json!(fp));
            }
            if !alpn.is_empty() {
                tls.insert("alpn".into(), json!(alpn));
            }
            out.insert("tlsSettings".into(), Value::Object(tls));
        }
        "reality" => {
            let pbk = v(&["pbk", "publicKey"]);
            if pbk.is_empty() {
                return err("reality link has no public key (pbk)");
            }
            out.insert("security".into(), json!("reality"));
            let mut r = Map::new();
            if !sni.is_empty() {
                r.insert("serverName".into(), json!(sni));
            }
            let fp = v(&["fp", "fingerprint"]);
            r.insert(
                "fingerprint".into(),
                json!(if fp.is_empty() { "chrome".to_string() } else { fp }),
            );
            r.insert("publicKey".into(), json!(pbk));
            r.insert("shortId".into(), json!(v(&["sid", "shortId"])));
            r.insert("spiderX".into(), json!(v(&["spx", "spiderX"])));
            let pqv = v(&["pqv", "mldsa65Verify"]);
            if !pqv.is_empty() {
                r.insert("mldsa65Verify".into(), json!(pqv));
            }
            out.insert("realitySettings".into(), Value::Object(r));
        }
        "none" | "" => {
            out.insert("security".into(), json!("none"));
        }
        other => return err(format!("unsupported security: {other}")),
    }
    let split_list =
        |s: &str| -> Vec<String> { s.split(',').map(|x| x.trim().to_string()).collect() };
    match net {
        "raw" => {
            if v(&["headerType"]).to_lowercase() == "http" {
                let mut request = Map::new();
                request.insert(
                    "path".into(),
                    json!(split_list(if path.is_empty() { "/" } else { &path })),
                );
                if !host.is_empty() {
                    request.insert("headers".into(), json!({ "Host": split_list(&host) }));
                }
                out.insert(
                    "rawSettings".into(),
                    json!({ "header": { "type": "http", "request": Value::Object(request) } }),
                );
            }
        }
        "ws" | "httpupgrade" => {
            let mut s = Map::new();
            s.insert(
                "path".into(),
                json!(if path.is_empty() { "/".to_string() } else { path.clone() }),
            );
            if !host.is_empty() {
                s.insert("host".into(), json!(host));
            }
            let key = if net == "ws" { "wsSettings" } else { "httpupgradeSettings" };
            out.insert(key.into(), Value::Object(s));
        }
        "grpc" => {
            let mut s = Map::new();
            let sn = v(&["serviceName"]);
            s.insert(
                "serviceName".into(),
                json!(if sn.is_empty() { path.clone() } else { sn }),
            );
            s.insert(
                "multiMode".into(),
                json!(v(&["mode"]).to_lowercase() == "multi"),
            );
            let authority = v(&["authority"]);
            if !authority.is_empty() {
                s.insert("authority".into(), json!(authority));
            }
            out.insert("grpcSettings".into(), Value::Object(s));
        }
        "xhttp" => {
            let mut s = Map::new();
            s.insert(
                "path".into(),
                json!(if path.is_empty() { "/".to_string() } else { path.clone() }),
            );
            if !host.is_empty() {
                s.insert("host".into(), json!(host));
            }
            let mode = v(&["mode"]);
            s.insert(
                "mode".into(),
                json!(if mode.is_empty() { "auto".to_string() } else { mode }),
            );
            let extra = v(&["extra"]);
            if !extra.is_empty() {
                if let Ok(Value::Object(e)) = serde_json::from_str::<Value>(&extra) {
                    s.insert("extra".into(), Value::Object(e));
                }
            }
            out.insert("xhttpSettings".into(), Value::Object(s));
        }
        "kcp" => {
            let mut s = Map::new();
            let ht = v(&["headerType"]);
            s.insert(
                "header".into(),
                json!({ "type": if ht.is_empty() { "none".to_string() } else { ht } }),
            );
            let seed = v(&["seed"]);
            if !seed.is_empty() {
                s.insert("seed".into(), json!(seed));
            }
            out.insert("kcpSettings".into(), Value::Object(s));
        }
        _ => {}
    }
    Ok(Value::Object(out))
}

// ------------------------------------------------------------------ JSON

/// یک کانفیگِ JSONِ Xray / V2Ray، فهرستی از آن‌ها، یا یک outboundِ تنها.
fn parse_json(text: &str, source: ConfigSource, now: i64) -> R<Vec<CustomConfig>> {
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return err("the JSON could not be read");
    };
    let configs: Vec<Map<String, Value>> = match root {
        Value::Array(a) => a
            .into_iter()
            .filter_map(|v| match v {
                Value::Object(o) => Some(o),
                _ => None,
            })
            .collect(),
        Value::Object(o) => vec![o],
        _ => Vec::new(),
    };
    let mut out = Vec::new();
    for cfg in configs {
        let Some(outbound) = pick_outbound(&cfg) else {
            continue;
        };
        let remarks = match cfg.get("remarks") {
            Some(v) => prim(Some(v)).unwrap_or_default(),
            None => String::new(),
        };
        let raw = Value::Object(cfg.clone()).to_string();
        out.push(from_outbound(
            &outbound,
            &remarks,
            ConfigFormat::XrayJson,
            source,
            &raw,
            now,
            None,
        ));
    }
    if out.is_empty() {
        return err("the JSON has no proxy outbound");
    }
    Ok(out)
}

/// outboundِ پراکسیِ یک کانفیگِ کامل (اول tagِ `proxy`)، یا خودِ `cfg` وقتی خودش outbound است.
pub fn pick_outbound(cfg: &Map<String, Value>) -> Option<Map<String, Value>> {
    if matches!(cfg.get("protocol"), Some(v) if is_primitive(v)) && cfg.get("outbounds").is_none() {
        return if is_proxy_protocol(cfg) {
            Some(cfg.clone())
        } else {
            None
        };
    }
    let Some(Value::Array(outbounds)) = cfg.get("outbounds") else {
        return None;
    };
    let proxies: Vec<&Map<String, Value>> = outbounds
        .iter()
        .filter_map(|v| v.as_object())
        .filter(|o| is_proxy_protocol(o))
        .collect();
    proxies
        .iter()
        .find(|o| prim(o.get("tag")).as_deref() == Some("proxy"))
        .or(proxies.first())
        .map(|o| (*o).clone())
}

fn is_primitive(v: &Value) -> bool {
    !matches!(v, Value::Object(_) | Value::Array(_))
}

fn is_proxy_protocol(o: &Map<String, Value>) -> bool {
    let Some(p) = prim(o.get("protocol")) else {
        return false;
    };
    !matches!(
        p.to_lowercase().as_str(),
        "freedom" | "blackhole" | "dns" | "loopback"
    )
}

/// outboundی که از کانفیگِ کسِ دیگری برداشته شده را تمیز می‌کند تا داخلِ کانفیگی
/// بنشیند که این برنامه می‌نویسد: tagش، هر `dialerProxy` / `proxySettings` که به
/// outboundهایی اشاره می‌کند که اینجا نیستند، `mark`/`interface`، `sendThrough`
/// و پرچمِ کلاینتیِ `show` حذف می‌شوند. بقیه — ترابری، TLS/REALITY، mux — دقیقاً
/// همان‌طور که نویسنده نوشته می‌ماند.
pub fn sanitize_outbound(o: &Map<String, Value>) -> Map<String, Value> {
    let stream = o.get("streamSettings").and_then(|s| s.as_object()).map(|s| {
        let mut m = Map::new();
        for (k, v) in s {
            match k.as_str() {
                "sockopt" => {
                    if let Some(so) = v.as_object() {
                        let filtered: Map<String, Value> = so
                            .iter()
                            .filter(|(key, _)| {
                                !matches!(key.as_str(), "dialerProxy" | "mark" | "interface")
                            })
                            .map(|(a, b)| (a.clone(), b.clone()))
                            .collect();
                        if !filtered.is_empty() {
                            m.insert(k.clone(), Value::Object(filtered));
                        }
                    }
                }
                "tlsSettings" | "realitySettings" => {
                    if let Some(t) = v.as_object() {
                        let filtered: Map<String, Value> = t
                            .iter()
                            .filter(|(key, _)| key.as_str() != "show")
                            .map(|(a, b)| (a.clone(), b.clone()))
                            .collect();
                        m.insert(k.clone(), Value::Object(filtered));
                    }
                }
                _ => {
                    m.insert(k.clone(), v.clone());
                }
            }
        }
        m
    });
    let mut out = Map::new();
    for (k, v) in o {
        match k.as_str() {
            "tag" | "proxySettings" | "sendThrough" => {}
            "streamSettings" => {
                if let Some(s) = &stream {
                    out.insert(k.clone(), Value::Object(s.clone()));
                }
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

fn from_outbound(
    outbound: &Map<String, Value>,
    name: &str,
    format: ConfigFormat,
    source: ConfigSource,
    raw: &str,
    now: i64,
    lock: Option<&NpvtLock>,
) -> CustomConfig {
    let clean = sanitize_outbound(outbound);
    let protocol = ConfigProtocol::from_xray(prim(clean.get("protocol")).as_deref());
    let (host, port) = server_of(&clean);
    let locked = lock.map(|l| l.locked).unwrap_or(false);
    let display = if name.trim().is_empty() {
        format!("{} {host}", protocol.short())
    } else {
        name.to_string()
    };
    CustomConfig {
        id: super::new_id(),
        name: take_chars(display.trim(), MAX_NAME),
        protocol,
        format,
        source,
        outbound: Value::Object(clean).to_string(),
        raw: if locked { String::new() } else { raw.to_string() },
        server: if locked { String::new() } else { host_port(&host, port) },
        locked,
        note: take_chars(lock.map(|l| l.message.as_str()).unwrap_or(""), MAX_NOTE),
        expires_at: lock.map(|l| l.expires_at).unwrap_or(0),
        mobile_only: lock.map(|l| l.mobile_only).unwrap_or(false),
        added_at: now,
    }
}

/// نخستین نشانی و پورتِ سروری که یک outbound نام می‌برد، برای نمایش.
pub fn server_of(o: &Map<String, Value>) -> (String, i64) {
    let Some(settings) = o.get("settings").and_then(|s| s.as_object()) else {
        return (String::new(), 0);
    };
    let list = settings.get("vnext").or_else(|| settings.get("servers"));
    if let Some(entry) = list
        .and_then(|l| l.as_array())
        .and_then(|a| a.first())
        .and_then(|e| e.as_object())
    {
        let host = prim(entry.get("address")).unwrap_or_default();
        let port = prim_int(entry.get("port")).unwrap_or(0);
        return (host, port);
    }
    // شکلِ تختی که Xray جدیدتر می‌پذیرد: settings.address / settings.port.
    if let Some(host) = prim(settings.get("address")) {
        let port = prim_int(settings.get("port")).unwrap_or(0);
        return (host, port);
    }
    let endpoint = settings
        .get("peers")
        .and_then(|p| p.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.as_object())
        .and_then(|p| prim(p.get("endpoint")));
    let Some(endpoint) = endpoint else {
        return (String::new(), 0);
    };
    match split_host_port(&endpoint) {
        Ok((h, p)) => (h, p as i64),
        Err(_) => (endpoint, 0),
    }
}

// ------------------------------------------------------------------ npvt

fn parse_npvt(
    text: &str,
    source: ConfigSource,
    password: Option<&str>,
    now: i64,
) -> R<Vec<CustomConfig>> {
    let decoded = npvt::decode(text, npvt::tables()).map_err(ImportError::Invalid)?;
    parse_decoded_npvt(decoded, text, source, password, now)
}

fn parse_decoded_npvt(decoded: npvt::Decoded, text: &str, source: ConfigSource,
    password: Option<&str>, now: i64) -> R<Vec<CustomConfig>> {
    let servers = match serde_json::from_str::<Value>(&decoded.servers) {
        Ok(Value::Array(a)) => a,
        _ => return err("npvt file could not be decrypted"),
    };
    let global_lock = match serde_json::from_str::<Value>(&decoded.lock) {
        Ok(Value::Object(o)) => Some(o),
        _ => None,
    };
    let mut out = Vec::new();
    let mut skipped: Option<String> = None;
    let count = servers.len();
    for (index, el) in servers.iter().enumerate() {
        let Some(server) = el.as_object() else {
            continue;
        };
        let lock_obj = server
            .get("lockConfig")
            .and_then(|l| l.as_object())
            .or(global_lock.as_ref());
        let lock = NpvtLock::of(lock_obj);
        lock.check(password, now)?;
        let kind = prim(server.get("type")).unwrap_or_default().to_uppercase();
        if kind != "V2RAY" {
            skipped = Some(format!(
                "npvt server type {kind} is not supported (only V2Ray/Xray servers are)"
            ));
            continue;
        }
        let Some(profile) = server.get("v2rayProfile").and_then(|p| p.as_object()) else {
            continue;
        };
        let Some(outbound) = npvt_outbound(profile) else {
            skipped = Some("an npvt server could not be converted".into());
            continue;
        };
        let name = prim(server.get("name"))
            .or_else(|| prim(profile.get("remarks")))
            .unwrap_or_default();
        let numbered = if count > 1 {
            format!(
                "{} #{}",
                if name.trim().is_empty() { "Npvt" } else { name.as_str() },
                index + 1
            )
        } else {
            name
        };
        out.push(from_outbound(
            &outbound,
            &numbered,
            ConfigFormat::Npvt,
            source,
            text.trim(),
            now,
            Some(&lock),
        ));
    }
    if out.is_empty() {
        return err(skipped.unwrap_or_else(|| "the npvt file holds no servers".into()));
    }
    Ok(out)
}

/// outboundِ یک سرورِ V2Rayِ npvt: JSONِ Xrayِ جاسازی‌شده اگر باشد، وگرنه بازسازی از فیلدهایش.
fn npvt_outbound(p: &Map<String, Value>) -> Option<Map<String, Value>> {
    let s = |key: &str| -> String { prim(p.get(key)).map(|v| v.trim().to_string()).unwrap_or_default() };
    let embedded = s("v2rayJson");
    if !embedded.is_empty() {
        if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(&embedded) {
            if let Some(ob) = pick_outbound(&o) {
                return Some(ob);
            }
        }
    }
    let host = s("server");
    let port: u16 = s("serverPort").parse().ok()?;
    if host.is_empty() {
        return None;
    }
    let net = s("network");
    let mut q: Vec<(String, String)> = vec![
        ("type".into(), if net.is_empty() { "tcp".into() } else { net }),
        ("security".into(), s("security")),
        ("host".into(), s("host")),
        ("path".into(), s("path")),
        ("sni".into(), s("sni")),
        ("fp".into(), s("fingerPrint")),
        ("alpn".into(), s("alpn")),
        ("flow".into(), s("flow")),
        ("pbk".into(), s("publicKey")),
        ("sid".into(), s("shortId")),
        ("spx".into(), s("spiderX")),
        ("headerType".into(), s("headerType")),
        ("serviceName".into(), s("serviceName")),
        ("mode".into(), s("mode")),
        (
            "allowInsecure".into(),
            if prim(p.get("insecure")).as_deref() == Some("true") {
                "1".into()
            } else {
                "0".into()
            },
        ),
    ];
    let id = s("password");
    // شماره‌گذاریِ EConfigTypeِ v2rayNG که خروجیِ ناپسترنت هم نگه می‌دارد.
    let built = match s("configType").parse::<i64>().ok()? {
        1 => {
            let m = s("method");
            vmess_outbound(
                &id,
                &host,
                port,
                s("alterId").parse().unwrap_or(0),
                if m.is_empty() { "auto" } else { &m },
                &q,
                "",
            )
            .ok()?
        }
        3 => {
            return shadowsocks(&format!(
                "ss://{}:{}@{}",
                s("method"),
                id,
                host_port(&host, port as i64)
            ))
            .ok()
            .and_then(|b| b.outbound.as_object().cloned());
        }
        5 => {
            let m = s("method");
            q.push((
                "encryption".into(),
                if m.is_empty() { "none".into() } else { m },
            ));
            vless(&UriParts {
                user: id,
                host: host.clone(),
                port,
                query: q,
                name: String::new(),
            })
            .ok()?
        }
        6 => trojan(&UriParts {
            user: id,
            host: host.clone(),
            port,
            query: q,
            name: String::new(),
        })
        .ok()?,
        _ => return None,
    };
    built.outbound.as_object().cloned()
}

/// تنظیماتِ قفلِ نویسندهٔ npvt، که واردکننده اجرا می‌کند.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpvtLock {
    pub locked: bool,
    pub password: String,
    pub expires_at: i64,
    pub device_ids: String,
    pub mobile_only: bool,
    pub message: String,
}

impl NpvtLock {
    /// کانفیگی را که این دستگاه نباید به کار ببرد، دقیقاً همان‌طور که قفل می‌گوید، رد می‌کند.
    pub fn check(&self, given: Option<&str>, now: i64) -> R<()> {
        if !self.device_ids.trim().is_empty() {
            return err("this npvt config is bound to specific devices by its author");
        }
        if self.expires_at >= 1 && self.expires_at < now {
            return err("this npvt config has expired");
        }
        // ویندوز: «فقط اینترنتِ موبایل» روی رایانه رعایت‌شدنی نیست، پس همین‌جا رد می‌شود.
        if self.mobile_only {
            return err(
                "this npvt config is restricted by its author to mobile data only, which a Windows PC cannot honour",
            );
        }
        if !self.password.is_empty() {
            match given {
                None | Some("") => return Err(ImportError::Password { wrong: false }),
                Some(g) if g != self.password => return Err(ImportError::Password { wrong: true }),
                _ => {}
            }
        }
        Ok(())
    }

    pub fn of(o: Option<&Map<String, Value>>) -> NpvtLock {
        let s = |k: &str| -> String {
            o.and_then(|o| prim(o.get(k)))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        let b = |k: &str| s(k).to_lowercase() == "true";
        NpvtLock {
            locked: b("isLocked"),
            password: s("password"),
            expires_at: parse_expiry(&s("expiryDate")),
            device_ids: s("deviceIds"),
            mobile_only: b("onlyMobileNetwork"),
            message: s("message"),
        }
    }
}

/// میلی‌ثانیهٔ epoch، ثانیهٔ epoch، یا تاریخ / تاریخ‌وزمانِ ISO (UTC)؛ ۰ وقتی خالی یا ناخوانا است.
pub fn parse_expiry(text: &str) -> i64 {
    if text.trim().is_empty() {
        return 0;
    }
    if let Ok(n) = text.parse::<i64>() {
        return if n < 100_000_000_000 { n * 1000 } else { n };
    }
    // (الگو، طولِ پیشوند)
    const PATTERNS: [(&str, usize); 5] = [
        ("yyyy-MM-ddTHH:mm:ss", 19),
        ("yyyy-MM-dd HH:mm:ss", 19),
        ("yyyy-MM-dd HH:mm", 16),
        ("yyyy-MM-dd", 10),
        ("yyyy/MM/dd", 10),
    ];
    for (pattern, len) in PATTERNS {
        let prefix: String = text.chars().take(len).collect();
        if let Some(ms) = match_date(&prefix, pattern) {
            return ms;
        }
    }
    0
}

fn match_date(text: &str, pattern: &str) -> Option<i64> {
    if text.chars().count() != pattern.chars().count() {
        return None;
    }
    let mut fields: [i64; 6] = [0, 1, 1, 0, 0, 0];
    let mut cur = String::new();
    let mut cur_field: Option<usize> = None;
    let flush = |cur: &mut String, field: Option<usize>, fields: &mut [i64; 6]| -> Option<()> {
        if let Some(f) = field {
            fields[f] = cur.parse().ok()?;
        }
        cur.clear();
        Some(())
    };
    for (pc, tc) in pattern.chars().zip(text.chars()) {
        let field = match pc {
            'y' => Some(0),
            'M' => Some(1),
            'd' => Some(2),
            'H' => Some(3),
            'm' => Some(4),
            's' => Some(5),
            _ => None,
        };
        match field {
            Some(f) => {
                if !tc.is_ascii_digit() {
                    return None;
                }
                if cur_field != Some(f) {
                    flush(&mut cur, cur_field, &mut fields)?;
                    cur_field = Some(f);
                }
                cur.push(tc);
            }
            None => {
                if tc != pc {
                    return None;
                }
                flush(&mut cur, cur_field, &mut fields)?;
                cur_field = None;
            }
        }
    }
    flush(&mut cur, cur_field, &mut fields)?;
    let [y, mo, d, h, mi, s] = fields;
    if !(1..=12).contains(&mo) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let dim = [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if d < 1 || d > dim[(mo - 1) as usize] {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    Some(((days * 24 + h) * 60 + mi) * 60_000 + s * 1000)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// روزها از ۱۹۷۰-۰۱-۰۱ (الگوریتمِ Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;
    const UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const PBK: &str = "JLfJZqtyFf3MgHBiZcxuvqmRscjrM5xmSBVaWPPsObE";
    const SYNTHETIC: &str = include_str!("testdata/synthetic.npvt");

    fn reality_vision() -> String {
        format!("vless://{UUID}@192.0.2.10:443?security=reality&encryption=none&pbk={PBK}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=yahoo.com&sid=c39cc7310a#%40reality-one")
    }
    const TLS_VISION: &str = "vless://user@vision.example.net:443?security=tls&alpn=h2&encryption=none&insecure=0&headerType=none&fp=chrome&type=tcp&allowInsecure=0&flow=xtls-rprx-vision&sni=vision.example.net#%40tls-vision";
    fn reality_firefox() -> String {
        format!("vless://{UUID}@198.51.100.7:2063?security=reality&encryption=none&pbk={PBK}&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.de#%40reality-two")
    }
    fn xhttp_cdn() -> String {
        format!("vless://{UUID}@203.0.113.9:443?mode=auto&path=%2F%40chan%2F%40chan&security=tls&alpn=h2&encryption=none&insecure=0&host=front.example.net&fp=chrome&type=xhttp&allowInsecure=0&sni=sni.example.com#%40xhttp")
    }

    fn p(text: &str) -> R<Vec<CustomConfig>> {
        parse(text, ConfigSource::Link, None, NOW)
    }
    fn one(text: &str) -> CustomConfig {
        let v = p(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(v.len(), 1);
        v.into_iter().next().unwrap()
    }
    fn out(c: &CustomConfig) -> Value {
        serde_json::from_str(&c.outbound).unwrap()
    }
    fn b64(s: &str) -> String {
        npvt::b64_encode(s.as_bytes(), npvt::STD_ALPHABET, true)
    }
    fn npvt_server(name: &str, lock: &str) -> String {
        format!("[{{\"name\":\"{name}\",\"address\":\"example.org:443\",\"type\":\"V2RAY\",\"v2rayProfile\":{{\"configType\":5,\"server\":\"example.org\",\"serverPort\":\"443\",\"password\":\"{UUID}\",\"network\":\"ws\",\"host\":\"cdn.example.org\",\"path\":\"/ws\",\"security\":\"tls\",\"sni\":\"cdn.example.org\",\"fingerPrint\":\"chrome\",\"insecure\":true}},\"lockConfig\":{lock}}}]")
    }
    fn make_npvt(servers: &str, lock: &str) -> String {
        npvt::encode(servers, lock, 1, npvt::tables())
    }

    #[test]
    fn vless_reality_vision() {
        let c = one(&reality_vision());
        assert_eq!(c.protocol, ConfigProtocol::Vless);
        assert_eq!(c.name, "@reality-one");
        assert_eq!(c.server, "192.0.2.10:443");
        let o = out(&c);
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        let s = &o["streamSettings"];
        assert_eq!(s["network"], "raw");
        assert_eq!(s["security"], "reality");
        assert_eq!(s["realitySettings"]["serverName"], "yahoo.com");
        assert_eq!(s["realitySettings"]["publicKey"], PBK);
        assert_eq!(s["realitySettings"]["shortId"], "c39cc7310a");
        assert_eq!(s["realitySettings"]["fingerprint"], "chrome");
        let f = one(&reality_firefox());
        assert_eq!(out(&f)["streamSettings"]["realitySettings"]["fingerprint"], "firefox");
    }

    #[test]
    fn vless_tls_vision_with_alpn() {
        let c = one(TLS_VISION);
        let s = &out(&c)["streamSettings"];
        assert_eq!(s["security"], "tls");
        assert_eq!(s["tlsSettings"]["serverName"], "vision.example.net");
        assert_eq!(s["tlsSettings"]["alpn"][0], "h2");
        assert_eq!(s["tlsSettings"]["allowInsecure"], false);
    }

    #[test]
    fn vless_xhttp_behind_a_cdn() {
        let c = one(&xhttp_cdn());
        let s = &out(&c)["streamSettings"];
        assert_eq!(s["network"], "xhttp");
        assert_eq!(s["xhttpSettings"]["path"], "/@chan/@chan");
        assert_eq!(s["xhttpSettings"]["host"], "front.example.net");
        assert_eq!(s["xhttpSettings"]["mode"], "auto");
        assert_eq!(s["tlsSettings"]["serverName"], "sni.example.com");
    }

    #[test]
    fn every_transport_is_mapped() {
        let base = format!("vless://{UUID}@h.example.com:443?security=tls");
        let ws = one(&format!("{base}&type=ws&path=%2Fw&host=a.example.com"));
        assert_eq!(out(&ws)["streamSettings"]["wsSettings"]["path"], "/w");
        assert_eq!(out(&ws)["streamSettings"]["wsSettings"]["host"], "a.example.com");
        let grpc = one(&format!("{base}&type=grpc&serviceName=svc&mode=multi&authority=au"));
        let g = &out(&grpc)["streamSettings"]["grpcSettings"];
        assert_eq!((g["serviceName"].as_str(), g["multiMode"].as_bool(), g["authority"].as_str()), (Some("svc"), Some(true), Some("au")));
        let hu = one(&format!("{base}&type=httpupgrade&path=%2Fu"));
        assert_eq!(out(&hu)["streamSettings"]["httpupgradeSettings"]["path"], "/u");
        let kcp = one(&format!("vless://{UUID}@h.example.com:443?type=kcp&headerType=wechat-video&seed=s33d"));
        let k = &out(&kcp)["streamSettings"];
        assert_eq!(k["kcpSettings"]["seed"], "s33d");
        assert_eq!(k["kcpSettings"]["header"]["type"], "wechat-video");
        assert_eq!(k["security"], "none");
        let http = one(&format!("vless://{UUID}@h.example.com:80?type=tcp&headerType=http&path=%2Fa,%2Fb&host=x.example.com"));
        let r = &out(&http)["streamSettings"]["rawSettings"]["header"];
        assert_eq!(r["type"], "http");
        assert_eq!(r["request"]["path"][1], "/b");
        assert_eq!(r["request"]["headers"]["Host"][0], "x.example.com");
        let xh = one(&format!("{base}&type=splithttp&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"));
        assert_eq!(out(&xh)["streamSettings"]["xhttpSettings"]["extra"]["xPaddingBytes"], "100-1000");
        // Removed Xray transports are refused with an explanation.
        assert!(p(&format!("{base}&type=h2")).unwrap_err().to_string().contains("XHTTP"));
        assert!(p(&format!("{base}&type=quic")).is_err());
    }

    #[test]
    fn a_multi_line_paste_becomes_one_config_per_link() {
        let text = [reality_vision(), TLS_VISION.into(), "".into(), reality_firefox(), xhttp_cdn(), "".into()].join("\n");
        let all = p(&text).unwrap();
        assert_eq!(all.len(), 4);
        let ids: std::collections::HashSet<_> = all.iter().map(|c| c.id.clone()).collect();
        assert_eq!(ids.len(), 4);
        // Windows line endings, too.
        assert_eq!(p(&text.replace('\n', "\r\n")).unwrap().len(), 4);
    }

    #[test]
    fn a_base64_subscription_is_unpacked() {
        let sub = b64(&format!("{}\n{}", reality_vision(), xhttp_cdn()));
        assert_eq!(p(&sub).unwrap().len(), 2);
        // URL-safe without padding, wrapped across lines.
        let url = npvt::b64_encode(format!("{}\n{}", reality_vision(), TLS_VISION).as_bytes(), npvt::URL_ALPHABET, false);
        let wrapped = format!("{}\n{}", &url[..40], &url[40..]);
        assert_eq!(p(&wrapped).unwrap().len(), 2);
    }

    #[test]
    fn vmess_v2rayn_base64_json() {
        let j = format!("{{\"v\":\"2\",\"ps\":\"vm\",\"add\":\"vm.example.com\",\"port\":\"8443\",\"id\":\"{UUID}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"h.example.com\",\"path\":\"/v\",\"tls\":\"tls\",\"sni\":\"h.example.com\"}}");
        let c = one(&format!("vmess://{}", b64(&j)));
        assert_eq!(c.protocol, ConfigProtocol::Vmess);
        assert_eq!(c.name, "vm");
        assert_eq!(c.server, "vm.example.com:8443");
        let s = &out(&c)["streamSettings"];
        assert_eq!(s["network"], "ws");
        assert_eq!(s["wsSettings"]["path"], "/v");
        assert_eq!(s["security"], "tls");
        // Numeric port and grpc multi.
        let g = format!("{{\"ps\":\"g\",\"add\":\"g.example.com\",\"port\":443,\"id\":\"{UUID}\",\"net\":\"grpc\",\"type\":\"multi\",\"path\":\"svc\",\"tls\":\"tls\"}}");
        let gc = one(&format!("vmess://{}", b64(&g)));
        assert_eq!(out(&gc)["streamSettings"]["grpcSettings"]["multiMode"], true);
        assert_eq!(out(&gc)["streamSettings"]["grpcSettings"]["serviceName"], "svc");
        // kcp seed rides in `path`.
        let k = format!("{{\"add\":\"k.example.com\",\"port\":\"1\",\"id\":\"{UUID}\",\"net\":\"kcp\",\"path\":\"seed1\"}}");
        assert_eq!(out(&one(&format!("vmess://{}", b64(&k))))["streamSettings"]["kcpSettings"]["seed"], "seed1");
    }

    #[test]
    fn vmess_uri_form() {
        let c = one(&format!("vmess://{UUID}@u.example.com:443?type=ws&security=tls&path=%2Fp&aid=2#uri"));
        assert_eq!(c.protocol, ConfigProtocol::Vmess);
        let o = out(&c);
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["alterId"], 2);
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["security"], "auto");
        assert_eq!(c.name, "uri");
    }

    #[test]
    fn trojan_and_shadowsocks() {
        let t = one("trojan://secret@t.example.com:443?sni=t.example.com&type=grpc&serviceName=svc#tr");
        assert_eq!(t.protocol, ConfigProtocol::Trojan);
        assert_eq!(out(&t)["streamSettings"]["network"], "grpc");
        assert_eq!(out(&t)["streamSettings"]["security"], "tls");
        let ui = npvt::b64_encode(b"chacha20-ietf-poly1305:pass", npvt::URL_ALPHABET, false);
        let s = one(&format!("ss://{ui}@ss.example.com:8388#ss"));
        assert_eq!(s.protocol, ConfigProtocol::Shadowsocks);
        let srv = &out(&s)["settings"]["servers"][0];
        assert_eq!(srv["method"], "chacha20-ietf-poly1305");
        assert_eq!(srv["password"], "pass");
        assert_eq!(s.chain_label(), "SS");
        // Legacy whole-base64 form and plain SIP002 form.
        let legacy = one(&format!("ss://{}#old", b64("aes-256-gcm:pw@1.2.3.4:8388")));
        assert_eq!(legacy.server, "1.2.3.4:8388");
        assert_eq!(out(&legacy)["settings"]["servers"][0]["method"], "aes-256-gcm");
        let plain = one("ss://AES-128-GCM:pw@[2001:db8::1]:443");
        assert_eq!(plain.server, "[2001:db8::1]:443");
        assert_eq!(out(&plain)["settings"]["servers"][0]["method"], "aes-128-gcm");
    }

    #[test]
    fn socks_and_wireguard() {
        let s = one("socks://dXNlcjpwYXNz@s.example.com:1080#s");
        let srv = &out(&s)["settings"]["servers"][0];
        assert_eq!(srv["users"][0]["user"], "user");
        assert_eq!(srv["users"][0]["pass"], "pass");
        // Same as Android 1.5.0 (`UriParts.of(link)` needs a user): a bare
        // socks5://host:port is refused rather than silently unauthenticated.
        assert!(p("socks5://s.example.com:1080").is_err());
        let s5 = one("socks5://u:p@s.example.com:1080");
        assert_eq!(out(&s5)["settings"]["servers"][0]["users"][0]["pass"], "p");
        let wg = one("wireguard://cHJpdmF0ZWtleQ%3D%3D@wg.example.com:51820?publickey=cHVibGlj&address=10.1.0.2%2F32,fd00::2%2F128&reserved=1,2,3&mtu=1280#wg");
        assert_eq!(wg.protocol, ConfigProtocol::Wireguard);
        let o = out(&wg);
        assert_eq!(o["settings"]["secretKey"], "cHJpdmF0ZWtleQ==");
        assert_eq!(o["settings"]["address"][1], "fd00::2/128");
        assert_eq!(o["settings"]["reserved"][2], 3);
        assert_eq!(o["settings"]["mtu"], 1280);
        assert_eq!(o["settings"]["peers"][0]["endpoint"], "wg.example.com:51820");
        assert_eq!(wg.server, "wg.example.com:51820");
        assert!(p("wg://key@wg.example.com:51820").is_err(), "no peer key");
    }

    #[test]
    fn a_full_xray_json_config_yields_its_proxy_outbound() {
        let json = "{\"remarks\":\"mine\",\"outbounds\":[{\"tag\":\"direct\",\"protocol\":\"freedom\"},{\"tag\":\"x\",\"protocol\":\"trojan\",\"settings\":{\"servers\":[{\"address\":\"j.example.com\",\"port\":443,\"password\":\"p\"}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\",\"sockopt\":{\"dialerProxy\":\"other\",\"mark\":1},\"tlsSettings\":{\"show\":true,\"serverName\":\"j.example.com\"}},\"proxySettings\":{\"tag\":\"x\"}}]}";
        let c = one(json);
        assert_eq!(c.format, ConfigFormat::XrayJson);
        assert_eq!(c.protocol, ConfigProtocol::Trojan);
        assert_eq!(c.server, "j.example.com:443");
        assert_eq!(c.name, "mine");
        let o = out(&c);
        assert!(o.get("tag").is_none());
        assert!(o.get("proxySettings").is_none());
        assert!(o["streamSettings"].get("sockopt").is_none(), "an emptied sockopt is dropped");
        assert!(o["streamSettings"]["tlsSettings"].get("show").is_none());
        assert_eq!(o["streamSettings"]["tlsSettings"]["serverName"], "j.example.com");
        // A bare outbound, and the `proxy` tag wins over order.
        let bare = one("{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"b.example.com\",\"port\":\"8443\",\"users\":[{\"id\":\"x\"}]}]}}");
        assert_eq!(bare.server, "b.example.com:8443");
        let tagged = one("{\"outbounds\":[{\"protocol\":\"socks\",\"settings\":{\"servers\":[{\"address\":\"a\",\"port\":1}]}},{\"tag\":\"proxy\",\"protocol\":\"vmess\",\"settings\":{\"vnext\":[{\"address\":\"v\",\"port\":2}]}}]}");
        assert_eq!(tagged.protocol, ConfigProtocol::Vmess);
        assert!(p("{\"outbounds\":[{\"protocol\":\"freedom\"}]}").is_err());
        assert!(p("{not json").is_err());
    }

    #[test]
    fn unsupported_input_is_refused() {
        for bad in ["hello world", "vless://", "ss://bm9uZQ@x.example.com:1?plugin=v2ray-plugin", "", "   ", "http://example.com", "vless://id@host"] {
            assert!(p(bad).is_err(), "accepted: {bad}");
        }
        assert!(p("ss://YWVzLTI1Ni1nY206cHc@x.example.com:1?plugin=obfs-local").unwrap_err().to_string().contains("plugins"));
    }

    #[test]
    fn locked_npvt_hides_its_server_and_keeps_the_note() {
        let c = one(SYNTHETIC);
        assert_eq!(c.format, ConfigFormat::Npvt);
        assert_eq!(c.protocol, ConfigProtocol::Vless);
        assert_eq!(c.chain_label(), "Npvt");
        assert!(c.locked);
        assert_eq!(c.raw, "");
        assert_eq!(c.server, "");
        assert_eq!(c.note, "hello");
        assert!(c.outbound.contains("11111111-2222-3333-4444-555555555555"));
        assert!(c.outbound.contains("\"ws\""));
    }

    #[test]
    fn npvt_link_form() {
        let link = format!("npvt://{}", b64(SYNTHETIC.trim()));
        assert_eq!(p(&link).unwrap().len(), 1);
    }

    #[test]
    fn unlocked_npvt_is_editable_and_keeps_insecure() {
        let text = make_npvt(&npvt_server("open", "{\"isLocked\":false,\"password\":\"\",\"expiryDate\":\"\",\"deviceIds\":\"\"}"), "{}");
        let c = one(&text);
        assert!(!c.locked);
        assert_eq!(c.server, "example.org:443");
        assert!(c.raw.starts_with("NPVT1"));
        assert_eq!(out(&c)["streamSettings"]["tlsSettings"]["allowInsecure"], true);
        assert_eq!(c.name, "open");
    }

    #[test]
    fn npvt_with_several_servers_is_one_config_each() {
        let two = format!(
            "[{},{}]",
            npvt_server("a", "{}").trim_start_matches('[').trim_end_matches(']'),
            npvt_server("", "{}").trim_start_matches('[').trim_end_matches(']')
        );
        let all = p(&make_npvt(&two, "{}")).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "a #1");
        assert_eq!(all[1].name, "Npvt #2");
    }

    #[test]
    fn npvt_password_is_enforced() {
        let text = make_npvt(&npvt_server("pw", "{\"isLocked\":true,\"password\":\"s3cret\"}"), "{}");
        assert_eq!(p(&text).unwrap_err(), ImportError::Password { wrong: false });
        assert_eq!(parse(&text, ConfigSource::Link, Some("nope"), NOW).unwrap_err(), ImportError::Password { wrong: true });
        assert_eq!(parse(&text, ConfigSource::Link, Some("s3cret"), NOW).unwrap().len(), 1);
    }

    #[test]
    fn npvt_expiry_device_binding_and_mobile_only() {
        let expired = make_npvt(&npvt_server("old", "{\"isLocked\":true,\"expiryDate\":\"2020-01-01\"}"), "{}");
        assert!(p(&expired).unwrap_err().to_string().contains("expired"));
        let bound = make_npvt(&npvt_server("dev", "{\"isLocked\":true,\"deviceIds\":\"abc\"}"), "{}");
        assert!(p(&bound).unwrap_err().to_string().contains("devices"));
        // Windows: mobile-only is refused at import, with a clear reason.
        let mobile = make_npvt(&npvt_server("mob", "{\"isLocked\":true,\"onlyMobileNetwork\":true,\"expiryDate\":\"2099-01-01\"}"), "{}");
        let e = p(&mobile).unwrap_err().to_string();
        assert!(e.contains("mobile data"), "{e}");
        // A future expiry is kept and enforced later.
        let future = make_npvt(&npvt_server("ok", "{\"isLocked\":true,\"expiryDate\":\"2099-01-01\"}"), "{}");
        let c = one(&future);
        assert!(c.expires_at > NOW);
        assert!(!c.is_expired(NOW));
        assert!(c.is_expired(c.expires_at + 1));
    }

    #[test]
    fn expiry_formats() {
        assert_eq!(parse_expiry(""), 0);
        assert_eq!(parse_expiry("1700000000"), 1_700_000_000_000);
        assert_eq!(parse_expiry("1700000000000"), 1_700_000_000_000);
        assert_eq!(parse_expiry("1970-01-02"), 86_400_000);
        assert_eq!(parse_expiry("2023-11-14T22:13:20"), 1_700_000_000_000);
        assert_eq!(parse_expiry("2023-11-14T22:13:20Z"), 1_700_000_000_000);
        assert_eq!(parse_expiry("2023-11-14 22:13"), 1_699_999_980_000);
        assert_eq!(parse_expiry("2024/02/29"), 1_709_164_800_000);
        assert_eq!(parse_expiry("2023-02-30"), 0);
        assert_eq!(parse_expiry("soon"), 0);
    }

    #[test]
    fn host_port_helpers() {
        assert_eq!(split_host_port("[::1]:80").unwrap(), ("::1".into(), 80));
        assert!(split_host_port("host:0").is_err());
        assert!(split_host_port("host").is_err());
        assert!(split_host_port(":80").is_err());
        assert_eq!(host_port("::1", 80), "[::1]:80");
        assert_eq!(decode_loose("aGVsbG8"), Some("hello".into()));
        assert_eq!(decode_loose("not base64!"), None);
        assert_eq!(decode("a%2Fb+c"), "a/b+c");
        assert_eq!(decode("bad%zz"), "bad%zz");
    }
}
