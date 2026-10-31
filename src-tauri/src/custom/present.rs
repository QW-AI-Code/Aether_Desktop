//! Display-only endpoint for a server row (port of mobile ServerPresentation.kt).
//! Never exposes names, adverts, credentials, SNI/WS-Host or *.workers.dev hosts.
use super::CustomConfig;
use serde_json::Value;
use std::net::IpAddr;

/// `host:port` with a validated IP literal or DNS name; empty string when none is honest.
pub fn clean_endpoint(value: &str) -> String {
    let v = value.trim();
    if v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}' | '/' | '?' | '#' | '@')) { return String::new(); }
    let (host, port) = if let Some(rest) = v.strip_prefix('[') {
        let Some((h, p)) = rest.split_once("]:") else { return String::new() };
        (h.to_string(), p)
    } else {
        let Some((h, p)) = v.rsplit_once(':') else { return String::new() };
        if h.contains(':') { return String::new(); }
        (h.to_string(), p)
    };
    let Ok(port) = port.parse::<u16>() else { return String::new() };
    if port == 0 { return String::new(); }
    let host = host.trim_end_matches('.').to_lowercase();
    if host == "workers.dev" || host.ends_with(".workers.dev") { return String::new(); }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if ip.is_ipv6() { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") };
    }
    let ok = host.len() <= 253 && host.contains('.')
        && host.split('.').all(|l| (1..=63).contains(&l.len())
            && l.chars().next().map_or(false, |c| c.is_ascii_alphanumeric())
            && l.chars().last().map_or(false, |c| c.is_ascii_alphanumeric())
            && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        && !host.chars().all(|c| c.is_ascii_digit() || c == '.');
    if ok { format!("{host}:{port}") } else { String::new() }
}

/// Prefer the actual outbound dial target over imported display metadata.
pub fn display_endpoint(c: &CustomConfig) -> String {
    if c.locked { return String::new(); }
    let target = serde_json::from_str::<Value>(&c.outbound).ok().and_then(|o| {
        let s = o.get("settings")?;
        let first = s.get("vnext").or_else(|| s.get("servers"))?.as_array()?.first()?;
        let addr = first.get("address")?.as_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
        let port = first.get("port").and_then(|p| p.as_u64());
        Some(match port {
            Some(p) => clean_endpoint(&if addr.contains(':') { format!("[{addr}]:{p}") } else { format!("{addr}:{p}") }),
            None => String::new(),
        })
    });
    target.unwrap_or_else(|| clean_endpoint(&c.server))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn endpoints() {
        assert_eq!(clean_endpoint("1.2.3.4:443"), "1.2.3.4:443");
        assert_eq!(clean_endpoint("Example.COM:8443"), "example.com:8443");
        assert_eq!(clean_endpoint("[2001:db8::1]:443"), "[2001:db8::1]:443");
        assert_eq!(clean_endpoint("a.b.workers.dev:443"), "");
        assert_eq!(clean_endpoint("host:0"), "");
        assert_eq!(clean_endpoint("user@h.com:1"), "");
        assert_eq!(clean_endpoint("localhost:1"), "");
    }
}
