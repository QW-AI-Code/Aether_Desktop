//! NPVO1 plain-text export (port of mobile NpvoCodec.kt).
//! line 1: `NPVO1`; then JSON `{"configs":[{..,"v2rayProfile":{..}}]}`.
//! String values may be `npvs1:<base64>` — an encoding, not encryption.
use super::{npvt::{self, Decoded}, parser::ImportError};
use serde_json::{json, Map, Value};

const HEADER: &str = "NPVO1";
const SENTINEL: &str = "npvs1:";
const MAX_CONFIGS: usize = 500;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 48;
type R<T> = Result<T, ImportError>;
fn bad(s: &str) -> ImportError { ImportError::Invalid(s.into()) }
fn trim(t: &str) -> &str { t.trim_start_matches(|c| matches!(c, '\u{feff}' | ' ' | '\n' | '\r' | '\t')) }

pub fn looks_like(text: &str) -> bool {
    let t = trim(text);
    if !t.starts_with(HEADER) { return false; }
    match t[HEADER.len()..].chars().next() {
        None => true,
        Some(c) => matches!(c, '\n' | '\r' | ' ' | '\t' | '{'),
    }
}

fn has_lock(o: &Map<String, Value>) -> bool {
    ["lockConfig", "policy", "lock", "isLocked"].iter().any(|k| o.contains_key(*k))
}

fn check_depth(text: &str) -> R<()> {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for c in text.chars() {
        if quoted {
            if escaped { escaped = false } else if c == '\\' { escaped = true } else if c == '"' { quoted = false }
        } else {
            match c {
                '"' => quoted = true,
                '{' | '[' => { depth += 1; if depth > MAX_DEPTH { return Err(bad("NPVO1 file is nested too deeply")); } }
                '}' | ']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

fn decode_sentinel(s: &str) -> R<Option<String>> {
    let Some(rest) = s.strip_prefix(SENTINEL) else { return Ok(None) };
    let enc_err = || bad("bad npvs1 value encoding");
    if rest.is_empty() || !rest.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=_-".contains(&c)) { return Err(enc_err()); }
    let bytes = npvt::decode_base64(rest).ok_or_else(enc_err)?;
    String::from_utf8(bytes).map(Some).map_err(|_| enc_err())
}

fn substitute(v: &Value, depth: usize) -> R<Value> {
    if depth > MAX_DEPTH { return Err(bad("NPVO1 file is nested too deeply")); }
    Ok(match v {
        Value::Object(o) => {
            if has_lock(o) { return Err(bad("locked NPVO1 files are not supported")); }
            Value::Object(o.iter().map(|(k, v)| Ok((k.clone(), substitute(v, depth + 1)?))).collect::<R<Map<_, _>>>()?)
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| substitute(v, depth + 1)).collect::<R<Vec<_>>>()?),
        Value::String(s) => match decode_sentinel(s)? { Some(d) => Value::String(d), None => v.clone() },
        _ => v.clone(),
    })
}

fn prim(v: Option<&Value>) -> String {
    match v { Some(Value::String(s)) => s.clone(), Some(Value::Number(n)) => n.to_string(), Some(Value::Bool(b)) => b.to_string(), _ => String::new() }
}

pub fn decode(text: &str) -> R<Decoded> {
    if text.len() > MAX_BYTES { return Err(bad("NPVO1 file is too large")); }
    check_depth(text)?;
    let t = trim(text);
    if !looks_like(t) { return Err(bad("not an NPVO1 file")); }
    let body = t[HEADER.len()..].trim();
    if body.is_empty() { return Err(bad("the NPVO1 file holds no servers")); }
    let root = match serde_json::from_str::<Value>(body) { Ok(Value::Object(o)) => o, _ => return Err(bad("NPVO1 body is not a JSON object")) };
    if has_lock(&root) { return Err(bad("locked NPVO1 files are not supported")); }
    let Some(Value::Array(configs)) = root.get("configs") else { return Err(bad("NPVO1 file has no configs array")) };
    if configs.is_empty() { return Err(bad("the NPVO1 file holds no servers")); }
    if configs.len() > MAX_CONFIGS { return Err(bad("NPVO1 file holds too many servers")); }
    let mut servers = Vec::new();
    for el in configs {
        let Value::Object(obj) = el else { return Err(bad("invalid NPVO1 server")) };
        if has_lock(obj) { return Err(bad("locked NPVO1 files are not supported")); }
        let Some(Value::Object(profile)) = obj.get("v2rayProfile") else { return Err(bad("NPVO1 V2Ray profile missing")) };
        let Value::Object(dp) = substitute(&Value::Object(profile.clone()), 0)? else { unreachable!() };
        let val = |k: &str| prim(dp.get(k));
        if !matches!(val("configType").parse::<i64>(), Ok(1 | 3 | 5 | 6)) { return Err(bad("unsupported NPVO1 server type")); }
        if val("server").trim().is_empty() || !matches!(val("serverPort").parse::<u32>(), Ok(1..=65535)) { return Err(bad("invalid NPVO1 endpoint")); }
        if val("password").trim().is_empty() { return Err(bad("NPVO1 credentials missing")); }
        if let Some(ty) = obj.get("type") { if prim(Some(ty)) != "V2RAY" { return Err(bad("unsupported NPVO1 server type")); } }
        let mut out = obj.clone();
        out.insert("v2rayProfile".into(), Value::Object(dp));
        out.insert("type".into(), json!("V2RAY"));
        servers.push(Value::Object(out));
    }
    Ok(Decoded { version: 1, servers: Value::Array(servers).to_string(), lock: "{}".into() })
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &str = include_str!("testdata/npvo_sample.npvs");
    #[test] fn header_detection() {
        assert!(looks_like("NPVO1\n{}")); assert!(looks_like("\u{feff} NPVO1"));
        assert!(!looks_like("NPVO10")); assert!(!looks_like("NPVOX")); assert!(!looks_like("NPVT1"));
    }
    #[test] fn sample_imports_via_parse_and_bytes() {
        let a = super::super::parser::parse(SAMPLE, crate::custom::ConfigSource::File, None, 0).expect("parse");
        assert!(!a.is_empty());
        let b = super::super::parser::parse_bytes(SAMPLE.as_bytes(), crate::custom::ConfigSource::File, None, 0).expect("bytes");
        assert_eq!(a.len(), b.len());
        eprintln!("imported {} servers; first={:?}", a.len(), a[0].name);
    }
    #[test] fn rejects_locked_and_bad() {
        assert!(decode("NPVO1\n{\"lock\":1,\"configs\":[]}").is_err());
        assert!(decode("NPVO1\n{\"configs\":[]}").is_err());
        assert!(decode("NPVO1\n{\"configs\":[{\"v2rayProfile\":{\"configType\":5,\"server\":\"npvs1:!!\",\"serverPort\":1,\"password\":\"x\"}}]}").is_err());
    }
    #[test] fn sample_imports_from_npvs_file_on_disk() {
        let dir = std::env::temp_dir().join("aether-npvo-test"); std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("Config.npvs"); std::fs::write(&f, SAMPLE).unwrap();
        let cfgs = super::super::import::from_file(&f, None).expect("file import");
        assert_eq!(cfgs.len(), 3);
        for c in &cfgs { assert!(!super::super::present::display_endpoint(c).is_empty(), "endpoint for {}", c.name); }
        let ep = super::super::present::display_endpoint(&cfgs[0]);
        eprintln!("endpoint0={ep}"); assert_eq!(ep, "217.69.167.203:43000");
    }
}
