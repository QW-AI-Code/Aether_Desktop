//! 1.5.0 (same version): "Send diagnostics".
//!
//! Builds a REDACTED report (the same `ai_redaction` the assistant uses: no
//! IPs, host names, UUIDs or keys) and the GitHub "new issue" URL for it. No
//! server of our own and no token: a token inside a public installer would let
//! anyone write to the repository. The UI copies the full report to the
//! clipboard and opens the issue page in the browser; the user pastes and
//! submits. Nothing leaves the PC without that last click, and the switch in
//! Settings turns the whole feature off.

use serde_json::{json, Value};

/// Where reports are filed (same repository as the releases, see `RELEASES_URL`).
pub const ISSUES_URL: &str = "https://github.com/QW-AI-Code/Aether_Desktop/issues/new";
const LOG_LINES: usize = 400;
/// GitHub refuses very long URLs; the pre-filled summary stays far below that.
const SUMMARY_CHARS: usize = 1200;

/// RFC 3986 percent-encoding of a query value.
pub fn encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len() * 3);
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// The report text and the pre-filled issue URL.
pub fn build(kind: &str, detail: &str, log: &str) -> (String, String) {
    let kind = match kind {
        "crash" | "connection failed" | "report" => kind,
        _ => "report",
    };
    let lines: Vec<&str> = log.lines().collect();
    let tail = lines[lines.len().saturating_sub(LOG_LINES)..].join("\n");
    let log = crate::ai_redaction::redact_all(&tail, "");
    let detail = crate::ai_redaction::redact_all(if detail.trim().is_empty() { "-" } else { detail }, "");
    let report = format!(
        "### Aether Desktop diagnostics report\n- kind: {kind}\n- app: {}\n- os: {} {}\n\n#### What happened\n{detail}\n\n#### Recent log (redacted)\n```\n{}\n```\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        if log.trim().is_empty() { "-" } else { log.as_str() },
    );
    let short = take_chars(detail.lines().find(|l| !l.trim().is_empty()).unwrap_or(""), 80);
    let title = if short.is_empty() {
        format!("[{kind}] Aether Desktop {}", env!("CARGO_PKG_VERSION"))
    } else {
        format!("[{kind}] Aether Desktop {}: {short}", env!("CARGO_PKG_VERSION"))
    };
    let body = format!(
        "{}\n\n---\nThe full redacted report was copied to your clipboard. Paste it here before submitting.\n\n",
        take_chars(&report, SUMMARY_CHARS)
    );
    let url = format!("{ISSUES_URL}?title={}&body={}", encode(&title), encode(&body));
    (report, url)
}

#[tauri::command]
pub fn diagnostics_report(kind: String, detail: String) -> Value {
    let (report, url) = build(&kind, &detail, &crate::log::DiagnosticsLog::export_text());
    crate::log::DiagnosticsLog::i("diag", &format!("Diagnostics report prepared ({kind})."));
    json!({ "report": report, "url": url })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_is_github_and_encoded() {
        let (report, url) = build("connection failed", "Engine died\nmore", "a\nb");
        assert!(url.starts_with("https://github.com/QW-AI-Code/Aether_Desktop/issues/new?title="));
        assert!(!url.contains(' ') && !url.contains('\n'));
        assert!(report.contains("connection failed") && report.contains("Engine died"));
        assert_eq!(encode("a b/ü"), "a%20b%2F%C3%BC");
    }

    #[test]
    fn unknown_kinds_are_reports() {
        let (report, _) = build("<script>", "", "");
        assert!(report.contains("- kind: report"));
    }
}
