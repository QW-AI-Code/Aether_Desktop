//! 1.5.0 (same version): which programs use the tunnel right now — the
//! traffic popup of the connection card.
//!
//! In the Windows edition programs reach the tunnel through Aether's local
//! proxy (system proxy -> `127.0.0.1:10811` HTTP, `127.0.0.1:10810` SOCKS5).
//! Every program with an open TCP connection to one of those ports is using
//! the tunnel at this moment. The list comes from `netstat -ano` (connections
//! with their owning process id) and `tasklist` (process names), both run
//! without a console window; nothing is installed or hooked. Windows does not
//! keep per-program byte counters for loopback connections without extended
//! TCP statistics, so the popup shows the number of open connections per
//! program, plus the session totals.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// Local proxy ports the system proxy points at (`sysproxy.rs`).
pub const PROXY_PORTS: [u16; 2] = [10811, 10810];

/// One `netstat -ano` TCP line: (local, remote, pid). Header and UDP lines -> None.
pub fn parse_netstat_line(line: &str) -> Option<(String, String, u32)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 5 || !cols[0].eq_ignore_ascii_case("TCP") {
        return None;
    }
    let pid = cols[cols.len() - 1].parse::<u32>().ok()?;
    Some((cols[1].to_string(), cols[2].to_string(), pid))
}

fn port_of(endpoint: &str) -> Option<u16> {
    endpoint.rsplit(':').next()?.parse().ok()
}

fn is_loopback(endpoint: &str) -> bool {
    endpoint.starts_with("127.") || endpoint.starts_with("[::1]")
}

/// Connections per pid whose remote end is one of [`PROXY_PORTS`] on loopback,
/// excluding `own_pid` (Aether talking to itself).
pub fn proxy_clients(netstat: &str, own_pid: u32) -> BTreeMap<u32, usize> {
    let mut out = BTreeMap::new();
    for line in netstat.lines() {
        let Some((_local, remote, pid)) = parse_netstat_line(line) else { continue };
        if pid == 0 || pid == own_pid || !is_loopback(&remote) {
            continue;
        }
        if port_of(&remote).map(|p| PROXY_PORTS.contains(&p)).unwrap_or(false) {
            *out.entry(pid).or_insert(0) += 1;
        }
    }
    out
}

/// `tasklist /fo csv /nh` -> pid -> image name.
pub fn parse_tasklist(csv: &str) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    for line in csv.lines() {
        let fields: Vec<&str> = line.split("\",\"").collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim_start_matches('"').to_string();
        if let Ok(pid) = fields[1].trim_end_matches('"').parse::<u32>() {
            out.insert(pid, name);
        }
    }
    out
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The programs connected to the tunnel's local proxy, most connections first.
#[tauri::command]
pub async fn app_connections() -> Value {
    let result = tauri::async_runtime::spawn_blocking(|| {
        let Some(netstat) = run("netstat", &["-ano", "-p", "TCP"]) else {
            return json!({ "available": false, "apps": [] });
        };
        let clients = proxy_clients(&netstat, std::process::id());
        let names = run("tasklist", &["/fo", "csv", "/nh"]).map(|t| parse_tasklist(&t)).unwrap_or_default();
        // Several processes of one program (browsers) are one row.
        let mut by_name: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (pid, n) in clients {
            let name = names.get(&pid).cloned().unwrap_or_else(|| format!("PID {pid}"));
            let e = by_name.entry(name).or_insert((0, 0));
            e.0 += n;
            e.1 += 1;
        }
        let mut apps: Vec<Value> = by_name
            .into_iter()
            .map(|(name, (connections, processes))| json!({ "name": name, "connections": connections, "processes": processes }))
            .collect();
        apps.sort_by(|a, b| b["connections"].as_u64().cmp(&a["connections"].as_u64()));
        json!({ "available": true, "apps": apps })
    })
    .await;
    result.unwrap_or_else(|_| json!({ "available": false, "apps": [] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETSTAT: &str = "\r
Active Connections\r
\r
  Proto  Local Address          Foreign Address        State           PID\r
  TCP    127.0.0.1:52001        127.0.0.1:10811        ESTABLISHED     4242\r
  TCP    127.0.0.1:52002        127.0.0.1:10811        ESTABLISHED     4242\r
  TCP    127.0.0.1:52003        127.0.0.1:10810        ESTABLISHED     5151\r
  TCP    127.0.0.1:10811        127.0.0.1:52001        ESTABLISHED     900\r
  TCP    192.168.1.5:52004      93.184.216.34:443      ESTABLISHED     4242\r
  TCP    127.0.0.1:52005        127.0.0.1:10811        ESTABLISHED     900\r
";

    #[test]
    fn only_clients_of_the_local_proxy_count() {
        let c = proxy_clients(NETSTAT, 900);
        assert_eq!(c.get(&4242), Some(&2));
        assert_eq!(c.get(&5151), Some(&1));
        assert!(!c.contains_key(&900));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn tasklist_csv_is_parsed() {
        let t = parse_tasklist("\"chrome.exe\",\"4242\",\"Console\",\"1\",\"120,000 K\"\r\n\"Telegram.exe\",\"5151\",\"Console\",\"1\",\"80,000 K\"\r\n");
        assert_eq!(t.get(&4242).map(String::as_str), Some("chrome.exe"));
        assert_eq!(t.get(&5151).map(String::as_str), Some("Telegram.exe"));
    }
}
