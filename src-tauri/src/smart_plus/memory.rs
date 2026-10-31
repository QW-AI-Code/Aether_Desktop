//! Mobile SmartPlusMemory 1.6.0: bounded, expiring, per-network evidence only.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Mutex};
pub const PROVEN_TTL_MS: i64 = 14 * 24 * 60 * 60 * 1000;
pub const FAILED_TTL_MS: i64 = 6 * 60 * 60 * 1000;
pub const MAX_NETWORKS: usize = 32;
const FILE: &str = "smart_plus_memory.json";
static IO: Mutex<()> = Mutex::new(());
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    #[serde(rename = "t")]
    pub tactic_id: Option<String>,
    #[serde(rename = "p")]
    pub proven_at: i64,
    #[serde(rename = "f", default)]
    pub failed_at: BTreeMap<String, i64>,
}
impl Entry {
    pub fn proven(&self, now: i64) -> bool {
        self.tactic_id.is_some()
            && now
                .checked_sub(self.proven_at)
                .map(|age| (0..=PROVEN_TTL_MS).contains(&age))
                .unwrap_or(false)
    }
    pub fn failed(&self, id: &str, now: i64) -> bool {
        self.failed_at
            .get(id)
            .and_then(|at| now.checked_sub(*at))
            .map(|age| (0..=FAILED_TTL_MS).contains(&age))
            .unwrap_or(false)
    }
}
#[derive(Default, Serialize, Deserialize)]
struct Disk {
    v: u32,
    n: BTreeMap<String, Entry>,
}
fn read(dir: &Path) -> BTreeMap<String, Entry> {
    let path = dir.join(FILE);
    if std::fs::metadata(&path)
        .map(|m| m.len() > 65536)
        .unwrap_or(true)
    {
        return BTreeMap::new();
    }
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Disk>(&b).ok())
        .filter(|d| d.v == 1)
        .map(|d| d.n)
        .unwrap_or_default()
}
pub fn prune(map: BTreeMap<String, Entry>, now: i64, max: usize) -> BTreeMap<String, Entry> {
    let mut rows: Vec<_> = map
        .into_iter()
        .map(|(key, mut e)| {
            e.failed_at.retain(|_, at| {
                now.checked_sub(*at)
                    .map(|a| (0..=FAILED_TTL_MS).contains(&a))
                    .unwrap_or(false)
            });
            if !e.proven(now) {
                e.tactic_id = None;
                e.proven_at = 0;
            }
            (key, e)
        })
        .filter(|(_, e)| e.tactic_id.is_some() || !e.failed_at.is_empty())
        .collect();
    rows.sort_by_key(|(key, e)| {
        (
            std::cmp::Reverse(
                e.proven_at
                    .max(e.failed_at.values().copied().max().unwrap_or(0)),
            ),
            key.clone(),
        )
    });
    rows.truncate(max);
    rows.into_iter().collect()
}
pub fn recall(dir: &Path, key: &str) -> Option<Entry> {
    if key == "none" {
        return None;
    }
    let _g = IO.lock().unwrap_or_else(|e| e.into_inner());
    read(dir).remove(key)
}
fn edit(dir: &Path, key: &str, id: &str, now: i64, success: bool) {
    if key.len() != 12 || !key.bytes().all(|b| b.is_ascii_hexdigit()) || !super::plan::known_id(id)
    {
        return;
    }
    let _g = IO.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = read(dir);
    let e = map.entry(key.into()).or_default();
    if success {
        e.tactic_id = Some(id.into());
        e.proven_at = now;
        e.failed_at.remove(id);
    } else {
        if e.tactic_id.as_deref() == Some(id) {
            e.tactic_id = None;
            e.proven_at = 0;
        }
        e.failed_at.insert(id.into(), now);
    }
    let data = serde_json::to_vec(&Disk {
        v: 1,
        n: prune(map, now, MAX_NETWORKS),
    })
    .unwrap_or_default();
    let tmp = dir.join(format!(".{FILE}.tmp-{}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, dir.join(FILE))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
}
pub fn remember(dir: &Path, key: &str, id: &str, now: i64) {
    edit(dir, key, id, now, true)
}
pub fn failure(dir: &Path, key: &str, id: &str, now: i64) {
    edit(dir, key, id, now, false)
}
pub fn clear(dir: &Path) {
    let _g = IO.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::remove_file(dir.join(FILE));
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries() {
        let e = Entry {
            tactic_id: Some("wg".into()),
            proven_at: 100,
            failed_at: BTreeMap::from([("masque.h2".into(), 100)]),
        };
        assert!(e.proven(100 + PROVEN_TTL_MS));
        assert!(!e.proven(99));
        assert!(!e.proven(101 + PROVEN_TTL_MS));
        assert!(e.failed("masque.h2", 100 + FAILED_TTL_MS));
        assert!(!e.failed("masque.h2", 101 + FAILED_TTL_MS));
    }
    #[test]
    fn bounded_and_stale() {
        let m = (0..40)
            .map(|i| {
                (
                    i.to_string(),
                    Entry {
                        tactic_id: Some("wg".into()),
                        proven_at: 100 + i,
                        failed_at: BTreeMap::new(),
                    },
                )
            })
            .collect();
        let p = prune(m, 150, 32);
        assert_eq!(p.len(), 32);
        assert!(!p.contains_key("0"));
        assert!(prune(p, PROVEN_TTL_MS + 1000, 32).is_empty());
    }
    #[test]
    fn persistence_failure_clear_and_isolation() {
        let dir = std::env::temp_dir().join(format!("smart-memory-{}", crate::custom::new_id()));
        let k = "012345abcdef";
        remember(&dir, k, "wg", 100);
        assert_eq!(recall(&dir, k).unwrap().tactic_id.as_deref(), Some("wg"));
        assert!(recall(&dir, "aaaaaaaaaaaa").is_none());
        failure(&dir, k, "wg", 110);
        assert!(recall(&dir, k).unwrap().tactic_id.is_none());
        remember(&dir, k, "wg", 120);
        assert!(recall(&dir, k).unwrap().failed_at.is_empty());
        clear(&dir);
        assert!(recall(&dir, k).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn corrupt_and_unknown_do_not_create_global_memory() {
        let dir = std::env::temp_dir().join(format!("smart-corrupt-{}", crate::custom::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE), b"broken").unwrap();
        assert!(recall(&dir, "012345abcdef").is_none());
        remember(&dir, "none", "wg", 1);
        assert!(recall(&dir, "none").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
