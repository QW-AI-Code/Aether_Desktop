//! 1.5.0 (same version): the numbers behind the latency popup of the
//! connection card — and the "Measure 10 times" button.
//!
//! Every live-latency probe of the current session (`state.rs`, one warm round
//! trip every LATENCY_INTERVAL_SECS) is recorded here, `None` for a probe that
//! got no answer. A new session starts empty.

use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::VecDeque;

const HISTORY: usize = 120;

fn cell() -> &'static Mutex<VecDeque<Option<u64>>> {
    static CELL: std::sync::OnceLock<Mutex<VecDeque<Option<u64>>>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| Mutex::new(VecDeque::with_capacity(HISTORY)))
}

/// One probe result of the live tunnel.
pub fn record(sample: Option<u64>) {
    let mut q = cell().lock();
    if q.len() >= HISTORY {
        q.pop_front();
    }
    q.push_back(sample);
}

/// Forgets the samples of the previous session / circuit.
pub fn reset() {
    cell().lock().clear();
}

/// last / min / max / average / jitter / loss of `samples` (pure, unit-tested).
pub fn summary(samples: &[Option<u64>]) -> Value {
    let ok: Vec<u64> = samples.iter().filter_map(|s| *s).collect();
    let total = samples.len();
    let loss = if total == 0 { 0 } else { ((total - ok.len()) * 100 + total / 2) / total };
    let last = samples.last().copied().flatten();
    if ok.is_empty() {
        return json!({ "samples": total, "answered": 0, "min": null, "max": null, "avg": null,
            "jitter": null, "loss": loss, "last": last });
    }
    let min = *ok.iter().min().unwrap_or(&0);
    let max = *ok.iter().max().unwrap_or(&0);
    let avg = (ok.iter().sum::<u64>() as f64 / ok.len() as f64).round() as u64;
    let jitter = if ok.len() < 2 {
        0
    } else {
        let diffs: u64 = ok.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
        (diffs as f64 / (ok.len() - 1) as f64).round() as u64
    };
    json!({ "samples": total, "answered": ok.len(), "min": min, "max": max, "avg": avg,
        "jitter": jitter, "loss": loss, "last": last })
}

#[tauri::command]
pub fn ping_stats() -> Value {
    let samples: Vec<Option<u64>> = cell().lock().iter().copied().collect();
    summary(&samples)
}

/// Ten extra probes through the live tunnel, recorded like the periodic ones.
#[tauri::command]
pub async fn ping_burst() -> Value {
    let _ = tauri::async_runtime::spawn_blocking(|| {
        for _ in 0..10 {
            let mut got = crate::ping::measure();
            if got.is_none() {
                // The periodic probe may hold the warm session for a moment.
                std::thread::sleep(std::time::Duration::from_millis(250));
                got = crate::ping::measure();
            }
            record(got);
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    })
    .await;
    ping_stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_of_a_mixed_series() {
        let v = summary(&[Some(100), Some(120), None, Some(80)]);
        assert_eq!(v["samples"], 4);
        assert_eq!(v["answered"], 3);
        assert_eq!(v["min"], 80);
        assert_eq!(v["max"], 120);
        assert_eq!(v["avg"], 100);
        assert_eq!(v["jitter"], 30);
        assert_eq!(v["loss"], 25);
        assert_eq!(v["last"], 80);
    }

    #[test]
    fn empty_and_all_lost() {
        assert_eq!(summary(&[])["samples"], 0);
        let v = summary(&[None, None]);
        assert_eq!(v["loss"], 100);
        assert!(v["avg"].is_null());
    }
}
