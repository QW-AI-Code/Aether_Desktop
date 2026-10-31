//! Shared production scheduler; tests use deterministic fake probes, never a fake scheduler.
use super::plan::{Lane, Tactic};
use crate::custom::cancel::Cancel;
use std::{
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
pub fn run<F, S>(
    lanes: Vec<Lane>,
    cancel: Arc<Cancel>,
    ceiling: Duration,
    attempt: F,
    stop: S,
) -> Option<Tactic>
where
    F: Fn(usize, &Tactic, &Arc<Cancel>) -> bool + Sync,
    S: Fn() + Sync,
{
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        for (index, lane) in lanes.into_iter().take(2).enumerate() {
            let tx = tx.clone();
            let cancel = cancel.clone();
            let attempt = &attempt;
            scope.spawn(move || {
                while started.elapsed() < Duration::from_millis(lane.start_after_ms) {
                    if cancel.stopped() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                for tactic in lane.tactics {
                    if cancel.stopped()
                        || started.elapsed() + Duration::from_millis(tactic.budget_ms) > ceiling
                    {
                        return;
                    }
                    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        attempt(index, &tactic, &cancel)
                    }))
                    .unwrap_or(false);
                    if cancel.stopped() {
                        return;
                    }
                    if ok {
                        let _ = tx.send(tactic);
                        return;
                    }
                }
            });
        }
        drop(tx);
        let winner = loop {
            if cancel.stopped() || started.elapsed() >= ceiling {
                break None;
            }
            match rx.recv_timeout(Duration::from_millis(2)) {
                Ok(t) => break Some(t),
                Err(mpsc::RecvTimeoutError::Disconnected) => break None,
                Err(_) => {}
            }
        };
        cancel.cancel();
        stop();
        winner
    }) // scope joins every child before the result escapes.
}
#[cfg(test)]
mod tests {
    use super::super::plan::*;
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    /// Ceiling for tests that are not about the ceiling: slow CI runners
    /// (notably i686 with backtrace symbolisation) must never turn a logic
    /// test into a timing test.
    const GENEROUS_CEILING: Duration = Duration::from_secs(30);
    fn lanes() -> Vec<Lane> {
        [Family::Warp, Family::Masque]
            .into_iter()
            .map(|f| Lane {
                tactics: tactics(f, Dpi::Open, false)
                    .into_iter()
                    .map(|mut t| {
                        t.budget_ms = 5;
                        t
                    })
                    .collect(),
                start_after_ms: 0,
            })
            .collect()
    }
    #[test]
    fn two_families_parallel_serial_inside_lane() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let counts = Mutex::new([0, 0]);
        let barrier = std::sync::Barrier::new(2);
        let out = run(
            lanes(),
            Cancel::new(),
            GENEROUS_CEILING,
            |lane, _, _| {
                let first = {
                    let mut c = counts.lock().unwrap();
                    c[lane] += 1;
                    c[lane] == 1
                };
                let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                if first {
                    barrier.wait();
                }
                thread::sleep(Duration::from_millis(15));
                active.fetch_sub(1, Ordering::SeqCst);
                false
            },
            || {},
        );
        assert!(out.is_none());
        assert_eq!(*counts.lock().unwrap(), [3, 3]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn early_winner_never_starts_delayed_lane() {
        let mut l = lanes();
        l[1].start_after_ms = 100;
        let called = Mutex::new(vec![]);
        let out = run(
            l,
            Cancel::new(),
            GENEROUS_CEILING,
            |i, t, _| {
                called.lock().unwrap().push(i);
                t.id == "wg"
            },
            || {},
        );
        assert_eq!(out.unwrap().id, "wg");
        assert_eq!(*called.lock().unwrap(), vec![0]);
    }
    #[test]
    fn cancellation_joins_both_lanes() {
        let token = Cancel::new();
        let c = token.clone();
        let alive = AtomicUsize::new(0);
        thread::scope(|s| {
            s.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                c.cancel();
            });
            assert!(run(
                lanes(),
                token,
                GENEROUS_CEILING,
                |_, _, c| {
                    alive.fetch_add(1, Ordering::SeqCst);
                    while !c.stopped() {
                        thread::sleep(Duration::from_millis(1));
                    }
                    alive.fetch_sub(1, Ordering::SeqCst);
                    false
                },
                || {}
            )
            .is_none());
        });
        assert_eq!(alive.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn ceiling_and_exhaustion_stop_without_success() {
        let stopped = AtomicUsize::new(0);
        let out = run(
            lanes(),
            Cancel::new(),
            Duration::ZERO,
            |_, _, _| panic!("must not start"),
            || {
                stopped.fetch_add(1, Ordering::SeqCst);
            },
        );
        assert!(out.is_none());
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn failed_or_panicking_tactic_does_not_suppress_fallback() {
        // Run 2026-10-16 (Build x86): this test failed on the i686 runner while
        // x64 passed. The panicking "wg" probe prints a RUST_BACKTRACE=1
        // backtrace, and symbolising it on 32-bit MSVC under a parallel test
        // load took >1 s - longer than the 1 s ceiling - so the lane returned
        // before "gool" was ever tried and `out` was `None`. The ceiling is not
        // what this test is about (that is `ceiling_and_exhaustion_stop_without_
        // success`), so it is generous here; the fallback itself is still
        // asserted exactly as before.
        let mut l = lanes();
        l.truncate(1);
        let out = run(
            l,
            Cancel::new(),
            GENEROUS_CEILING,
            |_, t, _| {
                if t.id == "wg" {
                    panic!("probe failure");
                }
                t.id == "gool"
            },
            || {},
        );
        assert_eq!(out.expect("fallback tactic must still win").id, "gool");
    }
}
