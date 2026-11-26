//! Shared production scheduler (mobile 1.7.0 `runRace`); tests use deterministic
//! fake probes, never a fake scheduler.
//!
//! Every lane walks its tactics serially; the lanes run side by side. A lane
//! stops at its first proven tactic and **leaves that engine running** - the
//! caller measures it afterwards. Once the first route is proven, the other
//! lanes get `window` more to prove one too; then every lane that has not
//! proven anything is cancelled and stopped through `stop_lane`.
use super::plan::{Lane, Tactic};
use crate::custom::cancel::Cancel;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
/// A tactic that carried real traffic, still running on its lane's engine.
#[derive(Debug, Clone)]
pub struct Proven {
    pub tactic: Tactic,
    pub lane: usize,
    pub after_ms: u64,
}
struct Board {
    decided: bool,
    proven: Vec<Proven>,
}
fn lock(b: &Mutex<Board>) -> std::sync::MutexGuard<'_, Board> {
    b.lock().unwrap_or_else(|e| e.into_inner())
}
/// Decrements `searching` exactly once, however the lane ends (even on panic).
struct Searching<'a>(&'a AtomicUsize);
impl Drop for Searching<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
pub fn run<F, S>(
    lanes: Vec<Lane>,
    cancel: Arc<Cancel>,
    ceiling: Duration,
    window: Duration,
    attempt: F,
    stop_lane: S,
) -> Vec<Proven>
where
    F: Fn(usize, &Tactic, &Arc<Cancel>) -> bool + Sync,
    S: Fn(usize) + Sync,
{
    run_adaptive(lanes, cancel, ceiling, window, attempt, stop_lane, |_, rest| rest)
}

/// 1.5.0 (same version) - the Smart brain's scheduler: identical to [`run`],
/// except that before every tactic the lane's remaining tactics go through
/// `adapt(lane, remaining)` (see `brain::adapt`), so what one lane learned
/// re-plans both. Equivalent tactics (same carrier, obfuscation, HTTP/2 and
/// fragmentation) are never attempted twice in a lane.
pub fn run_adaptive<F, S, A>(
    lanes: Vec<Lane>,
    cancel: Arc<Cancel>,
    ceiling: Duration,
    window: Duration,
    attempt: F,
    stop_lane: S,
    adapt: A,
) -> Vec<Proven>
where
    F: Fn(usize, &Tactic, &Arc<Cancel>) -> bool + Sync,
    S: Fn(usize) + Sync,
    A: Fn(usize, Vec<Tactic>) -> Vec<Tactic> + Sync,
{
    let started = Instant::now();
    let lanes: Vec<Lane> = lanes.into_iter().take(2).collect();
    let tokens: Vec<Arc<Cancel>> = lanes.iter().map(|_| Cancel::new()).collect();
    let searching = AtomicUsize::new(lanes.len());
    let board = Mutex::new(Board {
        decided: false,
        proven: vec![],
    });
    thread::scope(|scope| {
        for (index, lane) in lanes.into_iter().enumerate() {
            let token = tokens[index].clone();
            let attempt = &attempt;
            let adapt = &adapt;
            let board = &board;
            let searching = &searching;
            scope.spawn(move || {
                let _searching = Searching(searching);
                while started.elapsed() < Duration::from_millis(lane.start_after_ms) {
                    if token.stopped() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                let mut queue: VecDeque<Tactic> = lane.tactics.into();
                let mut tried = Vec::new();
                loop {
                    let rest: Vec<Tactic> = queue.drain(..).collect();
                    queue = adapt(index, rest).into();
                    let Some(tactic) = queue.pop_front() else {
                        return;
                    };
                    let sig = (
                        tactic.family,
                        tactic.protocol,
                        tactic.noize,
                        tactic.h2,
                        tactic.fragment,
                    );
                    if tried.contains(&sig) {
                        continue;
                    }
                    tried.push(sig);
                    if token.stopped()
                        || started.elapsed() + Duration::from_millis(tactic.budget_ms) > ceiling
                    {
                        return;
                    }
                    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        attempt(index, &tactic, &token)
                    }))
                    .unwrap_or(false);
                    if token.stopped() {
                        return;
                    }
                    if ok {
                        let mut b = lock(board);
                        if !b.decided {
                            b.proven.push(Proven {
                                tactic,
                                lane: index,
                                after_ms: started.elapsed().as_millis() as u64,
                            });
                        }
                        return;
                    }
                }
            });
        }
        // Supervisor.
        let mut first_at: Option<Instant> = None;
        loop {
            if cancel.stopped() || started.elapsed() >= ceiling {
                break;
            }
            let any = !lock(&board).proven.is_empty();
            if searching.load(Ordering::SeqCst) == 0 {
                break;
            }
            if any {
                let at = *first_at.get_or_insert_with(Instant::now);
                if at.elapsed() >= window {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        let keep: Vec<usize> = {
            let mut b = lock(&board);
            b.decided = true;
            if cancel.stopped() {
                b.proven.clear();
            }
            b.proven.iter().map(|p| p.lane).collect()
        };
        for (i, token) in tokens.iter().enumerate() {
            token.cancel();
            if !keep.contains(&i) {
                stop_lane(i);
            }
        }
    }); // scope joins every lane before the result escapes.
    let out = std::mem::take(&mut lock(&board).proven);
    out
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
    const NO_WINDOW: Duration = Duration::ZERO;
    fn lanes() -> Vec<Lane> {
        [Family::Warp, Family::Masque]
            .into_iter()
            .map(|f| Lane {
                tactics: tactics(f, Context::new(Dpi::Open))
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
        let sizes: Vec<usize> = lanes().iter().map(|l| l.tactics.len()).collect();
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let counts = Mutex::new([0usize, 0]);
        let barrier = std::sync::Barrier::new(2);
        let out = run(
            lanes(),
            Cancel::new(),
            GENEROUS_CEILING,
            NO_WINDOW,
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
            |_| {},
        );
        assert!(out.is_empty());
        assert_eq!(counts.lock().unwrap().to_vec(), sizes);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn early_winner_without_window_never_starts_delayed_lane() {
        let mut l = lanes();
        l[1].start_after_ms = 100;
        let called = Mutex::new(vec![]);
        let stopped = Mutex::new(vec![]);
        let out = run(
            l,
            Cancel::new(),
            GENEROUS_CEILING,
            NO_WINDOW,
            |i, t, _| {
                called.lock().unwrap().push(i);
                t.id == "wg"
            },
            |i| stopped.lock().unwrap().push(i),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tactic.id, "wg");
        assert_eq!(out[0].lane, 0);
        assert_eq!(*called.lock().unwrap(), vec![0]);
        assert_eq!(*stopped.lock().unwrap(), vec![1], "only the unproven lane is stopped");
    }
    #[test]
    fn the_quality_window_lets_the_other_lane_prove_too() {
        let out = run(
            lanes(),
            Cancel::new(),
            GENEROUS_CEILING,
            Duration::from_secs(5),
            |i, t, _| {
                if i == 1 {
                    thread::sleep(Duration::from_millis(30));
                }
                t.id == "wg" || t.id == "masque.h3"
            },
            |_| {},
        );
        let got: Vec<_> = out.iter().map(|p| p.tactic.id).collect();
        assert_eq!(got, ["wg", "masque.h3"]);
    }
    #[test]
    fn an_expired_window_stops_the_lane_that_is_still_searching() {
        let stopped = Mutex::new(vec![]);
        let out = run(
            lanes(),
            Cancel::new(),
            GENEROUS_CEILING,
            Duration::from_millis(40),
            |i, t, c| {
                if i == 1 {
                    while !c.stopped() {
                        thread::sleep(Duration::from_millis(1));
                    }
                    return true; // too late: the race is decided
                }
                t.id == "wg"
            },
            |i| stopped.lock().unwrap().push(i),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tactic.id, "wg");
        assert_eq!(*stopped.lock().unwrap(), vec![1]);
    }
    #[test]
    fn cancellation_joins_both_lanes_and_proves_nothing() {
        let token = Cancel::new();
        let c = token.clone();
        let alive = AtomicUsize::new(0);
        let stopped = AtomicUsize::new(0);
        thread::scope(|s| {
            s.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                c.cancel();
            });
            assert!(run(
                lanes(),
                token,
                GENEROUS_CEILING,
                NO_WINDOW,
                |_, _, c| {
                    alive.fetch_add(1, Ordering::SeqCst);
                    while !c.stopped() {
                        thread::sleep(Duration::from_millis(1));
                    }
                    alive.fetch_sub(1, Ordering::SeqCst);
                    false
                },
                |_| {
                    stopped.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_empty());
        });
        assert_eq!(alive.load(Ordering::SeqCst), 0);
        assert_eq!(stopped.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn ceiling_and_exhaustion_stop_without_success() {
        let stopped = AtomicUsize::new(0);
        let out = run(
            lanes(),
            Cancel::new(),
            Duration::ZERO,
            NO_WINDOW,
            |_, _, _| panic!("must not start"),
            |_| {
                stopped.fetch_add(1, Ordering::SeqCst);
            },
        );
        assert!(out.is_empty());
        assert_eq!(stopped.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn failed_or_panicking_tactic_does_not_suppress_fallback() {
        // Run 2026-10-16 (Build x86): a panicking probe prints a backtrace whose
        // symbolisation on 32-bit MSVC took longer than a 1 s ceiling. The
        // ceiling is not what this test is about, so it is generous here.
        let mut l = lanes();
        l.truncate(1);
        let out = run(
            l,
            Cancel::new(),
            GENEROUS_CEILING,
            NO_WINDOW,
            |_, t, _| {
                if t.id == "wg" {
                    panic!("probe failure");
                }
                t.id == "wg.heavy"
            },
            |_| {},
        );
        assert_eq!(out.first().expect("fallback tactic must still win").tactic.id, "wg.heavy");
    }
}
