//! Mobile 1.6 UplinkGovernor: delay-gradient autorate, token bucket and SFQ.
//! Clock-injected rate policy; no fixed cap on an unqueued/idle uplink.
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};
pub const MIN_RATE: f64 = 12. * 1024.;
pub const OPEN_RATE: f64 = 6. * 1024. * 1024.;
pub const ENGAGE: f64 = 16. * 1024.;
pub const SLICE: usize = 8192;
#[derive(Clone)]
struct Sample {
    at: u64,
    rtt: f64,
    floor: f64,
}
pub struct RateController {
    pub rate: f64,
    pub baseline: f64,
    pub last_rtt: f64,
    pub jitter: f64,
    pub cuts: u64,
    hold: u64,
    over: u32,
    jitter_n: u64,
    prev: f64,
    clean: VecDeque<(u64, f64)>,
    recent: VecDeque<Sample>,
}
impl Default for RateController {
    fn default() -> Self {
        Self {
            rate: f64::INFINITY,
            baseline: f64::NAN,
            last_rtt: f64::NAN,
            jitter: 0.,
            cuts: 0,
            hold: 0,
            over: 0,
            jitter_n: 0,
            prev: f64::NAN,
            clean: VecDeque::new(),
            recent: VecDeque::new(),
        }
    }
}
impl RateController {
    pub fn target(&self) -> f64 {
        (if self.baseline.is_nan() {
            0.
        } else {
            self.baseline
        } * 0.25)
            .max(40.)
            .max(2. * self.jitter)
            .min(250.)
    }
    pub fn limited(&self) -> bool {
        self.rate.is_finite()
    }
    pub fn loaded(&self, bps: f64) -> bool {
        bps >= if self.limited() {
            self.rate * 0.6
        } else {
            ENGAGE
        }
    }
    fn open_if_fast(&mut self) {
        if self.rate >= OPEN_RATE {
            self.rate = f64::INFINITY;
        }
    }
    pub fn tick(&mut self, bps: f64) {
        if self.limited() && !self.loaded(bps) {
            self.rate *= 1.01;
            self.open_if_fast();
        }
    }
    pub fn sample(&mut self, now: u64, rtt: f64, bps: f64) {
        if !rtt.is_finite() || rtt < 0. || !bps.is_finite() || bps < 0. {
            return;
        }
        self.last_rtt = rtt;
        while self
            .recent
            .front()
            .map(|s| now.saturating_sub(s.at) > 3000)
            .unwrap_or(false)
        {
            self.recent.pop_front();
        }
        let floor = self
            .recent
            .iter()
            .rev()
            .take(3)
            .take_while(|s| now.saturating_sub(s.at) <= 1600)
            .fold(rtt, |f, s| f.min(s.rtt));
        let fast = self
            .recent
            .back()
            .filter(|s| now.saturating_sub(s.at) <= 1600)
            .map(|s| s.rtt.min(rtt))
            .unwrap_or(rtt);
        let loaded = self.loaded(bps);
        if !loaded || self.baseline.is_nan() || rtt - self.baseline < self.target() {
            self.clean.push_back((now, rtt));
            if self.prev.is_finite() {
                let step = (rtt - self.prev).abs();
                self.jitter = if self.jitter_n == 0 {
                    step
                } else {
                    self.jitter * 0.9 + step * 0.1
                };
                self.jitter_n += 1;
            }
            self.prev = rtt;
        }
        while self
            .clean
            .front()
            .map(|s| now.saturating_sub(s.0) > 60000)
            .unwrap_or(false)
        {
            self.clean.pop_front();
        }
        self.baseline = self
            .clean
            .iter()
            .map(|s| s.1)
            .reduce(f64::min)
            .unwrap_or(if self.baseline.is_nan() {
                rtt
            } else {
                self.baseline
            })
            .min(rtt);
        let mut delta = floor - self.baseline;
        let target = self.target();
        let fast_delta = fast - self.baseline;
        let older = self
            .recent
            .iter()
            .rev()
            .find(|s| now.saturating_sub(s.at) >= 900)
            .cloned();
        let growing = older
            .as_ref()
            .map(|s| floor - s.floor > target / 2.)
            .unwrap_or(false);
        self.recent.push_back(Sample {
            at: now,
            rtt,
            floor,
        });
        self.over = if delta > target {
            self.over.saturating_add(1)
        } else {
            0
        };
        let engage = self.limited()
            || fast_delta > 4. * target
            || (self.over >= 2 && (growing || delta > 3. * target));
        if !self.limited() {
            delta = delta.max(fast_delta);
        }
        if delta > target && loaded && engage && now >= self.hold {
            let capacity = older
                .as_ref()
                .map(|s| {
                    let slope = (floor - s.floor) / now.saturating_sub(s.at).max(1) as f64;
                    if slope > -0.9 {
                        bps / (1. + slope)
                    } else {
                        bps * 2.
                    }
                })
                .unwrap_or(bps)
                .clamp(bps * 0.25, bps * 2.);
            self.rate = MIN_RATE.max(capacity * if delta < 4. * target { 0.9 } else { 0.5 });
            self.cuts += 1;
            self.hold = now + 800;
        } else if self.limited() && loaded && delta < target / 2. {
            self.rate = self.rate * if delta < target / 4. { 1.08 } else { 1.03 } + 1024.;
            self.open_if_fast();
        }
    }
}
#[derive(Default)]
pub struct Flow {
    finish: f64,
    last: Option<Instant>,
    burst: usize,
}
struct Waiter {
    tag: f64,
    seq: u64,
}
struct Bucket {
    rate: f64,
    tokens: f64,
    last: Instant,
    virtual_time: f64,
    seq: u64,
    waiters: Vec<Waiter>,
    active: bool,
}
pub struct Shaper {
    bucket: Mutex<Bucket>,
    changed: Condvar,
    pub released: AtomicU64,
    pub sparse: AtomicU64,
    pub cancel: Arc<crate::custom::cancel::Cancel>,
}
impl Shaper {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            bucket: Mutex::new(Bucket {
                rate: f64::INFINITY,
                tokens: 0.,
                last: Instant::now(),
                virtual_time: 0.,
                seq: 0,
                waiters: vec![],
                active: true,
            }),
            changed: Condvar::new(),
            released: AtomicU64::new(0),
            sparse: AtomicU64::new(0),
            cancel: crate::custom::cancel::Cancel::new(),
        })
    }
    fn refill(b: &mut Bucket) {
        let now = Instant::now();
        if b.rate.is_finite() {
            b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * b.rate)
                .min(4096f64.max(b.rate * 0.02));
        }
        b.last = now;
    }
    pub fn rate(&self) -> f64 {
        self.bucket.lock().unwrap().rate
    }
    pub fn set_rate(&self, rate: f64) {
        let mut b = self.bucket.lock().unwrap();
        Self::refill(&mut b);
        b.rate = if rate.is_finite() {
            rate.max(MIN_RATE)
        } else {
            f64::INFINITY
        };
        if !b.rate.is_finite() {
            b.tokens = 0.;
        }
        self.changed.notify_all();
    }
    pub fn shutdown(&self) {
        self.cancel.cancel();
        let mut b = self.bucket.lock().unwrap();
        b.active = false;
        self.changed.notify_all();
    }
    pub fn acquire(&self, flow: &mut Flow, bytes: usize, priority: bool) -> bool {
        let mut b = self.bucket.lock().unwrap();
        if !b.active {
            return false;
        }
        if !b.rate.is_finite() {
            self.released.fetch_add(bytes as u64, Ordering::Relaxed);
            return true;
        }
        Self::refill(&mut b);
        let now = Instant::now();
        if flow
            .last
            .map(|t| now.duration_since(t) > Duration::from_millis(250))
            .unwrap_or(true)
        {
            flow.burst = 0;
        }
        flow.last = Some(now);
        flow.burst = flow.burst.saturating_add(bytes);
        let sparse = priority || flow.burst <= 3000;
        if sparse && b.tokens >= -b.rate * 0.5 {
            b.tokens -= bytes as f64;
            self.sparse.fetch_add(1, Ordering::Relaxed);
            self.released.fetch_add(bytes as u64, Ordering::Relaxed);
            return true;
        }
        let tag = if sparse {
            b.virtual_time
        } else {
            b.virtual_time.max(flow.finish) + bytes as f64
        };
        if !sparse {
            flow.finish = tag;
        }
        let seq = b.seq;
        b.seq += 1;
        b.waiters.push(Waiter { tag, seq });
        loop {
            if !b.active || !b.rate.is_finite() {
                break;
            }
            Self::refill(&mut b);
            let head = b
                .waiters
                .iter()
                .min_by(|a, c| a.tag.total_cmp(&c.tag).then(a.seq.cmp(&c.seq)))
                .map(|w| w.seq)
                == Some(seq);
            if head && b.tokens >= 0. {
                b.tokens -= bytes as f64;
                break;
            }
            let wait = if head {
                Duration::from_secs_f64((-b.tokens / b.rate).max(0.001).min(0.5))
            } else {
                Duration::from_millis(50)
            };
            b = self.changed.wait_timeout(b, wait).unwrap().0;
        }
        b.waiters.retain(|w| w.seq != seq);
        b.virtual_time = b.virtual_time.max(tag);
        self.changed.notify_all();
        if !b.active {
            return false;
        }
        self.released.fetch_add(bytes as u64, Ordering::Relaxed);
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_loaded_path_is_never_capped() {
        let mut c = RateController::default();
        for t in 0..400 {
            c.sample(t * 400, 100. + (t % 2) as f64 * 10., 500000.);
        }
        assert!(!c.limited());
        assert_eq!(c.cuts, 0);
    }
    #[test]
    fn load_correlated_queue_engages_and_idle_relaxes() {
        let mut c = RateController::default();
        for i in 0..5 {
            c.sample(i * 400, 100., 0.);
        }
        for i in 5..18 {
            c.sample(i * 400, 100. + (i - 4) as f64 * 100., 100000.);
        }
        assert!(c.limited());
        assert!(c.rate >= MIN_RATE);
        assert!(c.cuts > 0);
        let before = c.rate;
        for _ in 0..1500 {
            c.tick(0.);
        }
        assert!(c.rate > before);
        assert!(!c.limited());
    }
    #[test]
    fn unloaded_delay_does_not_shape() {
        let mut c = RateController::default();
        c.sample(0, 100., 0.);
        for i in 1..30 {
            c.sample(i * 400, 2000., 1000.);
        }
        assert!(!c.limited());
    }
    #[test]
    fn ignores_invalid_samples() {
        let mut c = RateController::default();
        c.sample(0, f64::NAN, 100.);
        assert!(c.baseline.is_nan());
    }
    #[test]
    fn open_bucket_passes_and_closed_bucket_rejects() {
        let s = Shaper::new();
        assert!(s.acquire(&mut Flow::default(), 65000, false));
        assert_eq!(s.released.load(Ordering::Relaxed), 65000);
        s.shutdown();
        assert!(!s.acquire(&mut Flow::default(), 1, false));
    }
    #[test]
    fn sparse_is_charged_and_bulk_is_cancellable() {
        let s = Shaper::new();
        s.set_rate(MIN_RATE);
        assert!(s.acquire(&mut Flow::default(), 2000, true));
        assert_eq!(s.sparse.load(Ordering::Relaxed), 1);
        let other = s.clone();
        let h = std::thread::spawn(move || {
            let mut f = Flow::default();
            for _ in 0..100 {
                if !other.acquire(&mut f, 8192, false) {
                    return false;
                }
            }
            true
        });
        std::thread::sleep(Duration::from_millis(30));
        let at = Instant::now();
        s.shutdown();
        assert!(!h.join().unwrap());
        assert!(at.elapsed() < Duration::from_secs(1));
    }
}
