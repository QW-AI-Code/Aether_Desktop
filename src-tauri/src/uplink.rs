//! Owned Psiphon-only governor. Every new route starts open with a fresh baseline.
use crate::{
    ping::UplinkProbe,
    uplink_policy::{RateController, Shaper, ENGAGE},
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
static CURRENT: OnceLock<Mutex<Weak<Shaper>>> = OnceLock::new();
pub fn current() -> Option<Arc<Shaper>> {
    CURRENT
        .get_or_init(|| Mutex::new(Weak::new()))
        .lock()
        .unwrap()
        .upgrade()
}
pub struct Runtime {
    shaper: Arc<Shaper>,
    workers: Vec<JoinHandle<()>>,
}
fn pause(s: &Shaper, millis: u64) {
    for _ in 0..millis.div_ceil(50) {
        if s.cancel.stopped() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
}
impl Runtime {
    pub fn start(port: u16) -> Self {
        let shaper = Shaper::new();
        *CURRENT
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .unwrap() = Arc::downgrade(&shaper);
        let policy = Arc::new(Mutex::new(RateController::default()));
        let achieved = Arc::new(Mutex::new(0f64));
        let pending = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let mut workers = vec![];
        let (s, c, a, p) = (
            shaper.clone(),
            policy.clone(),
            achieved.clone(),
            pending.clone(),
        );
        workers.push(thread::spawn(move||{
   let(mut last,mut released,mut report,mut watchdog)=(Instant::now(),0u64,0u64,0u64);
   while !s.cancel.stopped(){pause(&s,250);if s.cancel.stopped(){break;}let now=start.elapsed().as_millis()as u64;let total=s.released.load(Ordering::Relaxed);let bps={let mut b=a.lock().unwrap();*b=*b*0.7+total.saturating_sub(released)as f64/last.elapsed().as_secs_f64().max(0.001)*0.3;*b};released=total;last=Instant::now();
    let mut c=c.lock().unwrap();let began=p.load(Ordering::Acquire);if began>0{let age=now.saturating_sub(began);let threshold=if c.baseline.is_nan(){1500.}else{1000f64.max(3.*c.baseline)};if age as f64>threshold&&now.saturating_sub(watchdog)>=500{c.sample(now,age as f64,bps);watchdog=now;}}
    c.tick(bps);s.set_rate(c.rate);if c.limited()&&now.saturating_sub(report)>=15000{report=now;crate::log::DiagnosticsLog::i("uplink",&format!("SQM rate={:.0} B/s baseline={:.0} ms target=+{:.0} ms cuts={} sparse={}",c.rate,c.baseline,c.target(),c.cuts,s.sparse.load(Ordering::Relaxed)));}
   }
  }));
        let (s, c, a, p) = (shaper.clone(), policy, achieved, pending);
        workers.push(thread::spawn(move || {
            let mut probe = UplinkProbe::default();
            let mut last_probe = 0;
            while !s.cancel.stopped() {
                pause(&s, 100);
                if s.cancel.stopped() {
                    break;
                }
                let now = start.elapsed().as_millis() as u64;
                let bps = *a.lock().unwrap();
                let fast = now < 8000 || c.lock().unwrap().limited() || bps >= ENGAGE;
                if now.saturating_sub(last_probe) < if fast { 400 } else { 3000 } {
                    continue;
                }
                last_probe = now;
                p.store(now.max(1), Ordering::Release);
                let rtt = probe.measure(port, &s.cancel);
                p.store(0, Ordering::Release);
                if s.cancel.stopped() {
                    break;
                }
                if let Some(rtt) = rtt {
                    let mut c = c.lock().unwrap();
                    c.sample(
                        start.elapsed().as_millis() as u64,
                        rtt as f64,
                        *a.lock().unwrap(),
                    );
                    s.set_rate(c.rate);
                }
            }
        }));
        Self { shaper, workers }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.shaper.shutdown();
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
        let mut current = CURRENT
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .unwrap();
        if current
            .upgrade()
            .map(|s| Arc::ptr_eq(&s, &self.shaper))
            .unwrap_or(false)
        {
            *current = Weak::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    #[test]
    fn teardown_interrupts_warm_probe_and_removes_generation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let _ = tx.send(());
            let mut bytes = [0; 32];
            use std::io::Read;
            let _ = (&socket).read(&mut bytes);
            let _ = (&socket).read(&mut bytes);
        });
        let runtime = Runtime::start(port);
        assert!(current().is_some());
        rx.recv_timeout(Duration::from_secs(4)).unwrap();
        let at = Instant::now();
        drop(runtime);
        assert!(at.elapsed() < Duration::from_secs(2));
        server.join().unwrap();
        assert!(current().is_none());
    }
}
