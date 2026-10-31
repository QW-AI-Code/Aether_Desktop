//! Socket-aware cancellation: teardown interrupts blocked SOCKS/TLS reads.
use std::{
    collections::BTreeMap,
    net::{Shutdown, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
#[derive(Default)]
pub struct Cancel {
    flag: AtomicBool,
    next: AtomicU64,
    sockets: Mutex<BTreeMap<u64, TcpStream>>,
}
impl Cancel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn stopped(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        for s in self
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
        {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
    pub fn track(self: &Arc<Self>, socket: &TcpStream) -> std::io::Result<Tracked> {
        let s = socket.try_clone()?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut all = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopped() {
            let _ = s.shutdown(Shutdown::Both);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        all.insert(id, s);
        Ok(Tracked {
            token: self.clone(),
            id,
        })
    }
}
pub struct Tracked {
    token: Arc<Cancel>,
    id: u64,
}
impl Drop for Tracked {
    fn drop(&mut self) {
        self.token
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::TcpListener,
        time::{Duration, Instant},
    };
    #[test]
    fn cancels_blocked_socket_without_waiting_for_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut server, _) = l.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let c = Cancel::new();
        let _g = c.track(&server).unwrap();
        let h = std::thread::spawn(move || {
            let mut b = [0];
            server.read(&mut b)
        });
        let at = Instant::now();
        c.cancel();
        assert!(h.join().unwrap().map(|n| n == 0).unwrap_or(true));
        assert!(at.elapsed() < Duration::from_secs(2));
        drop(client);
    }
}
