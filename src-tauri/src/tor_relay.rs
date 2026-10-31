//! >>> AETHER-APP-PATCH tor-aether-patient-dial
//! رلهٔ SOCKS5ِ محلی بینِ موتور و tor.exe — فقط برای `Tor → Aether`.
//!
//! # ریشهٔ کندی (لاگِ ۲۰۲۶-۱۰-۰۸، حالتِ تور+اتر)
//!
//! هستهٔ دست‌نخوردهٔ 2.4.0 برای هر اتصال از راهِ `AETHER_UPSTREAM` فقط **۱۰
//! ثانیه** صبر می‌کند تا پراکسیِ بالادست جوابِ SOCKS را بدهد
//! (`upstream.rs`: `HANDSHAKE_TIMEOUT`). tor.exe جوابِ SOCKS را تنها وقتی
//! می‌دهد که خروجیِ مدار `RELAY_CONNECTED` برگرداند، و اگر خروجیِ اول جواب
//! ندهد، خودِ tor **بعد از ۱۰ ثانیه** (`CircuitStreamTimeout` پیش‌فرض، که
//! کمترش مجاز نیست) سراغِ مدارِ بعدی می‌رود. یعنی هسته درست همان لحظه‌ای
//! قطع می‌کند که تور داشت خودش را اصلاح می‌کرد. لاگ همین را نشان می‌دهد:
//!
//! ```text
//! registration retry 1/4 … the upstream proxy at 127.0.0.1:1820 did not answer in time
//! … retry 4/4 …  Error: Api("registration: … did not answer in time")
//! Engine exited before it opened the SOCKS5 port — Connection failed
//! ```
//!
//! # راه‌حل (سمتِ برنامه؛ هسته دست نمی‌خورد)
//!
//! این رله درخواستِ CONNECT موتور را می‌گیرد، **بی‌درنگ** پاسخِ موفق می‌دهد،
//! و خودش با بودجهٔ صبورانه (`TOR_DIAL_BUDGET`) همان درخواست را به tor.exe
//! می‌فرستد؛ تا وقتی تور مدار را عوض می‌کند، بایت‌های موتور (ClientHello) در
//! بافرِ سوکت می‌مانند و بعد عیناً عبور می‌کنند. اگر تور در نهایت شکست بخورد،
//! اتصال بسته می‌شود و موتور همان خطای عادیِ TLS/API را می‌بیند و طبقِ منطقِ
//! خودش دوباره تلاش می‌کند. نام‌ها همان‌طور که موتور فرستاده (ATYP=3) به تور
//! می‌رسند، پس هیچ DNSی از این ماشین بیرون نمی‌رود. فقط CONNECT پشتیبانی
//! می‌شود — تور UDP حمل نمی‌کند.
//! <<< AETHER-APP-PATCH tor-aether-patient-dial

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::log::DiagnosticsLog;

const TAG: &str = "torrelay";

/// چقدر برای جوابِ tor به یک CONNECT صبر می‌شود. دو برابرِ چرخهٔ
/// «مدارِ اول ۱۰s + مدارِ دوم ۱۵s» خودِ تور، و کمتر از `SocksTimeout` آن (۱۲۰s).
pub const TOR_DIAL_BUDGET: Duration = Duration::from_secs(50);
/// اگر تور زودتر از این با خطا جواب دهد، یک بار دیگر می‌پرسیم.
const RETRY_IF_LEFT: Duration = Duration::from_secs(12);
/// دست‌دادنِ SOCKS با خودِ موتور (loopback) — باید فوری باشد.
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub struct TorDialRelay {
    port: u16,
    tor_port: u16,
    stop: Arc<AtomicBool>,
}

impl TorDialRelay {
    /// روی یک پورتِ آزادِ loopback گوش می‌دهد و هر CONNECT را به tor روی
    /// `127.0.0.1:tor_port` می‌برد.
    pub fn start(tor_port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        std::thread::Builder::new()
            .name("aether-torrelay".into())
            .spawn(move || accept_loop(listener, tor_port, flag))?;
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Patient Tor dialer on 127.0.0.1:{port} -> tor 127.0.0.1:{tor_port} (waits up to {}s per connection instead of the core's 10s).",
                TOR_DIAL_BUDGET.as_secs()
            ),
        );
        Ok(Self {
            port,
            tor_port,
            stop,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn tor_port(&self) -> u16 {
        self.tor_port
    }

    pub fn stop(&self) {
        if !self.stop.swap(true, Ordering::SeqCst) {
            // accept() مسدود است؛ یک اتصالِ خالی بیدارش می‌کند تا پرچم را ببیند.
            let _ = TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], self.port)),
                Duration::from_millis(300),
            );
        }
    }
}

impl Drop for TorDialRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, tor_port: u16, stop: Arc<AtomicBool>) {
    for incoming in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(client) = incoming else { continue };
        // فقط خودِ این ماشین؛ listener روی loopback است ولی صریح‌بودن ارزان است.
        if !client
            .peer_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false)
        {
            continue;
        }
        let _ = std::thread::Builder::new()
            .name("aether-torrelay-conn".into())
            .spawn(move || {
                let _ = serve(client, tor_port);
            });
    }
}

/// یک درخواستِ SOCKS5 از موتور: `(cmd, بایت‌های کاملِ درخواست)`.
fn read_request(client: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not socks5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        let _ = client.write_all(&[5, 0xFF]);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no acceptable auth",
        ));
    }
    client.write_all(&[5, 0])?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;
    if req[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request"));
    }
    let mut out = req.to_vec();
    match req[3] {
        1 => {
            let mut a = [0u8; 4 + 2];
            client.read_exact(&mut a)?;
            out.extend_from_slice(&a);
        }
        4 => {
            let mut a = [0u8; 16 + 2];
            client.read_exact(&mut a)?;
            out.extend_from_slice(&a);
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut a = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut a)?;
            out.push(len[0]);
            out.extend_from_slice(&a);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad address type",
            ))
        }
    }
    Ok((req[1], out))
}

/// جوابِ SOCKS5ِ tor را تا آخر می‌خواند و کدِ `REP` را برمی‌گرداند.
fn read_reply(tor: &mut TcpStream) -> io::Result<u8> {
    let mut head = [0u8; 4];
    tor.read_exact(&mut head)?;
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            tor.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad reply")),
    };
    let mut skip = vec![0u8; rest];
    tor.read_exact(&mut skip)?;
    Ok(head[1])
}

/// یک بار از tor می‌پرسد؛ `Ok(stream)` یعنی تور CONNECT را پذیرفت.
fn dial_tor(
    tor_port: u16,
    request: &[u8],
    budget: Duration,
    watch: &AbandonWatch,
) -> io::Result<TcpStream> {
    let mut tor = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], tor_port)),
        TOR_CONNECT_TIMEOUT,
    )?;
    // AETHER-APP-FIX tor-relay-drops-abandoned-dials: نگهبان باید بتواند همین را ببندد.
    watch.track(&tor);
    let _ = tor.set_nodelay(true);
    tor.set_read_timeout(Some(budget.max(Duration::from_secs(1))))?;
    tor.set_write_timeout(Some(TOR_CONNECT_TIMEOUT))?;
    tor.write_all(&[5, 1, 0])?;
    let mut method = [0u8; 2];
    tor.read_exact(&mut method)?;
    if method != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tor refused the method",
        ));
    }
    tor.write_all(request)?;
    match read_reply(&mut tor)? {
        0 => {
            tor.set_read_timeout(None)?;
            tor.set_write_timeout(None)?;
            Ok(tor)
        }
        rep => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("tor answered socks code {rep}"),
        )),
    }
}

fn serve(mut client: TcpStream, tor_port: u16) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    client.set_read_timeout(Some(CLIENT_HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(CLIENT_HANDSHAKE_TIMEOUT))?;
    let (cmd, request) = read_request(&mut client)?;
    if cmd != 1 {
        // فقط CONNECT؛ تور نه BIND دارد و نه UDP ASSOCIATE.
        let _ = client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        return Ok(());
    }
    // پاسخِ خوش‌بینانه: ساعتِ ده‌ثانیه‌ایِ هسته همین‌جا متوقف می‌شود.
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

    // >>> AETHER-APP-FIX tor-relay-drops-abandoned-dials
    // سنجه‌ای که هسته رها کرد (اسکنِ MASQUE هر نامزد را ۶ ثانیه می‌دهد) دیگر
    // تا ۵۰ ثانیه در تور زنده نمی‌ماند؛ رجوع به [`AbandonWatch`].
    let watch = AbandonWatch::start(&client)?;
    let started = Instant::now();
    let dialled = match dial_tor(tor_port, &request, TOR_DIAL_BUDGET, &watch) {
        Ok(stream) => Ok(stream),
        Err(first) => {
            let left = TOR_DIAL_BUDGET.saturating_sub(started.elapsed());
            if left < RETRY_IF_LEFT || watch.abandoned() {
                Err(first)
            } else {
                dial_tor(tor_port, &request, left, &watch)
            }
        }
    };
    watch.finish();
    let mut tor = match dialled {
        Ok(stream) => stream,
        Err(e) => {
            let _ = client.shutdown(Shutdown::Both);
            return Err(e);
        }
    };
    // <<< AETHER-APP-FIX tor-relay-drops-abandoned-dials
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    splice(&mut client, &mut tor)
}

/// دو جهت را به هم می‌دوزد؛ پایانِ هر جهت فقط نیمهٔ نوشتنِ طرفِ دیگر را می‌بندد.
// >>> AETHER-APP-FIX tor-relay-drops-abandoned-dials
/// نگهبانِ «مشتری رفت؟» در فاصلهٔ پاسخِ خوش‌بینانه تا وصل‌شدنِ تور.
///
/// # چرا (لاگِ «تور + اتر»، ۸ اکتبر)
///
/// پاسخِ SOCKS اینجا پیش از تور داده می‌شود، پس هسته نمی‌تواند بگوید «دیگر
/// نمی‌خواهم» جز با بستنِ سوکت — و رله تا امروز آن بستن را نمی‌دید: درخواست تا ۵۰
/// ثانیه (و یک تلاشِ دوباره) در تور می‌ماند. اسکنِ MASQUE با همزمانیِ ۱۰ و
/// مهلتِ ۶ ثانیه در هر ۴۵ ثانیه ده‌ها نامزد را رها می‌کند؛ همهٔ آن‌ها
/// استریم‌های باز در تور می‌ماندند و تور پشتِ سرِ هم «We tried for 30 seconds
/// … Retrying on a new circuit» می‌نوشت. موبایل چنین رله‌ای ندارد: arti همان
/// لحظه که سوکتِ SOCKS بسته شود استریم را رها می‌کند. اینجا هم همین: وقتی
/// مشتری بست، سوکتِ تور بسته می‌شود و تور استریم را رها می‌کند.
///
/// `peek` داده را مصرف نمی‌کند، پس ClientHelloای که هسته پس از پاسخِ خوش‌بینانه
/// فرستاده، دست‌نخورده به تور می‌رسد.
struct AbandonWatch {
    done: Arc<AtomicBool>,
    gone: Arc<AtomicBool>,
    tor: Arc<std::sync::Mutex<Option<TcpStream>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl AbandonWatch {
    const TICK: Duration = Duration::from_millis(200);

    fn start(client: &TcpStream) -> io::Result<Self> {
        let probe = client.try_clone()?;
        let done = Arc::new(AtomicBool::new(false));
        let gone = Arc::new(AtomicBool::new(false));
        let tor: Arc<std::sync::Mutex<Option<TcpStream>>> = Arc::new(std::sync::Mutex::new(None));
        let (done_flag, gone_flag, tor_slot) = (done.clone(), gone.clone(), tor.clone());
        let handle = std::thread::Builder::new()
            .name("aether-torrelay-watch".into())
            .spawn(move || {
                let _ = probe.set_read_timeout(Some(Self::TICK));
                let mut byte = [0u8; 1];
                while !done_flag.load(Ordering::SeqCst) {
                    let closed = match probe.peek(&mut byte) {
                        Ok(0) => true,
                        Ok(_) => {
                            std::thread::sleep(Self::TICK);
                            false
                        }
                        Err(e) => !matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ),
                    };
                    if closed {
                        gone_flag.store(true, Ordering::SeqCst);
                        if let Ok(slot) = tor_slot.lock() {
                            if let Some(tor) = slot.as_ref() {
                                let _ = tor.shutdown(Shutdown::Both);
                            }
                        }
                        break;
                    }
                }
            })?;
        Ok(Self {
            done,
            gone,
            tor,
            handle: Some(handle),
        })
    }

    /// سوکتِ تازهٔ تور، تا اگر مشتری رفت بسته شود.
    fn track(&self, tor: &TcpStream) {
        if let (Ok(clone), Ok(mut slot)) = (tor.try_clone(), self.tor.lock()) {
            if self.gone.load(Ordering::SeqCst) {
                let _ = clone.shutdown(Shutdown::Both);
            }
            *slot = Some(clone);
        }
    }

    fn abandoned(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    /// پیش از برداشتنِ مهلتِ خواندنِ مشتری صدا زده می‌شود: مهلت روی خودِ سوکت
    /// است و کلونِ نگهبان در آن شریک.
    fn finish(mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(mut slot) = self.tor.lock() {
            *slot = None;
        }
    }
}
// <<< AETHER-APP-FIX tor-relay-drops-abandoned-dials

fn splice(client: &mut TcpStream, tor: &mut TcpStream) -> io::Result<()> {
    let mut client_r = client.try_clone()?;
    let mut tor_w = tor.try_clone()?;
    let up = std::thread::Builder::new()
        .name("aether-torrelay-up".into())
        .spawn(move || {
            let _ = io::copy(&mut client_r, &mut tor_w);
            let _ = tor_w.shutdown(Shutdown::Write);
        })?;
    let _ = io::copy(tor, client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = up.join();
    let _ = client.shutdown(Shutdown::Both);
    let _ = tor.shutdown(Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// یک tor ساختگی: CONNECT را بعد از `delay` می‌پذیرد و هر چه آمد را پس می‌دهد.
    fn fake_tor(delay: Duration, rep: u8) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                std::thread::spawn(move || {
                    let mut g = [0u8; 3];
                    s.read_exact(&mut g).unwrap();
                    s.write_all(&[5, 0]).unwrap();
                    let mut r = [0u8; 5];
                    s.read_exact(&mut r).unwrap();
                    let mut rest = vec![0u8; r[4] as usize + 2];
                    s.read_exact(&mut rest).unwrap();
                    std::thread::sleep(delay);
                    s.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                    if rep == 0 {
                        let mut buf = [0u8; 64];
                        while let Ok(n) = s.read(&mut buf) {
                            if n == 0 || s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });
        port
    }

    fn connect_through(relay: u16) -> TcpStream {
        let mut c = TcpStream::connect(("127.0.0.1", relay)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).unwrap();
        assert_eq!(m, [5, 0]);
        let name = b"api.cloudflareclient.com";
        let mut req = vec![5, 1, 0, 3, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&443u16.to_be_bytes());
        c.write_all(&req).unwrap();
        c
    }

    /// تورِ کُند (بیش از ده ثانیهٔ هسته نیست، ولی کُند) دیگر شکست حساب نمی‌شود:
    /// جوابِ SOCKS فوری است و داده‌ای که پیش از آمادگیِ تور فرستاده شد، می‌رسد.
    #[test]
    fn a_slow_tor_answer_no_longer_counts_against_the_core() {
        let tor = fake_tor(Duration::from_millis(1500), 0);
        let relay = TorDialRelay::start(tor).unwrap();
        let mut c = connect_through(relay.port());
        let started = Instant::now();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "reply must not wait for tor"
        );
        c.write_all(b"hello").unwrap();
        let mut echo = [0u8; 5];
        c.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"hello");
    }

    /// تورِ ناموفق اتصال را می‌بندد؛ موتور EOF می‌بیند و خودش دوباره می‌کوشد.
    #[test]
    fn a_failed_tor_dial_closes_the_connection() {
        let tor = fake_tor(Duration::from_millis(10), 4);
        let relay = TorDialRelay::start(tor).unwrap();
        let mut c = connect_through(relay.port());
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).unwrap();
        let mut buf = [0u8; 8];
        let n = c.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }

    // >>> AETHER-APP-FIX tor-relay-drops-abandoned-dials
    /// سنجه‌ای که هسته رها کرد، در تور هم رها می‌شود — نه ۵۰ ثانیه بعد.
    #[test]
    fn an_abandoned_dial_is_dropped_in_tor_too() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let tor = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel::<Duration>();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[5, 0]).unwrap();
            let mut r = [0u8; 5];
            s.read_exact(&mut r).unwrap();
            let mut rest = vec![0u8; r[4] as usize + 2];
            s.read_exact(&mut rest).unwrap();
            // تورِ کند: هرگز جواب نمی‌دهد؛ فقط می‌پاید که کی بسته می‌شود.
            let began = Instant::now();
            let mut buf = [0u8; 16];
            s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let _ = s.read(&mut buf);
            let _ = tx.send(began.elapsed());
        });
        let relay = TorDialRelay::start(tor).unwrap();
        let mut c = connect_through(relay.port());
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        std::thread::sleep(Duration::from_millis(500));
        drop(c);
        let held = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("tor side closed");
        assert!(
            held < Duration::from_secs(3),
            "abandoned dial held for {held:?}"
        );
    }
    // <<< AETHER-APP-FIX tor-relay-drops-abandoned-dials
}
