//! ۱.۳.۰ — «پینگِ واقعی» برای کانفیگ‌های سفارشی؛ پورتِ `RealDelay.kt` و
//! `ConfigPing.kt` نسخهٔ اندروید ۱.۵.۰.
//!
//! پینگِ TCP به سرور هیچ نمی‌گوید: سرورِ REALITY/TLS پورتش را باز نگه می‌دارد
//! حتی وقتی UUID باطل شده یا مسیرِ آن‌سو بسته است. پس هر کانفیگ واقعاً در یک
//! Xrayِ موقت اجرا می‌شود و یک `GET /generate_204` از **دلِ همان کانفیگ**
//! فرستاده می‌شود؛ زمان از پاسخِ CONNECTِ SOCKS تا نخستین سطرِ وضعیتِ HTTP
//! است (Xray پیش از dialِ سرور به CONNECT پاسخ می‌دهد، پس دست‌دادنِ سرور و
//! رفت‌وبرگشتِ مقصد هر دو در عدد هستند).
//!
//! ```text
//!   یک xray.exe برای هر دسته (≤ ۳۲ کانفیگ)
//!   inbound  ping-in-<i>  SOCKS5 127.0.0.1:<p_i>  (رمزِ تصادفی، UDP خاموش، بی sniffing)
//!   outbound ping-out-<i> کانفیگِ i، مستقیم
//!   routing  ping-in-<i> → ping-out-<i>
//! ```
//!
//! دو دور، کمینه گزارش می‌شود؛ هر دور ۸ ثانیه مهلت دارد. اگر دسته بالا نیاید
//! (یک کانفیگِ خراب کلِ Xray را می‌کشد) هر کانفیگ تنها آزموده می‌شود و آن که
//! باز هم بالا نیاید «Invalid config» است. پس از شکست، تشخیصِ مستقیم (حلِ نام +
//! TCP، ۴ ثانیه) می‌گوید سرور خاموش است، فیلتر شده، یا پاسخ نمی‌دهد. در لاگ
//! هرگز نشانیِ سرور یا UUID نمی‌آید (`process::redact`).

use super::process::{self as xproc, XrayProcess};
use super::xray::direct_outbound;
use crate::log::DiagnosticsLog;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const TAG: &str = "custom";
/// بیشینهٔ کانفیگ در یک Xrayِ موقت.
pub const BATCH: usize = 32;
/// مهلتِ هر دورِ سنجش.
pub const ROUND_TIMEOUT: Duration = Duration::from_secs(8);
pub const ROUNDS: usize = 2;
/// مهلتِ تشخیصِ مستقیم (حلِ نام و TCP).
const DIAG_TIMEOUT: Duration = Duration::from_secs(4);
/// مهلتِ بالا آمدنِ شنونده‌های دسته.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// مقصدهای سنجش: همان‌هایی که اندروید می‌زند.
pub const PROBE_HOSTS: [&str; 2] = ["www.gstatic.com", "cp.cloudflare.com"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// پاسخِ HTTP از دلِ کانفیگ رسید.
    Ok,
    /// سرور در دسترس است (TCP باز) ولی از دلِ کانفیگ پاسخی نیامد: −1.
    NoReply,
    /// نام حل نشد، یا اتصال رد شد / مقصد دست‌نیافتنی: سرور خاموش است.
    Offline,
    /// مهلت، reset، یا نامی که به sinkhole حل می‌شود: فیلتر شده.
    Blocked,
    /// Xray این کانفیگ را نپذیرفت.
    Invalid,
    /// این دستگاه اصلاً شبکه ندارد.
    NoNetwork,
    UnexpectedStatus,
    PartialResponse,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::NoReply => "No response",
            Verdict::Offline => "Server off",
            Verdict::Blocked => "Filtered",
            Verdict::Invalid => "Invalid config",
            Verdict::NoNetwork => "No network",
            Verdict::UnexpectedStatus => "Unexpected HTTP status",
            Verdict::PartialResponse => "Partial response",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delay {
    pub id: String,
    /// میلی‌ثانیه؛ −1 یعنی پاسخی نیامد.
    pub ms: i64,
    pub status: Verdict,
    pub label: &'static str,
}

impl Delay {
    fn new(id: &str, ms: i64, status: Verdict) -> Self {
        Delay { id: id.to_string(), ms, status, label: status.label() }
    }
}

/// یک کانفیگ برای سنجش.
#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub outbound: String,
}

/// رمزِ تصادفی بی هیچ crateِ اضافه: `RandomState` هر بار کلیدِ تازه‌ای از سیستم‌عامل می‌گیرد.
fn random_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    for i in 0..2u64 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(i);
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

struct Lane {
    index: usize,
    port: u16,
    user: String,
    pass: String,
}

/// کانفیگِ Xrayِ یک دسته. `None` برای هر کانفیگی که حتی JSONِ درستی نیست.
pub fn batch_config(outbounds: &[(usize, Value)], ports: &[u16], creds: &[(String, String)]) -> String {
    let mut inbounds = Vec::new();
    let mut outs = Vec::new();
    let mut rules = vec![json!({ "type": "field", "inboundTag": ["ping-dns"], "outboundTag": "direct" })];
    for (k, (i, o)) in outbounds.iter().enumerate() {
        let (user, pass) = &creds[k];
        inbounds.push(json!({
            "tag": format!("ping-in-{i}"),
            "listen": "127.0.0.1",
            "port": ports[k],
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [ { "user": user, "pass": pass } ],
                "udp": false,
                "userLevel": 0
            },
            "sniffing": { "enabled": false }
        }));
        let mut o = o.clone();
        o["tag"] = json!(format!("ping-out-{i}"));
        outs.push(o);
        rules.push(json!({ "type": "field", "inboundTag": [format!("ping-in-{i}")], "outboundTag": format!("ping-out-{i}") }));
    }
    outs.push(json!({ "tag": "direct", "protocol": "freedom", "settings": { "domainStrategy": "UseIP" } }));
    json!({
        "log": { "loglevel": "error", "access": "none" },
        "dns": { "tag": "ping-dns", "queryStrategy": "UseIP", "servers": ["1.1.1.1", "8.8.8.8", "localhost"] },
        "inbounds": inbounds,
        "outbounds": outs,
        "policy": { "levels": { "0": { "handshake": 8, "connIdle": 30, "uplinkOnly": 2, "downlinkOnly": 5 } } },
        "routing": { "domainStrategy": "AsIs", "rules": rules }
    })
    .to_string()
}

/// همهٔ `targets` را می‌سنجد. ترتیبِ خروجی همان ترتیبِ ورودی است.
pub fn measure(binary: &Path, data_dir: &Path, targets: &[Target]) -> Vec<Delay> {measure_inner(binary,data_dir,targets,&super::cancel::Cancel::new(),true)}
pub fn measure_cancellable(binary:&Path,data_dir:&Path,targets:&[Target],cancel:&std::sync::Arc<super::cancel::Cancel>)->Vec<Delay>{measure_inner(binary,data_dir,targets,cancel,false)}
fn measure_inner(binary:&Path,data_dir:&Path,targets:&[Target],cancel:&std::sync::Arc<super::cancel::Cancel>,detailed:bool)->Vec<Delay> {
    let mut results: Vec<Option<Delay>> = vec![None; targets.len()];
    let mut valid: Vec<(usize, Value)> = Vec::new();
    for (i, t) in targets.iter().enumerate() {
        match direct_outbound(&t.outbound, &format!("ping-out-{i}")) {
            Ok(o) => valid.push((i, o)),
            Err(_) => results[i] = Some(Delay::new(&t.id, -1, Verdict::Invalid)),
        }
    }
    for chunk in valid.chunks(BATCH) {
        if cancel.stopped(){break;}
        match run_batch(binary, data_dir, targets, chunk,cancel,detailed) {
            Some(rows) => {
                for (i, d) in rows {
                    results[i] = Some(d);
                }
            }
            None if chunk.len() == 1 => {
                let i = chunk[0].0;
                results[i] = Some(Delay::new(&targets[i].id, -1, Verdict::Invalid));
            }
            None => {
                // یک کانفیگِ خراب کلِ دسته را کشت: تک‌تک.
                for one in chunk {
                    if cancel.stopped(){break;}
                    let i = one.0;
                    let d = run_batch(binary, data_dir, targets, std::slice::from_ref(one),cancel,detailed)
                        .and_then(|mut r| r.pop().map(|(_, d)| d))
                        .unwrap_or_else(|| Delay::new(&targets[i].id, -1, Verdict::Invalid));
                    results[i] = Some(d);
                }
            }
        }
    }
    let out: Vec<Delay> = results
        .into_iter()
        .enumerate()
        .map(|(i, d)| d.unwrap_or_else(|| Delay::new(&targets[i].id, -1, Verdict::Invalid)))
        .collect();
    for (t, d) in targets.iter().zip(out.iter()) {
        let name = xproc::redact(&t.name);
        let line = if d.ms >= 0 {
            format!("Real delay {name}: {} ms", d.ms)
        } else {
            format!("Real delay {name}: -1 -> {}", d.label)
        };
        DiagnosticsLog::i(TAG, &line);
    }
    out
}

/// `None` یعنی Xrayِ این دسته بالا نیامد.
fn run_batch(binary: &Path, data_dir: &Path, targets: &[Target], chunk: &[(usize, Value)], cancel:&std::sync::Arc<super::cancel::Cancel>,detailed:bool) -> Option<Vec<(usize, Delay)>> {
    let mut ports: Vec<u16> = Vec::with_capacity(chunk.len());
    for _ in chunk {
        let p = xproc::pick_port(&ports);
        if ports.contains(&p) {
            return None;
        }
        ports.push(p);
    }
    let creds: Vec<(String, String)> = chunk.iter().map(|_| (random_token()[..12].to_string(), random_token())).collect();
    let config = batch_config(chunk, &ports, &creds);
    let tag = format!("ping-{}", ports[0]);
    let mut x = XrayProcess::start(binary, data_dir, &tag, ports[0], &config).ok()?;
    let started = Instant::now();
    loop {
        if cancel.stopped() || !x.is_alive() {
            return None;
        }
        if ports.iter().all(|p| port_open(*p)) {
            break;
        }
        if started.elapsed() > START_TIMEOUT {
            x.stop();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let lanes: Vec<Lane> = chunk
        .iter()
        .enumerate()
        .map(|(k, (i, _))| Lane { index: *i, port: ports[k], user: creds[k].0.clone(), pass: creds[k].1.clone() })
        .collect();
    let (tx, rx) = mpsc::channel::<(usize, i64, Option<ProbeError>)>();
    let mut workers=Vec::new();
    for lane in lanes {
        let token=cancel.clone();
        let tx = tx.clone();
        let worker=std::thread::Builder::new()
            .name("aether-realdelay".into())
            .spawn(move || {
                let (best, failure) = measure_lane(lane.port, &lane.user, &lane.pass, Some(&token));
                let _ = tx.send((lane.index, best, failure));
            })
            ;
        match worker{Ok(h)=>workers.push(h),Err(_)=>{x.stop();for h in workers{let _=h.join();}return None;}}
    }
    drop(tx);
    let mut out = Vec::new();
    let deadline = Instant::now() + ROUND_TIMEOUT * (ROUNDS as u32 + 1) + Duration::from_secs(4);
    while out.len() < chunk.len() {
        if cancel.stopped()||Instant::now()>=deadline{break;}
        let left = deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(50));
        match rx.recv_timeout(left) {
            Ok((i, ms, e)) => out.push((i, ms, e)),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        }
    }
    x.stop();
    for h in workers{let _=h.join();}
    // اتصال‌ها بسته شدند؛ حالا تشخیصِ مستقیم برای آن‌هایی که پاسخ ندادند (موازی).
    let mut rows: Vec<(usize, Delay)> = Vec::new();
    let mut diag = Vec::new();
    for (i, _) in chunk {
        let result=out.iter().find(|(j,_,_)| j==i);
        let ms=result.map(|(_,ms,_)|*ms).unwrap_or(-1);
        let error=result.and_then(|(_,_,e)|*e);
        if ms >= 0 {
            rows.push((*i, Delay::new(&targets[*i].id, ms, Verdict::Ok)));
        } else if let Some(e)=error {
            let verdict=if matches!(e,ProbeError::UnexpectedStatus(_)){Verdict::UnexpectedStatus}else{Verdict::PartialResponse};
            rows.push((*i,Delay::new(&targets[*i].id,-1,verdict)));
        } else if !detailed || cancel.stopped(){rows.push((*i,Delay::new(&targets[*i].id,-1,Verdict::NoReply)));
        } else {
            let outbound = targets[*i].outbound.clone();
            let i = *i;
            diag.push((i, std::thread::spawn(move || diagnose(&outbound))));
        }
    }
    for (i, h) in diag {
        let v = h.join().unwrap_or(Verdict::NoReply);
        rows.push((i, Delay::new(&targets[i].id, -1, v)));
    }
    Some(rows)
}

fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(300)).is_ok()
}

/// یک دور: SOCKS5 با رمز → CONNECT → `GET /generate_204`. میلی‌ثانیه از پاسخِ
/// CONNECT تا نخستین سطرِ وضعیت.
pub fn probe_once(port: u16, user: &str, pass: &str) -> Option<i64> {
    for host in PROBE_HOSTS {
        if let Some(ms) = probe_host(port, user, pass, host) {
            return Some(ms);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError { Network, PartialResponse, UnexpectedStatus(u16) }

/// Strict ASCII status-line parser: only HTTP/1.0 and HTTP/1.1, exactly three digits.
pub fn parse_status_line(line: &str) -> Result<u16, ProbeError> {
    let b=line.as_bytes();
    if b.len()<12 || !(line.starts_with("HTTP/1.0 ") || line.starts_with("HTTP/1.1 "))
        || !b[9..12].iter().all(u8::is_ascii_digit)
        || (b.len()>12 && b[12]!=b' ')
        || b.iter().any(|c|*c<32 || *c==127) {return Err(ProbeError::PartialResponse);}
    let code=((b[9]-b'0') as u16)*100+((b[10]-b'0') as u16)*10+(b[11]-b'0') as u16;
    if !(100..=599).contains(&code) {return Err(ProbeError::PartialResponse);}
    Ok(code)
}
fn read_status(r: &mut impl Read) -> Result<u16,ProbeError> {
    let mut buf=Vec::new();let mut b=[0u8;1];
    loop {
        if buf.len()>=2048 {return Err(ProbeError::PartialResponse);}
        match r.read_exact(&mut b) {Ok(())=>{},Err(e)=>return Err(if e.kind()==ErrorKind::UnexpectedEof {ProbeError::PartialResponse}else{ProbeError::Network})}
        buf.push(b[0]);
        if b[0]==b'\n' {
            if buf.len()<2 || buf[buf.len()-2]!=b'\r' {return Err(ProbeError::PartialResponse);}
            return parse_status_line(std::str::from_utf8(&buf[..buf.len()-2]).map_err(|_|ProbeError::PartialResponse)?);
        }
    }
}
fn probe_host(port: u16,user: &str,pass: &str,host: &str) -> Option<i64> {request_through(port,user,pass,host).ok()}

pub fn request_through(port:u16,user:&str,pass:&str,host:&str)->Result<i64,ProbeError> {request_through_cancel(port,user,pass,host,None)}
pub fn request_through_cancel(port:u16,user:&str,pass:&str,host:&str,cancel:Option<&std::sync::Arc<super::cancel::Cancel>>)->Result<i64,ProbeError> {
    let deadline=Instant::now()+ROUND_TIMEOUT;
    let net=|_|ProbeError::Network;
    let mut s=TcpStream::connect_timeout(&SocketAddr::from(([127,0,0,1],port)),Duration::from_secs(2)).map_err(net)?;
    let _tracked=cancel.map(|c|c.track(&s)).transpose().map_err(net)?;
    let left=||deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    s.set_read_timeout(Some(left())).map_err(net)?;s.set_write_timeout(Some(left())).map_err(net)?;
    let _=s.set_nodelay(true);let auth=!user.is_empty();
    s.write_all(&[5,1,if auth {2}else{0}]).map_err(net)?;
    let mut b=[0;2];s.read_exact(&mut b).map_err(net)?;
    if b!=[5,if auth {2}else{0}] {return Err(ProbeError::Network);}
    if auth {
        if user.len()>255 || pass.len()>255 {return Err(ProbeError::Network);}
        let mut req=vec![1,user.len() as u8];req.extend(user.as_bytes());req.push(pass.len() as u8);req.extend(pass.as_bytes());
        s.write_all(&req).map_err(net)?;s.read_exact(&mut b).map_err(net)?;
        if b!=[1,0] {return Err(ProbeError::Network);}
    }
    let mut req=vec![5,1,0,3,host.len() as u8];req.extend(host.as_bytes());req.extend(443u16.to_be_bytes());
    s.write_all(&req).map_err(net)?;let mut head=[0;4];s.read_exact(&mut head).map_err(net)?;
    if head[0]!=5 || head[1]!=0 || head[2]!=0 {return Err(ProbeError::Network);}
    let len=match head[3] {1=>6,4=>18,3=>{let mut l=[0];s.read_exact(&mut l).map_err(net)?;l[0] as usize+2},_=>return Err(ProbeError::Network)};
    s.read_exact(&mut vec![0;len]).map_err(net)?;
    let t0=Instant::now(); // Cold TLS + HTTP, after SOCKS CONNECT, same contract as mobile.
    s.set_read_timeout(Some(left())).map_err(net)?;s.set_write_timeout(Some(left())).map_err(net)?;
    let connector=native_tls::TlsConnector::new().map_err(|_|ProbeError::Network)?;
    let mut tls=connector.connect(host,s).map_err(|_|ProbeError::Network)?;
    tls.get_ref().set_read_timeout(Some(left())).map_err(net)?;
    tls.get_ref().set_write_timeout(Some(left())).map_err(net)?;
    tls.write_all(format!("GET /generate_204 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).map_err(net)?;
    let code=read_status(&mut tls)?;
    if code!=204 {return Err(ProbeError::UnexpectedStatus(code));}
    if Instant::now()>deadline {return Err(ProbeError::Network);}
    Ok(t0.elapsed().as_millis().max(1) as i64)
}


/// Mobile `RealDelay.ProbeSession` + `QwDelayPolicy`: one SOCKS5 + certificate-validated TLS
/// channel to `www.gstatic.com`, reused (keep-alive) for every request. A discarded warm-up
/// request pays for the remote dial + TLS; the delay is the faster of `ROUNDS` warm requests.
pub const TARGET_HOST: &str = "www.gstatic.com";
type Tls = native_tls::TlsStream<TcpStream>;
pub struct ProbeSession<'a> {
    port: u16, user: &'a str, pass: &'a str, host: &'a str,
    cancel: Option<&'a std::sync::Arc<super::cancel::Cancel>>,
    tls: Option<Tls>, tracked: Option<super::cancel::Tracked>,
}
impl<'a> ProbeSession<'a> {
    pub fn new(port: u16, user: &'a str, pass: &'a str, host: &'a str, cancel: Option<&'a std::sync::Arc<super::cancel::Cancel>>) -> Self {
        Self { port, user, pass, host, cancel, tls: None, tracked: None }
    }
    pub fn close(&mut self) { self.tls = None; self.tracked = None; }
    fn connect(&mut self, deadline: Instant) -> Result<Instant, ProbeError> {
        let net = |_| ProbeError::Network;
        let left = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let mut s = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], self.port)), Duration::from_secs(2)).map_err(net)?;
        self.tracked = self.cancel.map(|c| c.track(&s)).transpose().map_err(net)?;
        s.set_read_timeout(Some(left())).map_err(net)?; s.set_write_timeout(Some(left())).map_err(net)?;
        let _ = s.set_nodelay(true);
        let auth = !self.user.is_empty();
        s.write_all(&[5, 1, if auth { 2 } else { 0 }]).map_err(net)?;
        let mut b = [0u8; 2]; s.read_exact(&mut b).map_err(net)?;
        if b != [5, if auth { 2 } else { 0 }] { return Err(ProbeError::Network); }
        if auth {
            if self.user.len() > 255 || self.pass.len() > 255 { return Err(ProbeError::Network); }
            let mut req = vec![1, self.user.len() as u8]; req.extend(self.user.as_bytes()); req.push(self.pass.len() as u8); req.extend(self.pass.as_bytes());
            s.write_all(&req).map_err(net)?; s.read_exact(&mut b).map_err(net)?;
            if b != [1, 0] { return Err(ProbeError::Network); }
        }
        // Like mobile: exclude only loopback authentication; remote CONNECT + TLS are in the cold clock.
        let started = Instant::now();
        let mut req = vec![5, 1, 0, 3, self.host.len() as u8]; req.extend(self.host.as_bytes()); req.extend(443u16.to_be_bytes());
        s.write_all(&req).map_err(net)?;
        let mut head = [0u8; 4]; s.read_exact(&mut head).map_err(net)?;
        if head[0] != 5 || head[1] != 0 || head[2] != 0 { return Err(ProbeError::Network); }
        let len = match head[3] { 1 => 6, 4 => 18, 3 => { let mut l = [0u8]; s.read_exact(&mut l).map_err(net)?; l[0] as usize + 2 }, _ => return Err(ProbeError::Network) };
        s.read_exact(&mut vec![0u8; len]).map_err(net)?;
        s.set_read_timeout(Some(left())).map_err(net)?; s.set_write_timeout(Some(left())).map_err(net)?;
        // Default connector validates chain + hostname.
        let tls = native_tls::TlsConnector::new().map_err(|_| ProbeError::Network)?.connect(self.host, s).map_err(|_| ProbeError::Network)?;
        self.tls = Some(tls);
        Ok(started)
    }
    /// One validated `GET /generate_204`. Cold: includes CONNECT + TLS. Warm: one round trip.
    pub fn request(&mut self) -> Result<i64, ProbeError> {
        let deadline = Instant::now() + ROUND_TIMEOUT;
        let r = self.request_inner(deadline);
        if r.is_err() { self.close(); }
        r
    }
    fn request_inner(&mut self, deadline: Instant) -> Result<i64, ProbeError> {
        let net = |_| ProbeError::Network;
        let mut started = Instant::now();
        if self.tls.is_none() { started = self.connect(deadline)?; }
        let left = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        let host = self.host.to_string();
        let tls = self.tls.as_mut().ok_or(ProbeError::Network)?;
        tls.get_ref().set_read_timeout(Some(left())).map_err(net)?;
        tls.get_ref().set_write_timeout(Some(left())).map_err(net)?;
        tls.write_all(format!("GET /generate_204 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n").as_bytes()).map_err(net)?;
        let code = read_status(tls)?;
        if code != 204 { return Err(ProbeError::UnexpectedStatus(code)); }
        // Consume the COMPLETE header block so the next round cannot read leftovers.
        let (mut bytes, mut close) = (0usize, false);
        loop {
            let line = read_line(tls)?;
            bytes += line.len() + 2;
            if bytes > 16_384 { return Err(ProbeError::PartialResponse); }
            if line.is_empty() { break; }
            let Some((k, v)) = line.split_once(':') else { return Err(ProbeError::PartialResponse) };
            if k.is_empty() || !k.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)) { return Err(ProbeError::PartialResponse); }
            let (k, v) = (k.to_ascii_lowercase(), v.trim());
            if (k == "content-length" && v.parse::<u64>().ok() != Some(0)) || k == "transfer-encoding" { return Err(ProbeError::PartialResponse); }
            if k == "connection" && v.eq_ignore_ascii_case("close") { close = true; }
        }
        if Instant::now() > deadline { return Err(ProbeError::Network); }
        let ms = started.elapsed().as_millis().max(1) as i64;
        if close { self.close(); }
        Ok(ms)
    }
}
fn read_line(r: &mut impl Read) -> Result<String, ProbeError> {
    let mut buf = Vec::new(); let mut b = [0u8; 1];
    loop {
        if buf.len() >= 8192 { return Err(ProbeError::PartialResponse); }
        match r.read_exact(&mut b) { Ok(()) => {}, Err(e) => return Err(if e.kind() == ErrorKind::UnexpectedEof { ProbeError::PartialResponse } else { ProbeError::Network }) }
        if b[0] == b'\n' {
            if buf.last() != Some(&b'\r') { return Err(ProbeError::PartialResponse); }
            buf.pop();
            if buf.iter().any(|c| *c < 0x20 && *c != b'\t') { return Err(ProbeError::PartialResponse); }
            return String::from_utf8(buf).map_err(|_| ProbeError::PartialResponse);
        }
        buf.push(b[0]);
    }
}

/// QwDelayPolicy: discard the warm-up, then the faster of `ROUNDS` keep-alive requests.
/// A failed warm-up yields no latency at all (never present startup as latency).
pub fn measure_lane(port: u16, user: &str, pass: &str, cancel: Option<&std::sync::Arc<super::cancel::Cancel>>) -> (i64, Option<ProbeError>) {
    let mut session = ProbeSession::new(port, user, pass, TARGET_HOST, cancel);
    if let Err(e) = session.request() {
        return (-1, if e == ProbeError::Network { None } else { Some(e) });
    }
    let (mut best, mut failure) = (-1i64, None);
    for _ in 0..ROUNDS {
        if cancel.map_or(false, |c| c.stopped()) { break; }
        match session.request() {
            Ok(ms) => { if best < 0 || ms < best { best = ms; } }
            Err(e) => { if e != ProbeError::Network { failure = Some(e); } }
        }
    }
    (best, if best >= 0 { None } else { failure })
}

/// نشانی‌ای که یک DNSِ مسموم به‌جای سرورِ واقعی برمی‌گرداند.
pub fn is_sinkhole(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_unspecified()
                || o[0] == 127
                || o[0] == 10
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] >= 224
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_unspecified()
                || v.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x00d0
        }
    }
}

/// پس از شکست: سرور خاموش است، فیلتر شده، یا باز است و فقط پاسخ نداد؟
pub fn diagnose(outbound: &str) -> Verdict {
    let Ok(Value::Object(o)) = serde_json::from_str::<Value>(outbound) else {
        return Verdict::Invalid;
    };
    let protocol = o.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_ascii_lowercase();
    let (host, port) = super::parser::server_of(&o);
    if host.is_empty() || !(1..=65535).contains(&port) {
        return Verdict::Invalid;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = port as u16;
    // حلِ نام با مهلت (ToSocketAddrs خودش مهلت ندارد).
    let (tx, rx) = mpsc::channel();
    let h = host.clone();
    std::thread::spawn(move || {
        let r = (h.as_str(), port).to_socket_addrs().map(|a| a.collect::<Vec<_>>());
        let _ = tx.send(r);
    });
    let addrs = match rx.recv_timeout(DIAG_TIMEOUT) {
        Ok(Ok(a)) if !a.is_empty() => a,
        Ok(_) => return if network_up() { Verdict::Offline } else { Verdict::NoNetwork },
        Err(_) => return if network_up() { Verdict::Blocked } else { Verdict::NoNetwork },
    };
    if host.parse::<IpAddr>().is_err() && addrs.iter().all(|a| is_sinkhole(a.ip())) {
        return Verdict::Blocked;
    }
    // سرورهای UDP (WireGuard، Hysteria): TCP چیزی نمی‌گوید.
    if matches!(protocol.as_str(), "wireguard" | "hysteria" | "hysteria2") {
        return Verdict::NoReply;
    }
    let addr = addrs.iter().find(|a| a.is_ipv4()).unwrap_or(&addrs[0]);
    match TcpStream::connect_timeout(addr, DIAG_TIMEOUT) {
        Ok(_) => Verdict::NoReply,
        Err(e) => match e.kind() {
            ErrorKind::ConnectionRefused => Verdict::Offline,
            ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
                if network_up() {
                    Verdict::Blocked
                } else {
                    Verdict::NoNetwork
                }
            }
            _ => {
                // «network/host unreachable» و مانندش.
                if network_up() {
                    Verdict::Offline
                } else {
                    Verdict::NoNetwork
                }
            }
        },
    }
}

/// آیا اصلاً شبکه‌ای هست؟ دو IP، بی DNS.
fn network_up() -> bool {
    [([1, 1, 1, 1], 443u16), ([8, 8, 8, 8], 53u16)].iter().any(|(ip, p)| {
        TcpStream::connect_timeout(&SocketAddr::from((*ip, *p)), Duration::from_secs(2)).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom::parser;
    use crate::custom::ConfigSource;

    fn vless() -> String {
        let link = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@203.0.113.9:443?security=tls&type=ws&path=%2Fws&host=cdn.example.org&sni=cdn.example.org#t";
        parser::parse(link, ConfigSource::Link, None, 0).unwrap()[0].outbound.clone()
    }

    #[test]
    fn labels_match_the_ui_contract() {
        assert_eq!(Verdict::NoReply.label(), "No response");
        assert_eq!(Verdict::Offline.label(), "Server off");
        assert_eq!(Verdict::Blocked.label(), "Filtered");
        assert_eq!(Verdict::Invalid.label(), "Invalid config");
        let d = serde_json::to_value(Delay::new("x", -1, Verdict::Blocked)).unwrap();
        assert_eq!(d["ms"], -1);
        assert_eq!(d["status"], "blocked");
        assert_eq!(d["label"], "Filtered");
    }

    #[test]
    fn batch_config_is_password_protected_and_routes_lane_by_lane() {
        let o = direct_outbound(&vless(), "x").unwrap();
        let cfg: Value = serde_json::from_str(&batch_config(
            &[(0, o.clone()), (3, o)],
            &[18831, 18832],
            &[("u1".into(), "p1".into()), ("u2".into(), "p2".into())],
        ))
        .unwrap();
        let ins = cfg["inbounds"].as_array().unwrap();
        assert_eq!(ins.len(), 2);
        for i in ins {
            assert_eq!(i["listen"], "127.0.0.1");
            assert_eq!(i["settings"]["auth"], "password");
            assert_eq!(i["settings"]["udp"], false);
            assert_eq!(i["sniffing"]["enabled"], false);
        }
        assert_eq!(cfg["outbounds"][1]["tag"], "ping-out-3");
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["inboundTag"][0] == "ping-in-3" && r["outboundTag"] == "ping-out-3"));
        assert!(cfg["outbounds"][0]["streamSettings"]["sockopt"].get("dialerProxy").is_none());
    }

    #[test]
    fn sinkholes_are_recognised() {
        for ip in ["0.0.0.0", "10.10.34.35", "127.0.0.1", "192.168.1.1", "172.20.0.1", "100.64.0.1", "224.0.0.1", "::", "fd00::1", "fe80::1"] {
            assert!(is_sinkhole(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["31.77.13.19", "1.1.1.1", "2606:4700::1111"] {
            assert!(!is_sinkhole(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn random_tokens_differ() {
        assert_ne!(random_token(), random_token());
        assert_eq!(random_token().len(), 32);
    }

    #[test]
    fn broken_outbounds_are_invalid_without_starting_xray() {
        let d = measure(
            Path::new("/nonexistent/xray"),
            &std::env::temp_dir(),
            &[Target { id: "a".into(), name: "a".into(), outbound: "nope".into() }],
        );
        assert_eq!(d[0].status, Verdict::Invalid);
        assert_eq!(d[0].ms, -1);
    }

    /// Optional: `XRAY_BIN=/path/to/xray AETHER_PING_LINKS=/path/v2ray.txt cargo test real_delay_live -- --nocapture`
    #[test]
    fn real_delay_live() {
        let (Ok(bin), Ok(file)) = (std::env::var("XRAY_BIN"), std::env::var("AETHER_PING_LINKS")) else {
            eprintln!("XRAY_BIN / AETHER_PING_LINKS not set — skipping the live real-delay check");
            return;
        };
        let text = std::fs::read_to_string(&file).unwrap();
        let configs = crate::custom::import::from_text(&text, None, crate::mini_https::Dial::Direct)
            .or_else(|_| crate::custom::import::from_file_text(&file, &text, None))
            .unwrap();
        let targets: Vec<Target> = configs
            .iter()
            .map(|c| Target { id: c.id.clone(), name: c.name.clone(), outbound: c.outbound.clone() })
            .collect();
        let dir = std::env::temp_dir().join("aether-ping-test");
        let out = measure(Path::new(&bin), &dir, &targets);
        for (t, d) in targets.iter().zip(out.iter()) {
            eprintln!("{} -> {} ms ({:?} / {})", xproc::redact(&t.name), d.ms, d.status, d.label);
        }
        assert_eq!(out.len(), targets.len());
    }
}

#[cfg(test)] mod strict_http_tests {
 use super::*;
 #[test] fn whitelist(){for s in ["HTTP/1.X 204 OK","HTTP/2.0 204 OK","HTTP/1.1 20X OK","HTTP/1.1 204X","HTTP/1.1 099 OK","HTTP/1.1 600 bad","HTTP/1.1 204 OK\t"] {assert_eq!(parse_status_line(s),Err(ProbeError::PartialResponse),"{s}");}}
 #[test] fn valid_status(){assert_eq!(parse_status_line("HTTP/1.1 204 No Content"),Ok(204));assert_eq!(parse_status_line("HTTP/1.0 403 Forbidden"),Ok(403));}
 #[test] fn crlf_only(){assert_eq!(read_status(&mut &b"HTTP/1.1 204 OK\n"[..]),Err(ProbeError::PartialResponse));assert_eq!(read_status(&mut &b"HTTP/1.1 204 OK\r\n"[..]),Ok(204));assert_eq!(read_status(&mut &b"HTTP/1.1 20"[..]),Err(ProbeError::PartialResponse));}
}

/// Owned worker: no stale background Xray/measurement survives the owning session.
pub struct ProbeTask{token:std::sync::Arc<super::cancel::Cancel>,slot:std::sync::Arc<parking_lot::Mutex<Option<Vec<Delay>>>>,join:Option<std::thread::JoinHandle<()>>}
impl ProbeTask{pub fn spawn(binary:std::path::PathBuf,dir:std::path::PathBuf,targets:Vec<Target>)->Self{let token=super::cancel::Cancel::new();let slot=std::sync::Arc::new(parking_lot::Mutex::new(None));let t=token.clone();let s=slot.clone();let join=std::thread::spawn(move||{let rows=measure_cancellable(&binary,&dir,&targets,&t);*s.lock()=Some(rows);});Self{token,slot,join:Some(join)}}pub fn poll(&mut self)->Option<Vec<Delay>>{let rows=self.slot.lock().take();if rows.is_some(){if let Some(h)=self.join.take(){let _=h.join();}}else if self.join.as_ref().map(|h|h.is_finished()).unwrap_or(false){if let Some(h)=self.join.take(){let _=h.join();}return Some(vec![]);}rows}}
impl Drop for ProbeTask{fn drop(&mut self){self.token.cancel();if let Some(h)=self.join.take(){let _=h.join();}}}
