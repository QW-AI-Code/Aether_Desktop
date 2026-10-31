//! پورت از `core/NetProbe.kt` + `core/PortProbe.kt`.
//!
//! قاعدهٔ ۱.۲.۲ که عیناً حفظ می‌شود: تا وقتی خروج واقعی از داخل تونل
//! تأیید نشده، برنامه حق ندارد بگوید «Connected».
//!
//! جدید (هم‌ترازی کامل با اندروید): جست‌وجوی IP عمومی + کد کشور —
//! معادل NetProbe.fetchIpInfoDirect / fetchIpInfoViaSocks — برای نشانِ
//! «IP + پرچم» صفحهٔ اصلی، با همان فراهم‌کنندگان و همان ترتیب اندروید.

use crate::log::DiagnosticsLog;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// مقاصد راستی‌آزمایی — همان لیست NetProbe.kt.
const PROBE_HOSTS: [(&str, u16); 3] = [
    ("cloudflare.com", 80),
    ("www.gstatic.com", 80),
    ("1.1.1.1", 80),
];

const CONNECT_TIMEOUT: Duration = Duration::from_millis(4_000);
const IO_TIMEOUT: Duration = Duration::from_millis(4_000);

pub struct EgressResult {
    pub endpoint: String,
    pub latency_ms: u64,
}

/// معادل `IpInfo` در NetProbe.kt — IP عمومی + کد کشور دو حرفی.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpInfo {
    pub ip: String,
    pub country_code: Option<String>,
    #[serde(default)]
    pub alternate_ip: Option<String>,
}

/// یک فراهم‌کنندهٔ جای‌یابی — معادل `GeoProvider` اندروید.
struct GeoProvider {
    /// چیزی که به آن وصل می‌شویم — نام یا IP.
    dial: &'static str,
    /// نامی که گواهی TLS با آن سنجیده می‌شود و در سرآیند `Host:` می‌رود.
    ///
    /// برای فراهم‌کنندهٔ IP این دو یکی نیستند و همین نکتهٔ کار است: به
    /// `1.1.1.1` وصل می‌شویم (بی‌نیاز از DNS) و گواهی را با
    /// `www.cloudflare.com` می‌سنجیم — همان میزبان، همان گواهی، همان مسیر.
    verify_as: &'static str,
    port: u16,
    path: &'static str,
    tls: bool,
}

/// فراهم‌کنندگان جای‌یابی — همان GEO_PROVIDERS اندروید ۱.۳.۰.
///
/// # چرا هیچ‌کدام دیگر HTTP خام نیست (F-5)
///
/// تا ۱.۲.۴ دو فراهم‌کننده از سه فراهم‌کننده روی `:80` و بدون رمز بودند.
/// نه اعتبارنامه‌ای در آن‌ها بود و نه داده‌ای از کاربر، پس افشای محتوا مسئله
/// نبود؛ مسئله این بود که ناظرِ مسیر می‌دید *این دستگاه پرسید «IP من چیست؟»*
/// و آن هم با شکلی که قابل تشخیص است — یعنی یک انگشت‌نگاریِ ضعیف اما واقعی
/// از خودِ برنامه، روی شبکه‌ای که وجود همین برنامه در آن، حساس است. کلودفلر
/// همان `/cdn-cgi/trace` را روی ۴۴۳ هم می‌دهد، پس این هزینه‌ای نداشت.
///
/// # چرا فراهم‌کنندهٔ دوم با IP وصل می‌شود ولی با نام سنجیده می‌شود
///
/// اندروید `1.1.1.1:443` را با اتکا به iPAddress SAN گواهی می‌سنجد؛ سنجندهٔ
/// پیش‌فرضِ جاوا این را پشتیبانی می‌کند. TLS دسکتاپ `native_tls` است و روی
/// ویندوز یعنی schannel — و اینکه schannel یک IP خام را با آن SAN می‌سنجد یا
/// نه، چیزی نیست که این پورت بتواند تأییدش کند. اگر نسنجد، این فراهم‌کننده
/// می‌مرد، و همین فراهم‌کننده تنها مسیر جای‌یابیِ بی‌نیاز از DNS است — یعنی
/// دقیقاً چیزی که شبکهٔ با resolverِ آلوده را می‌گذراند. پس به IP وصل می‌شود
/// و گواهی با `www.cloudflare.com` سنجیده می‌شود: بی‌DNS، با سنجشِ کاملِ نام،
/// و بی‌وابستگی به پشتیبانیِ IP-SAN در هیچ لایه‌ای.
const GEO_PROVIDERS: [GeoProvider; 2] = [
    GeoProvider {
        dial: "www.cloudflare.com",
        verify_as: "www.cloudflare.com",
        port: 443,
        path: "/cdn-cgi/trace",
        tls: true,
    },
    GeoProvider {
        dial: "1.1.1.1",
        verify_as: "www.cloudflare.com",
        port: 443,
        path: "/cdn-cgi/trace",
        tls: true,
    },
];

/// معادل `PortProbe.isReady()` — آیا SOCKS5 محلی موتور بالا آمده؟
pub fn socks_ready(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    match TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        Ok(s) => {
            let _ = s.shutdown(Shutdown::Both);
            true
        }
        Err(_) => false,
    }
}

/// معادل `NetProbe.checkSocksHandshake` — خروجیِ خط لوله واقعاً SOCKS5 حرف می‌زند؟
pub fn socks_handshake_ok() -> bool {
    socks_handshake_ok_on(crate::engine::exit_socks_port())
}

/// همان بررسی، روی یک پورت مشخص.
///
/// معادل `Diagnostics.runProxyStage` اندروید: در نشست زنجیره‌ای باید **استیج ۱**
/// را جدا از خروجی نهایی سنجید، وگرنه Psiphon روی پروکسی‌ای بالا می‌آید که
/// نمی‌تواند dial کند و شکست، ده‌ها ثانیه بعد و در جای اشتباه ظاهر می‌شود.
pub fn socks_handshake_ok_on(port: u16) -> bool {
    socks5_greeting_on(port, CONNECT_TIMEOUT).is_some()
}

/// دست‌دادن اولیهٔ SOCKS5 (بدون احراز هویت) با خروجیِ خط لولهٔ فعال.
fn socks5_greeting(timeout: Duration) -> Option<TcpStream> {
    socks5_greeting_on(crate::engine::exit_socks_port(), timeout)
}

/// دست‌دادن SOCKS5 روی یک پورت لوپ‌بکِ مشخص.
fn socks5_greeting_on(port: u16, timeout: Duration) -> Option<TcpStream> {
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&proxy, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    s.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).ok()?;
    if reply != [0x05, 0x00] {
        return None;
    }
    Some(s)
}

/// اتصال TCP به مقصد از «داخل» پروکسی SOCKS5 موتور (RFC 1928).
///
/// اگر مقصد دامنه باشد ATYP=DOMAIN فرستاده می‌شود تا DNS از راه دور و داخل
/// تونل حل شود — دقیقاً همان کاری که NetProbe.socks5Connect در اندروید می‌کند.
pub fn socks5_stream(dest_host: &str, dest_port: u16, timeout: Duration) -> Option<TcpStream> {
    socks5_stream_on(
        crate::engine::exit_socks_port(),
        dest_host,
        dest_port,
        timeout,
    )
}

/// همان CONNECT، روی یک پورت SOCKS5 مشخص.
///
/// The desktop checks the finished SOCKS route; the engine owns child health.
pub fn socks5_stream_on(
    proxy_port: u16,
    dest_host: &str,
    dest_port: u16,
    timeout: Duration,
) -> Option<TcpStream> {
    socks5_connect_stream(socks5_greeting_on(proxy_port, timeout)?, dest_host, dest_port)
}

fn socks5_connect_stream(mut s: TcpStream, dest_host: &str, dest_port: u16) -> Option<TcpStream> {
    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00];
    if let Ok(v4) = dest_host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else {
        let hb = dest_host.as_bytes();
        if hb.len() > 255 {
            return None;
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&dest_port.to_be_bytes());
    s.write_all(&req).ok()?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).ok()?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return None;
    }
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            s.read_exact(&mut skip).ok()?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).ok()?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut skip).ok()?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            s.read_exact(&mut skip).ok()?;
        }
        _ => return None,
    }
    Some(s)
}

/// End-to-end watchdog targets; these are not used to score Psiphon servers.
const WATCHDOG_TARGETS: [(&str, u16); 3] = [
    ("cloudflare.com", 80),
    ("www.gstatic.com", 80),
    ("1.1.1.1", 80),
];

/// معادل `NetProbe.checkTcpViaProxy` — CONNECT به IP خام، بدون DNS.
/// v1.2.0 watchdog: three independent end-to-end targets. A check passes
/// when at least two targets complete through the engine SOCKS5 path, which
/// avoids restarting a healthy tunnel because one CDN edge briefly hiccupped.
pub fn watchdog_probe() -> bool {
    let passed = WATCHDOG_TARGETS
        .iter()
        .filter(|(host, port)| socks5_stream(*host, *port, Duration::from_secs(5)).is_some())
        .count();
    passed >= 2
}

pub fn tcp_via_proxy(dest_ip: &str, dest_port: u16) -> bool {
    socks5_stream(dest_ip, dest_port, CONNECT_TIMEOUT).is_some()
}

/// همان سنجه با مهلتِ دلخواه — برای خط لوله‌های تور (AETHER-APP-FIX tor-proves-its-exit).
pub fn tcp_via_proxy_within(dest_ip: &str, dest_port: u16, timeout: Duration) -> bool {
    socks5_stream(dest_ip, dest_port, timeout).is_some()
}

/// همان بررسی، روی یک پورت SOCKS5 مشخص (دروازهٔ استیج ۱).
pub fn tcp_via_proxy_on(proxy_port: u16, dest_ip: &str, dest_port: u16) -> bool {
    socks5_stream_on(proxy_port, dest_ip, dest_port, CONNECT_TIMEOUT).is_some()
}

/// معادل `NetProbe.verify()` — یک HEAD واقعی از دل تونل.
pub fn verify_egress() -> Option<EgressResult> {
    for (host, port) in PROBE_HOSTS {
        let started = Instant::now();
        if http_head_ok(host, port).is_some() {
            return Some(EgressResult {
                endpoint: format!("{host}:{port}"),
                latency_ms: started.elapsed().as_millis() as u64,
            });
        }
    }
    None
}

fn http_head_ok(host: &str, port: u16) -> Option<()> {
    let mut s = socks5_stream(host, port, CONNECT_TIMEOUT)?;
    s.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(request.as_bytes()).ok()?;
    let mut buf = [0u8; 12];
    let n = s.read(&mut buf).ok()?;
    let _ = s.shutdown(Shutdown::Both);
    if n >= 5 && buf.starts_with(b"HTTP/") {
        Some(())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
//  جای‌یابی IP — معادل بخش geolocation در NetProbe.kt
// ---------------------------------------------------------------------------

/// IP واقعی/اپراتور (مستقیم، خارج از تونل) — معادل `fetchIpInfoDirect`.
pub fn fetch_ip_direct(timeout_ms: u64) -> Option<IpInfo> {
    for p in &GEO_PROVIDERS {
        let got = if p.tls {
            connect_direct_ipv4(p.dial, p.port, timeout_ms)
                .and_then(|s| tls_get(s, p.verify_as, p.path))
                .and_then(|body| parse_ip_info(&body))
        } else {
            connect_direct_ipv4(p.dial, p.port, timeout_ms)
                .and_then(|mut s| http_get(&mut s, p.verify_as, p.path))
                .and_then(|body| parse_ip_info(&body))
        };
        match got {
            Some(info) => return Some(refine_country(info, p.dial, false, timeout_ms)),
            None => DiagnosticsLog::d("netprobe", &format!("direct geo {} failed", p.dial)),
        }
    }
    None
}

/// IP خروجی/سرور (از داخل پروکسی SOCKS5) — معادل `fetchIpInfoViaSocks`.
pub fn fetch_ip_via_socks(timeout_ms:u64)->Option<IpInfo> {
    fetch_ip_via_socks_enriched(timeout_ms,crate::engine::exit_socks_port(), |_|{})
}

/// Bounded parallel race. Give IPv4 1.2 s after an IPv6 result, never wait indefinitely.
/// Callback is invoked synchronously with the selected IP BEFORE slow country enrichment.
pub fn fetch_ip_via_socks_enriched(timeout_ms:u64,port:u16,mut publish:impl FnMut(&IpInfo))->Option<IpInfo> {
    use std::sync::mpsc;
    let (tx,rx)=mpsc::channel();let timeout=Duration::from_millis(timeout_ms);
    // The literal endpoint cannot resolve to IPv6. It is the IPv4-priority lane.
    for p in &GEO_PROVIDERS {
        let tx=tx.clone();let dial=p.dial;let verify=p.verify_as;let path=p.path;let dport=p.port;
        std::thread::spawn(move|| {
            let r=socks5_stream_on(port,dial,dport,timeout).and_then(|s|tls_get(s,verify,path)).and_then(|b|parse_ip_info(&b));
            let _=tx.send(r);
        });
    }
    drop(tx);let deadline=std::time::Instant::now()+timeout+IO_TIMEOUT;
    let mut until=deadline;let mut first_v6=None;let mut chosen=None;let mut alternate=None;
    while let Ok(result)=rx.recv_timeout(until.saturating_duration_since(std::time::Instant::now())) {
        if let Some(info)=result {
            if info.ip.parse::<std::net::IpAddr>().ok()?.is_ipv4() {
                alternate=first_v6.as_ref().map(|i:&IpInfo|i.ip.clone());chosen=Some(info);break;
            }
            if first_v6.is_none() {first_v6=Some(info);until=deadline.min(std::time::Instant::now()+Duration::from_millis(1200));}
        }
    }
    let mut selected=chosen.or(first_v6)?;selected.alternate_ip=alternate;
    publish(&selected);
    let refined=refine_country_on(selected,"race",true,timeout_ms,port);
    publish(&refined);Some(refined)
}

/// معادل `fetchIpInfoDirectWithRetry` — شبکهٔ اپراتور بدقلق را دور می‌زند.
pub fn fetch_ip_direct_retry(attempts: u32, delay_ms: u64, timeout_ms: u64) -> Option<IpInfo> {
    for i in 0..attempts {
        if let Some(info) = fetch_ip_direct(timeout_ms) {
            return Some(info);
        }
        if i + 1 < attempts {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    None
}

/// معادل `fetchIpInfoViaSocksWithRetry` — پنجرهٔ سردِ warp-in-warp را رد می‌کند.
pub fn fetch_ip_via_socks_retry(attempts: u32, delay_ms: u64, timeout_ms: u64) -> Option<IpInfo> {
    for i in 0..attempts {
        if let Some(info) = fetch_ip_via_socks(timeout_ms) {
            return Some(info);
        }
        if i + 1 < attempts {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    None
}

/// آیا اصلاً سراغ `ip-api.com` برویم؟ (تصمیم جدا شده تا آزمون‌پذیر باشد)
///
/// # چرا این تابع وجود دارد
///
/// اندروید ۱.۳.۰ فراهم‌کنندگانِ بی‌رمز را حذف کرد ولی *اصلاحِ* بی‌رمز را نگه
/// داشت: بعد از هر جست‌وجوی موفق، یک
/// `GET /json/<IP عمومیِ خودِ کاربر>` به `ip-api.com:80` می‌فرستد. این همان
/// انگشت‌نگاریِ F-5 است و بدتر از یافتهٔ اولیه، چون این درخواست IP واقعیِ
/// کاربر را بی‌رمز و در مسیرِ مستقیم — یعنی جایی که ناظر همان اپراتور است —
/// حمل می‌کند.
///
/// و دیگر چیزی هم نمی‌خرد: هر دو فراهم‌کننده `/cdn-cgi/trace` کلودفلرند که
/// خودش `loc=` می‌دهد؛ پایگاه دادهٔ دومی نمانده که با آن اختلاف پیدا کند، پس
/// «پرچم‌پرش»ی هم نمانده که صاف شود.
///
/// پس فقط وقتی که کشور واقعاً ناشناخته است، و فقط از داخل تونل: آنجا آنچه
/// افشا می‌شود IPِ سرور است به ip-api، و برای اپراتور هیچ. در مسیر مستقیم،
/// نبودنِ پرچم بهتر از اعلامِ بی‌رمزِ IP خودِ کاربر است.
/// آیا این دو حرف واقعاً کدِ کشور است؟
///
/// کلودفلر در `loc=` چند کدِ شبهٔ‌کشور هم می‌دهد که هیچ جایی روی نقشه
/// نیستند: `T1` برای خروجیِ تور، `A1` پراکسیِ ناشناس، `A2` ماهواره‌ای،
/// `O1` دیگر، و `XX`/`ZZ` نامعلوم.
pub fn is_real_country(code: &str) -> bool {
    const ISO: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";
    let cc=code.trim().to_ascii_uppercase();
    cc.len()==2 && ISO.split_ascii_whitespace().any(|c|c==cc)
}

fn should_refine_country(country_known: bool, via_socks: bool) -> bool {
    !country_known && via_socks
}

/// معادل `refineCountry` در اندروید — با محدودیتِ بالا.
fn refine_country(info: IpInfo, provider_host: &str, via_socks: bool, timeout_ms: u64) -> IpInfo {
    refine_country_on(info,provider_host,via_socks,timeout_ms,crate::engine::exit_socks_port())
}
fn refine_country_on(info:IpInfo,provider_host:&str,via_socks:bool,timeout_ms:u64,port:u16)->IpInfo {
    if provider_host == "ip-api.com" {
        return info;
    }
    if !should_refine_country(info.country_code.is_some(), via_socks) {
        if info.country_code.is_none() {
            DiagnosticsLog::d(
                "netprobe",
                "country unknown and this is the direct path - skipping the cleartext \
                 ip-api refinement rather than sending this device's own IP in the clear",
            );
        }
        return info;
    }
    let path = format!("/json/{}?fields=status,countryCode", info.ip);
    // >>> AETHER-APP-PATCH the-flag-is-already-on-disk
    // قبل از هر بایتی روی سیم: همین دو حرف روی دیسکِ کاربر هست —
    // `geoip`ِ خودِ Tor. رجوع به [`crate::geoip`]. اگر نبود، مسیرِ زیر سرِ
    // جایش می‌ماند.
    if let Ok(addr) = info.ip.parse::<std::net::IpAddr>() {
        if let Some(code) = crate::geoip::lookup(addr) {
            if is_real_country(&code) {
                DiagnosticsLog::d(
                    "netprobe",
                    &format!("country for {} came from the local geoip file", info.ip),
                );
                return IpInfo {
                    ip: info.ip,
                    alternate_ip: info.alternate_ip,
                    country_code: Some(code),
                };
            }
        }
    }
    // <<< AETHER-APP-PATCH the-flag-is-already-on-disk
    // فقط از داخلِ تونل. مسیرِ مستقیم اینجا عمداً وجود ندارد و نه فقط
    // «فراخوانده نمی‌شود»: تا وقتی یک شاخهٔ `connect_direct_ipv4` در این تابع
    // باشد، تضمینِ «بی‌رمز از سیمِ کاربر رد نمی‌شود» به درستیِ شرطِ بالا و به
    // هر صداکنندهٔ آیندهٔ این تابع وابسته می‌ماند. با نبودنش، ساختاری است.
    let body = socks5_stream_on(port,"ip-api.com", 80, Duration::from_millis(timeout_ms))
        .and_then(|mut s| http_get(&mut s, "ip-api.com", &path));
    if let Some(cc) = body.and_then(|b| json_str(&b, "countryCode")) {
        if is_real_country(&cc) {
            return IpInfo {
                ip: info.ip,
                alternate_ip: info.alternate_ip,
                country_code: Some(cc.to_ascii_uppercase()),
            };
        }
    }
    info
}

/// اتصال مستقیم با اجبار IPv4 — همان رفع باگ «IPv6 موقت روی شبکهٔ دو‌پشته».
fn connect_direct_ipv4(host: &str, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let timeout = Duration::from_millis(timeout_ms);
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()?;
    let s = TcpStream::connect_timeout(&addr, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    Some(s)
}

/// Lightweight network fingerprint - a scaled-down port of the DPI probe in
/// the mobile SmartAuto.kt. IP-literal hosts only (no DNS), so a poisoned
/// resolver cannot skew the verdict. If direct TCP:80 egress is dead, the
/// network is treated as filtered and the connection ladder leads with the
/// hardened anti-DPI candidate instead of wasting the first pass.
pub fn network_looks_filtered() -> bool {
    const FINGERPRINT_PROBES: [(&str, u16); 2] = [("1.1.1.1", 80), ("8.8.8.8", 80)];
    let reachable = FINGERPRINT_PROBES
        .iter()
        .any(|(host, port)| connect_direct_ipv4(host, *port, 1_200).is_some());
    if !reachable {
        DiagnosticsLog::w(
            "netprobe",
            "fingerprint: direct :80 egress is blocked on this network",
        );
    }
    !reachable
}

/// Does UDP survive on this network?
///
/// # Why the desktop needed this
///
/// `network_looks_filtered` only ever dialled TCP:80, so the desktop had no idea
/// whether UDP worked - and the MASQUE carrier choice is *exactly* a question
/// about UDP. HTTP/3 rides QUIC over UDP; HTTP/2 rides TCP. Because the desktop
/// could not tell, the anti-DPI pass demoted every MASQUE attempt to HTTP/2
/// unconditionally, and HTTP/2 is the carrier with the small flow-control
/// window. The mobile build has run this probe since 1.2.8 (`SmartAuto.kt`
/// `udpDnsProbe`), which is the real reason its downloads are fast: it only
/// picks the TCP carrier on networks that actually need it.
///
/// A real DNS query for `example.com` to two public resolvers. An answer proves
/// UDP round-trips survive; silence from both means UDP is dropped or throttled.
pub fn udp_egress_ok() -> bool {
    const RESOLVERS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];
    RESOLVERS
        .iter()
        .any(|server| udp_dns_probe(server, Duration::from_millis(1_200)))
}

/// Cloudflare edges the MASQUE prober itself tries first, plus one public
/// HTTP/3 endpoint as a control. IP literals only - a poisoned resolver must not
/// be able to change the verdict.
const QUIC_PROBE_EDGES: [&str; 4] = [
    "162.159.198.1:443",
    "162.159.197.1:443",
    "162.159.196.1:443",
    "1.1.1.1:443",
];

/// Whole-probe budget for the QUIC leg. Every edge is dialled at once, so this
/// is the total cost added to a connect, not the cost per edge.
const QUIC_PROBE_BUDGET: Duration = Duration::from_millis(1_600);

/// Is the HTTP/3 (QUIC) MASQUE carrier actually usable on this network?
///
/// # Why [`udp_egress_ok`] alone was not enough
///
/// It answers a DNS query over UDP:53 and concludes from that single round trip
/// that "UDP works", which the planner then reads as "HTTP/3 works". Those are
/// not the same question, and on carrier networks they routinely have different
/// answers: UDP:53 to a resolver is allowed (nothing browses without it) while
/// QUIC on UDP:443 is dropped outright. The field log is unambiguous:
///
/// ```text
///   udp=ok -> MASQUE carrier prefers HTTP/3 (QUIC)
///   Attempt 1/5 -> MASQUE h3   ... SOCKS5 port never opened   (35s burnt)
///   Attempt 2/5 -> MASQUE h3   ... scan deadline, no gateway  (60s burnt)
///   Attempt 3/5 -> MASQUE h2   ... cached gateway still works (10s, connected)
/// ```
///
/// The same cached gateway that "no longer works" twice over HTTP/3 answers
/// immediately over HTTP/2. Nothing was wrong with the gateway, the network or
/// the ladder: the fingerprint lied about the carrier, so the first two rungs
/// were doomed before they were spawned. That is where the ~100 seconds the user
/// waits on the Connect button actually goes.
///
/// # How this probes the real thing
///
/// A QUIC long-header packet carrying a deliberately unsupported version. Any
/// QUIC server MUST answer that with a Version Negotiation packet (RFC 9000
/// section 6.1), and producing one needs no keys, no certificate and no
/// handshake - so this costs one datagram each way and still proves the exact
/// thing the carrier choice depends on: does a QUIC packet to UDP:443 reach a
/// Cloudflare edge, and does its answer come back.
///
/// All edges are probed concurrently and any answer is enough, so a healthy
/// network pays about one round trip and a blocked one pays the budget once.
pub fn quic_carrier_ok() -> bool {
    // Cheap pre-gate: if UDP cannot even carry DNS, QUIC certainly does not work
    // and there is no reason to pay the second probe.
    if !udp_egress_ok() {
        DiagnosticsLog::w(
            "netprobe",
            "fingerprint: UDP is blocked or throttled here - the HTTP/3 carrier cannot work on this network.",
        );
        return false;
    }

    let started = Instant::now();
    let handles: Vec<_> = QUIC_PROBE_EDGES
        .iter()
        .map(|edge| {
            let edge: &'static str = *edge;
            std::thread::Builder::new()
                .name("aether-quicprobe".into())
                .spawn(move || quic_version_negotiation_probe(edge, QUIC_PROBE_BUDGET))
        })
        .collect();

    let mut answered = false;
    for handle in handles {
        if let Ok(handle) = handle {
            if handle.join().unwrap_or(false) {
                answered = true;
            }
        }
    }

    if answered {
        DiagnosticsLog::i(
            "netprobe",
            &format!(
                "fingerprint: a Cloudflare edge answered QUIC on UDP:443 in {} ms - the HTTP/3 carrier is viable.",
                started.elapsed().as_millis()
            ),
        );
    } else {
        DiagnosticsLog::w(
            "netprobe",
            "fingerprint: UDP works but no Cloudflare edge answered QUIC on UDP:443 - QUIC is filtered here, so HTTP/2 is the only carrier that can connect.",
        );
    }
    answered
}

/// One QUIC Version Negotiation round trip. `true` means a QUIC server on the
/// far side answered, i.e. the datagram left this machine and came back.
fn quic_version_negotiation_probe(peer: &str, timeout: Duration) -> bool {
    let addr: SocketAddr = match peer.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sock = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if sock.set_read_timeout(Some(timeout)).is_err() {
        return false;
    }
    if sock.set_write_timeout(Some(timeout)).is_err() {
        return false;
    }

    let (packet, scid) = build_quic_version_probe();
    if sock.send_to(&packet, addr).is_err() {
        return false;
    }

    let mut buf = [0u8; 1500];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) if from.ip() == addr.ip() => is_version_negotiation(&buf[..n], &scid),
        _ => false,
    }
}

/// A long-header QUIC packet with a reserved version, padded to the 1200-byte
/// minimum an Initial has to reach so that no edge discards it as too small.
fn build_quic_version_probe() -> (Vec<u8>, [u8; 8]) {
    let dcid = probe_cid(0xD0);
    let scid = probe_cid(0x5C);

    let mut pkt: Vec<u8> = Vec::with_capacity(1200);
    // Header form + fixed bit set: this is a long header.
    pkt.push(0xC0);
    // A version from the reserved "force version negotiation" pattern (RFC 9000
    // section 15: 0x?a?a?a?a is permanently reserved and never supported).
    pkt.extend_from_slice(&[0x0a, 0x0a, 0x0a, 0x0a]);
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(&scid);
    pkt.resize(1200, 0);
    (pkt, scid)
}

/// Did the far side send back a Version Negotiation packet for OUR probe?
///
/// A VN packet is a long header whose version field is zero and which echoes our
/// source connection id back as its destination connection id. The echo check is
/// what stops a stray datagram or an injected reply from being read as success.
fn is_version_negotiation(msg: &[u8], scid: &[u8; 8]) -> bool {
    if msg.len() < 7 {
        return false;
    }
    if msg[0] & 0x80 == 0 {
        return false; // short header: cannot be a VN packet
    }
    if u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]) != 0 {
        return false; // VN is the only long-header packet with version 0
    }
    let dcid_len = msg[5] as usize;
    let dcid_end = 6 + dcid_len;
    if dcid_end > msg.len() {
        return false;
    }
    &msg[6..dcid_end] == scid.as_slice()
}

/// Connection id for the probe. Uniqueness is all that matters (it only has to
/// come back unchanged), so the clock plus a counter is plenty - and it keeps
/// this file free of a crypto-random dependency, exactly like
/// [`transaction_id`] below.
fn probe_cid(tag: u8) -> [u8; 8] {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) as u64;
    let mixed = nanos ^ (seq << 40) ^ ((tag as u64) << 56);
    mixed.to_be_bytes()
}

fn udp_dns_probe(server: &str, timeout: Duration) -> bool {
    // A minimal DNS query: id, standard query + recursion desired, 1 question,
    // QNAME example.com, QTYPE A, QCLASS IN.
    const QUERY: [u8; 29] = [
        0xAE, 0x71, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let bound = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    if bound.set_read_timeout(Some(timeout)).is_err() {
        return false;
    }
    let peer: SocketAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    if bound.send_to(&QUERY, peer).is_err() {
        return false;
    }

    let mut buf = [0u8; 512];
    match bound.recv_from(&mut buf) {
        // A well-formed reply: our transaction id back, and the QR bit set.
        Ok((n, _)) if n >= 12 => buf[0] == QUERY[0] && buf[1] == QUERY[1] && (buf[2] & 0x80) != 0,
        _ => false,
    }
}

/// HTTP/1.1 GET مینیمال — همان `httpGet` اندروید.
fn http_get(stream: &mut TcpStream, host: &str, path: &str) -> Option<String> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Aether/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 65_536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// GET روی TLS — معادل tlsWrap در NetProbe.kt.
/// در ویندوز native-tls از SChannel بومی ویندوز استفاده می‌کند (بدون OpenSSL / بدون unsafe).
/// تایم‌اوت‌های ساکت قبل از ورود به این تابع روی TcpStream تنظیم شده‌اند.
fn tls_get(stream: TcpStream, host: &str, path: &str) -> Option<String> {
    let connector = native_tls::TlsConnector::new().ok()?;
    let mut tls = connector.connect(host, stream).ok()?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Aether/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).ok()?;
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 65_536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// معادل `parseIpInfo` — هر دو قالب ip-api (JSON) و cloudflare trace.
fn parse_ip_info(response: &str) -> Option<IpInfo> {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    // قالب ۱: JSONِ ip-api  {"query":"1.2.3.4","countryCode":"DE"}
    if let Some(ip) = json_str(body, "query").filter(|s|s.parse::<std::net::IpAddr>().is_ok()) {
        let cc = json_str(body, "countryCode").filter(|cc| is_real_country(cc));
        return Some(IpInfo {
            ip,
            alternate_ip: None,
            country_code: cc.map(|c|c.to_ascii_uppercase()),
        });
    }
    // قالب ۲: خطوط key=value در /cdn-cgi/trace
    let mut ip: Option<String> = None;
    let mut loc: Option<String> = None;
    for line in body.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("ip=") {
            ip = v.trim().parse::<std::net::IpAddr>().ok().map(|a|a.to_string());
        } else if let Some(v) = line.strip_prefix("loc=") {
            let v = v.trim();
            // >>> AETHER-APP-PATCH a-pseudo-country-is-not-a-country
            // دو حرفی که کشور نیست را نگه نمی‌داریم: خروجیِ تور از دید
            // کلودفلر `loc=T1` است — در تصویرِ کاربر همین دو حرف بود که هم
            // کنارِ IP چسبیده بود و هم پرچم را به کرهٔ خالی می‌برد.
            // `None` گذاشتنش دو کار می‌کند: دروغ را پاک می‌کند، و پالایشِ
            // از‌داخلِ‌تونل را — که فقط برای کشورِ ناشناخته راه می‌افتد — روشن
            // می‌کند، پس پرچمِ واقعیِ گرهِ خروجی می‌آید.
            if is_real_country(v) {
                loc = Some(v.to_uppercase());
            }
            // <<< AETHER-APP-PATCH a-pseudo-country-is-not-a-country
        }
    }
    ip.map(|ip| IpInfo {
        ip,
        alternate_ip: None,
        country_code: loc,
    })
}

/// استخراج مقدار رشته‌ای یک کلید JSON بدون وابستگی regex.
fn json_str(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let idx = body.find(&pat)? + pat.len();
    let rest = &body[idx..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ---------------------------------------------------------------------------
//  v1.2.0 — سنجش واقعی نشتی WebRTC (درخواست STUN مستقیم)
// ---------------------------------------------------------------------------
//
//  ادعا کافی نیست. مرورگر برای ساختن نامزد srflx دقیقاً همین کار را می‌کند:
//  یک دیتاگرام UDP خام به سرور STUN. اگر پاسخ برگردد یعنی مسیر UDP مستقیم
//  باز است و آی‌پی داخل پاسخ همان چیزی است که هر سایتی می‌تواند ببیند.

use std::net::Ipv4Addr;

/// سرورهای STUN — همان‌هایی که ابزارهای عمومی «WebRTC Leak Test» می‌زنند.
pub const STUN_SERVERS: [&str; 4] = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
    "stun.voip.blackberry.com:3478",
];

const STUN_MAGIC: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// آنچه یک صفحهٔ وب با WebRTC از شما می‌بیند.
#[derive(Debug, Clone)]
pub struct StunResult {
    pub server: String,
    pub reflexive_ip: String,
}

/// یک لحظه بیشتر از مهلتِ یک پرسش — سهمِ نامیابیِ DNS داخلِ همان تردها.
const STUN_JOIN_SLACK: Duration = Duration::from_millis(750);

/// `Some` یعنی دیتاگرام از کارت فیزیکی بیرون رفت و آی‌پی برگشته قابل دیدن
/// است — یعنی نشتی. `None` یعنی مسیر UDP مستقیم بسته است (حالت مطلوب).
pub fn stun_reflexive_ip(timeout: Duration) -> Option<StunResult> {
    // >>> AETHER-APP-PATCH the-leak-check-asks-every-server-at-once
    // چهار کارگزار هم‌زمان پرسیده می‌شوند، نه یکی پس از دیگری.
    //
    // # چرا این ۸ ثانیه از زمانِ اتصال کم می‌کند
    //
    // این سنجش در حالتِ سالم **هیچ** جوابی نمی‌گیرد: گاردِ نشتی UDP مستقیم را
    // بسته، پس هر چهار پرسش تا آخرِ مهلت ساکت می‌مانند. پشت‌سرهم یعنی
    // ۴ × ۲.۵s ≈ ۱۰s، و لاگِ ۱۷ سپتامبر دقیقاً همین را نشان می‌دهد: بین
    // `DNS+HTTP via tunnel: OK` در ۰۶:۲۹:۱۱ و `WebRTC / UDP leak check` در
    // ۰۶:۲۹:۲۲ — ۱۰.۷ ثانیه سکوت، تنها بزرگ‌ترین تکهٔ آن ۳۴ ثانیه.
    //
    // پوششش عوض نمی‌شود: هر چهار کارگزار همچنان پرسیده می‌شوند و اولین پاسخ
    // برنده است. مرورگر هم همین کار را می‌کند — نامزدهای srflx را هم‌زمان
    // می‌فرستد، نه نوبتی.
    let (tx, rx) = std::sync::mpsc::channel::<StunResult>();
    for server in STUN_SERVERS {
        let tx = tx.clone();
        let _ = std::thread::Builder::new()
            .name("aether-stun".into())
            .spawn(move || {
                if let Some(ip) = stun_query(server, timeout) {
                    let _ = tx.send(StunResult {
                        server: server.to_string(),
                        reflexive_ip: ip,
                    });
                }
            });
    }
    // فرستندهٔ اصلی باید بیفتد، وگرنه وقتی همهٔ تردها ساکت تمام شدند `recv`
    // تا آخرِ مهلت می‌نشیند به‌جای آنکه فوراً «هیچ‌کس جواب نداد» بگوید.
    drop(tx);
    rx.recv_timeout(timeout + STUN_JOIN_SLACK).ok()
    // <<< AETHER-APP-PATCH the-leak-check-asks-every-server-at-once
}

fn stun_query(server: &str, timeout: Duration) -> Option<String> {
    let addr = server.to_socket_addrs().ok()?.find(|a| a.is_ipv4())?;
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.set_write_timeout(Some(timeout)).ok()?;

    let txid = transaction_id();
    let req = build_binding_request(&txid);
    sock.send_to(&req, addr).ok()?;

    let mut buf = [0u8; 512];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from.ip() != addr.ip() {
        return None; // پاسخ از جای دیگر — نادیده.
    }
    parse_binding_response(&buf[..n], &txid)
}

fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes()); // بدون attribute
    req.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    req.extend_from_slice(txid);
    req
}

/// استخراج آی‌پی از پاسخ Binding (اول XOR-MAPPED-ADDRESS، بعد MAPPED-ADDRESS).
fn parse_binding_response(msg: &[u8], txid: &[u8; 12]) -> Option<String> {
    if msg.len() < 20 {
        return None;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != STUN_BINDING_RESPONSE {
        return None;
    }
    if u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]) != STUN_MAGIC {
        return None;
    }
    if msg[8..20] != *txid {
        return None; // پاسخ کهنه یا جعلی.
    }
    let declared = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let end = (20 + declared).min(msg.len());

    let mut i = 20;
    let mut fallback: Option<String> = None;
    while i + 4 <= end {
        let atype = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let alen = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        let start = i + 4;
        let stop = start + alen;
        if stop > end {
            break;
        }
        let body = &msg[start..stop];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(ip) = xor_mapped_v4(body) {
                    return Some(ip);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if fallback.is_none() {
                    fallback = mapped_v4(body);
                }
            }
            _ => {}
        }
        // هر attribute تا مرز ۴ بایتی padding می‌شود.
        i = stop + ((4 - (alen % 4)) % 4);
    }
    fallback
}

fn xor_mapped_v4(body: &[u8]) -> Option<String> {
    if body.len() < 8 || body[1] != 0x01 {
        return None; // فقط IPv4
    }
    let cookie = STUN_MAGIC.to_be_bytes();
    let mut octets = [0u8; 4];
    for k in 0..4 {
        octets[k] = body[4 + k] ^ cookie[k];
    }
    Some(Ipv4Addr::from(octets).to_string())
}

fn mapped_v4(body: &[u8]) -> Option<String> {
    if body.len() < 8 || body[1] != 0x01 {
        return None;
    }
    Some(Ipv4Addr::new(body[4], body[5], body[6], body[7]).to_string())
}

/// شناسهٔ تراکنش ۹۶ بیتی — بدون وابستگی به یک کتابخانهٔ تصادفی.
fn transaction_id() -> [u8; 12] {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..].copy_from_slice(&seq.to_be_bytes());
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_ready_is_false_on_a_closed_port() {
        assert!(!socks_ready(1));
    }

    #[test]
    fn parses_ip_api_json() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"query\":\"1.2.3.4\",\"countryCode\":\"DE\"}";
        let info = parse_ip_info(resp).unwrap();
        assert_eq!(info.ip, "1.2.3.4");
        assert_eq!(info.country_code.as_deref(), Some("DE"));
    }

    #[test]
    fn parses_cloudflare_trace() {
        let resp = "HTTP/1.1 200 OK\r\n\r\nfl=1\nip=5.6.7.8\nloc=nl\n";
        let info = parse_ip_info(resp).unwrap();
        assert_eq!(info.ip, "5.6.7.8");
        assert_eq!(info.country_code.as_deref(), Some("NL"));
    }

    // >>> AETHER-APP-PATCH a-pseudo-country-is-not-a-country
    /// `loc=T1` کدِ کشور نیست، پس نه در کارت می‌نشیند و نه پالایش را می‌بندد.
    ///
    /// همان چیزی که تصویرِ «تور تنها» نشان می‌داد: `185.220.101.146 · T1` و
    /// کره‌ی خالی جای پرچم.
    #[test]
    fn a_tor_exit_has_no_country_yet() {
        let resp = "HTTP/1.1 200 OK\r\n\r\nfl=1\nip=185.220.101.146\nloc=T1\n";
        let info = parse_ip_info(resp).unwrap();
        assert_eq!(info.ip, "185.220.101.146");
        assert_eq!(info.country_code, None);
        // و چون ناشناخته است، پالایشِ از-داخلِ-تونل مجاز می‌شود.
        assert!(should_refine_country(info.country_code.is_some(), true));
    }

    #[test]
    fn the_pseudo_codes_are_all_rejected() {
        for code in ["T1", "A1", "A2", "O1", "XX", "ZZ", "t1", "x", "DEU", "1D"] {
            assert!(!is_real_country(code), "{code} باید رد شود");
        }
        for code in ["DE", "nl", "IR", "us"] {
            assert!(is_real_country(code), "{code} باید پذیرفته شود");
        }
    }
    // <<< AETHER-APP-PATCH a-pseudo-country-is-not-a-country

    // --- v1.2.0: کدک STUN (پایهٔ سنجش نشتی WebRTC) ---

    #[test]
    fn binding_request_has_the_rfc5389_header() {
        let txid = [7u8; 12];
        let req = build_binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&req[2..4], &[0x00, 0x00]); // بدون attribute
        assert_eq!(&req[4..8], &[0x21, 0x12, 0xA4, 0x42]); // magic cookie
        assert_eq!(&req[8..20], &txid);
    }

    #[test]
    fn decodes_xor_mapped_address() {
        let txid = [9u8; 12];
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&0x0101u16.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes());
        msg.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0x00);
        msg.push(0x01); // IPv4
        msg.extend_from_slice(&[0x00, 0x00]); // پورت (بی‌اهمیت)
                                              // 5.61.25.9 در XOR با magic cookie
        let ip = [5u8, 61, 25, 9];
        let cookie = 0x2112_A442u32.to_be_bytes();
        for k in 0..4 {
            msg.push(ip[k] ^ cookie[k]);
        }
        assert_eq!(
            parse_binding_response(&msg, &txid).as_deref(),
            Some("5.61.25.9")
        );
    }

    /// پاسخ با شناسهٔ تراکنش دیگر باید دور ریخته شود (ضد جعل).
    #[test]
    fn rejects_a_foreign_transaction_id() {
        let txid = [1u8; 12];
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&0x0101u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        msg.extend_from_slice(&[2u8; 12]);
        assert!(parse_binding_response(&msg, &txid).is_none());
    }

    #[test]
    fn transaction_ids_never_repeat() {
        assert_ne!(transaction_id(), transaction_id());
    }

    // --- 1.2.3-p3: the QUIC carrier probe that decides h3 vs h2 ---

    #[test]
    fn quic_probe_is_a_padded_long_header_with_a_reserved_version() {
        let (pkt, scid) = build_quic_version_probe();
        assert_eq!(
            pkt.len(),
            1200,
            "an Initial-sized datagram is never dropped as too small"
        );
        assert_eq!(pkt[0] & 0x80, 0x80, "long header");
        assert_eq!(pkt[0] & 0x40, 0x40, "fixed bit");
        assert_eq!(
            &pkt[1..5],
            &[0x0a, 0x0a, 0x0a, 0x0a],
            "reserved: forces version negotiation"
        );
        assert_eq!(pkt[5], 8, "destination connection id length");
        assert_eq!(pkt[14], 8, "source connection id length");
        assert_eq!(&pkt[15..23], &scid, "the id we expect echoed back");
    }

    #[test]
    fn accepts_a_version_negotiation_that_echoes_our_id() {
        let (_, scid) = build_quic_version_probe();
        let mut vn: Vec<u8> = vec![0xC0, 0x00, 0x00, 0x00, 0x00, 8];
        vn.extend_from_slice(&scid);
        vn.push(0); // empty source connection id
        vn.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // one supported version
        assert!(is_version_negotiation(&vn, &scid));
    }

    /// Anti-spoofing: a reply that does not carry our connection id back is not
    /// evidence that OUR packet made the round trip.
    #[test]
    fn rejects_a_version_negotiation_for_a_foreign_id() {
        let (_, scid) = build_quic_version_probe();
        let mut vn: Vec<u8> = vec![0xC0, 0x00, 0x00, 0x00, 0x00, 8];
        vn.extend_from_slice(&[9u8; 8]);
        vn.push(0);
        assert!(!is_version_negotiation(&vn, &scid));
    }

    #[test]
    fn rejects_replies_that_are_not_version_negotiation() {
        let (_, scid) = build_quic_version_probe();
        // Short header.
        assert!(!is_version_negotiation(&[0x40, 1, 2, 3, 4, 5, 6, 7], &scid));
        // Long header, but a real version: that is a handshake packet, not VN.
        let mut initial: Vec<u8> = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        initial.extend_from_slice(&scid);
        assert!(!is_version_negotiation(&initial, &scid));
        // Truncated.
        assert!(!is_version_negotiation(&[0xC0, 0, 0], &scid));
    }

    #[test]
    fn probe_connection_ids_never_repeat() {
        assert_ne!(probe_cid(0xD0), probe_cid(0xD0));
        assert_ne!(probe_cid(0xD0), probe_cid(0x5C));
    }
}

#[cfg(test)]
mod f5_tests {
    use super::*;

    /// F-5: هیچ فراهم‌کنندهٔ جای‌یابی نباید بی‌رمز باشد. این آزمون هست تا اگر
    /// روزی کسی «برای اطمینان» یک `:80` به جدول برگرداند، ساخت بشکند.
    #[test]
    fn no_geo_provider_is_cleartext() {
        for p in &GEO_PROVIDERS {
            assert!(p.tls, "geo provider {} is cleartext", p.dial);
            assert_eq!(p.port, 443, "geo provider {} is not on 443", p.dial);
        }
    }

    /// نامی که گواهی با آن سنجیده می‌شود باید دامنه باشد، نه IP: سنجشِ IP-SAN
    /// در schannel تأییدنشده است و همین فراهم‌کننده تنها مسیرِ بی‌DNS است.
    #[test]
    fn every_provider_is_verified_against_a_domain() {
        for p in &GEO_PROVIDERS {
            assert!(
                p.verify_as.parse::<std::net::IpAddr>().is_err(),
                "provider {} would rely on an IP-SAN match",
                p.dial,
            );
            assert!(p.verify_as.contains('.') && p.verify_as.contains("cloudflare"));
        }
    }

    /// و یکی از آن‌ها باید با IP وصل شود، وگرنه شبکه‌ای که DNS را آلوده کرده
    /// جای‌یابی را کاملاً می‌کشد.
    #[test]
    fn one_provider_needs_no_dns() {
        let dns_free = GEO_PROVIDERS
            .iter()
            .any(|p| p.dial.parse::<std::net::IpAddr>().is_ok());
        assert!(dns_free, "no DNS-free geo provider left");
    }

    #[test]
    fn refinement_only_when_unknown_and_tunnelled() {
        // مسیر عادی: کشور از `loc=` آمده — هیچ درخواست اضافه‌ای نباید برود.
        assert!(!should_refine_country(true, true));
        assert!(!should_refine_country(true, false));
        // ناشناخته و مستقیم: IP خودِ کاربر بی‌رمز نمی‌رود.
        assert!(!should_refine_country(false, false));
        // ناشناخته و از داخل تونل: آنجا اشکالی ندارد.
        assert!(should_refine_country(false, true));
    }
}

/// Cancellable warm-probe dial. Track before ANY SOCKS/TLS blocking operation.
pub fn socks5_stream_cancelled(port:u16, host:&str, target_port:u16, timeout:Duration, cancel:&std::sync::Arc<crate::custom::cancel::Cancel>) -> Option<(TcpStream,crate::custom::cancel::Tracked)> {
    if cancel.stopped(){return None;}
    let mut socket=TcpStream::connect_timeout(&SocketAddr::from(([127,0,0,1],port)),timeout.min(Duration::from_secs(1))).ok()?;
    let tracked=cancel.track(&socket).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;socket.set_write_timeout(Some(timeout)).ok()?;
    socket.write_all(&[5,1,0]).ok()?;let mut greeting=[0;2];socket.read_exact(&mut greeting).ok()?;
    if greeting!=[5,0]{return None;}
    Some((socks5_connect_stream(socket,host,target_port)?,tracked))
}
