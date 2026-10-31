//! کانفیگِ کاملی که یک هاپِ کانفیگِ سفارشی با آن اجرا می‌شود — پورتِ
//! `XrayConfigBuilder.kt` نسخهٔ اندروید ۱.۵.۰.
//!
//! ```text
//!   inbound   SOCKS5 127.0.0.1:<listen_port>  (UDP روشن، فقط loopback)
//!   outbound  "proxy"     کانفیگِ کاربر
//!   outbound  "chain-up"  SOCKS5 127.0.0.1:<dial_via>  (فقط وقتی کانفیگ هاپِ
//!                         آخر است: پراکسی سرورش را از دلِ خروجیِ موتور dial
//!                         می‌کند — `sockopt.dialerProxy` در Xray)
//!   outbound  "direct"    freedom، فقط برای DNSِ خودِ Xray
//! ```
//!
//! # sniffing خاموش می‌ماند (درسِ `Config → Tor`)
//!
//! با `destOverride: tls`، Xray نشانیِ مقصدِ یک اتصال را با SNIِ داخلِ
//! ClientHello عوض می‌کند. دست‌دادنِ لینکِ تور با یک رله، SNIِ ساختگی
//! (`www.<random>.com`) دارد؛ پس هر dialِ نگهبان/رله‌ای که موتور از این هاپ
//! می‌گذراند به جست‌وجوی نامی تبدیل می‌شد که وجود ندارد: «tls handshake eof»،
//! «Could not connect to guard»، تور روی ۹۳٪ — همان گیرِ زنجیرهٔ
//! `Config → Tor`. ترابری‌های domain-fronted (meek/fronted TLSِ Psiphon) هم
//! همین‌طور می‌شکستند. هیچ چیز اینجا بر اساسِ دامنه مسیر نمی‌دهد و هر هاپی که
//! نام به ما می‌دهد خودش نام را می‌فرستد. آزمونِ `sniffing_stays_off_*` این را
//! برای هر سه جایگاه قفل می‌کند.
//!
//! # DNS
//!
//! وقتی کانفیگ مستقیم بیرون می‌رود، DNSِ خودِ Xray نامِ سرور را حل می‌کند
//! (`sockopt.domainStrategy: UseIPv4v6`). وقتی از دلِ موتور/تور dial می‌کند،
//! نام **حل‌نشده** به لیسنرِ SOCKSِ موتور داده می‌شود (`dialerProxy`)، پس
//! جست‌وجو آن‌سرِ تونل انجام می‌شود و هرگز روی شبکهٔ محلی نه؛ و جست‌وجوهای
//! خودِ Xray فقط TCP‌اند (`tcp://1.1.1.1:53`) چون تور UDP حمل نمی‌کند.

use super::parser::sanitize_outbound;
use serde_json::{json, Map, Value};

pub const PROXY_TAG: &str = "proxy";
pub const CHAIN_TAG: &str = "chain-up";
pub const INBOUND_TAG: &str = "socks-in";
pub const DNS_TAG: &str = "dns-internal";
/// هاپِ جلوییِ tor.exe در `Config → Tor…`: freedom با شکستنِ رکوردِ ClientHello
/// که خودش از دلِ `proxy` dial می‌کند. رجوع به [`TOR_LINK_FRAGMENT`].
pub const TOR_LINK_TAG: &str = "tor-link";
/// طولِ هر رکوردِ TLS پس از شکستنِ ClientHelloِ تور (بایت).
///
/// # ریشهٔ `Config → Tor` (هر سه زنجیرهٔ تور پشتِ کانفیگ)
///
/// tor.exe در هر دست‌دادنِ لینک با رله یک SNIِ ساختگی (`www.<random>.com`)
/// می‌فرستد. سرورِ کانفیگ (پیش‌فرضِ 3x-ui/Marzban: `sniffing` با
/// `destOverride: tls`) آن نام را از ClientHello می‌خواند، IPِ رله را با نامی
/// که وجود ندارد عوض می‌کند و اتصال را می‌بندد: «unexpected eof while reading;
/// TLS_ERROR»، تور روی ۱۰٪ — دقیقاً لاگِ میدانی. موبایل ۱.۵.۰ همین را با وصلهٔ
/// arti (`AETHER_TOR_LINK_SNI=off`، ClientHello بی SNI) حل کرده؛ tor.exe رسمی
/// قابلِ وصله نیست. پس این‌جا ClientHello در چند رکوردِ TLS شکسته می‌شود
/// (`fragment.packets = tlshello`، بی تأخیر — همه در یک write): sniffer سرور فقط
/// رکوردِ اول را می‌خواند، `extensionsLength` با طولِ آن جور نیست و
/// `errNotClientHello` برمی‌گرداند — هیچ نامی، هیچ جایگزینی؛ اتصال به IPِ واقعیِ
/// رله می‌رود. شکستنِ رکورد در transcriptِ TLS اثری ندارد (هش روی پیام‌های
/// handshake است، نه رکوردها) و OpenSSLِ رله آن را سرهم می‌کند. ۱۰۰ بایت از
/// ۷۳ بایتِ تا سرِ cipher suiteها بیشتر است، پس sniffer هرگز `ErrNoClue` نمی‌گیرد
/// و برای دادهٔ بیشتر منتظر نمی‌ماند.
pub const TOR_LINK_FRAGMENT: &str = "100-200";
const LOOPBACK: &str = "127.0.0.1";

/// فقط وقتی resolverهای خودِ شبکه معلوم نیستند.
pub const FALLBACK_DNS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

fn is_dns_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

// ---- زمان‌بندیِ زنجیره (پورتِ ۱.۵.۰-r2 اندروید) ----
//
// لاگِ میدانیِ `Npvt → Tor`: هر dialِ رله‌ای که موتور از این هاپ می‌گذراند با
// «tls handshake eof» یا «Channel for [relay] timed out» می‌مرد و تور روی ۹۳٪
// می‌ماند. `handshake` بودجهٔ Xray برای برپاشدنِ **یک** اتصال است و در زنجیره
// هم دست‌دادنِ TLS/REALITYِ کانفیگ را می‌پردازد، هم dialِ آن‌سرِ تونل را؛ ۸
// ثانیه برای نگهبانِ تور آن سرِ دنیا کم بود. `uplinkOnly`/`downlinkOnly`
// مهلتِ نیمه‌بسته‌اند (۲/۵ پاسخ‌های در راه را قطع می‌کرد) و `connIdle` ۳۰۰
// کانالِ بیکار-ولی-زندهٔ تور را درو می‌کرد.

/// ثانیه‌هایی که یک اتصال برای برپاشدن از دلِ این هاپ دارد.
pub const HANDSHAKE_SECONDS: u32 = 30;
/// اتصالِ بیکار-ولی-زنده؛ بلندتر از عمرِ کانالِ خودِ تور.
pub const CONN_IDLE_SECONDS: u32 = 1800;
/// مهلتِ uplink پس از بسته‌شدنِ downlink.
pub const UPLINK_ONLY_SECONDS: u32 = 10;
/// مهلتِ downlink پس از بسته‌شدنِ uplink (پاسخی که هنوز می‌رسد).
pub const DOWNLINK_ONLY_SECONDS: u32 = 30;
/// Mux برای کانفیگی که از دلِ هاپِ کند (تور، سایفون) dial می‌شود؛ پیش‌فرضِ v2rayNG.
pub const SLOW_CHAIN_MUX: u32 = 0;

/// کانفیگِ کاملِ Xray را می‌سازد. `dial_via = Some(port)` یعنی کانفیگ هاپِ
/// **آخر** است و از `127.0.0.1:port` بیرون می‌رود. Mux خاموش.
#[allow(dead_code)]
pub fn build(
    outbound: &str,
    listen_port: u16,
    dial_via: Option<u16>,
    network_dns: &[String],
    log_level: &str,
) -> Result<String, String> {
    build_chain(outbound, listen_port, dial_via, network_dns, log_level, 0)
}

/// مثلِ [`build_chain`]، وقتی هاپِ بعدی tor.exe است (`Config → Tor`،
/// `Config → Tor → Aether`، `Config → Tor → Psiphon`): ورودی به
/// [`TOR_LINK_TAG`] می‌رود که ClientHelloِ تور را می‌شکند و از دلِ `proxy`
/// بیرون می‌رود. بقیهٔ پیکربندی همان است.
pub fn build_for_tor(
    outbound: &str,
    listen_port: u16,
    network_dns: &[String],
    log_level: &str,
) -> Result<String, String> {
    let base = build_chain(outbound, listen_port, None, network_dns, log_level, 0)?;
    let mut v: Value = serde_json::from_str(&base).map_err(|e| e.to_string())?;
    if let Some(outs) = v["outbounds"].as_array_mut() {
        outs.insert(
            1,
            json!({
                "tag": TOR_LINK_TAG,
                "protocol": "freedom",
                "settings": { "fragment": {
                    "packets": "tlshello", "length": TOR_LINK_FRAGMENT, "interval": "0"
                } },
                "streamSettings": { "sockopt": { "dialerProxy": PROXY_TAG } }
            }),
        );
    }
    if let Some(rules) = v["routing"]["rules"].as_array_mut() {
        for r in rules.iter_mut() {
            if r["inboundTag"][0] == INBOUND_TAG {
                r["outboundTag"] = json!(TOR_LINK_TAG);
            }
        }
    }
    Ok(v.to_string())
}

/// مثلِ [`build`]، با Mux: `mux_concurrency > 1` همهٔ جریان‌ها را در **یک**
/// اتصالِ بازِ سرور می‌برد (فقط جریانِ اول هزینهٔ برپاییِ زنجیره را می‌دهد).
/// لاگِ `Tor → Npvt`: بی Mux هر جریان یک streamِ تازهٔ تور و یک دست‌دادنِ
/// کاملِ REALITY بود. برای XTLS flow، wireguard و hysteria نادیده گرفته می‌شود.
pub fn build_chain(
    outbound: &str,
    listen_port: u16,
    dial_via: Option<u16>,
    network_dns: &[String],
    log_level: &str,
    mux_concurrency: u32,
) -> Result<String, String> {
    let user = match serde_json::from_str::<Value>(outbound) {
        Ok(Value::Object(o)) => o,
        _ => return Err("stored config is not valid JSON".into()),
    };
    // ۱.۴.۰: در زنجیره (dial_via / هاپِ بالادستیِ SOCKS5 مثل تور یا سایفون) Mux
    // خاموش می‌شود. یک اتصالِ Mux شده روی نشستِ تور/سایفون، با اولین stall یا
    // reset، همهٔ جریان‌ها را با هم می‌بُرد (پینگِ قطع، بن‌بستِ داده در نشستِ
    // جاافتاده). هر جریان مستقل، ارزان‌تر از بازسازیِ کلِ زنجیره است.
    // Windows: Mux is disabled for EVERY chain (BPB/Cloudflare :2086 endpoints do not
    // support it and drop the link with "failed to read metadata"). The parameter is
    // kept for API compatibility only.
    let _ = mux_concurrency;
    let chained = dial_via.is_some() || is_socks_upstream(&user);
    let base = with_sockopt(sanitize_outbound(&user), dial_via);
    let proxy = if chained { without_mux(base) } else { base };
    let mut plain_dns: Vec<String> = Vec::new();
    for d in network_dns
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| is_dns_ip(d))
        .chain(FALLBACK_DNS.iter().map(|s| s.to_string()))
    {
        if !plain_dns.contains(&d) {
            plain_dns.push(d);
        }
    }
    // از دلِ موتور، جست‌وجوهای خودِ Xray روی TCP می‌روند: تور UDP حمل نمی‌کند و
    // یک پرس‌وجوی TCP از هر هاپی که موتور جلو بگذارد رد می‌شود. `localhost`
    // (resolverِ سیستم) آخر، برای شبکه‌ای که DNSِ عمومی را می‌بندد.
    let dns: Vec<String> = if dial_via.is_some() {
        FALLBACK_DNS.iter().map(|d| format!("tcp://{d}:53")).collect()
    } else {
        let mut v = plain_dns;
        v.push("localhost".into());
        v
    };

    let mut outbounds = vec![Value::Object(proxy)];
    if let Some(via) = dial_via {
        outbounds.push(json!({
            "tag": CHAIN_TAG,
            "protocol": "socks",
            "settings": { "servers": [ { "address": LOOPBACK, "port": via } ] },
            // دامنه‌ها بدونِ resolveِ محلی به SOCKSِ بالادستی سپرده می‌شوند.
            "streamSettings": { "sockopt": { "domainStrategy": "AsIs" } },
            "mux": { "enabled": false }
        }));
    }
    outbounds.push(json!({
        "tag": "direct",
        "protocol": "freedom",
        "settings": { "domainStrategy": "UseIP" }
    }));

    let config = json!({
        "log": { "loglevel": log_level, "access": "none" },
        "dns": { "tag": DNS_TAG, "queryStrategy": "UseIP", "servers": dns },
        "inbounds": [ {
            "tag": INBOUND_TAG,
            "listen": LOOPBACK,
            "port": listen_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true, "ip": LOOPBACK, "userLevel": 8 },
            // Sniffing OFF — see the module docs (the Config → Tor stall).
            "sniffing": { "enabled": false }
        } ],
        "outbounds": outbounds,
        "policy": { "levels": { "8": {
            "handshake": HANDSHAKE_SECONDS, "connIdle": CONN_IDLE_SECONDS,
            "uplinkOnly": UPLINK_ONLY_SECONDS, "downlinkOnly": DOWNLINK_ONLY_SECONDS
        } } },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                { "type": "field", "inboundTag": [DNS_TAG],
                  "outboundTag": if dial_via.is_some() { CHAIN_TAG } else { "direct" } },
                { "type": "field", "inboundTag": [INBOUND_TAG], "outboundTag": PROXY_TAG }
            ]
        }
    });
    Ok(config.to_string())
}

/// outboundِ کاربر را tag می‌زند و dialerش را یا به موتور یا به DNSِ Xray می‌سپارد.
fn with_sockopt(o: Map<String, Value>, dial_via: Option<u16>) -> Map<String, Value> {
    let protocol = o.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_string();
    let stream: Map<String, Value> = o
        .get("streamSettings")
        .and_then(|s| s.as_object())
        .cloned()
        .unwrap_or_default();
    let mut sockopt: Map<String, Value> = stream
        .get("sockopt")
        .and_then(|s| s.as_object())
        .cloned()
        .unwrap_or_default();
    if dial_via.is_some() {
        sockopt.insert("dialerProxy".into(), json!(CHAIN_TAG));
        sockopt.remove("domainStrategy");
    } else if protocol == "socks" {
        // outboundِ SOCKS (تور/سایفون/پراکسیِ بالادستی): دامنه‌ها **بدونِ**
        // resolveِ محلی به خودِ SOCKS می‌روند (AsIs)؛ نشتِ DNS و شکستنِ
        // مسیرِ onion/داخلیِ پراکسی جلوگیری می‌شود.
        sockopt.remove("domainStrategy");
    } else if protocol != "wireguard" {
        // IPv4 اول، IPv6 فقط وقتی نام رکوردِ A ندارد.
        sockopt.insert("domainStrategy".into(), json!("UseIPv4v6"));
    }
    let mut new_stream = stream;
    new_stream.insert("sockopt".into(), Value::Object(sockopt.clone()));
    let mut out = o.clone();
    out.insert("tag".into(), json!(PROXY_TAG));
    if protocol == "wireguard" {
        // WireGuard در Xray streamSettingsِ خودش را ندارد؛ فقط dialer اعمال می‌شود.
        out.insert("streamSettings".into(), json!({ "sockopt": Value::Object(sockopt) }));
        if dial_via.is_none() {
            let mut settings = o
                .get("settings")
                .and_then(|s| s.as_object())
                .cloned()
                .unwrap_or_default();
            settings.insert("domainStrategy".into(), json!("ForceIPv4v6"));
            out.insert("settings".into(), Value::Object(settings));
        }
    } else {
        out.insert("streamSettings".into(), Value::Object(new_stream));
    }
    out
}

/// آیا outboundِ کاربر خودش یک هاپِ بالادستیِ SOCKS5 است (تور، سایفون، پراکسیِ محلی)؟
pub fn is_socks_upstream(o: &Map<String, Value>) -> bool {
    o.get("protocol")
        .and_then(|p| p.as_str())
        .map(|p| p.eq_ignore_ascii_case("socks"))
        .unwrap_or(false)
}

/// Mux را صریحاً خاموش می‌کند (`"enabled": false`) — برای حالت‌های زنجیره‌ای.
fn without_mux(mut o: Map<String, Value>) -> Map<String, Value> {
    o.insert("mux".into(), json!({ "enabled": false }));
    o
}

/// Mux روی outbound؛ `concurrency <= 1` یعنی بی‌تغییر (هر نشستِ مستقیم).
#[allow(dead_code)]
fn with_mux(mut o: Map<String, Value>, concurrency: u32) -> Map<String, Value> {
    if concurrency <= 1 {
        return o;
    }
    let protocol = o
        .get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(protocol.as_str(), "wireguard" | "hysteria" | "hysteria2") || has_xtls_flow(&o) {
        return o;
    }
    o.insert(
        "mux".into(),
        json!({
            "enabled": true,
            "concurrency": concurrency.clamp(2, 128),
            // UDP مسیرِ خودش را دارد: QUIC پشتِ صفِ TCP نمی‌نشیند.
            "xudpConcurrency": 0,
            "xudpProxyUDP443": "reject"
        }),
    );
    o
}

/// هر کاربری با `flow` (مثلاً `xtls-rprx-vision`) — Xray روی آن Mux را رد می‌کند.
pub fn has_xtls_flow(o: &Map<String, Value>) -> bool {
    let Some(settings) = o.get("settings").and_then(|s| s.as_object()) else {
        return false;
    };
    let Some(holders) = settings
        .get("vnext")
        .or_else(|| settings.get("servers"))
        .and_then(|v| v.as_array())
    else {
        return false;
    };
    holders.iter().any(|h| {
        h.get("users")
            .and_then(|u| u.as_array())
            .map(|users| {
                users.iter().any(|u| {
                    u.get("flow")
                        .and_then(|f| f.as_str())
                        .map(|f| !f.trim().is_empty())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    })
}

/// outboundِ کاربر، پاک‌سازی‌شده و با `tag` دلخواه، برای پینگِ واقعی: مستقیم
/// (بی dialerProxy)، DNSِ سرور از Xray (`UseIPv4v6`)، بی Mux.
pub fn direct_outbound(outbound: &str, tag: &str) -> Result<Value, String> {
    let user = match serde_json::from_str::<Value>(outbound) {
        Ok(Value::Object(o)) => o,
        _ => return Err("stored config is not valid JSON".into()),
    };
    let mut o = with_sockopt(sanitize_outbound(&user), None);
    o.insert("tag".into(), json!(tag));
    Ok(Value::Object(o))
}

/// آیا outbound دست‌کم یک سرور نام می‌برد؟ (برای آزمون‌ها)
#[cfg_attr(not(test), allow(dead_code))]
pub fn has_server(outbound: &Map<String, Value>) -> bool {
    outbound
        .get("settings")
        .and_then(|s| s.as_object())
        .and_then(|s| s.get("vnext").or_else(|| s.get("servers")).or_else(|| s.get("peers")))
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
}

/// نشانیِ سرورِ outbound — برای تصمیمِ گاردِ نشتی (پورتِ STUN/IPv6)؛ هرگز لاگ نمی‌شود.
pub fn server_endpoint(outbound: &str) -> Option<(String, i64)> {
    let o = match serde_json::from_str::<Value>(outbound) {
        Ok(Value::Object(o)) => o,
        _ => return None,
    };
    let (h, p) = super::parser::server_of(&o);
    (!h.is_empty()).then_some((h, p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom::parser;
    use crate::custom::ConfigSource;

    const UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn sample() -> String {
        let link = format!("vless://{UUID}@203.0.113.9:443?security=tls&type=ws&path=%2Fws&host=cdn.example.org&sni=cdn.example.org#t");
        parser::parse(&link, ConfigSource::Link, None, 0).unwrap()[0].outbound.clone()
    }
    fn wg() -> String {
        parser::parse("wg://a2V5@wg.example.com:51820?publickey=cHVi", ConfigSource::Link, None, 0).unwrap()[0].outbound.clone()
    }
    fn built(outbound: &str, via: Option<u16>) -> Value {
        serde_json::from_str(&build(outbound, 18830, via, &[], "warning").unwrap()).unwrap()
    }

    fn assert_sniffing_off(v: &Value) {
        let inbound = &v["inbounds"][0];
        assert_eq!(inbound["sniffing"]["enabled"], false);
        assert!(inbound["sniffing"].get("destOverride").is_none());
        assert!(!v.to_string().contains("destOverride"));
    }

    #[test]
    fn sniffing_stays_off_solo() {
        assert_sniffing_off(&built(&sample(), None));
    }

    #[test]
    fn sniffing_stays_off_first() {
        // FIRST runs exactly like SOLO (the engine dials into this listener).
        assert_sniffing_off(&built(&sample(), None));
        assert_sniffing_off(&built(&wg(), None));
    }

    #[test]
    fn sniffing_stays_off_last() {
        assert_sniffing_off(&built(&sample(), Some(1819)));
        assert_sniffing_off(&built(&wg(), Some(1820)));
    }

    #[test]
    fn solo_and_first_dial_directly_with_xrays_own_dns() {
        let v = built(&sample(), None);
        let inbound = &v["inbounds"][0];
        assert_eq!(inbound["listen"], "127.0.0.1");
        assert_eq!(inbound["port"], 18830);
        assert_eq!(inbound["protocol"], "socks");
        assert_eq!(inbound["settings"]["udp"], true);
        assert_eq!(inbound["settings"]["auth"], "noauth");
        assert_eq!(inbound["settings"]["userLevel"], 8);
        let outs = v["outbounds"].as_array().unwrap();
        assert_eq!(outs.len(), 2, "no chain-up outbound without dial_via");
        assert_eq!(outs[0]["tag"], "proxy");
        assert_eq!(outs[0]["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4v6");
        assert!(outs[0]["streamSettings"]["sockopt"].get("dialerProxy").is_none());
        assert_eq!(outs[1]["tag"], "direct");
        assert_eq!(outs[1]["settings"]["domainStrategy"], "UseIP");
        assert_eq!(v["dns"]["servers"], json!(["1.1.1.1", "8.8.8.8", "localhost"]));
        assert_eq!(v["dns"]["tag"], "dns-internal");
        assert_eq!(v["dns"]["queryStrategy"], "UseIP");
        assert_eq!(v["routing"]["rules"][0]["outboundTag"], "direct");
        assert_eq!(v["routing"]["rules"][1]["inboundTag"][0], "socks-in");
        assert_eq!(v["routing"]["rules"][1]["outboundTag"], "proxy");
        assert_eq!(v["routing"]["domainStrategy"], "AsIs");
        assert_eq!(v["policy"]["levels"]["8"]["handshake"], 30);
        assert_eq!(v["policy"]["levels"]["8"]["connIdle"], 1800);
        assert_eq!(v["policy"]["levels"]["8"]["uplinkOnly"], 10);
        assert_eq!(v["policy"]["levels"]["8"]["downlinkOnly"], 30);
        assert_eq!(v["log"]["loglevel"], "warning");
        assert_eq!(v["log"]["access"], "none");
        let with_net = serde_json::from_str::<Value>(&build(&sample(), 1, None, &["9.9.9.9".into(), "fe80::1".into(), "1.1.1.1".into()], "none").unwrap()).unwrap();
        assert_eq!(with_net["dns"]["servers"], json!(["9.9.9.9", "1.1.1.1", "8.8.8.8", "localhost"]));
    }

    #[test]
    fn last_dials_through_the_engine_with_tcp_dns() {
        let v = built(&sample(), Some(1820));
        let outs = v["outbounds"].as_array().unwrap();
        assert_eq!(outs.len(), 3);
        assert_eq!(outs[0]["streamSettings"]["sockopt"]["dialerProxy"], "chain-up");
        assert!(outs[0]["streamSettings"]["sockopt"].get("domainStrategy").is_none());
        assert_eq!(outs[1]["tag"], "chain-up");
        assert_eq!(outs[1]["protocol"], "socks");
        assert_eq!(outs[1]["settings"]["servers"][0]["address"], "127.0.0.1");
        assert_eq!(outs[1]["settings"]["servers"][0]["port"], 1820);
        assert_eq!(v["dns"]["servers"], json!(["tcp://1.1.1.1:53", "tcp://8.8.8.8:53"]));
        assert_eq!(v["routing"]["rules"][0]["outboundTag"], "chain-up");
    }

    #[test]
    fn wireguard_gets_only_a_dialer() {
        let solo = built(&wg(), None);
        let p = &solo["outbounds"][0];
        assert_eq!(p["settings"]["domainStrategy"], "ForceIPv4v6");
        assert_eq!(p["streamSettings"], json!({ "sockopt": {} }));
        let last = built(&wg(), Some(1819));
        let p = &last["outbounds"][0];
        assert!(p["settings"].get("domainStrategy").is_none());
        assert_eq!(p["streamSettings"], json!({ "sockopt": { "dialerProxy": "chain-up" } }));
    }

    #[test]
    fn a_stale_dialer_from_the_author_is_replaced() {
        let ob = "{\"protocol\":\"trojan\",\"tag\":\"x\",\"settings\":{\"servers\":[{\"address\":\"a.example.com\",\"port\":443,\"password\":\"p\"}]},\"streamSettings\":{\"sockopt\":{\"dialerProxy\":\"gone\",\"tcpFastOpen\":true}}}";
        let v = built(ob, None);
        let so = &v["outbounds"][0]["streamSettings"]["sockopt"];
        assert!(so.get("dialerProxy").is_none());
        assert_eq!(so["tcpFastOpen"], true);
        assert!(build("not json", 1, None, &[], "warning").is_err());
        assert!(has_server(serde_json::from_str::<Value>(ob).unwrap().as_object().unwrap()));
        assert_eq!(server_endpoint(ob), Some(("a.example.com".into(), 443)));
    }

    /// Optional: `XRAY_BIN=/path/to/xray cargo test` checks every built config
    /// with the real core (`xray run -test`), Xray-core v25.12.8.
    #[test]
    fn real_xray_accepts_every_shape() {
        let Ok(bin) = std::env::var("XRAY_BIN") else {
            eprintln!("XRAY_BIN not set — skipping the xray -test check");
            return;
        };
        let links = [
            format!("vless://{UUID}@192.0.2.10:443?security=reality&encryption=none&pbk=JLfJZqtyFf3MgHBiZcxuvqmRscjrM5xmSBVaWPPsObE&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=yahoo.com&sid=c39cc7310a"),
            format!("vless://{UUID}@203.0.113.9:443?mode=auto&path=%2Fx&security=tls&alpn=h2&host=f.example.net&fp=chrome&type=xhttp&sni=s.example.com&allowInsecure=1"),
            format!("vless://{UUID}@h.example.com:443?security=tls&type=grpc&serviceName=svc"),
            format!("vless://{UUID}@h.example.com:443?security=tls&type=httpupgrade&path=%2Fu"),
            format!("vless://{UUID}@h.example.com:80?type=tcp&headerType=http&path=%2F&host=x.example.com"),
            format!("vless://{UUID}@h.example.com:443?type=kcp&seed=s33d&headerType=none"),
            "trojan://secret@t.example.com:443?sni=t.example.com&type=ws&path=%2Ft".into(),
            "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388".into(),
            "socks://dXNlcjpwYXNz@s.example.com:1080".into(),
            "wg://cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDE9@wg.example.com:51820?publickey=cHVibGljcHVibGljcHVibGljcHVibGljcHVibGljMDE9&address=10.1.0.2/32".into(),
        ];
        let vm = format!("{{\"ps\":\"vm\",\"add\":\"vm.example.com\",\"port\":\"8443\",\"id\":\"{UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"path\":\"/v\",\"tls\":\"tls\"}}");
        let mut all: Vec<String> = links.to_vec();
        all.push(format!("vmess://{}", crate::custom::npvt::b64_encode(vm.as_bytes(), crate::custom::npvt::STD_ALPHABET, true)));
        let dir = std::env::temp_dir().join(format!("aether-xray-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, link) in all.iter().enumerate() {
            let c = parser::parse(link, ConfigSource::Link, None, 0).unwrap().remove(0);
            for via in [None, Some(1819), Some(0)] {
                let cfg = if via == Some(0) {
                    build_for_tor(&c.outbound, 18830, &[], "warning").unwrap()
                } else {
                    build(&c.outbound, 18830, via, &[], "warning").unwrap()
                };
                let file = dir.join(format!("c{i}-{}.json", via.map(|p| p.to_string()).unwrap_or_default()));
                std::fs::write(&file, &cfg).unwrap();
                let out = std::process::Command::new(&bin)
                    .args(["run", "-test", "-c"])
                    .arg(&file)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "xray rejected {link} (via={via:?}):\n{}\n{}",
                    String::from_utf8_lossy(&out.stdout),
                    cfg
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mux_only_behind_a_slow_hop_and_never_on_xtls() {
        // ۱.۴.۰: پشتِ هاپ (زنجیره) Mux صریحاً خاموش است — نشستِ تور/سایفون با
        // Mux در اولین stall همهٔ جریان‌ها را می‌بُرد.
        let off: Value = serde_json::from_str(&build(&sample(), 1, Some(1820), &[], "warning").unwrap()).unwrap();
        assert_eq!(off["outbounds"][0]["mux"]["enabled"], false);
        let chained: Value =
            serde_json::from_str(&build_chain(&sample(), 1, Some(1820), &[], "warning", SLOW_CHAIN_MUX).unwrap()).unwrap();
        assert_eq!(chained["outbounds"][0]["mux"]["enabled"], false);
        assert_eq!(chained["outbounds"][1]["mux"]["enabled"], false);
        assert_eq!(chained["outbounds"][1]["streamSettings"]["sockopt"]["domainStrategy"], "AsIs");
        // Windows: Solo also has no Mux (BPB/Cloudflare :2086 does not support it).
        let on: Value =
            serde_json::from_str(&build_chain(&sample(), 1, None, &[], "warning", 8).unwrap()).unwrap();
        assert_ne!(on["outbounds"][0]["mux"]["enabled"], true);
        // outboundِ SOCKS بالادستی: بی Mux و دامنه‌ها AsIs.
        let socks_up = r#"{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1081}]}}"#;
        let s: Value = serde_json::from_str(&build_chain(socks_up, 1, None, &[], "warning", SLOW_CHAIN_MUX).unwrap()).unwrap();
        assert_eq!(s["outbounds"][0]["mux"]["enabled"], false);
        assert!(s["outbounds"][0]["streamSettings"]["sockopt"].get("domainStrategy").is_none());
        // XTLS Vision: Xray Mux را رد می‌کند.
        let vision = parser::parse(
            &format!("vless://{UUID}@203.0.113.9:443?security=reality&sni=rusbid.de&fp=firefox&pbk=AAAA&sid=ab&flow=xtls-rprx-vision&type=tcp#v"),
            ConfigSource::Link,
            None,
            0,
        )
        .unwrap()[0]
            .outbound
            .clone();
        let v: Value = serde_json::from_str(&build_chain(&vision, 1, None, &[], "warning", 8).unwrap()).unwrap();
        assert!(v["outbounds"][0].get("mux").is_none());
        let w: Value = serde_json::from_str(&build_chain(&wg(), 1, None, &[], "warning", 8).unwrap()).unwrap();
        assert!(w["outbounds"][0].get("mux").is_none());
        // و در زنجیره هم هرگز روشن نمی‌شود.
        let vc: Value = serde_json::from_str(&build_chain(&vision, 1, Some(1820), &[], "warning", 8).unwrap()).unwrap();
        assert_ne!(vc["outbounds"][0]["mux"]["enabled"], true);
    }

    #[test]
    fn tor_behind_the_config_gets_an_sni_safe_link() {
        let v: Value =
            serde_json::from_str(&build_for_tor(&sample(), 18830, &[], "warning").unwrap())
                .unwrap();
        assert_sniffing_off(&v);
        let outs = v["outbounds"].as_array().unwrap();
        assert_eq!(outs[0]["tag"], "proxy");
        assert!(outs[0]["streamSettings"]["sockopt"]
            .get("dialerProxy")
            .is_none());
        assert_eq!(
            outs[0]["streamSettings"]["sockopt"]["domainStrategy"],
            "UseIPv4v6"
        );
        let link = &outs[1];
        assert_eq!(link["tag"], TOR_LINK_TAG);
        assert_eq!(link["protocol"], "freedom");
        assert_eq!(link["settings"]["fragment"]["packets"], "tlshello");
        assert_eq!(link["settings"]["fragment"]["length"], "100-200");
        assert_eq!(link["settings"]["fragment"]["interval"], "0");
        assert_eq!(link["streamSettings"]["sockopt"]["dialerProxy"], "proxy");
        assert_eq!(v["routing"]["rules"][1]["inboundTag"][0], "socks-in");
        assert_eq!(v["routing"]["rules"][1]["outboundTag"], TOR_LINK_TAG);
        // DNSِ خودِ Xray همچنان مستقیم.
        assert_eq!(v["routing"]["rules"][0]["outboundTag"], "direct");
        // بدون تور هیچ تغییری نیست.
        assert!(!build(&sample(), 18830, None, &[], "warning")
            .unwrap()
            .contains(TOR_LINK_TAG));
        assert!(!build(&sample(), 18830, Some(1819), &[], "warning")
            .unwrap()
            .contains(TOR_LINK_TAG));
        // اولین رکوردِ شکسته باید از سرآیندِ تا cipher suiteها (۷۳ بایت) بلندتر باشد.
        let min: u32 = TOR_LINK_FRAGMENT
            .split('-')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(min > 73);
    }

    #[test]
    fn direct_outbound_is_tagged_and_dials_directly() {
        let o = direct_outbound(&sample(), "p3").unwrap();
        assert_eq!(o["tag"], "p3");
        assert!(o["streamSettings"]["sockopt"].get("dialerProxy").is_none());
        assert!(o.get("mux").is_none());
        assert!(direct_outbound("[]", "x").is_err());
    }
}
