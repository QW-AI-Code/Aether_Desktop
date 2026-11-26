//! پورت از `core/SmartAuto.kt` + منطق نردبان `AetherVpnService.directPlan/buildPlan`.
//!
//! ریشهٔ باگ قبلی دسکتاپ: فقط «یک» پروتکل انتخاب می‌شد و هیچ نردبان
//! تلاشِ چندمرحله‌ای وجود نداشت؛ در اندروید هر اتصال یک «برنامه» چند
//! کاندیدایی است که یکی‌یکی امتحان می‌شوند تا اولینِ قبول‌شده در خودآزما
//! برنده شود. همان منطق این‌جا پیاده شده:
//!
//!  * پروتکل دستی  ← (معادل directPlan): اول همان تنظیمات کاربر (سقف ۷۵
//!    ثانیه)، برای MASQUE سپس HTTP/2 (بستر TCP)، بعد پاس ضد-DPI — پروتکل هرگز
//!    عوض نمی‌شود و ECH هرگز خودکار روشن نمی‌شود (۱.۵.۰).
//!  * Smart Auto (نشست‌هایی که مسابقه ندارند) ← نردبانی از همان کاتالوگِ
//!    `smart_plus::plan` (۱.۵.۰، پورت موبایل ۱.۷.۰) + دو پلهٔ «آخرین تلاش».

use crate::log::DiagnosticsLog;
use crate::profile::{ConnectionProfile, GoolMode, IpVersion, Noize, Protocol, ScanMode, TorMode};

const TAG: &str = "auto";

/// سقف پاس اول — همان `FIRST_PASS_MAX_MS` اندروید. تعریفش در `budgets.rs`
/// است، کنارِ رزروِ راه‌اندازیِ موتور که با آن یک حساب می‌سازد.
use crate::budgets::FIRST_PASS_MAX_MS;

/// ترتیب ترجیح — همان ترتیبی که SmartAuto.kt دارد.
/// ترتیبِ پیش‌فرض وقتی UDP از کار افتاده — MASQUE روی TCP جلو می‌افتد و
/// WireGuard که بی UDP اصلاً کار نمی‌کند، آخر می‌ماند.
const PREFERENCE: [Protocol; 3] = [Protocol::Masque, Protocol::Gool, Protocol::Wireguard];

/// شکلِ فیلترینگِ این شبکه — همان `DpiClass` در `SmartAuto.kt`.
///
/// دسکتاپ تا پیش از این چنین چیزی نداشت و ترتیبِ نردبانش **ثابت** بود:
/// MASQUE، GOOL، WireGuard. یعنی روی شبکه‌ای هم که UDP در آن سالم است و
/// اندروید با WireGuard در ۵ ثانیه وصل می‌شود، دسکتاپ اول ۳۵ ثانیه MASQUE
/// «همان‌طور که تنظیم شده»، بعد ۱۲۰ ثانیه MASQUEِ سخت‌شده، بعد پلهٔ HTTP/2 و
/// بعد GOOL را می‌رفت — و WireGuard عملاً پس از چند دقیقه به نوبت می‌رسید.
/// WireGuard «ناموفق» شمرده نمی‌شد؛ هیچ‌وقت امتحان نمی‌شد.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiClass {
    /// UDP جواب می‌دهد و خروجِ مستقیم باز است — مسیرِ تقریباً پاک.
    Open,
    /// UDP سالم است ولی خروجِ مستقیم بسته — فیلترینگ روی TCP/SNI.
    SniFiltering,
    /// خروجِ مستقیم باز است ولی UDP جواب نمی‌دهد — QUIC و WireGuard گرسنه
    /// می‌مانند و ترابردِ TCP-شکل راهِ ورود است.
    UdpThrottled,
    /// هر دو خراب.
    Hostile,
}

impl NetFingerprint {
    /// نگاشتِ دو سنجهٔ دسکتاپ به همان چهار کلاسِ موبایل.
    pub fn dpi_class(self) -> DpiClass {
        match (self.udp_ok, self.filtered) {
            (true, false) => DpiClass::Open,
            (true, true) => DpiClass::SniFiltering,
            (false, false) => DpiClass::UdpThrottled,
            (false, true) => DpiClass::Hostile,
        }
    }
}

/// ترتیبِ پروتکل‌ها برای این شبکه — عیناً نردبانِ `SmartAuto.kt`.
///
/// 1.5.0: the Smart ladder is built from `smart_plus::plan` now; this stays for
/// reference and for older callers.
#[allow(dead_code)]
fn preference_for(fp: NetFingerprint) -> [Protocol; 3] {
    match fp.dpi_class() {
        // روی شبکهٔ باز، WireGuard سریع‌ترین است و اندروید هم با همین شروع
        // می‌کند. این تنها تغییری است که «چند دقیقه» را به «چند ثانیه»
        // برمی‌گردانَد.
        DpiClass::Open => [Protocol::Wireguard, Protocol::Masque, Protocol::Gool],
        // UDP سالم است، پس WireGuard هنوز بهترین شانس است؛ MASQUE که روی
        // TLS/SNI حساس‌تر است، پس از GOOL می‌آید.
        DpiClass::SniFiltering => [Protocol::Wireguard, Protocol::Gool, Protocol::Masque],
        // بی UDP، WireGuard آخر است — همان ترتیبی که دسکتاپ همیشه داشت.
        DpiClass::UdpThrottled | DpiClass::Hostile => PREFERENCE,
    }
}

/// What the pre-connect probes learned about this network.
///
/// Until 1.2.3-p2 this was a single `hostile: bool` derived from one TCP:80
/// dial, so the planner had no idea whether UDP worked - and the MASQUE carrier
/// choice is entirely a question about UDP. See [`harden`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetFingerprint {
    /// Direct TCP egress looks blocked: lead with the hardened anti-DPI pass.
    pub filtered: bool,
    /// A real UDP round trip completed. This is the signal for WireGuard.
    /// It must not be replaced by the QUIC result: UDP:53 can work while
    /// Cloudflare QUIC on UDP:443 is filtered (as in the field log).
    pub udp_ok: bool,
    /// A Cloudflare QUIC version-negotiation response was received. This only
    /// selects MASQUE's carrier; it does not decide whether WireGuard may run.
    pub quic_ok: bool,
    /// 1.5.0 (mobile 1.7.0): did a QUIC Version-Negotiation probe to the MASQUE
    /// gateways `162.159.198.1/.2:443` come back? `None` = not measured.
    pub quic_reachable: Option<bool>,
}

impl Default for NetFingerprint {
    fn default() -> Self {
        // Absent evidence, assume UDP works: HTTP/3 is the fast carrier and the
        // ladder still falls through to HTTP/2 if the attempt fails.
        Self {
            filtered: false,
            udp_ok: true,
            quic_ok: true,
            quic_reachable: None,
        }
    }
}

/// معادل `AutoCandidate` اندروید — یک استراتژی آمادهٔ اجرا.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub profile: ConnectionProfile,
    pub timeout_ms: u64,
    pub label: String,
    /// 1.5.0: the Smart catalogue id this rung was built from (`wg`, `masque.h2`,
    /// ...), so the serial ladder can remember its winner per network.
    pub tactic: Option<&'static str>,
}

// >>> AETHER-APP-PATCH smart-brain-ladder (1.5.0, same version)
/// Whether a concrete rung's outer carrier is UDP (WireGuard, QUIC).
pub fn rides_udp(p: &ConnectionProfile) -> bool {
    match p.protocol {
        Protocol::Wireguard => true,
        Protocol::Gool => p.gool_mode == crate::profile::GoolMode::Classic || !p.masque_http2,
        Protocol::Masque | Protocol::Mim => !p.masque_http2,
        Protocol::Smart => false,
    }
}

/// The Smart brain for the serial ladder (port of mobile 1.7.0
/// `DpiBrain.adaptLadder`): the rungs still to come are re-planned with what
/// the failed ones revealed. TCP carriers get TLS fragmentation (and at least
/// the Firewall obfuscation floor) once TLS is interfered with or gateways stay
/// silent; UDP carriers get the GFW disguise once UDP is dropped; and UDP rungs
/// move behind TCP ones once UDP is known to be blocked. Nothing is removed.
pub fn adapt_ladder(
    rest: Vec<Candidate>,
    k: &crate::smart_plus::brain::Knowledge,
) -> Vec<Candidate> {
    let hardened: Vec<Candidate> = rest
        .into_iter()
        .map(|mut c| {
            let udp = rides_udp(&c.profile);
            if !udp && (k.tls_interference() || k.gateways_filtered()) && !c.profile.fragment {
                c.profile.fragment = true;
                if (c.profile.noize as u8) < (Noize::Firewall as u8) {
                    c.profile.noize = Noize::Firewall;
                }
                c.label.push_str(" · fragment (smart)");
            } else if udp
                && (k.gateways_filtered() || k.udp_blocked())
                && (c.profile.noize as u8) < (Noize::Gfw as u8)
            {
                c.profile.noize = Noize::Gfw;
                c.label.push_str(" · noize=gfw (smart)");
            }
            c
        })
        .collect();
    if k.udp_blocked() {
        let (udp, tcp): (Vec<Candidate>, Vec<Candidate>) =
            hardened.into_iter().partition(|c| rides_udp(&c.profile));
        tcp.into_iter().chain(udp).collect()
    } else {
        hardened
    }
}
// <<< AETHER-APP-PATCH smart-brain-ladder

/// Whether a protocol's data plane is the MASQUE carrier, i.e. whether the
/// HTTP/3-vs-HTTP/2 choice applies to it at all.
///
/// ## 1.2.6: `MASQUE×2` belongs here too
///
/// The three helpers below used to test `== Protocol::Masque`, which was right
/// while MASQUE was the only protocol on that carrier. `Protocol::Mim`
/// (`--mim`, ported from mobile 1.3.0) is two MASQUE hops, and the core runs
/// **both** of them on whatever carrier `AETHER_MASQUE_HTTP2` names -- its
/// `Protocol::MasqueInMasque` arm calls `select_masque_transport()` exactly like
/// the single-hop arm, and the desktop always sends that variable. So on the
/// network in the field log -- where the probe proved
///
/// ```text
///   netprobe: UDP works but no Cloudflare edge answered QUIC on UDP:443
/// ```
///
/// -- a hand-picked `MASQUE×2` would have dialled QUIC twice on a network where
/// QUIC answers once: the outer hop can never come up, so the inner hop is never
/// reached. Same measurement, same conclusion, so the same switch has to apply.
fn rides_masque_carrier(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Masque | Protocol::Mim)
}

/// ساخت نسخهٔ سخت‌شدهٔ ضد-DPI — معادل پاس دوم `directPlan` اندروید.
///
/// ## 1.2.3-p2: hardening no longer means "make the download slow"
///
/// This used to set `masque_http2 = true` unconditionally. That one line is how
/// almost every desktop session ended up on the HTTP/2 carrier: MASQUE is the
/// first rung of the Smart Auto ladder, so a single flaky first attempt promoted
/// the hardened pass, the hardened pass demoted the carrier from HTTP/3 to
/// HTTP/2, and the session then stayed on the one data plane with a 64 KB
/// flow-control window - for the rest of its life, on a network where UDP was
/// perfectly healthy.
///
/// The mobile build never did this: `SmartAuto.kt` only passes `h2 = true` in
/// the `UDP_THROTTLED` and `HOSTILE` branches, i.e. only after a real UDP probe
/// has failed. Same rule here now. A user who ticked the toggle themselves is
/// still honoured.
fn harden(p: &ConnectionProfile, fp: NetFingerprint) -> ConnectionProfile {
    let mut h = p.clone();
    if h.noize == Noize::Off {
        h.noize = Noize::Firewall;
    }
    if h.protocol == Protocol::Masque {
        // 1.5.0 (mobile 1.7.0 `directPlan`): the anti-DPI MASQUE pass rides
        // HTTP/2 with TLS fragmentation - the combination that came up in Tehran
        // (`162.159.198.2:443` over h2) when HTTP/3 never did.
        h.masque_http2 = true;
        h.fragment = true;
    } else if rides_masque_carrier(h.protocol) {
        h.masque_http2 = p.masque_http2 || !fp.quic_ok;
        h.fragment = true;
    }
    // >>> AETHER-APP-FIX ech-is-only-ever-the-users-choice (1.5.0)
    // 1.4.0 switched ECH on for every hardened MASQUE rung outside OPEN networks
    // (`ech-only-where-sni-is-filtered`). Without a fetchable ECH key core 2.4.0
    // refuses to start - `Error: Ech("ECH is on but there is no ECH key to
    // offer ...")` after 0.4 s - which is exactly what the Tehran logs show for
    // every anti-DPI pass. ECH now stays whatever the user set.
    h.ech = p.ech;
    // <<< AETHER-APP-FIX ech-is-only-ever-the-users-choice (1.5.0)
    h
}

/// The profile with the MASQUE carrier forced onto HTTP/2 when the pre-connect
/// probe proved QUIC cannot work on this network.
///
/// ## 1.2.3-p3: the FIRST rung must not ride a carrier already known to be dead
///
/// This only ever turns the HTTP/2 carrier ON. A user who ticked the toggle
/// themselves is untouched, and on a healthy-UDP network nothing changes at all.
fn carrier_for(p: &ConnectionProfile, fp: NetFingerprint) -> ConnectionProfile {
    let mut out = p.clone();
    if rides_masque_carrier(out.protocol) && !fp.quic_ok {
        out.masque_http2 = true;
    }
    out
}

/// Carrier suffix for a label, so the log says which data plane is being tried.
fn carrier(p: &ConnectionProfile) -> &'static str {
    if rides_masque_carrier(p.protocol) && p.masque_http2 {
        " · h2"
    } else if rides_masque_carrier(p.protocol) {
        " · h3"
    } else {
        ""
    }
}

// >>> AETHER-APP-FIX plain-pass-goes-last-on-a-filtered-network
/// بودجهٔ یک پلهٔ «آخرین‌شانس» — تلاشی که دلیل داریم شکست می‌خورد ولی حذفش
/// هم درست نیست، چون انگشت‌نگاری شبکه قطعی نیست.
const LAST_RESORT_MS: u64 = 20_000;

fn last_resort(mut c: Candidate) -> Candidate {
    c.timeout_ms = c.timeout_ms.min(LAST_RESORT_MS);
    c
}
// <<< AETHER-APP-FIX plain-pass-goes-last-on-a-filtered-network

/// Budget of the HTTP/2 pass of a manual MASQUE (mobile 1.7.0 `directPlan`).
const H2_PASS_MAX_MS: u64 = 45_000;

/// معادل `directPlan` — پروتکل دستی، بدون تعویض پروتکل.
///
/// 1.5.0 (mobile 1.7.0): three passes for MASQUE -
/// 1. as configured (at most 75 s),
/// 2. the same over HTTP/2 (TCP carrier) when the user did not choose it (45 s),
/// 3. anti-DPI: obfuscation, and for MASQUE HTTP/2 + TLS fragmentation, with
///    ECH exactly as the user set it (full budget).
///
/// Identical passes are dropped.
fn direct_plan(user: &ConnectionProfile, fp: NetFingerprint) -> Vec<Candidate> {
    let full = user.connect_timeout_ms();
    let hostile = fp.filtered;
    let plain = carrier_for(user, fp);
    let hardened = harden(&plain, fp);
    let name = format!("{:?}", user.protocol).to_uppercase();
    let as_configured = Candidate {
        timeout_ms: full.min(FIRST_PASS_MAX_MS),
        label: format!("{name} · as configured{}", carrier(&plain)),
        profile: plain.clone(),
        tactic: None,
    };
    let h2_pass = (user.protocol == Protocol::Masque && !plain.masque_http2).then(|| {
        let mut p = plain.clone();
        p.masque_http2 = true;
        Candidate {
            timeout_ms: full.min(H2_PASS_MAX_MS),
            label: "MASQUE · h2 (TCP carrier)".to_string(),
            profile: p,
            tactic: None,
        }
    });
    let anti_dpi = Candidate {
        label: format!("{name} · hardened anti-DPI{}", carrier(&hardened)),
        profile: hardened,
        timeout_ms: full,
        tactic: None,
    };
    let ordered: Vec<Candidate> = if hostile {
        // >>> AETHER-APP-FIX plain-pass-goes-last-on-a-filtered-network
        // روی شبکه‌ای که انگشت‌نگاری می‌گوید فیلتر است، پاسِ ضد-DPI جلو می‌افتد و
        // پاسِ ساده با بودجهٔ کوتاه آخر می‌ماند (نه ۷۵ ثانیه).
        let mut v = vec![anti_dpi];
        v.extend(h2_pass);
        v.push(last_resort(as_configured));
        v
        // <<< AETHER-APP-FIX plain-pass-goes-last-on-a-filtered-network
    } else {
        let mut v = vec![as_configured];
        v.extend(h2_pass);
        v.push(anti_dpi);
        v
    };
    distinct(ordered)
}

/// Drops a pass whose profile equals an earlier one; the earlier keeps its
/// place, the later one's longer budget is kept on it.
fn distinct(list: Vec<Candidate>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for c in list {
        if let Some(prev) = out.iter_mut().find(|o| o.profile == c.profile) {
            prev.timeout_ms = prev.timeout_ms.max(c.timeout_ms);
            continue;
        }
        out.push(c);
    }
    out
}

/// Planner context for this network (shared with the Smart race).
pub fn smart_context(
    user: &ConnectionProfile,
    fp: NetFingerprint,
    prefer_tcp: bool,
) -> crate::smart_plus::plan::Context {
    use crate::smart_plus::plan::{Context, Dpi};
    Context {
        dpi: match fp.dpi_class() {
            DpiClass::Open => Dpi::Open,
            DpiClass::SniFiltering => Dpi::SniFiltering,
            DpiClass::UdpThrottled => Dpi::UdpThrottled,
            DpiClass::Hostile => Dpi::Hostile,
        },
        // Windows has no reliable cellular signal; never bias on it.
        mobile: false,
        quic: fp.quic_reachable.or(Some(fp.quic_ok)),
        gool_classic: user.gool_mode == GoolMode::Classic,
        prefer_tcp,
    }
}

/// Log label of one Smart rung: `PROTO · noize=.. · h2 · fragment · scan=turbo`.
pub fn tactic_label(p: &ConnectionProfile, last_resort: bool) -> String {
    let mut parts = vec![format!("{:?}", p.protocol).to_uppercase()];
    parts.push(format!("noize={}", format!("{:?}", p.noize).to_lowercase()));
    let masque_carrier = rides_masque_carrier(p.protocol) || p.protocol == Protocol::Gool;
    if masque_carrier && p.masque_http2 {
        parts.push("h2".into());
    } else if rides_masque_carrier(p.protocol) {
        parts.push("h3".into());
    }
    if p.fragment {
        parts.push("fragment".into());
    }
    if p.ech {
        parts.push("ech".into());
    }
    if p.protocol == Protocol::Wireguard
        && p.endpoint_mode == crate::profile::EndpointMode::ManualRange
        && !p.manual_range.trim().is_empty()
    {
        parts.push(format!("ranges[{}]", p.manual_range.trim()));
    }
    parts.push(format!("scan={}", format!("{:?}", p.scan_mode).to_lowercase()));
    let mut s = parts.join(" · ");
    if last_resort {
        s.push_str(" (last resort)");
    }
    s
}

/// Ladder rung budget: the tactic's race budget, stretched by half for a serial
/// ladder (no second lane covers for it), never above the rung's own scan budget.
fn rung_budget(t: &crate::smart_plus::plan::Tactic, full: u64) -> u64 {
    (t.budget_ms + t.budget_ms / 2).min(full)
}

/// نردبان Smart Auto — 1.5.0: built from the **same catalogue** as the Smart
/// race (`smart_plus::plan::ladder`), for profiles that cannot race (chains, a
/// fixed endpoint, Zero Trust e-mail sign-in).
///
/// * both families interleaved, every tactic once, MASQUE over HTTP/2 always in;
/// * per-network memory re-orders it (proven first, recent failures last);
/// * MASQUE / Gool / MASQUE×2 use the core's own gateway list - nothing measured
///   for WireGuard narrows them (desktop 1.4.0 never narrowed ranges either);
/// * two last-resort rungs (MASQUE h2, WireGuard) with a deep scan close it.
fn auto_plan(
    user: &ConnectionProfile,
    fp: NetFingerprint,
    memory: Option<&crate::smart_plus::memory::Entry>,
    now: i64,
) -> Vec<Candidate> {
    use crate::smart_plus::plan::{self as sp, Family};
    let ctx = smart_context(user, fp, false);
    let mut ladder = sp::ladder(ctx, memory, now);
    // فقط IPv6: WireGuard پایدارتر است — همان قاعدهٔ اندروید.
    if user.ip_version == IpVersion::V6 && ladder.first().map(|t| t.family) == Some(Family::Masque) {
        let (warp, masque): (Vec<_>, Vec<_>) =
            ladder.into_iter().partition(|t| t.family == Family::Warp);
        let mut merged = vec![];
        let n = warp.len().max(masque.len());
        for i in 0..n {
            merged.extend(warp.get(i).cloned());
            merged.extend(masque.get(i).cloned());
        }
        ladder = merged;
    }
    DiagnosticsLog::i(
        TAG,
        &format!(
            "Ladder for {:?} (quic={:?}): {}",
            fp.dpi_class(),
            ctx.quic,
            ladder.iter().map(|t| t.id).collect::<Vec<_>>().join(" -> ")
        ),
    );
    let mut plan = Vec::new();
    for t in &ladder {
        let profile = crate::smart_plus::apply(t, user, false);
        let full = profile.connect_timeout_ms();
        plan.push(Candidate {
            label: tactic_label(&profile, false),
            timeout_ms: rung_budget(t, full),
            profile,
            tactic: Some(t.id),
        });
    }
    for t in sp::last_resort(ctx) {
        let profile = crate::smart_plus::last_resort_profile(&t, user);
        plan.push(Candidate {
            label: tactic_label(&profile, true),
            timeout_ms: profile.connect_timeout_ms(),
            profile,
            tactic: Some(t.id),
        });
    }
    plan
}

/// نقطهٔ ورود: برنامهٔ کامل اتصال برای پروفایل کاربر.
pub fn build_plan(user: &ConnectionProfile, fp: NetFingerprint) -> Vec<Candidate> {
    build_plan_with_memory(user, fp, None, 0)
}

/// [`build_plan`] with the per-network Smart memory (ladder order only).
pub fn build_plan_with_memory(
    user: &ConnectionProfile,
    fp: NetFingerprint,
    memory: Option<&crate::smart_plus::memory::Entry>,
    now: i64,
) -> Vec<Candidate> {
    // پیش از هر چیز: حالت‌هایی که ترافیک دستگاه از تور بیرون می‌رود، نردبان
    // ندارند. اثرانگشتِ شبکه هم برایشان بی‌معنی است — چیزی که آن‌جا شکست
    // می‌خورد یا موفق می‌شود، bootstrapِ تور است نه یک نقطهٔ پایانی WARP.
    if let Some(plan) = tor_plan(user) {
        let summary: Vec<String> = plan.iter().map(|c| c.label.clone()).collect();
        DiagnosticsLog::i(
            TAG,
            &format!("Plan ready (1 attempt): {}", summary.join(" \u{2192} ")),
        );
        return plan;
    }
    if fp.filtered {
        DiagnosticsLog::w(
            TAG,
            "Network fingerprint: this network looks filtered - anti-DPI attempts run first.",
        );
    }
    // Say it out loud: this decides HTTP/3 (QUIC) versus HTTP/2 (TCP) for the
    // MASQUE carrier, and the two have very different throughput.
    DiagnosticsLog::i(
        TAG,
        &format!(
            "Network fingerprint: udp={} quic={} → MASQUE carrier prefers {}",
            if fp.udp_ok { "ok" } else { "blocked/throttled" },
            match fp.quic_reachable {
                Some(true) => "reachable",
                Some(false) => "unreachable",
                None => "unknown",
            },
            if fp.quic_ok {
                "HTTP/3 (QUIC)"
            } else {
                "HTTP/2 (TCP)"
            },
        ),
    );
    let plan = if user.protocol == Protocol::Smart {
        DiagnosticsLog::i(TAG, "Smart Auto: building the strategy ladder…");
        auto_plan(user, fp, memory, now)
    } else {
        direct_plan(user, fp)
    };
    let summary: Vec<String> = plan.iter().map(|c| c.label.clone()).collect();
    DiagnosticsLog::i(
        TAG,
        &format!(
            "Plan ready ({} attempt(s)): {}",
            plan.len(),
            summary.join(" → ")
        ),
    );
    plan
}

/// بودجهٔ یک تلاشِ تور-جلو — معادل `torBudget` اندروید.
///
/// وقتی پل مجاز است، بودجه باید جای fallbackِ خودِ هسته روی پل‌ها را هم داشته
/// باشد؛ وگرنه بودجهٔ سادهٔ bootstrap. آنچه این بودجهٔ بلند را به یک سکوتِ بلند
/// تبدیل نمی‌کند، شناساگرِ گیرکردن در `state.rs` است.
fn tor_budget(p: &ConnectionProfile) -> u64 {
    if p.tor_bridges != crate::profile::TorBridges::Off {
        crate::diagnostics::TOR_BRIDGE_BUDGET_MS
    } else {
        crate::diagnostics::TOR_BOOTSTRAP_BUDGET_MS
    }
}

/// نردبانِ حالت‌های تور، یا `None` وقتی این نشست تور-جلو نیست.
///
/// # چرا نردبانِ معمول اینجا **زیان‌آور** است
///
/// نردبان از یک فرض ساخته شده: هر پله یک ترابردِ دیگر برای رسیدن به یک نقطهٔ
/// پایانی است، پس پلهٔ شکست‌خورده چیزی دربارهٔ شبکه می‌گوید. در حالت‌های تور آن
/// فرض می‌شکند، و هر بار به شکل خودش:
///
/// * `--tor-only` هیچ تونلی بالا نمی‌آورد؛ نه نقطهٔ پایانی‌ای برای اسکن هست، نه
///   ترابردی برای مبهم‌سازی. هر سه پله **همان** فراخوانیِ هسته می‌شدند و تنها
///   کاری که می‌کردند این بود که bootstrapِ نیمه‌تمامِ تور را بکشند و از صفر
///   شروع کنند — دقیقاً همان‌جایی که تور به وقت نیاز دارد.
/// * زنجیرهٔ برعکس (`Tor → Aether`) تنها یک ترابرد دارد: هسته در این حالت
///   `--wg` و `--gool` را رد می‌کند، پس پله‌های WireGuard و Gool در یک چشم‌به‌هم‌زدن
///   شکست می‌خوردند و بودجه‌ای را می‌سوزاندند که مالِ bootstrap بود. MASQUE هم
///   اجباراً روی HTTP/2 است، چون UDP از تور رد نمی‌شود.
///
/// زنجیرهٔ عادی (`Aether → Tor`) عمداً اینجا **نیست**: آنجا استیج ۱ یک تونل
/// کاملِ WARP است و تور بعد از آن و از داخلش راه می‌افتد، پس همان اثرانگشت‌زنی
/// و همان سخت‌سازیِ ضد-DPI که برای هر نشست دیگری درست است، برای آن هم درست است.
/// بودجهٔ تورِ آن نشست جای دیگری است: دروازهٔ `tor_gate` در `state.rs`.
fn tor_plan(user: &ConnectionProfile) -> Option<Vec<Candidate>> {
    match user.backend.tor_mode() {
        Some(TorMode::Only) => {
            DiagnosticsLog::i(
                TAG,
                "Tor only: no tunnel to scan — one attempt, on a bootstrap-sized budget.",
            );
            Some(vec![Candidate {
                profile: user.clone(),
                timeout_ms: tor_budget(user),
                label: "Tor \u{b7} direct or via bridges".to_string(),
                tactic: None,
            }])
        }
        Some(TorMode::Reverse) => {
            DiagnosticsLog::i(
                TAG,
                "Tor \u{2192} Aether: MASQUE over HTTP/2 is the only transport Tor can carry \
                 — one attempt, on a bootstrap-sized budget.",
            );
            // >>> AETHER-APP-PATCH tor-reverse-short-scan (port of mobile 1.4.0 `reversePlan`)
            // تا اینجا فقط ترابرد قفل می‌شد. موبایل ۱.۴.۰ نشان داد این کافی نیست:
            // لاگِ میدانی `scan mode=turbo candidates=896 … budget=45s` از داخلِ
            // یک مدارِ تور بود، با بازه‌هایی که اثرانگشتِ DPI روی مسیرِ *مستقیم*
            // ساخته بود. آنچه یک خروجیِ تور می‌تواند برسد هیچ ربطی به آن بازه‌ها
            // ندارد. پس سه چیز این‌جا پین می‌شود، دقیقاً مثل موبایل:
            //   * Turbo — کوتاه‌ترین اسکنِ موتور: اولین پاسخ برنده است و
            //     گیت‌وی‌های شناخته‌شدهٔ کلادفلر (MASQUE_SEEDS) اول پروب می‌شوند؛
            //   * endpoint_mode = Auto و manual_range خالی — بازه‌های مسیرِ مستقیم
            //     به اسکنِ داخلِ تور نمی‌رسند؛
            //   * بودجهٔ هم‌اندازهٔ bootstrapِ تور (پایین‌تر، `tor_budget`).
            // یک peerِ دستی هم عمداً کنار می‌رود: همان دلیل، یک نشانیِ اندازه‌گیری‌شده
            // روی مسیرِ مستقیم.
            let mut p = user.clone();
            p.protocol = Protocol::Masque;
            p.masque_http2 = true;
            p.scan_mode = ScanMode::Turbo;
            p.endpoint_mode = crate::profile::EndpointMode::Auto;
            p.manual_range = String::new();
            p.manual_peer = String::new();
            // <<< AETHER-APP-PATCH tor-reverse-short-scan
            Some(vec![Candidate {
                profile: p,
                timeout_ms: tor_budget(user),
                label: "MASQUE \u{b7} h2 \u{b7} through Tor".to_string(),
                tactic: None,
            }])
        }
        _ => None,
    }
}

/// معادل `SmartAuto.choose()` — برای سازگاری با کد/تست‌های قبلی حفظ شده.
pub fn pick(profile: &ConnectionProfile) -> Protocol {
    if profile.protocol != Protocol::Smart {
        return profile.protocol;
    }
    if profile.has_manual_peer() {
        return Protocol::Masque;
    }
    if profile.ip_version == IpVersion::V6 {
        return Protocol::Wireguard;
    }
    PREFERENCE[0]
}

/// ترتیب تلاش مجدد پس از شکست — معادل `nextCandidate()`.
pub fn next_after(failed: Protocol) -> Option<Protocol> {
    let idx = PREFERENCE.iter().position(|p| *p == failed)?;
    PREFERENCE.get(idx + 1).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::TransportBackend;

    fn fp(filtered: bool, udp_ok: bool, quic_ok: bool) -> NetFingerprint {
        NetFingerprint {
            filtered,
            udp_ok,
            quic_ok,
            quic_reachable: None,
        }
    }
    fn labels(plan: &[Candidate]) -> Vec<String> {
        plan.iter().map(|c| c.label.clone()).collect()
    }
    fn is_last_resort(c: &Candidate) -> bool {
        c.label.ends_with("(last resort)")
    }

    /// نردبان باید Turbo بدهد در حالی که پروفایلِ ذخیره‌شده Balanced می‌ماند —
    /// همان چیدمانِ موبایل (`SmartAuto.kt`: «TURBO per attempt»). فقط دو پلهٔ
    /// «آخرین تلاش» اسکنِ عمیق دارند.
    #[test]
    fn every_ladder_rung_scans_in_turbo_while_the_profile_stays_balanced() {
        let user = ConnectionProfile::default();
        assert_eq!(user.scan_mode, ScanMode::Balanced);
        let plan = build_plan(&user, NetFingerprint::default());
        assert!(plan.len() > 1, "نردبان باید چند پله داشته باشد، نه یکی");
        for c in plan.iter().filter(|c| !is_last_resort(c)) {
            assert_eq!(c.profile.scan_mode, ScanMode::Turbo, "{}", c.label);
            assert!(c.timeout_ms <= 60_000, "{} got {}", c.label, c.timeout_ms);
        }
        let deep: Vec<_> = plan.iter().filter(|c| is_last_resort(c)).collect();
        assert_eq!(deep.len(), 2);
        assert_eq!(deep[0].tactic, Some("masque.h2"));
        assert_eq!(deep[1].tactic, Some("wg"));
        for c in deep {
            assert_eq!(c.profile.scan_mode, ScanMode::Balanced, "{}", c.label);
            assert_eq!(c.timeout_ms, c.profile.connect_timeout_ms());
        }
    }

    /// A user on Turbo gets Balanced for the deep last-resort scan.
    #[test]
    fn the_last_resort_of_a_turbo_user_scans_balanced() {
        let user = ConnectionProfile {
            scan_mode: ScanMode::Turbo,
            ..Default::default()
        };
        let plan = build_plan(&user, NetFingerprint::default());
        assert!(plan
            .iter()
            .filter(|c| is_last_resort(c))
            .all(|c| c.profile.scan_mode == ScanMode::Balanced));
    }

    /// پروتکلِ دستی = بی نردبان. حالتِ اسکنِ خودِ کاربر می‌ماند و بودجهٔ کامل می‌آید.
    #[test]
    fn a_manual_protocol_keeps_the_users_own_scan_mode() {
        let user = ConnectionProfile {
            protocol: Protocol::Wireguard,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        let plan = build_plan(&user, NetFingerprint::default());
        assert!(!plan.is_empty());
        for c in &plan {
            assert_eq!(c.profile.scan_mode, ScanMode::Balanced, "{}", c.label);
        }
        assert_eq!(plan.last().unwrap().timeout_ms, 150_000);
    }

    #[test]
    fn auto_never_reaches_the_engine() {
        let p = ConnectionProfile::default();
        assert_ne!(pick(&p), Protocol::Smart);
        for c in build_plan(&p, NetFingerprint::default()) {
            assert_ne!(c.profile.protocol, Protocol::Smart);
        }
    }

    #[test]
    fn explicit_protocol_is_respected() {
        let p = ConnectionProfile {
            protocol: Protocol::Wireguard,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        assert_eq!(pick(&p), Protocol::Wireguard);
        for c in build_plan(&p, NetFingerprint::default()) {
            assert_eq!(c.profile.protocol, Protocol::Wireguard);
        }
    }

    #[test]
    fn tor_only_gets_one_attempt_on_a_bootstrap_budget() {
        let p = ConnectionProfile {
            backend: TransportBackend::Tor,
            protocol: Protocol::Smart,
            gool_mode: GoolMode::Modern,
            tor_bridges: crate::profile::TorBridges::Off,
            ..Default::default()
        };
        let plan = build_plan(&p, NetFingerprint::default());
        assert_eq!(plan.len(), 1, "tor-only must not walk a ladder");
        assert_eq!(plan[0].timeout_ms, crate::diagnostics::TOR_BOOTSTRAP_BUDGET_MS);
    }

    #[test]
    fn permitted_bridges_widen_the_budget() {
        let p = ConnectionProfile {
            backend: TransportBackend::Tor,
            tor_bridges: crate::profile::TorBridges::Always,
            ..Default::default()
        };
        assert_eq!(
            build_plan(&p, NetFingerprint::default())[0].timeout_ms,
            crate::diagnostics::TOR_BRIDGE_BUDGET_MS,
        );
    }

    #[test]
    fn the_reverse_chain_never_plans_a_transport_tor_cannot_carry() {
        for protocol in [
            Protocol::Smart,
            Protocol::Wireguard,
            Protocol::Gool,
            Protocol::Masque,
        ] {
            let p = ConnectionProfile {
                backend: TransportBackend::TorAether,
                protocol,
                ..Default::default()
            };
            let plan = build_plan(&p, fp(true, true, true));
            assert_eq!(plan.len(), 1, "reverse chain must not walk a ladder ({protocol:?})");
            assert_eq!(plan[0].profile.protocol, Protocol::Masque);
            assert!(plan[0].profile.masque_http2, "UDP does not survive Tor");
        }
    }

    #[test]
    fn the_reverse_chain_scans_turbo_and_drops_direct_path_ranges() {
        let p = ConnectionProfile {
            backend: TransportBackend::TorAether,
            scan_mode: ScanMode::Ironclad,
            endpoint_mode: crate::profile::EndpointMode::ManualRange,
            manual_range: "188.114.97.0/24".into(),
            manual_peer: "162.159.198.1:443".into(),
            ..Default::default()
        };
        let plan = build_plan(&p, NetFingerprint::default());
        assert_eq!(plan.len(), 1);
        let rung = &plan[0].profile;
        assert_eq!(rung.scan_mode, ScanMode::Turbo);
        assert_eq!(rung.endpoint_mode, crate::profile::EndpointMode::Auto);
        assert!(rung.manual_range.is_empty());
        assert!(!rung.has_manual_peer());
        assert!(!rung.to_env().contains_key("AETHER_SCAN_CIDRS"));
        assert!(rung.to_args().iter().any(|a| a == "--turbo"));
    }

    #[test]
    fn the_ordinary_tor_chain_keeps_the_full_ladder() {
        let plain = build_plan(
            &ConnectionProfile {
                protocol: Protocol::Smart,
                gool_mode: GoolMode::Modern,
                ..Default::default()
            },
            NetFingerprint::default(),
        );
        let chained = build_plan(
            &ConnectionProfile {
                backend: TransportBackend::AetherTor,
                protocol: Protocol::Smart,
                gool_mode: GoolMode::Modern,
                ..Default::default()
            },
            NetFingerprint::default(),
        );
        assert!(chained.len() > 1, "Aether → Tor lost its ladder");
        assert_eq!(labels(&plain), labels(&chained));
    }

    #[test]
    fn fallback_order_matches_android() {
        assert_eq!(next_after(Protocol::Masque), Some(Protocol::Gool));
        assert_eq!(next_after(Protocol::Gool), Some(Protocol::Wireguard));
        assert_eq!(next_after(Protocol::Wireguard), None);
    }

    /// QUIC dead: MASQUE over HTTP/2 leads the ladder and no MASQUE rung rides QUIC
    /// before the HTTP/2 one has been tried.
    #[test]
    fn quic_dead_puts_masque_over_http2_first() {
        let plan = build_plan(&ConnectionProfile::default(), fp(false, false, false));
        assert_eq!(plan[0].tactic, Some("masque.h2"), "{:?}", labels(&plan));
        assert!(plan[0].profile.masque_http2);
        assert!(plan[0].label.contains(" · h2"), "{}", plan[0].label);
        let q = NetFingerprint {
            quic_reachable: Some(false),
            ..NetFingerprint::default()
        };
        assert_eq!(build_plan(&ConnectionProfile::default(), q)[0].tactic, Some("masque.h2"));
    }

    /// Every ladder has MASQUE over HTTP/2 - 1.4.0's OPEN ladder had none.
    #[test]
    fn every_ladder_carries_masque_over_http2() {
        for (filtered, udp_ok) in [(false, true), (true, true), (false, false), (true, false)] {
            let plan = build_plan(&ConnectionProfile::default(), fp(filtered, udp_ok, udp_ok));
            assert!(
                plan.iter().any(|c| c.profile.protocol == Protocol::Masque
                    && c.profile.masque_http2
                    && !is_last_resort(c)),
                "{:?}",
                labels(&plan)
            );
        }
    }

    /// UDP works, QUIC filtered (the field log): WireGuard leads, MASQUE leads with h2.
    #[test]
    fn udp_alive_but_quic_filtered_leads_with_masque_h2_and_keeps_wireguard_second() {
        let f = fp(false, true, false);
        assert_eq!(f.dpi_class(), DpiClass::Open);
        let plan = build_plan(&ConnectionProfile::default(), f);
        // quic=false → h2 first → the MASQUE lane leads; WireGuard is second.
        assert_eq!(plan[0].tactic, Some("masque.h2"));
        assert_eq!(plan[1].profile.protocol, Protocol::Wireguard);
    }

    #[test]
    fn a_hand_picked_two_hop_masque_also_avoids_a_dead_carrier() {
        let user = ConnectionProfile {
            protocol: Protocol::Mim,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        assert!(!user.masque_http2);
        for rung in &build_plan(&user, fp(false, true, false)) {
            assert_eq!(rung.profile.protocol, Protocol::Mim);
            assert!(rung.profile.masque_http2, "{}", rung.label);
            assert!(rung.label.contains("· h2"), "{}", rung.label);
        }
        for rung in build_plan(&user, fp(false, true, true)) {
            assert!(!rung.profile.masque_http2, "شبکهٔ سالم نباید به HTTP/2 برود");
            assert!(rung.label.contains("· h3"), "برچسب: {}", rung.label);
        }
    }

    /// On a healthy network the ladder opens with bare WireGuard and MASQUE over
    /// HTTP/3, both inside the first-pass window.
    #[test]
    fn a_healthy_network_leads_with_wireguard_then_masque_h3() {
        let plan = build_plan(&ConnectionProfile::default(), fp(false, true, true));
        assert_eq!(plan[0].tactic, Some("wg"), "{:?}", labels(&plan));
        assert_eq!(plan[0].profile.noize, Noize::Off);
        assert_eq!(plan[1].tactic, Some("masque.h3"));
        assert!(!plan[1].profile.masque_http2);
        assert!(plan[0].timeout_ms <= FIRST_PASS_MAX_MS);
    }

    #[test]
    fn without_udp_masque_leads_and_wireguard_closes() {
        let f = fp(false, false, false);
        assert_eq!(f.dpi_class(), DpiClass::UdpThrottled);
        let plan = build_plan(&ConnectionProfile::default(), f);
        assert_eq!(plan[0].profile.protocol, Protocol::Masque);
        assert_eq!(plan.last().unwrap().profile.protocol, Protocol::Wireguard);
    }

    /// SNI filtering: WireGuard first (UDP is fine); the MASQUE lane opens with
    /// HTTP/2, then fragmented HTTP/2.
    #[test]
    fn sni_filtering_keeps_wireguard_first_and_leads_masque_with_h2() {
        let f = fp(true, true, true);
        assert_eq!(f.dpi_class(), DpiClass::SniFiltering);
        let plan = build_plan(&ConnectionProfile::default(), f);
        assert_eq!(plan[0].profile.protocol, Protocol::Wireguard);
        let masque: Vec<_> = plan
            .iter()
            .filter(|c| c.profile.protocol == Protocol::Masque && !is_last_resort(c))
            .map(|c| c.tactic.unwrap())
            .collect();
        assert_eq!(masque, ["masque.h2", "masque.h2.frag", "masque.h3"]);
    }

    #[test]
    fn no_dpi_class_ever_drops_a_protocol() {
        for (filtered, udp_ok) in [(false, true), (true, true), (false, false), (true, false)] {
            let f = fp(filtered, udp_ok, udp_ok);
            let plan = build_plan(&ConnectionProfile::default(), f);
            for proto in [Protocol::Wireguard, Protocol::Masque, Protocol::Gool, Protocol::Mim] {
                assert!(
                    plan.iter().any(|c| c.profile.protocol == proto),
                    "{:?}: {proto:?} missing from the ladder",
                    f.dpi_class()
                );
            }
        }
    }

    /// Modern Gool (WireGuard inside MASQUE) rides the MASQUE carrier choice.
    #[test]
    fn modern_gool_follows_the_masque_carrier() {
        let plan = build_plan(&ConnectionProfile::default(), fp(false, false, false));
        let gool = plan.iter().find(|c| c.profile.protocol == Protocol::Gool).unwrap();
        assert!(gool.profile.masque_http2, "{}", gool.label);
    }

    #[test]
    fn an_explicit_http2_choice_is_never_undone() {
        let p = ConnectionProfile {
            masque_http2: true,
            ..Default::default()
        };
        for c in build_plan(&p, NetFingerprint::default()) {
            if c.profile.protocol == Protocol::Masque {
                assert!(c.profile.masque_http2);
            }
        }
    }

    #[test]
    fn direct_plan_has_a_hardened_second_pass() {
        let p = ConnectionProfile {
            protocol: Protocol::Gool,
            gool_mode: GoolMode::Modern,
            ..Default::default()
        };
        let plan = build_plan(&p, NetFingerprint::default());
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].profile.noize, Noize::Off);
        assert_eq!(plan[1].profile.noize, Noize::Firewall);
        assert_eq!(plan[0].profile.protocol, plan[1].profile.protocol);
    }

    /// Manual MASQUE (mobile 1.7.0 `directPlan`): as configured → HTTP/2 (TCP
    /// carrier) → anti-DPI with HTTP/2 + TLS fragmentation.
    #[test]
    fn manual_masque_walks_as_configured_then_h2_then_anti_dpi() {
        let p = ConnectionProfile {
            protocol: Protocol::Masque,
            ..Default::default()
        };
        let plan = build_plan(&p, fp(false, true, true));
        assert_eq!(plan.len(), 3, "{:?}", labels(&plan));
        assert!(!plan[0].profile.masque_http2);
        assert!(plan[0].timeout_ms <= 75_000);
        assert_eq!(plan[1].label, "MASQUE · h2 (TCP carrier)");
        assert!(plan[1].profile.masque_http2);
        assert!(plan[1].timeout_ms <= 45_000);
        let anti = &plan[2].profile;
        assert!(anti.masque_http2 && anti.fragment);
        assert_eq!(anti.noize, Noize::Firewall);
        assert!(!anti.ech);
        assert_eq!(plan[2].timeout_ms, p.connect_timeout_ms());
        // A user who already chose HTTP/2 gets no separate h2 pass.
        let q = ConnectionProfile {
            masque_http2: true,
            ..p.clone()
        };
        assert_eq!(build_plan(&q, fp(false, true, true)).len(), 2);
    }

    // >>> AETHER-APP-FIX ech-is-only-ever-the-users-choice (1.5.0)
    /// No plan, on any network, switches ECH on by itself; a user who turned it
    /// on keeps it on every rung.
    #[test]
    fn ech_is_never_switched_on_behind_the_users_back() {
        for (filtered, udp_ok) in [(false, true), (true, true), (false, false), (true, false)] {
            let f = fp(filtered, udp_ok, udp_ok);
            for protocol in [Protocol::Smart, Protocol::Masque, Protocol::Mim, Protocol::Gool] {
                let p = ConnectionProfile {
                    protocol,
                    ..Default::default()
                };
                assert!(!p.ech);
                for c in build_plan(&p, f) {
                    assert!(!c.profile.ech, "{:?}: {}", f.dpi_class(), c.label);
                }
                let on = ConnectionProfile { ech: true, ..p };
                for c in build_plan(&on, f) {
                    assert!(c.profile.ech, "{:?}: {}", f.dpi_class(), c.label);
                }
            }
        }
    }
    // <<< AETHER-APP-FIX ech-is-only-ever-the-users-choice (1.5.0)

    // >>> AETHER-APP-FIX plain-pass-goes-last-on-a-filtered-network
    /// A manual protocol on a filtered network: the anti-DPI pass leads and the
    /// plain pass keeps only a short budget at the end.
    #[test]
    fn on_a_filtered_network_the_plain_pass_only_gets_a_short_budget() {
        let p = ConnectionProfile {
            protocol: Protocol::Wireguard,
            ..Default::default()
        };
        let plan = build_plan(&p, fp(true, true, true));
        assert_eq!(plan.len(), 2, "{:?}", labels(&plan));
        assert_ne!(plan[0].profile.noize, Noize::Off);
        assert_eq!(plan[1].profile.noize, Noize::Off);
        assert!(plan[1].timeout_ms <= LAST_RESORT_MS);
    }

    #[test]
    fn on_a_healthy_network_the_plain_pass_still_leads() {
        let p = ConnectionProfile {
            protocol: Protocol::Wireguard,
            ..Default::default()
        };
        let plan = build_plan(&p, fp(false, true, true));
        assert_eq!(plan[0].profile.noize, Noize::Off);
        assert!(plan[0].timeout_ms > LAST_RESORT_MS);
    }
    // <<< AETHER-APP-FIX plain-pass-goes-last-on-a-filtered-network

    /// Per-network memory re-orders the ladder: the proven tactic opens it.
    #[test]
    fn memory_reorders_the_serial_ladder() {
        let e = crate::smart_plus::memory::Entry {
            tactic_id: Some("mim".into()),
            proven_at: 1_000,
            failed_at: Default::default(),
        };
        let plan = build_plan_with_memory(
            &ConnectionProfile::default(),
            NetFingerprint::default(),
            Some(&e),
            1_000,
        );
        assert_eq!(plan[0].tactic, Some("mim"));
    }

    /// The serial ladder holds every catalogue tactic once, then the two last resorts.
    #[test]
    fn the_ladder_is_the_whole_catalogue_plus_two_last_resorts() {
        for gool_mode in [GoolMode::Modern, GoolMode::Classic] {
            let p = ConnectionProfile {
                gool_mode,
                ..Default::default()
            };
            let plan = build_plan(&p, NetFingerprint::default());
            assert_eq!(plan.len(), 10, "{:?}", labels(&plan));
            assert_ne!(
                plan[0].profile.protocol == Protocol::Wireguard,
                plan[1].profile.protocol == Protocol::Wireguard,
                "the first two rungs come from the two families"
            );
            let mut ids: Vec<_> = plan[..8].iter().map(|c| c.tactic.unwrap()).collect();
            ids.sort();
            ids.dedup();
            assert_eq!(ids.len(), 8);
        }
    }
}
