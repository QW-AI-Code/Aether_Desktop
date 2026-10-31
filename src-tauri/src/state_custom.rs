//! ۱.۳.۰ — نشستِ «کانفیگِ سفارشی»: همان `connectCustom` نسخهٔ اندروید ۱.۵.۰،
//! روی ماشینِ حالتِ دسکتاپ.
//!
//! ```text
//! SOLO   xray (مستقیم)                                     → پل/پراکسیِ سیستم
//! FIRST  xray (مستقیم)  ← موتور/تور از دلِ xray dial می‌کند  → …            (Config → …)
//! LAST   خط لولهٔ موتور → xray با dialerProxy = خروجیِ آن    → پل/پراکسی   (… → Config)
//! ```
//!
//! # «خاموش» یعنی هیچ تغییری
//!
//! همهٔ قلاب‌های `state.rs` با `self.custom.is_none()` به رفتارِ قبلی برمی‌گردند:
//! وقتی کلیدِ کانفیگِ سفارشی خاموش است (پیش‌فرض) یا هیچ کانفیگی انتخاب نشده،
//! `custom_begin` چیزی نمی‌سازد، پروفایل دست نمی‌خورد و شش حالتِ موجود دقیقاً
//! مثل پیش اجرا می‌شوند.
//!
//! # پروفایل
//!
//! نشستِ سفارشی `backend` (و در FIRST پشتِ موتور، `upstream`) را **فقط در
//! حافظه** و فقط تا پایانِ نشست عوض می‌کند. `profile()` همیشه نسخهٔ کاربر را
//! برمی‌گرداند و `apply_profile` هم نسخهٔ کاربر را ذخیره می‌کند؛ پس تنظیماتِ
//! کاربر هرگز با زنجیرهٔ سفارشی بازنویسی نمی‌شود.

use super::*;
use crate::custom::process::{self as xproc, XrayProcess};
use crate::custom::{ChainBase, ChainPlacement, CustomSelection};
use crate::profile::TransportBackend;

const CTAG: &str = "custom";
/// بودجهٔ سنجشِ «این کانفیگ واقعاً بیرون می‌رود؟» پس از باز شدنِ پورت.
const REACH_BUDGET: Duration = Duration::from_secs(30);
const REACH_TARGETS: [(&str, u16); 2] = [("cp.cloudflare.com", 80), ("1.1.1.1", 80)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    /// هنوز Xray اجرا نشده (LAST پیش از بالا آمدنِ خروجیِ موتور).
    Idle,
    /// FIRST/SOLO: منتظرِ پورت و سنجشِ Xray، پیش از موتور.
    Front,
    /// LAST: Xray پشتِ خروجیِ موتور اجرا شده و منتظرِ پورتش هستیم.
    Back,
    /// Xray بالا و در مسیر است.
    Running,
}

pub(super) struct CustomRun {
    pub sel: CustomSelection,
    binary: PathBuf,
    port: u16,
    saved_backend: TransportBackend,
    saved_upstream: String,
    pub phase: Phase,
    since: Instant,
    resume: Prep,
    fingerprint: smart_auto::NetFingerprint,
    reach: Option<Arc<Mutex<Option<bool>>>>,
    dial_via: Option<u16>,
    xray: Option<XrayProcess>,
    restarts: u32,
    healthy_since: Option<Instant>,
    dead_checks: u32,
    next_monitor: Option<Instant>,
    trace_id: u64,
    trace_started: Instant,
    auto_next: Option<Instant>,
    auto_slot: Option<crate::custom::realdelay::ProbeTask> ,
    auto_basis: Option<crate::custom::store::State>,
}

impl CustomRun {
    fn base(&self) -> Option<ChainBase> {
        self.sel.mode.base()
    }
    fn placement(&self) -> ChainPlacement {
        self.sel.mode.placement()
    }
}

fn backend_of(base: ChainBase) -> TransportBackend {
    match base {
        ChainBase::Aether => TransportBackend::Aether,
        // `--psiphon-only` با پرچمِ موتور؛ ورودیِ آرگومان‌ها همان TorPsiphon است.
        ChainBase::Psiphon => TransportBackend::TorPsiphon,
        ChainBase::Tor => TransportBackend::Tor,
        ChainBase::AetherPsiphon => TransportBackend::AetherPsiphon,
        ChainBase::AetherTor => TransportBackend::AetherTor,
        ChainBase::TorPsiphon => TransportBackend::TorPsiphon,
        ChainBase::TorAether => TransportBackend::TorAether,
    }
}

/// پایه‌هایی که نخستین هاپشان خودِ موتور است (و نه tor.exe).
fn engine_front(base: ChainBase) -> bool {
    matches!(
        base,
        ChainBase::Aether | ChainBase::AetherPsiphon | ChainBase::AetherTor | ChainBase::Psiphon
    )
}

/// یک درخواستِ HTTP واقعی از دلِ پورتِ Xray. پذیرفتنِ CONNECT کافی نیست:
/// Xray پیش از dialِ سرور به SOCKS پاسخِ موفق می‌دهد.
fn reaches_out(port:u16)->bool {
    (0..2).any(|_|crate::custom::realdelay::request_through(port,"","","www.gstatic.com").is_ok())
}

fn transport_name(p: Option<Protocol>) -> Option<&'static str> {
    match p? {
        Protocol::Smart => None,
        Protocol::Masque => Some("MASQUE"),
        Protocol::Wireguard => Some("WireGuard"),
        Protocol::Gool => Some("Gool"),
        Protocol::Mim => Some("MIM"),
    }
}

/// Same bounded custom-upstream plan as mobile 1.6.0. No saved profile mutation.
pub(super) fn custom_upstream_plan(profile: &ConnectionProfile) -> Vec<Candidate> {
    use crate::profile::{ScanMode, EndpointMode, IpVersion};
    let mut full=profile.clone();full.endpoint_mode=EndpointMode::Auto;
    full.manual_peer.clear();full.manual_range.clear();full.ip_version=IpVersion::V4;
    // UDP carriers (WireGuard/Gool/MIM/QUIC) cannot traverse the custom config: always MASQUE over HTTP/2 (TCP).
    full.protocol=Protocol::Masque;
    full.masque_http2=true;
    let budget=full.connect_timeout_ms().max(180_000);
    let mut plan=Vec::new();
    if full.scan_mode!=ScanMode::Turbo {
        let mut fast=full.clone();fast.scan_mode=ScanMode::Turbo;
        plan.push(Candidate{profile:fast,timeout_ms:75_000,label:"Custom upstream TURBO".into()});
    }
    plan.push(Candidate{profile:full,timeout_ms:budget,label:"Custom upstream full budget".into()});plan
}

impl AetherController {
    pub(super) fn custom_upstream_engine(&self)->bool {
        // Windows: `Config → Aether`, `Config → Aether → Psiphon` and `Config → Aether → Tor`
        // all need the engine's first hop to ride TCP (MASQUE over HTTP/2) because UDP
        // (WireGuard/QUIC) cannot pass through the Xray SOCKS stage.
        self.custom.as_ref().map(|r|r.placement()==ChainPlacement::First && matches!(r.base(),Some(ChainBase::Aether|ChainBase::AetherPsiphon|ChainBase::AetherTor))).unwrap_or(false)
    }
    pub(super) fn custom_trace(&self,event:&str,reason:&str) {
        if let Some(r)=self.custom.as_ref() {
            DiagnosticsLog::i("ChainTrace",&format!("session={} elapsed_ms={} phase={:?} event={} local_socks=127.0.0.1:{} upstream={:?} reason={}",r.trace_id,r.trace_started.elapsed().as_millis(),r.phase,event,r.port,r.dial_via,crate::custom::process::redact(reason)));
        }
    }

    // ------------------------------------------------------------ profile

    /// پروفایلِ کاربر، بی هیچ جایگزینیِ نشستِ سفارشی.
    pub(super) fn custom_user_profile(&self) -> ConnectionProfile {
        let mut p = self.profile.clone();
        if let Some(run) = self.custom.as_ref() {
            p.backend = run.saved_backend;
            p.upstream = run.saved_upstream.clone();
        }
        p
    }

    /// پس از `apply_profile`: پروفایلِ تازهٔ کاربر را نگه می‌دارد و جایگزینیِ
    /// نشست را دوباره روی نسخهٔ در-حافظه می‌گذارد.
    pub(super) fn custom_reapply(&mut self) {
        let Some(run) = self.custom.as_mut() else {
            return;
        };
        run.saved_backend = self.profile.backend;
        run.saved_upstream = self.profile.upstream.clone();
        let (backend, upstream) = Self::override_for(run);
        self.profile.backend = backend;
        if let Some(u) = upstream {
            self.profile.upstream = u;
        }
    }

    fn override_for(run: &CustomRun) -> (TransportBackend, Option<String>) {
        match run.base() {
            // تنها: موتوری اجرا نمی‌شود؛ `Aether` فقط جای‌نگهدار است تا هیچ
            // شاخهٔ توری/زنجیره‌ای فعال نشود.
            None => (TransportBackend::Aether, None),
            Some(base) => {
                let upstream = (run.placement() == ChainPlacement::First && engine_front(base))
                    .then(|| format!("socks5://127.0.0.1:{}", run.port));
                (backend_of(base), upstream)
            }
        }
    }

    pub(super) fn custom_psiphon_base(&self) -> bool {
        self.custom
            .as_ref()
            .map(|r| r.base() == Some(ChainBase::Psiphon))
            .unwrap_or(false)
    }

    /// خروجیِ این نشست پورتِ سایفونِ ۱۸۱۹ است که موتور با `--psiphon-only` باز
    /// می‌کند (`Tor → Psiphon`، یا پایهٔ Psiphonِ کانفیگِ سفارشی).
    pub(super) fn psiphon_exit_session(&self) -> bool {
        self.profile.backend == TransportBackend::TorPsiphon
            && (self.native_tor.is_some() || self.custom_psiphon_base())
    }

    // ------------------------------------------------------------ lifecycle

    /// آغازِ نشست: اگر کانفیگِ سفارشی روشن است، نشست را آماده و پروفایلِ
    /// در-حافظه را جایگزین می‌کند. خاموش = هیچ کاری.
    pub(super) fn custom_begin(&mut self) -> Result<()> {
        self.custom_end();
        if self.profile.custom_auto_select {
            let snapshot=crate::custom::store::snapshot();
            if snapshot.enabled {if let Some(id)=crate::custom::selection::cached_choice(&snapshot){crate::custom::store::update(|s|s.select(&id));}}
        }
        let Some(sel) = crate::custom::store::selection() else {
            return Ok(());
        };
        let cfg = &sel.config;
        if cfg.is_expired(crate::custom::now_millis()) {
            return Err(anyhow::anyhow!("This custom config has expired. Import a fresh one or pick another config."));
        }
        if cfg.mobile_only {
            return Err(anyhow::anyhow!(
                "This custom config is locked to mobile data by its author, so it cannot run on Windows."
            ));
        }
        let install_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| self.data_dir.clone());
        let Some(binary) = xproc::locate(&install_dir, &self.data_dir) else {
            DiagnosticsLog::e(CTAG, "engine\\xray\\xray.exe is missing from this installation.");
            return Err(anyhow::anyhow!(
                "Custom configs need the bundled Xray core (engine\\xray\\xray.exe), which this installation is missing. Reinstall Aether."
            ));
        };
        let port = xproc::pick_port(&[]);
        let mode = sel.mode;
        DiagnosticsLog::i(
            CTAG,
            &format!(
                "Custom config: {} ({}) — chain {} — Xray on 127.0.0.1:{port}",
                cfg.protocol.short(),
                cfg.format.name(),
                mode.label(cfg.chain_label(), None)
            ),
        );
        let mut run = CustomRun {
            sel,
            binary,
            port,
            saved_backend: self.profile.backend,
            saved_upstream: self.profile.upstream.clone(),
            phase: Phase::Idle,
            since: Instant::now(),
            resume: Prep::Plan,
            fingerprint: smart_auto::NetFingerprint::default(),
            reach: None,
            dial_via: None,
            xray: None,
            restarts: 0,
            healthy_since: None,
            dead_checks: 0,
            next_monitor: None,
            trace_id: crate::custom::now_millis() as u64,
            trace_started: Instant::now(),
            auto_next: None,auto_slot:None,auto_basis:None,
        };
        // Xray که مستقیم بیرون می‌رود ممکن است سرورش روی پورتِ STUN یا IPv6
        // باشد؛ قاعدهٔ سیستم‌گسترده آن را هم می‌بست. همان باریک‌سازیِ تور.
        if run.placement() != ChainPlacement::Last {
            if let Some((host, sport)) = crate::custom::xray::server_endpoint(&run.sel.config.outbound) {
                let v6 = host.contains(':');
                let stun = u16::try_from(sport).map(leakguard::port_is_stun).unwrap_or(false);
                if v6 || stun {
                    leakguard::set_custom_egress(true);
                    DiagnosticsLog::w(
                        CTAG,
                        "The custom config's server is on IPv6 or a STUN/TURN port; the leak guard scopes those blocks to browsers so Xray itself can still reach it.",
                    );
                }
            }
        }
        // `Psiphon → Config`: psiphon-tunnel-core خودش مستقیم بیرون می‌رود (meek،
        // بروکرِ in-proxy با STUN و جبهه‌های IPv6). بلوک‌های سیستم‌گستردهٔ STUN
        // و 2000::/3 همان WSAEACCES (10013)ِ لاگ‌ها را روی آن می‌ساختند.
        if run.base() == Some(ChainBase::Psiphon) && run.placement() == ChainPlacement::Last {
            leakguard::set_custom_egress(true);
        }
        let (backend, upstream) = Self::override_for(&run);
        self.profile.backend = backend;
        if let Some(u) = upstream {
            self.profile.upstream = u;
        }
        run.phase = Phase::Idle;
        self.engine.set_chain_trace(Some(run.trace_id.to_string()));
        self.custom = Some(run);
        DiagnosticsLog::i(
            CTAG,
            "Wintun does not capture the default routes and Xray runs with no proxy variables, so neither Xray nor the engine can loop back into this tunnel.",
        );
        Ok(())
    }

    /// پایانِ نشست: پروفایل برمی‌گردد و Xray متوقف می‌شود.
    pub(super) fn custom_end(&mut self) {
        self.custom_trace("session_end","restore saved backend/upstream");
        if let Some(mut run) = self.custom.take() {
            if let Some(x) = run.xray.take() {
                x.stop();
            }
            self.profile.backend = run.saved_backend;
            self.profile.upstream = run.saved_upstream;
            // `Config → Psiphon` موتور را از دلِ پورتِ Xray فرستاده بود.
            self.engine.set_upstream_socks(None);
        }
        self.engine.set_chain_trace(None);
        leakguard::set_custom_egress(false);
        self.engine.set_psiphon_only(false);
        self.engine.set_custom_tcp_upstream(false);
    }

    /// بخشی از `cleanup_native`: Xrayِ این پله می‌رود، نشست می‌ماند.
    pub(super) fn custom_stop_xray(&mut self) {
        self.engine.set_psiphon_only(false);
        self.engine.set_custom_tcp_upstream(false);
        if self.custom.is_some() {
            // `Config → Psiphon` از دلِ پورتِ Xray می‌رفت؛ Xray که رفت، upstream هم.
            self.engine.set_upstream_socks(None);
        }
        if let Some(run) = self.custom.as_mut() {
            if let Some(x) = run.xray.take() {
                x.stop();
            }
            run.phase = Phase::Idle;
            run.reach = None;
            run.dead_checks = 0;
            run.healthy_since = None;
            run.next_monitor = None;
            run.auto_slot=None;run.auto_basis=None;run.auto_next=None;
        }
    }

    fn custom_spawn(&mut self, dial_via: Option<u16>) -> Result<(), String> {
        self.custom_trace("xray_spawn","starting local SOCKS stage");
        let Some(run) = self.custom.as_mut() else {
            return Err("no custom session".into());
        };
        if let Some(old) = run.xray.take() {
            old.stop();
        }
        // Mux فقط برای کانفیگی که پشتِ هاپِ کند (تور/سایفون) dial می‌شود: LAST
        // و پایه‌ای غیر از خودِ موتور. مستقیم (SOLO/FIRST) بی‌تغییر.
        let slow_hop = dial_via.is_some()
            && run.placement() == ChainPlacement::Last
            && !matches!(run.base(), None | Some(ChainBase::Aether));
        let mux = if slow_hop { crate::custom::xray::SLOW_CHAIN_MUX } else { 0 }; // Mux is always off on Windows
        if slow_hop && run.xray.is_none() && run.restarts == 0 {
            let vision = serde_json::from_str::<serde_json::Value>(&run.sel.config.outbound)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .map(|o| crate::custom::xray::has_xtls_flow(&o))
                .unwrap_or(false);
            DiagnosticsLog::i(
                CTAG,
                if vision {
                    "Behind a slow hop: chain timeouts (handshake 30s, idle 1800s); Mux stays off — XTLS Vision cannot be multiplexed."
                } else {
                    "Behind a slow hop: chain timeouts (handshake 30s, idle 1800s) Mux is off (BPB/Cloudflare endpoints do not support it)."
                },
            );
        }
        // `Config → Tor…`: tor.exe از دلِ این Xray بیرون می‌رود. ClientHelloِ
        // لینکِ تور شکسته می‌شود تا sniffingِ سمتِ سرور مقصد را با SNIِ ساختگی
        // عوض نکند — رجوع به `xray::TOR_LINK_FRAGMENT`.
        let tor_next = dial_via.is_none()
            && run.placement() == ChainPlacement::First
            && run.base().map(|b| !engine_front(b)).unwrap_or(false);
        let config = if tor_next {
            if run.xray.is_none() && run.restarts == 0 {
                DiagnosticsLog::i(
                    CTAG,
                    "tor.exe rides this config: its relay ClientHello is split across TLS records so the server's sniffer cannot swap the relay's address for Tor's made-up SNI.",
                );
            }
            crate::custom::xray::build_for_tor(&run.sel.config.outbound, run.port, &[], "warning")
        } else {
            crate::custom::xray::build_chain(&run.sel.config.outbound, run.port, dial_via, &[], "warning", mux)
        }
        .map_err(|e| format!("the custom config could not be turned into an Xray config: {e}"))?;
        let tag = format!("{}", run.port);
        let x = XrayProcess::start(&run.binary, &self.data_dir, &tag, run.port, &config)?;
        run.xray = Some(x);
        run.dial_via = dial_via;
        run.since = Instant::now();
        Ok(())
    }

    /// زمانِ اجرای پله: به‌جای `launch_plan`/`launch_candidate`.
    pub(super) fn custom_launch(&mut self, kind: Prep, fp: smart_auto::NetFingerprint) -> Result<()> {
        let Some(run) = self.custom.as_mut() else {
            return Ok(());
        };
        run.resume = kind;
        run.fingerprint = fp;
        let placement = run.placement();
        if placement == ChainPlacement::Last {
            return self.custom_resume();
        }
        self.custom_spawn(None).map_err(|e| anyhow::anyhow!(e))?;
        if let Some(run) = self.custom.as_mut() {
            run.phase = Phase::Front;
        }
        self.effective_protocol = None;
        self.deadline = Some(Instant::now() + xproc::XRAY_START_TIMEOUT + REACH_BUDGET);
        self.set_state(ConnectionState::Connecting, "Starting the custom config…");
        Ok(())
    }

    /// FIRST/LAST: موتور (یا تور، یا سایفون) را همان‌طور که این حالت همیشه
    /// اجرا می‌شد بالا می‌آورد.
    fn custom_resume(&mut self) -> Result<()> {
        self.custom_trace("resume_engine","Xray ready; starting downstream handshake");
        let Some(run) = self.custom.as_ref() else {
            return Ok(());
        };
        let (kind, fp) = (run.resume, run.fingerprint);
        if run.base() == Some(ChainBase::Psiphon) {
            return self.custom_start_psiphon();
        }
        match kind {
            Prep::Plan => self.launch_plan(fp),
            Prep::Candidate => self.launch_candidate(),
        }
    }

    /// `Config → Psiphon` / `Psiphon → Config`: موتور به‌عنوانِ سایفونِ خالص.
    fn custom_start_psiphon(&mut self) -> Result<()> {
        // پروفایلِ موتور: استیجِ زنجیره (بی LAN، بی قواعدِ مسیریابی) با آرگومان‌های
        // `TorPsiphon` که `psiphon_only` آن‌ها را به `--psiphon-only` بدل می‌کند.
        let mut stage = self.profile.chained_stage();
        stage.backend = TransportBackend::TorPsiphon;
        stage.exit_region = self.profile.exit_region.clone();
        // پروفایلِ مسیرِ داده: پروفایلِ کاربر، با backendی که هیچ قاعدهٔ توریِ
        // گاردِ نشتی را فعال نکند.
        let mut data = self.profile.clone();
        data.backend = TransportBackend::Aether;
        self.plan = vec![Candidate {
            profile: data,
            timeout_ms: CHAIN_BUDGET_MS,
            label: "Psiphon (custom chain)".into(),
        }];
        self.plan_index = 0;
        self.effective_protocol = None;
        // `Config → Psiphon`: psiphon-tunnel-core باید از دلِ SOCKSِ Xray بیرون
        // برود. `--upstream` این‌جا به آرگومان‌ها نمی‌رسد (`to_args_with_caps`
        // برای TorPsiphon پیش از بلوکِ upstream برمی‌گردد)، پس همان مسیرِ
        // `Tor → Psiphon` را می‌رویم: `AETHER_UPSTREAM=socks5://127.0.0.1:<xray>`
        // که هسته در `psiphon::run_only` با «psiphon dials out through the
        // upstream proxy» تأیید می‌کند. پیش از این `None` بود و لاگ «with no
        // tunnel underneath it» می‌گفت؛ سایفون مستقیم dial می‌کرد.
        let first_port = self
            .custom
            .as_ref()
            .filter(|r| r.placement() == ChainPlacement::First)
            .map(|r| r.port);
        self.engine.set_upstream_socks(first_port);
        if first_port.is_none() {
            // `Psiphon → Config`: سایفون خودش مستقیم بیرون می‌رود. قواعدِ
            // ماندهٔ یک نشستِ کشته‌شده (کلیدِ قطع، STUN، 2000::/3) همان
            // WSAEACCES (10013)ِ لاگ‌ها را روی psiphon-tunnel-core.exe می‌سازند.
            // این‌جا هیچ گاردی مالکِ قاعده‌ای نیست، پس هرچه مانده باقی‌مانده است.
            if self.guard.is_none() {
                leakguard::purge_stale();
            }
            leakguard::set_custom_egress(true);
            DiagnosticsLog::i(
                CTAG,
                "Psiphon dials out directly in this chain; the leak guard scopes its STUN/TURN and IPv6 blocks to browsers so psiphon-tunnel-core.exe (meek, in-proxy broker) is not refused with WSAEACCES.",
            );
        }
        crate::engine::reset_psiphon_access_hint();
        self.engine.set_psiphon_only(true);
        self.engine.start(&stage, Some(CHAIN_BUDGET_MS))?;
        self.psiphon_gate_since = Some(Instant::now());
        self.psiphon_next_probe = Some(Instant::now() + PSIPHON_PROBE_INTERVAL);
        self.psiphon_probe = None;
        self.deadline = Some(Instant::now() + Duration::from_millis(CHAIN_BUDGET_MS));
        self.set_state(ConnectionState::Connecting, "Starting Psiphon…");
        DiagnosticsLog::i(
            CTAG,
            &format!(
                "Psiphon: engine as plain Psiphon (--psiphon-only) on 127.0.0.1:{}{}",
                engine::LOCAL_SOCKS_PORT,
                match first_port {
                    Some(p) => format!(", dialling out through the custom config (AETHER_UPSTREAM=socks5://127.0.0.1:{p})"),
                    None => String::new(),
                }
            ),
        );
        Ok(())
    }

    fn custom_finish_solo(&mut self) {
        let Some(port) = self.custom.as_ref().map(|r| r.port) else {
            return;
        };
        self.plan.clear();
        self.plan_index = 0;
        engine::set_exit_socks_port(port);
        DiagnosticsLog::i(CTAG, &format!("Pipeline exit is the custom config on 127.0.0.1:{port}."));
        self.deadline = Some(Instant::now() + Duration::from_millis(OUTBOUND_GRACE_MS));
        if !self.bring_up_data_path() {
            return;
        }
        self.begin_verification();
    }

    /// LAST: خروجیِ موتور آماده است. به‌جای بالا آوردنِ مسیرِ داده، Xray را
    /// از دلِ آن اجرا می‌کند. `true` یعنی «مسیرِ داده بعداً، در `custom_poll`».
    pub(super) fn custom_hold_for_last(&mut self, exit: u16) -> bool {
        let Some(run) = self.custom.as_ref() else {
            return false;
        };
        if run.placement() != ChainPlacement::Last || run.phase != Phase::Idle {
            return false;
        }
        let exit_is_tor = run.base().map(ChainBase::exit_is_tor).unwrap_or(false);
        // tor.exe به CONNECTهای کند گاهی دیر پاسخ می‌دهد؛ همان رلهٔ صبوری که
        // `Tor → Aether` جلوی تور می‌گذارد، جلوی Xray هم می‌ایستد.
        let via = if exit_is_tor { self.patient_tor_dialer(exit) } else { exit };
        match self.custom_spawn(Some(via)) {
            Ok(()) => {
                if let Some(run) = self.custom.as_mut() {
                    run.phase = Phase::Back;
                }
                DiagnosticsLog::i(
                    CTAG,
                    &format!(
                        "The chain's exit is up on 127.0.0.1:{exit}; the custom config now dials out through it (via 127.0.0.1:{via})."
                    ),
                );
                self.set_state(ConnectionState::Connecting, "Starting the custom config…");
            }
            Err(e) => self.advance_or_fail(&e),
        }
        true
    }

    /// قدمِ Connecting برای فازهای Xray. `true` یعنی این تیک مصرف شد.
    pub(super) fn custom_poll(&mut self) -> bool {
        const NO_EXIT: &str = "The custom config opens no outbound connection. The server may be down or blocked on this network.";
        enum Next {
            Wait,
            Fail(&'static str),
            Advance(&'static str),
            StartReach(u16),
            FrontUp { port: u16, solo: bool },
            BackUp(u16),
        }
        let next = {
            let Some(run) = self.custom.as_mut() else {
                return false;
            };
            let phase = run.phase;
            if phase == Phase::Idle || phase == Phase::Running {
                return false;
            }
            let alive = run.xray.as_mut().map(|x| x.is_alive()).unwrap_or(false);
            let ready = alive && run.xray.as_mut().map(|x| x.ready()).unwrap_or(false);
            let elapsed = run.since.elapsed();
            if phase == Phase::Front {
                if !alive {
                    Next::Fail("The custom config could not start: Xray exited. Check the config, or open the diagnostics log.")
                } else if let Some(slot) = run.reach.clone() {
                    let verdict = slot.lock().take();
                    match verdict {
                        Some(true) => {
                            run.reach = None;
                            run.phase = Phase::Running;
                            run.healthy_since = Some(Instant::now());
                            Next::FrontUp { port: run.port, solo: run.base().is_none() }
                        }
                        Some(false) => Next::Fail(NO_EXIT),
                        None if elapsed > xproc::XRAY_START_TIMEOUT + REACH_BUDGET + Duration::from_secs(5) => {
                            Next::Fail(NO_EXIT)
                        }
                        None => Next::Wait,
                    }
                } else if ready && !self.profile.custom_verify_connection {
                    run.phase=Phase::Running;run.healthy_since=Some(Instant::now());
                    Next::FrontUp{port:run.port,solo:run.base().is_none()}
                } else if ready {
                    Next::StartReach(run.port)
                } else if elapsed > xproc::XRAY_START_TIMEOUT {
                    Next::Fail("The custom config did not open its local port in time (Xray). Check the config, or open the diagnostics log.")
                } else {
                    Next::Wait
                }
            } else if !alive {
                Next::Advance("Xray exited while starting behind the chain")
            } else if ready {
                run.phase = Phase::Running;
                run.healthy_since = Some(Instant::now());
                Next::BackUp(run.port)
            } else if elapsed > xproc::XRAY_START_TIMEOUT {
                Next::Advance("The custom config did not open its local port behind the chain in time")
            } else {
                Next::Wait
            }
        };
        match next {
            Next::Wait => {}
            Next::Fail(why) => self.fail(why),
            Next::Advance(why) => self.advance_or_fail(why),
            Next::StartReach(port) => {
                let slot: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
                if let Some(run) = self.custom.as_mut() {
                    run.reach = Some(slot.clone());
                }
                self.set_state(ConnectionState::Connecting, "Checking the custom config…");
                std::thread::Builder::new()
                    .name("aether-custom-reach".into())
                    .spawn(move || {
                        let ok = reaches_out(port);
                        *slot.lock() = Some(ok);
                    })
                    .ok();
            }
            Next::FrontUp { port, solo } => {
                DiagnosticsLog::i(
                    CTAG,
                    &format!("The custom config is up on 127.0.0.1:{port}; proceeding with the configured verification policy."),
                );
                if solo {
                    self.custom_finish_solo();
                } else {
                    DiagnosticsLog::i(CTAG, "The next hop now dials out through the custom config.");
                    if let Err(e) = self.custom_resume() {
                        let msg = e.to_string();
                        self.fail(&msg);
                    }
                }
            }
            Next::BackUp(port) => {
                engine::set_exit_socks_port(port);
                DiagnosticsLog::i(
                    CTAG,
                    &format!("Pipeline exit is the custom config on 127.0.0.1:{port} — bringing up the data path."),
                );
                if !self.bring_up_data_path() {
                    return true;
                }
                self.begin_verification();
            }
        }
        true
    }

    /// `Some(alive)` وقتی این نشست Xray دارد.
    pub(super) fn custom_xray_alive(&mut self) -> Option<bool> {
        let run = self.custom.as_mut()?;
        let x = run.xray.as_mut()?;
        Some(x.is_alive())
    }

    /// پایشِ Xray در حالتِ وصل. `true` یعنی این تیک مصرف شد.
    pub(super) fn custom_monitor(&mut self) -> bool {
        if self.custom_auto_monitor(){return true;}
        enum Next {
            Nothing,
            Restart(Option<u16>),
            Rebuild(u16),
        }
        let next = {
            let Some(run) = self.custom.as_mut() else {
                return false;
            };
            if run.phase != Phase::Running || run.xray.is_none() {
                return false;
            }
            let now = Instant::now();
            if run.next_monitor.map(|t| now < t).unwrap_or(false) {
                return false;
            }
            run.next_monitor = Some(now + xproc::MONITOR_INTERVAL);
            if run.healthy_since.map(|t| t.elapsed() >= xproc::HEALTHY_RESET).unwrap_or(false) {
                run.restarts = 0;
            }
            let alive = run.xray.as_mut().map(|x| x.is_alive()).unwrap_or(false);
            if !alive {
                if run.restarts >= xproc::MAX_RESTARTS {
                    DiagnosticsLog::e(CTAG, "Xray keeps exiting — rebuilding the whole session.");
                    // `carrier_alive` می‌بیند و مسیرِ اتصالِ دوباره را می‌رود.
                    Next::Nothing
                } else {
                    run.restarts += 1;
                    DiagnosticsLog::w(
                        CTAG,
                        &format!(
                            "Xray exited while connected — restarting it in place ({}/{}).",
                            run.restarts,
                            xproc::MAX_RESTARTS
                        ),
                    );
                    Next::Restart(run.dial_via)
                }
            } else if probe::socks_ready(run.port) {
                run.dead_checks = 0;
                Next::Nothing
            } else {
                run.dead_checks += 1;
                if run.dead_checks >= xproc::DEAD_PORT_CONFIRMATIONS {
                    Next::Rebuild(run.port)
                } else {
                    Next::Nothing
                }
            }
        };
        match next {
            Next::Nothing => false,
            Next::Restart(via) => {
                match self.custom_spawn(via) {
                    Ok(()) => {
                        if let Some(run) = self.custom.as_mut() {
                            run.phase = Phase::Running;
                            run.healthy_since = Some(Instant::now());
                            run.dead_checks = 0;
                        }
                    }
                    Err(e) => DiagnosticsLog::e(CTAG, &format!("Xray restart failed: {e}")),
                }
                true
            }
            Next::Rebuild(port) => {
                DiagnosticsLog::e(
                    CTAG,
                    &format!(
                        "Xray is running but 127.0.0.1:{port} stopped answering ({} checks) — reconnecting.",
                        xproc::DEAD_PORT_CONFIRMATIONS
                    ),
                );
                self.cleanup_native(true);
                self.connected_at = None;
                self.reconnect_at = Some(Instant::now() + Duration::from_secs(2));
                self.set_state(ConnectionState::Reconnecting, "Reconnecting…");
                true
            }
        }
    }

    /// Real-delay selection runs off the tick/UI thread. Dropping a run drops its result slot.
    fn custom_auto_monitor(&mut self)->bool {
        if !self.profile.custom_auto_select {return false;}
        let Some(run)=self.custom.as_mut() else{return false;};
        if run.phase!=Phase::Running{return false;}
        // ۱.۴.۰: در حالت‌های زنجیره‌ای (mode != SOLO) انتخابِ خودکار اجرا نمی‌شود.
        // سوییچِ خودکار زنجیره را از نو می‌ساخت (تور/سایفون/موتور ریست می‌شد) و
        // نشستِ جاافتاده از بین می‌رفت؛ ناظرِ سلامت (watchdog) همچنان فعال است.
        if run.sel.mode!=crate::custom::ChainMode::Solo {
            if run.auto_slot.take().is_some(){run.auto_basis=None;}
            run.auto_next=None;
            return false;
        }
        let result=run.auto_slot.as_mut().and_then(|task|task.poll());
        if let Some(rows)=result {
            run.auto_slot=None;
            let snapshot=crate::custom::store::snapshot();
            if run.auto_basis.take().as_ref()!=Some(&snapshot){run.auto_next=None;return false;}
            crate::custom::selection::record(&rows);
            if snapshot.active_id.as_deref()!=Some(&run.sel.config.id){return false;}
            if let Some(id)=crate::custom::selection::cached_choice(&snapshot){
                if id!=run.sel.config.id {
                    self.custom_trace("auto_select","fresh group candidate exceeds 50ms/20% hysteresis");
                    crate::custom::store::update(|s|s.select(&id));
                    self.cleanup_native(true);self.custom_end();self.connected_at=None;
                    self.reconnect_at=Some(Instant::now()+Duration::from_secs(1));
                    self.set_state(ConnectionState::Reconnecting,"Switching to the best healthy config…");return true;
                }
            }
        }
        let Some(run)=self.custom.as_mut()else{return false;};
        if run.auto_slot.is_some() || run.auto_next.map(|t|Instant::now()<t).unwrap_or(false){return false;}
        run.auto_next=Some(Instant::now()+Duration::from_secs(self.profile.custom_health_secs.clamp(30,3600)));
        let snapshot=crate::custom::store::snapshot();
        let targets=crate::custom::selection::group_configs(&snapshot).into_iter().map(|c|crate::custom::realdelay::Target{id:c.id,name:c.name,outbound:c.outbound}).collect::<Vec<_>>();
        run.auto_basis=Some(snapshot);let binary=run.binary.clone();let dir=self.data_dir.clone();run.auto_slot=Some(crate::custom::realdelay::ProbeTask::spawn(binary,dir,targets));false
    }

    // ------------------------------------------------------------ labels

    pub(super) fn custom_chain_label(&self) -> Option<String> {
        let run = self.custom.as_ref()?;
        Some(run.sel.mode.label(run.sel.config.chain_label(), None))
    }

    fn custom_transport(&self) -> Option<&'static str> {
        let run = self.custom.as_ref()?;
        if !run.base().map(ChainBase::uses_warp).unwrap_or(false) {
            return None;
        }
        // AETHER-APP-PATCH 1.4.0 smart-label: name the transport that actually won.
        transport_name(self.resolved_effective_protocol())
    }

    /// برچسبِ کارتِ اتصال برای نشستِ سفارشی.
    pub(super) fn custom_display(&self) -> Option<String> {
        let run = self.custom.as_ref()?;
        Some(run.sel.mode.label(run.sel.config.chain_label(), self.custom_transport()))
    }

    /// شکل‌های کوتاه‌تر برای ردیفِ باریک (اولی همان برچسبِ کامل).
    pub(super) fn custom_compact(&self) -> Vec<String> {
        let Some(run) = self.custom.as_ref() else {
            return Vec::new();
        };
        run.sel.mode.compact_labels(run.sel.config.chain_label(), self.custom_transport())
    }

    /// `true` وقتی tor.exe این نشست از دلِ کانفیگِ سفارشی بیرون می‌رود
    /// (`Config → Tor`، `Config → Tor → Aether`، `Config → Tor → Psiphon`).
    /// پل این‌جا هرگز به کار نمی‌آید (`custom_tor_front` آن را خاموش می‌کند).
    pub(super) fn custom_tor_behind_config(&self) -> bool {
        self.custom
            .as_ref()
            .map(|r| {
                r.placement() == ChainPlacement::First
                    && r.base().map(|b| !engine_front(b)).unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// FIRST پشتِ tor.exe: تور از دلِ Xray dial می‌کند و پل لازم نیست.
    pub(super) fn custom_tor_front(
        &self,
        bridges: crate::tor_native::BridgeMode,
    ) -> (Option<std::net::SocketAddr>, crate::tor_native::BridgeMode) {
        let Some(run) = self.custom.as_ref() else {
            return (None, bridges);
        };
        if run.placement() != ChainPlacement::First || run.xray.is_none() {
            return (None, bridges);
        }
        DiagnosticsLog::i(
            CTAG,
            &format!(
                "tor.exe dials out through the custom config on 127.0.0.1:{} (Socks5Proxy); bridges and pluggable transports are not used — the custom config already got us out.",
                run.port
            ),
        );
        (
            Some(([127, 0, 0, 1], run.port).into()),
            crate::tor_native::BridgeMode::None,
        )
    }
}

#[cfg(test)] mod port_policy_tests {
 use super::*;
 #[test]fn tcp_upstream_plan(){let p=ConnectionProfile::default();let plan=custom_upstream_plan(&p);assert_eq!(plan.len(),2);assert_eq!(plan[0].timeout_ms,75_000);assert_eq!(plan[0].profile.scan_mode,crate::profile::ScanMode::Turbo);assert!(plan[0].profile.masque_http2);assert!(plan[1].timeout_ms>=180_000);assert!(plan[0].profile.manual_range.is_empty());}
 #[test]fn already_turbo_one_pass(){let mut p=ConnectionProfile::default();p.scan_mode=crate::profile::ScanMode::Turbo;assert_eq!(custom_upstream_plan(&p).len(),1);}
}
