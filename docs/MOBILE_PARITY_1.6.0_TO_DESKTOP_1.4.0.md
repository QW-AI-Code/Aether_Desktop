# Portable feature parity review: mobile 1.6.0 → desktop 1.4.0

This is a subsystem review map, not a theorem of source-line equality. See the Persian technical report for code/test boundaries. The 133-file source inventory retains original mobile hashes.

| Mobile source area | Desktop equivalent | Disposition |
|---|---|---|
| SmartPlusPlan, SmartAuto, PortLease/PortProbe | smart_plus/{plan,scheduler,mod}.rs, smart_auto.rs, engine.rs | Implemented independent family lanes, timed/confirmed probes, serial intra-lane tactics, cancellation and fallback |
| SmartPlusMemory, NetworkIdentity, ProfileStore reset | smart_plus/{memory,network}.rs, state.rs | Per-network evidence, Windows physical default route, hashed NetworkGuid/gateway/DNS, TTL, bounded persistence and reset |
| UplinkGovernor, PsiphonSocksFront | uplink_policy.rs, uplink.rs, share.rs, ping.rs/probe.rs | Autorate/SFQ/sparse queueing; own warm TLS probe; no direct/download cap; owned lifecycle |
| ConfigCatalog/AutoSelectPolicy/ConfigPingStore | custom/store.rs, selection.rs, realdelay.rs, state*.rs | Persistent tabs, real-delay colours/sort, fresh initial batch and hysteresis/health; stale-basis rejection |
| ConfigParser/Importer/NpvsCodec/NpvtCodec | custom/{parser,import,npvs,npvt}.rs, custom_commands.rs, customconfigs.js | NPVS v5 + NPVT1, authenticated unlock/expiry/locked metadata, atomic subscription refresh, QR from image |
| CustomChainPolicy/Readiness, AetherVpnService chain trace | state_custom.rs, state.rs, engine.rs, native upstream.rs/masque_h2.rs | Two-pass custom TCP scan, stage readiness, owned exit status, session handshake and aggregate-transfer traces |
| NetProbe/PingMonitor/ConnectionCard | probe.rs, ping.rs, state.rs, connection-card.js/styles | IPv4 grace/IPv6 fallback, late generation-safe ISO country, globe, bounded responsive IP field; cold vs warm metrics not conflated |
| VerificationPolicy, diagnostics, tunnel health | profile.rs, state.rs, diagnostics.rs, advanced.js | Default-on initial verification for native/custom; readiness/leak/health protections survive opt-out |
| AI Gate/ModelPolicy/Redaction/HTTP client | ai_gate.rs, custom/ai_policy.rs, ai_model_policy.rs, ai_redaction.rs, ai_http.rs/ai_client.rs | Six model IDs/default preference reviewed; strict tunneled transport, matching custom-exit rules and actual active port; real policy/HTTP/redaction tests |
| TeamSignInHandoff/Record/Membership/ZeroTrustWeb | zt_signin.rs, zt_web.rs, engine.rs, SecretStore | Team/email isolation, expiry, enrollment-first ordering; DPAPI adaptation, no token in decision Debug; real handoff/web tests |
| Native Rust networking/core policy | native/aether + CORE_PORT_PATCHES.json | 17 reviewed overlay files, original baseline retained; full native host tests and both full MSVC checks |
| SmartLists/SmartRoutes, LAN guard/share/leak protection | smart_lists.rs, smart_routes.rs, share*.rs, leakguard.rs | Existing Windows route/DPAPI/firewall/guest separation retained; shaper excludes direct routes |
| Announcements/What's New/Settings/Config UI | src/news, src/views, src/ui, i18n.js/styles, news.rs | Windows-native presentation and persistent prefs suppression, compact forms/tabs, locally decoded QR images |
| TorTransport/TorBootstrap and platform storage | tor_native.rs, official pinned tor.exe, SecretStore/Windows APIs | Windows adaptation, not Android Arti/Keystore substitution |
| Android Intents, Activities, camera permission, VpnService, widgets/tiles, radio, phone hotspot | Windows shell/runtime alternatives where applicable | Android-only lifecycle and controls excluded. Image QR is portable and implemented. Device-attestation restrictions fail closed, not bypassed. |

No documented previous implementation gap is intentionally left for a future coding stage. Live Windows performance, interoperability, signing and installer/remote-CI acceptance still require release testing; this map does not certify them.
