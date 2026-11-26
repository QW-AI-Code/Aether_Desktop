# Aether Desktop 1.5.0 — release notes

<div dir="ltr" align="left">

Aether Core 2.4.0 remains the engine version. This release brings the connection changes of Aether Mobile **1.7.0** to Windows: a real engine readiness gate, a rewritten Smart mode (fair race, best route by measured quality), no automatic ECH, Gool in the MASQUE family, MASQUE over HTTP/2 in every ladder, a three-pass manual MASQUE plan, a QUIC reachability probe and security floors for the engine's Rust dependencies. Technical report: `docs/PORT_1.5.0_REPORT.fa.md`.

## Latest same-version update (1.5.0): Smart anti-DPI brain, Smart connection gate, chain diagram

The version is unchanged (1.5.0, engine core 2.4.0).

### Smart anti-DPI brain (`src-tauri/src/smart_plus/brain.rs`)
- **Listens:** `readiness::signals_of` tags every engine line: UDP silence, TLS reset, empty
  scan, blocked account API, damaged identity, missing ECH key.
- **Diagnoses** every failed race lane, ladder rung and last-resort attempt.
- **Learns:** `brain::Board` is shared by both race lanes. The serial ladder keeps its own
  knowledge, seeded from the network fingerprint.
- **Adapts:** `scheduler::run_adaptive` re-plans the tactics still to come, and
  `smart_auto::adapt_ladder` does the same for the serial ladder:
  - TCP carriers move ahead of UDP ones once UDP is dropped;
  - TLS fragmentation and the Firewall obfuscation floor are switched on once TLS is
    interfered with;
  - WireGuard gets the GFW disguise when its gateways stay silent;
  - hopeless UDP rungs are abandoned after 7 s;
  - equivalent tactics are never tried twice.
- **Heals** a damaged engine identity (`AetherProcess::heal_damaged_identity`, the damaged
  copy is removed) and retries the same strategy.
- Fixes in this revision:
  - an attempt the brain abandoned itself is not counted as new evidence;
  - a "provisioning a fresh identity" (recovery) line is not read as a damaged identity.

### Smart connection gate: "Verify connection" removed everywhere
- The connection page and the **Custom configs** page no longer have a verification switch.
  Both show the "Smart connection gate" information card (`src/ui/smartgate.js`).
- `verify_connection` / `custom_verify_connection` were removed from the profile. Old
  `profile.json` files still load.
- The state `VERIFYING` is now `PROVING`; it still reads old `VERIFYING` values. The status
  reads "Smart gate: waiting for real data…".
- Every session, including custom configs, is proven by a real HTTP request through the
  tunnel whose answer comes back. The custom front is always proven before anything is
  chained to it. The WebRTC leak check is unchanged and still fail-closed.

### Other changes
- **Auto-select lowest delay** for custom configs is now **on by default** (new installs; a choice you already saved is kept).
- In Persian, every AI error and every backend error message (presets, custom configs, chains) is translated; raw Google text is mapped to the matching Persian sentence (`tAiError`) instead of being shown in English.
- **Slow "Aether only" connects - root cause fixed:** the Smart race lane that proved a route was
  killed (TerminateProcess) and the confirming session started 0.3 s later on the *same* WARP device
  identity; Cloudflare still held the lane's session, so the confirm got `connect-ip status 400` or carried
  no return traffic, failed its gate after 45 s and fell through to a full rescan. Race lanes now run on
  their own identity (`aether-race*.toml`) and the session starts from the gateway the race proved
  (`adopt_race_gateways`). Quality window 2.5 s and route measurement 4.5 s, as on mobile.
- The speed-test button of a custom config uses the same speedometer icon as the mobile app.
- **Chained stage 1 is proven by real data too:** before stage 2 (e.g. Psiphon behind Aether) starts, stage 1 must carry a real HTTP answer (smart gate, `probe::data_via_proxy_on`; TLS answer for port 443), not only accept a CONNECT. The Tor bootstrap stall detection still ends the wait early.
- The core overlay (`config.rs`, `CORE_PORT_PATCHES.json`) quarantines a non-UTF-8 identity
  and provisions a fresh one instead of exiting.
- The 3-node chain diagram fits the default 390 px window (`src/ui/fit.js`).
- What's new revision `r3`.

### Security audit (0-100) - this release

| # | Area | Weight | Score | Findings |
|---|------|:-----:|:-----:|----------|
| 1 | Secrets at rest | 15 | 12 | Secrets, custom configs and Zero Trust tokens sealed with DPAPI. The engine identity (WARP key) stays plaintext in the app folder, as upstream does; damaged copies are removed. |
| 2 | Secrets on the command line | 10 | 10 | Credentials and upstream URLs only in the engine environment. |
| 3 | Leak protection | 15 | 14 | Leak guard and WebRTC/STUN check fail closed. The firewall kill switch needs administrator rights (browser-policy layer otherwise). |
| 4 | Connection-gate integrity | 10 | 9 | Real HTTP response bytes required; bounded timeouts; no user data in probes. Plain-HTTP probe targets are public endpoints (low residual risk). |
| 5 | Smart brain and memory privacy | 5 | 5 | Pure logic; memory holds hashed network keys and tactic ids only. |
| 6 | TLS validation | 10 | 8 | Verified TLS for AI and geo lookups. MASQUE certificate pinning is opt-in. |
| 7 | Dependencies and supply chain | 15 | 11 | Core pinned to upstream 2.4.0 plus a hash-locked reviewed overlay; engine dependency floors; `npm ci` with a lockfile. No `cargo audit` gate for the app crate yet. |
| 8 | Build integrity and signing | 10 | 6 | Release-tree cleanup, core pristine guard and workflow-order guards. Windows binaries are not Authenticode-signed (SmartScreen warning possible). |
| 9 | Logging and diagnostics | 5 | 5 | Exit IPs masked in the persistent log; diagnostics report redacted. |
| 10 | Input validation | 5 | 5 | Profile, DNS, route and TLS options sanitised; Proxy Mode excluded on Windows. |
| | **Total** | **100** | **85** | **Good.** Residual risks: unsigned Windows binaries, no app-crate `cargo audit`, plaintext engine identity in the app folder. |


App version **1.5.0**, engine core **2.4.0**, ported from Aether Mobile **1.7.0**. This release is about one
thing: **connecting reliably, first time, without touching a setting** - especially in Tehran, where only
MASQUE gets through.

**Root cause of the connection failures (fixed)**

- **The engine was killed while it was still working.** The engine binds its local SOCKS5 port the moment it
  starts and only *serves* it once a tunnel is validated. The app took the open port (≈0.3 s after launch) for a
  ready engine and gave every attempt a single 4-second SOCKS5 handshake. Verifying a cached MASQUE gateway alone
  takes 2-3.5 s on Iranian links, a fresh scan much longer - so MASQUE failed "sometimes" and every scan failed always.
- **New readiness gate:** the app now waits - for the attempt's whole budget - until the engine itself reports that
  it serves SOCKS5 and a real handshake succeeds, and stops waiting the instant the engine exits. This applies to
  manual protocols, Smart mode, chained stage 1 and engine restarts by the watchdog.

**Smart mode, rewritten: a fair race and the best route, not the first one**

- **Fair start:** WARP (WireGuard) and MASQUE start **at the same instant** with the **same per-tactic budgets**
  (light 20 s, hardened 25 s, two-hop 40 s). Before, WireGuard started first, MASQUE 7 s later, after a serial 45 s
  remembered-route slot.
- **Light to heavy:** bare WireGuard and MASQUE over HTTP/3 or HTTP/2 first; Noize obfuscation, TLS-fragmented
  HTTP/2, then the two-hop Gool and MASQUE×2 only when needed.
- **Best route wins:** after the first route proves it carries traffic, the race runs 3.5 s longer so the other
  lane can prove one too. Every proven route is measured through itself - latency, ≈384 KB download and 128 KB
  upload over verified TLS - and ranked with an overhead factor per protocol. If the best one does not come up, the
  next proven route is tried.
- **HTTP/2 first where it matters:** MASQUE over HTTP/2 (TCP) leads on UDP-throttled networks and when a new QUIC
  probe (a Version-Negotiation packet to the MASQUE gateways) gets no answer.
- **Per-network memory** only re-orders a lane; failures are recorded per network. **Last resort** (deep
  full-range scan of the two cleanest carriers) only when nothing proved itself.

**Other fixes**

- **ECH crash:** anti-DPI passes no longer switch ECH on by themselves (without a fetchable ECH key the engine
  refuses to start). ECH is only ever your own choice.
- **Identity clash:** core 2.4.0's Gool (WireGuard inside MASQUE) now races in the MASQUE lane.
- **Wrong scan ranges:** MASQUE and Gool scans are no longer narrowed to the ranges measured for WireGuard.
- **Missing carrier:** MASQUE over HTTP/2 is part of every ladder now.
- **Manual MASQUE:** as configured → MASQUE over HTTP/2 (TCP) → anti-DPI pass (HTTP/2 + TLS fragmentation + obfuscation).
- **Engine dependencies:** security floors quinn-proto 0.11.19, quinn-udp 0.5.16, url 2.5.9, cookie 0.18.3.
- **What's new dialog** shows the 1.5.0 list and keeps the *"If you cannot connect at all"* steps.

## Same-version fixes in 1.5.0 (user reports)

- **NapsternetV configs that ping and connect on Android did nothing on Windows.** Three differences from
  Android were found and removed:
  - *DNS:* Android gives Xray the network's own resolvers first; Windows always passed an empty list, so a
    server given by NAME was resolved only by plain DNS to 1.1.1.1 / 8.8.8.8, which Iranian networks often drop
    or delay until the ping round and the handshake time out. New `custom/netdns.rs` reads the IPv4 DNS servers
    of the active adapters (`GetAdaptersAddresses`, Aether's own Wintun adapter and loopback skipped); the
    real-delay test, the speed test and the session use network → 1.1.1.1 → 8.8.8.8 → system, exactly like Android.
  - *TLS "allow insecure":* NapsternetV keeps it in `tlsAllowInsecure`; Windows read only the legacy `insecure`
    flag, so self-signed servers failed certificate verification inside Xray. Same order as Android now.
  - *Transport fields:* `xhttpMode`, `xhttpExtra`, `seed` (mKCP) and `authority` (gRPC) of a `.npvt`/`.npvs`
    server are read like on Android, so the rebuilt outbound is the same one Android runs.
  - The real-delay budget is 12 s per round, like Android (was 8 s).
- **Opening a config file with Aether.** Right-click → *Open with* → Aether (or a double-click) only opened the
  app. The program now reads the file it was started with - also when Aether is already running (single
  instance) - and imports it through the normal import path (password prompt, locks, size limit). The installer
  registers `.npvt` and `.npvs` (default handler and *Open with* entry) and removes the registration on
  uninstall. The portable ZIP has no registration; *Open with* → *Choose another app* → `Aether.exe` works there.
- **Auto-select:** "Test all" switches a live session to the fastest server at once; a network change
  (Wi-Fi, Ethernet, hotspot) measures again and re-selects; the first full test after a connect is
  applied with the eager 20 ms / 10 % threshold. The first connect itself never waits for a full test.
- **Configs:** one-click ping, speed test and delete on every server; "Speed test all"; sort by ping,
  download speed or upload speed.
- **Connection card:** click the latency row (last / min / max / average / jitter / packet loss, 10-probe
  burst), the protocol row (every node of the chain and its role) or the traffic row (session totals and
  the programs connected to Aether's local proxy right now).
- **Settings → Connection:** unified chain builder - number of nodes, the core of each node (Aether,
  Psiphon, Tor or a config) and each node's settings; only chains the app can run are offered.
- **Send diagnostics:** a redacted report (no IPs, host names, UUIDs or keys) is copied and a GitHub
  issue page opens; offered after a failed connection; switch in Settings → Display and sound.
- **Chain builder fixes:** changing the number of nodes or a node no longer adds a config node by itself; a
  config chain chosen before any config exists stays on screen and switches on when one is selected; 3-node
  chains explain why they always include a config. Node text uses the full width (controls below it) and
  the chain diagram stays on one line, shrinking its font to fit.
- **Smart text:** the ping / status chip of every config shows the whole text and shrinks instead of being
  cut; the one-click actions moved to their own row.
- The explicit `Tor → Psiphon` connection label and the official Tor process are unchanged.
- The What's new dialog lists both fixes. Version numbers are unchanged (1.5.0).

## Security notes (1.5.0)

- **No new permission, capability or listener.** The file association adds registry keys under `HKLM\Software\Classes` only (removed on uninstall); an opened file goes through the same size-limited, password-aware importer as drag & drop. Smart lanes still lease two random loopback ports exactly as before; nothing listens beyond `127.0.0.1`.
- **Quality measurement only runs through the tunnel being measured:** a `HEAD` to `1.1.1.1:80` (an IP literal, no DNS) and HTTPS to `speed.cloudflare.com` with full certificate and host-name verification (`native-tls`/SChannel); about 384 KB down and 128 KB of zeros up per proven route. Nothing is sent on the direct path.
- **The QUIC probe** is one 1200-byte random packet with a reserved version (`0x1a2a3a4a`), carrying no identity and no server name, to two Cloudflare MASQUE gateways (`162.159.198.1/.2:443`); only a Version-Negotiation answer counts.
- **ECH is never changed behind the user's back:** every plan keeps the user's own ECH setting.
- **Engine dependencies:** quinn-proto 0.11.19, quinn-udp 0.5.16, url 2.5.9 and cookie 0.18.3 are applied to the locked core in CI (`scripts/patch-engine-dependencies.py`, before `build-engine.ps1 --locked`). libsqlite3-sys 0.37.0 (RUSTSEC-2026-0459) stays: 0.39 needs rusqlite 0.41, which tor-dirmgr 0.46 does not accept; SQLite only opens Tor's directory cache inside the app's private data folder.

## Validation of 1.5.0 (honest)

Offline only: the repository's Python guards, `node --check`/syntax tests and the non-browser Node tests were run. `cargo`/`rustc` and `jsdom` were not available where this port was made, so the Rust code (including the new unit tests) and the jsdom UI tests were **not compiled or run** here; CI (`cargo test`, `npm test`) is the first real compile. No live connection was tested.

The same-version fixes were checked the same way (Python guards incl. `check-rust-parses.py`, `node tests/js-syntax.mjs` and the non-jsdom Node tests); new Rust unit tests: `netdns::tests`, `openfile::tests`, `pingstats::tests`, `apps::tests`, `diagreport::tests`, `selection::tests::eager_threshold_and_manual_flag`, plus `tests/chainbuilder150.mjs`, `xray::tests::direct_dns_puts_the_network_first_like_android`, `parser::tests::npvt_tls_allow_insecure_and_xhttp_fields_match_android`. They are compiled for the first time by CI.

</div>

<div dir="rtl" align="right">

## تازه‌ترین به‌روزرسانی هم‌نسخه (<bdi>1.5.0</bdi>): مغز هوشمند ضد <bdi>DPI</bdi>، دروازهٔ هوشمند اتصال و نمودار زنجیره

نسخه تغییر نکرده است (<bdi>1.5.0</bdi>، هستهٔ <bdi>2.4.0</bdi>).

### مغز هوشمند ضد <bdi>DPI</bdi> (<bdi>smart_plus/brain.rs</bdi>)
- **گوش می‌دهد:** هر خط لاگ هسته از نظر وضعیت شبکه برچسب می‌خورد: سکوت <bdi>UDP</bdi>، قطع <bdi>TLS</bdi>، اسکن خالی، مسدود بودن سرور ثبت‌نام، هویت خراب و نبودن کلید <bdi>ECH</bdi>.
- **تشخیص می‌دهد:** علت شکست هر مسیر مسابقه، هر پلهٔ نردبان و هر تلاش آخر را مشخص می‌کند.
- **یاد می‌گیرد:** دو مسیر مسابقه یک تختهٔ مشترک دارند. نردبان سریالی دانش خودش را دارد که از اثرانگشت شبکه شروع می‌شود.
- **تطبیق می‌دهد:** روش‌های باقی‌مانده همان لحظه دوباره چیده می‌شوند:
  - پروتکل‌های <bdi>TCP</bdi> جلوتر از <bdi>UDP</bdi> می‌آیند؛
  - تکه‌تکه‌سازی <bdi>TLS</bdi> و مبهم‌سازی سطح <bdi>Firewall</bdi> روشن می‌شود؛
  - اگر دروازه‌ها جواب ندهند، وایرگارد مبهم‌سازی <bdi>GFW</bdi> می‌گیرد؛
  - روش‌های <bdi>UDP</bdi> بی‌فایده بعد از ۷ ثانیه رها می‌شوند؛
  - روش‌های معادل دوبار تست نمی‌شوند.
- **ترمیم می‌کند:** هویت خراب هسته حذف و همان روش دوباره امتحان می‌شود.
- اصلاحات این بازنگری:
  - تلاشی که خود مغز رها کرده، شاهد تازه حساب نمی‌شود؛
  - خط بازیابی هویت، هویت خراب خوانده نمی‌شود.

### دروازهٔ هوشمند اتصال: «راستی‌آزمایی اتصال» از همه‌جا حذف شد
- صفحهٔ اتصال و صفحهٔ **کانفیگ‌های سفارشی** دیگر کلید راستی‌آزمایی ندارند و هر دو کارت توضیحی «دروازهٔ هوشمند اتصال» را نشان می‌دهند.
- فیلدهای <bdi>verify_connection</bdi> و <bdi>custom_verify_connection</bdi> از پروفایل حذف شدند. فایل‌های قدیمی <bdi>profile.json</bdi> بی‌مشکل باز می‌شوند.
- حالت <bdi>VERIFYING</bdi> به <bdi>PROVING</bdi> تغییر کرد. متن وضعیت حالا «دروازهٔ هوشمند: در انتظار عبور دادهٔ واقعی…» است.
- هر نشست، از جمله کانفیگ‌های سفارشی، با یک درخواست <bdi>HTTP</bdi> واقعی که پاسخش از تونل برگردد اثبات می‌شود. سنجش نشتی <bdi>WebRTC</bdi> مثل قبل سر جایش است.

- **مرحلهٔ اول زنجیره هم با عبور دادهٔ واقعی اثبات می‌شود:** پیش از شروع مرحلهٔ دوم (مثلاً <bdi>Psiphon</bdi> پشت <bdi>Aether</bdi>)، مرحلهٔ اول باید یک پاسخ <bdi>HTTP</bdi> واقعی را عبور دهد (دروازهٔ هوشمند)، نه فقط اتصال را بپذیرد. تشخیص گیرکردن <bdi>Tor</bdi> همچنان انتظار را زود تمام می‌کند.

- **رفع ریشه‌ای کندی اتصال در حالت «فقط Aether»:** مسیر برندهٔ مسابقه بسته می‌شد و نشست اصلی ۰٫۳ ثانیه بعد با *همان* هویت دستگاه <bdi>WARP</bdi> وصل می‌شد؛ کلادفلر هنوز نشست قبلی را نگه داشته بود، پس اتصال اصلی خطای <bdi>connect-ip 400</bdi> می‌گرفت یا داده برنمی‌گشت و بعد از ۴۵ ثانیه شکست می‌خورد و اسکن کامل شروع می‌شد. حالا مسیرهای مسابقه هویت جداگانهٔ خودشان را دارند و نشست اصلی از همان دروازه‌ای شروع می‌کند که مسابقه اثبات کرده است. پنجرهٔ مقایسه ۲٫۵ و سنجش هر مسیر ۴٫۵ ثانیه، مثل موبایل.
- آیکون دکمهٔ تست سرعت کانفیگ‌ها همان آیکون سرعت‌سنج نسخهٔ موبایل شد.

- کلید **انتخاب خودکار کمترین پینگ** در کانفیگ‌های سفارشی حالا **به‌طور پیش‌فرض روشن** است (برای نصب تازه؛ انتخابی که قبلاً ذخیره کرده‌اید حفظ می‌شود).
- در زبان فارسی، همهٔ خطاهای دستیار هوش مصنوعی و پیام‌های خطای بخش‌های دیگر (پروفایل‌ها، کانفیگ‌های سفارشی، زنجیره‌ها) ترجمه شدند؛ متن خام انگلیسی گوگل به جملهٔ فارسی مناسب تبدیل می‌شود.

### ممیزی امنیتی (۰ تا ۱۰۰) - همین انتشار

| # | حوزه | وزن | امتیاز | یافته‌ها |
|---|------|:---:|:-----:|----------|
| ۱ | رازها روی دیسک | ۱۵ | ۱۲ | رازها، کانفیگ‌های سفارشی و توکن‌های <bdi>Zero Trust</bdi> با <bdi>DPAPI</bdi> مهر و موم می‌شوند. هویت هسته (کلید <bdi>WARP</bdi>) مثل نسخهٔ اصلی هسته به‌صورت متن ساده در پوشهٔ برنامه می‌ماند؛ نسخه‌های خراب حذف می‌شوند. |
| ۲ | رازها در خط فرمان | ۱۰ | ۱۰ | اطلاعات ورود و نشانی پروکسی بالادستی فقط از راه محیط اجرای هسته فرستاده می‌شوند. |
| ۳ | جلوگیری از نشت | ۱۵ | ۱۴ | محافظ نشت و سنجش <bdi>WebRTC</bdi>/<bdi>STUN</bdi> در صورت شکست اتصال را می‌بندند. <bdi>Kill switch</bdi> فایروال به دسترسی مدیر نیاز دارد. |
| ۴ | درستی دروازهٔ اتصال | ۱۰ | ۹ | بایت‌های پاسخ واقعی لازم است، مهلت‌ها محدودند و کاوش‌ها دادهٔ کاربری ندارند. مقصدهای <bdi>HTTP</bdi> عمومی‌اند (ریسک باقی‌ماندهٔ کم). |
| ۵ | حریم خصوصی مغز و حافظه | ۵ | ۵ | منطق خالص؛ فقط کلید درهم‌شدهٔ شبکه و شناسهٔ روش ذخیره می‌شود. |
| ۶ | اعتبارسنجی <bdi>TLS</bdi> | ۱۰ | ۸ | <bdi>TLS</bdi> تأییدشده برای دستیار و موقعیت‌یابی؛ پین گواهی <bdi>MASQUE</bdi> اختیاری است. |
| ۷ | وابستگی‌ها و زنجیرهٔ تأمین | ۱۵ | ۱۱ | هسته روی <bdi>2.4.0</bdi> نسخهٔ اصلی است و فقط تغییرات بازبینی‌شده با هش قفل‌شده دارد؛ کف امنیتی وابستگی‌های هسته و <bdi>npm ci</bdi> با فایل قفل. دروازهٔ <bdi>cargo audit</bdi> برای کد خود برنامه هنوز وجود ندارد. |
| ۸ | درستی بیلد و امضا | ۱۰ | ۶ | پاک‌سازی درخت انتشار، محافظ دست‌نخوردگی هسته و محافظ ترتیب گردش‌کار وجود دارد. فایل‌های ویندوز امضای <bdi>Authenticode</bdi> ندارند (ممکن است هشدار <bdi>SmartScreen</bdi> نمایش داده شود). |
| ۹ | لاگ و عیب‌یابی | ۵ | ۵ | <bdi>IP</bdi> خروجی در لاگ دائمی پوشانده می‌شود و گزارش عیب‌یابی پاک‌سازی‌شده است. |
| ۱۰ | اعتبارسنجی ورودی | ۵ | ۵ | پروفایل، <bdi>DNS</bdi>، قواعد و گزینه‌های <bdi>TLS</bdi> پاک‌سازی می‌شوند؛ حالت پروکسی در ویندوز وجود ندارد. |
| | **جمع** | **۱۰۰** | **۸۵** | **خوب.** ریسک‌های باقی‌مانده: نبودن امضای <bdi>Authenticode</bdi>، نبودن <bdi>cargo audit</bdi> برای کد برنامه و متن ساده بودن هویت هسته در پوشهٔ برنامه. |

<h2 dir="rtl" align="right">تازه‌های نسخهٔ ویندوز ۱.۵.۰</h2>

<p dir="rtl" align="right">نسخهٔ برنامه <strong><span dir="ltr">1.5.0</span></strong> و هستهٔ موتور <strong><span dir="ltr">2.4.0</span></strong> است و تغییرات <span dir="ltr">Aether</span> موبایل <strong><span dir="ltr">1.7.0</span></strong> را می‌آورد. هدف این نسخه یک چیز است:</p>
<p dir="rtl" align="right"><strong>اتصال مطمئن از همان بار اول، بدون دست‌زدن به تنظیمات</strong>؛ به‌ویژه در تهران که فقط <span dir="ltr">MASQUE</span> جواب می‌دهد.</p>
<h3 dir="rtl" align="right">ریشهٔ «کانکشن فیل» شدن‌ها (رفع شد)</h3>
<ul dir="rtl">
<li><strong>هسته وسط کارش بسته می‌شد.</strong> موتور پورت <span dir="ltr">SOCKS5</span> محلی را همان لحظهٔ اجرا رزرو می‌کند، اما فقط وقتی تونل تأیید شد به آن پاسخ می‌دهد. برنامه باز بودن پورت (حدود ۰٫۳ ثانیه پس از اجرا) را به معنی آماده بودن موتور می‌گرفت و به هر تلاش فقط یک دست‌دهی ۴ ثانیه‌ای می‌داد. فقط بررسی دروازهٔ ذخیره‌شدهٔ <span dir="ltr">MASQUE</span> روی اینترنت ایران ۲ تا ۳٫۵ ثانیه طول می‌کشد و اسکن تازه خیلی بیشتر؛ برای همین <span dir="ltr">MASQUE</span> «گاهی» وصل می‌شد و هر اسکنی همیشه شکست می‌خورد.</li>
<li><strong>دروازهٔ آمادگی جدید:</strong> برنامه حالا در کل زمان هر تلاش صبر می‌کند تا خود موتور اعلام کند که <span dir="ltr">SOCKS5</span> را سرویس می‌دهد و یک دست‌دهی واقعی موفق شود، و اگر موتور بسته شود همان لحظه دست می‌کشد. این اصلاح برای پروتکل دستی، حالت هوشمند، مرحلهٔ اول زنجیره‌ها و راه‌اندازی دوبارهٔ موتور اعمال شده است.</li>
</ul>
<h3 dir="rtl" align="right">حالت هوشمند از نو نوشته شد: مسابقهٔ منصفانه و انتخاب بهترین مسیر، نه اولین مسیر</h3>
<ul dir="rtl">
<li><strong>شروع منصفانه:</strong> <span dir="ltr">WARP</span> (وایرگارد) و <span dir="ltr">MASQUE</span> <strong>در یک لحظه</strong> و با <strong>بودجهٔ زمانی یکسان برای هر روش</strong> شروع می‌شوند (سبک ۲۰، تقویت‌شده ۲۵ و دوهاپی ۴۰ ثانیه). پیش‌تر وایرگارد اول شروع می‌شد و <span dir="ltr">MASQUE</span> هفت ثانیه بعد، آن هم پس از نوبت جداگانهٔ ۴۵ ثانیه‌ای.</li>
<li><strong>از سبک به سنگین:</strong> اول وایرگارد ساده و <span dir="ltr">MASQUE</span> روی <span dir="ltr">HTTP/3</span> یا <span dir="ltr">HTTP/2</span>؛ مبهم‌سازی <span dir="ltr">Noize</span>، <span dir="ltr">HTTP/2</span> با تکه‌تکه‌سازی <span dir="ltr">TLS</span> و در آخر <span dir="ltr">Gool</span> و <span dir="ltr">MASQUE×2</span> دوهاپی فقط در صورت نیاز.</li>
<li><strong>بهترین مسیر برنده است:</strong> پس از اولین اثبات، مسابقه ۳٫۵ ثانیه ادامه می‌یابد؛ سپس هر مسیر سالم از درون خودش سنجیده می‌شود (پینگ، دانلود حدود ۳۸۴ کیلوبایت، آپلود ۱۲۸ کیلوبایت روی <span dir="ltr">TLS</span> تأییدشده) و با ضریب سربار هر پروتکل رتبه می‌گیرد. اگر بهترین مسیر بالا نیاید، مسیر سالم بعدی امتحان می‌شود.</li>
<li><strong>اولویت <span dir="ltr">HTTP/2</span> در جای درست:</strong> در شبکه‌های با محدودیت <span dir="ltr">UDP</span> و وقتی پراب جدید <span dir="ltr">QUIC</span> جوابی نگیرد، <span dir="ltr">MASQUE</span> روی <span dir="ltr">HTTP/2</span> (بستر <span dir="ltr">TCP</span>) اول امتحان می‌شود.</li>
<li><strong>حافظهٔ هر شبکه</strong> فقط ترتیب را عوض می‌کند؛ <strong>آخرین تلاش</strong> (اسکن عمیق) فقط وقتی هیچ مسیری جواب نداد.</li>
</ul>
<h3 dir="rtl" align="right">رفع مشکلات دیگر</h3>
<ul dir="rtl">
<li><strong>توقف ناگهانی هسته با <span dir="ltr">ECH</span>:</strong> مراحل ضد <span dir="ltr">DPI</span> دیگر <span dir="ltr">ECH</span> را خودکار روشن نمی‌کنند. <span dir="ltr">ECH</span> فقط انتخاب خود شماست.</li>
<li><strong>تداخل هویت:</strong> <span dir="ltr">Gool</span> (وایرگارد داخل <span dir="ltr">MASQUE</span>) حالا در مسیر <span dir="ltr">MASQUE</span> اجرا می‌شود.</li>
<li><strong>محدودهٔ اسکن اشتباه:</strong> اسکن <span dir="ltr">MASQUE</span> و <span dir="ltr">Gool</span> دیگر به محدوده‌های وایرگارد محدود نمی‌شود.</li>
<li><strong><span dir="ltr">MASQUE</span> دستی:</strong> مطابق تنظیمات ← <span dir="ltr">MASQUE</span> روی <span dir="ltr">HTTP/2</span> (بستر <span dir="ltr">TCP</span>) ← مرحلهٔ ضد <span dir="ltr">DPI</span>.</li>
<li><strong>امنیت وابستگی‌های هسته:</strong> <span dir="ltr">quinn-proto 0.11.19</span>، <span dir="ltr">quinn-udp 0.5.16</span>، <span dir="ltr">url 2.5.9</span>، <span dir="ltr">cookie 0.18.3</span>.</li>
<li><strong>پنجرهٔ «تازه‌ها»</strong> فهرست <span dir="ltr">1.5.0</span> را نشان می‌دهد و بخش «اگر به هیچ وجه متصل نشدید چه کنید؟» را نگه داشته است.</li>
</ul>
<h3 dir="rtl" align="right">اصلاحات همین نسخه (گزارش کاربران)</h3>
<ul dir="rtl">
<li><strong>کانفیگ‌های نپستر که روی اندروید پینگ می‌دادند و وصل می‌شدند، در ویندوز نه پینگ می‌دادند نه وصل می‌شدند.</strong> سه تفاوت با اندروید پیدا و رفع شد:
<ul dir="rtl">
<li><strong><span dir="ltr">DNS</span>:</strong> اندروید اول <span dir="ltr">DNS</span> خودِ شبکه را به <span dir="ltr">Xray</span> می‌دهد؛ ویندوز همیشه فهرست خالی می‌فرستاد و نام سرور فقط با <span dir="ltr">1.1.1.1</span> و <span dir="ltr">8.8.8.8</span> پیدا می‌شد که در شبکه‌های ایران اغلب مسدود یا کند است و پینگ و دست‌دهی زودتر تمام می‌شدند. ماژول تازهٔ <span dir="ltr">custom/netdns.rs</span> <span dir="ltr">DNS</span>های کارت‌های شبکهٔ فعال را می‌خواند (کارت <span dir="ltr">Wintun</span> خودِ اتر و <span dir="ltr">loopback</span> کنار گذاشته می‌شوند)؛ پینگ واقعی، تست سرعت و خودِ اتصال حالا مثل اندروید به ترتیب شبکه ← <span dir="ltr">1.1.1.1</span> ← <span dir="ltr">8.8.8.8</span> ← سیستم کار می‌کنند.</li>
<li><strong>گواهی ناامن <span dir="ltr">TLS</span>:</strong> نپستر این گزینه را در <span dir="ltr">tlsAllowInsecure</span> نگه می‌دارد؛ ویندوز فقط <span dir="ltr">insecure</span> قدیمی را می‌خواند و سرورهای دارای گواهی خودامضا در <span dir="ltr">Xray</span> رد می‌شدند. حالا ترتیب همان اندروید است.</li>
<li><strong>فیلدهای ترابری:</strong> <span dir="ltr">xhttpMode</span>، <span dir="ltr">xhttpExtra</span>، <span dir="ltr">seed</span> (<span dir="ltr">mKCP</span>) و <span dir="ltr">authority</span> (<span dir="ltr">gRPC</span>) فایل‌های <span dir="ltr">.npvt</span> و <span dir="ltr">.npvs</span> مثل اندروید خوانده می‌شوند.</li>
<li>مهلت هر دور پینگ واقعی مثل اندروید ۱۲ ثانیه شد (قبلاً ۸ ثانیه).</li>
</ul></li>
<li><strong>باز کردن فایل کانفیگ با اتر:</strong> راست‌کلیک ← <span dir="ltr">Open with</span> ← اتر (یا دابل‌کلیک) فقط برنامه را باز می‌کرد. حالا برنامه فایلی را که با آن اجرا شده می‌خواند - حتی وقتی اتر از قبل باز است - و از همان مسیر عادی ورود (پرسیدن رمز، قفل‌ها، محدودیت حجم) وارد می‌کند. نصب‌کننده پسوندهای <span dir="ltr">.npvt</span> و <span dir="ltr">.npvs</span> را ثبت می‌کند و هنگام حذف برنامه پاک می‌کند. نسخهٔ قابل‌حمل (<span dir="ltr">ZIP</span>) ثبتی ندارد؛ آنجا <span dir="ltr">Open with</span> ← انتخاب برنامهٔ دیگر ← <span dir="ltr">Aether.exe</span> کار می‌کند.</li>
<li><strong>انتخاب خودکار:</strong> «تست همه» نشست فعلی را همان لحظه روی سریع‌ترین سرور می‌برد؛ با تغییر شبکه (وای‌فای، اترنت، هات‌اسپات) دوباره تست و انتخاب انجام می‌شود؛ اولین تست کامل پس از اتصال با آستانهٔ سریع اعمال می‌شود.</li>
<li><strong>کانفیگ‌ها:</strong> دکمه‌های سریع پینگ، تست سرعت و حذف؛ «تست سرعت همه»؛ مرتب‌سازی بر اساس پینگ، دانلود یا آپلود.</li>
<li><strong>کارت اتصال تعاملی:</strong> کلیک روی تأخیر (آخرین/کمینه/بیشینه/میانگین/جیتر/پکت‌لاس)، پروتکل (نودهای زنجیره) یا ترافیک (برنامه‌هایی که همین حالا از تونل استفاده می‌کنند).</li>
<li><strong>زنجیرهٔ اتصال یکپارچه</strong> در صفحهٔ اتصال: تعداد نودها، هستهٔ هر نود و تنظیمات هر نود.</li>
<li><strong>ارسال گزارش عیب‌یابی:</strong> گزارش پاک‌سازی‌شده کپی و صفحهٔ issue گیت‌هاب باز می‌شود؛ پس از اتصال ناموفق پیشنهاد داده می‌شود و در تنظیمات قابل خاموش‌کردن است.</li>
<li>پنجرهٔ «تازه‌ها» همهٔ این موارد را نشان می‌دهد. شمارهٔ نسخه تغییری نکرده است (<span dir="ltr">1.5.0</span>).</li>
</ul>

<p dir="rtl" align="right"><strong>اعتبارسنجی:</strong> فقط بررسی‌های آفلاین اجرا شد؛ <span dir="ltr">cargo</span> و <span dir="ltr">jsdom</span> در محیط پورت نبودند، پس کد <span dir="ltr">Rust</span> و تست‌های رابط در <span dir="ltr">CI</span> برای اولین بار کامپایل و اجرا می‌شوند. اتصال زنده آزموده نشده است.</p>
<p dir="rtl" align="right">اصلاحات همین نسخه هم به همین شکل آفلاین بررسی شدند؛ تست‌های واحد تازهٔ <span dir="ltr">Rust</span> (<span dir="ltr">netdns</span>، <span dir="ltr">openfile</span>، <span dir="ltr">direct_dns</span> و <span dir="ltr">tlsAllowInsecure</span>) نخستین بار در <span dir="ltr">CI</span> کامپایل می‌شوند.</p>

</div>
