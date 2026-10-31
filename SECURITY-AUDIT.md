> **Historical document (1.2.5).** The current 1.4.0 audit, with the 8-area score table and `cargo audit` / `npm audit` results, is in `release-notes.md`.

# Aether Desktop 1.2.5 Security Audit

**Scope:** Windows desktop shell, Rust control plane, bundled tunnel engine (Aether Core 2.0.0) and its app patches, the chained Psiphon stage, the **new Tor stages and the bundled pluggable transport**, the local proxy bridge, firewall policy, the AI layer (key storage, network path, redaction, model-output boundary), local storage, logs, build pipeline, and bundled runtime. **Date:** 2026-09-15 (1.2.5).

**Method and its limits — read this before quoting the score.** This is a source-level review of this repository plus the tests that were actually executed here: 72 Rust unit tests against the repository's own source files, 148 frontend jsdom assertions, the shipped bundle checked in a real browser at two window sizes × two languages, `cargo check` for the Windows target, and both release PowerShell scripts parsed *and* executed. It is **not** a penetration test. In this pass **no Windows binary was built, linked or run**, lyrebird itself was never compiled here, and no Tor bootstrap, bridge connection or leak test was performed on real hardware. Anything below that describes runtime behaviour is derived from code and from those tests, not from a live measurement.

## Executive result

**Score: 90/100** (1.2.4: 90). No hardcoded credentials. The connection path keeps TLS/SPKI pin verification, mandatory WebRTC protection, fail-closed IPv6 handling and the kill-switch. The score is **unchanged rather than raised**, and deliberately so: 1.2.5 closes a cleartext lookup that had been leaking a domain name outside the tunnel (A14), which on its own would be worth a point — but it also adds two new external surfaces, the Tor stages and a bundled third-party transport binary, whose runtime behaviour was not verified in this environment. A point earned in source and a point owed in measurement cancel out.

| Area | Result | Evidence / remaining risk |
|---|---|---|
| **Secrets and keys** | **Pass** | No API keys, passwords, private keys or tokens are hardcoded. The Gemini key is sealed with DPAPI (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`) in `secrets.bin`, written atomically, and kept out of `profile.json`. Zero Trust secrets are write-only and excluded from serialization. |
| **AI network path** | **Pass** | Requests are dialled through the app's own SOCKS5 proxy with `ATYP=DOMAIN`, so the API host is resolved at the exit, not on the operator's resolver. A gate blocks every AI call while the tunnel is down. No new HTTP dependency; TLS is SChannel via `native-tls`. |
| **AI data minimisation** | **Pass with residual, accepted** | Log excerpts are redacted before leaving: secret-shaped strings replaced (including the user's own key), public IPv4 → /16 and IPv6 → /32, WARP `device=` ids and bare UUIDs dropped, loopback/private kept, hard size cap. **Residual:** the feature still sends a redacted excerpt to a third-party API on explicit user action. That is inherent to the feature and is disclosed in the README; it is inert without a key. |
| **AI output as configuration** | **Pass** | Only `WRITABLE` keys are applied; unknown keys are rejected **and logged**; `accessSecret`/`accessToken` are absent from the list by design; values are type- and range-checked before the profile's own `normalize`. The allowlist is derived from `ConnectionProfile`, so it cannot silently drift from the real field names. |
| **Model selection** | **Pass** | One allowlist enforced at four points (fresh list, cached list, default pick, outgoing id), so a stale cache cannot reintroduce a filtered model. |
| **Tor stages** | **Pass in source, unverified at runtime (new in 1.2.5)** | Each backend maps onto a core flag (`--tor`, `--tor-only`, `--tor-reverse`) rather than onto app logic, and the SOCKS port handed to the bridge follows the mode: the tunnel's port in *Tor only*, tor's port in the chained and reverse modes — the mapping is asserted by unit tests, because the failure it prevents is silent (a user who picked *Aether → Tor* leaving through the WARP exit with a green tunnel). Bridges are enabled only in the two modes where tor faces the operator's network; in *Aether → Tor* the control is disabled with the reason shown, so it cannot appear to protect a hop it does not touch. *Tor → Reverse* carries an inherent exposure that is documented rather than hidden: tor must reach the network before the tunnel exists. **Not verified:** no bootstrap, no bridge connection, no leak test was run here. |
| **Bundled transport binary** | **Pass with supply-chain duty (new in 1.2.5)** | lyrebird is built from source at a pinned tag (`lyrebird-0.6.1`, `CGO_ENABLED=0`) rather than downloaded as a binary, and the recorded version travels with it in `engine/pt/LYREBIRD_VERSION`. Every failure path — no Go, unreachable clone, failed build — ends in a skipped step and a logged reason instead of a broken release, since bridges are an add-on. **Duty:** the clone is not pinned to a commit hash and is not signature-verified; a hash pin and reproducible-build verification are release-engineering items, and the binary was never compiled or run in this pass. |
| **Cryptography and protocols** | **Pass with pin rotation duty** | Core 2.0.0 validates the data plane before exposing the proxy and recovers MASQUE/WireGuard tunnels. TLS validates the platform chain and SPKI pins; an unpinned key is rejected. Pin rotation must ship before certificate/key rollover. |
| **DNS, IPv4, IPv6 and WebRTC leaks** | **Pass** | DNS/HTTP verification runs through SOCKS5. WebRTC direct UDP is blocked by browser policy and firewall rules. Global IPv6 is protected or blocked fail-closed. |
| **Traffic bypass** | **Pass for the supported desktop path** | System HTTP/HTTPS and SOCKS-aware applications use the local bridge; the kill-switch covers installed browsers and IPv6 fallback. Arbitrary third-party UDP applications are not transformed into TCP and stay outside the proxy model. |
| **User input reaching the engine** | **Pass (new in 1.2.4)** | A pinned address range is validated before it reaches the scanner: family and prefix length are checked, an out-of-range prefix such as `10.0.0.0/64` is rejected instead of collapsing to a single host, a bare address becomes a one-host range, and an all-invalid list falls back to built-in behaviour rather than producing an empty scan. |
| **Local storage** | **Partial** | Profile configuration and rotating diagnostics logs are plaintext by design. The AI key is now DPAPI-sealed. WARP identity files still need DPAPI/ACL hardening. |
| **OS privileges and UAC** | **Pass** | `requireAdministrator` is embedded and verified; the installer is admin-only; the manifest version tracks the release (`1.2.5.0`). |
| **Logging and errors** | **Pass** | Persistent logs mask public IPs and record no secrets; the upstream proxy value and Zero Trust secrets are masked; engine runtime logging stays at `info`. AI prompts and answers are not written to the rotating log. |
| **Dependencies and supply chain** | **Pass with release controls** | No new runtime dependency was added for the AI layer. Cargo dependencies are versioned and the lockfile moved with the core upgrade (`smoltcp 0.14.0`). Production releases should still add reproducible lockfile verification and Authenticode signatures. |
| **Outbound app-owned requests** | **Pass (fixed in 1.2.5)** | The exit-country refinement no longer issues a cleartext `http://` request outside the tunnel. It runs only from inside an established tunnel; with no tunnel nothing is sent and the country is read from the endpoint itself. See A14. |
| **Engine upgrade integrity** | **Pass (new in 1.2.4, held in 1.2.5)** | Core 2.0.0 was merged three-way against the recorded 1.9.0 baseline on the same method; the `AETHER-APP-PATCH` markers survived the merge. Core 1.9.0 was merged three-way against a recorded pristine baseline rather than copied over the app patches; 20 conflicts resolved, none left; surviving patches carry `AETHER-APP-PATCH` markers and are registered in `sync-core.sh`, so the next upgrade rebases them instead of dropping them. Verified by `cargo check` and 265 passing core tests. |

## Findings and controls

**A01–A05 (1.2.0–1.2.1), fixed and still enforced.** WebRTC direct UDP exposure, IPv6 fallback exposure, proxy restoration after disconnect, periodic upstream stalls, and UI blank/freeze. No regression was introduced by the settings-menu rebuild: the shell still paints before IPC and network work stays off the UI thread.

**A06: upstream proxy credentials, controlled (1.2.2).** `--upstream` may embed `user:pass`, so it is masked in the rotating log next to the Zero Trust secrets and validated on both sides of the IPC boundary.

**A07: identity refused by Cloudflare, handled (1.2.2).** A saved WARP identity the account API no longer accepts is replaced; offline or rate-limited answers never discard an identity.

**A08: host-name routing, scoped (1.2.2).** Domain rules match TLS SNI or HTTP `Host` only when domain rules exist and the proxy was handed a bare address; the connection still goes to the address the client asked for, bounded by `AETHER_ROUTE_SNIFF_MS`.

**A09: chained backend, contained (1.2.3).** Stage 2 listens on loopback only, `UpstreamProxyUrl` forces every Psiphon connection — server-list fetches included — through stage 1, and the exit-region value is validated in Rust before it reaches the config.

**A10: AI key at rest, fixed (1.2.4).** The key is not stored beside the profile in cleartext. DPAPI ties the ciphertext to the Windows login session, so `secrets.bin` copied to another account or machine does not open. A failed decrypt is treated as "no key" and the UI shows the same path a fresh install sees, which avoids an error state that would tempt a user to paste the key somewhere else.

**A11: prompt injection into configuration, contained (1.2.4).** The threat is not hypothetical: the settings advisor asks a third-party model for a JSON patch, and the app it patches controls the machine's network path. Defence is structural rather than textual — an allowlist that omits every credential field, rejection with a log entry for anything unknown, and type/range validation before `normalize`. A prompt is a request, not a guarantee, and is therefore not counted as a control.

**A12: log exfiltration through the advisor, contained (1.2.4).** A connection log written for a monitored user is exactly the wrong thing to forward verbatim. The excerpt is filtered (not merely truncated) and capped so a verbose session cannot quietly ship a megabyte of history off the device.

**A13: a setting that silently did nothing, fixed (1.2.4).** Endpoint mode *Manual range* sent three environment variables no core version read, so a user who pinned a range to avoid a blocked or monitored prefix kept scanning the built-in ranges — a trust failure, not a leak, and the more dangerous kind because the UI claimed otherwise. Both scanners now honour the range, and built-in seeds outside it are no longer probed, since seeds are probed first and would otherwise have landed the tunnel on an address the user deliberately excluded.

**A14: a cleartext lookup outside the tunnel, fixed (1.2.5).** Found while auditing this upgrade, in the code that sharpens the displayed exit country: a plain `http://ip-api.com` request — no TLS, and issued by the app's own socket, which does not pass through the tunnel. For a tool whose users are monitored that is two failures in one line: the domain name goes on the wire in the clear, announcing which tool is running, and the answer is forgeable by anyone on the path, so a displayed country could be chosen by the observer. The lookup now runs only from inside an established tunnel; with no tunnel nothing is sent at all, and the country falls back to what the endpoint itself says — which is what was displayed before this refinement existed, so nothing is lost by refusing.

**A15: the Tor mode's exit port, asserted rather than assumed (1.2.5).** The chained modes must hand out tor's SOCKS port and *Tor only* must hand out the tunnel's; a swap would send a user who explicitly chose *Aether → Tor* out of the WARP exit with a healthy-looking tunnel and no tor in the path. Nothing at runtime would report it — no error, no failed connection, only a wrong exit — so the mapping is pinned by unit tests instead of by review. Bridges are scoped to the two modes where tor faces the operator's network, and disabled with a visible reason elsewhere, so the UI cannot imply protection on a hop bridges do not touch.

**A16: a third-party transport binary in the bundle, contained with a remaining duty (1.2.5).** `obfs4` needs lyrebird, which means shipping a foreign executable next to the engine. It is compiled from source at a pinned tag rather than fetched as a binary, its version is recorded next to it, and its absence degrades to "bridges unavailable" instead of breaking the release. The remaining duty is explicit: the source is pinned by tag, not by commit hash, and the checkout is not signature-verified — a tag can be moved. A commit-hash pin belongs in the build before the next release, and in this pass the binary was neither compiled nor executed.

## 1.3.0 addendum: Custom configs (Xray child process)

**Scope of this addendum:** the *Custom configs* feature ported from Android 1.5.0 (`src-tauri/src/custom/`, `state_custom.rs`, `custom_commands.rs`, `src/views/customconfigs.js`). Verified here: 48 Rust unit tests for the parser, `.npvt` codec, Xray config builder, store and importer (including `xray run -test` against the real Xray 25.12.8 binary on Linux for the generated configs), the frontend jsdom suites, and `cargo check --target x86_64-pc-windows-msvc`. **Not verified here:** any Windows runtime — no chain was connected, no leak test was run.

**A17: a second network binary, pinned (1.3.0).** `xray.exe` (Xray-core v25.12.8, MPL-2.0, licence text shipped next to it in `engine/xray/LICENSE`) is downloaded by `scripts/stage-xray.ps1` from the official GitHub release; both the zip and the extracted `xray.exe` are pinned by SHA-256 for x64 and x86 (the zip digests equal the `.dgst` files published with the release). A digest mismatch always fails the build; a failed download only skips the step, and the publish gate refuses a build without the core. v26 is deliberately not used: it rejects `allowInsecure` and the mKCP `seed`, which existing configs still carry.

**A18: process containment (1.3.0).** xray runs hidden (`CREATE_NO_WINDOW`), is adopted into the app's kill-on-close Job Object (procguard), inherits no proxy environment variables, listens only on `127.0.0.1` on a port chosen away from the app's own ports, and its generated config (which contains the server credentials) lives in the data folder only while it runs and is deleted on stop. Its stdout/stderr are drained into the rotating log with public IPv4 addresses redacted. Restarts are capped (5, reset after 120 s healthy); a port that stays dead is reported as a reconnect instead of a silent green tunnel.

**A19: stored configs and `.npvt` locks (1.3.0).** The saved list is sealed with DPAPI (`custom_configs.bin`), like the AI key; a copy on another account or machine does not open. The web UI receives a view without the raw outbound. `.npvt` author locks are enforced the way Android does: device-bound, expired and *mobile only* files are rejected, password-protected files need the password, and the raw link of a locked config is never returned to the UI (copy/edit refused in Rust, not only hidden). Subscription downloads are `https://` only, at most 5 redirects, 2 MB and 20 s, and go through the tunnel while connected.

**A20: DNS and egress scoping (1.3.0).** Sniffing is disabled in every generated config (with `destOverride: tls` Xray rewrote each destination to the TLS SNI, which broke Tor's fake-SNI link handshake — the `Config → Tor` stall at 93 %); unit tests pin it for all three positions. When xray dials through the engine or Tor, the server name is passed unresolved to the SOCKS listener, so it is resolved at the far end. The leak guard opens the additional egress xray needs only while a custom config is running (`CUSTOM_EGRESS`), and it is cleared on disconnect. With the feature off, none of this code path runs: split tunnelling stays off by default and MTU 1280 is unchanged.

**A21: Tor behind a config, fixed at the root (1.3.0 build fix).** Disabling client-side sniffing (A20) was not enough: the config *server's* sniffer (3x-ui/Marzban default) still read Tor's fake SNI and replaced the relay address, so `Config → Tor…` chains stalled at 10 %. The hop that carries `tor.exe` now splits the ClientHello into 100–200 byte TLS records (`xray::TOR_LINK_FRAGMENT`) inside the config's own tunnel — the Android 1.5.0 equivalent is an Arti link without SNI. Nothing new leaves the machine; measured with the sample configs: Tor 100 % in 9–12 s, `IsTor: true`. The full bilingual 0–100 comparison with Android 1.5.0 is in `release-notes.md` (Windows 90.70 ≈ 91, Android 91.96 ≈ 92).

**No score change.** Like 1.2.5, a feature reviewed in source but not measured at runtime does not earn a point. The release gate additionally requires, on real Windows hardware: `Config`, `Config → Tor`, `Tor → Config` and `Config → Tor → Psiphon` connected, a DNS/WebRTC/IPv6 leak test in at least one FIRST and one LAST mode, and a run with `engine\xray\xray.exe` removed, which must fail with "core not found" while the six regular modes keep working.

## Deductions (why 90 and not 100)

* **−4 — the system proxy is not a universal VPN route.** HTTP/HTTPS and SOCKS-aware applications are covered; an arbitrary UDP application is not. This is a deliberate Windows design decision, documented in the README, not an oversight.
* **−3 — plaintext at rest for non-secret state.** `profile.json`, the rotating log and the WARP identity files are unencrypted. DPAPI/ACL hardening of the identity files is the next step; the AI key already has it.
* **−2 — release artifacts are not Authenticode-signed** unless a signing certificate is configured in CI.
* **−1 — SPKI pin rotation is a manual duty** that must precede any certificate or key rollover.

**Not a deduction, but owed for 1.2.5:** the Tor stages and the bundled transport were reviewed in source and covered by unit tests; they were not exercised at runtime here. The release gate below is where that debt is paid.

## Release gate

Do not publish unless all are green: `cargo fmt --check`, x64 and x86 `cargo test`, the merged core's own suite, the frontend jsdom suites, the frontend build, the Tauri release build, embedded manifest verification, installer silent install/uninstall, kill-switch cleanup, and a manual WebRTC/DNS/IPv6 leak test on real hardware — for 1.2.5, repeated on **each of the four Tor backends**, plus one bridge connection with the bundled lyrebird and one deliberate run with the transport removed, which must degrade to "bridges unavailable" rather than fail the connection.

<div dir="rtl" align="right" markdown="1">

# ممیزی امنیتی نسخهٔ ۱.۲.۵

**دامنه:** پوستهٔ ویندوز، کنترل‌پلین Rust، هستهٔ تونل ۲.۰.۰ و پچ‌هایش، استیج
زنجیره‌ای سایفون، **مراحل تازهٔ تور و ترابرِ افزونهٔ همراهِ بسته**، پل پروکسی،
فایروال، لایهٔ هوش مصنوعی، ذخیره‌سازی محلی، لاگ‌ها و زنجیرهٔ بیلد.
**امتیاز: ۹۰ از ۱۰۰** (۱.۲.۴: ۹۰).

**روش و حدِ آن:** این یک بازبینی در سطح سورس است به‌همراه آزمون‌هایی که واقعاً
اجرا شدند (۷۲ آزمون واحد Rust روی خودِ فایل‌های مخزن، ۱۴۸ سنجهٔ jsdom، بستهٔ
منتشرشده در مرورگر واقعی، `cargo check` برای هدف ویندوز، و اجرای هر دو اسکریپت
PowerShell). آزمون نفوذ نیست. در این نوبت **هیچ باینری ویندوزی ساخته، لینک یا
اجرا نشد**، خودِ lyrebird کامپایل نشد، و هیچ راه‌اندازی تور، اتصالِ پل یا آزمون
نشتی روی سخت‌افزار واقعی انجام نشد.

**چرا امتیاز بالا نرفت:** ۱.۲.۵ یک پرسشِ بی‌رمز بیرون از تونل را بست (A14) که
خودش یک امتیاز می‌ارزید، ولی دو سطحِ تماسِ تازه هم اضافه کرد — مراحل تور و یک
اجراییِ ثالث — که رفتار زمان‌اجرای‌شان اینجا سنجیده نشد. امتیازی که در سورس
به‌دست آمد با امتیازی که در اندازه‌گیری بدهکار است، یکدیگر را خنثی می‌کنند.

| بخش | نتیجه |
|---|---|
| **کلیدها و اسرار** | چیزی هاردکد نشده؛ کلید هوش مصنوعی با DPAPI در `secrets.bin` مهر می‌شود و جدا از پروفایل است؛ اسرار Zero Trust ذخیره نمی‌شوند. |
| **مسیر شبکهٔ هوش مصنوعی** | فقط از پروکسی SOCKS5 خودِ تونل، با `ATYP=DOMAIN` تا نام میزبان را نقطهٔ خروج حل کند؛ با تونلِ خاموش، دروازه هر تماس را رد می‌کند. |
| **کمینه‌سازی دادهٔ ارسالی** | برش لاگ پاک‌سازی و سقف‌دار می‌شود: رشته‌های شبیه راز جایگزین، IPv4 به /16 و IPv6 به /32، شناسه‌های نصب حذف، لوپ‌بک دست‌نخورده. **باقیمانده و پذیرفته‌شده:** ارسال برشِ پاک‌سازی‌شده به API شخص ثالث، با کنش صریح کاربر. |
| **خروجی مدل به‌عنوان پیکربندی** | فقط کلیدهای `WRITABLE`؛ کلید ناشناخته رد و لاگ می‌شود؛ `accessSecret`/`accessToken` در فهرست نیستند؛ نوع و بازه پیش از `normalize` بررسی می‌شود. |
| **رمزنگاری و پروتکل** | اعتبارسنجی زنجیرهٔ TLS و پین SPKI؛ چرخش پین وظیفهٔ دستی است. |
| **نشت DNS، IPv6 و WebRTC** | مسیر حفاظت‌شده تأیید می‌شود؛ UDP مستقیم و IPv6 ناامن fail-closed هستند. |
| **عبور خارج از تونل** | HTTP/HTTPS و برنامه‌های SOCKS-aware حفاظت می‌شوند؛ UDP دلخواه بیرون از مدل پروکسی است. |
| **ورودی کاربر به موتور** | بازهٔ پین‌شده پیش از رسیدن به اسکنر اعتبارسنجی می‌شود؛ `10.0.0.0/64` رد می‌شود نه اینکه بی‌صدا به یک میزبان تبدیل شود. |
| **ذخیره‌سازی محلی** | پروفایل و لاگ متن ساده‌اند؛ کلید هوش مصنوعی مهرشده است؛ سخت‌سازی فایل هویت WARP باقی است. |
| **مجوز و سیستم‌عامل** | `requireAdministrator` اجباری و verify می‌شود؛ نسخهٔ مانیفست `1.2.5.0`. |
| **مراحل تور (تازه در ۱.۲.۵)** | هر بک‌اند روی فلگ خودِ هسته می‌نشیند و درگاه SOCKS از حالت پیروی می‌کند؛ این نگاشت با آزمون واحد قفل شده، چون شکستش بی‌صداست: کاربری که `Aether → Tor` را انتخاب کرده از خروجی WARP بیرون می‌رفت با تونلی که سبز به نظر می‌رسد. پل فقط در دو حالتی فعال است که تور با شبکهٔ اپراتور روبه‌روست. **سنجیده نشد:** راه‌اندازی، اتصالِ پل و آزمون نشتی. |
| **اجراییِ ترابر در بسته (تازه در ۱.۲.۵)** | lyrebird از سورس و روی تگِ پین‌شده بیلد می‌شود، نه دانلودِ باینری؛ نسخه‌اش کنارش ثبت می‌شود؛ و نبودش به «پل در دسترس نیست» تنزل می‌کند نه به انتشارِ شکسته. **بدهی:** پین روی تگ است و نه هشِ کامیت، و checkout امضا‌سنجی نمی‌شود — تگ جابه‌جا شدنی است. |
| **درخواست‌های خودِ برنامه (اصلاح در ۱.۲.۵)** | پرسشِ کشورِ خروج دیگر بی‌رمز و بیرون از تونل نمی‌رود: فقط از داخل تونلِ برقرار، و بی تونل هیچ چیزی فرستاده نمی‌شود. |
| **لاگ** | آی‌پی ماسک، اسرار حذف، سطح موتور `info`؛ پرسش و پاسخ هوش مصنوعی در لاگ نوشته نمی‌شود. |
| **یکپارچگی ارتقای هسته** | merge سه‌طرفه با baseline بکر (۲.۰.۰ روی baselineِ ۱.۹.۰، همان روشِ نوبت قبل)، پچ‌های بازمانده با نشانهٔ `AETHER-APP-PATCH` ثبت‌شده در `sync-core.sh`. |

**کسری‌ها:** ۴− پروکسی سیستمی مسیر جهانی VPN نیست (UDP برنامه‌های ثالث)؛ ۳−
پروفایل، لاگ و فایل هویت متن ساده‌اند؛ ۲− امضای Authenticode در انتشار؛ ۱−
چرخش دستی پین SPKI.

**بدهیِ همین نسخه (کسری نیست):** مراحل تور و ترابرِ همراه در سورس بازبینی و با
آزمون واحد پوشش داده شدند، ولی اینجا در زمان اجرا آزموده نشدند. دروازهٔ انتشار
باید روی **هر چهار بک‌اند تور** تکرار شود، به‌همراه یک اتصالِ پل با lyrebirdِ
همراه و یک اجرای عمدی بی ترابر، که باید به «پل در دسترس نیست» تنزل کند و اتصال
را نشکند.

**افزودهٔ ۱.۳.۰ — کانفیگ‌های سفارشی:** xray.exe (Xray v25.12.8، مجوز MPL-2.0) با
دایجستِ SHA-256ِ پین‌شده برای zip و باینریِ هر دو معماری دانلود می‌شود، پنهان و
داخلِ Job Objectِ برنامه اجرا می‌شود، فقط روی 127.0.0.1 گوش می‌دهد و فایلِ
کانفیگش با توقف پاک می‌شود. فهرستِ کانفیگ‌ها با DPAPI رمز می‌شود، قفلِ فایل‌های
npvt (دستگاه، انقضا، «فقط موبایل»، رمز) رعایت می‌شود و لینکِ خامِ کانفیگِ قفل‌دار
هرگز به رابط نمی‌رسد. sniffing خاموش است (علتِ گیرِ Config → Tor) و گاردِ نشت فقط
هنگامِ اجرای کانفیگِ سفارشی راهِ خروجیِ اضافه را باز می‌کند. امتیاز تغییر نکرد:
این مسیر روی ویندوزِ واقعی آزموده نشده است.

**افزودهٔ A21 — تورِ پشتِ کانفیگ از ریشه درست شد:** خاموش‌کردنِ sniffingِ سمتِ
برنامه کافی نبود؛ sniffingِ سمتِ *سرورِ* کانفیگ هنوز SNIِ ساختگیِ تور را می‌خواند و
زنجیره‌های Config → Tor روی ۱۰٪ می‌ماندند. هاپِ حاملِ tor.exe حالا ClientHello را
داخلِ تونلِ خودِ کانفیگ به رکوردهای ۱۰۰ تا ۲۰۰ بایتی می‌شکند (معادلِ لینکِ بی‌SNIِ
Arti در اندروید ۱.۵.۰). خروجیِ تازه‌ای ساخته نمی‌شود. جدولِ کاملِ مقایسهٔ ۰ تا ۱۰۰
با اندروید ۱.۵.۰ در release-notes.md است (ویندوز ۹۱، اندروید ۹۲).

</div>
