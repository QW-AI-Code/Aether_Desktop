# Aether Desktop 1.4.0 — release notes

Aether Core 2.4.0 remains the engine version. This release ports the portable networking and custom-config features of mobile **1.6.0** to Tauri 2 / Windows. Android Intents, camera import, airplane-mode/radio controls, VpnService and phone hotspot UI are not copied.

## Headline change: Windows UI and dimensions now match mobile 1.6.0

The Windows 1.4.0 interface was rebuilt to follow the mobile 1.6.0 design instead of the older 1.3.0 desktop layout. Only the frontend changed in this pass; Rust, `native/` and `third_party/` are byte-identical to the input (SHA-256 compared for 2292 files).

- **Settings and cards.** The connection-verification switch is a separate card above the core settings (same `verifyConnection` key, same wording as mobile); protocol tiles are two columns with a full-width last tile; option cards share mobile's structure.
- **Custom configs page.** Capsule tabs without extra background or line, equal-height *Add config* (green) and *New tab* (dark pink) buttons, no duplicate “Saved configs” title, no fixed 560 px table width (long names, ports and the three-dot button stay inside the window; domains wrap under the type/ping badges), and a full-width *Test all* card under the table with icon, hint and assistant button.
- **RTL and language.** Picker arrows point left in RTL; the “Exit country” hint sits under the whole row; technical names (Aether, Tor, MASQUE×2) stay English; *Link or text*, *Import file* and *Name* are translated; technical strings in inputs keep LTR order.
- **Drawer and Gemini.** Triangular logo removed from the drawer header, uniform group spacing; Gemini icons use the `#9B8CFF` token and sit in the title row.
- **Modal fix.** Escape now closes only the modal and no longer also leaves the sub-page.

Limits: checked with Chromium (layout and a new DOM/geometry parity test) and a test IPC, not in WebView2 on Windows; pixel-exact parity is not claimed. See `docs/UI_PARITY_1.4.0.fa.md` and `docs/UIUX_1.4.0_REPORT.fa.md`.

- Authenticated NPVS v5 input through native paths and browser byte input: P-256 signature, ChaCha20-Poly1305 fields, PBKDF2/app-key unlock, expiry and locked-content privacy. Legacy NPVT1 stays supported. Recipient-device keys and attestation are explicitly rejected, not bypassed.
- Persistent automatic/named tabs, counters, per-server action menu, group moves, lowest-delay sorting and 150/300 ms colors. Subscription records refresh atomically in the DPAPI store.
- Cold TLS + generate_204 real delay, monotonic timing, strict HTTP/1.0/1.1 CRLF parsing and distinct HTTP/network outcomes. A warm live-ping number is a different measurement and is not forced to equal cold setup delay.
- Config → Aether uses a bounded two-step custom TCP plan. ChainTrace logs lifecycle and teardown without exposing raw locked configs.
- IPv4 grace race, validated ISO countries, delayed generation-safe country enrichment, globe fallback and wrapping IPv6 display.
- Optional initial verification (default on), background group auto-selection with 120-second freshness and 50 ms / 20% hysteresis, configurable health interval.
- Native performance/security ports: CUBIC and bounded netstack queues, WireGuard handoff/rekey safeguards, asymmetric UDP buffers (including Windows socket tuning), routing/DNS fixes, custom TCP gateway scan/SNI policy. (The shipped core `Cargo.lock` pins rustls 0.23.43; see the security audit below.)
- Version-scoped What's New suppression remains persisted in prefs.json; Windows network-adapter/router troubleshooting replaces phone-only advice.

## Reproducible source and validation limits

`CORE_PORT_PATCHES.json` records original/mobile/ported hashes. The upstream manifest has NOT been rewritten to disguise the reviewed overlay as pristine. Guards reject unrecorded changes. CORE_SYNC defaults to off; an explicit upgrade requires rebasing the overlay rather than discarding it.

See `docs/PORT_1.4.0_REPORT.fa.md` for actual test results and remaining limitations. Source delivery does not certify live VPN connectivity, signing, an installer or a remote GitHub Actions run. Third-party NPVS adaptation is AGPL-3.0 licensed; see THIRD_PARTY_NOTICES.md before distribution.

The existing explicit `Tor → Psiphon` connection label and official Tor process are retained; they are not replaced by a generic SMART label.

## Completion pass: portable mobile 1.6.0 gaps

- SmartPlus is a real two-family WARP/MASQUE race, with independent loopback probe ports/process ownership, serial tactics within each lane, a 7-second stagger, bounded budgets, confirmed winner and joined/cancelled losing workers. Saved profiles are never rewritten to the winning tactic.
- Tactics Memory is per default physical network (hashed gateway/DNS/NetworkGuid), not installation-global: 14-day proven evidence, 6-hour failed evidence, at most 32 networks, bounded/atomic storage and reset support. Unknown networks do not create a global cache entry.
- Auto-selection performs a fresh active-group Real Delay batch before connecting when enabled. Periodic results are rejected if their catalog basis changed; cancellation closes sockets, stops Xray and joins workers.
- Local QR image import, persistent HTTPS subscriptions from Paste, and native-path image import are implemented.
- Psiphon upload SQM ports the mobile delay-gradient autorate, token-bucket/SFQ and sparse-flow priority. It starts open, uses an independent warm verified-TLS RTT session, applies backpressure only to tunneled uploads, and resets/stops with the connection. Direct routes and downloads are not capped.
- ChainTrace now includes owned Xray/native exit status, session-linked SOCKS handshake stages and aggregate transfer counters without packet payloads or credentials.
- AI custom-exit eligibility follows the active session's actual final SOCKS port, not the saved backend's intermediate/default port. Disconnected/ineligible routes fail closed. Zero Trust handoff Debug output never reveals an access token.
- Development tooling refreshed to Vite 7.3.7 / puppeteer-core 25.14.0, with patched transitive dependencies; npm audit reports zero known advisories at validation time. Node >=22.12 is required.

## Actual validation and release boundary

Portable production-module tests: 171 passed. Core-policy tests: 33 passed. Full native core tests on Linux: 423 passed, 2 explicitly ignored live-network tests. No failures. These suites overlap in coverage and are not 627 distinct product behaviours.

Both app `cargo check --tests` and complete native core `cargo check` succeeded for x86_64-pc-windows-msvc and i686-pc-windows-msvc, including BoringSSL/ring/QUIC with a Windows SDK and Clang 19. The app checks use the CI resource-only override, not fake executable resources. npm test (13 harnesses), web build, Chromium layout and project preflight succeeded. See the Persian report and delivery verification log.

No source-level gap listed in the previous report is deliberately left as a future implementation item. This is not a proof of universal semantic equality or a Windows runtime certification. Windows linking/installers/signing, remote GitHub Actions and live chain/NPVS interoperability still need a real release test; they were not run in this Linux session. Android-only services, radio controls, camera Intents, Keystore/attestation and phone hotspot UI remain platform exclusions, not bypasses.

## 1.4.0 — fixes (Windows parity with mobile)
- Import of NapsternetV `NPVO1` text exports (`.npvs`), including `npvs1:` encoded values (port of `NpvoCodec.kt`).
- Server rows show only `TYPE S# • IP:PORT` (no names, adverts or worker hosts); S numbers are consecutive per tab.
- "New tab" button is on the left; the sparkle (AI) buttons were removed from the config page.
- Real ping now mirrors mobile: `www.gstatic.com`, discarded warm-up, two keep-alive rounds, validated TLS.
- "Home screen animations" off disables only the background glow; the connect-button spin keeps running.
- Wintun: DLL check, retries, reuse of a stale adapter, exact OS error; no silent fall-back to the system proxy.

## Security audit — Windows 1.4.0 (score 70/100)

Source-level review of this repository, scored on eight areas with fixed weights, plus tools actually run for this release: `cargo audit` (RustSec database of 30 Oct 2026) on both `Cargo.lock` files, `npm audit` (0 advisories), `grep` review of TLS, capabilities, CSP, CI and key material. It is **not** a penetration test; no leak test, installer, signing or live tunnel was run on Windows hardware. The scores are the reviewer's judgement against the evidence in the table, not an automated metric.

| # | Area | Weight | Score | Evidence / remaining risk |
|---|---|---:|---:|---|
| 1 | Data leaks (DNS, IPv6, WebRTC, bypass) | 15 | 13 | DNS inside the tunnel, WebRTC lock, IPv6 fail-closed, kill switch. The system proxy is not a universal route for arbitrary UDP apps. No leak test on real Windows hardware. |
| 2 | Permissions and app components | 15 | 12 | Tauri capabilities are minimal (window + shell:allow-open) and the CSP has no remote origin. Needs administrator rights; CSP allows 'unsafe-inline' for styles. |
| 3 | TLS and cryptography | 15 | 10 | SPKI pins and certificate + host-name checks in diagnostics are kept. But the Clean-IP scanner (cleanip.rs:517-518) accepts invalid certificates and host names, and the core accepts invalid certificates in bridges.rs and zerotrust.rs. |
| 4 | Dependencies (cargo audit / npm audit) | 15 | 7 | npm audit: zero. cargo audit on src-tauri/Cargo.lock: 1 vulnerability (crypto-bigint) and 11 warnings; on the core Cargo.lock: 16 advisories, including quinn-proto 0.11.17 (DoS, CVSS 7.5) and rustls 0.23.43. The lock does not match the earlier “rustls 0.23.46” claim. |
| 5 | Secrets and key management | 15 | 12 | AI key, Zero Trust sign-in, LAN-share password and saved configs are sealed with DPAPI; no hardcoded secret and no pfx/p12/jks file found. WARP identity files are plaintext. |
| 6 | Local data and logging | 10 | 8 | IPs, hosts and UUIDs are masked in logs and repeated lines are collapsed; profile.json and the rotating log are not encrypted. |
| 7 | Supply chain and CI | 10 | 5 | Xray is pinned by SHA-256 and the core/overlay guard is active. But GitHub Actions are referenced by tag (not commit), dtolnay/rust-toolchain@stable floats and installers are not Authenticode-signed. |
| 8 | Local services and LAN sharing | 5 | 3 | Listeners are loopback-only and LAN share has the zero-leak guard; but share authentication is off by default and the chain's local SOCKS is unauthenticated. |
| | **Total** | **100** | **70** | |

**Findings to fix next (not changed in this release, because the core overlay is hash-guarded and unverified edits would break `check-core-pristine`):**

1. **Core dependency advisories.** `native/aether/aether/Cargo.lock` pins `rustls 0.23.43`, `quinn-proto 0.11.17` (RUSTSEC-2026-0338/0340/0343, remote panic/DoS), `rustls-webpki 0.103.15`, `crypto-bigint 0.5.5`, `ctutils 0.4.2`, `zstd` crates and `rsa 0.9.10` (RUSTSEC-2023-0071, no fix available). The mobile project upgrades several of these in CI with `scripts/patch-engine-dependencies.py`; the Windows CI has no equivalent step. An earlier line of these notes said “rustls 0.23.46”; that is **not** what the shipped lock file contains and has been corrected.
2. **Clean-IP scanner accepts any certificate.** `src-tauri/src/custom/cleanip.rs:517-518` (`danger_accept_invalid_certs(true)` + `danger_accept_invalid_hostnames(true)`). If the scan only measures reachability and no secret is sent, impact is low; it should still be documented or replaced by a pinned check.
3. **Supply chain.** Pin GitHub Actions to commit SHAs, pin the Rust toolchain version, add Authenticode signing when a certificate exists (`.github/expected-signer.txt` is empty).
4. **Plaintext state.** WARP identity, `profile.json` and the log are not encrypted (not secrets by design, but sensitive).

---

<div dir="rtl" align="right">

<h2 dir="rtl" align="right">تغییر شاخص: رابط و ابعاد ویندوز ۱.۴.۰ با موبایل ۱.۶.۰ همسان شد</h2>

<p dir="rtl" align="right">رابط ویندوز ۱.۴.۰ به‌جای چیدمان قدیمی دسکتاپ ۱.۳.۰، بر پایهٔ طراحی موبایل ۱.۶.۰ بازسازی شد. در این مرحله فقط فرانت‌اند تغییر کرد؛ Rust و <bdi>native</bdi> و <bdi>third_party</bdi> با ورودی بایت‌به‌بایت یکسان‌اند (مقایسهٔ <bdi>SHA-256</bdi> برای ۲۲۹۲ فایل).</p>

<ul dir="rtl">
<li><strong>تنظیمات و کارت‌ها:</strong> سوئیچ راستی‌آزمایی اتصال کارت مستقل بالای تنظیمات هسته است (همان کلید <bdi>verifyConnection</bdi> و متن موبایل)؛ کاشی‌های پروتکل دو ستونه‌اند و گزینهٔ آخر تمام‌عرض است.</li>
<li><strong>صفحهٔ کانفیگ‌های سفارشی:</strong> تب‌های کپسولی، دکمه‌های هم‌ارتفاع «افزودن کانفیگ» (سبز) و «تب جدید» (صورتی تیره)، حذف عنوان تکراری، حذف عرض ثابت ۵۶۰ پیکسلی جدول (نام و پورت و دکمهٔ سه‌نقطه داخل پنجره می‌مانند) و کارت تمام‌عرض «تست پینگ همه» زیر جدول.</li>
<li><strong>راست‌به‌چپ و زبان:</strong> فلش انتخابگرها در RTL رو به چپ است؛ نام‌های فنی (<bdi>Aether</bdi>، <bdi>Tor</bdi>، <bdi>MASQUE×2</bdi>) انگلیسی می‌مانند؛ «لینک یا متن»، «وارد کردن فایل» و «نام» ترجمه شدند؛ رشته‌های فنی در ورودی‌ها ترتیب LTR دارند.</li>
<li><strong>کشو و Gemini:</strong> لوگوی مثلثی از هدر کشو حذف شد و فاصلهٔ گروه‌ها یکسان است؛ آیکون‌های <bdi>Gemini</bdi> از توکن <bdi>#9B8CFF</bdi> استفاده می‌کنند.</li>
<li><strong>رفع باگ مدال:</strong> کلید <bdi>Escape</bdi> فقط مدال را می‌بندد و همزمان از زیرصفحه خارج نمی‌شود.</li>
</ul>

<p dir="rtl" align="right"><strong>محدودیت:</strong> آزمون با <bdi>Chromium</bdi> و <bdi>IPC</bdi> آزمایشی انجام شده، نه روی <bdi>WebView2</bdi> ویندوز؛ انطباق پیکسلی ۱۰۰٪ ادعا نمی‌شود. جزئیات در <bdi>docs/UI_PARITY_1.4.0.fa.md</bdi>.</p>

</div>


<div dir="rtl" align="right">

<h2 dir="rtl" align="right">ممیزی امنیتی — ویندوز ۱.۴.۰ (امتیاز ۷۰ از ۱۰۰)</h2>

<p dir="rtl" align="right">بررسی در سطح سورس همین مخزن، در هشت حوزه با وزن ثابت، به‌همراه ابزارهایی که واقعاً برای این انتشار اجرا شدند: <bdi>cargo audit</bdi> (پایگاه <bdi>RustSec</bdi> در ۳۰ اکتبر ۲۰۲۶) روی هر دو <bdi>Cargo.lock</bdi>، <bdi>npm audit</bdi> (صفر توصیه) و مرور <bdi>grep</bdi> برای TLS، ظرفیت‌های Tauri، CSP، CI و مواد کلیدی. این <strong>تست نفوذ نیست</strong>؛ آزمون نشت، نصب‌کننده، امضا و اتصال زنده روی سخت‌افزار ویندوز اجرا نشده است. امتیازها قضاوت بازبین بر پایهٔ شواهد جدول‌اند، نه معیار خودکار.</p>

<table dir="rtl" align="right">
<thead><tr><th>#</th><th>حوزه</th><th>وزن</th><th>امتیاز</th><th>شواهد و ریسک باقی‌مانده</th></tr></thead>
<tbody>
<tr><td>۱</td><td>نشت داده (DNS، IPv6، WebRTC، دور زدن)</td><td>۱۵</td><td>۱۳</td><td>DNS داخل تونل، قفل WebRTC، IPv6 به‌صورت fail-closed و kill switch. پروکسی سیستمی مسیر عمومی برای هر برنامهٔ UDP نیست. نشتی روی سخت‌افزار واقعی ویندوز آزمون نشده است.</td></tr>
<tr><td>۲</td><td>مجوزها و مؤلفه‌های برنامه</td><td>۱۵</td><td>۱۲</td><td>ظرفیت‌های Tauri حداقلی‌اند (پنجره + shell:allow-open) و CSP بدون منبع راه دور است. برنامه نیاز به دسترسی Administrator دارد و CSP شامل 'unsafe-inline' برای style است.</td></tr>
<tr><td>۳</td><td>TLS و رمزنگاری</td><td>۱۵</td><td>۱۰</td><td>SPKI pin و تأیید گواهی و نام میزبان در عیب‌یابی حفظ شده‌اند. اما «اسکن Clean IP» (cleanip.rs:517-518) گواهی و نام میزبان نامعتبر را می‌پذیرد، و هسته نیز در bridges.rs و zerotrust.rs گواهی نامعتبر می‌پذیرد.</td></tr>
<tr><td>۴</td><td>وابستگی‌ها (cargo audit / npm audit)</td><td>۱۵</td><td>۷</td><td>npm audit: صفر. cargo audit روی src-tauri/Cargo.lock: ۱ آسیب‌پذیری (crypto-bigint) و ۱۱ هشدار؛ روی Cargo.lock هسته: ۱۶ توصیهٔ امنیتی، از جمله quinn-proto 0.11.17 (DoS با شدت ۷٫۵) و rustls 0.23.43. این قفل با ادعای «rustls 0.23.46» همخوان نیست.</td></tr>
<tr><td>۵</td><td>مدیریت کلید و رمز</td><td>۱۵</td><td>۱۲</td><td>کلید هوش مصنوعی، ورود Zero Trust، گذرواژهٔ اشتراک شبکه و کانفیگ‌ها با DPAPI مهر می‌شوند؛ رمز هاردکد دیده نشد و فایل pfx/p12/jks نیست. فایل هویت WARP متن ساده است.</td></tr>
<tr><td>۶</td><td>داده محلی و لاگ</td><td>۱۰</td><td>۸</td><td>IP، میزبان و UUID در لاگ پوشانده می‌شوند و خطوط تکراری فشرده می‌شوند؛ profile.json و لاگ چرخشی رمزنگاری نشده‌اند.</td></tr>
<tr><td>۷</td><td>زنجیرهٔ تأمین و CI</td><td>۱۰</td><td>۵</td><td>Xray با SHA-256 پین شده و نگهبان هستهٔ دست‌نخورده/overlay فعال است. اما GitHub Actions با تگ (نه commit hash) ارجاع شده‌اند، dtolnay/rust-toolchain@stable شناور است و نصب‌کننده‌ها Authenticode امضا نمی‌شوند.</td></tr>
<tr><td>۸</td><td>سرویس‌های محلی و اشتراک LAN</td><td>۵</td><td>۳</td><td>شنودکنندگان فقط loopback‌اند و اشتراک LAN نگهبان zero-leak دارد؛ اما احراز هویت اشتراک به‌صورت پیش‌فرض خاموش است و SOCKS محلی زنجیره بدون رمز است.</td></tr>
<tr><td></td><td><strong>جمع</strong></td><td><strong>۱۰۰</strong></td><td><strong>۷۰</strong></td><td></td></tr>
</tbody>
</table>

<p dir="rtl" align="right"><strong>یافته‌هایی که باید بعداً اصلاح شوند</strong> (در این انتشار تغییر نکردند، چون overlay هسته با هش محافظت می‌شود و ویرایش بررسی‌نشده <bdi>check-core-pristine</bdi> را می‌شکند):</p>

<ol dir="rtl">
<li><strong>توصیه‌های وابستگی هسته:</strong> <bdi>native/aether/aether/Cargo.lock</bdi> نسخه‌های <bdi>rustls 0.23.43</bdi>، <bdi>quinn-proto 0.11.17</bdi> (<bdi>RUSTSEC-2026-0338/0340/0343</bdi>، خرابی/DoS از راه دور)، <bdi>rustls-webpki 0.103.15</bdi>، <bdi>crypto-bigint</bdi>، <bdi>ctutils</bdi>، <bdi>zstd</bdi> و <bdi>rsa 0.9.10</bdi> (بدون اصلاحیه) را پین کرده است. پروژهٔ موبایل در <bdi>CI</bdi> با <bdi>scripts/patch-engine-dependencies.py</bdi> بخشی را ارتقا می‌دهد؛ <bdi>CI</bdi> ویندوز مرحلهٔ معادل ندارد. عبارت قبلی «<bdi>rustls 0.23.46</bdi>» با قفل تحویلی همخوان نبود و در این مستندات اصلاح شد.</li>
<li><strong>اسکنر Clean IP هر گواهی را می‌پذیرد:</strong> <bdi>src-tauri/src/custom/cleanip.rs:517-518</bdi>. اگر فقط دسترس‌پذیری سنجیده می‌شود و رازی ارسال نمی‌شود، اثر کم است؛ باید مستند یا با بررسی پین‌شده جایگزین شود.</li>
<li><strong>زنجیرهٔ تأمین:</strong> پین‌کردن <bdi>Actions</bdi> به <bdi>commit SHA</bdi> و نسخهٔ <bdi>Rust</bdi>، و امضای <bdi>Authenticode</bdi> پس از تهیهٔ گواهی (<bdi>.github/expected-signer.txt</bdi> خالی است).</li>
<li><strong>حالت ذخیره‌شدهٔ متن‌ساده:</strong> هویت <bdi>WARP</bdi>، <bdi>profile.json</bdi> و لاگ رمزنگاری نشده‌اند.</li>
</ol>

</div>
