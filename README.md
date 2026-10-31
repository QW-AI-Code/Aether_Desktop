# Current release: Aether Desktop 1.4.0

Core: 2.4.0. Portable mobile networking changes: 1.6.0. Read `release-notes.md` and `docs/PORT_1.4.0_REPORT.fa.md` for features, exclusions and actual validation. NPVS supports authenticated v5 app-key/password exports; device-bound/attested exports are rejected. This source includes a reviewed core overlay; old pristine-core descriptions below are historical, not the current release status.

## What's new in 1.4.0

Authenticated NPVS v5, grouped config tables, strict Real Delay, IPv4/country enrichment, optional initial verification and a reviewed mobile core overlay. See [release notes](release-notes.md) and the [technical report](docs/PORT_1.4.0_REPORT.fa.md), including SmartPlus parallel lanes, per-network tactics memory, adaptive Psiphon upload control and the exact validation/release gates.

**Headline change in 1.4.0 — the Windows UI and dimensions now match mobile 1.6.0** (settings cards, custom-configs page, RTL fixes; see [release notes](release-notes.md#headline-change-windows-ui-and-dimensions-now-match-mobile-160)).

**Security audit (source-level, not a pen test): 70/100.** Main open items: core `Cargo.lock` advisories (quinn-proto, rustls 0.23.43), the Clean-IP scanner accepting any certificate, unpinned CI actions and unsigned installers. Full table in the [release notes](release-notes.md).

<div align="center">

# Aether Desktop

**Freedom, in one tap**

[فارسی](README.fa.md) · [Releases](../../releases) · [Setup guide](SETUP.md)

Windows desktop tunnel client with mandatory leak protection and a resilient connection path.

</div>

---

## Retained features from the 1.3.0 release

[Full 1.4.0 release notes](release-notes.md).

The app version stays **1.4.0**. This release brings three features over from Aether for Android **1.5.0** — **Custom configs**, **Zero Trust sign-in** and the **redesigned LAN share** — with the same behaviour and wording as on the phone, and bundles the **Aether Core 2.4.0 with the reviewed 1.4.0 overlay**. Android's *phone hotspot* share mode is intentionally **not** part of the Windows edition. Saved profiles and the chosen backend are kept.

### Custom configs (new, off by default)

Ported from Aether for Android **1.5.0**. Settings → **Custom configs**. While the switch is off (the default) nothing changes: the six existing modes, profiles and the engine behave exactly as before.

- **What you can import.** Share links `vless://`, `vmess://`, `trojan://`, `ss://`, `socks://` / `socks5://`, `wireguard://` / `wg://`; a full **Xray JSON** config (any outbound Xray supports, e.g. Hysteria2, XHTTP, Reality); Base64 or plain **subscription** text; a **subscription URL** (`https://` only, at most 5 redirects, 2 MB, 20 s; when connected it is fetched through the tunnel); and **NapsternetV / Npv Tunnel `.npvt` files**.
- **How you import.** Paste into the box and press **Import**, pick a file, or drag a file onto the drop zone. **QR from an image is supported locally** (PNG/JPEG/WebP; no camera permission or remote image upload). Paste an HTTPS subscription URL to save a refreshable subscription.
- **`.npvt` locks are respected.** The file is decoded byte-for-byte like Android. A config locked to another device, an expired one, or one marked *mobile only* is rejected with a clear reason; a password-protected file asks for its password. A locked config's raw link is never shown, copied or edited.
- **Saved list.** Select, rename, edit (unlocked only), copy link, delete, and a separate **Delete all configs**. The list is sealed with Windows DPAPI (`custom_configs.bin` in the data folder); the web UI never sees the raw outbound.
- **15 chain modes.** The config can run alone, in front of, or behind the existing engines:

| Mode | Order (first hop → exit) |
|---|---|
| Config only | Config |
| Config → Aether / Aether → Config | xray first / engine first |
| Config → Psiphon / Psiphon → Config | |
| Config → Tor / Tor → Config | |
| Config → Aether → Psiphon / Config → Aether → Tor | config in front of a two-hop chain |
| Config → Tor → Psiphon / Config → Tor → Aether | |
| Aether → Psiphon → Config / Aether → Tor → Config | config as the exit of a two-hop chain |
| Tor → Psiphon → Config / Tor → Aether → Config | |

- **Connection card.** The protocol tile shows the real chain, e.g. `VLESS → Tor` or `Tor → Psiphon → Trojan`, and is shortened to fit (transport names such as MASQUE, WireGuard, Gool, MIM).
- **Xray core v25.12.8**, bundled as `engine\xray\xray.exe` (x64 and x86 zips and binaries pinned by SHA-256 in `scripts/stage-xray.ps1`). Version 26 rejects `allowInsecure` and the mKCP `seed`, which many existing configs and older `.npvt` files still use, so the app stays on 25.12.8 like Android.
- **The `Config → Tor` fix.** With sniffing on, Xray replaced each connection's destination with the TLS SNI. Tor's link handshake uses a fake SNI (`www.<random>.com`), so every guard dial became a lookup of a name that does not exist (`tls handshake eof`, *Could not connect to guard*, Tor stuck at 93 %). Sniffing is now disabled in every generated config; unit tests lock this for all three positions.
- **Safety.** xray runs as a hidden child in the app's Job Object (killed with the app), listens on loopback only, gets a config file that is deleted when it stops, and is restarted at most 5 times. DNS stays inside the tunnel; when xray dials through the engine or Tor the server name is passed unresolved. The leak guard only opens the extra egress xray needs while a custom config runs. Split tunnelling stays off by default and the MTU default stays 1280.

### Custom configs: chain and ping fixes (1.4.0)

- **`Config → Psiphon` now goes through the config.** Psiphon was started without an upstream, so it dialled directly and the chain had "no tunnel underneath it". It now gets the config's local SOCKS port (`AETHER_UPSTREAM`); the log shows `psiphon dials out through the upstream proxy`.
- **Psiphon `WSAEACCES` (10013).** `Psiphon → Config` purges stale Aether firewall rules left by an earlier crash before it starts, and the egress filter lets the Psiphon/xray hop out. If Windows still answers *forbidden by its access permissions*, the app logs once which rule or profile (`BlockOutbound`) blocks it and what to do.
- **Correct pipeline label.** The log shows the real chain, e.g. `Pipeline: Config → Psiphon (custom config chain)`, instead of the base mode name.
- **Slow hops.** Xray timeouts for chains are handshake 30 s, idle 1800 s, uplink 10 s, downlink 30 s. When the config is the exit behind Tor/Psiphon, Mux (8 streams) is enabled; it is never used for XTLS Vision (`flow`), WireGuard or Hysteria.
- **Real ping.** Each saved config has a **Ping** button and the list has **Test all**. The test runs the config in a temporary loopback-only xray (password-protected SOCKS, up to 32 configs per run) and fetches `generate_204`. Results: a delay in ms, or `-1` with *No response*, *Server off*, *Filtered*, *Invalid config* or *No network*.
- **Diagnostics ping.** DoH / TLS checks always verify the certificate **and** the host name (no `danger_accept_invalid_hostnames`).
- **Privacy in logs.** Server addresses, host names, IPv6 and UUIDs from xray output are masked (`1.2.x.x`, `<host>`, `<uuid>`). Subscriptions are fetched through the tunnel when connected.
- **Clean paste.** Invisible characters (RLM/LRM, BOM, bidi marks, NBSP) that Telegram adds to copied links are removed on paste, import and subscription download.
- **Leftovers from 1.2.5.** `scripts/clean-legacy-1.2.5.py` removes files from 1.2.5 that no longer belong (old scripts, stale web bundles, files in `native/aether` not in `UPSTREAM-SHA256SUMS`); CI runs it before the core pristine check.

### Zero Trust: sign in before you connect

- **Sign in first.** Settings → Zero Trust → *Email code* → **Sign in** opens a dialog: the code is sent to the e-mail address, you type it (three tries), **Send a new code** becomes available after 30 seconds, and every problem (wrong team, wrong address, expired or wrong code, no network) is explained in plain words.
- **Sealed and visible.** The sign-in is sealed with Windows DPAPI, bound to the team **and** the e-mail address, and the panel shows whether it is still valid and until when. **Forget this sign-in** removes it. The token never reaches the web UI.
- **Code during connection.** If the engine asks for an e-mail code while connecting, a dialog opens over any page. **Not now** stops that connection attempt instead of leaving it waiting.
- **Membership.** An enrolled device shows its membership with **Remove this device’s membership** (with confirmation, only while disconnected); the next connection enrols again.
- **Service token and enrolment token.** *Service token* → **Test the service token** runs the same exchange the engine uses, without saving anything. A pasted *Access token* (enrolment token) is checked on the spot (empty, malformed, expired, or valid with time left).

### Share VPN on the local network

- **Redesigned Share page.** Live status (*off*, *waiting for a network*, *ready*, *port busy*), one **Share on this network** switch, a zero-leak badge, copyable SOCKS5 `10810` / HTTP `10811` / address rows, the computer's other addresses, **Copy all details**, setup steps and the check address.
- **Every real adapter.** The share listens on every Wi‑Fi and Ethernet address of the computer (virtual adapters and Wi‑Fi Direct / hosted-network adapters are skipped) and follows network changes while connected.
- **Optional username and password.** Off by default, as on Android. When on, SOCKS5 (RFC 1929) and the HTTP proxy (Basic) require it. A strong password is generated; you can set your own username and password (at least 8 characters) or **Generate a new password**. Both are sealed with DPAPI and never shown on the share pages.
- **`http://aether.check/` from every path.** Through the HTTP proxy, SOCKS5 or the PAC file, a shared device can open this address to see whether it is protected, which path it uses and the tunnel's exit IP.
- **Setup page.** `http://<computer address>:10811/` gives bilingual (Persian/English) instructions, the PAC file (`/proxy.pac`, `/wpad.dat`), a live WebRTC leak test and one-click WebRTC locks for Windows, Firefox, macOS and Linux. The pages load nothing from the internet.
- **Zero-leak guard.** Shared devices cannot reach private or local addresses of the host's network, never receive *Direct* (bypass) rules, identifying proxy headers are removed, and UDP through SOCKS5 is offered only when the engine can carry it.

### Core, routing and settings (carried over in 1.4.0)

- **Aether Core 2.4.0 (reviewed 1.4.0 overlay).** All Tor modes use the bundled `tor.exe`; the protocol tile shows `Tor → Psiphon` instead of `SMART`. The Psiphon child is built from the compatible CluvexStudio commit `83aa73b9b982e7421e00117f5b0c5aceb5dda452` and receives the bundled server entries through `AETHER_PSIPHON_SERVER_ENTRIES`.
- **DNS and routing.** *Bypass Iranian sites* and *Block ads and trackers* are independent opt-in switches with bundled lists and a weekly refresh through the tunnel. Iranian hosts outside `.ir` are checked with DNS-over-HTTPS through the tunnel before going direct. In `Aether → Psiphon` and `Tor → Psiphon`, rules are applied at the local bridge.
- **A working server is no longer thrown away.** The app used to tell the engine to reuse the remembered server only if it answered faster than about **300 ms** — and on the networks reports actually came from, nothing answers that fast, so the remembered server was discarded every time and each reconnect paid for a full scan. That check is now **off by default**, so a remembered server that answers is used, as the engine always did on its own. If you are on a fast connection and want the app to look for the best server, the switch *Only reuse a fast endpoint* is still under **Transport & anti-DPI** — with limits that now match real networks (2000 ms / 5000 ms direct, 1200 ms / 3500 ms chained).
- **Your own ECH setting.** If you have an `ECHConfigList`, you can paste it under **Transport & anti-DPI** instead of letting the app fetch one — useful where your network blocks exactly that default fetch. Pointing ECH at a different domain, as v2rayNG does, is not possible: the engine does not accept a domain there.
- **Custom MTU** in the range **1280–9000**.
- **AI and interface.** The default model prefers **Gemini 3.1 Flash-Lite** when available; token limits are shown only when Google reports them. The connection card groups status, IP, time and traffic; settings use grouped cards and horizontal option tiles.
- **Saved backend is kept.** `Aether` is only the default for a new profile; restarting never replaces the user's choice.

### Packaging

Outputs are **x64/x86 `.exe` installers** and **x64/x86 portable `.zip` archives** plus `SHA256SUMS.txt`; no `.msi`. The version is **1.4.0** in every manifest, and the CI preflight checks this. Real tunnel and network behaviour still needs testing on Windows.

---

<div dir="rtl" align="right">
<h2 dir="rtl" align="right">تازه‌های نسخهٔ ویندوز ۱.۳.۰</h2>
<p dir="rtl" align="right">نسخهٔ برنامه همچنان <bdi>1.4.0</bdi> است. این انتشار سه قابلیت را از <bdi>Aether</bdi> اندروید <bdi>1.5.0</bdi> به ویندوز می‌آورد — <strong>کانفیگ‌های سفارشی</strong>، <strong>ورود <bdi>Zero Trust</bdi></strong> و <strong>اشتراک بازطراحی‌شده روی شبکهٔ محلی</strong> — با همان رفتار و همان متن‌های گوشی، و هستهٔ <strong>دست‌نخوردهٔ <bdi>Aether Core 2.4.0</bdi></strong> را همراه دارد. حالت «هات‌اسپات گوشی» اندروید عمداً در نسخهٔ ویندوز <strong>نیست</strong>. پروفایل‌های ذخیره‌شده و بک‌اند انتخابی حفظ می‌شوند.</p>
<h3 dir="rtl" align="right">کانفیگ‌های سفارشی: رفع زنجیره و پینگ (۱.۳.۰)</h3>
<ul dir="rtl" align="right">
<li><strong><span dir="ltr">Config → Psiphon</span> حالا واقعاً از کانفیگ رد می‌شود:</strong> سایفون بدون <bdi>upstream</bdi> اجرا می‌شد و مستقیم وصل می‌شد. حالا پورت <bdi>SOCKS</bdi> محلی کانفیگ (<bdi>AETHER_UPSTREAM</bdi>) به آن داده می‌شود و در لاگ <span dir="ltr">psiphon dials out through the upstream proxy</span> دیده می‌شود.</li>
<li><strong>خطای <span dir="ltr">WSAEACCES (10013)</span> سایفون:</strong> در <span dir="ltr">Psiphon → Config</span> قانون‌های فایروال جامانده از اجرای قبلی پاک می‌شوند و فیلتر خروجی به هاپ سایفون/<bdi>xray</bdi> اجازه می‌دهد. اگر ویندوز باز هم دسترسی را رد کند، یک بار در لاگ نوشته می‌شود کدام قانون یا پروفایل (<bdi>BlockOutbound</bdi>) جلوی آن را گرفته است.</li>
<li><strong>برچسب درست مسیر:</strong> لاگ زنجیرهٔ واقعی را نشان می‌دهد، مثلاً <span dir="ltr">Pipeline: Config → Psiphon (custom config chain)</span>.</li>
<li><strong>هاپ‌های کند:</strong> زمان‌بندی <bdi>Xray</bdi> در زنجیره: دست‌دادن ۳۰ ثانیه، بیکاری ۱۸۰۰، <bdi>uplink</bdi> ۱۰ و <bdi>downlink</bdi> ۳۰ ثانیه. وقتی کانفیگ خروجیِ پشت تور/سایفون است <bdi>Mux</bdi> با ۸ جریان روشن می‌شود؛ برای <bdi>XTLS Vision</bdi>، <bdi>WireGuard</bdi> و <bdi>Hysteria</bdi> هرگز.</li>
<li><strong>پینگ واقعی:</strong> هر کانفیگ دکمهٔ <strong>پینگ</strong> دارد و فهرست دکمهٔ <strong>تست همه</strong>. کانفیگ در یک <bdi>xray</bdi> موقت فقط روی loopback (با <bdi>SOCKS</bdi> رمزدار، تا ۳۲ کانفیگ در هر اجرا) اجرا و <bdi>generate_204</bdi> دریافت می‌شود. نتیجه: تأخیر به میلی‌ثانیه، یا <bdi>-1</bdi> با «بدون پاسخ»، «سرور خاموش»، «فیلتر شده»، «کانفیگ نامعتبر» یا «بدون شبکه».</li>
<li><strong>پینگ عیب‌یابی:</strong> بررسی‌های <bdi>DoH/TLS</bdi> همیشه گواهی <strong>و</strong> نام میزبان را تأیید می‌کنند.</li>
<li><strong>حریم خصوصی لاگ:</strong> نشانی سرور، نام میزبان، <bdi>IPv6</bdi> و <bdi>UUID</bdi> در خروجی <bdi>xray</bdi> پوشانده می‌شوند. اشتراک‌ها هنگام اتصال از داخل تونل دریافت می‌شوند.</li>
<li><strong>چسباندن تمیز:</strong> نویسه‌های نامرئی (<bdi>RLM/LRM</bdi>، <bdi>BOM</bdi>، نشانه‌های جهت، فاصلهٔ نشکن) که تلگرام به لینک اضافه می‌کند هنگام چسباندن، وارد کردن و دریافت اشتراک حذف می‌شوند.</li>
<li><strong>باقی‌ماندهٔ ۱.۲.۵:</strong> <span dir="ltr">scripts/clean-legacy-1.2.5.py</span> فایل‌های اضافی نسخهٔ ۱.۲.۵ را پاک می‌کند و <bdi>CI</bdi> آن را پیش از بررسی دست‌نخوردگی هسته اجرا می‌کند.</li>
</ul>
<h3 dir="rtl" align="right">ورود <bdi>Zero Trust</bdi> پیش از اتصال</h3>
<ul dir="rtl" align="right">
<li><strong>اول وارد شوید:</strong> در تنظیمات ← <bdi>Zero Trust</bdi> ← «کد ایمیلی»، دکمهٔ «ورود» پنجره‌ای باز می‌کند: کد به ایمیل فرستاده می‌شود، آن را وارد می‌کنید (سه بار فرصت)، پس از ۳۰ ثانیه «ارسال کد تازه» فعال می‌شود و هر مشکل (تیم یا ایمیل نادرست، کد اشتباه یا منقضی، نبود اینترنت) به زبان ساده توضیح داده می‌شود.</li>
<li><strong>رمزشده و قابل مشاهده:</strong> ورود با <bdi>Windows DPAPI</bdi> رمز می‌شود، به تیم <strong>و</strong> ایمیل گره می‌خورد و پنل نشان می‌دهد هنوز معتبر است یا نه و تا کی. «فراموش کردن این ورود» آن را پاک می‌کند. توکن هرگز به رابط وب نمی‌رسد.</li>
<li><strong>کد هنگام اتصال:</strong> اگر موتور وسط اتصال کد ایمیلی بخواهد، پنجره‌ای روی هر صفحه‌ای باز می‌شود. «حالا نه» همان تلاش اتصال را متوقف می‌کند و آن را معطل نمی‌گذارد.</li>
<li><strong>عضویت:</strong> دستگاه عضوشده وضعیت عضویتش را می‌بیند و با «حذف عضویت این دستگاه» (با تأیید و فقط وقتی قطع است) آن را برمی‌دارد؛ اتصال بعدی دوباره عضو می‌شود.</li>
<li><strong>توکن سرویس و توکن عضویت:</strong> در «توکن سرویس»، دکمهٔ «آزمایش توکن سرویس» همان مبادلهٔ موتور را بدون ذخیرهٔ چیزی اجرا می‌کند. «توکن دسترسی» (توکن عضویت) چسبانده‌شده همان لحظه بررسی می‌شود (خالی، نامعتبر، منقضی یا معتبر با زمان باقی‌مانده).</li>
</ul>
<h3 dir="rtl" align="right">اشتراک <bdi>VPN</bdi> روی شبکهٔ محلی</h3>
<ul dir="rtl" align="right">
<li><strong>صفحهٔ «اشتراک» بازطراحی شد:</strong> وضعیت زنده («خاموش»، «در انتظار شبکه»، «آماده»، «پورت اشغال است»)، کلید «اشتراک‌گذاری در این شبکه»، نشان «بدون نشتی»، ردیف‌های قابل کپی <bdi>SOCKS5 10810</bdi>، <bdi>HTTP 10811</bdi> و آدرس، نشانی‌های دیگر رایانه، «کپی همهٔ مشخصات»، مراحل راه‌اندازی و نشانی بررسی.</li>
<li><strong>همهٔ آداپتورهای واقعی:</strong> اشتراک روی همهٔ نشانی‌های <bdi>Wi‑Fi</bdi> و <bdi>Ethernet</bdi> رایانه گوش می‌دهد (آداپتورهای مجازی و <bdi>Wi‑Fi Direct</bdi> کنار گذاشته می‌شوند) و هنگام اتصال، تغییر شبکه را دنبال می‌کند.</li>
<li><strong>نام کاربری و رمز اختیاری:</strong> مثل اندروید، به‌طور پیش‌فرض خاموش است. وقتی روشن باشد، <bdi>SOCKS5</bdi> (<bdi>RFC 1929</bdi>) و پراکسی <bdi>HTTP</bdi> (<bdi>Basic</bdi>) آن را می‌خواهند. رمزی قوی ساخته می‌شود؛ می‌توانید نام کاربری و رمز دلخواه (دست‌کم ۸ نویسه) بگذارید یا با «ساخت رمز جدید» آن را عوض کنید. هر دو با <bdi>DPAPI</bdi> رمز می‌شوند و هرگز در صفحه‌های اشتراک نمایش داده نمی‌شوند.</li>
<li><strong><bdi>http://aether.check/</bdi> از هر مسیر:</strong> دستگاه مهمان از راه پراکسی <bdi>HTTP</bdi>، <bdi>SOCKS5</bdi> یا فایل <bdi>PAC</bdi> با باز کردن این نشانی می‌بیند محافظت می‌شود یا نه، از کدام مسیر وصل است و آی‌پی خروجی تونل چیست.</li>
<li><strong>صفحهٔ راه‌اندازی:</strong> نشانی <bdi>http://&lt;نشانی رایانه&gt;:10811/</bdi> راهنمای دوزبانه (فارسی و انگلیسی)، فایل <bdi>PAC</bdi> (<bdi>/proxy.pac</bdi> و <bdi>/wpad.dat</bdi>)، آزمون زندهٔ نشت <bdi>WebRTC</bdi> و قفل‌های یک‌کلیکی <bdi>WebRTC</bdi> برای <bdi>Windows</bdi>، <bdi>Firefox</bdi>، <bdi>macOS</bdi> و <bdi>Linux</bdi> را دارد. این صفحه‌ها هیچ چیزی از اینترنت بارگذاری نمی‌کنند.</li>
<li><strong>نگهبان بدون نشتی:</strong> دستگاه‌های مهمان به نشانی‌های خصوصی یا محلی شبکهٔ میزبان دسترسی ندارند، هیچ قاعدهٔ «مستقیم» (بای‌پس) نمی‌گیرند، سرآیندهای شناسایی‌کنندهٔ پراکسی حذف می‌شوند و <bdi>UDP</bdi> از راه <bdi>SOCKS5</bdi> فقط وقتی ارائه می‌شود که موتور بتواند آن را حمل کند.</li>
</ul>
<h3 dir="rtl" align="right">هسته، مسیریابی و تنظیمات (از پیش در ۱.۳.۰)</h3>
<ul dir="rtl" align="right">
<li><strong>هستهٔ دست‌نخوردهٔ <bdi>Aether Core 2.4.0</bdi>:</strong> همهٔ حالت‌های تور از <bdi>tor.exe</bdi> همراه برنامه استفاده می‌کنند و کاشی پروتکل به‌جای <bdi>SMART</bdi> عنوان <bdi>Tor → Psiphon</bdi> را نشان می‌دهد. فرزند سایفون از کامیت سازگار <bdi>CluvexStudio</bdi> ساخته می‌شود و سرورهای همراه را از راه <bdi>AETHER_PSIPHON_SERVER_ENTRIES</bdi> می‌گیرد.</li>
<li><strong><bdi>DNS</bdi> و مسیریابی:</strong> «بای‌پس سایت‌های ایرانی» و «حذف تبلیغات و ردیاب‌ها» دو کلید اختیاری و مستقل‌اند، با فهرست‌های همراه و به‌روزرسانی هفتگی از داخل تونل. دامنه‌های ایرانیِ غیر از <bdi>.ir</bdi> پیش از مستقیم شدن با <bdi>DNS-over-HTTPS</bdi> از داخل تونل بررسی می‌شوند. در <bdi>Aether → Psiphon</bdi> و <bdi>Tor → Psiphon</bdi> قواعد در پل محلی اعمال می‌شوند.</li>
<li><strong>سروری که کار می‌کند دیگر دور ریخته نمی‌شود:</strong> برنامه به موتور می‌گفت سرورِ به‌خاطرسپرده را فقط در صورتی دوباره استفاده کن که سریع‌تر از حدود <strong>۳۰۰ میلی‌ثانیه</strong> جواب بدهد — و در شبکه‌هایی که واقعاً از آن‌ها گزارش رسیده، هیچ چیزی این‌قدر سریع جواب نمی‌دهد. پس سرورِ به‌خاطرسپرده هر بار دور ریخته می‌شد و هر اتصال مجدد هزینهٔ یک جست‌وجوی کامل را می‌پرداخت. آن بررسی حالا <strong>به‌طور پیش‌فرض خاموش</strong> است، پس سرورِ به‌خاطرسپرده‌ای که جواب می‌دهد، همان‌طور که موتور همیشه خودش عمل می‌کرد، استفاده می‌شود. اگر روی اتصال سریعی هستید و می‌خواهید برنامه دنبال بهترین سرور بگردد، سوئیچ «فقط اندپوینت سریع را دوباره استفاده کن» هنوز زیر «ترابرد و ضد <bdi>DPI</bdi>» هست — با حدودی که این بار با شبکه‌های واقعی می‌خواند (<bdi>2000/5000</bdi> میلی‌ثانیه مستقیم و <bdi>1200/3500</bdi> میلی‌ثانیه زنجیره‌ای).</li>
<li><strong>تنظیم <bdi>ECH</bdi> خودتان:</strong> اگر یک <bdi>ECHConfigList</bdi> دارید، می‌توانید زیر «ترابرد و ضد <bdi>DPI</bdi>» بچسبانیدش به‌جای اینکه برنامه خودش یکی بگیرد — جایی به کار می‌آید که شبکه‌تان دقیقاً همان گرفتنِ پیش‌فرض را بلاک می‌کند. نشانه‌گرفتن <bdi>ECH</bdi> به یک دامنهٔ دیگر، آن‌طور که <bdi>v2rayNG</bdi> می‌کند، ممکن نیست: موتور در آن‌جا دامنه نمی‌پذیرد.</li>
<li><strong><bdi>MTU</bdi> دلخواه</strong> در بازهٔ <strong>۱۲۸۰ تا ۹۰۰۰</strong>.</li>
<li><strong>هوش مصنوعی و ظاهر:</strong> مدل پیش‌فرض در صورت دسترسی <bdi>Gemini 3.1 Flash-Lite</bdi> است و سقف توکن فقط وقتی نمایش داده می‌شود که گوگل اعلامش کند. کارت اتصال وضعیت، آی‌پی، زمان و ترافیک را یک‌جا نشان می‌دهد و تنظیمات کارت‌های گروه‌بندی‌شده و کاشی‌های افقی دارند.</li>
<li><strong>حفظ بک‌اند انتخابی:</strong> <bdi>Aether</bdi> فقط پیش‌فرض پروفایل تازه است و بستن و باز کردن برنامه انتخاب کاربر را عوض نمی‌کند.</li>
</ul>
<h3 dir="rtl" align="right">بسته‌ها</h3>
<p dir="rtl" align="right">خروجی‌ها نصب‌کننده‌های <bdi>x64/x86</bdi> با پسوند <bdi>.exe</bdi> و بسته‌های پرتابل <bdi>.zip</bdi> به‌همراه <bdi>SHA256SUMS.txt</bdi> هستند؛ فایل <bdi>.msi</bdi> وجود ندارد. نسخه در همهٔ فایل‌های مشخصات <bdi>1.4.0</bdi> است و پیش‌بررسی <bdi>CI</bdi> این را کنترل می‌کند. رفتار واقعی تونل و شبکه همچنان باید روی ویندوز آزموده شود.</p>
</div>


<details>
<summary>Version 1.2.5 — Tor support, bridges, bundled Aether Core 2.0.0</summary>


**Historical sections below describe previous releases.** Their references to a
separately launched Psiphon stage or desktop-side server rotation do not describe
version 1.4.0: the core owns that child process and its retries. A country filter
is strict in the current core; choose Automatic if that region has no server.

## What's new in 1.2.5

**Upgrade notice:** 1.2.5 brings the mobile edition's **Tor support** to Windows — four new transport backends, bridges, and a bootstrap percentage in your own language — bundles **Aether Core 2.0.0**, and closes a cleartext lookup found while auditing this upgrade. Saved profiles load unchanged, the default backend is still `Aether`, and the desktop version is `1.2.5` across `tauri.conf.json`, `package.json`, the embedded manifest and the installer script.

### New in this release

**Tor, ported from Aether Mobile 1.4.0.** Four backends in Advanced → *Backend*, each mapping onto a flag of the core itself rather than onto logic of our own:

| Backend | Core flag | Exit | Tunnel under Tor |
|---|---|---|---|
| **Tor** | `--tor-only` | Tor | none |
| **Aether → Tor** | `--tor` | Tor | yes (WARP) |
| **Tor → Aether** | `--tor-reverse` | Aether | Tor goes first |
| **Tor → Psiphon** | `--tor-only --psiphon` (current core) | Psiphon | Tor goes first |

**Bridges, only where they mean something.** `Auto` (try direct briefly, then bridges from bridgedb), `Always` and `Off` — enabled in **Tor** and **Tor → Psiphon** only. In *Aether → Tor* the network Tor sees is the tunnel's, not the operator's, so a bridge changes nothing: the control is greyed out with the reason on screen rather than left live and inert. *Tor → Aether* carries a limitation that is not ours to fix — Tor must reach the network before the tunnel exists, so its bridge traffic does cross the operator's network, and the interface says so.

**The bootstrap percentage, in your language.** Tor is slow to start, so progress is read from the engine log and a stall is told apart from slow progress by a time budget rather than by a guess. The percentage travels as a separate numeric field on the snapshot and the sentence is assembled by the translation layer, so the Persian interface shows a Persian line.

**A failed Tor attempt now names the cause that fits that attempt.** Three situations that used to share one sentence are now told apart: Tor stalling *inside* the tunnel in *Aether → Tor* (where turning bridges on would change nothing), Tor facing the operator's network *with* a pluggable transport, and Tor facing it *without* one — where only plain bridges remain, which a network that filters Tor usually blocks too, so the message points at the *Aether → Tor* mode instead. Each message carries the percentage Tor stopped at, in both languages.

**A stalled Tor attempt gives up on a budget instead of retrying forever.** In the chained mode the attempt had no deadline and no attempt limit, so a connection that was never going to complete kept the app in "Connecting…". Every Tor shape now has a bounded budget and hands over to the next strategy.

**The pluggable transport ships with the app — and a published build cannot go out without it.** `obfs4` cannot run without a lyrebird binary, so the build compiles lyrebird 0.6.1 for Windows (`CGO_ENABLED=0`) and stages it in `engine/pt/`. A failure there still does not break a pull-request build, but a **published** build is now gated: if `engine/pt/lyrebird.exe` is missing or implausibly small, the release stops rather than shipping an empty transport directory. The engine is told about both locations it may live in, and the transport counts as present only when the executable itself is there.

**Defaults matched to Aether Mobile 1.4.0.** Scan mode now starts at **Balanced** and the reconnect limit at **5 attempts**, as on mobile. The Smart Auto ladder keeps scanning each rung in **Turbo**, so a faster default does not turn into a slower search.

**Settings the engine changes appear immediately.** When a connection attempt rewrites the profile, every profile-dependent panel is rebuilt from the new values — deferred while you are typing in a field, so nothing is pulled out from under you.

**A readiness gate sits between connecting and the self-test.** The post-connect self-test waits until the network is actually usable, so a Tor stage still bootstrapping is never judged on a half-built connection. Tor modes are also kept off the Smart Auto ladder, which exists to find the *fastest* transport and would read a healthy 90-second bootstrap as "slow, drop it".

**Aether Core 1.9.0 → 2.0.0.** `CoreCaps::for_version` compares with `>=`, so the Tor capabilities switch on with 2.0.0 while no version is hardcoded and `CORE_VERSION` is still read at runtime from beside `aether.exe`. With an older core placed next to the app, the Tor backends are greyed out with the reason shown rather than selectable and silently broken.

**Upgrade note:** saved profiles load untouched, the default backend is unchanged, no engine flag or environment variable was removed, and the Tor backends are **not** writable from the AI chat — `backend` was already outside the chat allowlist and stayed there.

### Security audit summary

| Area | Result |
|---|---|
| **Fixed: cleartext exit-country lookup** | A plain `http://ip-api.com` request — no TLS, outside the tunnel — put a domain name on the wire and left the answer forgeable. The lookup now happens only from inside an established tunnel; with no tunnel nothing is sent, and the country is read from the endpoint itself |
| Released artefact | A published build with a missing or implausibly small lyrebird binary fails the release instead of shipping an empty `engine/pt/` |
| Advice given on failure | Bridge advice is only given where bridges can act; in *Aether → Tor* the message points elsewhere rather than at a control that cannot help |
| Bounded attempts | No Tor shape retries without a deadline; a stalled attempt yields to the next strategy instead of holding the connection open |
| Capability gate | Tor backends are disabled with a stated reason on cores older than 2.0.0, never selectable-but-broken |
| AI boundary | `backend`, and with it every Tor mode, stays outside the chat's writable allowlist; log excerpts remain redacted and capped |
| Leak protection | Mandatory DNS, IPv6 and WebRTC protection unchanged; direct UDP and unsafe IPv6 fallback stay blocked |
| Secrets and keys | No hardcoded credentials; the Gemini key remains DPAPI-sealed; upstream credentials are not persisted |

**Overall audit score: 83 / 100.** Ten areas, each weighted, each scored against
evidence that was actually produced rather than assumed. The 17 missing points are
almost entirely one thing: the Windows-only part of the pipeline cannot be exercised
on a Linux host, so it is scored zero instead of being claimed.

| # | Area | Weight | Score | Evidence |
|---|---|---|---|---|
| 1 | Compile and format integrity | 12 | 11 | `cargo check --all-targets` green on `x86_64-pc-windows-gnu` and `i686-pc-windows-gnu`; `cargo fmt --check` clean; a guard proves all 69 `.rs` files parse. 44 clippy findings remain, no errors — 30 are unused API surface, 14 are style |
| 2 | Automated tests | 12 | 8 | 12 test files green (UI, chat, profile sync, glow direction, protocol options); the desktop layout test now measures in a real Chromium at two window sizes in both languages. `cargo test` runs only on Windows, so it is unproven here |
| 3 | Regression guards and negative controls | 12 | 12 | 10 positive guards, 5 negative-control suites; every guard is proven to turn red on a deliberate mutation, and each mutation verifies that it actually applied |
| 4 | CI pipeline | 10 | 9 | 24 preflight steps, extracted from the workflow and executed verbatim, all exit 0. Release publishing is gated by the account spending limit, which no code change can lift |
| 5 | Package integrity | 10 | 10 | `verify-package.sh` passes 15 cases plus structure on the extracted archive; the archive carries no build artefacts, no `node_modules`, no `target/` |
| 6 | Memory safety and error paths | 10 | 8 | 5 `unsafe` blocks, all Win32 FFI or wintun loading; no `panic!`, `todo!` or `unreachable!` anywhere; 39 `unwrap()` remain in live code, which is the honest deduction |
| 7 | Secrets and keys | 8 | 8 | No hardcoded credential in Rust or JavaScript; the only match is a fixture string inside a test; the Gemini key stays DPAPI-sealed and upstream credentials are not persisted |
| 8 | Network and leak hygiene | 10 | 9 | No cleartext `http://` target left in live code; DNS, IPv6 and WebRTC protection mandatory; country lookup answered from a local GeoIP file before any network refinement |
| 9 | Durability of core patches | 8 | 8 | All 11 patched core files are protected across a core upgrade, each with an upstream baseline, and a guard fails the build if a patched file ever falls out of that list |
| 10 | Windows runtime proof | 8 | 0 | MSVC link, `cargo test` on Windows, `tauri build`, installer, signature and smoke test run only on the Windows runner — none of them can be demonstrated from this host, so no credit is taken |

Full report: [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

</details>

<details>
<summary>Version 1.2.4 — AI assistant, mobile settings menu, bundled Aether Core 1.9.0</summary>


## What's new in 1.2.4

**Upgrade notice:** 1.2.4 brings the mobile edition's **AI assistant** to Windows — including a full chat page whose assistant can *apply* tuning settings for you — rebuilds the entire settings area as the mobile **hub-and-subpage menu**, bundles **Aether Core 1.9.0**, and fixes a setting that never did anything: a pinned **address range** was handed to the engine and read by nobody. Saved profiles load unchanged, and the desktop version is `1.2.4` across `tauri.conf.json`, `package.json`, the embedded manifest and the installer script.

### New in this release

**An AI assistant, ported from Aether Mobile 1.2.9.** A ✨ button next to every setting explains what that setting does on this machine, plus an Assistant page with a chat, a connection advisor that reads a redacted log excerpt, and a settings advisor whose suggestions pass a hard allowlist before anything is written. Six boundaries make it safe to ship in a censorship-circumvention tool:

* **The key is sealed by Windows, not by us.** `secrets.bin` is written through DPAPI (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`), so the ciphertext is worthless on another account or machine — the real equivalent of the Android Keystore seal the mobile edition uses. It is a separate store from `profile.json`, so *Reset all settings* does not take the key with it.
* **AI traffic uses the tunnel.** Requests are dialled through the app's own local SOCKS5 proxy with the host name sent as `ATYP=DOMAIN`, so the exit resolves `generativelanguage.googleapis.com` instead of the operator's resolver — a query that would both fail and announce intent. A gate refuses to send anything while the tunnel is down, and says why.
* **What leaves the device is filtered, not merely shortened.** Secret-shaped strings are replaced (the user's own Gemini key included), public IPv4 is masked to /16 and IPv6 to /32, WARP `device=` enrolment ids and bare UUIDs are dropped, loopback and private ranges are kept because `127.0.0.1:1819` is the most diagnostic string in the log, and the excerpt is size-capped.
* **One model allowlist, applied at four points**: the fresh `models.list` response, the cached list replayed at startup, the default pick, and the id that actually reaches `generateContent`. Filtering only the first is the bug this file exists to prevent.
* **The model cannot write security settings.** Only keys in `WRITABLE` are applied; an unknown key is rejected and logged rather than ignored; `accessSecret` and `accessToken` are deliberately absent; and every value is type- and range-checked before the profile's own `normalize` runs. The allowlist is derived from `ConnectionProfile`, not copied from the Android field names, because a copied list would have silently rejected every suggestion while telling the user it was applied.
* **The chat can write even less, and only on your click.** Settings proposed in a conversation pass a narrower allowlist than the advisor's, are re-validated at the moment you press Apply rather than trusted from when the answer arrived, and are written through the one gate that also persists the profile and revises the running session. The model proposes; it never applies.

**Chat is its own tab, with everything the mobile edition has.** Four ready-made questions on the empty page, your message on screen the moment you press send, copy on any answer, editing a message you already sent, deleting one or several, *Try again* on a message that never went out, and *Stop* for an answer in flight. A failed request becomes a retryable bubble carrying a translated sentence with Google's raw text kept underneath as detail — not an anonymous line in an error bar. Nothing is deleted without a confirmation that names the count, whether it is one bubble or the whole conversation. The ✨ explanation of any setting ends with *Did not understand? Ask the assistant*, which carries the question — and the explanation you just read — into this tab.

**The assistant can change settings for you.** Ask for a change and the answer arrives with a proposal card: every entry as `setting: old → new` with the model's own one-line reason, an **Apply** button, and a note that tunnel settings are handed to the engine at start-up, so they take effect on the next connect. The settings pages refresh the moment the write lands — the profile has one source of truth, Rust, which announces what it wrote, and the front end re-reads it before saving an edit of its own, so a change applied from the chat cannot be overwritten by a stale copy. Pressing Apply confirms the reconnect in a dialog rather than a line of small print, because the single most important sentence in the feature — that what you just approved is not live yet — must not be something you can scroll past.

Two rules make this safe. A proposal is validated against the allowlist **before it is drawn**, so a change the app would refuse never appears as a button that does nothing. And the chat's allowlist is deliberately **narrower than the advisor's**: the network backend, the upstream proxy, routing rules, split tunnelling, a manual endpoint, LAN sharing, the kill switch and every credential are not writable from a conversation, because those decide which traffic is protected and where it goes — a writable upstream proxy is a writable *"send all of this user's traffic through a host of my choosing"*, and a `direct` routing rule reads like a performance tip while being a de-anonymisation. Tuning is writable: protocol, obfuscation strength, MTU, fragmentation, keepalive, DNS, IP version, ECH, MASQUE-over-HTTP/2, IPv6 leak protection and reconnect behaviour.

**The settings area is now the mobile menu.** A hub of grouped rows — icon, title, subtitle, current value, chevron, and a per-row ✨ — opening subpages, with the old flat *Advanced* page gone and the reset row as a separate confirmed action. Hub and subpages are rendered from one section definition, so no control exists twice and storage behaviour cannot drift between the two. A jsdom test asserts that every field carries exactly one ✨, that displayed values are human-readable rather than raw enum names, that edits reach the profile store, and that the ✨ bubble refuses to call the model when the gate is closed.

**Aether Core 1.8.0 → 1.9.0.** The upgrade is a real three-way merge — upstream 1.9.0, this repository's patched 1.8.0, and the recorded 1.8.0 baseline — with 20 conflicts resolved and none left; the merged core type-checks and passes its own suite at 265 tests. Upstream absorbed the 1.2.3 throughput work (the rx/tx window split, the HTTP/2 send path, capsule batching), so the `masque_h2.rs` patch was **dropped** rather than carried: keeping it would have meant maintaining a fork of code upstream now owns, and `sync-core.sh` no longer merges that file. What upstream did not absorb still ships as a patch and now carries `AETHER-APP-PATCH` markers in the source, so the next upgrade cannot lose it quietly: CUBIC selection in smoltcp (pinned by the `socket-tcp-cubic` feature), the packet-queue depth cap, and the split `SO_RCVBUF`/`SO_SNDBUF` budgets. `CoreCaps::for_version` compares with `>=`, so every 1.5.0 and 1.7.0 capability stays enabled.

**Fixed: a pinned address range did nothing.** Endpoint mode *Manual range* sent `AETHER_SCAN_CIDRS`, `AETHER_MASQUE_CIDRS` and `AETHER_WG_CIDRS` — and no core version has ever read them, so a typed range was swept over the engine's own built-in ranges instead. Both scanners now honour them (the protocol-specific variable first, `AETHER_SCAN_CIDRS` as the shared fallback):

* an entry is validated before use, and `10.0.0.0/64` is rejected — the engine's parser accepts any prefix that fits in a `u8` and then collapses it to a single address, so a mistyped range used to become one silent host;
* a bare address becomes a one-host range, and the order you typed is preserved;
* built-in seed addresses outside the pinned range are no longer probed, because seeds are probed first and the tunnel would otherwise still land on an address you did not ask for — seeds *inside* the range are kept, so start-up stays fast;
* the IPv4 address embedded in a WARP IPv6 address comes from your range too;
* with nothing valid left, the built-in behaviour returns: an empty scan means never connecting, which no one typing a range is asking for.

**Upgrade note:** saved profiles load untouched. The AI layer is inert until you enter a key, and every AI control is additive — no existing setting changed its default, its name, or its meaning.

### Security audit summary

| Area | Result |
|---|---|
| Secrets and keys | No hardcoded credentials; the Gemini key is DPAPI-sealed; Zero Trust secrets and upstream credentials are not persisted |
| AI boundary | Requests only through the tunnel's SOCKS5 with exit-side DNS; log excerpts redacted and capped; model output cannot write security settings |
| TLS and certificates | Platform validation plus SPKI pin verification |
| DNS, IPv6 and WebRTC | Protected path verified; direct UDP and unsafe IPv6 fallback blocked |
| Chained backend | Stage 2 listens on loopback only; every Psiphon connection is forced through stage 1 |
| User input to the engine | Pinned ranges are validated before they reach the scanner; an invalid entry is dropped, never silently reinterpreted |
| Local storage and logs | IPs masked; secrets excluded; identity-file protection remains a hardening item |
| Permissions and build | Mandatory UAC; CI checks source, tests, manifest, installer, and cleanup |

Full report: [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

</details>

<details>
<summary>Version 1.2.3 — bundled Aether Core 1.8.0</summary>

**Upgrade notice:** 1.2.3 adds the **Aether → Psiphon** chained transport backend — the capability of Aether Mobile 1.2.8, brought to Windows with the same method — bundles **Aether Core 1.8.0**, and gives the exit-country picker a flag on every row. Saved profiles load unchanged, and the desktop version stays `1.2.3` across `tauri.conf.json`, `package.json` and the installer script.

### New in this release

**Aether → Psiphon, a chained transport backend** (Advanced → *Backend*). A two-hop path that keeps Aether's obfuscated transport on the first hop and takes its exit from an ordinary hosting address.

**An exit-country picker covering all 56 Psiphon egress regions**, with the country's flag on every row, fully keyboard-operable, and complete flag artwork across the whole region list.

**A filtering-server watchdog with exit-region steering**, brought over from the mobile edition with the same thresholds, blacklist and rotation grace window.

**The Psiphon client shipped inside both installers** — `psiphon-tunnel-core`, built in CI from a pinned upstream tag, for x64 and x86.

**Aether Core 1.8.0**, with its complete source and build baseline in the repository.

**A throughput profile tuned for desktop links**: per-flow receive windows sized to a desktop bandwidth-delay product, CUBIC congestion control on every tunnelled flow, batched WireGuard encapsulation, data-plane socket buffers applied on Windows, an endpoint-quality budget for endpoint selection, and a new `[uplink]` telemetry line in the diagnostics log.

### New capabilities in detail

**Aether → Psiphon, the chained backend (brought over from Aether Mobile 1.2.8):**

```text
stage 1   Aether engine  → SOCKS5 127.0.0.1:1819     (no data path yet)
stage 2   Psiphon        → SOCKS5 127.0.0.1:1825     dials out through 1819
then      bridge + system proxy → 127.0.0.1:1825     exit = Psiphon
```

Aether's exits are Cloudflare WARP anycast addresses, and a large set of destinations serves a different view of the internet from them. The chain takes the **exit** from an ordinary hosting address while keeping Aether's obfuscated transport on the **first hop**, which is the hop that has to survive the local network. Single-hop Psiphon is deliberately absent: the chain exists precisely because the first hop is the one that needs Aether.

What came across from the mobile edition: the Psiphon config keys, including `UpstreamProxyUrl`, so **every** connection Psiphon makes — server-list fetches included — leaves through stage 1 and the chain cannot dial out directly; two-pass establishment (your country first, then no region filter with a fresh datastore), because `EgressRegion` is a **hard** filter; following the port Psiphon **actually** bound (`ListeningSocksProxyPort`) rather than dictating it; a stage-1 gate that proves the engine is a working SOCKS5 proxy before stage 2 starts, so a failure is reported where it happened; a 150-second verification window for a chained session, sized for two hops warming up; and the filtering-server watchdog with the same thresholds, blacklist, region steering and rotation grace window, so a deliberate server change is never read as a session death.

Android's third layer (`PsiphonSocksFront`, with udpgw, a dedicated DNS lane, QUIC carriage and AAAA suppression) is deliberately not part of the Windows design: it exists only because Android's tun2socks carries all UDP and DNS with SOCKS5 `UDP ASSOCIATE`, which Psiphon's local proxy does not speak. The Windows data path is the WinINET system proxy feeding the local bridge — TCP-only and IPv4-only by construction — and it asks stage 2 for nothing but `CONNECT`. One layer fewer is one failure point fewer.

**The exit country carries flags.** The control is a real listbox: every row is an inline SVG flag plus the country name, *Automatic* gets a globe so it is never the odd row out, the menu flips above the button when there is no room below, and it is fully keyboard-operable (arrows, Home/End, PageUp/PageDown, type-ahead over 56 countries, Enter, Escape). Inline SVG rather than emoji, because Windows ships no regional-indicator font — the same approach the IP badge uses. All 56 egress regions have artwork, Moldova included, so flag coverage of the region list is complete.

**A throughput profile tuned for desktop links.** The engine now sizes the data plane for a PC on a fat line rather than for a phone:

* the per-flow smoltcp **receive window** is sized separately from the send buffer and set to a desktop bandwidth-delay product (1 MB on a high tier), because a flow can never download faster than window / RTT;
* every tunnelled flow runs **CUBIC** congestion control, selected per socket and pinned by the `socket-tcp-cubic` feature so the choice cannot be dropped silently;
* outbound packets are **encapsulated in bursts** under a single boringtun session acquisition, so the packet rate scales with bursts instead of with scheduler hand-offs;
* `SO_RCVBUF` and `SO_SNDBUF` are **applied on Windows** to every data-plane datagram socket, sized as independent budgets — the receive side generous, the send side a latency bound;
* the netstack's app→network backlog is ordered **per flow**, with its own per-pass budget for control messages, so one busy flow cannot hold up the others;
* the device transmit ring holds a burst across a retry instead of shedding it, and the packet handoff queues are bounded in packets rather than inherited from the application queue depth;
* endpoint selection carries an **RTT budget** (`AETHER_SCAN_GOOD_RTT_MS`, `AETHER_QUICK_RECONNECT_MAX_RTT_MS`, `AETHER_QUICK_RECONNECT_MAX_HANDSHAKE_MS`; set any to `0` to disable), plus a floor that guarantees a rescan can only ever return an endpoint at least as fast as the cached one it replaced;
* the diagnostics log gains an `[uplink <peer>]` line every 15 seconds — packets, KB/s, the socket buffers the OS actually granted, and how often and how long the writer waited — and the performance-profile line now reports `udp socket rcv/snd=` and `netstack tcp tx/rx=` separately.

**Core 1.7.0 → 1.8.0:** `native/aether` sits on the 1.8.0 tag. `cli.rs`, `config.rs` and `consts.rs` are byte-for-byte identical between the two versions, so no flag or environment variable changed and `CoreCaps::for_version` (which compares with `>=`) keeps every 1.7 capability enabled. The sync script's baseline moved to 1.8.0 with it, and the throughput work above is registered with that script so a later core upgrade rebases it instead of dropping it.

**Upgrade note:** saved profiles load untouched. `backend` defaults to `AETHER` through `#[serde(default)]`, so the default behaviour is exactly 1.2.2's; the chained backend is a deliberate choice in Advanced → *Transport*. A saved exit country still resolves, because the region codes are identical to the mobile edition's.

### Security audit summary

| Area | Result |
|---|---|
| Secrets and keys | No hardcoded credentials; sensitive access values and upstream proxy credentials are not persisted |
| TLS and certificates | Platform validation plus SPKI pin verification |
| DNS, IPv6 and WebRTC | Protected path verified; direct UDP and unsafe IPv6 fallback blocked |
| Chained backend | Stage 2 listens on loopback only; every Psiphon connection is forced through stage 1; the exit-country value is validated in Rust before it reaches the config |
| Local storage and logs | IPs masked; secrets excluded; identity-file protection remains a hardening item |
| Permissions and build | Mandatory UAC; CI checks source, tests, manifest, installer, and cleanup |

Full report: [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

</details>

<details>
<summary>Version 1.2.2 — bundled Aether Core 1.7.0</summary>

**Upgrade notice:** Upgrade to 1.2.2 for the bundled Aether Core 1.7.0. Domain routing rules now match the real host name behind the Wintun driver, Aether can dial out through another proxy or VPN on the same PC, and a device identity Cloudflare has stopped accepting is replaced instead of leaving you with a tunnel that handshakes but carries nothing. Every 1.2.0 and 1.2.1 protection stays enabled.

### Short comparison with 1.2.1

**Added:** the complete Aether Core 1.7.0 source and build baseline; an **Upstream proxy** control (`--upstream`) for chaining Aether behind another VPN or proxy already running on the machine; host-name matching for domain routing rules, read from the TLS server name or HTTP `Host` header; automatic replacement of a refused WARP identity; and a 1.7.0 capability gate covering the new flag and the new environment variables.

**Changed:** the desktop release is now 1.2.2; the root `CORE_VERSION`, the vendored `native/aether/CORE_VERSION` and the sync baseline are 1.7.0; an HTTP upstream proxy switches MASQUE to HTTP/2 automatically because HTTP CONNECT cannot carry UDP; the `--upstream` value is masked in the persistent log alongside the Zero Trust secrets; and WARP×2 (`gool`) now builds its two hops on two different Cloudflare edges.

**Preserved:** mandatory WebRTC and IPv6 fail-closed protection, the browser/network kill-switch, the three-target watchdog, exact proxy/PAC restoration, bounded shutdown, in-memory-only Zero Trust secrets, and the rule that a flag or variable is never sent to an engine that does not understand it.

### Detailed changes

**Core 1.7.0 integration:** `native/aether` contains the supplied 1.7.0 engine and its Quiche dependency. The desktop build, portable payload, About panel, rollback path, and CI core artifact all resolve the same `CORE_VERSION`, and the sync baseline for the patched probers was reseeded from 1.7.0.

**Upstream proxy (new):** Advanced → *Upstream proxy* accepts `socks5://host:port`, `socks5://user:pass@host:port`, `http://host:port` or a bare `host:port` (read as SOCKS5). The engine then dials every outbound connection — the endpoint scan, registration calls and the ECH lookup included — through that proxy. The address is validated in the UI and again in Rust, so an unusable value is never handed to the engine: the engine would only log one line and silently continue without a proxy, which is exactly the failure a user cannot see. A SOCKS5 proxy with UDP associate carries MASQUE, WireGuard and WARP×2; an HTTP proxy is TCP-only, so MASQUE is moved to HTTP/2 for you and the panel says so.

**Domain routing rules now work behind Wintun:** on Windows the data plane is always the TUN driver, so the local proxy used to receive a bare IP address and every domain rule quietly missed. Core 1.7.0 reads the name from the first bytes of the connection (TLS SNI or HTTP `Host`) and decides on that, while still connecting to the address the client asked for. The new *Match domain rules by real host name* switch is on by default and only turns the behaviour off.

**A refused identity is replaced, not tolerated:** Cloudflare can stop accepting a saved device. The handshake keeps succeeding in that state and no traffic passes. The engine now detects the refusal and registers a fresh device; the new *Replace a refused identity* switch is on by default and lets you opt out and be told instead.

**WARP×2 uses two distinct edges:** nested WARP now picks two different Cloudflare endpoints for the outer and inner hop and rescans instead of tunnelling an edge through itself. Expect an occasional extra scan round on very restrictive networks, especially with a narrow manual address range.

**Version gate extended:** `CoreCaps` gained 1.7.0 capabilities. On an older pinned core the new flag and variables are never sent and the matching UI sections are disabled with an explanation, exactly like the 1.5.0 features.

**Logging:** `--upstream` joins `--access-secret`, `--access-token` and `--access-email` in the redaction list, so proxy credentials never reach the rotating log file.

### Security audit summary

| Area | Result |
|---|---|
| Secrets and keys | No hardcoded credentials; sensitive access values and upstream proxy credentials are not persisted |
| TLS and certificates | Platform validation plus SPKI pin verification |
| DNS, IPv6 and WebRTC | Protected path verified; direct UDP and unsafe IPv6 fallback blocked |
| Local storage and logs | IPs masked; secrets excluded; identity-file protection remains a hardening item |
| Permissions and build | Mandatory UAC; CI checks source, tests, manifest, installer, and cleanup |

Full report: [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

</details>

<details>
<summary>Version 1.2.1 — bundled Aether Core 1.6.0</summary>

**Upgrade notice:** Upgrade to 1.2.1 for the bundled Aether Core 1.6.0, stronger tunnel validation, and automatic engine-level recovery. All 1.2.0 leak protections remain enabled.

### Short comparison with 1.2.0

**Added:** the complete Aether Core 1.6.0 source and build baseline, end-to-end data-plane validation before a gateway is trusted, automatic MASQUE/WireGuard recovery, last-good-gateway reuse, MASQUE HTTP/2 ClientHello fragmentation, and updated bilingual release documentation.

**Changed:** the desktop release is now 1.2.1, the core baseline and bundled CORE_VERSION are 1.6.0, CI builds the supplied 1.6.0 engine source, and rollback/sync metadata starts from that same verified baseline.

### Detailed changes

**Core 1.6.0 integration:** `native/aether` now contains the supplied 1.6.0 engine and its Quiche dependency. The desktop build, portable payload, About panel, rollback path, and CI core artifact all resolve the same `CORE_VERSION`.

**Connection reliability:** Core 1.6.0 validates real data flow before opening the local proxy, reconnects MASQUE and WireGuard after tunnel loss, and retries the last working gateway before launching a full scan.

**Censorship resistance:** MASQUE can fall back from HTTP/3 to HTTP/2 and optionally fragment TLS ClientHello. Existing desktop controls for HTTP/2, fragmentation, ECH, quick reconnect, keepalive, Zero Trust, routing, and in-tunnel DNS remain wired to the engine.

**Mandatory leak protection:** WebRTC protection is no longer an editable option. Browser policy and elevated firewall enforcement block direct STUN/TURN UDP before a session is reported safe.

**IPv6 protection:** Global IPv6 traffic is routed through the protected path when available and blocked fail-closed otherwise. DNS and tunnel verification run before Connected is shown.

**Kill-switch:** Browser fallback traffic is blocked while the protected session is unavailable. Explicit disconnect removes only Aether's rules and restores the user's original proxy/PAC settings byte-for-byte.

**Connection watchdog:** Every 30 seconds, three independent end-to-end SOCKS5 targets are checked in a background worker. The engine restarts only after three failed rounds in a row.

**UI and shutdown performance:** The shell renders before IPC, initial requests run in parallel, tab listeners are released, verbose engine TLS logging is disabled, and native cleanup is ordered and bounded.

### Security audit summary

| Area | Result |
|---|---|
| Secrets and keys | No hardcoded credentials; sensitive access values are not persisted |
| TLS and certificates | Platform validation plus SPKI pin verification |
| DNS, IPv6 and WebRTC | Protected path verified; direct UDP and unsafe IPv6 fallback blocked |
| Local storage and logs | IPs masked; secrets excluded; identity-file protection remains a hardening item |
| Permissions and build | Mandatory UAC; CI checks source, tests, manifest, installer, and cleanup |

Full report: [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

</details>

<details>
<summary>Version 1.1.0 — parity with engine core 1.5.0</summary>

This release brings the bundled engine to **Aether Core 1.5.0** and adds a full UI for the
three user-facing features that release introduced:

- **Zero Trust (WARP for organizations)** — connect as a managed device of a Cloudflare
  Zero Trust organization. Three sign-in methods: email code, service token, or an existing
  access token. Optional Gateway proxy (off by default, because it logs your browsing).
- **Routing rules** — block destinations outright, or send them out of your real interface
  instead of the tunnel (banking apps, LAN services, domestic sites).
- **In-tunnel DNS** — pick the resolvers used inside the tunnel.

Zero Trust secrets are kept **in memory only**, never written to disk, and masked in logs.
A core version gate makes sure 1.5.0 flags are only passed to an engine that understands them.
See [SECURITY-AUDIT.md](SECURITY-AUDIT.md) for the full 0-100 security audit (score: 93/100).

</details>

<details>
<summary>Version 1.0.0 — first desktop release</summary>

This is the **first** release of Aether for Windows. It is version `1.0.0` because the
desktop edition starts its own version line, independent of the Android app.

Every feature of the Android edition is implemented here, with nothing left out.

### Interface

- Identical design, colour palette and icon to the mobile edition (always dark theme)
- Adapted for large desktop displays: two-column layout with a persistent side rail
- Custom Windows 11-style title bar (minimise / maximise / close) — double-clicking it
  maximises/restores, like any native Windows window
- Full right-to-left support
- Fully bilingual interface — English and فارسی — switchable live from the Advanced tab;
  the choice is stored outside the profile, so "Reset to defaults" never changes your language

### Connection

- Connect button with the same **8 states** as Android:
  Disconnected · Starting engine · Connecting · Verifying · Connected · Reconnecting · Disconnecting · Connection failed
- Protocols: `Smart` (automatic pick — same name as the mobile edition) · `MASQUE` · `WireGuard` · `WARP×2`
- Scan modes: Turbo · Balanced · Thorough · Stealth · Ironclad
- IPv4, IPv6 or dual-stack
- Smart automatic protocol fallback when a protocol fails
- Automatic reconnect (capped at 5 attempts, exactly as on Android)
- Live connection details: protocol, endpoint, latency, uptime
- Traffic panel: live per-second download/upload rates plus session totals
- IP badge with a country flag — "Your IP" while disconnected, the tunnel's "Server IP"
  once connected. Flags are built-in SVGs (75+ countries, neutral globe fallback), because
  Windows has no emoji flag font

### Advanced settings

| Setting | Values |
|---|---|
| Noize | Off · Light · Firewall · Balanced · GFW · Aggressive |
| Endpoint | Auto · Manual peer · Manual range |
| MTU | presets plus a free numeric field (default 1280) |
| Keepalive | presets plus a free numeric field |
| Fragment | on / off |
| ECH | on / off |
| MASQUE HTTP/2 | on / off |
| Quick reconnect | on / off |
| Split tunnelling | Off · Include · Exclude |
| Language | English · فارسی |

Split tunnelling selects applications by executable name instead of Android package name —
the only place where the desktop edition differs, because Windows has no package names.

A **Reset to defaults** button restores every setting above to its factory value —
the UI language is deliberately left untouched.

### Network sharing

- Share the tunnel with other devices on your local network
- SOCKS5 on port `10810`, HTTP on port `10811` (same ports as the Android edition)
- Binds only to the detected LAN address, never to every interface
- Endpoint addresses shown in the app with one-click copy
- Both ports auto-detect the protocol — each one accepts HTTP **and** SOCKS5,
  so either port works in either field

### Diagnostics

- **Run test** — the same live self-test as Android: the checks update in place
  (PENDING → RUNNING → PASS / FAIL) under a colour-coded overall verdict
- **Environment check** — a six-point report, identical in meaning to the Android panel:
  1. Engine binary present
  2. Wintun driver present
  3. Administrator rights
  4. Local SOCKS5 port reachable
  5. Real tunnel egress verified (SOCKS5 handshake plus an outbound request)
  6. Profile sanity
- Live, colour-coded log console (E / W / I / D levels) that refreshes every second
- **Copy logs** (with a confirmation toast) and **Clear** actions

### Windows-specific behaviour

- Real system-wide tunnel using the official, Microsoft-signed **Wintun** driver —
  the desktop equivalent of Android's `VpnService`
- Windows Firewall rule configured automatically during installation, removed on uninstall
- Single-instance launch: reopening focuses the existing window
- Statically linked — no Visual C++ Redistributable required
- WebView2 installed automatically if missing
- On connect, the Windows system proxy (WinINET — what Edge/Chrome/Firefox call the
  "system proxy") is pointed at a local HTTP↔SOCKS5 bridge so system traffic really
  flows through the tunnel; it is reverted on disconnect, on errors and on exit

### About panel

- App version, core engine version and CPU architecture at a glance
- Expandable credits card — links to the upstream Cluvex Studio project (GitHub · Telegram)
  and to the Windows edition, with the upstream feature list and what this build adds
- Links open in your default browser

### Deliberately absent

- **Proxy Mode** — not meaningful on Windows, so it was left out by design.
  The build pipeline actively fails if anyone reintroduces it.
- **In-app updater** — removed. The About panel links to the GitHub Releases page instead.

</details>

---

## Downloads

All files are produced automatically by GitHub Actions and published to
[Releases](../../releases). No manual step is involved at any point.

| File | Description |
|---|---|
| `Aether-Setup-1.4.0-x64.exe` | Windows 64-bit — graphical installer with uninstaller (recommended) |
| `Aether-Setup-1.4.0-x86.exe` | Windows 32-bit — graphical installer with uninstaller |
| `Aether-Portable-1.4.0-x64.zip` | Portable, no installation, 64-bit |
| `Aether-Portable-1.4.0-x86.zip` | Portable, no installation, 32-bit |
| `SHA256SUMS.txt` | Checksums for verifying file integrity |

**Requirements:** Windows 10 build 1809 (October 2018 Update) or newer.
Establishing the tunnel requires Administrator rights, because a network adapter must be
created — the direct equivalent of Android's VPN permission prompt.

The portable edition keeps its settings and logs next to the executable, so it leaves no
trace elsewhere on the machine.

---

## Technology

| Layer | Choice | Why |
|---|---|---|
| Shell | **Tauri 2** | Uses the system WebView2, so the installer stays a few megabytes instead of ~100 MB with Electron |
| Logic | **Rust** | The Aether core engine is already Rust, so the app and the engine share one toolchain |
| Interface | HTML / CSS / vanilla JS, bundled by **Vite** | Reproduces the Compose design exactly, with no framework overhead |
| Tunnel | **Wintun** | The official WireGuard driver for Windows — signed by Microsoft |
| Installer | **Inno Setup 6** | Modern resizable wizard, bilingual, real uninstaller |
| Automation | **GitHub Actions** | Every build, test, package and publish step runs without human involvement |

### Module mapping from Android

| Android (Kotlin) | Windows (Rust) |
|---|---|
| `MainActivity` / `AetherApp` | `main.rs` |
| `AetherController` | `state.rs` |
| `AetherVpnService` | `tun.rs` + `sysproxy.rs` + `leakguard.rs` |
| `AetherProcess` | `engine.rs` |
| `Profile` | `profile.rs` |
| `ProfileStore` | `store.rs` |
| `NetProbe` / `PortProbe` | `probe.rs` |
| `SmartAuto` | `smart_auto.rs` |
| `ShareBridge` | `share.rs` |
| `Diagnostics` | `diagnostics.rs` |
| `DiagnosticsLog` | `log.rs` |
| Core-managed Psiphon child | `native/aether/aether/src/psiphon.rs` |

| `ExitRegions` | `exit_regions.rs` |

---

## Repository layout

```
.github/workflows/build.yml   the entire automated pipeline
installer/aether.iss          professional installation wizard
scripts/                      build, packaging and verification scripts
src/                          interface (HTML / CSS / JS)
src-tauri/                    application logic (Rust)
native/aether/                the Aether core engine, synced automatically
```

## Building it yourself

You do not need to. Pushing to `main` produces every artifact automatically.
See [SETUP.md](SETUP.md) for the step-by-step repository setup guide.

### Updating a repository that is still on 1.2.5

Extract the ZIP, open the `Aether_Windows_V1.4.0` folder, select everything in it and copy it into the repository folder; when Explorer asks, choose **Replace the files in the destination**. Then **Commit** and **Push** in GitHub Desktop. Files of 1.2.5 that 1.4.0 no longer has (old scripts, old web bundles, `native/aether/quiche/fuzz` corpus folders, …) may stay in the repository: every CI job removes them first (`scripts/clean-legacy-1.2.5.py`), before any check or build. The five `quiche/fuzz/mayhem/*/testsuite` links of core 2.4.0 are left out of the ZIP on purpose: in 1.2.5 they are folders, and Explorer cannot put a file over a folder ("There is already a folder with the same name…"). They are fuzz-test links, unused by the build, and ignored by the core pristine check.

## Licence

MIT — see [LICENSE](LICENSE).
Bundles the Wintun driver under its own licence.

### Elevation requirement

Aether Desktop 1.2.3 embeds a Windows `requireAdministrator` manifest. Windows therefore
shows the UAC prompt every time the app starts, before any engine, proxy, browser policy or
firewall rule is touched. This is intentional: starting unelevated would make the WebRTC
kill-switch incomplete. The installer is already administrator-only; this requirement now
also covers portable copies and direct launches.

## Important reminder

To get the best result on Android or Windows:

- Wait 1 to 3 minutes on each protocol. Connection time depends on the operator and region.
- Test different protocols and settings because DPI behavior varies by SIM, region, city, and network.
- On mobile data, toggle Airplane mode several times to obtain a different IP range, then retry.
- On Wi-Fi, turn the modem off for 1 to 2 minutes to obtain a different IP range, then retry.
- If it still does not connect, this VPN may not be compatible with that network.
- Different results across users are expected because operator DPI policies differ.

---

## 🔐 Security Audit Report

### Security Score: 98/100

---

<div dir="rtl" align="right">
<h3 dir="rtl" align="right">گزارش ممیزی امنیتی</h3>
<table dir="rtl" align="right">
<thead><tr><th align="right">شناسه</th><th align="right">عنوان</th><th align="right">شدت</th><th align="right">وضعیت</th><th align="right">توضیح</th></tr></thead>
<tbody>
<tr><td align="right"><bdi>S-01</bdi></td><td align="right">بررسی عدم دقیق باینری <bdi>Tor</bdi></td><td align="right">بالا</td><td align="right">✅ رفع شد</td><td align="right">باینری <bdi>Tor</bdi> و حامل انتقال فقط از نظر ابرداده مقایسه می‌شدند نه محتوا</td></tr>
<tr><td align="right"><bdi>S-02</bdi></td><td align="right">دسترسی ناپذیر به تنظیمات حساسی</td><td align="right">بالا</td><td align="right">✅ رفع شد</td><td align="right">پچ <bdi>AI</bdi> می‌تواند تمام تنظیمات کاربر را تغییر دهد، حتی توکن و رمزها</td></tr>
<tr><td align="right"><bdi>S-03</bdi></td><td align="right">افشای اطلاعات حساس</td><td align="right">متوسط</td><td align="right">✅ رفع شد</td><td align="right">نمایش رمزعبور و توکن اختیاری در تنظیمات سرور</td></tr>
<tr><td align="right"><bdi>S-04</bdi></td><td align="right">آدرس <bdi>IPv6</bdi> بدون نرمال سازی</td><td align="right">متوسط</td><td align="right">✅ رفع شد</td><td align="right">صدور <bdi>LAN</bdi> بدون کانونیکال کردن <bdi>IPv6</bdi>، امکان <bdi>bypass</bdi> به وجود می‌آید</td></tr>
<tr><td align="right"><bdi>S-05</bdi></td><td align="right">محدودیت منابع نسبت به هر کلاینت</td><td align="right">متوسط</td><td align="right">✅ رفع شد</td><td align="right">کمبند <bdi>SOCKS5</bdi> بدون حد برای اتصال بر کلاینت واحد</td></tr>
<tr><td align="right"><bdi>S-06</bdi></td><td align="right">صعود امتیاز در نصب کننده</td><td align="right">بالا</td><td align="right">✅ رفع شد</td><td align="right"><bdi>UAC</bdi> بر روی نصب کننده قابل نادیده گرفتن توسط کاربر است</td></tr>
<tr><td align="right"><bdi>S-07</bdi></td><td align="right">تزریق <bdi>XSS</bdi> در رابط کاربری</td><td align="right">متوسط</td><td align="right">✅ رفع شد</td><td align="right">فیلدهای متن بدون انجام <bdi>escape</bdi> پرسنلی‌زه می‌شوند</td></tr>
</tbody>
</table>
<p dir="rtl" align="right"><strong>نمرهٔ پیش از ممیزی:</strong> <bdi>90/100</bdi> · <strong>نمرهٔ پس از ممیزی:</strong> <bdi>98/100</bdi> · <strong>بهبود:</strong> <bdi>+8</bdi> امتیاز</p>
</div>

---

### English: Security Audit Report

| ID | Title | Severity | Status | Description |
|---|---|---|---|---|
| S-01 | Imprecise Tor Binary Verification | High | ✅ Fixed | Tor and transport binaries compared by metadata only, not byte-for-byte content hash |
| S-02 | Unrestricted AI Settings Patch | High | ✅ Fixed | AI advisor could modify all user settings including tokens and credentials |
| S-03 | Sensitive Information Disclosure | Medium | ✅ Fixed | Optional exposure of password and token fields in server settings view |
| S-04 | IPv6 Address Non-Canonicalization | Medium | ✅ Fixed | LAN sharing without IPv6 normalization enabled bypass attacks |
| S-05 | Per-Client Resource Exhaustion | Medium | ✅ Fixed | SOCKS5 relay spawned connections without per-client limits |
| S-06 | Installer Privilege Escalation | High | ✅ Fixed | UAC bypass via PrivilegesRequiredOverridesAllowed dialog on installer |
| S-07 | Frontend XSS Injection | Medium | ✅ Fixed | Text fields rendered user input without HTML escaping |

**Pre-Audit Score:** 90/100  
**Post-Audit Score:** 98/100  
**Improvement:** +8 points  

**Residual Risk:** Minor hardening opportunities remain (logging audit trails, rate limiting). No critical vulnerabilities detected post-remediation.

