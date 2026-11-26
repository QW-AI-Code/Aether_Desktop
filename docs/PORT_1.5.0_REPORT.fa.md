# گزارش پورت: اتر موبایل 1.7.0 → اتر دسکتاپ 1.5.0

نسخهٔ برنامه `1.5.0`، هستهٔ موتور `2.4.0` (بدون تغییر در سورس هسته). مبنا: `Aether_Desktop v1.4.0`.

## ۱. ریشهٔ مشکلات (از لاگ‌های تهران، همان هسته در ویندوز)

1. **هسته پیش از سرویس‌دهی کشته می‌شد.** هسته پورت SOCKS را هنگام start می‌بندد (`Listeners::bind`) ولی فقط پس از تأیید تونل سرویس می‌دهد (`[+] socks5 server listening on …`). کرنل دست‌دهی TCP را خودش کامل می‌کند، پس `probe::socks_ready` در حدود ۰٫۳ ثانیه «بالا» می‌گفت و خودآزما فقط یک دست‌دهی ۴ ثانیه‌ای داشت. هسته‌ای که هنوز دروازهٔ کش‌شده را بررسی می‌کرد (۲ تا ۳٫۵ ثانیه در ایران) یا اسکن می‌کرد، بسته می‌شد.
2. **ECH اجباری در مراحل ضد DPI** (`AETHER-APP-FIX ech-only-where-sni-is-filtered` در `smart_auto.rs`): بدون کلید ECH هسته با `Error: Ech("ECH is on but there is no ECH key to offer …")` در ۰٫۴ ثانیه می‌میرد.
3. **مسابقهٔ ناعادلانه:** WARP از ۰، MASQUE از ۷ ثانیه، و پیش از آن نوبت سریالی ۴۵ ثانیه‌ای مسیر حفظ‌شده.
4. **Gool مدرن در خانوادهٔ WARP:** در هستهٔ 2.4.0 Gool یعنی WireGuard داخل MASQUE با `aether-masque.toml` و lastconn مسک؛ هم‌زمانی با lane مسک → تداخل هویت.
5. **اولین پاسخ برنده بود**، بدون مقایسهٔ پینگ و سرعت.
6. **MASQUE روی HTTP/2 در نردبان شبکهٔ باز نبود.** (نسخهٔ ویندوز برخلاف موبایل رنج‌های WireGuard را روی اسکن MASQUE تحمیل نمی‌کرد؛ آن بخش اصلاحی لازم نداشت.)

## ۲. اصلاحات

| بخش | فایل | چه شد |
|---|---|---|
| ردیابی آمادگی هر فرآیند | `engine.rs`، `readiness.rs` (جدید) | `Readiness` برای هر start تازه ساخته می‌شود؛ ترد خواندن stdout/stderr (نشست و lane) خط `socks5 server listening on` و خط `Error:` (حداکثر ۴۰۰ نویسه) را ثبت می‌کند. |
| دروازهٔ آمادگی | `readiness.rs` | `await_ready` (مسدودکننده، برای lane) و `Gate` (غیرمسدود، برای تیک ۲۰۰ms): تا پایان بودجه؛ با اعلام سرویس هر ۳۰۰ms دست‌دهی ۲ ثانیه‌ای، بدون اعلام هر ۲ ثانیه دست‌دهی کور ۱ ثانیه‌ای؛ مرگ هسته = پایان فوری. |
| اتصال عادی و ریستارت ناظر | `state.rs` | بعد از باز شدن پورت و پیش از مسیر داده/خودآزما/زنجیره: `Gate` با `max(باقی‌ماندهٔ بودجه، 8000ms)`؛ جز حالت‌های تور، Psiphon، کانفیگ سفارشی و upstream. Trace: `engine-serving after=…`، `engine-fail category=died-before-serving reason=…`، `timeout-before-serving`. لاگ «SOCKS5 port is bound; waiting for the engine to start serving it.» |
| حالت هوشمند | `smart_plus/plan.rs`، `scheduler.rs`، `mod.rs` | کاتالوگ موبایل 1.7.0 (`wg`، `wg.noize`، `wg.heavy`، `masque.h3`، `masque.h2`، `masque.h2.frag`، `gool`، `mim`)، بودجهٔ سبک ۲۰/تقویت‌شده ۲۵/دوهاپی ۴۰ ثانیه، هر دو lane از ۰، پنجرهٔ کیفیت ۳٫۵ ثانیه، سقف ۱۵۰ ثانیه، سنجش و رتبه‌بندی، تأیید به ترتیب رتبه (حداکثر ۶۰ ثانیه)، دو پلهٔ «آخرین تلاش» (`masque.h2`، `wg`، اسکن Turbo→Balanced). `Step::Remembered` و `REMEMBERED_MS` حذف شدند. |
| سنجش کیفیت | `probe.rs` | `measure_tunnel_quality`: سه HEAD به `1.1.1.1:80`، دانلود `393216` بایت و آپلود `131072` بایت از `speed.cloudflare.com` روی TLS تأییدشده (native-tls)؛ امتیاز `(4·rtt + 0.5·downMs + 0.5·upMs) × overhead`. |
| ECH | `smart_auto.rs`، `smart_plus/mod.rs` | هیچ تاکتیک/مرحله‌ای ECH را روشن نمی‌کند؛ فقط تنظیم کاربر. پچ قدیمی با `ech-is-only-ever-the-users-choice` جایگزین شد. |
| نردبان سریالی | `smart_auto.rs` | از همان کاتالوگ (`plan::ladder`، یکی‌درمیان دو خانواده) + حافظهٔ هر شبکه + دو پلهٔ آخرین تلاش؛ برچسب `PROTO · noize=.. · h2 · fragment · scan=turbo`. برنده/شکست هر پله در حافظهٔ شبکه ثبت می‌شود. |
| MASQUE دستی | `smart_auto.rs` | as configured (≤۷۵s) → `MASQUE · h2 (TCP carrier)` (≤۴۵s) → ضد DPI با HTTP/2 + fragment (ECH = کاربر)؛ موارد تکراری حذف. روی شبکهٔ فیلترشده ترتیب «ضد DPI اول، ساده کوتاه در آخر» حفظ شد. |
| پراب QUIC | `probe.rs`، `smart_auto.rs`، `state.rs` | `quic_reachable: Option<bool>`: بستهٔ ۱۲۰۰ بایتی تصادفی با نسخهٔ `1a2a3a4a` به `162.159.198.1/.2:443` (۱٫۵s، موازی با بقیهٔ اثرانگشت)؛ فقط Version Negotiation معتبر است. |
| وابستگی‌های هسته | `scripts/patch-engine-dependencies.py`، `build.yml` | گام جدید پیش از `Build engine` (پس از چک pristine در preflight). |
| رابط | `i18n.js`، `views/advanced.js`، `news/announcements.js` | متن‌های «همهٔ پروتکل‌ها هم‌زمان…»، «مقایسهٔ مسیرهای سالم…»، خطای نهایی هوشمند، «دروازهٔ سالمی پیدا نشد»، توضیح جدید حالت هوشمند؛ اطلاعیهٔ 1.5.0 (V140 حذف، فقط بخش «اگر به هیچ وجه متصل نشدید» ماند). |
| نسخه | همهٔ مانیفست‌ها | `1.5.0` (و `1.5.0.0` در windows-manifest)، PATCHLEVEL، Cargo.lock پکیج aether-desktop، تست‌های rust-port/core-policy، خروجی پروفایل (`appVersion: 1.5.0`؛ ورودی نسخه را بررسی نمی‌کند، پس 1.4.0 هم پذیرفته می‌شود). |

## ۳. وابستگی‌های Rust هسته

| پکیج | قفل‌شده در 1.4.0 | کف | RUSTSEC | وضعیت |
|---|---|---|---|---|
| quinn-proto | 0.11.17 | 0.11.19 | 2026-0523، 2026-0524 | در CI با `cargo update --precise` |
| quinn-udp | 0.5.15 | 0.5.16 | 2026-0538 | در CI |
| url | 2.5.8 | 2.5.9 | 2026-0592 | در CI |
| cookie | 0.18.2 | 0.18.3 | 2026-0594 | در CI |
| libsqlite3-sys | 0.37.0 | 0.39 | 2026-0459 | **بدون تغییر**: نیاز به rusqlite 0.41 که tor-dirmgr 0.46 نمی‌پذیرد؛ SQLite فقط کش دایرکتوری تور را در پوشهٔ خصوصی برنامه باز می‌کند. ویندوز `cargo audit` ندارد، پس استثنایی هم لازم نشد. |

`native/aether` دست‌نخورده است؛ ارتقا فقط روی کپی کاری جاب بیلد اعمال می‌شود و `build-engine.ps1` با `--locked` همان قفل را می‌سازد.

## ۴. تست‌ها

- **Rust (نوشته شد، اجرا نشد):** `smart_plus/plan.rs` (خانواده‌ها مخلوط نمی‌شوند در همهٔ DPIها × classic، Gool مدرن در MASQUE و کلاسیک در WARP، هر تاکتیک یک‌بار، هر دو lane از ۰، بودجه بر اساس وزن، سبک→سنگین و mim آخر، ترتیب h2/h3 برای mobile/quic=false/true/None/prefer_tcp، SNI/HOSTILE → `[h2, h2.frag, h3]`، حافظه: proven اول lane خودش و آن lane اول، انقضا، شکست به آخر، شکست کهنه و id ناشناخته نادیده، ladder با masque.h2 و هر ۸ تاکتیک و دو rung اول از دو خانواده، rank، سقف مسابقه)، `scheduler.rs` (موازی بین lane و سریالی داخل lane، پنجرهٔ کیفیت، توقف lane جست‌وجوگر، لغو، سقف، fallback پس از panic)، `readiness.rs`، `probe.rs` (شکل بستهٔ QUIC، پاسخ VN، پورت مرده)، `smart_plus/mod.rs` (apply سخت‌تر می‌کند و ECH کاربر را نگه می‌دارد، eligibility، آخرین تلاش)، `smart_auto.rs` (بازنویسی تست‌های وابسته به نردبان قدیم و پچ ECH).
- **JS:** `tests/whatsnew.mjs` برای 1.5.0 و «فقط یک اطلاعیه، شامل بخش اگر متصل نشدید»؛ تست‌های `*140*.mjs` قفل‌شده روی نسخه به 1.5.0.

## ۵. آنچه اجرا شد / نشد

اجرا شد (همه سبز):
- `scripts/check-connection-card.py`، `check-psiphon-core-compat.py`، `check-rust-parses.py`، `check-session-verdicts.py`، `check-tor-native.py`، `check-tor-staging.py`، `check-workflow-order.py` و نسخه‌های `-negative.sh` همین نگهبان‌ها.
- `node --check` روی همهٔ ماژول‌های `src/`؛ تست‌های Node بدون مرورگر: `js-syntax`، `i18n-scan-keys`، `closeout140`، `sound-assets140`، `npvs-i18n`، `glow-direction`، `css-classes`.
- `scripts/patch-engine-dependencies.py --dry-run` (چهار ارتقای مورد انتظار را پیدا کرد).

اجرا نشد (ابزار در محیط پورت نبود):
- `cargo build`/`cargo test`/`cargo fmt` (rustc/cargo نبود) → کد Rust و تست‌های واحد جدید **کامپایل نشده‌اند**؛ اولین کامپایل واقعی در CI است.
- تست‌های jsdom/puppeteer (`whatsnew`، `ui-smoke`، `settings-smoke`، `layout-desktop`، …) و `qr140` (بستهٔ `qrcode-generator`) چون `node_modules` نبود.
- اتصال زنده، نصب‌کننده و WebView2.

نگهبان‌های قدیمیِ خارج از CI (`check-bridge-lines.py`، `check-core-patches.py`، `check-core-pristine.py` روی این کپی، `check-tor-runtime.py`، `check-tor-watchdog.py`) در ورودی 1.4.0 هم قرمز بودند و این پورت به فایل‌هایی که بررسی می‌کنند دست نزده است.
