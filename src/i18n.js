// =============================================================================
//  i18n — دوزبانه: English + فارسی
//  انتخاب کاربر در localStorage می‌ماند و عمداً جدا از profile است تا با
//  «بازنشانی به تنظیمات پیش‌فرض» زبان کاربر عوض نشود.
//
//  قاعده: کلیدها همان جمله‌های انگلیسی رابط هستند؛ اگر ترجمه‌ای نبود
//  همان انگلیسی نمایش داده می‌شود. واژه‌های لاتین داخل جمله‌های فارسی در
//  <bdi> می‌نشینند تا چپ‌به‌راست رندر شوند و متن راست‌به‌چپ بهم نریزد
//  (فقط در رشته‌هایی که با innerHTML رندر می‌شوند).
// =============================================================================

const STORAGE_KEY = 'aether.lang'

export const LANGS = [
  ['en', 'English'],
  ['fa', 'فارسی'],
]

const FA = {
  // 1.4.0 — core 2.4.0 TLS / API options
  'Server names (SNI)': 'نام سرور (SNI)',
  'MASQUE server name': 'نام سرور MASQUE',
  'The name the MASQUE handshakes put in their ClientHello. Empty = core default.': 'نامی که دست‌دهی‌های MASQUE در ClientHello می‌گذارند. خالی = پیش‌فرض هسته.',
  'API address': 'نشانی API',
  'Send the calls to the WARP API to this IP or name instead of the default. Empty = default.': 'فراخوانی‌های API وارپ به‌جای نشانی پیش‌فرض به این IP یا نام فرستاده می‌شوند. خالی = پیش‌فرض.',
  'API server name (SNI)': 'نام سرور API (SNI)',
  'The server name the ClientHello of those API calls sends.': 'نام سروری که ClientHello آن فراخوانی‌های API می‌فرستد.',
  'API host': 'هاست API',
  'The HTTP host of those API calls.': 'هاست HTTP آن فراخوانی‌های API.',
  'Certificate checks': 'بررسی گواهی',
  'Verify the MASQUE gateway certificate': 'تأیید گواهی دروازهٔ MASQUE',
  'Hold the gateway certificate to the pins the core carries. Always on with Zero Trust.': 'گواهی دروازه با پین‌های همراه هسته سنجیده می‌شود. با Zero Trust همیشه روشن است.',
  'Trust anchor IDs': 'شناسه‌های لنگر اعتماد',
  'Dotted IDs separated by a colon. Empty = none.': 'شناسه‌های نقطه‌دار که با دونقطه جدا می‌شوند. خالی = هیچ.',
  'Certificate compression': 'فشرده‌سازی گواهی',
  'TLS fingerprint': 'اثرانگشت TLS',
  'TLS 1.2 cipher suites': 'مجموعه رمزهای TLS 1.2',
  'Names separated by a colon. Empty = Chrome default.': 'نام‌ها با دونقطه جدا می‌شوند. خالی = پیش‌فرض Chrome.',
  'TLS 1.3 cipher suites': 'مجموعه رمزهای TLS 1.3',
  'Standard names separated by a colon, in order. Empty = Chrome default.': 'نام‌های استاندارد به ترتیب و با دونقطه. خالی = پیش‌فرض Chrome.',
  'TLS groups': 'گروه‌های TLS',
  'Groups in order. Empty = core default.': 'گروه‌ها به ترتیب. خالی = پیش‌فرض هسته.',
  'Key shares': 'اشتراک کلید',
  'Groups that get a key share; each must be one of the TLS groups. Empty = Chrome default.': 'گروه‌هایی که اشتراک کلید می‌گیرند؛ هرکدام باید یکی از گروه‌های TLS باشد. خالی = پیش‌فرض Chrome.',
  'Signature algorithms': 'الگوریتم‌های امضا',
  'BoringSSL names separated by a colon. Empty = core default.': 'نام‌های BoringSSL با دونقطه جدا می‌شوند. خالی = پیش‌فرض هسته.',
  'ALPS': 'ALPS',
  'New': 'جدید',
  'Old': 'قدیمی',
  'Server padding (bytes)': 'پدینگ سرور (بایت)',
  'Bytes of padding asked of the server, 0 to 65535. Empty = none.': 'بایت‌های پدینگ درخواستی از سرور، ۰ تا ۶۵۵۳۵. خالی = هیچ.',
  'Disable GREASE': 'غیرفعال‌کردن GREASE',
  'Leave out the GREASE values Chrome sends.': 'مقادیر GREASE که Chrome می‌فرستد حذف می‌شوند.',
  'GREASE signature algorithm': 'GREASE در الگوریتم امضا',
  'Put a GREASE value first among the signature algorithms, as Chrome does.': 'مانند Chrome یک مقدار GREASE در ابتدای الگوریتم‌های امضا قرار می‌گیرد.',
  'ECH GREASE': 'ECH GREASE',
  'Send a GREASE ECH extension when no ECH key is offered.': 'وقتی کلید ECH ارائه نمی‌شود، افزونهٔ GREASE برای ECH فرستاده می‌شود.',
  'Disable OCSP stapling': 'غیرفعال‌کردن OCSP stapling',
  'Leave out the status_request extension.': 'افزونهٔ status_request حذف می‌شود.',
  'Disable SCT': 'غیرفعال‌کردن SCT',
  'Leave out the signed_certificate_timestamp extension.': 'افزونهٔ signed_certificate_timestamp حذف می‌شود.',
  'Disable session tickets': 'غیرفعال‌کردن تیکت نشست',
  'Leave out the session_ticket extension.': 'افزونهٔ session_ticket حذف می‌شود.',
  'Disable extension permutation': 'غیرفعال‌کردن جابه‌جایی افزونه‌ها',
  "Keep one fixed order of the extensions instead of Chrome's per-handshake shuffle.": 'به‌جای جابه‌جایی تصادفی Chrome در هر دست‌دهی، ترتیب افزونه‌ها ثابت می‌ماند.',
  'The TLS and API options need engine core 2.4.0 or newer. The bundled core is older, so they are disabled.': 'گزینه‌های TLS و API به هستهٔ 2.4.0 یا جدیدتر نیاز دارند. هستهٔ همراه قدیمی‌تر است، پس غیرفعال‌اند.',
  'TLS fingerprint & API': 'اثرانگشت TLS و API',
  'Server names, certificate checks and TLS handshake details (core 2.4.0)': 'نام سرورها، بررسی گواهی و جزئیات دست‌دهی TLS (هستهٔ 2.4.0)',
  'Download / upload speed test': 'تست سرعت دانلود / آپلود',
  'Measuring real throughput…': 'در حال سنجش سرعت واقعی…',
  'No throughput result; endpoint or proxy unavailable': 'نتیجه‌ای دریافت نشد؛ پراکسی یا مقصد آزمون در دسترس نیست',
  'This test sends synthetic data through this server only and may use approximately 10 MiB per attempt. Mobile data charges may apply. No personal files are uploaded.': 'این آزمون فقط از همین سرور عبور می‌کند و در هر تلاش حدود ۱۰ مگابایت دادهٔ آزمایشی مصرف می‌کند. ممکن است هزینهٔ اینترنت همراه داشته باشد. هیچ فایل شخصی آپلود نمی‌شود.',
  'Start test': 'شروع آزمون',
  'Scan / change clean IP': 'اسکن / تغییر IP تمیز',
  // --- ترجمه‌های تکمیلی ۱.۴.۰ ---
  'Quick and shallow — fewest candidates and shortest wait.': 'سریع و سطحی — کمترین نامزد و کوتاه‌ترین انتظار.',
  'Default — a balanced mix of depth and speed.': 'پیش‌فرض — ترکیبی متعادل از عمق و سرعت.',
  'Most thorough and slowest — use when a scan finds nothing.': 'کامل‌ترین و کندترین — وقتی اسکن چیزی پیدا نمی‌کند استفاده کنید.',
  'Scan profile, manual ping and the automatic scan for your own configs': 'پروفایل اسکن، پینگ دستی و اسکن خودکار برای کانفیگ‌های خودتان',
  'Display and sound': 'نمایش و صدا',
  'Clean IP scan settings': 'تنظیمات اسکن آی‌پی تمیز',
  'Home screen animations': 'انیمیشن‌های صفحهٔ اصلی',
  'Turn off the moving home-screen effects on weaker PCs. The live ping meter stays animated.': 'در رایانه‌های ضعیف‌تر، جلوه‌های متحرک صفحهٔ اصلی را خاموش کنید. نمایشگر زندهٔ پینگ متحرک می‌ماند.',
  'Connection sounds': 'صدای اتصال',
  'Play a short cue when connected or disconnected.': 'هنگام اتصال یا قطع اتصال، یک صدای کوتاه پخش می‌شود.',
  'Clipboard is empty.': 'کلیپ‌بورد خالی است.',
  'Could not read the clipboard — paste with Ctrl+V.': 'خواندن کلیپ‌بورد ممکن نشد — با Ctrl+V جای‌گذاری کنید.',
  'Sort servers by ping': 'مرتب‌سازی سرورها بر اساس پینگ',
  'Off keeps the original order of the tab.': 'خاموش، ترتیب اصلی تب را نگه می‌دارد.',
  'Disconnect and finish any active ping test before scanning.': 'پیش از اسکن، اتصال را قطع کنید و تست پینگ در حال اجرا را تمام کنید.',
  'A scan is already running.': 'یک اسکن در حال اجراست.',
  'No scannable config here. Locked, expired or incompatible configs are skipped.': 'اینجا کانفیگ قابل‌اسکنی نیست. کانفیگ‌های قفل‌شده، منقضی یا ناسازگار نادیده گرفته می‌شوند.',
  'Custom ranges are on but no valid range is entered. Add a range or turn the option off.': 'رنج سفارشی روشن است اما رنج معتبری وارد نشده. رنجی اضافه کنید یا گزینه را خاموش کنید.',
  'Checking real proxy ping…': 'در حال بررسی پینگ واقعی پروکسی…',
  'Scanning Cloudflare IPs…': 'در حال اسکن آی‌پی‌های کلودفلر…',
  'Scanning server {0} of {1}': 'اسکن سرور {0} از {1}',
  'How hard the clean-IP scanner works, for both single and group scans.': 'میزان سختی کار اسکنر آی‌پی تمیز؛ هم برای اسکن تکی و هم اسکن گروهی.',
  'Use manual ping limit': 'استفاده از محدودیت دستی پینگ',
  'On: take the first stable IP within the limit. Off: choose the lowest stable real ping among the tested candidates.': 'روشن: اولین آی‌پی پایدار در محدودهٔ زیر پذیرفته می‌شود. خاموش: کمترین پینگ واقعی پایدار میان کاندیداهای آزمایش‌شده انتخاب می‌شود.',
  'Maximum allowed ping (ms)': 'بیشینهٔ پینگ مجاز (میلی‌ثانیه)',
  'Probes public Cloudflare edges: up to 1 MB per healthy candidate, potentially hundreds of MB (data charges may apply). Edge results are preliminary; applying to a server requires real proxy ping plus 3 stability checks. Disconnect first. Locked and incompatible servers cannot be changed.': 'اسکن لبه‌های عمومی کلودفلر برای هر آی‌پی سالم تا ۱ مگابایت و در مجموع احتمالاً صدها مگابایت داده مصرف می‌کند؛ ممکن است هزینهٔ اینترنت داشته باشد. نتایج اولیهٔ لبه فقط سلامت لبه را نشان می‌دهند؛ اعمال روی سرور نیازمند پینگ واقعی و ۳ تأیید پایداری است. ابتدا اتصال را قطع کنید. سرورهای قفل‌شده یا ناسازگار تغییر نمی‌کنند.',
  'Custom Cloudflare IP ranges': 'رنج آی‌پی سفارشی کلودفلر',
  'Use my own IP ranges': 'استفاده از رنج‌های آی‌پی خودم',
  'On: the scanner looks for a clean IP only inside the ranges entered below instead of the built-in Cloudflare ranges.': 'روشن: اسکنر برای پیدا کردن آی‌پی تمیز فقط داخل رنج‌هایی که پایین وارد می‌کنید می‌گردد، نه رنج‌های پیش‌فرض کلودفلر.',
  'IP ranges': 'رنج‌های آی‌پی',
  'Budget {0} · timeout {1} ms · tries {2} · parallel {3}': 'بودجه {0} · وقفه {1} میلی‌ثانیه · تلاش {2} · موازی {3}',
  'Enter 50–5000 ms. The last valid saved limit remains in use until a valid value is entered.': 'عددی بین ۵۰ تا ۵۰۰۰ میلی‌ثانیه وارد کنید. تا ورود مقدار معتبر، آخرین حد معتبر ذخیره‌شده به‌کار می‌رود.',
  '50–5000 ms. If no confirmed candidate is within the enabled limit, keep the current server endpoint.': 'بازهٔ مجاز ۵۰ تا ۵۰۰۰ میلی‌ثانیه است. اگر هیچ کاندیدای تأییدشده‌ای زیر سقف فعال نباشد، آدرس فعلی سرور حفظ می‌شود.',
  'Invalid or non-public entry: {0}': 'ورودی نامعتبر یا غیرعمومی: {0}',
  'One per line: CIDR (104.16.0.0/20), single IP (104.16.1.5) or range (104.16.1.1-104.16.1.80). Public IPv4 only.': 'هر مورد در یک خط: CIDR (104.16.0.0/20)، آی‌پی تکی (104.16.1.5) یا بازه (104.16.1.1-104.16.1.80). فقط IPv4 عمومی.',
  '{0} range(s), {1} addresses': '{0} رنج، {1} آدرس',
  'Scan clean IP': 'اسکن آی‌پی تمیز',
  'Scan tab': 'اسکن آی‌پی تمیزِ سرورهای این تب',
  'Subscription sources': 'مدیریت منابع اشتراک',
  'Default': 'پیش‌فرض',
  'Connection profiles': 'پروفایل‌های اتصال',
  'Rename profile': 'تغییر نام پروفایل',
  'Delete profile': 'حذف پروفایل',
  'Import settings': 'ورود تنظیمات',
  'Profile imported and applied.': 'پروفایل وارد و اعمال شد.',
  'Profile exported without secrets.': 'پروفایل بدون اطلاعات حساس خروجی گرفته شد.',
  'Export selected profile (non-secret)': 'خروجی پروفایل انتخاب‌شده (غیرمحرمانه)',
  'Save current settings as a new profile': 'ذخیرهٔ تنظیمات فعلی به‌عنوان پروفایل جدید',
  'Preparing Aether…': 'در حال آماده‌سازی اتر…',
  'Aether could not finish loading. Please restart the app.': 'آماده‌سازی اتر کامل نشد. برنامه را دوباره اجرا کنید.',
  'Retry': 'تلاش مجدد',
  'This tab and all its configs will be permanently deleted. All cannot be deleted.': 'این تب و تمام کانفیگ‌های آن برای همیشه حذف می‌شوند. تب «همه» حذف‌شدنی نیست.',

  'Use this config': 'استفاده از این کانفیگ',
  'Test ping': 'تست پینگ',
  'Paste one or more links, a JSON config or a subscription address': 'یک یا چند لینک، کانفیگ JSON یا آدرس اشتراک را وارد کنید',
  'Paste from clipboard': 'جای‌گذاری از کلیپ‌بورد',
  'Import now': 'اکنون وارد کن',
  'Keepalive': 'زنده‌نگه‌داشتن اتصال (Keepalive)',
  'your-team': 'نام-سازمان-شما',

  // --- ۱.۴.۰ — پیام‌های وضعیت موتور (زنجیره‌ها، تور، سایفون، ناظر) ---
  'Testing configs in the active group…': 'در حال آزمایش کانفیگ‌ها در گروه فعال…',
  'Switching to the best healthy config…': 'در حال انتقال به بهترین کانفیگ سالم…',
  'Starting Psiphon through Tor…': 'در حال راه‌اندازی سایفون از طریق تور…',
  'Starting the tunnel through Tor…': 'در حال راه‌اندازی تونل از طریق تور…',
  'Initial verification skipped': 'راستی‌آزمایی اولیه رد شد',
  'Initial verification skipped — data path is up; health monitoring continues.': 'راستی‌آزمایی اولیه رد شد — مسیر داده برقرار است؛ پایش سلامت ادامه دارد.',
  'Watchdog reconnect…': 'اتصال مجدد ناظر خودکار…',
  'Tor is not moving inside the tunnel — trying the next strategy…': 'ترافیک تور در داخل تونل عبور نمی‌کند — در حال آزمایش راهبرد بعدی…',
  'Reaching the Tor network… {p}%': 'در حال اتصال به شبکه تور… {p}%',
  'Edit tab': 'ویرایش تب',
  'Tab options': 'گزینه‌های تب',
  'Psiphon (custom chain)': 'سایفون (زنجیرهٔ سفارشی)',
  'Pipeline: {chain} (custom config chain)': 'خط لوله: {chain} (زنجیرهٔ کانفیگ سفارشی)',
  'SOCKS5 port is up — bringing up the data path.': 'پورت SOCKS5 بالا آمد — در حال برقراری مسیر داده.',
  'All checks passed — tunnel is ready.': 'همهٔ بررسی‌ها موفق بود — تونل آماده است.',
  'Watchdog confirmed a persistent upstream failure — restarting the engine.': 'ناظر خودکار خرابی پایدار مسیر بالادست را تأیید کرد — در حال راه‌اندازی مجدد موتور.',
  'Xray keeps exiting — rebuilding the whole session.': 'Xray پیوسته خارج می‌شود — در حال بازسازی کامل نشست.',
  'The engine keeps dying — giving up after repeated restarts.': 'موتور پیوسته از کار می‌افتد — پس از چند راه‌اندازی مجدد متوقف شد.',
  'Smart Auto tried every strategy and none passed the self-test on this network.': 'حالت هوشمند همهٔ راهبردها را آزمود و هیچ‌کدام در این شبکه از خودآزمایی عبور نکرد.',
  'Auto-select lowest delay': 'انتخاب خودکار کمترین پینگ',
  'Health interval': 'بازه پایش سلامت',
  // --- ۱.۳.۰ — پیام‌ها و اطلاعیه‌ها (پنجرهٔ «تازه‌ها»؛ پورت از اندروید ۱.۵.۰) ---
  'All': 'همه',
  'New tab': 'تب جدید',
  'Rename tab': 'تغییر نام تب',
  'Delete tab': 'حذف تب',
  'Move to tab': 'انتقال به تب',
  'Config tabs': 'تب\u200cهای کانفیگ',
  'Server actions': 'عملیات سرور',
  'Server / Ping': 'سرور / پینگ',
  'Port': 'پورت',
  'QR from image': 'کد QR از تصویر',
  'Import QR from an image file; no camera is required.': 'ورود کد QR از فایل تصویر؛ نیازی به دوربین نیست.',
  'Smart: racing independent connection tactics…': 'هوشمند: آزمون موازی راهکارهای مستقل اتصال…',
  'Link or text': 'لینک یا متن',
  'Import file': 'وارد کردن فایل',
  'Name': 'نام',
  'Default on for all six built-in modes. Turning off skips optional initial connection checks, not engine startup, Tor bootstrap, exit-IP lookup or ongoing health monitoring.': 'پیش‌فرض برای شش حالت اصلی روشن است. خاموش‌کردن، تست اختیاری اولیه را رد می‌کند؛ نه راه‌اندازی هسته، آماده‌سازی Tor، دریافت IP خروجی یا پایش مداوم سلامت اتصال را.',
  'Real delay: a request through each config': 'تأخیر واقعی: یک درخواست از داخل هر کانفیگ',
  'Verify connection': 'راستی\u200cآزمایی اتصال',
  'Only skips the initial check; core startup and health monitoring stay enabled.': 'فقط بررسی اولیه رد می\u200cشود؛ راه\u200cاندازی هسته و پایش سلامت فعال می\u200cمانند.',
  'Add subscription': 'افزودن اشتراک',
  'Subscription name': 'نام اشتراک',
  'HTTPS subscription URL': 'نشانی HTTPS اشتراک',
  'Refresh': 'به\u200cروزرسانی',
  'Delete subscription?': 'اشتراک حذف شود؟',
  'Configs remain in All.': 'کانفیگ\u200cها در تب همه باقی می\u200cمانند.',
  'Unexpected HTTP status': 'وضعیت HTTP غیرمنتظره',
  'Partial response': 'پاسخ ناقص',
  'Next': 'بعدی',
  'Messages & announcements': 'پیام‌ها و اطلاعیه‌ها',
  "What's new in this version and the connection guide, any time": 'تازه‌های این نسخه و راهنمای اتصال، هر زمان که خواستید',
  'Version {0}': 'نسخهٔ {0}',
  'Release notes and guide for the current version.': 'اطلاعیه و راهنمای نسخهٔ فعلی برنامه.',
  // --- ۱.۳.۰ — کانفیگ‌های سفارشی (پورت از اندروید ۱.۵.۰؛ بدونِ QR) ---
  'Custom configs': 'کانفیگ‌های سفارشی',
  'Your own VLESS, VMess, Trojan, Shadowsocks, SOCKS, WireGuard or npvt server, alone or chained': 'سرورِ خودتان با <bdi>VLESS</bdi>، <bdi>VMess</bdi>، <bdi>Trojan</bdi>، <bdi>Shadowsocks</bdi>، <bdi>SOCKS</bdi>، <bdi>WireGuard</bdi> یا <bdi>npvt</bdi> — تنها یا زنجیره‌ای',
  'Custom config': 'کانفیگ سفارشی',
  'Use a custom config': 'استفاده از کانفیگ سفارشی',
  'Off: Aether runs exactly as before. On: the next connection runs the chain below.': 'خاموش: اتر دقیقاً مثل قبل کار می‌کند. روشن: اتصالِ بعدی زنجیرهٔ زیر را اجرا می‌کند.',
  'Import a config first, then pick it in the list.': 'اول یک کانفیگ وارد کنید و بعد آن را در فهرست انتخاب کنید.',
  'Chain': 'زنجیره',
  'Config': 'کانفیگ',
  'Single · the config alone': 'تکی · فقط کانفیگ',
  'Double chain': 'زنجیرهٔ دوتایی',
  'Triple chain': 'زنجیرهٔ سه‌تایی',
  'Where the config sits in the route. Config first: the engine dials out through it. Config last: it dials out through the engine. Changes apply at the next connection.': 'جای کانفیگ در مسیر. کانفیگ اول: موتور از دلِ آن بیرون می‌رود. کانفیگ آخر: کانفیگ از دلِ موتور بیرون می‌رود. تغییرها از اتصالِ بعدی اعمال می‌شوند.',
  'Import': 'وارد کردن',
  'Link, subscription or config': 'لینک، اشتراک یا کانفیگ',
  'Paste one or more share links, a full Xray JSON config, a base64 subscription, an npvt config, or a single https:// subscription address.': 'یک یا چند لینکِ اشتراک‌گذاری، یک کانفیگِ کاملِ <bdi>Xray JSON</bdi>، اشتراکِ <bdi>base64</bdi>، کانفیگِ <bdi>npvt</bdi> یا یک نشانیِ اشتراکِ <bdi>https://</bdi> بچسبانید.',
  'Choose file…': 'انتخاب فایل…',
  '…or drop a .npvt, .txt, .json or .conf file on this window.': '…یا یک فایلِ <bdi>.npvt</bdi>، <bdi>.txt</bdi>، <bdi>.json</bdi> یا <bdi>.conf</bdi> را روی همین پنجره رها کنید.',
  'QR codes are not supported on Windows (no camera or image scanner). Use a link, a subscription or a file instead.': 'کد <bdi>QR</bdi> در نسخهٔ ویندوز پشتیبانی نمی‌شود (دوربین و اسکنرِ تصویر ندارد). به‌جایش از لینک، اشتراک یا فایل استفاده کنید.',
  'Saved configs': 'کانفیگ‌های ذخیره‌شده',
  'No configs yet.': 'هنوز کانفیگی وارد نشده است.',
  'Delete all configs': 'حذف همهٔ کانفیگ‌ها',
  'Removes every imported config from this PC.': 'همهٔ کانفیگ‌های واردشده از این رایانه پاک می‌شوند.',
  'Delete all configs?': 'همهٔ کانفیگ‌ها حذف شوند؟',
  'Every imported config is removed from this PC. This cannot be undone.': 'همهٔ کانفیگ‌های واردشده از این رایانه پاک می‌شوند. این کار برگشت‌پذیر نیست.',
  'Delete all': 'حذف همه',
  'Delete this config?': 'این کانفیگ حذف شود؟',
  'Edit config': 'ویرایش کانفیگ',
  'Rename': 'تغییر نام',
  'Copy link': 'کپی لینک',
  'Locked': 'قفل‌شده',
  'Expired': 'منقضی‌شده',
  'Expired on {0}': 'در {0} منقضی شد',
  'Expires on {0}': 'انقضا: {0}',
  'Password': 'رمز',
  'Unlock': 'باز کردن',
  'This npvt config is password protected.': 'این کانفیگِ <bdi>npvt</bdi> رمز دارد.',
  'Wrong password for this npvt config.': 'رمزِ این کانفیگِ <bdi>npvt</bdi> اشتباه است.',
  'This config is locked by its author.': 'این کانفیگ را سازنده‌اش قفل کرده است.',
  'Paste a link or config first.': 'اول یک لینک یا کانفیگ بچسبانید.',
  '1 config imported.': 'یک کانفیگ وارد شد.',
  '{0} configs imported.': '{0} کانفیگ وارد شد.',
  'Something went wrong.': 'مشکلی پیش آمد.',
  // --- Clean IP scanner ---
  'Clean IP scanner': 'اسکنر IP تمیز',
  'Finds a fast Cloudflare IP for Cloudflare-fronted configs and writes it into the config. Disconnect first.': 'برای کانفیگ‌های پشت Cloudflare یک IP سریع پیدا می‌کند و در کانفیگ می‌نویسد. ابتدا اتصال را قطع کنید.',
  'Options': 'تنظیمات',
  'Scan': 'اسکن',
  'Clear': 'پاک کردن',
  'Scanning…': 'در حال اسکن…',
  'Validating with Real Delay…': 'اعتبارسنجی با Real Delay…',
  'Clean IP applied': 'IP تمیز اعمال شد',
  'Not better than current': 'بهتر از IP فعلی نبود',
  'Cancelled': 'لغو شد',
  'Failed': 'ناموفق',
  'Fast': 'سریع',
  'Deep': 'عمیق',
  'Scan depth': 'عمق اسکن',
  'Ping ceiling (ms)': 'سقف پینگ (میلی‌ثانیه)',
  'Use custom IP ranges': 'استفاده از رنج IP سفارشی',
  'ranges': 'رنج',
  'invalid': 'نامعتبر',
  'Options are locked while a scan runs.': 'هنگام اسکن، تنظیمات قفل است.',
  // --- ۱.۳.۰ — پینگِ واقعی (Xrayِ موقت + generate_204) ---
  'Ping': 'پینگ',
  'Test all': 'پینگ همه',
  'Testing…': 'در حالِ تست…',
  'No response': 'بی‌پاسخ',
  'Server off': 'سرور خاموش',
  'Filtered': 'فیلتر شده',
  'Invalid config': 'کانفیگ نامعتبر',
  'No network': 'شبکه در دسترس نیست',
  'a real-delay test is already running': 'یک تستِ پینگ در حالِ اجراست',
  'the bundled Xray core (engine\\xray\\xray.exe) is missing — reinstall Aether': 'هستهٔ Xrayِ همراه (engine\\xray\\xray.exe) پیدا نشد — اتر را دوباره نصب کنید',
  'the test was interrupted': 'تست نیمه‌کاره ماند',
  'file is larger than 2 MB': 'حجم فایل بیش از ۲ مگابایت است',
  'file could not be read': 'فایل خوانده نشد',
  'Starting the custom config…': 'در حال راه‌اندازیِ کانفیگ سفارشی…',
  'Checking the custom config…': 'در حال بررسیِ کانفیگ سفارشی…',
  'Starting Psiphon…': 'در حال راه‌اندازیِ سایفون…',
  'This custom config has expired. Import a fresh one or pick another config.': 'این کانفیگِ سفارشی منقضی شده است. یک کانفیگِ تازه وارد کنید یا کانفیگِ دیگری انتخاب کنید.',
  'This custom config is locked to mobile data by its author, so it cannot run on Windows.': 'سازندهٔ این کانفیگ آن را به اینترنتِ موبایل محدود کرده، پس روی ویندوز اجرا نمی‌شود.',
  'Custom configs need the bundled Xray core (engine\\xray\\xray.exe), which this installation is missing. Reinstall Aether.': 'کانفیگ‌های سفارشی به هستهٔ همراهِ <bdi>Xray</bdi> (<bdi>engine\\xray\\xray.exe</bdi>) نیاز دارند که در این نصب نیست. اتر را دوباره نصب کنید.',
  'The custom config could not start: Xray exited. Check the config, or open the diagnostics log.': 'کانفیگِ سفارشی اجرا نشد: <bdi>Xray</bdi> بسته شد. کانفیگ را بررسی کنید یا لاگِ عیب‌یابی را ببینید.',
  'The custom config opens no outbound connection. The server may be down or blocked on this network.': 'کانفیگِ سفارشی هیچ اتصالی به بیرون باز نمی‌کند. ممکن است سرور خاموش باشد یا روی این شبکه بسته شده باشد.',
  'The custom config did not open its local port in time (Xray). Check the config, or open the diagnostics log.': 'کانفیگِ سفارشی پورتِ محلی‌اش را به‌موقع باز نکرد (<bdi>Xray</bdi>). کانفیگ را بررسی کنید یا لاگِ عیب‌یابی را ببینید.',
  'empty input': 'ورودی خالی است',
  'no supported config found': 'هیچ کانفیگِ پشتیبانی‌شده‌ای پیدا نشد',
  'link has no server address': 'لینک نشانیِ سرور ندارد',
  'link has no user id': 'لینک شناسهٔ کاربر ندارد',
  'link has no user id / password': 'لینک شناسهٔ کاربر یا رمز ندارد',
  'link has no valid port': 'لینک پورتِ معتبر ندارد',
  'the JSON could not be read': 'این <bdi>JSON</bdi> خوانده نشد',
  'the JSON has no proxy outbound': 'این <bdi>JSON</bdi> هیچ <bdi>outbound</bdi>ِ پروکسی ندارد',
  'npvt file could not be decrypted': 'فایلِ <bdi>npvt</bdi> رمزگشایی نشد',
  'this npvt config has expired': 'این کانفیگِ <bdi>npvt</bdi> منقضی شده است',
  'this npvt config is bound to specific devices by its author': 'سازندهٔ این کانفیگِ <bdi>npvt</bdi> آن را به دستگاه‌های مشخصی محدود کرده است',
  'this npvt config is restricted by its author to mobile data only, which a Windows PC cannot honour': 'سازندهٔ این کانفیگِ <bdi>npvt</bdi> آن را فقط به اینترنتِ موبایل محدود کرده و رایانهٔ ویندوزی نمی‌تواند این شرط را رعایت کند',
  'the HTTP/2 (h2) transport was removed from Xray; ask for an XHTTP config': 'ترابرِ <bdi>HTTP/2 (h2)</bdi> از <bdi>Xray</bdi> حذف شده؛ کانفیگِ <bdi>XHTTP</bdi> بخواهید',
  'the QUIC transport was removed from Xray': 'ترابرِ <bdi>QUIC</bdi> از <bdi>Xray</bdi> حذف شده است',
  'unsupported file type (use .npvt, .txt, .json or .conf)': 'نوعِ فایل پشتیبانی نمی‌شود (<bdi>.npvt</bdi>، <bdi>.txt</bdi>، <bdi>.json</bdi> یا <bdi>.conf</bdi>)',
  'unsupported file type (use .npvt, .npvs, .txt, .json or .conf)': 'نوعِ فایل پشتیبانی نمی‌شود (<bdi>.npvt</bdi>، <bdi>.npvs</bdi>، <bdi>.txt</bdi>، <bdi>.json</bdi> یا <bdi>.conf</bdi>)',
  'file is not UTF-8 text': 'این فایل متنِ <bdi>UTF-8</bdi> نیست',
  'binary NPVS files must be imported as bytes': 'فایل‌های باینریِ <bdi>NPVS</bdi> باید به‌صورت بایت وارد شوند',
  'NPVO1 file is too large': 'فایل NPVO1 بیش از حد بزرگ است',
  'NPVO1 file is nested too deeply': 'ساختار فایل NPVO1 بیش از حد تودرتوست',
  'not an NPVO1 file': 'این فایل NPVO1 نیست',
  'the NPVO1 file holds no servers': 'فایل NPVO1 هیچ سروری ندارد',
  'NPVO1 body is not a JSON object': 'محتوای فایل NPVO1 معتبر نیست',
  'locked NPVO1 files are not supported': 'فایل‌های NPVO1 قفل‌شده پشتیبانی نمی‌شوند',
  'NPVO1 file has no configs array': 'فایل NPVO1 فهرست کانفیگ ندارد',
  'NPVO1 file holds too many servers': 'فایل NPVO1 سرورهای بیش از حد دارد',
  'invalid NPVO1 server': 'یکی از سرورهای NPVO1 نامعتبر است',
  'NPVO1 V2Ray profile missing': 'پروفایل V2Ray در فایل NPVO1 وجود ندارد',
  'unsupported NPVO1 server type': 'نوع سرور NPVO1 پشتیبانی نمی‌شود',
  'invalid NPVO1 endpoint': 'نشانی سرور NPVO1 نامعتبر است',
  'NPVO1 credentials missing': 'مشخصات ورود سرور NPVO1 وجود ندارد',
  'bad npvs1 value encoding': 'رمزگذاری یکی از مقادیر npvs1 نامعتبر است',
  'NPVS authentication failed': 'اصالت فایلِ <bdi>NPVS</bdi> تأیید نشد؛ فایل آسیب‌دیده یا دستکاری شده است',
  'NPVS creator signature is invalid': 'امضای سازندهٔ فایلِ <bdi>NPVS</bdi> نامعتبر است؛ فایل دستکاری شده یا ناقص است',
  'NPVS recipient-bound config requires its owner\'s device key': 'این فایلِ <bdi>NPVS</bdi> به دستگاهِ گیرندهٔ خودش قفل شده و روی این رایانه باز نمی‌شود',
  'NPVS device attestation is not supported': 'اعتبارسنجیِ سخت‌افزاریِ دستگاه در این نسخه پشتیبانی نمی‌شود',
  'NPVS length exceeds limit': 'اندازهٔ بخش‌های فایلِ <bdi>NPVS</bdi> از حدِ مجاز بیشتر است',
  'NPVS length overflow': 'اندازهٔ بخش‌های فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'NPVS config nesting is too deep': 'ساختارِ کانفیگِ <bdi>NPVS</bdi> بیش‌ازحد تودرتوست',
  'NPVS config table missing': 'جدولِ کانفیگ‌ها در فایلِ <bdi>NPVS</bdi> نیست',
  'NPVS configs missing': 'فهرستِ کانفیگ‌ها در فایلِ <bdi>NPVS</bdi> نیست',
  'NPVS field is missing': 'یکی از فیلدهای فایلِ <bdi>NPVS</bdi> وجود ندارد',
  'NPVS field is not UTF-8': 'یکی از فیلدهای فایلِ <bdi>NPVS</bdi> متنِ معتبر نیست',
  'NPVS key derivation failed': 'مشتق‌سازیِ کلیدِ فایلِ <bdi>NPVS</bdi> ناموفق بود',
  'NPVS policy missing': 'سیاستِ فایلِ <bdi>NPVS</bdi> وجود ندارد',
  'NPVS server is not an object': 'ساختارِ یکی از سرورهای فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'bad NPVS app-key block': 'بخشِ کلیدِ برنامه در فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'bad NPVS cipher parameters': 'پارامترهای رمزنگاریِ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'bad NPVS key': 'کلیدِ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'bad NPVS sentinel encoding': 'کدگذاریِ یکی از مقادیرِ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS NPF body': 'بدنهٔ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS NPF trailer length': 'انتهای بدنهٔ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS body length': 'طولِ بدنهٔ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS config count': 'تعدادِ کانفیگ‌های فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS config table': 'جدولِ کانفیگ‌های فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS content key': 'کلیدِ محتوای فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS expiry': 'تاریخِ انقضای فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS field count': 'تعدادِ فیلدهای فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS metadata length': 'طولِ فرادادهٔ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'invalid NPVS metadata': 'فرادادهٔ فایلِ <bdi>NPVS</bdi> نامعتبر است',
  'too many NPVS recipients': 'تعدادِ گیرندگانِ فایلِ <bdi>NPVS</bdi> بیش از حدِ مجاز است',
  'truncated NPVS compact header': 'سرآیندِ فایلِ <bdi>NPVS</bdi> ناقص است',
  'truncated NPVS header': 'سرآیندِ فایلِ <bdi>NPVS</bdi> ناقص است',
  'truncated NPVS payload': 'فایلِ <bdi>NPVS</bdi> ناقص یا کوتاه‌شده است',
  'unsupported NPVS compact header': 'نسخهٔ سرآیندِ فایلِ <bdi>NPVS</bdi> پشتیبانی نمی‌شود',
  'unsupported NPVS envelope version': 'نسخهٔ پاکتِ فایلِ <bdi>NPVS</bdi> پشتیبانی نمی‌شود (فقط نسخهٔ ۵)',
  'unsupported NPVS password work factor': 'ضریبِ کارِ رمزِ فایلِ <bdi>NPVS</bdi> پشتیبانی نمی‌شود',
  'unsupported NPVS server or nested lock policy': 'سرورِ فایلِ <bdi>NPVS</bdi> (یا قفلِ تودرتو) پشتیبانی نمی‌شود',
  'unsupported NPVS unlock method': 'روشِ بازکردنِ فایلِ <bdi>NPVS</bdi> پشتیبانی نمی‌شود',
  'unsupported or duplicate NPVS field': 'فیلدِ ناپشتیبانی یا تکراری در فایلِ <bdi>NPVS</bdi>',
  'input is larger than 2 MB': 'حجمِ ورودی بیش از ۲ مگابایت است',
  'subscription is larger than 2 MB': 'حجمِ اشتراک بیش از ۲ مگابایت است',
  'subscription redirected to a non-https address': 'اشتراک به نشانیِ غیرِ <bdi>https</bdi> هدایت شد',
  'subscription redirected too many times': 'اشتراک بیش از حد هدایت شد',
  'locked configs cannot be edited': 'کانفیگِ قفل‌شده ویرایش‌پذیر نیست',
  'an edit must contain exactly one config': 'ویرایش باید دقیقاً یک کانفیگ داشته باشد',
  'Default · highest daily limit, best for continuous everyday use':
    'پیش‌فرض · سقف مصرف روزانهٔ بالا، بهینه برای استفادهٔ مداوم',
  'Very fast · reaches the free daily limit sooner':
    'سرعت بالا · رسیدن سریع‌تر به سقف محدودیت روزانه',
  'Flash-Lite family · high daily limit (alias/preview build)':
    'خانوادهٔ ⁨Flash-Lite⁩ · سقف روزانهٔ بالا (نسخهٔ پیش‌نمایش/نام مستعار)',


  // --- ۱.۴.۰ (پورت به ویندوز ۱.۳.۰): MTU دستی، ECH سفارشی، اندپوینتِ کش‌شده ---
  'Custom MTU': 'MTU دلخواه',
  'Safe range: 1280 to 9000 bytes. Lower it if connections stall.':
    'بازهٔ امن: ۱۲۸۰ تا ۹۰۰۰ بایت. اگر اتصال‌ها گیر می‌کنند، کمترش کنید.',
  'Only reuse a fast endpoint': 'فقط اندپوینت سریع را دوباره استفاده کن',
  'Quick reconnect skips the scan for the last endpoint that worked. With this on it is also checked for speed, and a slow one is replaced by a fresh scan instead of halving your download and upload for the whole session.':
    'اتصال مجدد سریع برای آخرین اندپوینتی که کار کرده بود اسکن را رد می‌کند. با روشن بودن این گزینه، سرعت آن هم سنجیده می‌شود و اندپوینت کند با یک اسکن تازه جایگزین می‌شود، به‌جای آنکه سرعت دانلود و آپلود شما تا آخر آن نشست نصف بماند.',
  'Encrypted Client Hello': 'کلاینت‌هلو رمزنگاری‌شده (ECH)',
  'Hide the destination name (SNI) from DPI': 'پنهان‌کردن نام مقصد (<bdi>SNI</bdi>) از <bdi>DPI</bdi>',
  'ECHConfigList (base64, optional)': '<bdi>ECHConfigList</bdi> (<bdi>base64</bdi>، اختیاری)',
  'Leave empty to let the engine fetch one. Paste a base64 ECHConfigList to use it instead — useful where fetching the default one is what your network blocks. Naming a different domain, as v2rayNG does, needs an engine change and is not possible here.':
    'خالی بگذارید تا موتور خودش بگیرد. یک <bdi>ECHConfigList</bdi> به شکل <bdi>base64</bdi> بچسبانید تا از همان استفاده شود — جایی به کار می‌آید که شبکه‌تان دقیقاً گرفتنِ نسخهٔ پیش‌فرض را بلاک می‌کند. دادن نام یک دامنهٔ دیگر، آن‌طور که <bdi>v2rayNG</bdi> می‌کند، نیاز به تغییر موتور دارد و اینجا ممکن نیست.',

  // --- ۱.۴.۰ (#66، #67): فهرست‌های هوشمند — همان values-fa موبایل ---
  'Smart lists': 'فهرست‌های هوشمند',
  'Bypass Iranian sites': 'بای‌پس سایت‌های ایرانی',
  'Iranian sites (.ir and Iranian IP ranges) open directly on this Windows PC only; shared devices stay in the tunnel.':
    'سایت‌های ایرانی (<bdi>.ir</bdi> و رنج آی‌پی ایران) فقط روی همین ویندوز مستقیم باز می‌شوند؛ دستگاه‌های اشتراکی داخل تونل می‌مانند.',
  'Block ads and trackers': 'حذف تبلیغات و ردیاب‌ها',
  'Blocks ad and tracker domains (HaGeZi Light list, refreshed weekly through the tunnel).':
    'دامنه‌های تبلیغاتی و ردیاب مسدود می‌شوند (لیست <bdi>HaGeZi Light</bdi>، به‌روزرسانی هفتگی از داخل تونل).',
  'built-in copy': 'نسخهٔ داخلی برنامه',
  '{0} Iranian IP ranges and {1} domains · updated {2}': '{0} رنج آی‌پی ایران و {1} دامنه · به‌روزرسانی {2}',
  '{0} ad and tracker domains · updated {1}': '{0} دامنهٔ تبلیغاتی و ردیاب · به‌روزرسانی {1}',

  // --- ۱.۴.۰ (#12): Zero Trust — اول ورود، بعد اتصال ---
  'Sign in before connecting': 'ورود پیش از اتصال',
  'Checking this device\u2019s membership\u2026': 'در حال بررسی عضویت این دستگاه…',
  'Login code': 'کد ورود',
  'Signed in as {0}. The next connect joins this device without asking for a code.':
    'با {0} وارد شده‌اید. اتصال بعدی بدون پرسیدن کد این دستگاه را عضو می‌کند.',
  '{0} day(s) left.': '{0} روز مانده.',
  'This device is already a member of {0}. Connecting needs no sign-in.':
    'این دستگاه از قبل عضو {0} است. برای وصل شدن ورود لازم نیست.',
  'Your sign-in has expired. Sign in again before connecting, or the code is asked for while connecting.':
    'اعتبار ورود شما تمام شده. پیش از وصل شدن دوباره وارد شوید، وگرنه کد در حین اتصال پرسیده می‌شود.',
  'The saved sign-in is for {0} in team {1}, not the address and team above. It will not be used: sign in again.':
    'ورود ذخیره‌شده برای {0} در تیم {1} است، نه نشانی و تیمِ بالا. از آن استفاده نمی‌شود: دوباره وارد شوید.',
  'A one-time code was e-mailed to {0}. Type it here to sign in.':
    'یک کد یک‌بارمصرف به {0} ایمیل شد. برای ورود، آن را اینجا وارد کنید.',
  'Not signed in yet. Sign in now and the connect will not stop to ask for a code. If you skip this, the code is asked for while connecting.':
    'هنوز وارد نشده‌اید. اگر الان وارد شوید، اتصال برای پرسیدن کد متوقف نمی‌شود. اگر این کار را نکنید، کد در حین اتصال پرسیده می‌شود.',
  'Enter the team name above to sign in or to see whether this device is already a member.':
    'برای ورود، یا برای دیدن اینکه این دستگاه از قبل عضو است یا نه، اول نام تیم را در بالا وارد کنید.',
  'Disconnect to sign in or to change the membership.': 'برای ورود یا تغییر عضویت، اول اتصال را قطع کنید.',
  'Sign in': 'ورود',
  'Send a new code': 'ارسال کد تازه',
  'Sign in again': 'ورود دوباره',
  'Forget this sign-in': 'فراموش کردن این ورود',
  'Enter your work e-mail above first.': 'اول ایمیل کاری خود را در بالا وارد کنید.',
  'Asking for a code\u2026': 'در حال درخواست کد…',
  'You can ask for a new code in {0} s.': 'تا {0} ثانیهٔ دیگر می‌توانید کد تازه بخواهید.',
  'Asking for a new code\u2026': 'در حال درخواست کد تازه…',
  'A new code is on its way. Only the newest code works.': 'کد تازه در راه است. فقط جدیدترین کد کار می‌کند.',
  'Enter the code from the e-mail.': 'کدِ داخل ایمیل را وارد کنید.',
  'Checking the code\u2026': 'در حال بررسی کد…',
  'Signed in. Connect now to join the organization.': 'وارد شدید. حالا وصل شوید تا عضو سازمان شوید.',
  'Sign-in forgotten.': 'ورود فراموش شد.',
  // پیام‌های خطای zt_signin.rs (Failure::message) و main.rs
  'That team name is not valid.': 'این نام تیم معتبر نیست.',
  'That e-mail address is not valid.': 'این نشانی ایمیل معتبر نیست.',
  'This team does not offer sign-in with an e-mail code.': 'این تیم ورود با کد ایمیلی را ارائه نمی‌کند.',
  'Cloudflare refused the request (HTTP {0}).': '<bdi>Cloudflare</bdi> درخواست را رد کرد (<bdi>HTTP {0}</bdi>).',
  'Cloudflare did not start a code session. Try again.': '<bdi>Cloudflare</bdi> نشستِ کد را شروع نکرد. دوباره امتحان کنید.',
  'Ask for a code first.': 'اول کد بخواهید.',
  'That code was not accepted (HTTP {0}). Check it, or ask for a new one.':
    'این کد پذیرفته نشد (<bdi>HTTP {0}</bdi>). آن را بررسی کنید، یا کد تازه بخواهید.',
  'Cloudflare returned an unusable token.': '<bdi>Cloudflare</bdi> توکنی برگرداند که قابل استفاده نیست.',
  'The request thread stopped unexpectedly.': 'رشتهٔ درخواست ناگهان متوقف شد.',

  // --- ۱.۲.۵: پیام‌های شکستِ تور (از diagnostics.rs، از راهِ snapshot.detail)
  'The tunnel started but the self-test failed.':
    'تونل بالا آمد ولی خودآزما شکست خورد.',
  'The tunnel is up, but Tor never reported any progress from inside it. Try Tor on its own, which lets Tor pick its own way to the network.':
    'تونل بالاست، ولی تور از داخلش هیچ پیشرفتی گزارش نکرد. «تنها تور» را امتحان کنید تا تور خودش راهش به شبکه را انتخاب کند.',
  'The tunnel is up, but Tor stopped at {0}% inside it and did not reach the Tor network. Try another protocol for the tunnel, or Tor on its own with bridges.':
    'تونل بالاست، ولی تور داخلش روی {0}٪ ایستاد و به شبکهٔ تور نرسید. پروتکل دیگری برای تونل امتحان کنید، یا «تنها تور» با پل.',
  'Tor stopped at {0}% and could not reach the Tor network. No pluggable transport is installed, so only plain bridges can be tried — and a network that filters Tor usually blocks those too. Use the Aether → Tor mode: Tor is then dialled through the tunnel, where the operator cannot see or block it.':
    'تور روی {0}٪ ایستاد و به شبکهٔ تور نرسید. هیچ ترابرِ افزودنی نصب نیست، پس فقط پلِ ساده ممکن است — و شبکه‌ای که تور را فیلتر می‌کند معمولاً آن را هم می‌بندد. از حالتِ <bdi>Aether → Tor</bdi> استفاده کنید: آن‌وقت تور از داخلِ تونل شماره‌گیری می‌شود، جایی که اپراتور نه می‌بیندش نه می‌تواند ببندد.',
  'The engine started but Tor never reported any progress towards the Tor network, and no pluggable transport is installed. Use the Aether → Tor mode, which builds Tor inside the tunnel.':
    'موتور اجرا شد ولی تور هیچ پیشرفتی به سمتِ شبکهٔ تور گزارش نکرد، و هیچ ترابرِ افزودنی نصب نیست. از حالتِ <bdi>Aether → Tor</bdi> استفاده کنید که تور را داخلِ تونل می‌سازد.',
  // --- v12 (۱.۲.۴-p4): صفحهٔ گفت‌وگو، پورت از AiChatScreen.kt ---
  // ترجمه‌ها همان `ai_chat_*` در values-fa/strings.xml هستند؛ جملهٔ تازه‌ای
  // ساخته نشده تا کاربری که موبایل را می‌شناسد همان کلمات را ببیند.
  'Chat': 'گفت‌وگو',
  'Chat with Gemini': 'گفت‌وگو با جمینای',
  'Open the chat': 'باز کردن گفت‌وگو',
  'Ask anything, or say what you want changed': 'هر چیزی بپرسید، یا بگویید چه چیزی عوض شود',
  'Model: {0}': 'مدل: {0}',
  '{0} message(s) in the conversation': '{0} پیام در گفت‌وگو',
  'Hi, I am Aether AI': 'سلام، من هوش مصنوعی اتر هستم',
  'I can explain any setting in this app, read this session’s log and propose tuning, or just answer a question.':
    'می‌توانم هر تنظیمی در این برنامه را توضیح بدهم، لاگ همین نشست را بخوانم و تنظیمات پیشنهاد کنم، یا فقط به سؤالتان جواب بدهم.',
  'Why is my connection slow right now?': 'چرا اتصالم الان کند است؟',
  'Which protocol should I use on mobile data?': 'روی دیتای همراه چه پروتکلی بهتر است؟',
  'Explain MTU and pick the best one for me': 'MTU را توضیح بده و بهترینش را انتخاب کن',
  'Make the tunnel harder to detect': 'تونل را سخت‌تر قابل تشخیص کن',
  'Ask Aether AI…': 'از هوش مصنوعی اتر بپرسید…',
  'Stop': 'توقف',
  'Clear the conversation': 'پاک کردن گفت‌وگو',
  'Thinking…': 'در حال فکر کردن…',
  'Copy answer': 'کپی پاسخ',
  'Copied': 'کپی شد',
  'Could not copy — your system refused clipboard access.': 'کپی نشد — سیستم شما اجازهٔ دسترسی به کلیپ‌بورد را نداد.',
  'Try again': 'تلاش مجدد',
  'Edit': 'ویرایش',
  'Delete': 'حذف',
  'edited': 'ویرایش‌شده',
  'Cancel': 'انصراف',
  'Edit message': 'ویرایش پیام',
  'Send again': 'ارسال دوباره',
  'Everything after this message will be removed and the assistant will answer the edited question.':
    'هر چیزی پس از این پیام حذف می‌شود و دستیار به پرسش ویرایش‌شده پاسخ می‌دهد.',
  '{0} selected': '{0} مورد انتخاب شد',
  'Select all': 'انتخاب همه',
  'Cancel selection': 'لغو انتخاب',
  'Delete selected': 'حذف موارد انتخاب‌شده',
  // تأییدِ حذف — یک دیالوگ برای هر سه مسیر (سطلِ حباب، حذفِ گروهی، پاک‌کردنِ همه).
  // متن‌ها از `ai_chat_delete_*` در `values-fa/strings.xml` موبایل می‌آیند.
  'Delete {0} message(s)?': '{0} پیام حذف شود؟',
  'This cannot be undone. Deleted messages are no longer sent to the assistant as context.':
    'این کار قابل بازگشت نیست. پیام‌های حذف‌شده دیگر به‌عنوان زمینهٔ گفت‌وگو برای دستیار فرستاده نمی‌شوند.',
  'Clear the whole conversation?': 'کلِ گفت‌وگو پاک شود؟',
  Clear: 'پاک کردن',
  // کارتِ تنظیماتِ پیشنهادی و دیالوگِ پس از اعمال — از `ai_changes_title`،
  // `ai_apply`، `ai_applied`، `ai_apply_note` و `ai_applied_dialog_*` موبایل.
  'Proposed settings ({0})': 'تنظیمات پیشنهادی ({0})',
  Apply: 'اعمال',
  Applied: 'اعمال شد',
  'Tunnel settings are handed to the engine when it starts, so these take effect on your next connect.':
    'تنظیمات تونل هنگام راه‌اندازی به موتور داده می‌شوند، پس این تغییرها در اتصال بعدی اثر می‌گذارند.',
  'Saved for the next connection': 'برای اتصال بعدی ذخیره شد',
  'The new settings are stored, but the tunnel is already running with the old ones. Tunnel settings are handed to the engine when it starts, so disconnect and connect again for them to take effect.':
    'تنظیمات جدید ذخیره شد، اما تونل همچنان با تنظیمات قبلی در حال اجراست. تنظیمات تونل هنگام شروع به موتور داده می‌شود؛ پس یک‌بار قطع و دوباره وصل کنید تا اعمال شوند.',
  'Got it': 'متوجه شدم',
  // پایکِ حبابِ ✨ و پرسشی که به گفت‌وگو منتقل می‌کند.
  'Did not understand? Ask the assistant': 'متوجه نشدید؟ از دستیار بپرسید',
  'Explain this more simply: “{0}”. This is what the app told me: {1}':
    'این را ساده‌تر توضیح بده: «{0}». چیزی که برنامه به من گفت این بود: {1}',
  // جمله‌های شکست — از `errorKind` ساخته می‌شوند، نه از متنِ خامِ گوگل.
  'Google rejected this key. Check it in AI Studio, or paste it again.':
    'گوگل این کلید را رد کرد. آن را در <bdi>AI Studio</bdi> بررسی کنید یا دوباره بچسبانید.',
  'The free quota for this key is used up for now. Try again later.':
    'سهمیهٔ رایگان این کلید فعلاً تمام شده. بعداً دوباره تلاش کنید.',
  'This key cannot use the selected model. Discover the models again.':
    'این کلید نمی‌تواند از مدل انتخاب‌شده استفاده کند. مدل‌ها را دوباره کشف کنید.',
  'The request never reached Google. Check the tunnel and try again.':
    'درخواست هرگز به گوگل نرسید. تونل را بررسی کنید و دوباره تلاش کنید.',
  'Google failed on its own side. This is not your connection — try again.':
    'گوگل سمت خودش شکست خورد. مشکل از اتصال شما نیست — دوباره تلاش کنید.',
  'Google sent back something this app could not read.': 'گوگل چیزی برگرداند که این برنامه نتوانست بخواند.',
  'The answer was cut off before it finished.': 'پاسخ پیش از تمام‌شدن بریده شد.',
  'The model returned no answer.': 'مدل هیچ پاسخی برنگرداند.',
  'The request failed.': 'درخواست شکست خورد.',
  // --- v12 (۱.۲.۳): بک‌اند ترابرد زنجیره‌ای ---
  'Transport': 'ترابرد',
  'Backend': 'بک‌اند',
  'Exit country': 'کشور خروجی',
  'Search country': 'جستجوی کشور',
  'Automatic': 'خودکار',
  'Aether alone exits through a Cloudflare WARP edge. Chaining Psiphon keeps Aether as the first hop and swaps the exit for an ordinary hosting IP, which is what opens sites that reject WARP ranges.':
    'اِتِر تنها از یک لبهٔ <bdi>Cloudflare WARP</bdi> بیرون می‌رود. زنجیره‌کردن <bdi>Psiphon</bdi> هاپ اول را همان اِتِر نگه می‌دارد و خروجی را با یک آی‌پی هاستینگ عادی عوض می‌کند؛ همین است که سایت‌هایی را باز می‌کند که رنج‌های <bdi>WARP</bdi> را رد می‌کنند.',
  'Only applies to the chained backend. If no server is reachable in that country, Aether falls back to an automatic exit instead of hanging.':
    'فقط برای بک‌اند زنجیره‌ای است. اگر در آن کشور هیچ سروری در دسترس نباشد، اِتِر به‌جای معلق‌ماندن به خروجی خودکار برمی‌گردد.',
  'Starting the Psiphon stage…': 'در حال راه‌اندازی مرحلهٔ <bdi>Psiphon</bdi>…',
  'Waiting for engine-managed Psiphon…': 'در انتظار راه‌اندازی سایفون توسط هسته…',
  'Rebuilding the chain…': 'بازسازی زنجیره…',
  // --- v12 (۱.۲.۴): دستیار هوش مصنوعی ---
  'Assistant': 'دستیار',
  'Gemini API key': 'کلید API جمینای',
  'The key is stored sealed on this PC with Windows DPAPI and is never written to the log.':
    'کلید روی همین رایانه با <bdi>DPAPI</bdi> ویندوز مهر و ذخیره می‌شود و هرگز در لاگ نوشته نمی‌شود.',
  'Save': 'ذخیره',
  'Forget': 'فراموش کن',
  'No key stored.': 'کلیدی ذخیره نشده.',
  'A key ending in …{0} is stored.': 'کلیدی که به …{0} ختم می‌شود ذخیره است.',
  'Get a free key from Google AI Studio': 'یک کلید رایگان از <bdi>Google AI Studio</bdi> بگیرید',
  'Model': 'مدل',
  'Only fast Flash-class models are offered: they answer on a free key.':
    'فقط مدل‌های سریعِ ردهٔ <bdi>Flash</bdi> پیشنهاد می‌شوند؛ همان‌هایی که روی کلید رایگان پاسخ می‌دهند.',
  'Discover models for this key': 'کشف مدل‌های این کلید',
  'No models discovered yet.': 'هنوز مدلی کشف نشده.',
  'Add a key first.': 'اول یک کلید وارد کنید.',
  'Tune for my network': 'تنظیم برای شبکهٔ من',
  'Reads the recent connection log — with addresses masked and identifiers removed — and changes at most one or two transport settings.':
    'لاگ اخیر اتصال را می‌خواند — با نشانی‌های ماسک‌شده و شناسه‌های حذف‌شده — و حداکثر یکی دو تنظیم ترابرد را عوض می‌کند.',
  'Analyse and tune': 'تحلیل و تنظیم',
  'Changed': 'تغییر داده شد',
  'Nothing needed changing.': 'چیزی نیاز به تغییر نداشت.',
  'Refused by the app': 'ردشده توسط برنامه',
  'Dismiss': 'بستن',
  'Ask anything': 'هر چه می‌خواهید بپرسید',
  'Ask about a setting, an error, or censorship…': 'دربارهٔ یک تنظیم، یک خطا، یا فیلترینگ بپرسید…',
  'Send': 'بفرست',
  'Clear conversation': 'پاک‌کردن گفت‌وگو',
  'Close': 'بستن',
  'Ask the assistant about this setting': 'از دستیار دربارهٔ این تنظیم بپرس',
  'Add your Gemini API key to use the assistant.': 'برای استفاده از دستیار، کلید <bdi>API</bdi> جمینای را وارد کنید.',
  'No model has been discovered for this key yet.': 'هنوز هیچ مدلی برای این کلید کشف نشده است.',
  'The assistant needs the tunnel to be connected — Google is not reachable otherwise.':
    'دستیار به تونلِ وصل نیاز دارد — وگرنه گوگل در دسترس نیست.',
  'Switch the connection to Aether → Psiphon: Google refuses the Cloudflare WARP addresses that Aether alone exits from.':
    'اتصال را به «اِتِر ← <bdi>Psiphon</bdi>» عوض کنید: گوگل نشانی‌های <bdi>Cloudflare WARP</bdi> را که اِتِرِ تنها از آن‌ها بیرون می‌رود رد می‌کند.',
  'The assistant is not available right now.': 'دستیار در این لحظه در دسترس نیست.',
  // --- v12 (۱.۲.۴): منوی تنظیمات (پورت a2) ---
  'Settings': 'تنظیمات',
  'Tunnel settings': 'تنظیمات تونل',
  'Back': 'بازگشت',
  'On': 'روشن',
  'Tunnel': 'تونل',
  'Connection': 'اتصال',
  'Network backend, exit country, protocol and scanning': 'بک‌اند شبکه، کشور خروجی، پروتکل و اسکن',
  'Transport & anti-DPI': 'ترابرد و ضدDPI',
  'Obfuscation, endpoint, MTU and anti-DPI': 'مبهم‌سازی، اندپوینت، <bdi>MTU</bdi> و ضدDPI',
  'DNS & routing rules': 'DNS و قواعد مسیریابی',
  'Resolvers inside the tunnel, block and bypass lists': 'ریزالورهای داخل تونل، فهرست‌های مسدود و عبور',
  'Upstream proxy (chaining)': 'پروکسی بالادست (زنجیره‌ای)',
  'Dial out through a proxy already running on this PC': 'خروج از طریق پروکسی‌ای که همین حالا روی این رایانه اجراست',
  'Kill switch & leak protection': 'قطع‌کن و محافظت از نشتی',
  'What happens the moment the tunnel drops': 'وقتی تونل می‌افتد چه می‌شود',
  'Join a Cloudflare organisation instead of plain WARP': 'به‌جای <bdi>WARP</bdi> ساده، عضو یک سازمان <bdi>Cloudflare</bdi> شوید',
  'Application': 'برنامه',
  'Apps & LAN sharing': 'برنامه‌ها و اشتراک شبکه',
  'Which programs use the tunnel, and who else may': 'کدام برنامه‌ها از تونل استفاده کنند، و چه کسی دیگر اجازه دارد',
  'Interface language': 'زبان رابط کاربری',
  'Reset all settings to defaults': 'بازنشانی همهٔ تنظیمات به پیش‌فرض',
  'Every setting goes back to its default, including endpoint ranges, routing rules and enrolment details.':
    'هر تنظیم به مقدار پیش‌فرضش برمی‌گردد، از جمله بازه‌های اندپوینت، قواعد مسیریابی و جزئیات ثبت‌نام.',
  'Reset every setting to its default?': 'همهٔ تنظیمات به پیش‌فرض برگردند؟',
  'The tunnel is running. Changes are saved now and handed to the engine the next time it starts — reconnect to apply them.':
    'تونل در حال اجراست. تغییرها همین حالا ذخیره می‌شوند و در استارت بعدی به هسته داده می‌شوند — برای اعمال، دوباره وصل شوید.',
  // --- پوسته (منو + نوار عنوان) ---
  'Home': 'خانه',
  'Advanced': 'پیشرفته',
  'Diagnostics': 'عیب‌یابی',
  'Share over LAN': 'اشتراک در شبکه',
  'About': 'درباره',
  'Add config': 'افزودن کانفیگ',
  'min': 'دقیقه',
  'h': 'ساعت',
  's': 'ثانیه',
  'Aether AI': 'هوش مصنوعی اتر',
  'Diagnostics & logs': 'عیب‌یابی و لاگ‌ها',
  'Share VPN': 'اشتراک‌گذاری VPN',
  'Gemini inside the app: explain, optimize and chat': 'Gemini داخل برنامه: توضیح، بهینه‌سازی و چت',
  'Ask anything, or say what should change': 'هر چیزی بپرسید، یا بگویید چه چیزی عوض شود',
  'Connection, apps, security and troubleshooting': 'اتصال، برنامه‌ها، امنیت و عیب‌یابی',
  'Live status of every part of the tunnel': 'وضعیت زنده‌ی همه‌ی بخش‌های تونل',
  'Use this computer as a proxy for other devices': 'استفاده از این سیستم به‌عنوان پراکسی برای دستگاه‌های دیگر',
  'Makers, links and what changed in this version': 'سازندگان، لینک‌ها و تغییرات این نسخه',
  'Menu': 'منو',
  'Aether': 'اِتِر',

  // --- صفحهٔ اصلی ---
  'Freedom, in one tap': 'آزادی، در یک لمس',
  'Tap to connect securely': 'برای اتصال امن لمس کنید',
  'Tap to disconnect': 'برای قطع اتصال لمس کنید',
  'Something went wrong': 'مشکلی پیش آمد',
  'Verifying connection…': 'در حال راستی‌آزمایی اتصال…',
  'Disconnected': 'قطع',
  'Starting engine…': 'در حال راه‌اندازی موتور…',
  'Connecting…': 'در حال اتصال…',
  'Verifying…': 'در حال راستی‌آزمایی…',
  'Connected': 'متصل',
  'Reconnecting…': 'اتصال دوباره…',
  'Disconnecting…': 'در حال قطع اتصال…',
  'Connection failed': 'اتصال ناموفق بود',
  'Your IP': 'آی‌پی شما',
  'Server IP': 'آی‌پی سرور',
  'Checking IP…': 'در حال بررسی آی‌پی…',
  'IP unavailable': 'آی‌پی در دسترس نیست',
  'Connected for': 'مدت اتصال',
  'Protocol': 'پروتکل',
  'Gool mode': 'حالت GOOL',
  'Modern: WireGuard inside MASQUE, the core 2.4.0 default.': 'نوین: وایرگارد داخل MASQUE، حالت پیش‌فرض هسته ۲.۴.۰.',
  'Classic: the older WireGuard-inside-WireGuard mode.': 'سنتی: حالت قدیمی وایرگارد داخل وایرگارد.',
  'Modern (MASQUE)': 'نوین (بستر MASQUE)',
  'Classic (WireGuard)': 'سنتی (بستر WireGuard)',
  'MASQUE×2': 'MASQUE×2',
  'Smart': 'هوشمند',
  'Endpoint': 'نقطهٔ اتصال',
  'Latency': 'تأخیر',
  'Download': 'دانلود',
  'Upload': 'آپلود',

  // --- ۱.۲.۴: کارت اتصال (پورت از ConnectionCard.kt) ---
  'Total': 'مجموع',
  'Ping strength': 'قدرت پینگ',
  'Excellent': 'عالی',
  'Good': 'خوب',
  'Fair': 'متوسط',
  'Poor': 'ضعیف',
  'Measuring…': 'در حال سنجش…',
  'Offline': 'قطع',

  // --- v1.2.0: محافظت در برابر نشتی WebRTC ---
  'Connection safety': 'امنیت اتصال',
  'Kill switch': 'کیل‌سوییچ',
  'Block browser traffic if the tunnel drops': 'اگر تونل قطع شد، ترافیک مرورگرها را مسدود می‌کند',
  'IPv6 leak protection': 'محافظت در برابر نشت IPv6',
  'Keep the IPv6 default route protected or block it safely': 'مسیر پیش‌فرض IPv6 را داخل مسیر امن نگه می‌دارد یا ایمن مسدود می‌کند',
  'Automatic reconnect attempts': 'تعداد تلاش‌های اتصال مجدد خودکار',
  'WebRTC protected — no IP leak': 'WebRTC محافظت شد — بدون نشت آی‌پی',
  'WebRTC is leaking your real IP': 'WebRTC آی‌پی واقعی شما را لو می‌دهد',
  'Checking for WebRTC leaks…': 'در حال بررسی نشتی WebRTC…',
  'WebRTC leak test': 'آزمایش نشتی WebRTC',
  'Testing for WebRTC leaks…': 'در حال آزمایش نشتی WebRTC…',

  // --- تنظیمات پیشرفته ---
  'Language': 'زبان برنامه',
  'Scan mode': 'حالت اسکن',
  'IP version': 'نسخهٔ آی‌پی',
  'Noize': 'نویز',
  // v17: گزینه‌های حالت اسکن و نویز — تا کل صفحهٔ پیشرفته فارسی باشد.
  'Turbo': 'توربو',
  'Balanced': 'متعادل',
  'Thorough': 'موشکافانه',
  'Stealth': 'پنهان‌کار',
  'Ironclad': 'آهنین',
  'Light': 'ملایم',
  'Firewall': 'فایروال',
  'GFW': 'فیلترینگ چین (GFW)',
  'Aggressive': 'تهاجمی',
  'Automatic': 'خودکار',
  'Manual peer': 'سرور دستی',
  'Manual range': 'بازهٔ دستی',
  'Peer address': 'آدرس سرور',
  'Address range': 'بازهٔ آدرس',
  'Off': 'خاموش',
  'Both': 'هر دو',
  'Quick reconnect': 'اتصال مجدد سریع',
  'Reconnect instantly after a drop': 'بعد از قطعی بلافاصله دوباره وصل می‌شود',
  'MASQUE over HTTP/2': '<bdi>MASQUE</bdi> روی <bdi>HTTP/2</bdi>',
  'Helps on networks that block HTTP/3': 'برای شبکه‌هایی که <bdi>HTTP/3</bdi> را مسدود می‌کنند',
  'Packet fragmentation': 'قطعه‌قطعه‌سازی بسته‌ها',
  'Splits the handshake to evade filtering': 'دست‌دادن <bdi>TLS</bdi> را تکه‌تکه می‌کند تا از فیلترینگ عبور کند',
  'Encrypted Client Hello (auto)': 'کلاینت‌هلو رمزنگاری‌شده (ECH) (خودکار)',
  'Let other devices on your network use this tunnel': 'دستگاه‌های دیگر شبکه بتوانند از این تونل استفاده کنند',
  'Split tunneling': 'تونل تفکیکی',
  'Only these apps': 'فقط این برنامه‌ها',
  'All except these': 'همه به‌جز این‌ها',
  'Applications': 'برنامه‌ها',
  'One executable name per line.': 'در هر خط نام یک فایل اجرایی (<bdi>exe</bdi>).',

  // --- v10: Zero Trust، مسیریابی و DNS (هستهٔ 1.5.0) ---
  'Zero Trust': '<bdi>Zero Trust</bdi> (سازمانی)',
  'Team name': 'نام تیم (سازمان)',
  'Connect as a managed device of a Cloudflare Zero Trust organization. Leave empty for normal WARP.': 'اتصال به‌عنوان دستگاه مدیریت‌شدهٔ یک سازمان <bdi>Cloudflare Zero Trust</bdi>. برای <bdi>WARP</bdi> معمولی خالی بگذارید.',
  'Sign-in method': 'روش ورود',
  'Email code': 'کد ایمیلی',
  'Service token': 'توکن سرویس',
  'Access token': 'توکن دسترسی',
  'Access email': 'ایمیل ورود',
  'A one-time code is sent to this mailbox on connect.': 'هنگام اتصال، یک کد یک‌بارمصرف به این صندوق ایمیل فرستاده می‌شود.',
  'Stored in memory only — never written to disk.': 'فقط در حافظه نگه داشته می‌شود — هرگز روی دیسک نوشته نمی‌شود.',
  'Gateway proxy': 'پروکسی <bdi>Gateway</bdi>',
  "Route HTTP/HTTPS through your organization's Gateway (adds a hop and logs browsing)": 'عبور <bdi>HTTP/HTTPS</bdi> از <bdi>Gateway</bdi> سازمان (یک هاپ اضافه می‌کند و مرور شما را لاگ می‌کند)',
  'Routing rules': 'قوانین مسیریابی',
  'Blocked destinations': 'مقصدهای مسدود',
  'One rule per line — domain, IP or CIDR. These connections are refused.': 'در هر خط یک قاعده — دامنه، آی‌پی یا <bdi>CIDR</bdi>. این اتصال‌ها کاملاً رد می‌شوند.',
  'Direct destinations': 'مقصدهای مستقیم',
  'One rule per line. These bypass the tunnel — for banking apps, LAN services and domestic sites.': 'در هر خط یک قاعده. این مقصدها از تونل عبور نمی‌کنند — برای بانک، سرویس‌های شبکهٔ محلی و سایت‌های داخلی.',
  'In-tunnel DNS servers': 'سرورهای <bdi>DNS</bdi> داخل تونل',
  'Resolvers used inside the tunnel. Empty = engine defaults.': 'حل‌کننده‌های نام داخل تونل. خالی = پیش‌فرض موتور.',
  'These features need engine core 1.5.0 or newer. The bundled core is older, so they are disabled.': 'این قابلیت‌ها به هستهٔ <bdi>1.5.0</bdi> یا بالاتر نیاز دارند. هستهٔ همراه این بیلد قدیمی‌تر است، پس غیرفعال شده‌اند.',

  // --- v11: پروکسی بالادست، تشخیص نام میزبان و هویت (هستهٔ 1.7.0) ---
  'Upstream proxy': 'پروکسی بالادست',
  'Proxy address': 'نشانی پروکسی',
  'Aether dials out through this proxy — use it to chain behind another VPN or proxy already running on this PC. Empty = direct.':
    'اِتِر همهٔ اتصال‌های بیرونی‌اش را از این پروکسی می‌گیرد — برای زنجیره‌کردن پشت یک <bdi>VPN</bdi> یا پروکسیِ در حال اجرا روی همین ویندوز. خالی = اتصال مستقیم.',
  'That is not a proxy address Aether can use. Expected socks5://host:port or http://host:port — the port is required.':
    'این نشانی برای اِتِر قابل‌استفاده نیست. قالب درست: <bdi>socks5://host:port</bdi> یا <bdi>http://host:port</bdi> — نوشتن پورت الزامی است.',
  'An HTTP proxy cannot carry UDP, so MASQUE is switched to HTTP/2 automatically and WireGuard / WARP×2 will not pass through it. Use a SOCKS5 proxy for those.':
    'پروکسی <bdi>HTTP</bdi> نمی‌تواند <bdi>UDP</bdi> حمل کند؛ پس <bdi>MASQUE</bdi> خودکار روی <bdi>HTTP/2</bdi> می‌رود و <bdi>WireGuard</bdi> و <bdi>WARP×2</bdi> از این پروکسی رد نمی‌شوند. برای آن‌ها از پروکسی <bdi>SOCKS5</bdi> استفاده کنید.',
  'SOCKS5 with UDP support carries every protocol: MASQUE, WireGuard and WARP×2.':
    'پروکسی <bdi>SOCKS5</bdi> با پشتیبانی <bdi>UDP</bdi> هر سه پروتکل را حمل می‌کند: <bdi>MASQUE</bdi>، <bdi>WireGuard</bdi> و <bdi>WARP×2</bdi>.',
  'Match domain rules by real host name': 'تطبیق قواعد دامنه با نام واقعی میزبان',
  'Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even though Windows hands the tunnel an IP address':
    'نام میزبان را از بایت‌های اول (<bdi>TLS SNI</bdi> یا هدر <bdi>Host</bdi>) می‌خواند؛ پس قواعد دامنه حتی وقتی ویندوز فقط یک آی‌پی به تونل می‌دهد هم کار می‌کنند',
  'Account identity': 'هویت حساب',
  'Replace a refused identity': 'جایگزینی هویتِ ردشده',
  'If Cloudflare stops accepting the saved device, register a fresh one instead of handshaking a tunnel that carries no traffic':
    'اگر <bdi>Cloudflare</bdi> دیگر دستگاه ذخیره‌شده را نپذیرد، یک دستگاه تازه ثبت می‌شود؛ وگرنه تونل دست می‌دهد ولی هیچ ترافیکی عبور نمی‌کند',
  'The upstream proxy, host-name routing and identity replacement need engine core 1.7.0 or newer. The bundled core is older, so they are disabled.':
    'پروکسی بالادست، مسیریابی براساس نام میزبان و جایگزینی هویت به هستهٔ <bdi>1.7.0</bdi> یا بالاتر نیاز دارند. هستهٔ همراه این بیلد قدیمی‌تر است، پس غیرفعال شده‌اند.',

  'Reset to defaults': 'بازنشانی به تنظیمات پیش‌فرض',
  'Restores every setting above to its factory value': 'همهٔ تنظیمات بالا به مقدار کارخانه برمی‌گردد',
  'Reset': 'بازنشانی',

  // --- عیب‌یابی ---
  'Run the test to verify connectivity': 'برای بررسی اتصال، آزمایش را اجرا کنید',
  'A problem was detected — see the failing check': 'مشکلی پیدا شد — بررسیِ ناموفق را ببینید',
  'All checks passed — traffic should flow': 'همهٔ بررسی‌ها موفق بود — ترافیک باید برقرار باشد',
  'Testing connectivity…': 'در حال آزمایش اتصال…',
  'Run test': 'اجرای آزمایش',
  'Copy logs': 'کپی لاگ‌ها',
  'Clear': 'پاک‌سازی',
  'Environment check': 'بررسی محیط',
  'Log': 'لاگ',
  'No logs yet. Connect or run a test.': 'هنوز لاگی ثبت نشده. متصل شوید یا آزمایش را اجرا کنید.',
  'Logs copied to clipboard': 'لاگ‌ها در کلیپ‌بورد کپی شد',
  'Running…': 'در حال اجرا…',

  // --- اشتراک در شبکه ---
  'Other devices on the same Wi‑Fi can route their traffic through this computer. Point them at one of the addresses below.': 'دستگاه‌های دیگر روی همین <bdi>Wi‑Fi</bdi> می‌توانند ترافیکشان را از این رایانه عبور دهند. یکی از آدرس‌های زیر را در آن‌ها وارد کنید.',
  'Enable sharing': 'فعال‌سازی اشتراک',
  'Only listens on your local network address.': 'فقط روی آدرس شبکهٔ محلی شما گوش می‌دهد.',
  'Copy': 'کپی',
  'Sharing only works while Aether is connected.': 'اشتراک فقط وقتی کار می‌کند که <bdi>Aether</bdi> متصل باشد.',
  'Both ports accept HTTP and SOCKS5 automatically — either port works in either field.': 'هر دو پورت به‌صورت خودکار هم <bdi>HTTP</bdi> و هم <bdi>SOCKS5</bdi> را می‌پذیرند — هر پورتی را هر جا وارد کنید کار می‌کند.',
  'Apps like Telegram ignore the system proxy; set a SOCKS5 proxy inside the app instead.': 'برنامه‌هایی مثل تلگرام پروکسی سیستم را نادیده می‌گیرند؛ در تنظیمات خودِ برنامه یک پروکسی <bdi>SOCKS5</bdi> تنظیم کنید.',

  // --- درباره ---
  'App version': 'نسخهٔ برنامه',
  'Core version': 'نسخهٔ هسته',
  'Architecture': 'معماری',
  'Credits, links & what this build adds': 'سازندگان، لینک‌ها و امکانات این بیلد',
  'Version': 'نسخه',
  'Original project — Cluvex Studio': 'پروژهٔ اصلی — <bdi>Cluvex Studio</bdi>',
  'The core engine powering this app': 'موتور اصلیِ این برنامه',
  'Windows edition — QW-AI-Code': 'نسخهٔ ویندوز — <bdi>QW-AI-Code</bdi>',
  'The native Windows desktop edition of Aether — what we upgraded in this build': 'نسخهٔ بومی ویندوزِ <bdi>Aether</bdi> — بهبودهای همین بیلد',

  // --- ۱.۲.۴-p1: ذخیرهٔ کلید و تست اتصال ---
  'Show': 'نمایش',
  'Hide': 'پنهان',
  'API key saved.': 'کلید API ذخیره شد.',
  'API key removed': 'کلید API حذف شد',
  'Test the API connection': 'تست اتصال به API',
  'Testing…': 'در حال تست…',
  'Checks the key and lists the models it may use': 'کلید را بررسی می‌کند و مدل‌هایی که اجازهٔ استفاده دارد را فهرست می‌کند',
  'Working — {0} model(s) available through {1}': 'سالم — {0} مدل از مسیر {1} در دسترس است',
  'Not working: {0}': 'کار نمی‌کند: {0}',
  // --- v13 (۱.۲.۵ / هستهٔ 2.0.0): تور -----------------------------------
  // ترجمه‌ها همان رشته‌های `tor_*` و `backend_help_*` در values-fa/strings.xml
  // هستند. نام کشورهای پل ترجمه نشده — نه در این برنامه (فهرست کشور خروجی هم
  // انگلیسی است) و نه در موبایل.
  'Tor': 'تور',
  'Bridges': 'پل‌ها',
  'How Tor reaches the network when it is blocked.': 'وقتی تور بلاک است، چگونه به شبکه برسد.',
  'Not needed in this mode: Tor is dialled through the Aether tunnel, so the network you are on never sees it.':
    'در این حالت لازم نیست: تور از داخل تونل اتر وصل می‌شود، پس شبکه‌ای که در آن هستید هرگز آن را نمی‌بیند.',
  'Always': 'همیشه',
  'Bridge country': 'کشور پل',
  'Detect automatically': 'تشخیص خودکار',
  'Which country bridgedb hands out bridges for. Detection asks the network where you are, which is the request most likely to fail here.':
    'اینکه <bdi>bridgedb</bdi> پل‌های مربوط به کدام کشور را بدهد. تشخیص خودکار از شبکه می‌پرسد کجا هستید، و همین درخواست بیشتر از هر چیز اینجا شکست می‌خورد.',
  'Bootstrap patience': 'مدت صبر برای بوت‌استرپ',
  'Automatic (75 s)': 'خودکار (۷۵ ثانیه)',
  '{0} seconds': '{0} ثانیه',
  'How long Tor tries the direct path before falling back to bridges. Shorten it where Tor is definitely blocked.':
    'تور چقدر مسیر مستقیم را امتحان کند پیش از رفتن به سراغ پل‌ها. اگر مطمئنید تور بلاک است، کوتاه‌ترش کنید.',
  'Own bridge lines': 'خطوط پل خودتان',
  'One per line, in the format bridges.torproject.org hands out. Leave empty to use the bridges the app fetches for your country. A line naming a transport the app does not ship is ignored.':
    'هر خط یکی، در قالبی که <bdi>bridges.torproject.org</bdi> می‌دهد. خالی بگذارید تا برنامه پل‌های مناسب کشور شما را خودش بگیرد. خطی که نام ترانسپورتی را بگوید که برنامه ندارد، نادیده گرفته می‌شود.',
  'Reachability check': 'بررسی دسترسی',
  'The address Tor must reach before the bootstrap counts as working. Change it only if bootstrap keeps failing on a Tor that seems fine \u2014 the default target is itself blocked on some networks.':
    'آدرسی که تور باید به آن برسد تا بوت‌استرپ موفق شمرده شود. فقط وقتی عوضش کنید که بوت‌استرپ مدام شکست می‌خورد در حالی که تور سالم به نظر می‌رسد — خود مقصد پیش‌فرض در بعضی شبکه‌ها بلاک است.',
  'Tor carries TCP only \u2014 in every app, on every platform. Aether answers DNS over TCP inside Tor and drops other UDP, so QUIC-capable apps fall back to TCP. That is normal and nothing is leaking: dropped UDP goes nowhere, least of all around Tor. Expect noticeably higher latency, and expect the first connect to take a while \u2014 Tor downloads its directory before it can build a circuit.':
    'تور فقط <bdi>TCP</bdi> را حمل می‌کند — در هر برنامه و روی هر پلتفرم. اتر <bdi>DNS</bdi> را روی <bdi>TCP</bdi> داخل تور پاسخ می‌دهد و بقیهٔ <bdi>UDP</bdi> را دور می‌ریزد، پس برنامه‌هایی که <bdi>QUIC</bdi> دارند به <bdi>TCP</bdi> برمی‌گردند. این طبیعی است و چیزی لیک نمی‌شود: <bdi>UDP</bdi> دورریخته به هیچ‌جا نمی‌رود، چه برسد به دور زدن تور. منتظر تاخیر محسوساً بیشتر باشید، و اینکه اولین اتصال طول بکشد — تور قبل از ساخت مدار، دایرکتوری خود را دانلود می‌کند.',
  'Fixed to MASQUE over HTTP/2 in this mode. Tor carries TCP only and WARP\u2019s WireGuard endpoints answer on UDP alone, so the engine refuses WireGuard and WARP\u00d72 here.':
    'در این حالت روی <bdi>MASQUE</bdi> بر <bdi>HTTP/2</bdi> قفل است. تور فقط <bdi>TCP</bdi> را حمل می‌کند و اندپوینت‌های <bdi>WireGuard</bdi> مربوط به <bdi>WARP</bdi> فقط روی <bdi>UDP</bdi> پاسخ می‌دهند، پس موتور اینجا <bdi>WireGuard</bdi> و <bdi>WARP×۲</bdi> را قبول نمی‌کند.',
  'Tor chooses its own exit node, and a new one per circuit. No setting can pin it to a country.':
    'تور خودش گره خروجی را انتخاب می‌کند، و برای هر مدار یکی تازه. هیچ تنظیمی آن را به یک کشور محدود نمی‌کند.',
  'The Tor modes need engine core 2.0.0 or newer. The bundled core is older, so they are disabled.':
    'حالت‌های تور به هستهٔ <bdi>2.0.0</bdi> یا بالاتر نیاز دارند. هستهٔ همراه این بیلد قدیمی‌تر است، پس غیرفعال شده‌اند.',

  // وضعیتِ زندهٔ bootstrap — همان `state_tor_*`. درصد را رابط جاگذاری می‌کند.
  'Reaching the Tor network… {0}%': 'در حال رسیدن به شبکهٔ تور… {0}%',
  'Reaching the Tor network…': 'در حال رسیدن به شبکهٔ تور…',
  'Tor is not getting through directly — trying bridges…': 'تور بلاک شده است — تلاش با پل‌ها…',
  'Tor is ready — opening its local proxy…': 'تور آماده است — در حال باز کردن پروکسی محلی آن…',

  // توضیحِ هر بک‌اند — همان `backend_help_*`.
  'One hop through the bundled Aether/WARP engine. Fastest.':
    'یک هاپ از موتور اتر/<bdi>WARP</bdi> همراه برنامه. سریع‌ترین حالت.',
  'Two hops: Aether connects first, then Psiphon tunnels through it. Your exit IP becomes Psiphon\u2019s, so sites that block Aether/WARP addresses open again.':
    'دو هاپ: اول اتر وصل می‌شود، بعد سایفون از داخل آن تونل می‌زند. آی‌پی خروجی شما به سایفون تغییر می‌کند، پس سایت‌هایی که آدرس‌های اتر/<bdi>WARP</bdi> را بلاک می‌کنند باز می‌شوند.',
  'Tor alone, without the Aether tunnel. Your exit is a Tor exit node and your traffic passes three relays, which is the slowest and the most private of the modes. Tor has to reach the Tor network by itself here, so it uses bridges when it is blocked.':
    'تور به تنهایی، بدون تونل اتر. خروجی شما یک گره خروجی تور است و ترافیک از سه رله می‌گذرد: کندترین و خصوصی‌ترین حالت. اینجا تور باید خودش به شبکهٔ تور برسد، پس اگر بلاک باشد از پل استفاده می‌کند.',
  'Two hops: Aether connects first, then Tor is built INSIDE that tunnel. The network you are on sees only Aether\u2019s obfuscated transport, never Tor \u2014 so this is the mode to use where Tor is blocked. Your exit is a Tor exit node.':
    'دو هاپ: اول اتر وصل می‌شود، بعد تور داخل همان تونل ساخته می‌شود. شبکه‌ای که در آن هستید فقط ترانسپورت مخفی‌شدهٔ اتر را می‌بیند، هرگز تور را — پس هر جا تور بلاک است، این حالت را انتخاب کنید. خروجی شما گره خروجی تور است.',
  'Three hops: Tor first, then Psiphon dialled through it. Your exit IP is Psiphon\u2019s, reached from a Tor address, so sites that block Tor exit nodes open again while your own address stays behind Tor. The slowest mode.':
    'سه هاپ: اول تور، بعد سایفون از داخل آن. آی‌پی خروجی شما مال سایفون است که از یک آدرس تور به آن رسیده‌اید؛ پس سایت‌هایی که گره‌های خروجی تور را بلاک می‌کنند باز می‌شوند و آدرس خود شما پشت تور می‌ماند. کندترین حالت.',
  'The reverse chain: Tor first, then the Aether tunnel built INSIDE it. Your exit is a WARP address \u2014 the same as plain Aether \u2014 but the network you are on sees only Tor, and cannot tell that a VPN tunnel exists at all. Use it where Cloudflare/WARP itself is blocked or throttled but Tor still gets through. Carries normal UDP, unlike the Tor-exit modes.':
    'زنجیرهٔ معکوس: اول تور، بعد تونل اتر داخل آن ساخته می‌شود. خروجی شما یک آدرس <bdi>WARP</bdi> است — همان چیزی که اتر ساده می‌دهد — اما شبکه‌ای که در آن هستید فقط تور را می‌بیند و اصلاً نمی‌تواند بفهمد که تونل <bdi>VPN</bdi>‌ی وجود دارد. جایی به کار بیاید که خود <bdi>Cloudflare/WARP</bdi> بلاک یا کند شده اما تور هنوز رد می‌شود. برخلاف حالت‌های با خروجی تور، <bdi>UDP</bdi> عادی را حمل می‌کند.',

  // --- 1.3.0-r4: رشته‌های صفحهٔ اتصال که ترجمه نشده بودند (a1/a2) ---
  'Network backend': 'بک‌اند شبکه',
  'Core': 'هسته',
  'Aether/WARP chooses its own anycast exit.':
    'اتر/<bdi>WARP</bdi> خروجیِ <bdi>anycast</bdi> خودش را انتخاب می‌کند.',
  'Psiphon treats this as a hard region filter. If it cannot establish there, the app retries automatically with an automatic exit.':
    'سایفون این را یک فیلتر قطعیِ منطقه می‌گیرد. اگر آنجا وصل نشود، برنامه خودکار با خروجیِ خودکار دوباره تلاش می‌کند.',
  'Smart tries the protocols one at a time, starting with the one most likely to work on this network, and keeps the first one that passes the self-test.':
    'حالت هوشمند پروتکل‌ها را یکی‌یکی امتحان می‌کند، از محتمل‌ترین گزینه برای همین شبکه شروع می‌کند و اولین پروتکلی را که از خودآزمایی سربلند بیرون بیاید نگه می‌دارد.',
  'There is no WARP tunnel in this mode: Tor carries the traffic by itself, so the protocol, scan mode and IP version are not used.':
    'در این حالت تونل <bdi>WARP</bdi> وجود ندارد: تور خودش ترافیک را می‌برد، پس پروتکل، حالت اسکن و نسخهٔ آی‌پی استفاده نمی‌شوند.',


  // --- ۱.۵.۰ (پورت از موبایل ۱.۵.۰): Zero Trust (عضویت، دیالوگ ورود، کد حین اتصال) و «اشتراک VPN» ---
  "A browser set to use a proxy still sends WebRTC on its own connection, which can reveal the device’s real IP. Open the setup page below on the other device: it tests WebRTC live and gives a one‑click lock for Chrome, Edge, Brave and Firefox. Phones: use v2rayNG / NekoBox in VPN mode with the SOCKS5 address.":
    "مرورگری که روی پراکسی تنظیم شده، ⁨WebRTC⁩ را همچنان از اینترنت خودش می‌فرستد و می‌تواند ⁨IP⁩ واقعی دستگاه را لو دهد. صفحهٔ تنظیم زیر را روی دستگاه دیگر باز کنید: ⁨WebRTC⁩ را زنده آزمایش می‌کند و برای کروم، اج، بریو و فایرفاکس قفل یک‌کلیکی می‌دهد. در گوشی‌ها از ⁨v2rayNG⁩ یا ⁨NekoBox⁩ در حالت ⁨VPN⁩ با آدرس ⁨SOCKS5⁩ استفاده کنید.",
  "Accepted: the organization issued an enrolment token for this service token.":
    "پذیرفته شد: سازمان برای این توکن سرویس یک توکن عضویت صادر کرد.",
  "Address copied":
    "آدرس کپی شد",
  "All details copied":
    "همهٔ مشخصات کپی شد",
  "Also reachable on these links (use the one the device is connected by)":
    "روی این اتصال‌ها هم در دسترس است (آدرس همان اتصالی را بزنید که دستگاه با آن وصل است)",
  "Asking your organization to e-mail a code to {0}…":
    "در حال درخواست از سازمان برای ارسال کد به ⁨{0}⁩…",
  "Asks your organization for an enrolment token exactly as the engine will when connecting. Nothing is stored.":
    "دقیقاً همان‌طور که موتور موقع اتصال این کار را می‌کند، از سازمان شما یک توکن عضویت می‌خواهد. چیزی ذخیره نمی‌شود.",
  "Automatic proxy (PAC) URL — easiest, fail‑closed":
    "نشانی پراکسی خودکار (⁨PAC⁩) — ساده‌ترین و ایمن‌ترین",
  "Cloudflare issued a token that is already expired. Check that this PC’s date and time are correct, then sign in again.":
    "کلادفلر توکنی داد که از همین حالا منقضی است. درست بودن تاریخ و ساعت این رایانه را بررسی کنید و دوباره وارد شوید.",
  "Cloudflare refused the request (HTTP {0}). Check the team name, and that this address is allowed to join.":
    "کلادفلر درخواست را رد کرد (⁨HTTP {0}⁩). نام تیم را بررسی کنید، و اینکه این نشانی اجازهٔ عضویت دارد.",
  "Connect the VPN first — sharing routes other devices through this PC’s tunnel.":
    "اول ⁨VPN⁩ را وصل کنید — اشتراک‌گذاری، دستگاه‌های دیگر را از طریق تونل همین رایانه عبور می‌دهد.",
  "Connect this PC to your home Wi‑Fi or wired network. The addresses appear here automatically.":
    "این رایانه را به وای‌فای یا شبکهٔ کابلی خانه وصل کنید. آدرس‌ها خودکار اینجا ظاهر می‌شوند.",
  "Copy all details":
    "کپی همهٔ مشخصات",
  "Could not reach {0} ({1}). Check the connection and try again. If Cloudflare is only reachable through your upstream proxy, skip signing in here: the code asked for while connecting goes through that proxy.":
    "دسترسی به ⁨{0}⁩ ممکن نشد (⁨{1}⁩). اتصال را بررسی کنید و دوباره امتحان کنید. اگر کلادفلر فقط از راه پراکسی بالادستیِ شما در دسترس است، از ورود در اینجا بگذرید: کدی که در حین اتصال پرسیده می‌شود از همان پراکسی می‌گذرد.",
  "Credentials saved":
    "مشخصات ذخیره شد",
  "Deletes the saved membership for this team only. The next connect joins again. Use it after your organization removed this device, or to join as someone else.":
    "فقط عضویت ذخیره‌شده برای همین تیم را پاک می‌کند و اتصال بعدی دوباره عضو می‌شود. وقتی سازمان این دستگاه را حذف کرده، یا می‌خواهید با کاربر دیگری عضو شوید، از این استفاده کنید.",
  "Deletes the saved sign-in from this PC. A membership this device already has is not affected.":
    "ورود ذخیره‌شده را از این رایانه پاک می‌کند. عضویتی که این دستگاه از قبل دارد دست نمی‌خورد.",
  "Disconnect first: the running tunnel is using this membership.":
    "اول اتصال را قطع کنید: تونلِ روشن از همین عضویت استفاده می‌کند.",
  "Enter both the client ID and the client secret first.":
    "اول شناسه و رمز کلاینت را هر دو وارد کنید.",
  "Enter on the other device (same Wi‑Fi)":
    "در دستگاه دیگر (روی همین وای‌فای) وارد کنید",
  "Enter your login code":
    "کد ورود را وارد کنید",
  "Ethernet address":
    "آدرس اترنت",
  "Everything the other device sends through the share leaves via the VPN tunnel only: DNS is resolved inside the tunnel, UDP is relayed through it, local/private targets are blocked, and if the tunnel drops, connections fail instead of going direct.":
    "هر چه دستگاه دیگر از طریق اشتراک بفرستد فقط از تونل ⁨VPN⁩ خارج می‌شود: ⁨DNS⁩ داخل تونل حل می‌شود، ⁨UDP⁩ از تونل عبور می‌کند، مقصدهای محلی مسدودند و اگر تونل قطع شود اتصال برقرار نمی‌شود، نه اینکه مستقیم برود.",
  "Generate a new password":
    "ساخت رمز جدید",
  "HTTP proxy — enter in system proxy settings":
    "پراکسی ⁨HTTP⁩ — در تنظیمات پراکسی سیستم وارد کنید",
  "How to connect":
    "روش اتصال",
  "In its Wi‑Fi / network settings choose Proxy → Automatic and paste the PAC URL (or Manual with the HTTP proxy). For apps and TUN clients (v2rayN, NekoBox, sing‑box) use the SOCKS5 address with remote DNS.":
    "در تنظیمات وای‌فای/شبکهٔ آن، پراکسی را روی «خودکار» بگذارید و نشانی ⁨PAC⁩ را بچسبانید (یا «دستی» با پراکسی ⁨HTTP⁩). برای برنامه‌ها و کلاینت‌های ⁨TUN⁩ مثل ⁨v2rayN⁩، ⁨NekoBox⁩ و ⁨sing-box⁩ از آدرس ⁨SOCKS5⁩ با ⁨DNS⁩ راه‌دور استفاده کنید.",
  "Make sure the other device is on the same Wi‑Fi (or wired network) as this PC.":
    "مطمئن شوید دستگاه دیگر به همان وای‌فای (یا شبکهٔ کابلی) این رایانه وصل است.",
  "Membership removed. The next connect joins again.":
    "عضویت حذف شد. اتصال بعدی دوباره عضو می‌شود.",
  "New code possible in {0} seconds":
    "کد تازه تا {0} ثانیهٔ دیگر",
  "New proxy password generated":
    "رمز جدید پراکسی ساخته شد",
  "Not a member yet. The next connect joins with the enrolment token above.":
    "هنوز عضو نیست. اتصال بعدی با توکن عضویتِ بالا عضو می‌شود.",
  "Not a member yet. The next connect joins with the service token above, without you.":
    "هنوز عضو نیست. اتصال بعدی با توکن سرویسِ بالا و بدون دخالت شما عضو می‌شود.",
  "Not accepted (HTTP {0}). Check the client ID and secret, and that the service token is allowed to enrol devices (Service Auth).":
    "پذیرفته نشد (⁨HTTP {0}⁩). شناسه و رمز را بررسی کنید، و اینکه این توکن سرویس اجازهٔ عضو کردن دستگاه (⁨Service Auth⁩) را دارد.",
  "Not now":
    "حالا نه",
  "Only traffic sent to the share is protected. A device or app that is not set to use it goes out on its own connection — a shared proxy cannot force other devices through the VPN.":
    "فقط ترافیکی که به اشتراک فرستاده شود محافظت می‌شود. دستگاه یا برنامه‌ای که روی آن تنظیم نشده باشد با اینترنت خودش بیرون می‌رود — یک پراکسیِ اشتراکی نمی‌تواند ترافیک دستگاه‌های دیگر را اجباری از ⁨VPN⁩ عبور دهد.",
  "Open the check page below in a browser: it only loads when the device is protected.":
    "صفحهٔ بررسی زیر را در مرورگر باز کنید: فقط وقتی دستگاه محافظت شود باز می‌شود.",
  "Opens a local proxy that devices on the same Wi‑Fi or wired network can use":
    "یک پراکسی محلی باز می‌کند که دستگاه‌های روی همین وای‌فای یا شبکهٔ کابلی می‌توانند استفاده کنند",
  "Optional — recommended on shared or public Wi‑Fi. Devices must sign in before using the share.":
    "اختیاری — در وای‌فای عمومی یا مشترک توصیه می‌شود. دستگاه‌ها پیش از استفاده باید وارد شوند.",
  "PC IP address":
    "آدرس ⁨IP⁩ رایانه",
  "Password must be at least {0} Latin characters.":
    "رمز باید دست‌کم ⁨{0}⁩ نویسهٔ لاتین باشد.",
  "Ports 10810/10811 are used by another app on this PC. Close it and toggle sharing again.":
    "پورت‌های ⁨10810/10811⁩ روی این رایانه توسط برنامهٔ دیگری استفاده می‌شوند. آن را ببندید و سوییچ را دوباره روشن کنید.",
  "Protection check page":
    "صفحهٔ بررسی محافظت",
  "Proxy password":
    "رمز پراکسی",
  "Proxy username":
    "نام کاربری پراکسی",
  "Remove the membership?":
    "عضویت حذف شود؟",
  "Remove this device’s membership":
    "حذف عضویت این دستگاه",
  "Remove":
    "حذف",
  "Require username & password":
    "الزام نام کاربری و رمز عبور",
  "SOCKS5 proxy — for apps that support SOCKS":
    "پراکسی ⁨SOCKS5⁩ — برای برنامه‌هایی که ⁨SOCKS⁩ پشتیبانی می‌کنند",
  "Send code":
    "ارسال کد",
  "Setup page + WebRTC test (open on the other device)":
    "صفحهٔ تنظیم + آزمایش ⁨WebRTC⁩ (روی دستگاه دیگر باز کنید)",
  "Share VPN":
    "اشتراک‌گذاری ⁨VPN⁩",
  "Share on this network":
    "اشتراک‌گذاری در این شبکه",
  "Share username & password":
    "نام کاربری و رمز اشتراک",
  "Sharing live · {0} connection(s)":
    "اشتراک فعال · ⁨{0}⁩ اتصال",
  "Sign in at https://{0}.cloudflareaccess.com/warp in a browser, then copy the value that follows token= and paste it here. Or pick E-mail code above to sign in inside the app instead.":
    "در مرورگر به ⁨https://{0}.cloudflareaccess.com/warp⁩ بروید و وارد شوید، بعد مقداری که پس از ⁨token=⁩ می‌آید را کپی و اینجا بچسبانید. یا به‌جایش در بالا «کد ایمیلی» را انتخاب کنید تا داخل خود برنامه وارد شوید.",
  "Sign in to {0}":
    "ورود به ⁨{0}⁩",
  "Signed in, but this PC could not store the result securely, so nothing was saved.":
    "وارد شدید، ولی این رایانه نتوانست نتیجه را به‌صورت امن ذخیره کند، پس چیزی ذخیره نشد.",
  "Starting sharing… if this takes more than a few seconds, toggle the switch off and on again.":
    "در حال راه‌اندازی اشتراک‌گذاری… اگر بیش از چند ثانیه طول کشید، سوییچ را خاموش و دوباره روشن کنید.",
  "Test the service token":
    "آزمایش توکن سرویس",
  "That code was not accepted either. Ask for a new code and try again.":
    "این کد هم پذیرفته نشد. یک کد تازه بخواهید و دوباره امتحان کنید.",
  "That code was not accepted. Attempt {0} of {1}.":
    "آن کد پذیرفته نشد. تلاش {0} از {1}.",
  "That e-mail address is not complete.":
    "این نشانی ایمیل کامل نیست.",
  "That team name is not valid. Use just the name, for example acme.":
    "این نام تیم معتبر نیست. فقط خود نام را بنویسید، مثلاً ⁨acme⁩.",
  "The code was sent, but Cloudflare’s answer lacked what the sign-in needs. Try again; if it keeps happening, the sign-in page has changed.":
    "کد فرستاده شد، ولی در پاسخ کلادفلر چیزی که ورود لازم دارد نبود. دوباره امتحان کنید؛ اگر تکرار شد، صفحهٔ ورود تغییر کرده است.",
  "The connection is waiting for this. It gives up after {0} seconds.":
    "اتصال منتظر همین است. بعد از {0} ثانیه منصرف می‌شود.",
  "The other device must sign in to the proxy with these:":
    "دستگاه دیگر باید با این مشخصات به پراکسی وارد شود:",
  "The sign-in carries no expiry date.":
    "این ورود تاریخ انقضا ندارد.",
  "The sign-in expires in under a minute.":
    "اعتبار ورود کمتر از یک دقیقهٔ دیگر تمام می‌شود.",
  "The sign-in is valid for {0} more day(s).":
    "ورود تا {0} روز دیگر معتبر است.",
  "The sign-in is valid for {0} more hour(s).":
    "ورود تا {0} ساعت دیگر معتبر است.",
  "The sign-in is valid for {0} more minute(s): connect before then.":
    "ورود تا {0} دقیقهٔ دیگر معتبر است: پیش از آن وصل شوید.",
  "This PC’s saved identity in {0} is deleted, and the next connect joins the organization again as a new device. Personal WARP and other teams are not touched. This cannot be undone.":
    "هویت ذخیره‌شدهٔ این رایانه در ⁨{0}⁩ پاک می‌شود و اتصال بعدی به‌عنوان یک دستگاه تازه دوباره عضو سازمان می‌شود. ⁨WARP⁩ شخصی و تیم‌های دیگر دست نمی‌خورند. این کار برگشت‌پذیر نیست.",
  "This does not look like a token. Copy the whole value that follows token= on the enrolment page.":
    "این شبیه توکن نیست. کل مقداری که در صفحهٔ عضویت پس از ⁨token=⁩ آمده را کپی کنید.",
  "This organization does not offer sign-in with an e-mailed code. Ask its administrator, or use a service token or an enrolment token instead.":
    "این سازمان ورود با کد ایمیلی را ارائه نمی‌کند. از مدیر آن بپرسید، یا به‌جایش از توکن سرویس یا توکن عضویت استفاده کنید.",
  "This token has expired. Sign in again and paste a fresh one.":
    "این توکن منقضی شده. دوباره وارد شوید و یک توکن تازه بچسبانید.",
  "Token looks valid but expires in under a day.":
    "توکن معتبر به‌نظر می‌رسد ولی کمتر از یک روز دیگر منقضی می‌شود.",
  "Token looks valid, expires in {0} day(s).":
    "توکن معتبر به‌نظر می‌رسد؛ {0} روز دیگر منقضی می‌شود.",
  "Token looks valid. It carries no expiry date.":
    "توکن معتبر به‌نظر می‌رسد. تاریخ انقضایی در آن نیست.",
  "Turn on sharing, and the addresses to enter on the other device appear here.":
    "اشتراک‌گذاری را روشن کنید؛ آدرس‌هایی که باید در دستگاه دیگر وارد شوند اینجا نمایش داده می‌شوند.",
  "Use this PC as a proxy for your laptop, phone or another computer":
    "استفاده از این رایانه به‌عنوان پراکسی برای لپ‌تاپ، گوشی یا رایانهٔ دیگر",
  "Username: 1–64 Latin characters, no spaces or \":\".":
    "نام کاربری: ۱ تا ۶۴ نویسهٔ لاتین، بدون فاصله و «:».",
  "WebRTC (real‑IP leak in browsers)":
    "⁨WebRTC⁩ (نشت ⁨IP⁩ واقعی در مرورگر)",
  "Wi‑Fi address":
    "آدرس وای‌فای",
  "Your organization e-mailed a one-time code to {0}. Type it here to finish joining.":
    "سازمان شما یک کد یک‌بارمصرف به ⁨{0}⁩ ایمیل کرد. برای کامل شدن عضویت، آن را اینجا وارد کنید.",
  "Your organization e-mailed you a one-time code. Type it here to finish joining.":
    "سازمان شما یک کد یک‌بارمصرف برایتان ایمیل کرد. برای کامل شدن عضویت، آن را اینجا وارد کنید.",
  "Your organization e-mails a one-time code to the address above, you type it here, and the result is kept encrypted on this PC for the next connect.":
    "سازمان شما یک کد یک‌بارمصرف به نشانی بالا ایمیل می‌کند، شما آن را اینجا وارد می‌کنید، و نتیجه برای اتصال بعدی به‌صورت رمزشده روی همین رایانه نگه داشته می‌شود.",
  "Membership":
    "عضویت",
  "Zero‑leak guard active":
    "محافظ ضدنشت فعال است",
  "Zero Trust sign-in was cancelled, so the connection was stopped. Sign in under Settings → Zero Trust, or connect again when you have the code.":
    "ورود ⁨Zero Trust⁩ لغو شد، پس اتصال متوقف شد. از «تنظیمات ← ⁨Zero Trust⁩» وارد شوید، یا وقتی کد را دارید دوباره وصل شوید.",
}

let current = (() => {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'fa' || v === 'en') return v
  } catch { /* localStorage ممکن است در دسترس نباشد */ }
  return 'en'
})()

export function getLang() {
  return current
}

// >>> AETHER-APP-PATCH ui-lang-on-disk (1.3.0)
// localStorage وب‌ویو تنها جای زبان بود و WebView2 گاهی آن را پیش از بستن روی
// دیسک نمی‌نوشت؛ برنامه دوباره انگلیسی باز می‌شد. main.js یک نویسنده ثبت می‌کند
// که زبان را در prefs.json سمت Rust هم بنویسد؛ اینجا وابستگی به Tauri نمی‌ماند.
let persistLang = null
export function setLangPersister(fn) {
  persistLang = typeof fn === 'function' ? fn : null
}

/** زبانِ خوانده‌شده از دیسک را بی‌نوشتنِ دوباره اعمال می‌کند. true = عوض شد. */
export function adoptStoredLang(lang) {
  if (lang !== 'fa' && lang !== 'en') return false
  try { localStorage.setItem(STORAGE_KEY, lang) } catch { /* بی‌اثر */ }
  if (lang === current) return false
  current = lang
  applyLang()
  return true
}
// <<< AETHER-APP-PATCH ui-lang-on-disk

export function setLang(lang) {
  current = lang === 'fa' ? 'fa' : 'en'
  try {
    localStorage.setItem(STORAGE_KEY, current)
  } catch { /* بی‌اثر */ }
  if (persistLang) {
    Promise.resolve()
      .then(() => persistLang(current))
      .catch((e) => console.error('saving UI language failed', e))
  }
  applyLang()
}

/** جهت و فونت کل سند را با زبان فعلی هماهنگ می‌کند. */
export function applyLang() {
  const fa = current === 'fa'
  const html = document.documentElement
  html.lang = fa ? 'fa' : 'en'
  html.dir = fa ? 'rtl' : 'ltr'
  document.body.classList.toggle('lang-fa', fa)
}

/** ترجمهٔ یک رشتهٔ رابط — کلید = متن انگلیسی. */
/**
 * `<bdi>` را به جداسازهای دوسویهٔ یونیکد تبدیل می‌کند و هر تگِ دیگر را دور
 * می‌ریزد.
 *
 * # چرا این تابع وجود دارد
 *
 * ترجمه‌های فارسی برای محافظت از تکه‌های لاتین (`chrome.exe`، `SOCKS5`) از
 * `<bdi>` استفاده می‌کنند، و `app.css` هم قاعده‌ای برایش دارد. ولی همهٔ نماها
 * متن را با `textContent` می‌نشانند — که تنها راه درست است، چون یک رشتهٔ ترجمه
 * هرگز نباید به‌عنوان HTML اجرا شود. نتیجه این بود که کاربر عیناً
 * `<bdi>chrome.exe</bdi>` را روی صفحه می‌دید.
 *
 * `U+2068 FIRST STRONG ISOLATE` و `U+2069 POP DIRECTIONAL ISOLATE` دقیقاً همان
 * کاری را می‌کنند که `<bdi>` می‌کرد — جداسازیِ دوسویه — ولی نویسه‌اند و نه
 * نشانه‌گذاری، پس در `textContent` هم کار می‌کنند و هیچ راهی برای تزریق باز
 * نمی‌کنند.
 */
export function isolateBidi(text) {
  if (typeof text !== 'string' || !text.includes('<')) return text
  return text
    .replace(/<bdi>/g, '\u2068')
    .replace(/<\/bdi>/g, '\u2069')
    // هر تگِ دیگری که از قلم افتاده باشد پاک می‌شود: به کاربر نشان دادنِ
    // `<b>` بهتر از اجرایش نیست.
    .replace(/<[^>]*>/g, '')
}


// ---------------------------------------------------------------------------
// ۱.۴.۰: خطاهای پویای بک‌اند (دانلود اشتراک، خطای سوکت ویندوز، NPVS و …) که متنِ
// دقیقشان از پیش معلوم نیست. به فارسی و قابل‌فهم برمی‌گردند؛ جزئیات فنی (کد خطا)
// در انتها می‌ماند تا برای عیب‌یابی قابل‌گزارش باشد.
const WIN_ERR = [
  [/10013|forbidden by its access permissions|access is denied|permission denied/i,
    'ویندوز یا فایروال/آنتی‌ویروس اجازهٔ اتصال شبکه به این برنامه را نداد (خطای ۱۰۰۱۳). برنامه را در فایروال مجاز کنید، VPN/پروکسی دیگر را خاموش کنید و دوباره تلاش کنید.'],
  [/10060|timed out|timeout/i, 'زمان اتصال به سرور تمام شد. اینترنت را بررسی کنید یا بعداً دوباره تلاش کنید.'],
  [/10061|connection refused/i, 'سرور اتصال را نپذیرفت.'],
  [/10054|connection reset/i, 'اتصال توسط سرور یا شبکه قطع شد.'],
  [/11001|no such host|dns|name or service not known|resolve/i, 'نشانی سرور پیدا نشد (خطای DNS). اینترنت یا نشانی لینک را بررسی کنید.'],
  [/certificate|tls|ssl|handshake/i, 'برقراری اتصال امن (TLS) با سرور ناموفق بود.'],
]
const STATIC_ERR = {
  'subscription is not UTF-8 text': 'محتوای اشتراک متن UTF-8 معتبر نیست.',
  'subscription is larger than 2 MB': 'اندازهٔ اشتراک بیش از ۲ مگابایت است.',
  'subscription redirected to a non-https address': 'اشتراک به نشانی غیر امن (غیر https) هدایت شد.',
  'subscription redirected too many times': 'اشتراک بیش از حد هدایت (ریدایرکت) شد.',
  'input is larger than 2 MB': 'ورودی بیش از ۲ مگابایت است.',
  'file is larger than 2 MB': 'فایل بیش از ۲ مگابایت است.',
  'not a file': 'مسیر انتخاب‌شده فایل نیست.',
  'file is not UTF-8 text': 'فایل، متن UTF-8 معتبر نیست.',
  'unsupported file type (use .npvt, .npvs, .txt, .json or .conf)': 'نوع فایل پشتیبانی نمی‌شود (از .npvt، .npvs، .txt، .json یا .conf استفاده کنید).',
  'binary NPVS files must be imported as bytes': 'فایل‌های باینری NPVS باید به‌صورت بایت وارد شوند.',
  'locked configs cannot be edited': 'کانفیگ‌های قفل‌شده قابل ویرایش نیستند.',
  'an edit must contain exactly one config': 'ویرایش باید دقیقاً یک کانفیگ داشته باشد.',
  'the system downloader also failed': 'دانلودکنندهٔ خود ویندوز هم موفق نشد.',
  'NPVS authentication failed': 'احراز اصالت فایل NPVS ناموفق بود؛ گذرواژه یا فایل نادرست است.',
  'NPVS creator signature is invalid': 'امضای سازندهٔ فایل NPVS معتبر نیست.',
  'NPVS device attestation is not supported': 'گواهی دستگاه در NPVS پشتیبانی نمی‌شود.',
  "NPVS recipient-bound config requires its owner's device key": 'این فایل NPVS به دستگاه گیرنده قفل شده و فقط روی همان دستگاه باز می‌شود.',
  'unsupported NPVS envelope version': 'نسخهٔ پاکت NPVS پشتیبانی نمی‌شود.',
  'unsupported NPVS unlock method': 'روش بازگشایی این NPVS پشتیبانی نمی‌شود.',
  'unsupported NPVS password work factor': 'ضریب کار گذرواژهٔ این NPVS بیش از حد مجاز است.',
  'invalid NPVS expiry': 'تاریخ انقضای NPVS نامعتبر است.',
  'truncated NPVS header': 'سرفایل NPVS ناقص است.',
  'truncated NPVS compact header': 'سرفایل فشردهٔ NPVS ناقص است.',
  'truncated NPVS payload': 'محتوای NPVS ناقص است.',
  'NPVS configs missing': 'فایل NPVS کانفیگی ندارد.',
}
function dynamicError(key) {
  if (typeof key !== 'string' || key.length < 8) return null
  if (STATIC_ERR[key]) return STATIC_ERR[key]
  let m = key.match(/^subscription download failed:\s*([\s\S]*)$/i)
  if (m) {
    const detail = m[1]
    const hit = WIN_ERR.find(([re]) => re.test(detail))
    const head = 'دانلود اشتراک ناموفق بود. '
    const code = detail.match(/os error (\d+)/i)
    return head + (hit ? hit[1] : 'اتصال به سرور اشتراک برقرار نشد.') + (code ? ` (کد ${code[1]})` : '')
  }
  m = key.match(/^subscription server answered HTTP (\d+)$/i)
  if (m) return `سرور اشتراک با کد HTTP ${m[1]} پاسخ داد.`
  m = key.match(/^file could not be read:/i)
  if (m) return 'خواندن فایل ممکن نشد.'
  if (/^(invalid|bad|unsupported|truncated|too many)\b.*NPVS|NPVS .*(missing|invalid|too deep|exceeds|failed|not UTF-8)/i.test(key)) return 'فایل NPVS نامعتبر یا پشتیبانی‌نشده است.'
  if (/\b(10013|10060|10061|10054|11001)\b|os error \d+/i.test(key)) {
    const hit = WIN_ERR.find(([re]) => re.test(key))
    if (hit) return hit[1]
  }
  return null
}

export function t(key) {
  const raw = current === 'fa' ? (FA[key] ?? dynamicError(key) ?? numbered(key) ?? key) : key
  return isolateBidi(raw)
}

/// دومین تلاشِ ترجمه برای جمله‌هایی که یک عدد داخلشان است.
///
/// وضعیتِ اتصال از سمتِ Rust به‌صورت **جملهٔ کامل** می‌آید (`snapshot.detail`)،
/// پس جمله‌ای مثل «Tor stopped at 15% …» هیچ‌وقت در جدولی که به متنِ دقیق کلید
/// می‌زند پیدا نمی‌شود — و درست همان جمله‌ای است که کاربر در لحظهٔ خطا می‌خواند.
/// این‌جا عدد با {0} جایگزین می‌شود، ترجمه پیدا می‌شود، و عدد سرِ جایش برمی‌گردد.
function numbered(key) {
  const digits = key.match(/\d+/)
  if (!digits) return null
  const pattern = key.replace(/\d+/, '{0}')
  const hit = FA[pattern]
  return hit ? hit.replace('{0}', digits[0]) : null
}
