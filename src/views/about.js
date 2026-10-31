// پورت یک‌به‌یک از ui/AboutPanel.kt نسخهٔ اندروید:
// کارت بازشوندهٔ «About» با سازندگان، لینک‌ها و فهرست امکانات.
// تفاوت‌های عمدی با موبایل:
//   - بخش QW-AI-Code به‌جای نسخهٔ اندروید، نسخهٔ دسکتاپ (ویندوز) را توضیح می‌دهد.
//   - دکمهٔ «Check for updates» حذف شده است.
// آیکون برنامه از طریق import به باندل Vite اضافه می‌شود؛ رشتهٔ خام «icon.png»
// در خروجی build وجود نداشت و همین باعث خرابی تصویر لوگو بود.
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-shell'
import iconUrl from '../icon.png'
import { t, getLang } from '../i18n.js'

const URL_ORIGINAL_GITHUB = 'https://github.com/CluvexStudio/Aether'
const URL_ORIGINAL_TELEGRAM = 'https://t.me/CluvexStudio'
const URL_PORT_GITHUB = 'https://github.com/QW-AI-Code'

// v17: در زبان فارسی، نسخهٔ فارسیِ روان (پایین‌تر) نمایش داده می‌شود؛
// نسخهٔ انگلیسی همان فهرست README پروژهٔ اصلی است.
const ORIGINAL_FEATURES = [
  'Automatic endpoint discovery with end-to-end data-plane validation',
  'MASQUE (HTTP/3 & HTTP/2) with optional TLS ClientHello fragmentation',
  'WireGuard and nested WireGuard (WARP-in-WARP "gool")',
  'Traffic obfuscation for DPI-heavy networks',
  'Automatic reconnection with quick-reconnect to the last good gateway',
  'Local SOCKS5 proxy — CLI for Linux, Windows, macOS and Android (Termux)',
  'Zero Trust enrolment — connect as a managed device of a Cloudflare organization (core 1.5.0)',
  'Routing rules — block or send destinations direct instead of through the tunnel (core 1.5.0)',
  'Selectable in-tunnel DNS resolvers (core 1.5.0)',
  'Routing rules matched from the real host name, so they keep working behind a tun front end (core 1.7.0)',
  'Upstream proxy support — dial out through another VPN or proxy already running on the machine (core 1.7.0)',
  'A device identity Cloudflare no longer accepts is detected and replaced instead of silently carrying no traffic (core 1.7.0)',
]

// آنچه این نسخهٔ دسکتاپ روی پروژهٔ اصلی اضافه می‌کند (معادل PORT_IMPROVEMENTS،
// بازنویسی‌شده برای ویندوز).
const PORT_IMPROVEMENTS = [
  'Full native Windows desktop app — upstream is CLI-only (no Windows GUI)',
  'One-click system-wide tunnel via the Wintun TUN driver — no manual proxy setup',
  'Bundled Aether core engine, launched and supervised in-process by the app',
  'Live protocol, endpoint, latency, uptime and traffic stats on the home screen',
  'Step-by-step connectivity self-test with crash-persistent diagnostic logs',
  'Automatic reconnect with backoff and per-scan-mode connect timeouts',
  'Protocol, scan-mode and IP-version controls in a modern dark UI (English + فارسی)',
  'Share the tunnel over LAN — built-in HTTP + SOCKS5 proxy for laptops & other phones',
  'Professional bilingual installer (x64/x86) + portable ZIP, published automatically from GitHub Actions',
  'Full UI for the core 1.5.0 features: Zero Trust sign-in, routing rules and in-tunnel DNS',
  'Bundled Aether Core 1.7.0 with data-plane validation, automatic tunnel recovery and last-good-gateway reuse',
  'Full UI for the core 1.7.0 features: upstream proxy chaining, host-name routing and identity replacement',
  'An HTTP upstream proxy switches MASQUE to HTTP/2 automatically, because HTTP CONNECT cannot carry UDP',
  'Zero Trust secrets kept in memory only — never written to disk, masked in logs',
  'Core version gate — 1.5.0 and 1.7.0 flags are only sent to an engine that understands them',
  'WebRTC leak guard (1.2.0) — browsers can no longer expose your real IP over direct UDP',
  'Built-in WebRTC leak test (1.2.0) — a real STUN probe proves the tunnel is airtight',
  'Default profile is locked (no edit or delete); profiles can be exported and imported as files',
  'Custom configs: clean, left-to-right server names, stable Server IDs, row numbers and optional real-delay sorting',
  'Country search in the exit-country picker; calmer connect animation',
  'Support dialog for the Aether core creator, also available from the announcements archive',
]

// v17: ترجمهٔ روان فارسی هر دو فهرست بالا — وقتی زبان برنامه فارسی است
// این‌ها نمایش داده می‌شوند. واژه‌های لاتین داخل <bdi> می‌نشینند تا چینش
// راست‌به‌چپ بهم نریزد.
const ORIGINAL_FEATURES_FA = [
  'کشف خودکار بهترین سرور همراه با اعتبارسنجی سرتاسری مسیر داده',
  '<bdi>MASQUE</bdi> (<bdi>HTTP/3</bdi> و <bdi>HTTP/2</bdi>) با قابلیت قطعه‌قطعه‌سازی <bdi>TLS ClientHello</bdi>',
  '<bdi>WireGuard</bdi> و وایرگاردِ تودرتو (<bdi>WARP-in-WARP</bdi> یا همان <bdi>gool</bdi>)',
  'مبهم‌سازی ترافیک برای شبکه‌های دارای بازرسی عمیق بسته‌ها (<bdi>DPI</bdi>)',
  'اتصال مجدد خودکار همراه با بازگشت سریع به آخرین سرور سالم',
  'پروکسی محلی <bdi>SOCKS5</bdi> — خط فرمان برای لینوکس، ویندوز، مک و اندروید (<bdi>Termux</bdi>)',
  'ورود <bdi>Zero Trust</bdi> — اتصال به‌عنوان دستگاه مدیریت‌شدهٔ یک سازمان (هستهٔ <bdi>1.5.0</bdi>)',
  'قوانین مسیریابی — مسدودکردن یا فرستادن مقصد از مسیر مستقیم به‌جای تونل (هستهٔ <bdi>1.5.0</bdi>)',
  'انتخاب سرورهای <bdi>DNS</bdi> داخل تونل (هستهٔ <bdi>1.5.0</bdi>)',
  'تطبیق قواعد مسیریابی با نام واقعی میزبان، حتی وقتی ترافیک از یک درایور <bdi>tun</bdi> می‌آید (هستهٔ <bdi>1.7.0</bdi>)',
  'پروکسی بالادست — عبور همهٔ اتصال‌ها از یک <bdi>VPN</bdi> یا پروکسیِ در حال اجرا روی همان دستگاه (هستهٔ <bdi>1.7.0</bdi>)',
  'هویتی که <bdi>Cloudflare</bdi> دیگر قبولش ندارد تشخیص داده و جایگزین می‌شود، نه اینکه تونل بی‌صدا بی‌ترافیک بماند (هستهٔ <bdi>1.7.0</bdi>)',
]

const PORT_IMPROVEMENTS_FA = [
  'برنامهٔ کاملاً بومی دسکتاپ ویندوز — پروژهٔ اصلی فقط خط فرمان دارد و رابط گرافیکی ویندوز ندارد',
  'تونل سراسری سیستم با یک کلیک از طریق درایور <bdi>Wintun</bdi> — بدون نیاز به تنظیم دستی پروکسی',
  'موتور اصلی اِتِر همراه برنامه ارائه می‌شود و توسط خود برنامه اجرا و مدیریت می‌شود',
  'نمایش زندهٔ پروتکل، نقطهٔ اتصال، تأخیر، مدت اتصال و آمار ترافیک در صفحهٔ اصلی',
  'خودآزمای گام‌به‌گام اتصال با لاگ‌های عیب‌یابی ماندگار حتی پس از کرش',
  'اتصال مجدد خودکار با تأخیر پلکانی و مهلت اتصالِ متناسب با حالت اسکن',
  'کنترل پروتکل، حالت اسکن و نسخهٔ آی‌پی در رابط تیرهٔ مدرن (انگلیسی + فارسی)',
  'اشتراک تونل در شبکهٔ محلی — پروکسی داخلی <bdi>HTTP</bdi> و <bdi>SOCKS5</bdi> برای لپ‌تاپ و گوشی‌های دیگر',
  'نصب‌کنندهٔ حرفه‌ای دوزبانه (<bdi>x64/x86</bdi>) + نسخهٔ پرتابل <bdi>ZIP</bdi>، با انتشار خودکار از <bdi>GitHub Actions</bdi>',
  'رابط کاربری کامل برای قابلیت‌های هستهٔ <bdi>1.5.0</bdi>: ورود <bdi>Zero Trust</bdi>، قوانین مسیریابی و <bdi>DNS</bdi> داخل تونل',
  'هستهٔ همراه <bdi>Aether Core 1.7.0</bdi> با بررسی واقعی مسیر داده، بازیابی خودکار تونل و استفادهٔ دوباره از آخرین <bdi>gateway</bdi> سالم',
  'رابط کامل برای قابلیت‌های هستهٔ <bdi>1.7.0</bdi>: پروکسی بالادست، مسیریابی براساس نام میزبان و جایگزینی هویت',
  'با پروکسی بالادستِ <bdi>HTTP</bdi>، خودکار <bdi>MASQUE</bdi> روی <bdi>HTTP/2</bdi> می‌رود چون <bdi>HTTP CONNECT</bdi> توان حمل <bdi>UDP</bdi> ندارد',
  'اسرار <bdi>Zero Trust</bdi> فقط در حافظه می‌مانند — هرگز روی دیسک نوشته نمی‌شوند و در لاگ ماسک می‌شوند',
  'گارد نسخهٔ هسته — فلگ‌های <bdi>1.5.0</bdi> و <bdi>1.7.0</bdi> فقط به هسته‌ای فرستاده می‌شوند که آن‌ها را می‌فهمد',
  'گارد نشتی <bdi>WebRTC</bdi> (نسخهٔ <bdi>1.2.0</bdi>) — مرورگرها دیگر نمی‌توانند آی‌پی واقعی شما را با <bdi>UDP</bdi> مستقیم لو بدهند',
  'آزمایش داخلی نشتی <bdi>WebRTC</bdi> (نسخهٔ <bdi>1.2.0</bdi>) — یک درخواست واقعی <bdi>STUN</bdi> که بی‌نشتی‌بودن تونل را اثبات می‌کند',
  'پروفایل پیش‌فرض قفل است (غیرقابل ویرایش و حذف)؛ پروفایل‌ها با فایل ورود و خروجی می‌شوند',
  'کانفیگ‌های سفارشی: نام سرور تمیز و چپ‌به‌راست، شناسهٔ ثابت سرور، شمارهٔ ردیف و سورت اختیاری بر پایهٔ تأخیر واقعی',
  'جستجوی کشور در انتخاب کشور خروجی و انیمیشن آرام‌تر دکمهٔ اتصال',
  'پنجرهٔ حمایت از سازندهٔ هستهٔ اتر، قابل‌دسترس از بایگانی پیام‌ها',
]

// ---- آیکون‌های SVG داخلی (معادل Icons.Rounded و painterResource موبایل) ----
const ICON_INFO =
  '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="currentColor"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm0 5a1.25 1.25 0 1 1 0 2.5A1.25 1.25 0 0 1 12 7Zm1 10h-2v-6h2v6Z"/></svg>'
const ICON_CHEVRON =
  '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="currentColor"><path d="M7.41 8.59 12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41Z"/></svg>'
const ICON_GITHUB =
  '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>'
const ICON_TELEGRAM =
  '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="currentColor"><path d="M21.94 4.35c.25-1.02-.38-1.47-1.09-1.2L2.7 10.14c-1.19.46-1.18 1.13-.21 1.42l4.63 1.44 10.75-6.77c.51-.33.97-.15.59.18l-8.7 7.85-.33 4.78c.48 0 .69-.21.94-.46l2.26-2.18 4.7 3.46c.87.48 1.49.23 1.71-.8l3.9-14.71Z"/></svg>'

function featureListHtml(items) {
  // v17: فهرست فارسی راست‌به‌چپ رندر می‌شود؛ انگلیسی مثل قبل LTR می‌ماند.
  const fa = getLang() === 'fa'
  return `<ul class="features${fa ? '' : ' ltr'}"${fa ? '' : ' dir="ltr"'}>${items
    .map((f) => `<li><span class="features__dot">•</span><span>${f}</span></li>`)
    .join('')}</ul>`
}

function linkRowHtml(icon, label, url) {
  return `
    <button type="button" class="linkrow" data-url="${url}">
      <span class="linkrow__icon">${icon}</span>
      <span class="linkrow__label ltr" dir="ltr">${label}</span>
    </button>`
}

export function renderAbout() {
  const root = document.createElement('div')
  root.className = 'view view--about'
  root.innerHTML = `
    <div class="about__mark">
      <img src="${iconUrl}" alt="" width="88" height="88">
    </div>
    <h2 class="view__title">${t('Aether')}</h2>
    <p class="view__lead">${t('Freedom, in one tap')}</p>

    <dl class="kv">
      <dt>${t('App version')}</dt><dd class="ltr" dir="ltr" id="a-app">—</dd>
      <dt>${t('Core version')}</dt><dd class="ltr" dir="ltr" id="a-core">—</dd>
      <dt>${t('Architecture')}</dt><dd class="ltr" dir="ltr" id="a-arch">—</dd>
    </dl>

    <!-- کارت بازشونده — همان AboutPanel.kt -->
    <section class="about-card" id="about-card">
      <button type="button" class="about-card__head" id="about-toggle" aria-expanded="false" aria-controls="about-body">
        <span class="about-card__info">${ICON_INFO}</span>
        <span class="about-card__titles">
          <span class="about-card__title">${t('About')}</span>
          <span class="about-card__sub">${t('Credits, links & what this build adds')}</span>
        </span>
        <span class="about-card__chevron">${ICON_CHEVRON}</span>
      </button>

      <div class="about-card__body" id="about-body">
        <div class="about-card__inner">
          <hr class="about-card__sep">
          <p class="about-card__version">${t('Version')} <span class="ltr" dir="ltr" id="a-version">—</span></p>

          <h3 class="about-sec__title">${t('Original project — Cluvex Studio')}</h3>
          <p class="about-sec__note">${t('The core engine powering this app')}</p>
          ${linkRowHtml(ICON_GITHUB, 'github.com/CluvexStudio/Aether', URL_ORIGINAL_GITHUB)}
          ${linkRowHtml(ICON_TELEGRAM, 't.me/CluvexStudio', URL_ORIGINAL_TELEGRAM)}
          ${featureListHtml(getLang() === 'fa' ? ORIGINAL_FEATURES_FA : ORIGINAL_FEATURES)}

          <hr class="about-card__sep">

          <h3 class="about-sec__title">${t('Windows edition — QW-AI-Code')}</h3>
          <p class="about-sec__note">${t('The native Windows desktop edition of Aether — what we upgraded in this build')}</p>
          ${linkRowHtml(ICON_GITHUB, 'github.com/QW-AI-Code', URL_PORT_GITHUB)}
          ${featureListHtml(getLang() === 'fa' ? PORT_IMPROVEMENTS_FA : PORT_IMPROVEMENTS)}
        </div>
      </div>
    </section>
  `

  invoke('about_info').then((info) => {
    root.querySelector('#a-app').textContent = info.appVersion
    root.querySelector('#a-core').textContent = info.coreVersion
    root.querySelector('#a-arch').textContent = info.arch
    root.querySelector('#a-version').textContent = info.appVersion
  })

  // باز/بسته شدن کارت با انیمیشن — معادل AnimatedVisibility + rotate موبایل.
  const card = root.querySelector('#about-card')
  const toggle = root.querySelector('#about-toggle')
  toggle.addEventListener('click', () => {
    const openNow = card.classList.toggle('is-open')
    toggle.setAttribute('aria-expanded', String(openNow))
  })

  // لینک‌ها در مرورگر پیش‌فرض باز می‌شوند — معادل LocalUriHandler موبایل.
  for (const row of root.querySelectorAll('.linkrow')) {
    row.addEventListener('click', () => {
      const url = row.dataset.url
      if (url) open(url).catch(() => {})
    })
  }

  return root
}
