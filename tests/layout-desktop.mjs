#!/usr/bin/env node
// tests/layout-desktop.mjs
//
// چیزی که هیچ‌کدام از تست‌های jsdom نمی‌توانستند ثابت کنند: کارتِ اتصال در
// کوچک‌ترین پنجرهٔ مجازِ برنامه **کامل** دیده می‌شود و کاربر برای دیدنِ پایینِ
// کارت مجبور به اسکرول نیست (ایراد a4).
//
// jsdom چیدمان را اندازه نمی‌گیرد — هر ارتفاعی صفر است. پس این تست بستهٔ واقعیِ
// vite را روی یک سرور استاتیک در یک Chromium واقعی بالا می‌آورد (همان موتوری که
// WebView2 هم از آن است)، IPC را با همان جدول قلابیِ settings-smoke شبیه‌سازی
// می‌کند و ارتفاع‌های واقعیِ layout را می‌خواند.
//
// اجرا:
//   npm i --no-save puppeteer-core
//   CHROME=/path/to/chrome node tests/layout-desktop.mjs
// اگر puppeteer-core یا مرورگر نبود، تست با پیام «رد شد» بی‌خطا تمام می‌شود؛
// یک ابزار توسعه نباید بیلد را بشکند.
import { createServer } from 'node:http'
import { createReadStream, readFileSync, writeFileSync, cpSync, mkdtempSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const DIST = new URL('../dist-web/', import.meta.url).pathname
// مرورگر: اول $CHROME، بعد مسیرهای متعارف. «وجود فایل» کافی نیست — روی دبیان
// ‏/usr/bin/chromium-browser یک شیمِ snap است که موجود است ولی اجرا نمی‌شود؛
// پس تا وقتی یکی واقعاً بالا نیاید، سراغ بعدی می‌رویم.
const CHROME_CANDIDATES = [
  process.env.CHROME,
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/local/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  '/tmp/chrome-headless-shell-linux64/chrome-headless-shell',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean).filter((p) => existsSync(p))

if (!existsSync(join(DIST, 'index.html'))) {
  console.log('SKIP: dist-web ساخته نشده — اول `npx vite build`')
  process.exit(0)
}
let puppeteer
try {
  puppeteer = (await import('puppeteer-core')).default
} catch {
  console.log('SKIP: puppeteer-core نصب نیست (npm i --no-save puppeteer-core)')
  process.exit(0)
}
if (CHROME_CANDIDATES.length === 0) {
  console.log('SKIP: هیچ مرورگری پیدا نشد — مسیر را با CHROME= بده')
  process.exit(0)
}

// کوچک‌ترین پنجره‌ای که برنامه اجازه می‌دهد، از خودِ پیکربندی خوانده می‌شود تا
// اگر روزی minHeight عوض شد، این تست همان لحظه دربارهٔ اندازهٔ جدید حرف بزند.
const conf = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url)))
const win = conf.app?.windows?.[0] ?? {}
const MIN_W = win.minWidth ?? 360
const MIN_H = win.minHeight ?? 720
// decorations:false → نوار عنوانِ خودِ برنامه داخل همین ناحیهٔ وب است، پس کلِ
// ارتفاع پنجره برای وب است و چیزی کم نمی‌شود.
const CHROME_BAR = win.decorations === false ? 0 : 32

const CONNECTED = {
  state: 'CONNECTED', detail: 'Tap to disconnect', error: null,
  endpoint: '188.114.99.205:3581', protocol: 'WIREGUARD \u2192 PSIPHON',
  latencyMs: 199, uptimeSecs: 8, rxBytes: 98000, txBytes: 82800,
  shareSocks: null, shareHttp: null, ipLoading: false,
  ipInfo: { ip: '139.162.179.163', countryCode: 'DE' },
  webrtcLeak: null, leakGuard: false,
}
const PROFILE = {
  backend: 'AETHER_PSIPHON', exitRegion: 'DE', protocol: 'SMART', scanMode: 'BALANCED',
  ipVersion: 'V4', noize: 'FIREWALL', endpointMode: 'MANUAL_PEER', manualPeer: '188.114.99.205:3581',
  manualRange: '', mtu: 1380, keepalive: 25, quickReconnect: true, masqueHttp2: false,
  fragment: true, ech: true, lanShare: false, killSwitch: true, ipv6Protection: true,
  reconnectAttempts: 5, splitMode: 'INCLUDE', splitApps: [], dns: ['1.1.1.1'],
  routeBlock: [], routeDirect: [], routeSniff: true, upstream: '', reprovision: true,
}

// vite مسیرِ دارایی‌ها را مطلق می‌نویسد (`/assets/…`)؛ روی file:// آن مسیر به
// ریشهٔ فایل‌سیستم می‌رود و باندل هرگز بالا نمی‌آید. یک سرور استاتیکِ چندخطی
// همان شرایطِ WebView2 را می‌سازد.
const work = mkdtempSync(join(tmpdir(), 'aether-layout-'))
cpSync(DIST, work, { recursive: true })
writeFileSync(join(work, 'probe.html'), readFileSync(join(work, 'index.html'), 'utf8'))

const TYPES = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png',
  '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.json': 'application/json',
}
const server = createServer((req, res) => {
  const path = decodeURIComponent(req.url.split('?')[0])
  const file = join(work, path === '/' ? 'probe.html' : path)
  res.setHeader('content-type', TYPES[file.slice(file.lastIndexOf('.'))] ?? 'application/octet-stream')
  createReadStream(file).on('error', () => { res.statusCode = 404; res.end('nope') }).pipe(res)
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const BASE = `http://127.0.0.1:${server.address().port}/probe.html`

let browser
let CHROME
for (const bin of CHROME_CANDIDATES) {
  try {
    browser = await puppeteer.launch({
      executablePath: bin,
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--font-render-hinting=none'],
    })
    CHROME = bin
    break
  } catch (e) {
    console.log(`  (${bin} بالا نیامد: ${String(e).split('\n')[0]})`)
  }
}
if (!browser) {
  console.log('SKIP: هیچ‌کدام از مرورگرهای پیداشده اجرا نشدند')
  server.close()
  process.exit(0)
}
console.log(`مرورگر: ${CHROME}`)

async function probe(w, h, lang) {
  const page = await browser.newPage()
  await page.setViewport({ width: w, height: h, deviceScaleFactor: 1 })
  // شیم باید قبل از باندل بنشیند: خودِ @tauri-apps/api از window می‌خواند.
  await page.evaluateOnNewDocument((snap, prof, lang) => {
    try { localStorage.setItem('aether.lang', lang) } catch {}
    window.__TAURI_INTERNALS__ = {
      invoke: (cmd) => {
        if (cmd === 'plugin:event|listen') return Promise.resolve(1)
        if (cmd === 'get_snapshot') return Promise.resolve(snap)
        if (cmd === 'get_profile') return Promise.resolve(prof)
        if (cmd === 'core_caps') {
          return Promise.resolve({ zeroTrust: true, routing: true, customDns: true, upstream: true, routeSniff: true })
        }
        return Promise.resolve(null)
      },
      transformCallback: (cb) => cb,
      metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
    }
  }, CONNECTED, PROFILE, lang)

  const errors = []
  page.on('pageerror', (e) => errors.push(String(e)))
  await page.goto(BASE, { waitUntil: 'load' })
  await page.waitForSelector('.ccard', { timeout: 10000 })
  // منتظرِ واقعیِ فونت می‌مانیم، نه یک خوابِ حدسی: IRANSans حدود یک مگابایت است
  // و `font-display: swap` دارد؛ اگر پیش از رسیدنش اندازه بگیریم، ارتفاعِ فونتِ
  // جایگزین را سنجیده‌ایم — روی رانرِ کندِ CI یعنی تستِ لرزان.
  await page.evaluate(() => document.fonts.ready)
  await new Promise((r) => setTimeout(r, 400))

  const out = await page.evaluate(() => {
    const q = (s) => document.querySelector(s)
    const rect = (el) => { const r = el.getBoundingClientRect(); return { top: Math.round(r.top), bottom: Math.round(r.bottom), h: Math.round(r.height), w: Math.round(r.width) } }
    const res = {
      viewport: { w: innerWidth, h: innerHeight },
      docScrollH: document.documentElement.scrollHeight,
      bodyScrollH: document.body.scrollHeight,
    }
    const main = q('main') ?? q('#view')?.parentElement
    if (main) res.main = { ...rect(main), scrollH: main.scrollHeight, clientH: main.clientHeight, overflowY: getComputedStyle(main).overflowY }
    const view = q('#view')
    if (view) res.view = { ...rect(view), scrollH: view.scrollHeight, clientH: view.clientHeight }
    const card = q('.ccard')
    if (card) res.card = rect(card)
    const btn = q('.connect')
    if (btn) res.connect = rect(btn)
    const mark = q('.connect__mark, .cmark')
    if (mark) res.mark = rect(mark)
    // پایین‌ترین چیزی که واقعاً رنگ خورده — اگر این بیرون کادر باشد، کاربر
    // چیزی را از دست می‌دهد، حتی اگر ظرفِ بالادستی‌اش سرریز نشان ندهد.
    let low = { bottom: 0, cls: '' }
    for (const el of document.querySelectorAll('#view *, main *')) {
      const r = el.getBoundingClientRect()
      const st = getComputedStyle(el)
      if (r.height < 1 || st.visibility === 'hidden' || st.display === 'none') continue
      if (r.bottom > low.bottom) low = { bottom: Math.round(r.bottom), cls: String(el.className).slice(0, 60) }
    }
    res.lowest = low
    return res
  })
  // بازرسیِ پیکسلی: سه ردیفِ آخرِ تصویر باید همان پس‌زمینهٔ خالی باشد. اگر
  // چیزی آنجا رنگ خورده، یعنی محتوا به لبه چسبیده یا بریده شده — همان چیزی که
  // کاربر در اسکرین‌شات دید و rect نشانش نمی‌داد.
  const png = await page.screenshot({ encoding: 'base64' })
  out.edge = await page.evaluate(async (b64, w, h) => {
    const img = new Image()
    await new Promise((r) => { img.onload = r; img.src = 'data:image/png;base64,' + b64 })
    const cv = document.createElement('canvas')
    cv.width = w; cv.height = h
    cv.getContext('2d').drawImage(img, 0, 0)
    const cx = cv.getContext('2d')
    // فقط ستونِ محتوا بازرسی می‌شود. ریلِ ناوبری در LTR چپ است و در RTL راست —
    // پس محدوده از خودِ `main` گرفته می‌شود، نه با یک عددِ ثابت. (اولین نسخهٔ
    // این سنجه همین را اشتباه کرد و در انگلیسی کلِ ریل را «رنگ‌خورده» شمرد.)
    const mr = (document.querySelector('main') ?? document.body).getBoundingClientRect()
    const x0 = Math.round(mr.left) + 2
    const x1 = Math.min(Math.round(mr.right) - 2, w)
    // مرجع، پس‑زمینهٔ اعلام‑شدهٔ صفحه است و نه یک پیکسلِ نمونه: نمونه‌برداری از
    // گوشه، اگر محتوا تا همان گوشه آمده باشد، خودِ ایراد را «پس‑زمینه» می‌گیرد.
    const rgb = getComputedStyle(document.body).backgroundColor.match(/\d+/g).map(Number)
    const strip = cx.getImageData(x0, h - 3, x1 - x0, 3).data
    let painted = 0
    for (let i = 0; i < strip.length; i += 4) {
      const d = Math.abs(strip[i] - rgb[0]) + Math.abs(strip[i + 1] - rgb[1]) + Math.abs(strip[i + 2] - rgb[2])
      if (d > 24) painted++
    }
    return { bg: rgb, range: [x0, x1], paintedPixels: painted, sampled: strip.length / 4 }
  }, png, w, h)
  out.errors = errors

  // >>> AETHER-APP-PATCH seg-labels-stay-on-one-line
  // ردیفِ Backend شش برچسب دارد و بلندترینش «Aether → Psiphon» است. با عرضِ
  // مساویِ اجباری، همان یکی دو خطی می‌شد و «Psiphon» زیرِ فلش می‌افتاد. jsdom
  // این را نمی‌بیند (ارتفاع همه صفر است)؛ فقط اندازه‌گیریِ واقعی می‌بیند.
  out.seg = await page.evaluate(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms))
    // ۱.۴.۰-mobile: ناوبری از کشو (drawer) است، نه ریل.
    const tab = document.querySelector('.drawer__item[data-tab="advanced"]')
    if (!tab) return { reached: false, why: 'آیتمِ Settings در کشو نیست' }
    tab.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await wait(150)
    const rows = [...document.querySelectorAll('.setrow__title')]
    const row = rows.find((x) => /^(Connection|اتصال)$/.test(x.textContent.trim()))
    if (!row) return { reached: false, why: 'ردیفِ Connection نیست، ردیف‌ها: ' + rows.map((x) => x.textContent.trim()).join('/') }
    row.closest('.setrow').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await wait(150)
    const bar = document.querySelector('.seg[data-key="backend"]')
    if (!bar) return { reached: false, why: 'ردیفِ قطعه‌ایِ backend نیست' }
    const items = [...bar.querySelectorAll('.seg__item')].map((b) => {
      const line = parseFloat(getComputedStyle(b).lineHeight) || 17
      const pad = parseFloat(getComputedStyle(b).paddingTop) + parseFloat(getComputedStyle(b).paddingBottom)
      return {
        text: b.textContent.trim(),
        h: Math.round(b.getBoundingClientRect().height),
        oneLineH: Math.round(line + pad),
        clipped: b.scrollWidth > b.clientWidth + 1,
      }
    })
    return {
      reached: true,
      count: items.length,
      overflow: bar.scrollWidth > bar.clientWidth + 1,
      barW: Math.round(bar.getBoundingClientRect().width),
      needW: bar.scrollWidth,
      items,
    }
  })
  // <<< AETHER-APP-PATCH seg-labels-stay-on-one-line

  await page.close()
  return out
}

let failures = 0
const check = (ok, what) => { console.log((ok ? '  ok   ' : '  FAIL ') + what); if (!ok) failures++ }

for (const [label, w, h] of [
  ['کوچک‌ترین پنجرهٔ مجاز', MIN_W, MIN_H - CHROME_BAR],
  ['پنجرهٔ پیش‌فرض (قاب موبایل)', win.width ?? 390, (win.height ?? 820) - CHROME_BAR],
]) for (const lang of ['en', 'fa']) {
  const r = await probe(w, h, lang)
  console.log(`\n── ${label} — ناحیهٔ وب ${w}\u00d7${h} — ${lang}`)
  console.log('   ' + JSON.stringify(r))
  check(r.errors.length === 0, `بدون خطای اجرا${r.errors.length ? ': ' + r.errors[0] : ''}`)
  check(r.docScrollH <= r.viewport.h + 1, `سند اسکرول عمودی ندارد (${r.docScrollH} \u2264 ${r.viewport.h})`)
  if (r.card) {
    check(r.card.bottom <= r.viewport.h + 1,
      `کارت اتصال کامل دیده می‌شود (پایینش ${r.card.bottom}\u060c فضای خالیِ زیرش ${r.viewport.h - r.card.bottom}px)`)
    check(r.card.top >= -1, `بالای کارت هم داخل کادر است (${r.card.top})`)
  }
  check(r.lowest.bottom <= r.viewport.h + 1,
    `پایین‌ترین المانِ رسم‌شده داخل کادر است (${r.lowest.bottom} \u2014 «${r.lowest.cls}»)`)
  if (r.main) check(r.main.scrollH <= r.main.clientH + 1, `ناحیهٔ main سرریز ندارد (${r.main.scrollH} \u2264 ${r.main.clientH})`)
  check(r.edge.paintedPixels === 0,
    `سه ردیفِ آخرِ تصویر خالی است (${r.edge.paintedPixels} پیکسلِ رنگ‌خورده از ${r.edge.sampled})`)
  // >>> AETHER-APP-PATCH seg-labels-stay-on-one-line
  if (r.seg?.reached) {
    const tall = r.seg.items.filter((i) => i.h > i.oneLineH + 2)
    check(tall.length === 0,
      `هر شش برچسبِ Backend یک‌خطی است${tall.length ? ' — دوخطی: ' + tall.map((i) => `«${i.text}» ${i.h}px`).join('، ') : ''}`)
    check(!r.seg.overflow, `ردیفِ Backend سرریز ندارد (${r.seg.needW} \u2264 ${r.seg.barW})`)
    const cut = r.seg.items.filter((i) => i.clipped)
    check(cut.length === 0, `هیچ برچسبی بریده نشده${cut.length ? ' — ' + cut.map((i) => `«${i.text}»`).join('، ') : ''}`)
  } else {
    check(false, 'ردیفِ Backend سنجیده نشد: ' + (r.seg?.why ?? '?'))
  }
  // <<< AETHER-APP-PATCH seg-labels-stay-on-one-line
  if (r.connect) console.log(`   دکمهٔ اتصال: ${r.connect.w}\u00d7${r.connect.h}px` + (r.card ? `\u060c کارت: ${r.card.h}px` : ''))
}

await browser.close()
server.close()
console.log(failures === 0 ? '\nALL OK' : `\n${failures} FAILED`)
process.exit(failures === 0 ? 0 : 1)
