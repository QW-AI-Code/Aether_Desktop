#!/usr/bin/env node
// tests/shots.mjs — عکس‌برداری از صفحه‌ها برای بازبینیِ چشمی (EN و FA).
// تستِ pass/fail نیست؛ ابزارِ نگاه‌کردن است. خروجی در /tmp/shots.
import { createServer } from 'node:http'
import { createReadStream, readFileSync, writeFileSync, cpSync, mkdtempSync, mkdirSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const DIST = new URL('../dist-web/', import.meta.url).pathname
// مرورگر: اول $CHROME، بعد مسیرهای متعارف. «وجود فایل» کافی نیست — شیمِ snap
// دبیان موجود است ولی اجرا نمی‌شود؛ پس یکی‌یکی امتحان می‌کنیم.
const CHROME_CANDIDATES = [
  process.env.CHROME,
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/tmp/chrome-headless-shell-linux64/chrome-headless-shell',
].filter(Boolean).filter((p) => existsSync(p))
const OUT = process.env.OUT ?? '/tmp/shots'
if (!existsSync(join(DIST, 'index.html'))) { console.log('SKIP: dist-web نیست'); process.exit(0) }
let puppeteer
try { puppeteer = (await import('puppeteer-core')).default } catch { console.log('SKIP: puppeteer-core نیست'); process.exit(0) }
if (CHROME_CANDIDATES.length === 0) { console.log('SKIP: مرورگری پیدا نشد'); process.exit(0) }
mkdirSync(OUT, { recursive: true })

const CONNECTED = {
  state: 'CONNECTED', detail: 'Tap to disconnect', error: null,
  endpoint: '188.114.99.205:3581', protocol: 'WIREGUARD \u2192 PSIPHON',
  latencyMs: 199, uptimeSecs: 8, rxBytes: 98000, txBytes: 82800,
  shareSocks: null, shareHttp: null, ipLoading: false,
  ipInfo: { ip: '139.162.179.163', countryCode: 'DE' }, webrtcLeak: null, leakGuard: false,
}
const PROFILE = {
  backend: 'AETHER_PSIPHON', exitRegion: 'DE', protocol: 'SMART', scanMode: 'BALANCED',
  ipVersion: 'V4', noize: 'FIREWALL', endpointMode: 'MANUAL_PEER', manualPeer: '188.114.99.205:3581',
  manualRange: '', mtu: 1380, keepalive: 25, quickReconnect: true, masqueHttp2: false,
  fragment: true, ech: true, lanShare: false, killSwitch: true, ipv6Protection: true,
  reconnectAttempts: 5, splitMode: 'INCLUDE', splitApps: [], dns: ['1.1.1.1'],
  routeBlock: [], routeDirect: [], routeSniff: true, upstream: '', reprovision: true,
}
// snapshotِ دستیار: کلید ذخیره‌شده، مدل‌ها کشف‌شده، و نتیجهٔ تستِ اتصال.
// fixture باید عیناً شکلِ `AiSnapshot` در `ai_session.rs` باشد، وگرنه صفحه در
// عکس «سالم» یا «خراب» به‌دروغ دیده می‌شود. نسخهٔ اولِ این fixture سه نوارِ خالی
// و یک دروازهٔ اشتباه نشان داد، چون `models` را رشته داده بودم و `assistant.js`
// از `model.id` می‌خواند، و `gateCode` را جا انداخته بودم.
const AI = {
  gate: 'READY',
  gateCode: 'READY',
  hasKey: true,
  keyHint: '4271',
  models: [
    { id: 'gemini-2.5-flash', displayName: 'Gemini 2.5 Flash', description: '', inputTokenLimit: 1048576, outputTokenLimit: 65536, chatCapable: true },
    { id: 'gemini-2.5-flash-lite', displayName: 'Gemini 2.5 Flash Lite', description: '', inputTokenLimit: 1048576, outputTokenLimit: 65536, chatCapable: true },
    { id: 'gemini-2.0-flash', displayName: 'Gemini 2.0 Flash', description: '', inputTokenLimit: 1048576, outputTokenLimit: 8192, chatCapable: true },
  ],
  selectedModel: 'gemini-2.5-flash',
  modelNumber: 1,
  busy: false,
  error: null,
  errorKind: null,
  messages: [],
  advisor: null,
  probe: { state: 'OK', modelCount: 3, via: 'Aether \u2192 Psiphon', message: null },
}

// گفت‌وگوی نمونه: هر چهار حالتِ حباب در یک عکس، وگرنه «عکس گرفتم» چیزی را ثابت
// نمی‌کند. شکل باید عیناً `ChatMessage` سمت Rust باشد (`id`, `sourcePrompt`,
// `errorKind`, `edited`) — fixtureِ اشتباه، صفحه را به‌دروغ سالم نشان می‌دهد.
const AI_CHAT = {
  ...AI,
  messages: [
    { id: 1, fromUser: true, text: 'Why is my connection slow right now?', failed: false, edited: false },
    {
      id: 2,
      fromUser: false,
      text: 'Latency of 199 ms through a chained exit is normal — the traffic goes to a WARP edge first and then to a Psiphon server. If throughput matters more than reachability, switch the backend to Aether alone.',
      failed: false,
      edited: false,
    },
    { id: 3, fromUser: true, text: 'Make the tunnel harder to detect', failed: false, edited: true },
    {
      id: 4,
      fromUser: false,
      text: 'API key not valid. Pass a valid API key.',
      failed: true,
      errorKind: 'BAD_KEY',
      sourcePrompt: 'Make the tunnel harder to detect',
      edited: false,
    },
  ],
}

const work = mkdtempSync(join(tmpdir(), 'aether-shots-'))
cpSync(DIST, work, { recursive: true })
writeFileSync(join(work, 'probe.html'), readFileSync(join(work, 'index.html'), 'utf8'))
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.json': 'application/json' }
const server = createServer((req, res) => {
  const p = decodeURIComponent(req.url.split('?')[0])
  const f = join(work, p === '/' ? 'probe.html' : p)
  res.setHeader('content-type', TYPES[f.slice(f.lastIndexOf('.'))] ?? 'application/octet-stream')
  createReadStream(f).on('error', () => { res.statusCode = 404; res.end('x') }).pipe(res)
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const BASE = `http://127.0.0.1:${server.address().port}/probe.html`

let browser
for (const bin of CHROME_CANDIDATES) {
  try {
    browser = await puppeteer.launch({ executablePath: bin, args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--force-device-scale-factor=1'] })
    console.log(`مرورگر: ${bin}`)
    break
  } catch {}
}
if (!browser) { console.log('SKIP: هیچ مرورگری اجرا نشد'); server.close(); process.exit(0) }

async function shot(name, { lang, w, h, tab, ai = AI }) {
  const page = await browser.newPage()
  await page.setViewport({ width: w, height: h, deviceScaleFactor: 1 })
  await page.evaluateOnNewDocument((snap, prof, ai, lang) => {
    localStorage.setItem('aether.lang', lang)
    window.__TAURI_INTERNALS__ = {
      invoke: (cmd) => {
        if (cmd === 'plugin:event|listen') return Promise.resolve(1)
        if (cmd === 'get_snapshot') return Promise.resolve(snap)
        if (cmd === 'get_profile') return Promise.resolve(prof)
        if (cmd === 'ai_snapshot' || cmd === 'ai_get') return Promise.resolve(ai)
        if (cmd === 'core_caps') return Promise.resolve({ zeroTrust: true, routing: true, customDns: true, upstream: true, routeSniff: true })
        if (cmd === 'diagnostics_run') return Promise.resolve([])
        return Promise.resolve(null)
      },
      transformCallback: (cb) => cb,
      metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
    }
  }, CONNECTED, PROFILE, ai, lang)
  await page.goto(BASE, { waitUntil: 'load' })
  await page.waitForSelector('#view', { timeout: 10000 })
  if (tab && tab !== 'home') {
    await page.evaluate((tab) => {
      const el = document.querySelector(`.drawer__item[data-tab="${tab}"]`)
      if (el) el.click()
    }, tab)
  }
  // اگر snapshot دستیار از رخداد می‌آید، همان را هم تزریق کن.
  await page.evaluate((snap) => { window.__AI_SNAPSHOT__ = snap }, ai)
  // منتظرِ واقعیِ فونت می‌مانیم، نه یک خوابِ حدسی: IRANSans حدود یک مگابایت است
  // و `font-display: swap` دارد؛ اگر پیش از رسیدنش اندازه بگیریم، ارتفاعِ فونتِ
  // جایگزین را سنجیده‌ایم — روی رانرِ کندِ CI یعنی تستِ لرزان.
  await page.evaluate(() => document.fonts.ready)
  await new Promise((r) => setTimeout(r, 400))
  await page.screenshot({ path: join(OUT, name + '.png') })
  const text = await page.evaluate(() => document.querySelector('#view')?.innerText?.slice(0, 400))
  console.log(`${name}.png  «${(text ?? '').replace(/\n/g, ' / ').slice(0, 120)}»`)
  await page.close()
}

await shot('home-en-360x720', { lang: 'en', w: 360, h: 720, tab: 'home' })
await shot('home-fa-360x720', { lang: 'fa', w: 360, h: 720, tab: 'home' })
await shot('ai-en-390x820', { lang: 'en', w: 390, h: 820, tab: 'assistant' })
await shot('ai-fa-390x820', { lang: 'fa', w: 390, h: 820, tab: 'assistant' })
await shot('settings-fa-390x820', { lang: 'fa', w: 390, h: 820, tab: 'advanced' })
// چت: خالی (پرسش‌های آماده) و پُر (چهار حالتِ حباب)، در دو زبان.
await shot('chat-empty-fa-390x820', { lang: 'fa', w: 390, h: 820, tab: 'chat' })
await shot('chat-en-390x820', { lang: 'en', w: 390, h: 820, tab: 'chat', ai: AI_CHAT })
await shot('chat-fa-390x820', { lang: 'fa', w: 390, h: 820, tab: 'chat', ai: AI_CHAT })
await shot('chat-fa-360x720', { lang: 'fa', w: 360, h: 720, tab: 'chat', ai: AI_CHAT })

await browser.close()
server.close()
console.log('عکس‌ها در ' + OUT)
