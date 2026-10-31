// هر پروتکلی که هستهٔ Rust می‌شناسد باید در UI قابل انتخاب باشد — و در همان
// چیزی که ساخته می‌شود، نه فقط در سورس.
//
// چرا این تست هست: کاربر با اسکرین‌شات نشان داد ردیف Protocol فقط چهار گزینه
// دارد (Smart / MASQUE / WireGuard / WARP×2) درحالی‌که `Protocol::Mim` در
// profile.rs و `['MIM', 'MASQUE×2']` در advanced.js وجود داشت. هیچ تستی این
// شکاف را نمی‌گرفت، چون هیچ تستی ردیفِ پروتکل را نمی‌شمرد.
//
// این تست سه چیز را به هم قید می‌کند:
//   ۱. enumِ `Protocol` در profile.rs  ⟷ آرایهٔ `PROTOCOLS` در advanced.js
//   ۲. آرایهٔ `PROTOCOLS`              ⟷ دکمه‌هایی که واقعاً رندر می‌شوند
//   ۳. برچسبِ هر مقدار در `VALUE_LABEL` تنظیمات (ردیفِ هاب)
import { JSDOM } from 'jsdom'
import { readFileSync } from 'node:fs'

const dom = new JSDOM('<!doctype html><html><body><div id="view"></div></body></html>', {
  url: 'http://localhost/',
  pretendToBeVisual: true,
})
globalThis.window = dom.window
globalThis.document = dom.window.document
globalThis.HTMLElement = dom.window.HTMLElement
globalThis.localStorage = dom.window.localStorage
globalThis.requestAnimationFrame = (fn) => setTimeout(() => fn(0), 0)
globalThis.cancelAnimationFrame = clearTimeout
window.__TAURI_INTERNALS__ = {
  invoke: (cmd) => {
    if (cmd === 'plugin:event|listen') return Promise.resolve(1)
    // Complete bootstrap replies: null snapshots make main.js fail asynchronously.
    if (cmd === 'get_profile') return Promise.resolve({ backend: 'AETHER', protocol: 'SMART', scanMode: 'BALANCED', ipVersion: 'V4' })
    if (cmd === 'get_snapshot') return Promise.resolve({ state: 'DISCONNECTED', detail: '', latencyMs: -1, uptimeSecs: 0, rxBytes: 0, txBytes: 0 })
    if (cmd === 'core_caps') {
      return Promise.resolve({
        zeroTrust: true, routing: true, customDns: true,
        upstream: true, routeSniff: true, tor: true, mim: true,
      })
    }
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
  metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
}

let failures = 0
const check = (ok, what) => {
  console.log((ok ? '  ok   ' : '  FAIL ') + what)
  if (!ok) failures++
}

// ---- ۱) enum سمت Rust ------------------------------------------------------
const rust = readFileSync(new URL('../src-tauri/src/profile.rs', import.meta.url), 'utf8')
const body = rust.slice(rust.indexOf('pub enum Protocol {'))
const enumBody = body.slice(0, body.indexOf('\n}'))
const fromRust = [...enumBody.matchAll(/^\s{4}([A-Z][A-Za-z]*),/gm)].map((m) => m[1].toUpperCase())
check(fromRust.length >= 5, `enum Protocol در Rust: ${fromRust.join(', ')}`)

// ---- ۲) آنچه واقعاً رندر می‌شود -------------------------------------------
const main = await import('../src/main.js').then(async m => { await m.bootReady; return m })
main.app.profile = { backend: 'AETHER', protocol: 'SMART', scanMode: 'BALANCED', ipVersion: 'V4' }
const { renderAdvanced } = await import('../src/views/advanced.js')

const root = renderAdvanced(['connection'])
const rendered = [...root.querySelectorAll('.seg[data-key="protocol"] .seg__item')]
  .map((b) => b.dataset.value.toUpperCase())
check(rendered.length > 0, `ردیف Protocol رندر شد (${rendered.length} گزینه)`)

for (const value of fromRust) {
  check(rendered.includes(value), `گزینهٔ «${value}» در ردیف Protocol رندر می‌شود`)
}

// GOOL's carrier must be selectable even when Smart Auto later chooses GOOL.
// The saved value maps to real Core 2.4.0 flags, not just a cosmetic label.
const modes = [...root.querySelectorAll('.seg[data-key="goolMode"] .seg__item')]
check(modes.map((b) => b.dataset.value).join(',') === 'MODERN,CLASSIC',
  'انتخاب هر دو بستر GOOL در بخش اتصال حتی با Smart دیده می‌شود')
check(!root.innerHTML.includes('[object Object]'), 'توضیح GOOL شیء خام نیست')
check(modes[0]?.getAttribute('aria-checked') === 'true', 'حالت نوین پیش‌فرض است')
main.app.profile = { ...main.app.profile, goolMode: 'CLASSIC', protocol: 'GOOL' }
const classic = renderAdvanced(['connection'])
check(classic.querySelector('.seg[data-key="goolMode"] [data-value="CLASSIC"]')?.getAttribute('aria-checked') === 'true',
  'انتخاب ذخیره‌شدهٔ سنتی دوباره رندر می‌شود')
check(classic.textContent.includes('WireGuard'), 'شرح بستر سنتی نمایش داده می‌شود')
main.app.profile = { ...main.app.profile, backend: 'TOR_AETHER' }
check(!renderAdvanced(['connection']).querySelector('.seg[data-key="goolMode"]'),
  'GOOL در زنجیرهٔ تور→اتر که فقط MASQUE را می‌پذیرد نشان داده نمی‌شود')
main.app.profile = { backend: 'AETHER', protocol: 'SMART', scanMode: 'BALANCED', ipVersion: 'V4' }
check(rust.includes('GoolMode::Modern => "--gool"') && rust.includes('GoolMode::Classic => "--gool-classic"'),
  'انتخاب‌های GOOL به فلگ واقعی هسته متصل هستند')
for (const value of rendered) {
  check(fromRust.includes(value), `گزینهٔ «${value}» در UI یک مقدار واقعی هسته است`)
}

// ---- ۳) برچسب ردیف هاب ----------------------------------------------------
const settingsSrc = readFileSync(new URL('../src/views/settings.js', import.meta.url), 'utf8')
const labels = settingsSrc.slice(settingsSrc.indexOf('const VALUE_LABEL'))
for (const value of fromRust) {
  check(new RegExp(`\\b${value}:`).test(labels), `«${value}» در VALUE_LABEL هاب برچسب دارد`)
}

// ---- ۴) و در باندلِ ساخته‌شده، اگر وجود داشته باشد ------------------------
// یک `dist-web` کهنه در مخزن یعنی برنامه می‌تواند UIای را نشان بدهد که با سورس
// یکی نیست — دقیقاً همان چیزی که در اسکرین‌شات دیده شد. اگر باندل هست، باید
// همان گزینه‌ها را داشته باشد.
let bundle = null
try {
  const { readdirSync } = await import('node:fs')
  const dir = new URL('../dist-web/assets/', import.meta.url)
  const file = readdirSync(dir).find((n) => /^index-.*\.js$/.test(n))
  if (file) bundle = readFileSync(new URL(file, dir), 'utf8')
} catch { /* بدون باندل، چیزی برای سنجیدن نیست */ }

if (bundle) {
  for (const value of fromRust) {
    check(
      new RegExp(`["']${value}["']`).test(bundle),
      `«${value}» در باندلِ dist-web هم هست (باندل کهنه = UI کهنه)`,
    )
  }
} else {
  console.log('  --   dist-web وجود ندارد؛ باندل سنجیده نشد')
}

console.log(failures === 0 ? '\nPROTOCOL OPTIONS OK' : `\n${failures} FAIL`)
process.exit(failures === 0 ? 0 : 1)
