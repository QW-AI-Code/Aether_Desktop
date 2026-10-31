// هارنس منوی تنظیمات + دستیار (jsdom).
//
// چیزی که این تست واقعاً ثابت می‌کند: هر ردیفِ هاب باز می‌شود، زیرصفحه‌اش
// کنترل‌های واقعی را از advanced.js می‌گیرد، هر گزینه یک ✨ می‌گیرد، و در مجموعِ
// همهٔ زیرصفحه‌ها **هیچ** کلیدِ پروفایلی از قلم نیفتاده. آخری مهم‌ترین است:
// شکستنِ پنل به بخش‌ها می‌توانست یک گزینه را بی‌صدا از دسترس کاربر خارج کند.
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!doctype html><html><body><div id="view"></div></body></html>', {
  url: 'http://localhost/',
  pretendToBeVisual: true,
})
globalThis.window = dom.window
globalThis.document = dom.window.document
globalThis.HTMLElement = dom.window.HTMLElement
globalThis.localStorage = dom.window.localStorage
// navigator در Node 22 فقط getter است؛ jsdom بدون آن هم کار می‌کند.
globalThis.requestAnimationFrame = (fn) => setTimeout(() => fn(0), 0)
globalThis.cancelAnimationFrame = clearTimeout
window.confirm = () => false

// همهٔ IPCها ثبت می‌شوند تا بتوان بررسی کرد چه چیزی ذخیره شد.
const invoked = []
// روی `window` می‌نشیند و نه globalThis: خودِ @tauri-apps/api از window می‌خواند.
window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    invoked.push([cmd, args])
    if (cmd === 'plugin:event|listen') return Promise.resolve(1)
    if (cmd === 'core_caps') {
      return Promise.resolve({ zeroTrust: true, routing: true, customDns: true, upstream: true, routeSniff: true, tls24: true })
    }
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
  metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
}

const PROFILE = {
  backend: 'AETHER_PSIPHON', exitRegion: 'DE', protocol: 'SMART', scanMode: 'BALANCED',
  ipVersion: 'V4', noize: 'FIREWALL', endpointMode: 'MANUAL_PEER', manualPeer: '1.2.3.4:443',
  manualRange: '', mtu: 1380, keepalive: 25, quickReconnect: true, masqueHttp2: false,
  fragment: true, ech: true, lanShare: false, killSwitch: true, ipv6Protection: true,
  reconnectAttempts: 5, splitMode: 'INCLUDE', splitApps: ['chrome.exe'], team: 'acme',
  accessMode: 'SERVICE_TOKEN', accessEmail: '', accessId: 'x.access', gateway: false,
  routeBlock: ['ads.example.com'], routeDirect: ['bank.ir'], routeSniff: true,
  dns: ['1.1.1.1'], upstream: 'socks5://127.0.0.1:1080', reprovision: true,
}

const main = await import('../src/main.js').then(async m => { await m.bootReady; return m })
main.app.profile = PROFILE
main.app.snapshot = { ...main.app.snapshot, state: 'CONNECTED' }

const { renderSettings, SETTINGS_ROWS } = await import('../src/views/settings.js')

let failures = 0
const check = (ok, what) => {
  console.log((ok ? '  ok   ' : '  FAIL ') + what)
  if (!ok) failures++
}

// ---- هاب ----
const view = renderSettings()
document.getElementById('view').appendChild(view)
const hubRows = view.querySelectorAll('.setrow')
console.log('rows in hub =', hubRows.length)
// +2: دو سوییچ «نمایش و صدا» (انیمیشن صفحهٔ اصلی، صدای اتصال) مستقیماً در هاب‌اند.
check(hubRows.length === SETTINGS_ROWS.length + 1 + 2, 'هر ردیف + دو سوییچ نمایش‌وصدا + ردیف بازنشانی رندر شد')
check(view.querySelectorAll('.setrow .aihint').length === hubRows.length, 'هر ردیف هاب یک ✨ دارد')
check(view.querySelector('.setnotice')?.hidden === false, 'با تونلِ وصل، نوار اطلاع دیده می‌شود')

// مقدار فعلی باید برچسبِ خوانا باشد و نه نام داخلی.
const values = [...view.querySelectorAll('.setrow__value')].map((v) => v.textContent)
console.log('values =', JSON.stringify(values))
check(values.includes('Aether \u2192 Psiphon'), 'مقدار بک‌اند با نام خوانا نشان داده می‌شود')
check(!values.some((v) => v.includes('_')), 'هیچ نام داخلیِ SNAKE_CASE به کاربر نشان داده نمی‌شود')

// ---- هر زیرصفحه ----
const seen = new Set()
for (const row of SETTINGS_ROWS) {
  const el = [...view.querySelectorAll('.setrow__title')].find((x) => x.textContent === row.title)
  el.closest('.setrow').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
  const controls = view.querySelectorAll('.seg, .select, .switch, .input, .fdrop')
  const hints = view.querySelectorAll('.field__head .aihint')
  const labels = view.querySelectorAll('.field:not(.field--verify) .field__label')
  console.log(`${row.id}: controls=${controls.length} labels=${labels.length} ✨=${hints.length}`)
  // `controlless`: زیرصفحه‌ای که فقط خواندنی است (بایگانیِ پیام‌ها) کنترلی ندارد.
  check(row.controlless || controls.length > 0, `${row.id}: کنترل‌های واقعی رندر شدند`)
  check(hints.length === labels.length, `${row.id}: هر گزینه یک ✨ گرفت`)
  check(!!view.querySelector('.setpage__back'), `${row.id}: دکمهٔ بازگشت هست`)
  for (const c of controls) {
    const key = c.dataset.key ?? c.closest('[data-key]')?.dataset.key
    if (key) seen.add(key)
  }
  // بازگشت به هاب
  view.querySelector('.setpage__back').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
  check(view.querySelectorAll('.setrow').length === hubRows.length, `${row.id}: بازگشت به هاب کار می‌کند`)
}

// ---- هیچ گزینه‌ای گم نشده ----
const EXPECTED = [
  '__lang', 'backend', 'exitRegion', 'protocol', 'scanMode', 'ipVersion', 'noize',
  'endpointMode', 'manualPeer', 'mtu', 'keepalive', 'quickReconnect', 'masqueHttp2',
  'fragment', 'ech', 'lanShare', 'killSwitch', 'ipv6Protection', 'reconnectAttempts',
  'splitMode', 'splitApps', 'team', 'accessMode', 'accessId', 'accessSecret', 'gateway',
  'routeBlock', 'routeDirect', 'routeSniff', 'dns', 'upstream', 'reprovision',
  // core 2.4.0 TLS / API options
  'masqueSni', 'apiAddress', 'apiSni', 'apiHost', 'tlsVerify', 'tlsTrustAnchors',
  'tlsCertCompression', 'tlsCiphers', 'tls13Ciphers', 'tlsGroups', 'tlsKeyShares',
  'tlsSigalgs', 'tlsAlps', 'tlsServerPadding', 'disableGrease', 'enableGreaseSigalgs',
  'enableEchGrease', 'disableOcspStapling', 'disableSct', 'disableSessionTicket',
  'disableExtensionPermutation',
]
const missing = EXPECTED.filter((k) => !seen.has(k))
console.log('keys reachable =', seen.size)
check(missing.length === 0, `هیچ کلیدی از دسترس خارج نشده${missing.length ? ' — گم‌شده: ' + missing.join(', ') : ''}`)

// ---- سیم‌کشیِ ذخیره در زیرصفحه ----
const conn = [...view.querySelectorAll('.setrow__title')].find((x) => x.textContent === 'Connection')
conn.closest('.setrow').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
const item = [...view.querySelectorAll('.seg[data-key="protocol"] .seg__item')].find((b) => b.dataset.value === 'WIREGUARD')
item.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
await new Promise((r) => setTimeout(r, 20))
const saved = invoked.filter(([c]) => c === 'set_profile').pop()
check(saved?.[1]?.profile?.protocol === 'WIREGUARD', 'تغییر در زیرصفحه با set_profile ذخیره می‌شود')

// ---- کلیک ✨ ردیف، زیرصفحه را باز نمی‌کند ----
view.querySelector('.setpage__back').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
const before = view.querySelector('.sethub') !== null
view.querySelector('.setrow .aihint').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
check(before && view.querySelector('.sethub') !== null, 'کلیک روی ✨ ردیف را باز نمی‌کند')
check(document.querySelector('.aibubble') !== null, 'حبابِ توضیح باز شد')
check(document.querySelector('.aibubble__body').classList.contains('is-blocked'), 'بی‌کلید، حباب پیام دروازه را می‌دهد و درخواستی نمی‌فرستد')
check(!invoked.some(([c]) => c === 'ai_explain'), 'با دروازهٔ بسته هیچ ai_explain فرستاده نشد')

console.log(failures === 0 ? '\nALL OK' : `\n${failures} FAILED`)
process.exit(failures === 0 ? 0 : 1)
