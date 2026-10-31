// هارنس صفحهٔ دستیار (jsdom) — دقیقاً همان چهار اشکالی که در ۱.۲.۴ گزارش شد.
//
// این تست عمداً روی *رفتار* می‌ایستد و نه روی ظاهر: اینکه ذخیرهٔ کلید بازخورد
// می‌دهد، دکمهٔ تست اتصال وجود دارد و فرمانِ درست را می‌فرستد، نتیجهٔ probe به
// خط خلاصه می‌رسد، و هیچ تگِ HTMLی به‌صورت متن از ترجمه‌ها بیرون نمی‌زند.
import { JSDOM } from 'jsdom'

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

const SNAPSHOT = {
  state: 'CONNECTED', detail: '', serverIp: '139.162.179.163', country: 'DE',
  downRate: 0, upRate: 0, downTotal: 0, upTotal: 0, connectedSeconds: 8,
  protocol: 'WIREGUARD', endpoint: '188.114.99.205:3581', latencyMs: 199,
  leak: 'SAFE', backend: 'AETHER_PSIPHON',
}
// ردیف‌های بررسی: عیناً شکلی که `get_checks` برمی‌گرداند — یکی با شرح و یکی
// بی‌شرح، چون همین دومی بود که سطر دومِ گرید را بی‌دلیل باز می‌کرد.
const CHECKS = [
  { id: 'tun', label: 'TUN adapter', state: 'PASS', detail: 'Wintun 0.14 attached to \\Device\\Aether' },
  { id: 'dns', label: 'DNS inside tunnel', state: 'PASS', detail: '' },
  { id: 'handshake', label: 'SOCKS5 handshake', state: 'FAIL', detail: 'connection refused on 127.0.0.1:1080' },
]

const invoked = []
window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    invoked.push([cmd, args])
    if (cmd === 'plugin:event|listen') return Promise.resolve(1)
    if (cmd === 'core_caps') return Promise.resolve({ zeroTrust: true, routing: true, customDns: true, upstream: true, routeSniff: true })
    if (cmd === 'get_snapshot') return Promise.resolve(SNAPSHOT)
    if (cmd === 'get_checks') return Promise.resolve(CHECKS)
    if (cmd === 'read_logs') return Promise.resolve([])
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
  metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
}

await import('../src/main.js').then(async m => { await m.bootReady; return m })
const { ai, applyAiSnapshot, refreshAi } = await import('../src/ai.js')
const { renderAssistant } = await import('../src/views/assistant.js')
const { renderDiagnostics } = await import('../src/views/diagnostics.js')
const { t, setLang, LANGS } = await import('../src/i18n.js')

let failures = 0
const check = (ok, what) => {
  console.log((ok ? '  ok   ' : '  FAIL ') + what)
  if (!ok) failures++
}
const tick = () => new Promise((r) => setTimeout(r, 0))

// ---------------------------------------------------------------- ۱) کلید API
applyAiSnapshot({
  hasKey: false, keyHint: '', models: [], selectedModel: '', busy: false,
  gateCode: 'NO_KEY', error: null, messages: [], advisor: null,
  probe: { state: 'IDLE', modelCount: 0, via: '', message: '' },
})

const view = renderAssistant()
document.getElementById('view').replaceChildren(view)

const input = view.querySelector('.ai__keyrow input')
check(!!input, 'فیلد کلید رندر شد')
check(input.classList.contains('input'), 'فیلد کلاسِ استایل‌دارِ .input را دارد (نه field__input)')
check(input.classList.contains('ltr'), 'فیلد کلید در فارسی هم چپ‌چین است')
check(input.type === 'password', 'کلید پیش‌فرض پوشیده است')

const reveal = [...view.querySelectorAll('.ai__keyactions .btn')].find((b) => b.textContent === t('Show'))
check(!!reveal, 'دکمهٔ نمایش کلید هست')
reveal.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
check(input.type === 'text', 'نمایش/پنهان کار می‌کند')
reveal.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))

input.value = 'AIzaTESTKEY'
const save = [...view.querySelectorAll('.ai__keyrow .btn')].find((b) => b.textContent === t('Save'))
save.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
await tick(); await tick()
const setCall = invoked.find(([c]) => c === 'ai_set_key')
check(!!setCall && setCall[1].key === 'AIzaTESTKEY', 'ai_set_key با کلید فرستاده شد')
check(input.value === '' && input.type === 'password', 'فیلد بعد از ذخیره پاک و پوشیده شد')
const toastEl = document.querySelector('.toast')
check(!!toastEl && toastEl.textContent === t('API key saved.'), 'پیام موفقیت ذخیره نمایش داده شد')
// توست با opacity صفر شروع می‌شود؛ بی کلاسِ is-shown دیده نمی‌شود.
await tick()
check(document.querySelector('.toast')?.classList.contains('is-shown'), 'توست واقعاً دیده می‌شود (is-shown)')

// -------------------------------------------------------- ۲) تست اتصال به API
const testBtn = [...view.querySelectorAll('.btn')].find((b) => b.textContent === t('Test the API connection'))
check(!!testBtn, 'دکمهٔ «تست اتصال به API» وجود دارد')
check(testBtn.disabled === true, 'بی‌کلید، دکمهٔ تست غیرفعال است')

applyAiSnapshot({ ...ai, hasKey: true, keyHint: 'TKEY', gateCode: 'READY' })
check(testBtn.disabled === false, 'با کلیدِ ذخیره‌شده دکمهٔ تست فعال می‌شود')
testBtn.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
await tick()
check(invoked.some(([c]) => c === 'ai_test_key'), 'کلیک، فرمان ai_test_key را می‌فرستد')

applyAiSnapshot({ ...ai, probe: { state: 'OK', modelCount: 7, via: 'Aether → Psiphon', message: '' } })
let summary = view.querySelector('.ai__probe.is-ok')
check(!!summary && summary.textContent.includes('7') && summary.textContent.includes('Psiphon'),
  'نتیجهٔ موفق با شمار مدل و مسیر نمایش داده می‌شود')

applyAiSnapshot({ ...ai, probe: { state: 'FAILED', modelCount: 0, via: '', message: 'HTTP 400: API key not valid' } })
summary = view.querySelector('.ai__probe.is-bad')
check(!!summary && summary.textContent.includes('API key not valid'), 'پیام خطای واقعی به کاربر می‌رسد')

applyAiSnapshot({ ...ai, busy: true })
check(view.querySelector('.ai__probe').textContent === t('Testing…'), '«در حال تست…» بر نتیجهٔ کهنه مقدم است')
applyAiSnapshot({ ...ai, busy: false })

// مدل‌ها حتی با فهرستِ کش‌شده بدون کلید یا بدون تونل نمایش داده نمی‌شوند.
const offered = [
  'gemini-3.8-flash', 'gemini-3.7-flash', 'gemini-3.5-flash-lite',
  'gemini-3.1-flash-lite', 'gemini-3.1-flash-lite-preview', 'gemini-flash-lite-latest',
].map((id) => ({ id, outputTokenLimit: 2048 }))
const modelBox = view.querySelector('.ai__models').parentElement
applyAiSnapshot({ ...ai, hasKey: false, tunnelConnected: true, models: offered })
check(modelBox.hidden && !view.querySelector('.ai__model'), 'بدون کلید، مدل‌های کش‌شده پنهان‌اند')
applyAiSnapshot({ ...ai, hasKey: true, tunnelConnected: false, models: offered })
check(modelBox.hidden && !view.querySelector('.ai__model'), 'با تونل قطع، مدل‌های کش‌شده پنهان‌اند')
applyAiSnapshot({ ...ai, hasKey: true, tunnelConnected: true, models: offered })
check(!modelBox.hidden && view.querySelectorAll('.ai__model').length === 6,
  'پس از کلید و اتصال، مدل‌های مجاز نمایش داده می‌شوند')
check(view.querySelectorAll('.ai__modelmeta').length === 6,
  'برای هر شش مدل موبایل، توضیح محدودیت روزانه نمایش داده می‌شود')
check(view.querySelectorAll('.ai__modelmeta')[3].textContent ===
  'Default · highest daily limit, best for continuous everyday use',
  'توضیح مدل پیش‌فرض عیناً با موبایل یکی است')
setLang('fa')
const faDesc = view.querySelectorAll('.ai__modelmeta')[3].textContent
// Changing language rebuilds the view, as in production.
const faView = renderAssistant()
document.getElementById('view').replaceChildren(faView)
check(faView.querySelectorAll('.ai__modelmeta')[3].textContent ===
  'پیش‌فرض · سقف مصرف روزانهٔ بالا، بهینه برای استفادهٔ مداوم',
  'توضیح فارسی مدل پیش‌فرض عیناً با موبایل یکی است')
setLang('en')

// پاسخ قدیمیِ ai_snapshot نباید اتصال جدیدتر را دوباره «قطع» نشان دهد.
const savedInvoke = window.__TAURI_INTERNALS__.invoke
let finishOld
window.__TAURI_INTERNALS__.invoke = (command, args) =>
  command === 'ai_snapshot' ? new Promise((resolve) => { finishOld = resolve }) : savedInvoke(command, args)
const pendingOld = refreshAi()
applyAiSnapshot({ ...ai, gateCode: 'READY', tunnelConnected: true })
finishOld({ ...ai, gateCode: 'DISCONNECTED', tunnelConnected: false })
await pendingOld
check(ai.gateCode === 'READY' && ai.tunnelConnected,
  'snapshot دیررس نمی‌تواند وضعیت اتصال تازه‌تر را بازنویسی کند')
window.__TAURI_INTERNALS__.invoke = savedInvoke

// ------------------------------------------------- ۳) هیچ تگی به‌صورت متن
const TAGISH = /<[^>]+>|&[a-z]+;/i
const leaked = []
for (const [lang] of LANGS) {
  setLang(lang)
  const strings = new Set()
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 3) strings.add(child.textContent)
      else walk(child)
    }
  }
  const v = renderAssistant()
  document.getElementById('view').replaceChildren(v)
  walk(v)
  const d = renderDiagnostics()
  document.getElementById('view').replaceChildren(d)
  walk(d)
  for (const s of strings) if (TAGISH.test(s)) leaked.push(`${lang}: ${s}`)
}
console.log('leaked tags =', leaked.length)
check(leaked.length === 0, 'هیچ تگ HTML به‌صورت متن نمایش داده نمی‌شود' + (leaked.length ? ` — ${leaked[0]}` : ''))

// رشته‌های تازه باید ترجمهٔ فارسی داشته باشند، وگرنه رابط فارسی انگلیسی می‌ماند.
setLang('fa')
const NEW_KEYS = [
  'Show', 'Hide', 'API key saved.', 'API key removed', 'Test the API connection',
  'Testing…', 'Checks the key and lists the models it may use',
  'Working — {0} model(s) available through {1}', 'Not working: {0}',
]
const untranslated = NEW_KEYS.filter((k) => t(k) === k)
check(untranslated.length === 0, 'هر رشتهٔ تازه ترجمهٔ فارسی دارد' + (untranslated.length ? ` — ${untranslated.join(', ')}` : ''))

// ۱.۲.۵ — پیام‌های شکستِ تور از Rust می‌آیند (`snapshot.detail`) و در home.js
// از `t()` می‌گذرند. سنجهٔ مهم، همان پیامِ دارای درصد است: جمله‌ای که یک عدد
// داخلش است هیچ‌وقت در جدولی که به متنِ دقیق کلید می‌زند پیدا نمی‌شود، پس تا
// پیش از ۱.۲.۵ درست همان جمله‌ای انگلیسی می‌ماند که کاربر در لحظهٔ خطا می‌خواند.
const TOR_FAILURES = [
  'The tunnel started but the self-test failed.',
  'The tunnel is up, but Tor never reported any progress from inside it. Try Tor on its own, which lets Tor pick its own way to the network.',
  'The engine started but Tor never reported any progress towards the Tor network, and no pluggable transport is installed. Use the Aether \u2192 Tor mode, which builds Tor inside the tunnel.',
]
const torUntranslated = TOR_FAILURES.filter((k) => t(k) === k)
check(torUntranslated.length === 0,
  'پیام‌های شکستِ تور ترجمه دارند' + (torUntranslated.length ? ` — ${torUntranslated.length} مانده` : ''))

const withPercent = 'Tor stopped at 15% and could not reach the Tor network. No pluggable transport is installed, so only plain bridges can be tried \u2014 and a network that filters Tor usually blocks those too. Use the Aether \u2192 Tor mode: Tor is then dialled through the tunnel, where the operator cannot see or block it.'
const translated = t(withPercent)
check(translated !== withPercent && translated.includes('15'),
  `پیامِ دارای درصد هم ترجمه شد و عدد سرِ جایش ماند (${translated.slice(0, 24)}…)`)

// و عددِ دیگری همان ترجمه را می‌گیرد — یعنی یک الگو، نه یک ورودیِ دستی برای ۱۵٪.
const other = t(withPercent.replace('15%', '80%'))
check(other !== withPercent && other.includes('80'), 'همان الگو برای هر درصدی کار می‌کند')

// جداسازهای یونیکد باید جای <bdi> نشسته باشند، آن هم جفت‌به‌جفت.
const isolated = t('Add an app by its executable name, for example <bdi>chrome.exe</bdi>.')
const opens = [...isolated].filter((c) => c === '\u2068').length
const closes = [...isolated].filter((c) => c === '\u2069').length
check(!isolated.includes('<bdi>') && opens > 0 && opens === closes,
  `<bdi> به جداسازِ یونیکد تبدیل شد (${opens} جفت)`)

// ------------------------------------------- ۴) ردیف‌های بررسی: چهار فرزند
const diag = renderDiagnostics()
document.getElementById('view').replaceChildren(diag)
// `refresh()` خودکار اجرا نمی‌شود: پنل با دیده‌شدنِ خودش شروع و با پنهان‌شدنش
// متوقف می‌شود (`__onShow`/`__onHide`، همان چیزی که جای MutationObserver سراسری
// را گرفت). پس تست هم باید همان قرارداد را رعایت کند.
diag.__onShow()
for (let i = 0; i < 5; i++) await tick()
diag.__onHide()
const rows = [...diag.querySelectorAll('.check')]
console.log('check rows =', rows.length)
check(rows.length === CHECKS.length, 'ردیف‌های بررسی رندر شدند')
const withEmptyDetail = rows.filter((r) => {
  const d = r.querySelector('.check__detail')
  return d && d.textContent.trim() === ''
})
check(withEmptyDetail.length === 0, 'شرحِ خالی رندر نمی‌شود (سطر دوم گرید بی‌دلیل باز نمی‌ماند)')
const details = rows.map((r) => r.querySelector('.check__detail')).filter(Boolean)
check(details.length === 2 && details.every((d) => d.getAttribute('dir') === 'ltr'),
  'هر شرحِ موجود با dir=ltr رندر می‌شود')

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL OK')
process.exit(failures ? 1 : 0)
