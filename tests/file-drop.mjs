// ۱.۳.۰ — رها کردنِ فایلِ کانفیگ روی پنجره: هر سه مسیر (رویدادِ بومیِ تائوری،
// `aether://file-drop`ِ Rust برای برنامهٔ ارتقایافته، و drop‌ِ HTML5 با File
// واقعی) باید به ورود برسند و کانفیگ در فهرست دیده شود (jsdom، IPCِ ساختگی).
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!doctype html><html><body><div id="view"></div></body></html>', {
  url: 'http://localhost/',
  pretendToBeVisual: true,
})
globalThis.window = dom.window
globalThis.document = dom.window.document
globalThis.HTMLElement = dom.window.HTMLElement
globalThis.localStorage = dom.window.localStorage
globalThis.FileReader = dom.window.FileReader
globalThis.requestAnimationFrame = (fn) => setTimeout(() => fn(0), 0)
globalThis.cancelAnimationFrame = clearTimeout

const cfg = (id, name) => ({
  id, name, protocol: 'VLESS', format: 'URI', source: 'FILE', server: '', locked: false, note: '',
  expiresAt: 0, expired: false, addedAt: Date.now(), chainLabel: 'VLESS', shareable: true,
})
const VIEW = {
  enabled: false, mode: 'SOLO', modeLabel: 'Config', activeId: null,
  modes: [{ id: 'SOLO', label: 'Config', hops: 1 }], configs: [], max: 500, qr: false,
}
const LINK = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@203.0.113.9:443?security=tls&sni=a.example#dropped'
const listeners = new Map()
const invoked = []
const add = (name) => {
  VIEW.configs = [...VIEW.configs, cfg(`c${VIEW.configs.length + 1}`, name)]
  return { ...VIEW, added: 1 }
}
window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    invoked.push([cmd, args])
    if (cmd === 'plugin:event|listen') {
      const list = listeners.get(args.event) ?? []
      list.push(args.handler)
      listeners.set(args.event, list)
      return Promise.resolve(listeners.size)
    }
    if (cmd === 'cc_state') return Promise.resolve(VIEW)
    if (cmd === 'get_snapshot') {
      return Promise.resolve({
        state: 'DISCONNECTED', detail: '', serverIp: '', country: '', downRate: 0, upRate: 0,
        downTotal: 0, upTotal: 0, connectedSeconds: 0, protocol: 'SMART', endpoint: '',
        latencyMs: -1, leak: 'SAFE', backend: 'AETHER',
      })
    }
    if (cmd === 'cc_import_path') return Promise.resolve(add(args.path.split(/[\\/]/).pop()))
    if (cmd === 'cc_import_bytes') {
      if (new TextDecoder().decode(new Uint8Array(args.bytes)).trim() !== LINK) return Promise.reject({ kind: 'invalid', message: 'bad content' })
      return Promise.resolve(add(args.name))
    }
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
  metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
}

await import('../src/main.js').then(async m => { await m.bootReady; return m })
const cc = await import('../src/views/customconfigs.js')
const { setLang, t } = await import('../src/i18n.js')

let failures = 0
const check = (ok, what) => {
  console.log((ok ? '  ok   ' : '  FAIL ') + what)
  if (!ok) failures++
}
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms))
const fire = (name, payload) => (listeners.get(name) ?? []).forEach((h) => h({ event: name, id: 1, payload }))
const calls = (cmd) => invoked.filter(([c]) => c === cmd)

const root = cc.renderCustomConfigs()
document.getElementById('view').appendChild(root)
await tick()
const zone = (root.classList.contains('view--custom') ? root : root.querySelector('.view--custom'))
const configCount = () => root.querySelectorAll('.ccfg').length

for (const ev of ['tauri://drag-enter', 'tauri://drag-over', 'tauri://drag-drop', 'tauri://drag-leave', 'aether://file-drop']) {
  check(listeners.has(ev), `به ${ev} گوش داده می‌شود`)
}
check(!!zone && configCount() === 0, 'فهرست خالی است')

// --- ۱) رویدادِ بومیِ تائوری
fire('tauri://drag-enter', { paths: ['C:\\cfg\\a.npvt'], position: { x: 1, y: 1 } })
check(zone.classList.contains('is-over'), 'drag-enter کادر را روشن می‌کند')
fire('tauri://drag-leave', null)
check(!zone.classList.contains('is-over'), 'drag-leave کادر را خاموش می‌کند')
fire('tauri://drag-over', { position: { x: 3, y: 3 } })
fire('tauri://drag-drop', { paths: ['C:\\cfg\\a.npvt'], position: { x: 3, y: 3 } })
await tick()
check(!zone.classList.contains('is-over'), 'پس از drop کادر خاموش است')
check(calls('cc_import_path').length === 1 && calls('cc_import_path')[0][1].path === 'C:\\cfg\\a.npvt', 'tauri://drag-drop → cc_import_path با همان مسیر')
check(configCount() === 1 && root.querySelectorAll('.ccfg').length === 1, 'کانفیگِ رهاشده در فهرست است')

// --- ۲) مسیرِ برنامهٔ ارتقایافته (WM_DROPFILES در filedrop.rs)
fire('aether://file-drop', ['D:\\x\\b.json', 'D:\\x\\c.conf'])
await tick()
const paths = calls('cc_import_path').map(([, a]) => a.path)
check(paths.includes('D:\\x\\b.json') && paths.includes('D:\\x\\c.conf'), 'aether://file-drop هر دو فایل را وارد می‌کند')
check(configCount() === 3, 'سه کانفیگ در فهرست')
// همان رها کردن اگر از دو مسیر برسد، یک بار وارد می‌شود.
fire('tauri://drag-drop', { paths: ['D:\\x\\b.json'] })
await tick()
check(calls('cc_import_path').length === 3, 'رها کردنِ تکراری از مسیرِ دوم نادیده گرفته می‌شود')

// --- ۳) drop‌ِ HTML5 با File واقعی (محتوا خوانده و فرستاده می‌شود)
const file = new window.File([LINK + '\n'], 'free.txt', { type: 'text/plain' })
const dt = { types: ['Files'], files: [file], dropEffect: 'none' }
const over = new window.Event('dragover', { bubbles: true, cancelable: true })
over.dataTransfer = dt
zone.dispatchEvent(over)
check(over.defaultPrevented && dt.dropEffect === 'copy', 'dragover پذیرفته می‌شود (preventDefault + copy)')
check(zone.classList.contains('is-over'), 'dragover کادر را روشن می‌کند')
const drop = new window.Event('drop', { bubbles: true, cancelable: true })
drop.dataTransfer = dt
zone.dispatchEvent(drop)
check(drop.defaultPrevented, 'drop پیش‌فرضِ WebView (باز کردنِ فایل) را می‌گیرد')
await tick(60)
const f = calls('cc_import_bytes')
check(f.length === 1 && f[0][1].name === 'free.txt' && new TextDecoder().decode(new Uint8Array(f[0][1].bytes)).trim() === LINK, 'محتوای فایل خوانده و با cc_import_bytes فرستاده شد')
check(configCount() === 4, 'کانفیگِ فایلِ HTML5 در فهرست است')

// فایلِ باینریِ NPVS (بایت‌های ≥ 0x80) باید بی‌هیچ تبدیلِ متنی به Rust برسد.
{
  const raw = new Uint8Array(1106)
  raw.set([0x4e, 0x50, 0x56, 0x53, 5, 0, 0, 0, 0x87], 0)
  for (let i = 9; i < raw.length; i++) raw[i] = (i * 37 + 0x80) & 0xff
  const bin = new window.File([raw], 'config.npvs', { type: 'application/octet-stream' })
  const btDrop = new window.Event('drop', { bubbles: true, cancelable: true })
  btDrop.dataTransfer = { types: ['Files'], files: [bin], dropEffect: 'none' }
  zone.dispatchEvent(btDrop)
  await tick(60)
  const sent = calls('cc_import_bytes').find(([, a]) => a.name === 'config.npvs')
  check(!!sent && sent[1].bytes.length === raw.length && sent[1].bytes.every((b, i) => b === raw[i]),
    'فایل .npvs به‌صورت بایتِ خام (بدون تبدیل UTF-8) با cc_import_bytes ارسال می‌شود')
  check(!calls('cc_import_file').length, 'مسیر متنیِ cc_import_file برای NPVS استفاده نمی‌شود')
}

// کشیدنِ متن (نه فایل) به textarea دست نمی‌خورد.
const textOver = new window.Event('dragover', { bubbles: true, cancelable: true })
textOver.dataTransfer = { types: ['text/plain'], files: [] }
;(root.querySelector('.cc-paste') ?? document.body).dispatchEvent(textOver)
check(!textOver.defaultPrevented, 'کشیدنِ متن به textarea رفتارِ عادی دارد')

// --- دکمهٔ «تست همه»
setLang('fa')
check(t('Test all') === 'پینگ همه', 'ترجمهٔ فارسیِ Test all')
document.getElementById('view').replaceChildren(cc.renderCustomConfigs())
await tick()
check(document.querySelector('.cc-ping-all__title')?.textContent === 'پینگ همه', 'دکمه در رابطِ فارسی «پینگ همه» است')

// --- بیرون از صفحه، رها کردن کاری نمی‌کند
document.getElementById('view').replaceChildren()
const before = invoked.length
fire('tauri://drag-drop', { paths: ['E:\\other.npvt'] })
await tick()
check(!invoked.slice(before).some(([c]) => c === 'cc_import_path'), 'بیرون از صفحهٔ کانفیگ‌ها چیزی وارد نمی‌شود')

if (failures) {
  console.log(`\nFILE DROP: ${failures} failure(s)`)
  process.exit(1)
}
console.log('\nFILE DROP OK')
process.exit(0)
