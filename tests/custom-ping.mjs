// ۱.۳.۰ — صفحهٔ کانفیگ‌های سفارشی: دکمهٔ پینگِ هر کارت، «Test all»، برچسبِ وضعیت
// و پاک‌شدنِ نویسه‌های نامرئی هنگامِ چسباندن (jsdom، IPCِ ساختگی).
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

const VIEW = {
  enabled: false, mode: 'SOLO', modeLabel: 'VLESS', activeId: 'a',
  modes: [{ id: 'SOLO', label: 'Config', hops: 1 }],
  configs: [
    { id: 'a', name: 'one', protocol: 'VLESS', format: 'URI', source: 'LINK', server: '', locked: true, note: '', expiresAt: 0, expired: false, addedAt: 1, chainLabel: 'VLESS', shareable: false },
    { id: 'b', name: 'two', protocol: 'VLESS', format: 'URI', source: 'LINK', server: '', locked: false, note: '', expiresAt: 0, expired: false, addedAt: 2, chainLabel: 'VLESS', shareable: true },
  ],
  max: 500, qr: false,
}
const invoked = []
window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    invoked.push([cmd, args])
    if (cmd === 'plugin:event|listen') return Promise.resolve(1)
    if (cmd === 'cc_state') return Promise.resolve(VIEW)
    if (cmd === 'get_snapshot') {
      return Promise.resolve({
        state: 'DISCONNECTED', detail: '', serverIp: '', country: '', downRate: 0, upRate: 0,
        downTotal: 0, upTotal: 0, connectedSeconds: 0, protocol: 'SMART', endpoint: '',
        latencyMs: -1, leak: 'SAFE', backend: 'AETHER',
      })
    }
    if (cmd === 'cc_ping') return Promise.resolve({ results: [{ id: args.id, ms: 312, status: 'ok', label: 'OK' }] })
    if (cmd === 'cc_ping_all') {
      return Promise.resolve({ results: [
        { id: 'a', ms: 140, status: 'ok', label: 'OK' },
        { id: 'b', ms: -1, status: 'blocked', label: 'Filtered' },
      ] })
    }
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
  metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
}

await import('../src/main.js').then(async m => { await m.bootReady; return m })
const cc = await import('../src/views/customconfigs.js')
const { setLang } = await import('../src/i18n.js')

let failures = 0
const check = (ok, what) => {
  console.log((ok ? '  ok   ' : '  FAIL ') + what)
  if (!ok) failures++
}
const tick = () => new Promise((r) => setTimeout(r, 5))

// --- paste hygiene
const dirty = '\u200F\u2067vless://u@\u200Bhost.example:443?sni=x#\u0645\u200C\u0646\u2069\uFEFF'
const clean = cc.stripInvisible(dirty)
check(clean === 'vless://u@host.example:443?sni=x#\u0645\u200C\u0646', 'stripInvisible حذفِ RLM/isolate/ZWSP/BOM و نگه‌داشتنِ ZWNJ')
check(cc.stripInvisible('a\u00A0b\r\nc') === 'a b\nc', 'فاصلهٔ نشکن و CRLF یکسان می‌شوند')

// --- labels
check(cc.pingText({ ms: 88 }) === '88 ms', 'عدد بر حسبِ ms')
check(cc.pingText({ ms: -1, label: 'Server off' }) === '-1 · Server off', 'وضعیتِ Server off')
check(cc.pingText({ ms: -1, label: 'No response' }) === '-1 · No response', 'وضعیتِ No response (−1)')
check(cc.pingText({ ms: -1, label: 'Invalid config' }) === '-1 · Invalid config', 'وضعیتِ Invalid config')
setLang('fa')
check(cc.pingText({ ms: -1, label: 'Filtered' }) === '-1 · فیلتر شده', 'برچسبِ فارسیِ Filtered')
setLang('en')

// --- render
await cc.refreshCustomConfigs()
const root = cc.renderCustomConfigs()
document.getElementById('view').appendChild(root)
await tick()
const rows = root.querySelectorAll('.ccfg')
check(rows.length === 2, 'دو کارت رندر شد')
const actionButtons = root.querySelectorAll('.ccfg__actions')
check(actionButtons.length === 2, 'هر کارت دکمهٔ منوی عملیات دارد (قفل‌شده هم)')
const all = root.querySelector('.cc-ping-all')
check(!!all && !all.hidden, 'دکمهٔ Test all دیده می‌شود')

actionButtons[1].click()
await tick()
const pingItem = [...document.querySelectorAll('.mlist .mbtn')].find((b) => b.textContent === 'Test ping')
check(!!pingItem, 'منوی عملیات گزینهٔ Test ping دارد')
pingItem.click()
await tick()
check(invoked.some(([c, a]) => c === 'cc_ping' && a?.id === 'b'), 'cc_ping با شناسهٔ همان کارت')
check(!invoked.some(([c]) => c === 'cc_select'), 'زدنِ پینگ کارت را انتخاب نمی‌کند')
check(root.querySelector('.ccfg[data-id="b"]').querySelector('.ccfg__ping')?.textContent === '312 ms', 'نتیجهٔ پینگ روی کارت')

root.querySelector('.cc-ping-all').click()
await tick()
check(invoked.some(([c]) => c === 'cc_ping_all'), 'cc_ping_all فراخوانده شد')
const chips = [...root.querySelectorAll('.ccfg__ping')].map((e) => e.textContent)
check(chips[0] === '140 ms' && chips[1] === '-1 · Filtered', 'نتایجِ Test all روی هر دو کارت')
check(root.querySelectorAll('.ccfg__ping.is-muted').length === 1, 'کلاسِ is-muted برای −1')

// --- paste event
root.querySelector('.cc-add').click()
await tick()
;[...document.querySelectorAll('.mlist .mbtn')].find((b) => b.textContent === 'Link or text').click()
await tick()
const paste = document.querySelector('.cc-paste')
const ev = new window.Event('paste', { bubbles: true, cancelable: true })
ev.clipboardData = { getData: () => dirty }
paste.dispatchEvent(ev)
check(paste.value === clean, 'چسباندن در textarea نویسه‌های نامرئی را حذف می‌کند')

if (failures) {
  console.log(`\nCUSTOM PING: ${failures} failure(s)`)
  process.exit(1)
}
console.log('\nCUSTOM PING OK')
process.exit(0)
