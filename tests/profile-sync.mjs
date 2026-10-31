// هارنسِ «تنظیماتِ اعمال‌شده واقعاً روی صفحه می‌آید» (jsdom).
//
// این فایل برای یک اشکالِ گزارش‌شدهٔ کاربر نوشته شده: دستیار تنظیمی را پیشنهاد
// می‌داد، کاربر «اعمال» را می‌زد، پنجرهٔ تأیید می‌آمد — و برنامه همان مقدارِ قبلی
// را نشان می‌داد. لاگِ کاربر ثابت کرد نوشتن انجام شده بود (اتصالِ بعدی با
// `--masque` و بعدتر با `--noize gfw --fragment` بالا آمد)؛ چیزی که انجام نمی‌شد
// خبردادن به رابط کاربری بود.
//
// پس اینجا سه چیز سنجیده می‌شود، و هیچ‌کدام «ظاهر» نیست:
//   ۱. رخدادِ `aether://profile` کپیِ رابط را جایگزین می‌کند و همهٔ شنونده‌ها
//      خبردار می‌شوند — یعنی صفحهٔ تنظیمات مقدارِ تازه را می‌گیرد.
//   ۲. `saveProfile` پیش از نوشتن، پروفایل را از Rust **می‌خواند** و تغییر را روی
//      همان می‌نشاند. این مهم‌ترین سنجهٔ فایل است: نسخهٔ قبلی روی کپیِ محلی
//      می‌نوشت، پس ویرایشِ هر تنظیمِ بی‌ربط، تغییرِ دستیار را بی‌صدا باطل می‌کرد.
//   ۳. اگر خواندن شکست بخورد، نوشتنِ کاربر باز هم انجام می‌شود — یک شبکهٔ خرابِ
//      محلی نباید ذخیره‌کردنِ تنظیمات را قفل کند.
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

// پروفایلی که «سمت Rust» است. تستِ زیر آن را عوض می‌کند تا نوشتنِ Rust را بازی کند.
let rustProfile = {
  protocol: 'WIREGUARD',
  noize: 'OFF',
  mtu: 1280,
  fragment: false,
  dns: ['1.1.1.1'],
  accessSecret: '',
  accessToken: '',
}
const invoked = []
window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    invoked.push([cmd, args])
    if (cmd === 'plugin:event|listen') return Promise.resolve(1)
    if (cmd === 'get_profile') return Promise.resolve({ ...rustProfile })
    if (cmd === 'core_caps') return Promise.resolve({ tor: true, psiphon: true, warp: true })
    if (cmd === 'set_profile') {
      // همان کاری که کنترلر می‌کند: کلِ شیء را می‌نشاند.
      rustProfile = { ...args.profile }
      return Promise.resolve(null)
    }
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
  metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
}

const main = await import('../src/main.js').then(async m => { await m.bootReady; return m })
main.app.profile = { ...rustProfile }

let failed = 0
const ok = (cond, what) => {
  console.log((cond ? '  ok   ' : '  FAIL ') + what)
  if (!cond) failed++
}
const last = (cmd) => [...invoked].reverse().find(([c]) => c === cmd)

// ---- ۱) رخدادِ پروفایل ------------------------------------------------------
console.log('\n── رخدادِ aether://profile')
let notified = 0
main.onChange(() => { notified++ })

// همان چیزی که Rust پس از `ai_apply_changes` می‌فرستد.
main.applyProfileSnapshot({ ...rustProfile, protocol: 'MASQUE', noize: 'FIREWALL' })
ok(main.app.profile.protocol === 'MASQUE', `کپیِ رابط جایگزین شد (protocol=${main.app.profile.protocol})`)
ok(main.app.profile.noize === 'FIREWALL', 'هر دو تغییر رسید، نه یکی')
ok(notified === 1, `شنونده‌ها یک بار خبردار شدند (${notified})`)
// و اینکه پنلِ ساخته‌شده هم واقعاً عوض می‌شود، در بخش ۴ سنجیده می‌شود —
// چون همین‌جا بود که نتیجه‌گیریِ غلط نشست: خبردادن ≠ بازساختِ کنترل.

// ---- ۲) نوشتنِ کاربر روی پروفایلِ تازه می‌نشیند، نه روی کپیِ کهنه -----------
//
// این دقیقاً همان چیزی است که کاربر دید: دستیار تنظیمی را اعمال می‌کرد و بعد
// اولین ویرایشِ دستی، آن را برمی‌گرداند. برای بازسازی، کپیِ رابط عمداً کهنه
// می‌شود — مثل حالتی که رخداد از دست رفته باشد.
console.log('\n── ویرایشِ کاربر نباید تغییرِ دستیار را باطل کند')
rustProfile = { ...rustProfile, protocol: 'MASQUE', fragment: true, noize: 'GFW' }
main.app.profile = { protocol: 'WIREGUARD', noize: 'OFF', mtu: 1280, fragment: false, dns: ['1.1.1.1'], accessSecret: '', accessToken: '' }

invoked.length = 0
await main.saveProfile({ mtu: 1500 })

const order = invoked.map(([c]) => c)
ok(order.indexOf('get_profile') !== -1 && order.indexOf('get_profile') < order.indexOf('set_profile'),
  `اول خوانده می‌شود بعد نوشته (${order.join(' → ')})`)
const written = last('set_profile')?.[1]?.profile
ok(written?.mtu === 1500, `تغییرِ خودِ کاربر نوشته شد (mtu=${written?.mtu})`)
ok(written?.protocol === 'MASQUE', `تغییرِ دستیار زنده ماند (protocol=${written?.protocol}) — نسخهٔ قبلی اینجا WIREGUARD می‌نوشت`)
ok(written?.fragment === true, 'fragment هم برنگشت')
ok(written?.noize === 'GFW', 'noize هم برنگشت')
ok(rustProfile.mtu === 1500 && rustProfile.protocol === 'MASQUE', 'و نتیجه روی «دیسک» همان است')

// ---- ۳) اگر خواندن شکست بخورد، ذخیره‌کردن قفل نمی‌شود ----------------------
console.log('\n── خواندنِ ناموفق')
const realInvoke = window.__TAURI_INTERNALS__.invoke
window.__TAURI_INTERNALS__.invoke = (cmd, args) => {
  if (cmd === 'get_profile') return Promise.reject(new Error('IPC down'))
  return realInvoke(cmd, args)
}
invoked.length = 0
const quiet = console.error
console.error = () => {}
await main.saveProfile({ keepalive: 30 })
console.error = quiet
ok(last('set_profile')?.[1]?.profile?.keepalive === 30, 'با خواندنِ شکست‌خورده هم تنظیم ذخیره می‌شود')
window.__TAURI_INTERNALS__.invoke = realInvoke

// ---- ۴) پنلِ **ساخته‌شده** باید مقدارِ تازه را نشان بدهد --------------------
//
// این همان چیزی است که کاربر می‌دید: ردیفِ هاب مقدارِ تازه را می‌نوشت (چون
// `onChange` دارد) و زیرصفحه زیرِ همان ردیف، رگولاتورِ کهنه را. علتش نه IPC بود
// نه ذخیره‌سازی: `advanced.js` پروفایل را فقط **یک بار، هنگام ساخت** می‌خواند و
// نمای ساخته‌شده در کَشِ تب می‌ماند.
console.log('\n── پنلِ ساخته‌شده پس از نوشتنِ Rust')

const { SETTINGS_ROWS } = await import('../src/views/settings.js')
document.body.innerHTML = '<div id="view"></div>'

rustProfile = { ...rustProfile, noize: 'OFF' }
main.app.profile = { ...rustProfile }
main.app.snapshot = { ...main.app.snapshot, state: 'DISCONNECTED' }
main.showTab('advanced')

// زیرصفحهٔ «ترابری» را باز کن — همان‌جا که کشویِ noize هست.
const rows = SETTINGS_ROWS
const transportIndex = rows.findIndex((r) => r.id === 'transport')
const hubRows = document.querySelectorAll('#view .setrow')
ok(transportIndex >= 0 && hubRows.length > transportIndex, 'ردیفِ ترابری در هاب هست')
hubRows[transportIndex].dispatchEvent(new window.MouseEvent('click', { bubbles: true }))

const noizeNow = () => document.querySelector('#view select[data-key="noize"]')
ok(noizeNow()?.value === 'OFF', `کشوی noize با مقدارِ فعلی باز شد (${noizeNow()?.value})`)

// همان چیزی که Rust پس از اعمالِ دستیار می‌فرستد.
main.applyProfileSnapshot({ ...rustProfile, noize: 'GFW' })
ok(noizeNow()?.value === 'GFW',
  `پس از رخدادِ پروفایل، کنترل مقدارِ تازه را دارد (${noizeNow()?.value}) — پیش از این fix اینجا OFF می‌ماند`)

// ---- ۵) ...ولی نه وسطِ تایپِ کاربر -----------------------------------------
//
// بازساختِ فوری در حین تایپ، فیلدِ زیرِ نشانگر را عوض می‌کند و نوشتهٔ نیمه‌کارهٔ
// کاربر را می‌خورد. پس تا وقتی نشانگر داخلِ یک فیلدِ متنی است، بازسازی به بعد
// می‌افتد — و فراموش نمی‌شود.
console.log('\n── رخداد در حینِ تایپ')
// بازساختِ بخش ۴ ما را روی همان زیرصفحه نگه داشت (`OPEN` سرِ جایش می‌ماند —
// همان رفتاری که نگذاشت کاربر وسطِ کار به هاب پرت شود). پس اول با دکمهٔ back
// به هاب برگرد.
document.querySelector('#view .setpage__back')?.dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
const hubRows2 = document.querySelectorAll('#view .setrow')
const dnsIndex = rows.findIndex((r) => r.id === 'dns')
ok(hubRows2.length > dnsIndex, 'با back به هاب برگشتیم')
hubRows2[dnsIndex]?.dispatchEvent(new window.MouseEvent('click', { bubbles: true }))
const typing = document.querySelector('#view input, #view textarea')
ok(!!typing, 'زیرصفحهٔ DNS یک فیلدِ متنی دارد')
typing.focus()
typing.value = '9.9.9.'
main.applyProfileSnapshot({ ...rustProfile, noize: 'FIREWALL' })
ok(document.activeElement === typing && typing.value === '9.9.9.',
  'نوشتهٔ نیمه‌کاره سرِ جایش ماند و نشانگر نپرید')

// و بازسازیِ عقب‌افتاده در اولین بازگشت به تب انجام می‌شود. سنجه همان فیلدِ
// نیمه‌تایپ‌شده است: بازسازی آن را با مقدارِ واقعیِ پروفایل عوض می‌کند. (سنجیدنِ
// noize اینجا بی‌فایده بود — هر بار که کاربر به یک زیرصفحه می‌رود، آن زیرصفحه
// از نو از `app.profile` ساخته می‌شود، پس آن سنجه بی fix هم سبز می‌شد.)
main.showTab('home')
main.showTab('advanced')
const dnsArea = document.querySelector('#view textarea[data-key="dns"]')
ok(dnsArea?.value === '1.1.1.1',
  `بازسازیِ عقب‌افتاده انجام شد و فیلد از پروفایل پر شد (${JSON.stringify(dnsArea?.value)})`)

console.log(failed === 0 ? '\nPROFILE SYNC OK' : `\n${failed} ایراد`)
process.exit(failed === 0 ? 0 : 1)
