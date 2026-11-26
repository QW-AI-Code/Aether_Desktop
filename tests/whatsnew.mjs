// هارنسِ پنجرهٔ «تازه‌ها» (jsdom): تصمیمِ نمایش، چک‌باکس، ذخیره و بایگانی.
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost/' })
globalThis.window = dom.window
globalThis.document = dom.window.document
globalThis.HTMLElement = dom.window.HTMLElement
globalThis.localStorage = dom.window.localStorage

const prefs = {}
const invoked = []
window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    invoked.push([cmd, args])
    if (cmd === 'news_state') {
      return Promise.resolve({ version: '1.5.0', lastLaunched: prefs.last ?? null, suppressed: prefs.suppressed ?? null })
    }
    if (cmd === 'news_mark') {
      prefs.last = '1.5.0'
      if (args.suppress) prefs.suppressed = '1.5.0'
      return Promise.resolve(null)
    }
    return Promise.resolve(null)
  },
  transformCallback: (cb) => cb,
}

localStorage.setItem('aether.support.suppressed', '1') // مدال حمایت این آزمون را قطع نکند
const { shouldShowNews, maybeShowWhatsNew } = await import('../src/ui/whatsnew.js')
const { renderAnnouncements } = await import('../src/views/announcements.js')

let failed = 0
const check = (ok, msg) => { console.log(`${ok ? '✓' : '✗'} ${msg}`); if (!ok) failed++ }

check(shouldShowNews('1.5.0', null), 'نصبِ تازه: نمایش')
check(!shouldShowNews('1.5.0', '1.5.0'), 'همین نسخه ساکت شده: عدمِ نمایش')
check(shouldShowNews('1.4.0', '1.5.0'), 'ارتقا: دوباره نمایش')

// ۱) اجرای اول، بستن بدون تیک
check(await maybeShowWhatsNew(), 'اجرای اول: پنجره باز شد')
const root = document.querySelector('.news')
check(root?.getAttribute('dir') === 'rtl', 'پنجره راست‌چین است')
check(!!root.querySelector('.news__check:not([hidden])'), 'چک‌باکس دیده می‌شود')
check(root.querySelector('.news__check span').textContent === 'دیگر این پیام را نمایش نده', 'برچسبِ دقیقِ چک‌باکس')
const ltrSpans = [...root.querySelectorAll('.announcement-content [dir="ltr"]')].map((e) => e.textContent)
for (const term of ['1.5.0', '2.4.0', 'WireGuard', 'MASQUE', 'HTTP/3', 'HTTP/2', 'Gool', 'MASQUE×2', 'TCP', 'DPI', 'TLS', 'ECH', 'QUIC', 'quinn-proto', 'quinn-udp', 'url', 'cookie', 'IP', 'VPN', 'prefs.json']) {
  check(ltrSpans.includes(term), `«${term}» در span[dir=ltr]`)
}
check(!root.textContent.includes('Airplane Mode') && !root.textContent.includes('حالت پرواز ({') && root.textContent.includes('کارت شبکه'), 'راهنمای شبکه بومی ویندوز است')
check(root.textContent.includes('حالت هوشمند از نو نوشته شد') && root.textContent.includes('انتخاب بهترین مسیر، نه اولین مسیر'), 'تازه‌های ۱.۵.۰ (حالت هوشمند جدید) در پیام هست')
check(root.textContent.includes('اگر به هیچ وجه متصل نشدید چه کنید؟') && root.querySelectorAll('.announcement-content ol li').length === 3, 'بخشِ «اگر به هیچ وجه متصل نشدید» از ۱.۴.۰ مانده است')
check(!root.textContent.includes('رابط ویندوز دقیقاً مثل موبایل شد') && !root.textContent.includes('⚠') && !root.textContent.includes('NPVS v5'), 'بقیهٔ پیامِ ۱.۴.۰ (ابعاد رابط، هشدار) حذف شده')
check(root.querySelectorAll('.announcement-content h2').length === 1, 'فقط یک اطلاعیه')
check(!/گوشی‌های ضعیف|دکمه را پشت‌سر‌هم نزنید.*موبایل/.test(root.textContent), 'عبارت‌های مخصوص گوشی به ویندوز تبدیل شده‌اند')
root.querySelector('.news__ok').click()
check(!document.querySelector('.news'), '«متوجه شدم» پنجره را بست')
check(prefs.suppressed === undefined, 'بدون تیک: ساکت نشد')

// ۲) اجرای دوم همان نسخه: دوباره باز، این بار با تیک و Escape
check(await maybeShowWhatsNew(), 'اجرای دومِ بدون تیک: دوباره باز شد')
document.querySelector('.news__checkbox').checked = true
document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape' }))
check(!document.querySelector('.news'), 'Escape پنجره را بست')
check(prefs.suppressed === '1.5.0', 'تیک برای همین نسخه ذخیره شد')

// ۳) اجرای سوم: ساکت
check(!(await maybeShowWhatsNew()), 'اجرای سوم: پنجره باز نشد')

// ۴) بایگانی: پنجره بدون چک‌باکس دوباره باز می‌شود
const archive = renderAnnouncements()
check(archive.querySelectorAll('.setrow').length === 2, 'بایگانی: یک اطلاعیه + ردیف حمایت')
check(!archive.textContent.includes('1.4.0') && archive.textContent.includes('1.5.0'), 'فقط نسخهٔ 1.5.0 نمایش داده می‌شود')
document.body.append(archive)
archive.querySelector('.setrow').click()
check(!!document.querySelector('.news .news__check[hidden]'), 'از بایگانی: پنجره بدون چک‌باکس باز شد')
document.querySelector('.news__close').click()
check(prefs.suppressed === '1.5.0' && !document.querySelector('.news'), 'بستن از بایگانی وضعیت را تغییر نداد')

if (failed) { console.log(`\n${failed} مورد شکست خورد`); process.exit(1) }
console.log('\nOK — پنجرهٔ «تازه‌ها»')
