// =============================================================================
//  src/ui/fit.js — متنِ «هوشمند» (۱.۵.۰، همان نسخه)
//
//  یک متن یا یک ردیف (نمودارِ زنجیره، چیپِ پینگ) همیشه در یک خط و کامل دیده
//  می‌شود: اگر در جایش جا نشود، اندازهٔ فونتش کوچک می‌شود (تا `min` پیکسل) و با
//  بزرگ‌شدنِ پنجره دوباره به اندازهٔ طبیعی برمی‌گردد. نه سه‌نقطه، نه شکستنِ
//  عمودی. در jsdom (بی‌چیدمان) هیچ کاری نمی‌کند.
//
//  1.5.0 (same version) — رفعِ «لرزش و پرشِ» نمودارِ زنجیرهٔ ۳ نودی:
//  نسخهٔ قبلی روی همان عنصری که اندازه‌اش را عوض می‌کرد ResizeObserver داشت و در
//  هر بار اجرا فونت را اول به اندازهٔ طبیعی برمی‌گرداند و بعد قدم‌به‌قدم کوچک
//  می‌کرد. تغییرِ فونت بلندیِ نمودار (و همهٔ چیزهای زیرش) را عوض می‌کرد، همین
//  تغییر دوباره observer را صدا می‌زد و چرخهٔ «بزرگ ← کوچک ← بزرگ» تا وقتی پنجره
//  آن‌قدر پهن نمی‌شد که اندازهٔ طبیعی جا شود ادامه داشت؛ کلِ صفحه بالا و پایین
//  می‌پرید. حالا:
//    • [scaleToFit]: عرضِ طبیعیِ محتوا یک‌بار و در اندازهٔ مرجعِ ثابت اندازه
//      گرفته می‌شود (نتیجه همیشه یکی است) و نسبتِ «عرض بر فونت» در متغیرِ CSS
//      `--fit-k` می‌نشیند. اندازهٔ فونت را خودِ CSS با واحدِ container query
//      (`100cqi / k`) حساب می‌کند؛ هنگامِ تغییرِ اندازهٔ پنجره هیچ JS‌ای اجرا
//      نمی‌شود و ظرف (با `container-type` و بلندیِ ثابت) به محتوایش وابسته نیست،
//      پس حلقهٔ بازخورد از نظرِ ساختاری ناممکن است.
//    • [autoFit]: فقط به تغییرِ *عرضِ* واقعی واکنش نشان می‌دهد، نه به تغییرِ
//      اندازه‌ای که خودش ساخته، و اجراها را در یک فریم جمع می‌کند.
// =============================================================================

const raf = (fn) => (globalThis.requestAnimationFrame || ((f) => setTimeout(f, 16)))(fn)
const hasRO = () => typeof globalThis.ResizeObserver !== 'undefined'

/** فونتِ `el` را تا جایی کوچک می‌کند که محتوایش در عرضش جا شود. */
export function fitText(el, { min = 8 } = {}) {
  if (!el || !el.isConnected) return
  el.style.fontSize = ''
  if (!(el.clientWidth > 0) || !(el.scrollWidth > el.clientWidth + 1)) return
  const base = parseFloat(globalThis.getComputedStyle?.(el)?.fontSize) || 13
  let size = base
  let guard = 0
  while (el.scrollWidth > el.clientWidth + 1 && size > min && guard++ < 60) {
    size = Math.max(min, size - 0.5)
    el.style.fontSize = `${size}px`
  }
}

const watched = new WeakMap()

/** مثلِ [fitText]، و با هر تغییرِ واقعیِ عرضِ عنصر دوباره (نه تغییرِ خودساخته). */
export function autoFit(el, opts) {
  if (!el) return
  let state = watched.get(el)
  if (!state) {
    state = { opts, pending: false, lastW: -1 }
    watched.set(el, state)
  }
  state.opts = opts
  const run = () => {
    state.pending = false
    if (!el.isConnected) return
    fitText(el, state.opts)
    // عرضی که خودمان عنصر را در آن رها کردیم؛ گزارشِ بعدیِ observer با همین عرض
    // پیامدِ کارِ خودمان است و نادیده گرفته می‌شود.
    state.lastW = el.getBoundingClientRect?.().width ?? -1
  }
  const schedule = () => {
    if (state.pending) return
    state.pending = true
    raf(run)
  }
  schedule()
  if (state.ro || !hasRO()) return
  state.ro = new globalThis.ResizeObserver((entries) => {
    if (!el.isConnected) { state.ro.disconnect(); return }
    const w = entries[entries.length - 1]?.borderBoxSize?.[0]?.inlineSize
      ?? el.getBoundingClientRect().width
    if (Math.abs(w - state.lastW) < 1) return   // فقط بلندی عوض شده، یا تغییرِ خودمان
    schedule()
  })
  state.ro.observe(el)
}

/**
 * ردیفِ یک‌خطیِ `track` را درونِ ظرفِ `box` جا می‌دهد (نمودارِ زنجیره).
 *
 * 1.5.0 (same version) — رفعِ «نمودارِ ۳ نودی در عرضِ پیش‌فرضِ پنجره جا نمی‌شود»:
 * نسخهٔ قبلی نسبتِ «عرض بر فونت» را با `getBoundingClientRect` می‌گرفت و فونت را
 * به CSS (`100cqi / k`) می‌سپرد. آن اندازه‌گیری تبدیل‌ها (انیمیشنِ ورودِ صفحه) را
 * هم حساب می‌کرد و بخش‌هایی که با فونت کوچک نمی‌شوند (حاشیه‌ها، ایموجیِ دو سرِ
 * نمودار که با فونتِ دیگری رسم می‌شود) در نسبت نبودند؛ پس در عرضِ ۳۹۰ پیکسل
 * دو سرِ نمودار بریده می‌شد. حالا:
 *   • عرض با `offsetWidth` (پیکسلِ واقعیِ چیدمان، بی‌اثر از transform) گرفته می‌شود؛
 *   • فونت تا جایی کوچک می‌شود که جا شود (نه کمتر از `min`)؛
 *   • اگر هنوز چیزی بیرون بماند، کلِ ردیف با `transform: scale()` کوچک می‌شود —
 *     پس نمودار **همیشه** کامل دیده می‌شود، در هر عرض و هر زبان.
 * ظرف به محتوایش وابسته نیست (عرض از کارت، بلندی ثابت، `contain`) و transform
 * چیدمان را عوض نمی‌کند؛ پس حلقهٔ بازخورد و لرزش همچنان ناممکن است.
 *
 * @returns {{ k: number, dispose: () => void }} — `k` آخرین نسبتِ اندازه‌گرفته‌شده.
 */
export function scaleToFit(box, track, { min = 7, max = 13, safety = 1.03, k = 0, onMeasure } = {}) {
  const handle = { k, dispose: () => {} }
  if (!box || !track) return handle
  box.style.setProperty('--fit-min', `${min}px`)
  box.style.setProperty('--fit-max', `${max}px`)
  if (k > 0) box.style.setProperty('--fit-k', k.toFixed(3))
  let disposed = false
  let pending = false
  let lastAvail = -1

  const update = () => {
    pending = false
    if (disposed || !box.isConnected) return
    const avail = box.clientWidth
    if (!(avail > 0)) return   // هنوز نمایش داده نشده (یا jsdom)
    // اندازهٔ مرجع: بزرگ‌ترین فونت، بی هیچ transform.
    track.style.transform = ''
    track.style.fontSize = `${max}px`
    const natural = track.offsetWidth
    if (!(natural > 0)) return
    const nextK = Math.round((natural / max) * safety * 1000) / 1000
    if (Math.abs(nextK - handle.k) > 0.001) {
      handle.k = nextK
      box.style.setProperty('--fit-k', nextK.toFixed(3))
      onMeasure?.(nextK)
    }
    const target = avail / safety
    let size = max
    if (natural > target) size = Math.max(min, Math.floor(((max * target) / natural) * 4) / 4)
    track.style.fontSize = `${size}px`
    // آنچه با فونت کوچک نمی‌شود (یا کفِ `min`) هنوز ممکن است جا نشود: کلِ ردیف کوچک می‌شود.
    const w = track.offsetWidth
    if (w > avail) {
      track.style.transformOrigin = 'left center'
      track.style.transform = `scale(${(Math.floor((avail / w) * 1000) / 1000).toFixed(3)})`
    }
    lastAvail = avail
  }
  const schedule = () => {
    if (pending || disposed) return
    pending = true
    raf(update)
  }

  schedule()
  // فونتِ نهایی ممکن است بعد از اولین نقاشی برسد؛ دوباره اندازه بگیر.
  globalThis.document?.fonts?.ready?.then?.(() => schedule())

  let ro = null
  if (hasRO()) {
    // فقط تغییرِ واقعیِ عرضِ ظرف (نمایان‌شدنِ صفحه، تغییرِ اندازهٔ پنجره)؛ بلندیِ
    // ظرف ثابت است و کارِ خودمان روی track عرضِ ظرف را عوض نمی‌کند.
    ro = new globalThis.ResizeObserver((entries) => {
      if (!box.isConnected) { handle.dispose(); return }
      const e = entries.find((x) => x.target === box)
      if (!e) return
      const w = e.contentRect?.width ?? box.clientWidth
      if (Math.abs(w - lastAvail) < 0.5) return
      schedule()
    })
    ro.observe(box)
  }

  handle.dispose = () => {
    if (disposed) return
    disposed = true
    ro?.disconnect()
  }
  return handle
}
