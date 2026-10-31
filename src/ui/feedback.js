// =============================================================================
//  src/ui/feedback.js — «نمایش و صدا» (هم‌تراز VisualPrefs.kt + ConnectionSounds.kt موبایل ۱.۶.۰)
// -----------------------------------------------------------------------------
//  ۱. انیمیشن‌های تزئینی صفحهٔ اصلی (پیش‌فرض روشن). خاموش‌شدن این‌ها را می‌بندد:
//     هالهٔ نبض‌دارِ دکمهٔ اتصال، چرخش حالت مشغول، نشانِ زندهٔ A (ثابت می‌شود) و نور
//     متحرک لبهٔ کارت اتصال. انیمیشن «پینگ زندهٔ» کارت (میله‌ها/متر) عمداً بسته نمی‌شود.
//  ۲. صدای اتصال/قطع (پیش‌فرض روشن) با همان فایل‌های sfx_connect.ogg / sfx_disconnect.ogg.
//     قاعدهٔ ConnectionSoundPolicy موبایل: بدون صدا هنگام شروع برنامه، بدون صدای
//     تکراری «متصل»، بدون صدای قطعِ کاذب هنگام اتصال مجدد.
//
//  ذخیره: localStorage وب‌ویو (همان سازوکار تب انتخاب‌شده و مرتب‌سازی پینگ در
//  customconfigs.js)؛ پس از اجرای مجدد برنامه می‌ماند.
// =============================================================================

export const ANIM_KEY = 'aether.ui.homeAnimations'
export const SOUND_KEY = 'aether.ui.connectionSounds'

const CONNECT_URL = new URL('../assets/sfx_connect.ogg', import.meta.url).href
const DISCONNECT_URL = new URL('../assets/sfx_disconnect.ogg', import.meta.url).href

function lsGet(k) { try { return globalThis.localStorage?.getItem(k) ?? null } catch (_) { return null } }
function lsSet(k, v) { try { globalThis.localStorage?.setItem(k, v) } catch (_) { /* storage unavailable */ } }
const readBool = (k) => lsGet(k) !== '0' // پیش‌فرض روشن

// ------------------------------------------------------------- انیمیشن

const animWatchers = new Set()

export function homeAnimationsEnabled() { return readBool(ANIM_KEY) }

function applyAnimClass() {
  try { document.documentElement.classList.toggle('no-home-anim', !homeAnimationsEnabled()) } catch (_) { /* بدون DOM */ }
}

export function setHomeAnimationsEnabled(on) {
  lsSet(ANIM_KEY, on ? '1' : '0')
  applyAnimClass()
  for (const fn of [...animWatchers]) { try { fn(!!on) } catch (_) { /* بی‌اثر */ } }
}

/** صفحهٔ اصلی با تغییر انتخاب خودش را از نو می‌سازد. */
export function onHomeAnimationsChange(fn) {
  animWatchers.add(fn)
  return () => animWatchers.delete(fn)
}

// ------------------------------------------------------------------ صدا

export function connectionSoundsEnabled() { return readBool(SOUND_KEY) }
export function setConnectionSoundsEnabled(on) { lsSet(SOUND_KEY, on ? '1' : '0') }

/** همان `ConnectionSoundPolicy.kt`؛ ورودی نام حالتِ هسته (CONNECTED، …). */
export class ConnectionSoundPolicy {
  constructor() { this.connected = false; this.seeded = false }
  /** @returns {'CONNECT'|'DISCONNECT'|null} */
  accept(state) {
    if (!this.seeded) {
      // اولین حالتِ دیده‌شده فقط پایه است: شروع برنامه هیچ صدایی ندارد.
      this.seeded = true
      this.connected = state === 'CONNECTED'
      return null
    }
    if (state === 'CONNECTED') {
      if (this.connected) return null
      this.connected = true
      return 'CONNECT'
    }
    if (state === 'DISCONNECTED' || state === 'FAILED' || state === 'DISCONNECTING') {
      if (!this.connected) return null
      this.connected = false
      return 'DISCONNECT'
    }
    return null // RECONNECTING و حالت‌های گذار: نه صدا، نه تغییر پرچم
  }
}

let policy = new ConnectionSoundPolicy()
const live = new Set()

/** فایل را می‌زند. قابل‌تزریق برای تست: `setPlayer(fn)`. */
let player = (url) => {
  // معادل MediaPlayer موبایل: هر نشانه یک پخش‌کنندهٔ مستقل با ولوم ۰٫۹ است و
  // نشانهٔ قبلی قطع نمی‌شود؛ پس از پایان یا خطا مرجع رها می‌شود.
  try {
    const a = new Audio(url)
    a.volume = 0.9
    live.add(a)
    const done = () => { live.delete(a) }
    a.addEventListener('ended', done)
    a.addEventListener('error', done)
    const p = a.play()
    if (p && typeof p.catch === 'function') p.catch(done)
  } catch (_) { /* بدون خروجی صدا */ }
}
export function setPlayer(fn) { player = fn }
export function resetPolicy() { policy = new ConnectionSoundPolicy() }

/** از main.js با هر حالتِ تازهٔ اتصال صدا زده می‌شود. */
export function onConnectionState(state) {
  const cue = policy.accept(state)
  if (!cue) return null
  if (connectionSoundsEnabled()) player(cue === 'CONNECT' ? CONNECT_URL : DISCONNECT_URL)
  return cue
}

export const SOUND_URLS = { connect: CONNECT_URL, disconnect: DISCONNECT_URL }

applyAnimClass()
