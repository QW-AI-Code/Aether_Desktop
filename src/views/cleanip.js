// =============================================================================
//  src/views/cleanip.js — اسکنر IP تمیز Cloudflare (۱.۴.۰، هم‌تراز موبایل ۱.۶.۰)
// -----------------------------------------------------------------------------
//  سه چیز در این فایل است و هر سه فقط لایهٔ رابط‌اند؛ منطق (نمونه‌برداری،
//  TLS/trace، Real Delay، بازنویسی کانفیگ) همه در Rust است:
//
//   ۱. یک «انبار وضعیتِ اسکن» مشترک (`onScan`, `startScan`, `stopScan`, …) که
//      دکمهٔ اسکنِ تب، ذره‌بین/منوی هر سرور و پیشرفتِ زیر هر سرور از آن می‌خوانند.
//   ۲. زیرصفحهٔ مستقل «تنظیمات اسکن آی‌پی تمیز» (`renderCleanIpSettings`) —
//      معادل `CleanIpSettingsPage.kt`.
//   ۳. کمکی‌های نمایشِ پیشرفت/نتیجه زیر هر سرور (`scanLineFor`).
//
//  فرمان‌های Rust (موجود در custom_commands.rs): cc_scan_options،
//  cc_scan_set_options، cc_scan_state، cc_scan_start، cc_scan_stop،
//  cc_scan_dismiss و رویداد aether://cleanip. هیچ فرمان تازه‌ای ساخته نشده.
// =============================================================================
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { t } from '../i18n.js'
import { toast } from '../ui/toast.js'
import { openModal, modalButton } from '../ui/modal.js'

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

/** پیام خطای Rust → متن قابل‌ترجمه (kind پایدار است، message انگلیسیِ خام). */
export function scanErrorText(e) {
  const kind = e && e.kind
  const raw = e && (e.message || e.kind)
  switch (kind) {
    case 'busy':
      if (/disconnect/i.test(String(raw))) return t('Disconnect and finish any active ping test before scanning.')
      if (/already running/i.test(String(raw))) return t('A scan is already running.')
      return t('Options are locked while a scan runs.')
    case 'empty': return t('No scannable config here. Locked, expired or incompatible configs are skipped.')
    case 'ranges': return t('Custom ranges are on but no valid range is entered. Add a range or turn the option off.')
    default: return raw ? String(raw) : t('Something went wrong.')
  }
}

// ----------------------------------------------------------- انبارِ وضعیت

let state = { running: false, progress: 0, validating: false, applied: 0, completed: 0, total: 0, targetId: null, message: '', results: [] }
const subs = new Set()
let wired = false

const adopt = (v) => {
  if (!v || typeof v !== 'object') return
  state = { ...state, ...v, results: Array.isArray(v.results) ? v.results : [] }
  for (const fn of [...subs]) { try { fn(state) } catch (_) { /* یک مشترکِ خراب بقیه را نمی‌شکند */ } }
}

function wire() {
  if (wired) return
  wired = true
  try { Promise.resolve(listen('aether://cleanip', (e) => adopt(e.payload))).catch(() => {}) } catch (_) { /* jsdom */ }
  Promise.resolve(invoke('cc_scan_state')).then(adopt).catch(() => {})
}

export const scanState = () => state

/** مشترک می‌شود و فوراً وضعیت فعلی را می‌دهد. owner (اختیاری): اگر از DOM جدا شد خودکار رها می‌شود. */
export function onScan(fn, owner = null) {
  wire()
  const wrapped = (s) => {
    if (owner && !owner.isConnected) { subs.delete(wrapped); return }
    fn(s)
  }
  subs.add(wrapped)
  try { fn(state) } catch (_) { /* مشترکِ تازه هنوز در DOM نیست */ }
  return () => subs.delete(wrapped)
}

export async function startScan(ids) {
  try { adopt(await invoke('cc_scan_start', { ids: ids && ids.length ? ids : null })); return true } catch (e) { toast(scanErrorText(e)); return false }
}
export async function stopScan() {
  try { adopt(await invoke('cc_scan_stop')) } catch (e) { toast(scanErrorText(e)) }
}
export async function dismissScanResult(id) {
  try { adopt(await invoke('cc_scan_dismiss', { id: id ?? null })) } catch (_) { /* نتیجهٔ از قبل پاک */ }
}

const OUTCOME = {
  applied: 'Clean IP applied',
  unchanged: 'Not better than current',
  cancelled: 'Cancelled',
  failed: 'Failed',
}

/**
 * وضعیتِ اسکنِ یک سرور برای نمایش زیر ردیفش.
 * @returns {null | {kind:'live', percent:number, text:string} | {kind:'result', outcome:string, text:string}}
 */
export function scanLineFor(id, s = state) {
  if (s.running && s.targetId === id) {
    const pct = Math.max(0, Math.min(100, Number(s.progress) || 0))
    return { kind: 'live', percent: pct, text: `${s.validating ? t('Checking real proxy ping…') : t('Scanning Cloudflare IPs…')} ${pct}%` }
  }
  const r = [...(s.results || [])].reverse().find((x) => x && x.id === id)
  if (!r) return null
  const base = t(OUTCOME[r.outcome] || 'Failed')
  const text = r.outcome === 'applied'
    ? `${base} · ${r.previous ? `${r.previous} → ` : ''}${r.next ?? ''} · ${r.pingMs} ms`
    : base
  return { kind: 'result', outcome: String(r.outcome || 'failed'), text }
}

/** «در حال اسکن سرور i از n» برای دکمهٔ اسکنِ تب. */
export function groupProgressText(s = state) {
  if (!s.running) return ''
  const n = Math.max(1, Number(s.total) || 1)
  const i = Math.min(n, (Number(s.completed) || 0) + 1)
  return t('Scanning server {0} of {1}').replace('{0}', String(i)).replace('{1}', String(n))
}

// -------------------------------------------------- زیرصفحهٔ تنظیمات اسکن

const FIELD = {
  profiles: [
    { id: 'FAST', title: 'Fast', desc: 'Quick and shallow — fewest candidates and shortest wait.' },
    { id: 'BALANCED', title: 'Balanced', desc: 'Default — a balanced mix of depth and speed.' },
    { id: 'DEEP', title: 'Deep', desc: 'Most thorough and slowest — use when a scan finds nothing.' },
  ],
}
export const CEILING_MIN = 50
export const CEILING_MAX = 5000
export const MAX_RANGES_TEXT = 8000

const CHECK =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>'

/**
 * عدد ورودیِ سقف پینگ معتبر است؟ (۵۰..۵۰۰۰، فقط رقم) — همان `limit.toIntOrNull() in 50..5000` موبایل.
 */
export function validCeiling(text) {
  const s = String(text ?? '').trim()
  if (!/^\d{1,5}$/.test(s)) return null
  const n = Number(s)
  return n >= CEILING_MIN && n <= CEILING_MAX ? n : null
}

export function renderCleanIpSettings() {
  wire()
  const root = document.createElement('div')
  root.className = 'view view--advanced view--cleanip'
  root.innerHTML = `
    <div class="scard-group">
      <div class="sethub__card scard scard--fields">
        <section class="field cip-depth">
          <span class="field__label">${esc(t('Scan depth'))}</span>
          <span class="field__hint">${esc(t('How hard the clean-IP scanner works, for both single and group scans.'))}</span>
          <div class="seg seg--chain cip-profiles" role="radiogroup" aria-label="${esc(t('Scan depth'))}"></div>
        </section>
      </div>
    </div>

    <div class="scard-group">
      <div class="sethub__card scard scard--fields">
        <section class="field field--row">
          <div>
            <span class="field__label">${esc(t('Use manual ping limit'))}</span>
            <span class="field__hint">${esc(t('On: take the first stable IP within the limit. Off: choose the lowest stable real ping among the tested candidates.'))}</span>
          </div>
          <button type="button" class="switch cip-manual" role="switch" aria-checked="true"><span class="switch__knob"></span></button>
        </section>
        <section class="field">
          <span class="field__label">${esc(t('Maximum allowed ping (ms)'))}</span>
          <input class="input ltr cip-ceiling" dir="ltr" type="text" inputmode="numeric" maxlength="5" autocomplete="off" placeholder="2000">
          <span class="field__hint cip-ceiling-hint"></span>
          <span class="field__hint cip-notice">${esc(t('Probes public Cloudflare edges: up to 1 MB per healthy candidate, potentially hundreds of MB (data charges may apply). Edge results are preliminary; applying to a server requires real proxy ping plus 3 stability checks. Disconnect first. Locked and incompatible servers cannot be changed.'))}</span>
        </section>
      </div>
    </div>

    <div class="scard-group">
      <h3 class="sethub__group">${esc(t('Custom Cloudflare IP ranges'))}</h3>
      <div class="sethub__card scard scard--fields">
        <section class="field field--row">
          <div>
            <span class="field__label">${esc(t('Use my own IP ranges'))}</span>
            <span class="field__hint">${esc(t('On: the scanner looks for a clean IP only inside the ranges entered below instead of the built-in Cloudflare ranges.'))}</span>
          </div>
          <button type="button" class="switch cip-custom" role="switch" aria-checked="false"><span class="switch__knob"></span></button>
        </section>
        <section class="field">
          <span class="field__label">${esc(t('IP ranges'))}</span>
          <textarea class="input input--area ltr cip-ranges" dir="ltr" rows="5" maxlength="${MAX_RANGES_TEXT}" placeholder="104.16.0.0/13&#10;172.64.0.1-172.64.0.255"></textarea>
          <span class="field__hint cip-ranges-hint"></span>
        </section>
      </div>
    </div>
    <p class="field__hint cip-locked" hidden>${esc(t('Options are locked while a scan runs.'))}</p>`

  const q = (s) => root.querySelector(s)
  const profilesBox = q('.cip-profiles')
  const manual = q('.cip-manual')
  const ceiling = q('.cip-ceiling')
  const ceilingHint = q('.cip-ceiling-hint')
  const custom = q('.cip-custom')
  const ranges = q('.cip-ranges')
  const rangesHint = q('.cip-ranges-hint')
  const lockedNote = q('.cip-locked')

  let opts = null
  let locked = false
  let rangeTimer = 0

  const setSwitch = (el, on) => { el.classList.toggle('is-on', !!on); el.setAttribute('aria-checked', String(!!on)) }

  const paintProfiles = () => {
    const list = (opts && opts.profiles) || FIELD.profiles.map((p) => ({ id: p.id }))
    profilesBox.innerHTML = FIELD.profiles.map((p) => {
      const meta = list.find((x) => x.id === p.id) || {}
      const detail = meta.candidates != null
        ? t('Budget {0} · timeout {1} ms · tries {2} · parallel {3}')
          .replace('{0}', meta.candidates).replace('{1}', meta.timeoutMs).replace('{2}', meta.probes).replace('{3}', meta.parallel)
        : ''
      const on = opts && opts.profile === p.id
      return `<button type="button" role="radio" class="seg__item cc-opt ${on ? 'is-active' : ''}" data-value="${p.id}" aria-checked="${!!on}" ${locked ? 'disabled' : ''}>
        <span class="seg__text"><span class="cc-opt__title">${esc(t(p.title))}</span><span class="cc-opt__sub">${esc(t(p.desc))}</span><span class="cc-opt__sub ltr" dir="ltr">${esc(detail)}</span></span>
        <span class="seg__check">${CHECK}</span></button>`
    }).join('')
  }

  const paintCeilingHint = () => {
    const bad = !!(opts && opts.manual) && validCeiling(ceiling.value) == null
    ceilingHint.textContent = bad
      ? t('Enter 50–5000 ms. The last valid saved limit remains in use until a valid value is entered.')
      : t('50–5000 ms. If no confirmed candidate is within the enabled limit, keep the current server endpoint.')
    ceilingHint.classList.toggle('is-error', bad)
    ceiling.classList.toggle('is-invalid', bad)
  }

  const paintRangesHint = () => {
    const blank = ranges.value.trim() === ''
    const invalid = (opts && opts.rangeInvalid) || []
    let text
    if (invalid.length) text = t('Invalid or non-public entry: {0}').replace('{0}', invalid[0])
    else if (blank) text = opts && opts.customEnabled ? t('Custom ranges are on but no valid range is entered. Add a range or turn the option off.') : t('One per line: CIDR (104.16.0.0/20), single IP (104.16.1.5) or range (104.16.1.1-104.16.1.80). Public IPv4 only.')
    else text = t('{0} range(s), {1} addresses').replace('{0}', String(opts?.rangeCount ?? 0)).replace('{1}', String(opts?.rangeTotal ?? 0))
    rangesHint.textContent = text
    const bad = !!(opts && opts.customEnabled) && (invalid.length > 0 || blank)
    rangesHint.classList.toggle('is-error', bad)
    ranges.classList.toggle('is-invalid', bad)
  }

  const paint = () => {
    if (!opts) return
    paintProfiles()
    setSwitch(manual, opts.manual)
    if (document.activeElement !== ceiling) ceiling.value = String(opts.ceiling ?? 2000)
    setSwitch(custom, opts.customEnabled)
    if (document.activeElement !== ranges) ranges.value = opts.customRanges || ''
    const off = locked
    manual.disabled = off
    custom.disabled = off
    ceiling.disabled = off || !opts.manual
    ranges.disabled = off || !opts.customEnabled
    lockedNote.hidden = !locked
    paintCeilingHint()
    paintRangesHint()
  }

  const load = async () => {
    try { opts = await invoke('cc_scan_options'); paint() } catch (e) { toast(scanErrorText(e)) }
  }

  /** یک تغییر را به Rust می‌دهد؛ مقدار برگشتی (با شمارش رنج‌ها) مرجع نمایش است. */
  const save = async (patch) => {
    if (!opts || locked) return
    const next = {
      profile: opts.profile, manual: opts.manual, ceiling: opts.ceiling,
      customEnabled: opts.customEnabled, customRanges: opts.customRanges,
      ...patch,
    }
    try { opts = await invoke('cc_scan_set_options', { options: next }); paint() } catch (e) {
      toast(scanErrorText(e))
      await load()
    }
  }

  profilesBox.addEventListener('click', (e) => {
    const item = e.target.closest('.seg__item')
    if (!item || item.disabled || item.dataset.value === opts?.profile) return
    save({ profile: item.dataset.value })
  })
  manual.addEventListener('click', () => { if (opts && !locked) save({ manual: !opts.manual }) })
  custom.addEventListener('click', () => { if (opts && !locked) save({ customEnabled: !opts.customEnabled }) })

  // سقف: فقط رقم؛ تا مقدارِ معتبر وارد نشده آخرین مقدارِ معتبرِ ذخیره‌شده می‌ماند.
  ceiling.addEventListener('input', () => {
    const digits = ceiling.value.replace(/\D/g, '').slice(0, 5)
    if (digits !== ceiling.value) ceiling.value = digits
    const n = validCeiling(digits)
    if (n != null && opts && n !== opts.ceiling) {
      opts = { ...opts, ceiling: n }
      save({ ceiling: n })
    }
    paintCeilingHint()
  })
  ceiling.addEventListener('blur', () => { if (opts && validCeiling(ceiling.value) == null) { ceiling.value = String(opts.ceiling); paintCeilingHint() } })

  ranges.addEventListener('input', () => {
    clearTimeout(rangeTimer)
    const text = ranges.value.slice(0, MAX_RANGES_TEXT)
    rangeTimer = setTimeout(() => { save({ customRanges: text }) }, 250)
    if (opts) { opts = { ...opts, customRanges: text }; paintRangesHint() }
  })

  onScan((s) => {
    const was = locked
    locked = !!s.running
    if (opts && was !== locked) paint()
  }, root)

  load()
  return root
}
