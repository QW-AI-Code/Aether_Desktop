// =============================================================================
//  src/ui/diagshare.js — «ارسال گزارش عیب‌یابی» (۱.۵.۰، همان نسخه)
//
//  کرش‌ها و اتصال‌های ناموفق را می‌شود با یک کلیک به مخزن گیت‌هاب سازندگان
//  گزارش داد. نه سرورِ جدا و نه توکن: Rust گزارشِ پاک‌سازی‌شده (بی IP، نام
//  میزبان، UUID یا کلید) و نشانیِ «issue تازه» را می‌سازد (`diagreport.rs`)؛
//  اینجا گزارشِ کامل در کلیپ‌بورد کپی و صفحهٔ issue در مرورگر باز می‌شود و
//  کاربر خودش آن را ثبت می‌کند. سوییچِ تنظیمات کلِ قابلیت را خاموش می‌کند.
// =============================================================================
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-shell'
import { t } from '../i18n.js'
import { toast } from './toast.js'
import { confirmModal } from './modal.js'

const KEY = 'aether.diag.share'

export function diagShareEnabled() {
  try { return globalThis.localStorage?.getItem(KEY) !== '0' } catch (_) { return true }
}

export function setDiagShareEnabled(on) {
  try { globalThis.localStorage?.setItem(KEY, on ? '1' : '0') } catch (_) { /* storage unavailable */ }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch (_) {
    try {
      const area = document.createElement('textarea')
      area.value = text
      area.setAttribute('readonly', '')
      area.style.position = 'fixed'
      area.style.opacity = '0'
      document.body.append(area)
      area.select()
      const ok = document.execCommand('copy')
      area.remove()
      return ok
    } catch (_) { return false }
  }
}

/** گزارش را می‌سازد، کپی می‌کند و صفحهٔ issue را باز می‌کند. */
export async function sendDiagnostics(kind = 'report', detail = '') {
  if (!diagShareEnabled()) return false
  try {
    const { report, url } = await invoke('diagnostics_report', { kind, detail: String(detail || '') })
    const copied = await copyText(report)
    await open(url)
    toast(copied
      ? t('The full report was copied. Paste it into the GitHub page before submitting.')
      : t('The report page was opened. Copy the log from Diagnostics if you want to add it.'))
    return true
  } catch (e) {
    toast(t('Could not prepare the diagnostics report.'))
    return false
  }
}

// پیشنهاد بعد از اتصالِ ناموفق — یک بار برای هر شکست.
let lastState = null
let offered = false
export function watchForFailure(snapshot) {
  const state = snapshot?.state ?? null
  if (state === 'CONNECTED' || state === 'CONNECTING') offered = false
  const failedNow = state === 'FAILED' && lastState !== 'FAILED'
  lastState = state
  if (!failedNow || offered || !diagShareEnabled()) return
  offered = true
  const detail = [snapshot?.error, snapshot?.detail, snapshot?.protocol ? `protocol=${snapshot.protocol}` : '']
    .filter(Boolean).join('\n')
  Promise.resolve(confirmModal({
    title: t('Connection failed'),
    body: t('Send a diagnostics report to the developers? It contains the redacted log of this attempt, no IPs, servers or keys. You can turn this off in Settings.'),
    ok: t('Send report'),
    cancel: t('Not now'),
  })).then((ok) => { if (ok) sendDiagnostics('connection failed', detail) }).catch(() => {})
}
