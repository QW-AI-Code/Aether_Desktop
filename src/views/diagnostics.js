// پورت از ui/DiagnosticsPanel.kt + core/Diagnostics.kt + core/DiagnosticsLog.kt
//
// رفع ریشه‌ای مشکل ۶: تمام امکانات پنل لاگ موبایل این‌جا هست:
//   * وضعیت کلی با نقطهٔ رنگی + شرح
//   * ۴ بررسی زنده (همان چک‌های Diagnostics.kt) با رنگ PENDING/RUNNING/PASS/FAIL
//   * دکمه‌های Run test / Copy logs / Clear — کپی لاگ با توست تأیید
//   * کنسول لاگ مونواسپیس با رنگ سطر بر اساس سطح (E/W/I/D) + اسکرول خودکار
//   * تازه‌سازی زندهٔ تقریباً هر ۱ ثانیه — دیگر دکمهٔ «Refresh log» لازم نیست
import { invoke } from '@tauri-apps/api/core'
import { t } from '../i18n.js'
import { toast } from '../ui/toast.js'

const CHECK_COLOR = { PASS: '#3EDBB0', FAIL: '#FF5C7A', RUNNING: '#F5C451', PENDING: '#8A93A6' }
const LEVEL_CLASS = { E: 'log__line--e', W: 'log__line--w', I: 'log__line--i', D: 'log__line--d' }

function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export function renderDiagnostics() {
  const root = document.createElement('div')
  root.className = 'view view--diagnostics'
  root.innerHTML = `
    <h2 class="view__title">${t('Diagnostics')}</h2>

    <div class="diag-overall">
      <span class="diag-overall__dot" id="overall-dot"></span>
      <span class="diag-overall__text" id="overall-text">${t('Run the test to verify connectivity')}</span>
    </div>

    <ul class="checks" id="checks"></ul>

    <div class="row">
      <button class="btn btn--primary" id="run">${t('Run test')}</button>
      <button class="btn" id="copy">${t('Copy logs')}</button>
      <button class="btn btn--danger" id="clear">${t('Clear')}</button>
      <button class="btn" id="env">${t('Environment check')}</button>
      <button class="btn" id="leak">${t('WebRTC leak test')}</button>
    </div>

    <p class="summary" id="summary"></p>
    <ul class="checks checks--env" id="env-checks"></ul>

    <h3 class="view__subtitle">${t('Log')}</h3>
    <pre class="log ltr" dir="ltr" id="log"><span class="log__empty">${t('No logs yet. Connect or run a test.')}</span></pre>
  `

  const checksEl = root.querySelector('#checks')
  const envEl = root.querySelector('#env-checks')
  const summaryEl = root.querySelector('#summary')
  const logEl = root.querySelector('#log')
  const overallDot = root.querySelector('#overall-dot')
  const overallText = root.querySelector('#overall-text')

  // وضعیت کلی — همان رشته‌های strings.xml.
  function paintOverall(checks) {
    if (!checks.length) {
      overallDot.style.background = CHECK_COLOR.PENDING
      overallText.textContent = t('Run the test to verify connectivity')
      return
    }
    const anyFail = checks.some((c) => c.state === 'FAIL')
    const anyRunning = checks.some((c) => c.state === 'RUNNING' || c.state === 'PENDING')
    const allPass = checks.every((c) => c.state === 'PASS')
    if (anyFail) {
      overallDot.style.background = CHECK_COLOR.FAIL
      overallText.textContent = t('A problem was detected — see the failing check')
    } else if (allPass) {
      overallDot.style.background = CHECK_COLOR.PASS
      overallText.textContent = t('All checks passed — traffic should flow')
    } else if (anyRunning) {
      overallDot.style.background = CHECK_COLOR.RUNNING
      overallText.textContent = t('Testing connectivity…')
    }
  }

  function paintChecks(checks) {
    checksEl.innerHTML = checks.map((c) => `
      <li class="check">
        <span class="check__dot" style="background:${CHECK_COLOR[c.state] || CHECK_COLOR.PENDING}"></span>
        <span class="check__name">${esc(c.label)}</span>
        <span class="check__state" style="color:${CHECK_COLOR[c.state] || CHECK_COLOR.PENDING}">${c.state}</span>
        ${c.detail ? `<span class="check__detail ltr" dir="ltr">${esc(c.detail)}</span>` : ''}
      </li>`).join('')
    paintOverall(checks)
  }

  function paintLog(lines) {
    if (!lines.length) {
      logEl.innerHTML = `<span class="log__empty">${t('No logs yet. Connect or run a test.')}</span>`
      return
    }
    // قالب خطوط: `HH:mm:ss.SSS L/tag: message` — رنگ‌آمیزی بر اساس سطح.
    const near = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 24
    logEl.innerHTML = lines.map((ln) => {
      const m = ln.match(/^\S+\s+([EWID])\//)
      const cls = m ? LEVEL_CLASS[m[1]] : 'log__line--d'
      return `<span class="log__line ${cls}">${esc(ln)}</span>`
    }).join('\n')
    if (near) logEl.scrollTop = logEl.scrollHeight
  }

  async function refresh() {
    const [checks, lines] = await Promise.all([invoke('get_checks'), invoke('read_logs')])
    paintChecks(checks)
    paintLog(lines)
  }

  root.querySelector('#run').addEventListener('click', async () => {
    await invoke('run_self_test')
    await refresh()
  })

  root.querySelector('#copy').addEventListener('click', async () => {
    const text = await invoke('export_logs')
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      // رزرو — در صورت محدودیت دسترسی کلیپ‌بورد.
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      ta.remove()
    }
    toast(t('Logs copied to clipboard'))
  })

  root.querySelector('#clear').addEventListener('click', async () => {
    await invoke('clear_logs')
    await refresh()
  })

  root.querySelector('#env').addEventListener('click', async () => {
    summaryEl.textContent = t('Running…')
    const report = await invoke('run_diagnostics')
    summaryEl.textContent = report.summary
    const ico = { pass: '✓', warn: '!', fail: '✕' }
    envEl.innerHTML = report.checks.map((c) => `
      <li class="check check--${c.verdict}">
        <span class="check__badge">${ico[c.verdict]}</span>
        <span class="check__name">${esc(c.name)}</span>
        ${c.detail ? `<span class="check__detail ltr" dir="ltr">${esc(c.detail)}</span>` : ''}
      </li>`).join('')
  })

  // v1.2.0 — آزمایش نشتی WebRTC روی همان مسیری که مرورگر می‌رود (UDP خام).
  root.querySelector('#leak').addEventListener('click', async () => {
    summaryEl.textContent = t('Testing for WebRTC leaks…')
    try {
      const r = await invoke('webrtc_leak_test')
      summaryEl.textContent = r.leaking
        ? `${t('WebRTC is leaking your real IP')} — ${r.ip ?? ''}`
        : t('WebRTC protected — no IP leak')
      toast(summaryEl.textContent)
    } catch (e) {
      summaryEl.textContent = String(e)
    }
    await refresh()
  })

  // تازه‌سازی زنده — هر ۱ ثانیه، فقط وقتی این تب دیده می‌شود.
  //
  // This used to watch document.body with a subtree MutationObserver purely to
  // notice its own unmount — a global observer firing on every DOM change the
  // whole app made, plus a 1s log poll that kept running after the user had
  // moved on. The panel now starts and stops with its own visibility.
  let timer = null
  root.__onShow = () => {
    refresh()
    timer ??= setInterval(refresh, 1000)
  }
  root.__onHide = () => {
    clearInterval(timer)
    timer = null
  }

  return root
}
