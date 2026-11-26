// =============================================================================
//  src/ui/carddetails.js — ردیف‌های تعاملیِ کارتِ اتصال (۱.۵.۰، همان نسخه)
//
//  - ردیفِ تأخیر  → آخرین/کمینه/بیشینه/میانگین، جیتر، پکت‌لاس و تعدادِ آزمون‌ها
//    (`ping_stats`) و دکمهٔ «۱۰ بار اندازه بگیر» (`ping_burst`).
//  - ردیفِ پروتکل/زنجیره → همهٔ نودهای زنجیره به ترتیبِ خروجِ ترافیک، نقشِ هر نود
//    (کدام را شبکه/DPI می‌بیند، کدام را سایت‌ها).
//  - ردیفِ دانلود/آپلود → مجموعِ نشست و برنامه‌هایی که همین حالا از تونل
//    استفاده می‌کنند (`app_connections`).
//
//  متنِ روی برچسب‌های رنگی سفید است: متنِ رنگی روی زمینهٔ رنگی خسته‌کننده است.
// =============================================================================
import { invoke } from '@tauri-apps/api/core'
import { t } from '../i18n.js'
import { openModal, modalButton } from './modal.js'

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

function bytes(v) {
  const b = Math.max(0, Number(v) || 0)
  if (b >= 1024 ** 3) return `${(b / 1024 ** 3).toFixed(2)} GB`
  if (b >= 1024 ** 2) return `${(b / 1024 ** 2).toFixed(1)} MB`
  if (b >= 1024) return `${Math.round(b / 1024)} KB`
  return `${Math.round(b)} B`
}

const ms = (v) => (v == null || v < 0 ? '\u2014' : `${v} ms`)

function statRow(label, value) {
  return `<div class="cdet__row"><span class="cdet__k">${esc(label)}</span><span class="cdet__v ltr" dir="ltr">${esc(value)}</span></div>`
}

// ------------------------------------------------------------------ latency

export async function openPingDetails(connected) {
  const modal = openModal({ title: t('Latency details'), onEscape: () => modal.close() })
  const box = document.createElement('div')
  box.className = 'cdet'
  modal.body.append(box)
  const paint = (s) => {
    box.innerHTML = [
      statRow(t('Last'), ms(s?.last)),
      statRow(t('Minimum'), ms(s?.min)),
      statRow(t('Maximum'), ms(s?.max)),
      statRow(t('Average'), ms(s?.avg)),
      statRow(t('Jitter'), ms(s?.jitter)),
      statRow(t('Packet loss'), `${s?.loss ?? 0}%`),
      statRow(t('Answered / probes'), `${s?.answered ?? 0} / ${s?.samples ?? 0}`),
    ].join('') + `<p class="cdet__note">${esc(t('Measured through the live tunnel since this connection started. A probe without an answer counts as lost.'))}</p>`
  }
  paint(null)
  try { paint(await invoke('ping_stats')) } catch (_) { /* jsdom / no backend */ }
  const burst = modalButton(t('Measure 10 times'), 'btn--primary', async () => {
    burst.disabled = true
    burst.textContent = t('Measuring…')
    try { paint(await invoke('ping_burst')) } catch (_) { /* ignore */ }
    burst.disabled = !connected
    burst.textContent = t('Measure 10 times')
  })
  burst.disabled = !connected
  modal.actions.append(modalButton(t('Close'), 'btn--ghost', () => modal.close()), burst)
  return modal
}

// ------------------------------------------------------------------ chain

/** نودهای یک برچسبِ خطِ لوله مثلِ «VLESS → Aether(MASQUE) → Tor». */
export function chainNodes(label) {
  return String(label ?? '').split('\u2192').map((s) => s.trim()).filter((s) => s && s !== '\u2014')
}

function nodeKind(name) {
  const n = name.toLowerCase()
  if (n.startsWith('aether')) return t('Aether engine: Cloudflare WARP / MASQUE tunnel')
  if (n.startsWith('tor')) return t('Tor network: three relays')
  if (n.startsWith('psiphon')) return t('Psiphon network')
  return t('Your own config (Xray)')
}

function nodeRole(i, count) {
  if (count === 1) return t('The only node: your network sees it and websites see its address')
  if (i === 0) return t('First node: the only one your network (and its DPI) sees')
  if (i === count - 1) return t('Exit node: websites see this node\u2019s address')
  return t('Middle node: carries the traffic between the others')
}

export function openChainDetails(label, connected, exitIp) {
  const modal = openModal({ title: t('Connection chain'), onEscape: () => modal.close() })
  const nodes = connected ? chainNodes(label) : []
  const box = document.createElement('div')
  box.className = 'cdet cdet--chain'
  if (!nodes.length) {
    box.innerHTML = `<p class="cdet__note">${esc(t('Not connected. Connect to see the nodes your traffic passes through.'))}</p>`
  } else {
    const parts = [`<div class="cdet__end">\uD83D\uDCBB ${esc(t('This computer'))}</div>`]
    nodes.forEach((n, i) => {
      parts.push('<div class="cdet__arrow" aria-hidden="true">\u2193</div>')
      parts.push(`<div class="cdet__node"><span class="cdet__num">${i + 1}</span><span class="cdet__nodetext"><span class="cdet__name ltr" dir="ltr">${esc(n)}</span><span class="cdet__kind">${esc(nodeKind(n))}</span><span class="cdet__role">${esc(nodeRole(i, nodes.length))}</span></span></div>`)
    })
    parts.push('<div class="cdet__arrow" aria-hidden="true">\u2193</div>')
    parts.push(`<div class="cdet__end">\uD83C\uDF10 ${esc(t('Internet'))}${exitIp ? ` <bdi class="ltr" dir="ltr">${esc(exitIp)}</bdi>` : ''}</div>`)
    box.innerHTML = parts.join('')
  }
  modal.body.append(box)
  modal.actions.append(modalButton(t('Close'), 'btn--ghost', () => modal.close()))
  return modal
}

// ------------------------------------------------------------------ traffic

export function openTrafficDetails(getSnapshot) {
  const modal = openModal({ title: t('Traffic details'), onEscape: () => stop() })
  const box = document.createElement('div')
  box.className = 'cdet cdet--traffic'
  modal.body.append(box)
  let timer = null
  let alive = true
  const stop = () => { alive = false; if (timer) clearTimeout(timer); modal.close() }
  const paint = (apps) => {
    const s = getSnapshot() || {}
    const connected = s.state === 'CONNECTED'
    const head = statRow(t('Download'), bytes(connected ? s.rxBytes : 0)) + statRow(t('Upload'), bytes(connected ? s.txBytes : 0))
    let list
    if (!apps) list = `<p class="cdet__note">\u2026</p>`
    else if (!apps.available) list = `<p class="cdet__note">${esc(t('The list of programs is not available on this system.'))}</p>`
    else if (!apps.apps.length) list = `<p class="cdet__note">${esc(t('No program is using the tunnel right now.'))}</p>`
    else list = apps.apps.slice(0, 25).map((a) => `<div class="cdet__app"><span class="cdet__appname ltr" dir="ltr">${esc(a.name)}</span><span class="cdet__chip">${esc(t('{0} connections').replace('{0}', String(a.connections)))}</span></div>`).join('')
    box.innerHTML = head + `<h4 class="cdet__h">${esc(t('Programs using the tunnel now'))}</h4>` + list +
      `<p class="cdet__note">${esc(t('Programs connected to Aether\u2019s local proxy right now. Windows keeps no per-program byte counters for these connections, so the number of open connections is shown. TUN mode traffic is not listed.'))}</p>`
  }
  const tick = async () => {
    if (!alive || !modal.root.isConnected) return
    let apps = null
    try { apps = await invoke('app_connections') } catch (_) { apps = { available: false, apps: [] } }
    if (!alive) return
    paint(apps)
    timer = setTimeout(tick, 3000)
  }
  paint(null)
  tick()
  modal.actions.append(modalButton(t('Close'), 'btn--ghost', () => stop()))
  return modal
}
