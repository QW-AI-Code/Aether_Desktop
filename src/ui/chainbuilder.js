// =============================================================================
//  src/ui/chainbuilder.js — «زنجیرهٔ اتصال» یکپارچه (۱.۵.۰، همان نسخه)
//
//  «استفاده از کانفیگ سفارشی» (صفحهٔ کانفیگ‌ها) و «بک‌اند شبکه» (همین صفحه) دو
//  کلیدِ جدا بودند که با هم زنجیره را می‌ساختند. حالا کاربر اول تعدادِ نودها را
//  انتخاب می‌کند، بعد هستهٔ هر نود را، به ترتیبی که ترافیک از رایانه بیرون
//  می‌رود؛ با «تنظیمات» هر نود، تنظیماتِ همان هسته باز می‌شود:
//    Aether  → پروتکل/اسکن/نسخهٔ IP همین صفحه، و «ترابری و ضد DPI»
//    Psiphon → کشورِ خروجی      Tor → بریج‌ها و بقیهٔ تنظیماتِ تور
//    Config  → صفحهٔ کانفیگ‌های سفارشی (سرورها، انتخاب خودکار، پینگ، سرعت)
//  فقط زنجیره‌هایی پیشنهاد می‌شوند که برنامه واقعاً اجرا می‌کند (همان نگاشتِ
//  ChainBuilderPolicy.kt موبایل).
// =============================================================================
import { invoke } from '@tauri-apps/api/core'
import { t } from '../i18n.js'
import { toast } from './toast.js'
import { scaleToFit } from './fit.js'
import { app, saveProfile } from '../main.js'
import { customState, applyCustomView, refreshCustomConfigs, onCustomConfigs } from '../views/customconfigs.js'

export const BACKEND_CHAINS = {
  AETHER: ['AETHER'],
  AETHER_PSIPHON: ['AETHER', 'PSIPHON'],
  TOR: ['TOR'],
  AETHER_TOR: ['AETHER', 'TOR'],
  TOR_PSIPHON: ['TOR', 'PSIPHON'],
  TOR_AETHER: ['TOR', 'AETHER'],
}

const BASE_CHAINS = {
  AETHER: ['AETHER'], PSIPHON: ['PSIPHON'], TOR: ['TOR'],
  AETHER_PSIPHON: ['AETHER', 'PSIPHON'], AETHER_TOR: ['AETHER', 'TOR'],
  TOR_PSIPHON: ['TOR', 'PSIPHON'], TOR_AETHER: ['TOR', 'AETHER'],
}

/** شناسهٔ ChainMode (Rust، SCREAMING_SNAKE_CASE) → نودها. */
export function modeChain(mode) {
  if (!mode || mode === 'SOLO') return ['CONFIG']
  if (mode.startsWith('CONFIG_')) {
    const base = BASE_CHAINS[mode.slice('CONFIG_'.length)]
    return base ? ['CONFIG', ...base] : null
  }
  if (mode.endsWith('_CONFIG')) {
    const base = BASE_CHAINS[mode.slice(0, -'_CONFIG'.length)]
    return base ? [...base, 'CONFIG'] : null
  }
  return null
}

export const MODES = ['SOLO', 'CONFIG_AETHER', 'AETHER_CONFIG', 'CONFIG_PSIPHON', 'PSIPHON_CONFIG', 'CONFIG_TOR', 'TOR_CONFIG',
  'CONFIG_AETHER_PSIPHON', 'CONFIG_AETHER_TOR', 'CONFIG_TOR_PSIPHON', 'CONFIG_TOR_AETHER',
  'AETHER_PSIPHON_CONFIG', 'AETHER_TOR_CONFIG', 'TOR_PSIPHON_CONFIG', 'TOR_AETHER_CONFIG']

const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

/** همهٔ زنجیره‌های قابلِ اجرا، کوتاه‌ترها اول. */
export function allChains() {
  const out = [...Object.values(BACKEND_CHAINS), ...MODES.map(modeChain).filter(Boolean)]
  const uniq = []
  for (const c of out) if (!uniq.some((u) => same(u, c))) uniq.push(c)
  return uniq.sort((a, b) => a.length - b.length || a.join().localeCompare(b.join()))
}

export function options(prefix, length, slot) {
  const set = []
  for (const c of allChains()) {
    if (c.length !== length || !same(c.slice(0, slot), prefix.slice(0, slot))) continue
    if (!set.includes(c[slot])) set.push(c[slot])
  }
  return set
}

export function complete(prefix, length, wish = []) {
  const cands = allChains().filter((c) => c.length === length && same(c.slice(0, prefix.length), prefix))
  if (!cands.length) return null
  // 1.5.0 (same version): a config node is never ADDED on the user's behalf —
  // growing "Aether" to two nodes used to pick "Aether → Config" and then asked
  // for a config nobody chose. It stays only if the user picked or already had it.
  const keepConfig = prefix.includes('CONFIG') || wish.includes('CONFIG')
  const score = (c) => c.filter((x, i) => wish[i] === x).length * 2 - (!keepConfig && c.includes('CONFIG') ? 100 : 0)
  return cands.reduce((best, c) => (score(c) > score(best) ? c : best), cands[0])
}

/** زنجیره‌هایی با این تعداد نود که فقط با کانفیگ اجرا می‌شوند (۳ نود). */
export function lengthNeedsConfig(length) {
  const cands = allChains().filter((c) => c.length === length)
  return cands.length > 0 && cands.every((c) => c.includes('CONFIG'))
}

// زنجیرهٔ کانفیگ‌داری که کاربر پیش از افزودن/انتخابِ کانفیگ برگزیده: همان روی
// صفحه می‌ماند و به‌محضِ وجودِ کانفیگ خودکار روشن می‌شود.
let pendingChain = null

/** آنچه برای این زنجیره ذخیره می‌شود؛ null یعنی اجراشدنی نیست. */
export function target(chain) {
  if (!allChains().some((c) => same(c, chain))) return null
  if (!chain.includes('CONFIG')) {
    const backend = Object.keys(BACKEND_CHAINS).find((k) => same(BACKEND_CHAINS[k], chain))
    return backend ? { backend, customEnabled: false, mode: null } : null
  }
  const mode = MODES.find((m) => { const c = modeChain(m); return c && same(c, chain) })
  if (!mode) return null
  const base = mode === 'SOLO' ? null : mode.replace(/^CONFIG_/, '').replace(/_CONFIG$/, '')
  return { backend: base && BACKEND_CHAINS[base] ? base : null, customEnabled: true, mode }
}

export function currentChain(backend, customOn, mode) {
  return customOn ? (modeChain(mode) || ['CONFIG']) : (BACKEND_CHAINS[backend || 'AETHER'] || ['AETHER'])
}

const CORE_NAME = { CONFIG: 'Config', AETHER: 'Aether', PSIPHON: 'Psiphon', TOR: 'Tor' }
const CORE_DESC = {
  CONFIG: 'Your own V2Ray / Xray / NapsternetV server',
  AETHER: 'Cloudflare WARP or MASQUE, with Smart mode and anti-DPI',
  PSIPHON: 'Psiphon network, exit country automatic or chosen',
  TOR: 'Tor network, bridges when it is blocked',
}

function role(i, n) {
  if (n === 1) return t('The only node: your network sees it and websites see its address')
  if (i === 0) return t('First node: the only one your network (and its DPI) sees')
  if (i === n - 1) return t('Exit node: websites see this node\u2019s address')
  return t('Middle node: carries the traffic between the others')
}

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

/**
 * @param {{ panel: HTMLElement, openRow: (id: string) => void, refresh: () => void }} opts
 */
export function renderChainBuilder({ panel, openRow, refresh }) {
  const root = document.createElement('div')
  root.className = 'scard-group chainb'
  let busy = false
  // 1.5.0 (same version): the diagram's fitter of the current paint, and the
  // measured width/font ratio per chain, so a repaint starts at the final size
  // (no one-frame jump back to 13px before the fit catches up).
  let fit = null
  const fitK = new Map()

  const chainNow = () => {
    const cc = customState()
    return pendingChain || currentChain(app.profile?.backend, !!(cc.enabled && cc.activeId), cc.mode)
  }

  async function applyChain(next) {
    const tg = next && target(next)
    if (!tg || busy) return
    busy = true
    try {
      if (tg.backend && tg.backend !== (app.profile?.backend || 'AETHER')) await saveProfile({ backend: tg.backend })
      const cc = customState()
      if (tg.mode && tg.mode !== cc.mode) applyCustomView(await invoke('cc_set_mode', { mode: tg.mode }))
      const wantOn = tg.customEnabled && !!customState().activeId
      if (!!customState().enabled !== wantOn) applyCustomView(await invoke('cc_set_enabled', { enabled: wantOn }))
      pendingChain = tg.customEnabled && !customState().activeId ? next : null
    } catch (e) {
      toast(t(typeof e === 'string' ? e : (e?.message || 'Something went wrong.')))
    } finally {
      busy = false
    }
    refresh()
  }

  function focusCore(core) {
    if (core === 'CONFIG') { openRow('custom'); return }
    const target = core === 'AETHER'
      ? panel.querySelector('[data-key="protocol"]')
      : core === 'TOR'
        ? panel.querySelector('#v20-tor')
        : panel.querySelector('[data-key="exitRegion"]')
    const group = target?.closest('.scard-group') || target
    if (!group) { if (core === 'AETHER') openRow('transport'); return }
    group.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    group.classList.add('chainb-flash')
    setTimeout(() => group.classList.remove('chainb-flash'), 1600)
  }

  function paint() {
    const cc = customState()
    // A config exists now: the drafted chain becomes the real one.
    if (pendingChain && cc.activeId && !busy) {
      const draft = pendingChain
      pendingChain = null
      applyChain(draft)
    }
    const chain = chainNow()
    const n = chain.length
    // 1.5.0 (same version): every size inside the track is in em, so its width
    // is exactly proportional to its font; see scaleToFit() in fit.js.
    const diagram = ['<span class="chainb__end" aria-hidden="true">\uD83D\uDCBB</span>',
      ...chain.map((c, i) => `<span class="chainb__pill"><span class="chainb__num">${i + 1}</span>${esc(CORE_NAME[c])}</span>`),
      '<span class="chainb__end" aria-hidden="true">\uD83C\uDF10</span>']
      .join('<span class="chainb__arrow" aria-hidden="true">\u2192</span>')
    const chainKey = chain.join('>')
    const k0 = fitK.get(chainKey) || estimateK(chain)
    const nodes = chain.map((core, slot) => {
      const opts = options(chain, n, slot)
      // 1.5.0 (same version): text on its own full-width line, controls below —
      // no more one-word-per-line columns next to the select and button.
      return `<div class="chainb__node" data-slot="${slot}">
        <div class="chainb__head">
          <span class="chainb__num">${slot + 1}</span>
          <span class="chainb__text"><span class="chainb__role">${esc(role(slot, n))}</span>
            <span class="chainb__desc">${esc(t(CORE_DESC[core]))}</span></span>
        </div>
        <div class="chainb__controls">
          <select class="chainb__core" aria-label="${esc(t('Node {0}').replace('{0}', String(slot + 1)))}" ${busy ? 'disabled' : ''}>
            ${opts.map((o) => `<option value="${o}" ${o === core ? 'selected' : ''}>${esc(o === 'CONFIG' ? t('Config') : CORE_NAME[o])}</option>`).join('')}
          </select>
          <button type="button" class="btn btn--small chainb__open">${esc(t('Settings'))}</button>
        </div>
      </div>`
    }).join('')
    root.innerHTML = `
      <h3 class="chainb__caption">${esc(t('Connection chain'))}</h3>
      <div class="sethub__card scard chainb__card">
        <div class="chainb__diagram ltr" dir="ltr" aria-label="${esc(chain.map((c) => CORE_NAME[c]).join(' \u2192 '))}"><span class="chainb__track">${diagram}</span></div>
        <div class="chainb__count" role="radiogroup" aria-label="${esc(t('Number of nodes'))}">
          <span class="chainb__countlabel">${esc(t('Number of nodes'))}</span>
          ${[1, 2, 3].map((k) => `<button type="button" class="chainb__countbtn ${k === n ? 'is-on' : ''}" role="radio" aria-checked="${k === n}" data-count="${k}">${k}</button>`).join('')}
        </div>
        ${lengthNeedsConfig(n) ? `<p class="chainb__hint">${esc(t('A 3-node chain always contains a config: the engine runs at most two of Aether, Psiphon and Tor one after the other, and the third node is your own config (first or last).'))}</p>` : ''}
        ${nodes}
        ${chain.includes('CONFIG') && !cc.activeId ? `<p class="chainb__notice">${esc(t('This chain needs a custom config. Add or select one in Custom configs.'))}</p>` : ''}
        ${chain.includes('AETHER') ? `<button type="button" class="btn btn--small chainb__transport">${esc(t('Transport & anti-DPI'))}</button>` : ''}
      </div>
      <p class="chainb__footer">${esc(t('Pick how many nodes the chain has and which core runs on each node, in the order traffic leaves this computer. A node\u2019s Settings button opens that core\u2019s options.'))}</p>`
    for (const b of root.querySelectorAll('.chainb__countbtn')) {
      b.addEventListener('click', () => {
        const k = Number(b.dataset.count)
        if (k === n) return
        applyChain(complete(chain.slice(0, 1), k, chain) || complete([], k, chain))
      })
    }
    for (const node of root.querySelectorAll('.chainb__node')) {
      const slot = Number(node.dataset.slot)
      node.querySelector('.chainb__core').addEventListener('change', (e) => {
        applyChain(complete([...chain.slice(0, slot), e.target.value], n, chain))
      })
      node.querySelector('.chainb__open').addEventListener('click', () => focusCore(chain[slot]))
    }
    root.querySelector('.chainb__transport')?.addEventListener('click', () => openRow('transport'))
    // The diagram stays on one line; its font shrinks to the width it has.
    // 1.5.0 (same version): measured once at a fixed reference size, scaled by
    // CSS container units — no ResizeObserver feedback loop, no jitter.
    fit?.dispose()
    fit = scaleToFit(root.querySelector('.chainb__diagram'), root.querySelector('.chainb__track'), {
      min: 7, max: 13, k: k0, onMeasure: (k) => fitK.set(chainKey, k),
    })
  }

  paint()
  refreshCustomConfigs()
  const unwatch = onCustomConfigs(() => {
    if (!root.isConnected) { unwatch(); fit?.dispose(); return }
    paint()
  })
  return root
}

// 1.5.0 (same version): first guess of the diagram's width in em (before the
// real measurement in fit.js), so even the very first frame is close to final.
// Monospace ≈ 0.6em per letter; pill = number + gap + padding; arrow + margins.
function estimateK(chain) {
  const letters = chain.reduce((sum, c) => sum + CORE_NAME[c].length, 0)
  return (letters * 0.62 + chain.length * 2.6 + (chain.length + 1) * 1.6 + 2 * 1.4) * 1.03
}
