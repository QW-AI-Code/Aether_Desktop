// =============================================================================
//  src/views/customconfigs.js — زیرصفحهٔ «کانفیگ‌های سفارشی» (۱.۳.۰)
//  پورت از ui/settings/CustomConfigsPage.kt نسخهٔ اندروید ۱.۵.۰ — بدونِ QR.
// =============================================================================
//
//  # آنچه این صفحه هرگز ندارد
//
//  نمایی که از Rust می‌آید (`cc_state`) outbound و متنِ خامِ کانفیگ را ندارد.
//  متنِ خام فقط با `cc_get_raw` و فقط برای کانفیگِ قفل‌نشده خوانده می‌شود (ویرایش
//  و کپیِ لینک). کانفیگِ قفل‌شدهٔ npvt نشانی و کلیدش را هیچ‌جا نشان نمی‌دهد.
//
//  # QR
//
//  نسخهٔ ویندوز دوربین و اسکنرِ تصویر ندارد؛ ورود فقط از متن، نشانیِ اشتراک،
//  انتخابِ فایل و کشیدن‌ورها‌کردنِ فایل است.

import { invoke } from '@tauri-apps/api/core'
import { decodeQrFile } from '../qr.js'
import { listen } from '@tauri-apps/api/event'
import { t, getLang } from '../i18n.js'
import { toast } from '../ui/toast.js'
import { emit, app, saveProfile } from '../main.js'
import { openModal, modalButton, modalNote, confirmModal } from '../ui/modal.js'
import { icon } from '../ui/icons.js'
import { onScan, scanState, startScan, stopScan, scanLineFor, groupProgressText, dismissScanResult } from './cleanip.js'

const EMPTY = { enabled: false, mode: 'SOLO', modeLabel: 'Config', activeId: null, modes: [], configs: [], max: 500, groups: [], tabNames: {}, hiddenTabs: [], subscriptions: [] }

/** آخرین نمای شناخته‌شده؛ ردیفِ هاب مقدارش را از همین می‌خواند. */
let CC = { ...EMPTY }
const watchers = new Set()
let wired = false

const FILE_ACCEPT = '.npvt,.npvs,.txt,.json,.conf,.png,.jpg,.jpeg,.webp'
const isQrImage=(name)=>/\.(png|jpe?g|webp)$/i.test(name)
// 1.4.0 — the selected tab survives leaving the page and restarting the app.
const TAB_KEY = 'aether.cc.tab'
const SORT_KEY = 'aether.cc.sortByPing'
const SID_KEY = 'aether.cc.serverIds.v1'
function lsGet(k) { try { return globalThis.localStorage?.getItem(k) ?? null } catch (_) { return null } }
function lsSet(k, v) { try { globalThis.localStorage?.setItem(k, v) } catch (_) { /* storage unavailable */ } }
let currentTab = lsGet(TAB_KEY) || 'all'
let CCLoaded = false
function setTab(id) { currentTab = id; lsSet(TAB_KEY, id) }
/** Automatic ping sort (default on). Off keeps the import order. */
export function sortByPing() { return lsGet(SORT_KEY) !== '0' }
export function setSortByPing(on) { lsSet(SORT_KEY, on ? '1' : '0') }

// ------------------------------------------------------------- display helpers (1.4.0)
//
//  Names shipped with public configs carry channel adverts, emojis and long
//  Cloudflare-worker hostnames. They are removed for DISPLAY only; the stored
//  name is never rewritten.
export function cleanServerName(raw, fallback = '') {
  let s = String(raw ?? '')
  // eslint-disable-next-line no-misleading-character-class
  s = s.replace(/[\u00AD\u061C\u180E\u200B\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, '')
  s = s.replace(/https?:\/\/\S+/gi, ' ')
  s = s.replace(/\b(?:t\.me|telegram\.me)\/\S*/gi, ' ')
  s = s.replace(/@[A-Za-z0-9_]{3,}/g, ' ')
  s = s.replace(/[\p{Extended_Pictographic}\p{Regional_Indicator}\uFE0F\u20E3]/gu, ' ')
  s = s.replace(/\b[\w-]+(?:\.[\w-]+)*\.(?:workers|pages)\.dev(?::\d+)?/gi, ' ')
  s = s.replace(/(?:join\s+us|join|subscribe|telegram|channel|تلگرام|کانال|عضو\s*شوید|عضو\s*شو)\S*/gi, ' ')
  s = s.replace(/\s+/g, ' ').replace(/^[\s|•·\-–—_:,.>]+|[\s|•·\-–—_:,.>]+$/g, '')
  return s || fallback
}

/** Display-only numbering (mobile parity): ids of one tab, in stored order, become S1..SN with no gaps. */
export function assignServerIds(_tabId, ids) {
  const out = {}
  let n = 0
  for (const id of ids) if (!(id in out)) out[id] = `S${++n}`
  return out
}

/** `TYPE S# • IP:PORT` — never a name, advert, or worker host. Always left-to-right. */
export function serverLine(c, sid) {
  const head = [String(c.chainLabel || c.format || '').trim(), sid].filter(Boolean).join(' ')
  const ep = c.locked ? '' : String(c.endpoint || '').trim()
  return ep ? `${head} • ${ep}` : head
}

// ------------------------------------------------------------- real delay
//
//  «پینگِ واقعی» (`cc_ping` / `cc_ping_all`): هر کانفیگ در یک Xrayِ موقت اجرا و
//  یک `GET /generate_204` از دلِ آن فرستاده می‌شود. نتیجه فقط در حافظهٔ همین
//  صفحه می‌ماند (برای هر شناسه): `{ ms, status, label }` یا `{ pending: true }`.

const PING = new Map()
let pingAllBusy = false

/** برچسب‌های وضعیت؛ رشتهٔ انگلیسی همان است که Rust می‌فرستد. */
const PING_LABELS = ['No response', 'Server off', 'Filtered', 'Invalid config', 'No network', 'Unexpected HTTP status', 'Partial response']

export function pingText(r) {
  if (!r) return ''
  if (r.pending) return t('Testing…')
  if (typeof r.ms === 'number' && r.ms >= 0) return `${r.ms} ms`
  const label = PING_LABELS.includes(r.label) ? t(r.label) : t('No response')
  return `-1 · ${label}`
}

export function pingClass(r) {
  if (!r || r.pending) return r?.pending ? 'is-wait' : 'is-muted'
  if (!Number.isFinite(r.ms) || r.ms < 0) return 'is-muted'
  return r.ms < 150 ? 'is-good' : r.ms <= 300 ? 'is-slow' : 'is-bad'
}
export function catalogRows(configs, tab, pings = PING, subscriptions = CC.subscriptions, sorted = true) {
  return configs.filter((c) => tab === 'all' || (tab === 'format:npvt' ? !c.groupId && c.format === 'NPVT' : tab === 'format:v2ray' ? !c.groupId && c.format !== 'NPVT' : tab.startsWith('sub:') ? (subscriptions || []).find(s => s.id === tab)?.configIds?.includes(c.id) : c.groupId === tab))
    .sort((a,b) => {
      if (!sorted) return 0
      const ms = (c) => { const p=pings.get(c.id); return p && !p.pending && Number.isFinite(p.ms) && p.ms >= 0 ? p.ms : Infinity }
      return ms(a)-ms(b) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id)
    })
}
export function catalogTabs(state = CC) {
 const tabs=[{id:'all',name:t('All')}]
 if(state.configs.some((c)=>!c.groupId && c.format!=='NPVT')) tabs.push({id:'format:v2ray',name:'V2Ray'})
 if(state.configs.some((c)=>!c.groupId && c.format==='NPVT')) tabs.push({id:'format:npvt',name:'Npvt'})
 return [...tabs,...state.groups].map((g)=>({...g,name:state.tabNames[g.id]||g.name,count:catalogRows(state.configs,g.id,PING,state.subscriptions).length}))
}
async function moveConfig(c) {
 const m=openModal({title:t('Move to tab')})
 for(const g of [{id:null,name:t('All')},...CC.groups]) {
  m.body.append(modalButton(g.name,'btn--ghost',async()=>{try {adopt(await invoke('cc_move',{ids:[c.id],groupId:g.id}));m.close()}catch(e){toast(errorText(e))}}))
 }
}
async function saveTab(id=null) {
 const old=catalogTabs().find((g)=>g.id===id)
 const name=await textDialog({title:t(id?'Rename tab':'New tab'),value:old?.name||'',okLabel:t('Save')})
 if(!name?.trim()) return
 try {adopt(await invoke('cc_tab_save',{id,name}))}catch(e){toast(errorText(e))}
}


function notifyWatchers() {
  for (const fn of [...watchers]) fn()
}

function adoptPings(payload) {
  for (const r of payload?.results ?? []) {
    if (r && r.id) PING.set(r.id, { ms: r.ms, status: r.status, label: r.label })
  }
  notifyWatchers()
}

// ------------------------------------------------------------- تست سرعت
//  پورت ConfigSpeedTest.kt: Rust یک Xrayِ موقت بالا می‌آورد و بایت‌های واقعی را از دل
//  همین کانفیگ دانلود/آپلود می‌کند؛ اینجا فقط وضعیت و نتیجه نشان داده می‌شود.
const SPEED = new Map()

function adoptSpeed(payload) {
  const rows = Array.isArray(payload?.results) ? payload.results : payload && payload.id ? [payload] : []
  for (const r of rows) if (r && r.id) SPEED.set(r.id, r)
  notifyWatchers()
}

export const speedLabel = (bps) => (bps > 0 ? `${(bps / 1_000_000).toFixed(2)} MB/s` : '—')

export function speedText(r) {
  if (!r) return ''
  if (r.running) return t('Measuring real throughput…')
  if (r.downloadBps > 0 || r.uploadBps > 0) return `↓ ${speedLabel(r.downloadBps)}  ↑ ${speedLabel(r.uploadBps)}`
  return t('No throughput result; endpoint or proxy unavailable')
}

async function speedOne(c) {
  if (SPEED.get(c.id)?.running) return
  const ok = await confirmModal({
    title: t('Download / upload speed test'),
    body: t('This test sends synthetic data through this server only and may use approximately 10 MiB per attempt. Mobile data charges may apply. No personal files are uploaded.'),
    ok: t('Start test'),
    cancel: t('Cancel'),
  })
  if (!ok) return
  SPEED.set(c.id, { id: c.id, running: true, downloadBps: -1, uploadBps: -1 })
  notifyWatchers()
  try {
    adoptSpeed(await invoke('cc_speed_test', { id: c.id }))
  } catch (e) {
    SPEED.delete(c.id)
    notifyWatchers()
    toast(errorText(e))
  }
}

async function pingOne(c) {
  if (PING.get(c.id)?.pending) return
  PING.set(c.id, { pending: true })
  notifyWatchers()
  try {
    adoptPings(await invoke('cc_ping', { id: c.id }))
  } catch (e) {
    PING.delete(c.id)
    notifyWatchers()
    toast(errorText(e))
  }
}

async function pingAll() {
  if (pingAllBusy || !CC.configs.length) return
  pingAllBusy = true
  for (const c of CC.configs) PING.set(c.id, { pending: true })
  notifyWatchers()
  try {
    adoptPings(await invoke('cc_ping_all'))
  } catch (e) {
    for (const c of CC.configs) if (PING.get(c.id)?.pending) PING.delete(c.id)
    toast(errorText(e))
  } finally {
    pingAllBusy = false
    notifyWatchers()
  }
}

// ------------------------------------------------------------- paste hygiene
//
//  همان فهرستِ `ConfigParser.cleanInput` اندروید (و `import::clean_input` در
//  Rust): RLM/LRM و جداکننده‌های bidi که پیام‌رسان‌های راست‌به‌چپ دورِ متنِ لاتین
//  می‌گذارند، فاصلهٔ صفرعرض، word joiner، BOM، soft hyphen. ZWNJ/ZWJ می‌مانند.
// eslint-disable-next-line no-misleading-character-class
const INVISIBLE = /[\u00AD\u061C\u180E\u200B\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g

export function stripInvisible(text) {
  return String(text ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(INVISIBLE, '')
    .replace(/[\u00A0\u202F]/g, ' ')
}

function esc(v) {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function adopt(view) {
  if (view && typeof view === 'object' && Array.isArray(view.configs)) { CC = { ...EMPTY, ...view }; CCLoaded = true }
  for (const fn of [...watchers]) fn()
  // ردیفِ هابِ تنظیمات مقدارش را از `CC` می‌خواند.
  emit()
}

function wireOnce() {
  if (wired) return
  wired = true
  try {
    Promise.resolve(listen('aether://custom', (e) => adopt(e.payload))).catch(() => {})
    Promise.resolve(listen('aether://custom-ping', (e) => adoptPings(e.payload))).catch(() => {})
    Promise.resolve(listen('aether://custom-speed', (e) => adoptSpeed(e.payload))).catch(() => {})
    Promise.resolve(invoke('cc_speed_state')).then(adoptSpeed).catch(() => {})
  } catch (_) { /* jsdom */ }
  wireDrop()
}

// ------------------------------------------------------------- drag & drop
//
//  سه مسیر، با یک مقصد (`importPaths` / `importFiles`):
//
//  ۱. رویدادهای بومیِ تائوری (`tauri://drag-enter|over|drop|leave`) — وقتی برنامه
//     بی‌ارتقا اجرا شود. با `listen` سراسری گوش داده می‌شوند (هدفِ Any)، تا فرقی
//     نکند Rust آن‌ها را به webview بفرستد یا به window.
//  ۲. `aether://file-drop` از `filedrop.rs` — برنامهٔ نصب‌شده با دسترسیِ مدیر اجرا
//     می‌شود و ویندوز (UIPI) رها کردنِ OLE از Explorer را به آن نمی‌رساند؛ Rust
//     همان مسیرها را از `WM_DROPFILES` می‌خواند.
//  ۳. رویدادهای HTML5 (`dragover`/`drop`) با `File`ِ واقعی — اگر WebView خودش
//     فایل را تحویل داد. بدونِ `preventDefault` روی dragover، رها کردن مجاز نیست
//     و WebView به‌جایش فایل را باز می‌کند.
//
//  یک رها کردن ممکن است از دو مسیر برسد؛ نامِ فایل تا دو ثانیه یک بار پذیرفته می‌شود.

const DROP_DEDUPE_MS = 2000
const recentDrops = new Map()
let dropWired = false

function baseName(p) {
  return String(p ?? '').split(/[\\/]/).pop().toLowerCase()
}

function freshDrop(name) {
  const now = Date.now()
  for (const [k, at] of recentDrops) if (now - at > DROP_DEDUPE_MS) recentDrops.delete(k)
  if (!name || recentDrops.has(name)) return false
  recentDrops.set(name, now)
  return true
}

/** ناحیهٔ رها کردنِ فایل = خودِ صفحهٔ کانفیگ‌ها؛ کادرِ خط‌چین از رابط حذف شده. */
function dropZone() {
  return document.querySelector('.view--custom')
}

function setDropOver(on) {
  dropZone()?.classList.toggle('is-over', !!on)
}

/** مسیرهایی که از رویدادِ پنجره رسیده‌اند؛ تعدادِ پذیرفته‌شده. */
export function handleDroppedPaths(paths) {
  setDropOver(false)
  if (!dropZone()) return 0
  const list = (Array.isArray(paths) ? paths : [])
    .filter((p) => typeof p === 'string' && p.trim())
    .filter((p) => freshDrop(baseName(p)))
  if (list.length) importPaths(list)
  return list.length
}

/** `File`هایی که خودِ WebView تحویل داده؛ تعدادِ پذیرفته‌شده. */
export function handleDroppedFiles(files) {
  setDropOver(false)
  if (!dropZone()) return 0
  const list = [...(files ?? [])].filter((f) => f && freshDrop(String(f.name ?? '').toLowerCase()))
  if (list.length) importFiles(list)
  return list.length
}

function hasFiles(ev) {
  const types = ev?.dataTransfer?.types
  if (!types) return false
  return typeof types.includes === 'function' ? types.includes('Files') : [...types].includes('Files')
}

function wireDrop() {
  if (dropWired) return
  dropWired = true
  const onTauri = (name, fn) => {
    try { Promise.resolve(listen(name, fn)).catch(() => {}) } catch (_) { /* jsdom */ }
  }
  onTauri('tauri://drag-enter', () => setDropOver(true))
  onTauri('tauri://drag-over', () => setDropOver(true))
  onTauri('tauri://drag-leave', () => setDropOver(false))
  onTauri('tauri://drag-drop', (e) => handleDroppedPaths(e?.payload?.paths))
  onTauri('aether://file-drop', (e) => handleDroppedPaths(Array.isArray(e?.payload) ? e.payload : e?.payload?.paths))

  const allow = (ev) => {
    if (!hasFiles(ev)) return
    ev.preventDefault()
    const zone = dropZone()
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = zone ? 'copy' : 'none'
    setDropOver(!!zone)
  }
  document.addEventListener('dragenter', allow)
  document.addEventListener('dragover', allow)
  document.addEventListener('dragleave', (ev) => {
    // فقط وقتی نشانگر واقعاً از پنجره بیرون رفت، نه بینِ دو عنصر.
    if (!ev.relatedTarget) setDropOver(false)
  })
  document.addEventListener('drop', (ev) => {
    if (!hasFiles(ev)) return
    ev.preventDefault()
    handleDroppedFiles(ev.dataTransfer?.files)
  })
}

/** برای ردیفِ هاب. */
export function customConfigsValue() {
  wireOnce()
  if (!CC.enabled) return t('Off')
  return CC.modeLabel ? chainText(CC.modeLabel) : t('On')
}

/** بارِ اول (و پس از هر بازگشت به هاب) نما را از Rust می‌خواند. */
export async function refreshCustomConfigs() {
  wireOnce()
  try {
    adopt(await invoke('cc_state'))
  } catch (_) {
    adopt(null)
  }
}

export function onCustomConfigs(fn) {
  watchers.add(fn)
  return () => watchers.delete(fn)
}

// ------------------------------------------------------------- errors

function errorText(e) {
  if (!e) return t('Something went wrong.')
  if (typeof e === 'string') return t(e)
  if (e.kind === 'password') return t('This npvt config is password protected.')
  if (e.kind === 'wrongPassword') return t('Wrong password for this npvt config.')
  if (e.kind === 'locked') return t('This config is locked by its author.')
  return t(e.message || String(e))
}

/** دیالوگِ رمز؛ `null` اگر کاربر لغو کرد. */
function askPassword(wrong) {
  return new Promise((resolve) => {
    let done = false
    const finish = (v) => { if (done) return; done = true; modal.close(); resolve(v) }
    const modal = openModal({ title: t('Password'), onEscape: () => finish(null) })
    modal.body.append(modalNote(wrong ? t('Wrong password for this npvt config.') : t('This npvt config is password protected.'), wrong ? 'is-error' : ''))
    const input = document.createElement('input')
    input.className = 'input ltr'
    input.dir = 'ltr'
    input.type = 'password'
    input.autocomplete = 'off'
    input.placeholder = t('Password')
    input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); finish(input.value) } })
    modal.body.append(input)
    modal.actions.append(
      modalButton(t('Cancel'), 'btn--ghost', () => finish(null)),
      modalButton(t('Unlock'), 'btn--primary', () => finish(input.value)),
    )
    setTimeout(() => input.focus(), 0)
  })
}

/** یک ورود؛ اگر رمز لازم شد می‌پرسد و دوباره می‌فرستد. */
async function withPassword(call, destination = currentTab.startsWith('user:') ? currentTab : null) {
  let password = null
  for (let round = 0; round < 4; round++) {
    try {
      let view = await call(password)
      adopt(view)
      const n = view?.added ?? 0
      if (n) toast(n === 1 ? t('1 config imported.') : t('{0} configs imported.').replace('{0}', String(n)))
      return true
    } catch (e) {
      if (e && (e.kind === 'password' || e.kind === 'wrongPassword')) {
        password = await askPassword(e.kind === 'wrongPassword')
        if (password === null) return false
        continue
      }
      toast(errorText(e))
      return false
    }
  }
  return false
}

function importPaths(paths) {
  const destination = currentTab.startsWith('user:') ? currentTab : null
  ;(async () => {
    for (const path of paths) {
      if(isQrImage(path)){try{const bytes=await invoke('cc_read_qr_image',{path});await importQr(new Blob([new Uint8Array(bytes)]),destination)}catch(e){toast(errorText(e))}}
      else await withPassword((password) => invoke('cc_import_path', { path, password, groupId:destination }), destination)
    }
  })()
}

async function importFiles(files, destination = currentTab.startsWith('user:') ? currentTab : null) {
  for (const file of files) {
    if(isQrImage(file.name)){await importQr(file,destination);continue;}
    let bytes
    try { bytes = await readFile(file) } catch (e) { toast(errorText(e)); continue }
    await withPassword((password) => invoke('cc_import_bytes', { name: file.name, bytes, password, groupId:destination }), destination)
  }
}

async function importQr(file, destination = currentTab.startsWith('user:') ? currentTab : null){try {const text=stripInvisible(await decodeQrFile(file)).trim();return await importText(text,destination);}catch(e){toast(errorText(e));return false;}}
async function importText(text, destination = currentTab.startsWith('user:') ? currentTab : null){
 const subscription=/^https:\/\/\S+$/i.test(text)
 return withPassword((password)=>subscription?invoke('cc_subscription_save',{id:null,name:new URL(text).hostname,url:text,groupId:destination,password}):invoke('cc_import_text',{text,password,groupId:destination}), destination)
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    if (file.size > 2 * 1024 * 1024) { reject(t('file is larger than 2 MB')); return }
    const r = new FileReader()
    r.onload = () => resolve(Array.from(new Uint8Array(r.result)))
    r.onerror = () => reject(t('file could not be read'))
    r.readAsArrayBuffer(file)
  })
}

// ------------------------------------------------------------- dialogs

function textDialog({ title, value = '', area = false, okLabel, note = '' }) {
  return new Promise((resolve) => {
    let done = false
    const finish = (v) => { if (done) return; done = true; modal.close(); resolve(v) }
    const modal = openModal({ title, onEscape: () => finish(null) })
    if (note) modal.body.append(modalNote(note))
    const input = document.createElement(area ? 'textarea' : 'input')
    input.className = area ? 'input input--area ltr cc-edit' : 'input'
    if (area) input.dir = 'ltr'
    input.value = value
    if (!area) input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); finish(input.value) } })
    modal.body.append(input)
    modal.actions.append(
      modalButton(t('Cancel'), 'btn--ghost', () => finish(null)),
      modalButton(okLabel, 'btn--primary', () => finish(input.value)),
    )
    setTimeout(() => input.focus(), 0)
  })
}

async function editConfig(c) {
  let raw
  try { raw = await invoke('cc_get_raw', { id: c.id }) } catch (e) { toast(errorText(e)); return }
  const next = await textDialog({ title: t('Edit config'), value: raw ?? '', area: true, okLabel: t('Save') })
  if (next === null) return
  await withPassword((password) => invoke('cc_edit', { id: c.id, raw: next, password }))
}

async function renameConfig(c) {
  const next = await textDialog({ title: t('Rename'), value: c.name, okLabel: t('Save') })
  if (next === null || !next.trim()) return
  adopt(await invoke('cc_rename', { id: c.id, name: next }))
}

async function copyLink(c) {
  try {
    const raw = await invoke('cc_get_raw', { id: c.id })
    await navigator.clipboard.writeText(raw ?? '')
    toast(t('Copied'))
  } catch (e) {
    toast(errorText(e))
  }
}

async function deleteConfig(c) {
  const ok = await confirmModal({
    title: t('Delete this config?'),
    body: c.name,
    ok: t('Delete'),
    cancel: t('Cancel'),
    danger: true,
  })
  if (ok) adopt(await invoke('cc_delete', { id: c.id }))
}

async function deleteAll() {
  const ok = await confirmModal({
    title: t('Delete all configs?'),
    body: t('Every imported config is removed from this PC. This cannot be undone.'),
    ok: t('Delete all'),
    cancel: t('Cancel'),
    danger: true,
  })
  if (ok) adopt(await invoke('cc_delete_all'))
}

// ------------------------------------------------------------- menus (1.4.0-r5)
//
//  همان برگه‌های a3/a4/a5/a6 موبایل: کارتِ مدال با دکمه‌های تمام‌عرضِ گرد و
//  «انصراف» در پایین. فقط لایهٔ رابط است؛ همهٔ فرمان‌ها همان `invoke`های قبلی‌اند.

function menuButton(label, kind, fn, modal) {
  const b = document.createElement('button')
  b.type = 'button'
  b.className = `mbtn ${kind}`.trim()
  b.textContent = label
  b.addEventListener('click', () => { modal.close(); fn() })
  return b
}

function menuModal({ title, hint = null, items, cancelLabel = t('Cancel') }) {
  const m = openModal({ title, onEscape: () => m.close() })
  m.root.classList.add('chat__modal--menu')
  m.root.addEventListener('mousedown', (ev) => { if (ev.target === m.root) m.close() })
  const list = document.createElement('div')
  list.className = 'mlist'
  for (const it of items) list.append(menuButton(it.label, it.kind || '', it.fn, m))
  m.body.append(list)
  m.actions.append(modalButton(cancelLabel, 'btn--ghost', () => m.close()))
  return m
}

function openServerMenu(c, pick) {
  const items = [
    { label: t('Use this config'), fn: pick },
    { label: t('Test ping'), fn: () => pingOne(c) },
    // اسکن IP تمیز فقط برای همین سرور (شناسهٔ صریح؛ نه پیش‌فرضِ «همه»). قفل/منقضی را Rust رد می‌کند.
    ...(c.locked || c.expired ? [] : [{ label: t('Scan / change clean IP'), fn: () => startScan([c.id]) }]),
    { label: t('Download / upload speed test'), fn: () => speedOne(c) },
    { label: t('Move to tab'), fn: () => moveConfig(c) },
  ]
  if (!c.locked) items.push({ label: t('Edit'), fn: () => editConfig(c) })
  items.push({ label: t('Rename'), fn: () => renameConfig(c) })
  if (c.shareable) items.push({ label: t('Copy link'), fn: () => copyLink(c) })
  items.push({ label: t('Delete'), kind: 'is-danger', fn: () => deleteConfig(c) })
  const shown = cleanServerName(c.name, c.name)
  return menuModal({ title: serverLine(c, ''), items })
}

function openSubscriptionSources() {
  const m=openModal({title:t('Subscription sources'),onEscape:()=>m.close()})
  for(const sub of CC.subscriptions) {
    const row=document.createElement('div');row.className='presets__row'
    const name=document.createElement('span');name.className='presets__name';name.textContent=sub.name;name.title=sub.name
    row.append(name,modalButton(t('Refresh'),'btn--ghost',async()=>{
      m.close();await withPassword(password=>invoke('cc_subscription_refresh',{id:sub.id,password}))
    }),modalButton(t('Delete'),'btn--danger',async()=>{
      m.close()
      if(await confirmModal({title:t('Delete'),body:t('This tab and all its configs will be permanently deleted. All cannot be deleted.'),ok:t('Delete'),cancel:t('Cancel'),danger:true})) {
        try {adopt(await invoke('cc_subscription_delete',{id:sub.id}))}catch(e){toast(errorText(e))}
      }
    }));m.body.append(row)
  }
  m.actions.append(modalButton(t('Cancel'),'btn--ghost',()=>m.close()))
}

function openAddMenu({ text, file, qr }) {
  return menuModal({
    title: t('Add config'),
    items: [
      { label: t('Link or text'), fn: text },
      { label: t('Import file'), fn: file },
      { label: t('QR from image'), fn: qr },
      ...(CC.subscriptions.length ? [{ label:t('Subscription sources'), fn:openSubscriptionSources }] : []),
    ],
  })
}

function openTextImport(destination = currentTab.startsWith('user:') ? currentTab : null) {
  const m = openModal({ title: t('Link or text'), onEscape: () => m.close() })
  m.root.classList.add('chat__modal--menu')
  const area = document.createElement('textarea')
  area.className = 'input input--area ltr cc-paste'
  area.dir = 'ltr'
  area.placeholder = t('Paste one or more links, a JSON config or a subscription address')
  area.addEventListener('paste', (ev) => {
    const raw = ev.clipboardData?.getData('text')
    if (typeof raw !== 'string') return
    const clean = stripInvisible(raw)
    if (clean === raw) return
    ev.preventDefault()
    const { selectionStart: a = area.value.length, selectionEnd: b = area.value.length } = area
    area.value = area.value.slice(0, a) + clean + area.value.slice(b)
    area.selectionStart = area.selectionEnd = a + clean.length
  })
  const clip = document.createElement('button')
  clip.type = 'button'
  clip.className = 'mclip'
  clip.innerHTML = `${icon('content_paste', 18)}<span></span>`
  clip.querySelector('span').textContent = t('Paste from clipboard')
  clip.addEventListener('click', async () => {
    try {
      const txt = stripInvisible(await navigator.clipboard.readText())
      if (txt.trim()) area.value = txt
      else toast(t('Clipboard is empty.'))
    } catch (_) { toast(t('Could not read the clipboard — paste with Ctrl+V.')); area.focus() }
  })
  m.body.append(area, clip)
  const ok = modalButton(t('Import now'), 'btn--primary', async () => {
    const txt = stripInvisible(area.value).trim()
    if (!txt) { toast(t('Paste a link or config first.')); return }
    ok.disabled = true
    const done = await importText(txt, destination)
    ok.disabled = false
    if (done) m.close()
  })
  m.actions.append(modalButton(t('Cancel'), 'btn--ghost', () => m.close()), ok)
  setTimeout(() => area.focus(), 0)
  return m
}

/** Deletion is confirmed and cascades on the authoritative sealed store. */
async function deleteTab(g) {
  if (g.id === 'all') return
  if (await confirmModal({ title: t('Delete tab'), body: t('This tab and all its configs will be permanently deleted. All cannot be deleted.'), ok: t('Delete'), cancel: t('Cancel'), danger: true })) {
    try { adopt(await invoke('cc_tab_delete', { id: g.id })) } catch (e) { toast(errorText(e)) }
  }
}

/** Named, format and subscription tabs share the same actions. */
async function editTab(g, addConfig) {
  const deletable = g.id !== 'all'
  const m = openModal({ title: t('Edit tab'), onEscape: () => m.close() })
  m.root.classList.add('chat__modal--menu')
  const label = document.createElement('label')
  label.className = 'mfield'
  const cap = document.createElement('span')
  cap.textContent = t('Name')
  const input = document.createElement('input')
  input.className = 'input'
  input.value = g.name
  input.maxLength = 40
  label.append(cap, input)
  m.body.append(label)
  const save = async () => {
    const name = input.value.trim()
    if (!name) return
    m.close()
    try { adopt(await invoke('cc_tab_save', { id: g.id, name })) } catch (e) { toast(errorText(e)) }
  }
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); save() } })
  m.actions.append(modalButton(t('Add config'), 'btn--ghost', () => { m.close(); addConfig(g.id) }))
  if (deletable) {
    m.actions.append(modalButton(t('Delete'), 'btn--danger', async () => {
      m.close()
      await deleteTab(g)
    }))
  }
  if (String(g.id).startsWith('sub:')) {
    m.actions.append(modalButton(t('Refresh'), 'btn--ghost', async () => {
      m.close()
      await withPassword(password => invoke('cc_subscription_refresh', { id: g.id, password }))
    }))
  }
  m.actions.append(modalButton(t('Cancel'), 'btn--ghost', () => m.close()), modalButton(t('Save'), 'btn--primary', save))
  setTimeout(() => { input.focus(); input.select() }, 0)
}

// Horizontal strip: native touch, mouse drag, and vertical-wheel translation.
export function wireTabScroll(tabs) {
  let drag = null, suppressClick = false
  tabs.addEventListener('pointerdown', e => {
    if (e.pointerType !== 'mouse' || e.button !== 0) return
    suppressClick = false
    drag = { id:e.pointerId, x:e.clientX, scroll:tabs.scrollLeft, moved:false }
  })
  tabs.addEventListener('pointermove', e => {
    if (!drag || drag.id !== e.pointerId || !(e.buttons & 1)) return
    const delta = e.clientX - drag.x
    if (!drag.moved && Math.abs(delta) < 6) return
    if (!drag.moved) { drag.moved = true; tabs.setPointerCapture(e.pointerId); tabs.classList.add('is-dragging') }
    tabs.scrollLeft = drag.scroll - delta
    e.preventDefault()
  })
  const finish = e => {
    if (!drag || drag.id !== e.pointerId) return
    suppressClick = drag.moved
    drag = null; tabs.classList.remove('is-dragging')
    if (tabs.hasPointerCapture(e.pointerId)) tabs.releasePointerCapture(e.pointerId)
  }
  tabs.addEventListener('pointerup', finish)
  tabs.addEventListener('pointercancel', finish)
  tabs.addEventListener('lostpointercapture', finish)
  tabs.addEventListener('click', e => {
    if (suppressClick) { e.preventDefault(); e.stopImmediatePropagation(); suppressClick = false }
  }, true)
  tabs.addEventListener('wheel', e => {
    if (e.ctrlKey || e.shiftKey || Math.abs(e.deltaX) > Math.abs(e.deltaY) || !e.deltaY) return
    const before = tabs.scrollLeft
    const rtl = getComputedStyle(tabs).direction === 'rtl'
    const delta = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? tabs.clientWidth : 1)
    tabs.scrollLeft += rtl ? -delta : delta
    if (tabs.scrollLeft !== before) e.preventDefault()
  }, { passive:false })
  tabs.addEventListener('focusin', e => e.target.closest('.cc-tab')?.scrollIntoView({ block:'nearest', inline:'nearest' }))
}

// ------------------------------------------------------------- render

const ROUTE_ICON =
  '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="6" r="2.2"/><path d="M8.2 18H15a3 3 0 0 0 0-6H9a3 3 0 0 1 0-6h6.8"/></svg>'
const CHEV_ICON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg>'
const CHECK_ICON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>'

/** «Config» عمومی (پیش از انتخابِ کانفیگ) ترجمه می‌شود؛ نامِ پروتکل‌ها (VLESS، Npvt…) در هر دو زبان انگلیسی می‌مانند. */
function chainText(label) {
  return String(label ?? '').replace(/\bConfig\b/g, t('Config'))
}

/** زیرنویسِ هر زنجیره — `hopsLabel` موبایل. */
function hopsText(hops) {
  if (hops === 1) return t('Single · the config alone')
  return hops === 2 ? t('Double chain') : t('Triple chain')
}

function expiryText(c) {
  if (!c.expiresAt) return ''
  const d = new Date(c.expiresAt)
  const when = d.toLocaleDateString(getLang() === 'fa' ? 'fa-IR' : 'en-GB', { year: 'numeric', month: 'short', day: 'numeric' })
  return c.expired ? t('Expired on {0}').replace('{0}', when) : t('Expires on {0}').replace('{0}', when)
}

/** پیشرفت/نتیجهٔ اسکنِ IP تمیز زیر یک ردیف (درجا؛ ردیف‌ها بازسازی نمی‌شوند). */
function paintScanLine(row, line) {
  const box = row.querySelector('.ccfg__scan')
  if (!box) return
  box.hidden = !line
  if (!line) return
  box.dataset.kind = line.kind
  box.dataset.outcome = line.outcome || ''
  box.querySelector('.ccfg__scanbar').hidden = line.kind !== 'live'
  box.querySelector('.ccfg__scanfill').style.width = `${line.kind === 'live' ? line.percent : 0}%`
  box.querySelector('.ccfg__scantext').textContent = line.text
}

function configRow(c, activeId, index = 0, sid = '') {
  const row = document.createElement('div')
  row.className = `ccfg ${c.id === activeId ? 'is-active' : ''} ${c.expired ? 'is-expired' : ''}`.trim()
  row.dataset.id=c.id
  row.setAttribute('role', 'radio')
  row.setAttribute('aria-checked', String(c.id === activeId))
  row.tabIndex = 0
  const ping = PING.get(c.id)
  const badges = [
    `<span class="ccfg__badge ltr" dir="ltr">${esc(c.chainLabel)}</span>`,
    ping ? `<span class="ccfg__ping ${pingClass(ping)}" dir="auto">${esc(pingText(ping))}</span>` : '',
    c.locked ? `<span class="ccfg__badge ccfg__badge--lock">${esc(t('Locked'))}</span>` : '',
    c.expired ? `<span class="ccfg__badge ccfg__badge--bad">${esc(t('Expired'))}</span>` : '',
  ].join('')
  const port = c.locked ? '' : (c.server.match(/:(\d+)$/)?.[1] || '')
  const pingChip = ping
    ? `<span class="ccfg__chip ccfg__ping ${pingClass(ping)}" dir="auto">${esc(pingText(ping))}</span>`
    : '<span class="ccfg__chip ccfg__ping is-muted" aria-hidden="true">–</span>'
  const canScan = !(c.locked || c.expired)
  row.innerHTML = `
    <span class="ccfg__top">
      <span class="ccfg__dot ccfg__num" aria-hidden="true">${index + 1}</span>
      ${pingChip}
      <span class="ccfg__spacer"></span>
      ${canScan ? `<button type="button" class="ccfg__scanbtn" aria-label="${esc(t('Scan clean IP'))}" title="${esc(t('Scan clean IP'))}">${icon('search',20)}</button>` : ''}
      <button type="button" class="ccfg__actions" aria-haspopup="dialog" aria-label="${esc(t('Server actions'))}">${icon('more',20)}</button>
    </span>
    <span class="ccfg__text">
      <span class="ccfg__server ltr" dir="ltr">${esc(serverLine(c, sid))}</span>
      ${c.locked || c.expired ? `<span class="ccfg__meta">${[c.locked ? `<span class="ccfg__badge ccfg__badge--lock">${esc(t('Locked'))}</span>` : '', c.expired ? `<span class="ccfg__badge ccfg__badge--bad">${esc(t('Expired'))}</span>` : ''].join('')}</span>` : ''}
      <span class="ccfg__scan" hidden><span class="ccfg__scanbar"><span class="ccfg__scanfill"></span></span><span class="ccfg__scantext"></span></span>
      ${SPEED.has(c.id) ? `<span class="ccfg__speed ltr${SPEED.get(c.id).running ? ' is-running' : ''}" dir="auto">${esc(speedText(SPEED.get(c.id)))}</span>` : ''}
      ${c.expiresAt ? `<span class="ccfg__note">${esc(expiryText(c))}</span>` : ''}
    </span>`
  paintScanLine(row, scanLineFor(c.id))
  const pick = async () => { adopt(await invoke('cc_select', { id: c.id })) }
  row.querySelector('.ccfg__actions').addEventListener('click', (ev) => { ev.stopPropagation(); openServerMenu(c, pick) })
  row.querySelector('.ccfg__actions').addEventListener('keydown', (ev) => { ev.stopPropagation() })
  const sb = row.querySelector('.ccfg__scanbtn')
  if (sb) {
    sb.addEventListener('click', (ev) => { ev.stopPropagation(); startScan([c.id]) })
    sb.addEventListener('keydown', (ev) => { ev.stopPropagation() })
  }
  row.addEventListener('click', pick)
  row.addEventListener('keydown', (ev) => {
    if (ev.target === row && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); pick() }
  })
  return row
}

const SPEED_ICON = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4.2 17a9 9 0 1 1 15.6 0"/><path d="M12 13l4-4"/><circle cx="12" cy="13" r="1.2" fill="currentColor"/></svg>'

/** ۱.۴.۰-ui: همان گزینه‌های موبایل ۱.۶.۰ — ۶۰، ۱۸۰، ۳۰۰، ۶۰۰، ۱۸۰۰، ۳۶۰۰ ثانیه
 *  (هسته ۳۰ تا ۳۶۰۰ را می‌پذیرد؛ مقدار ذخیره‌شدهٔ خارج از فهرست هم نشان داده می‌شود). */
const HEALTH_CHOICES = [60, 180, 300, 600, 1800, 3600]
function healthOptions() {
  const cur = app.profile?.customHealthSecs
  return Number.isFinite(cur) && cur >= 30 && cur <= 3600 && !HEALTH_CHOICES.includes(cur)
    ? [...HEALTH_CHOICES, cur].sort((x, y) => x - y)
    : HEALTH_CHOICES
}
export function healthText(sec) {
  if (sec >= 3600 && sec % 3600 === 0) return `${sec / 3600} ${t('h')}`
  if (sec % 60 === 0) return `${sec / 60} ${t('min')}`
  return `${sec} ${t('s')}`
}

/** کلِ پنل؛ `settings.js` آن را در زیرصفحهٔ عمومی می‌نشاند. */
export function renderCustomConfigs() {
  wireOnce()
  const root = document.createElement('div')
  root.className = 'view view--advanced view--custom'

  root.innerHTML = `
    <div class="scard-group">
      <div class="sethub__card scard scard--fields">
        <section class="field field--row">
          <div>
            <span class="field__label">${esc(t('Use a custom config'))}</span>
            <span class="field__hint cc-enable-hint"></span>
          </div>
          <button type="button" class="switch cc-enable" role="switch" aria-checked="false"><span class="switch__knob"></span></button>
        </section>
        <section class="field field--pick cc-chainpick">
          <div class="pick cc-pick" role="button" tabindex="0" aria-haspopup="dialog">
            <span class="pick__icon">${ROUTE_ICON}</span>
            <span class="pick__text">
              <span class="field__label">${esc(t('Chain'))}</span>
            </span>
            <span class="pick__value cc-pick__value"><span class="pick__value-text cc-chain ltr" dir="ltr"></span><span class="cc-pick__hops"></span></span>
            <span class="pick__chev">${CHEV_ICON}</span>
          </div>
          <p class="field__hint pick__summary cc-chain__summary">${esc(t('Where the config sits in the route. Config first: the engine dials out through it. Config last: it dials out through the engine. Changes apply at the next connection.'))}</p>
          <div class="sheet cc-sheet" hidden>
            <div class="sheet__scrim"></div>
            <div class="sheet__panel" role="dialog" aria-modal="true" aria-label="${esc(t('Chain'))}">
              <span class="sheet__handle" aria-hidden="true"></span>
              <h3 class="sheet__title">${esc(t('Chain'))}</h3>
              <div class="seg seg--sheet seg--chain cc-modes" role="radiogroup"></div>
            </div>
          </div>
        </section>
      </div>
    </div>

    <div class="scard-group"><div class="sethub__card scard scard--fields">
      <section class="field field--row">
        <div>
          <span class="field__label">${esc(t('Verify connection'))}</span>
          <span class="field__hint">${esc(t('Only skips the initial check; core startup and health monitoring stay enabled.'))}</span>
        </div>
        <button class="switch cc-verify ${app.profile?.customVerifyConnection!==false?'is-on':''}" role="switch" aria-checked="${app.profile?.customVerifyConnection!==false}"><span class="switch__knob"></span></button>
      </section>
      <section class="field field--row"><div><span class="field__label">${esc(t('Sort servers by ping'))}</span><span class="field__hint">${esc(t('Off keeps the original order of the tab.'))}</span></div><button class="switch cc-sort ${sortByPing()?'is-on':''}" role="switch" aria-checked="${sortByPing()}"><span class="switch__knob"></span></button></section>
      <section class="field field--row"><span class="field__label">${esc(t('Auto-select lowest delay'))}</span><button class="switch cc-auto ${app.profile?.customAutoSelect?'is-on':''}" role="switch" aria-checked="${!!app.profile?.customAutoSelect}"><span class="switch__knob"></span></button></section>
      <section class="field field--row cc-health-card">
        <span class="cc-health__icon" aria-hidden="true">${SPEED_ICON}</span>
        <label class="field__label cc-health__label" for="cc-health">${esc(t('Health interval'))}</label>
        <span class="cc-health__chip ltr" dir="ltr"><span class="cc-health__chip-text"></span><select id="cc-health" class="cc-health" aria-label="${esc(t('Health interval'))}">${healthOptions().map((sec)=>`<option value="${sec}" ${sec===(app.profile?.customHealthSecs??300)?'selected':''}>${esc(healthText(sec))}</option>`).join('')}</select></span>
      </section>
    </div></div>
    <input type="file" class="cc-qr-input" accept="image/png,image/jpeg,image/webp" hidden>
    <input type="file" class="cc-file-input" accept="${FILE_ACCEPT}" multiple hidden>

    <div class="scard-group">
      <div class="cc-top">
        <div class="cc-top__row">
          <div class="cc-ping-card">
            <button type="button" class="cc-ping-all" title="${esc(t('Real delay: a request through each config'))}">
              <span class="cc-ping-all__icon" aria-hidden="true">${SPEED_ICON}</span>
              <span class="cc-ping-all__copy"><span class="cc-ping-all__title">${esc(t('Test all'))}</span></span>
            </button>
          </div>
          <button type="button" class="cc-add">${icon('add',18)}${esc(t('Add config'))}</button>
        </div>
        <button type="button" class="cc-scan-tab">${esc(t('Scan tab'))}</button>
      </div>
      <div class="cc-tabs-bar">
        <button type="button" class="cc-new-tab" aria-label="${esc(t('New tab'))}" title="${esc(t('New tab'))}">${icon('add',22)}</button>
        <div class="cc-tabs" role="tablist" aria-label="${esc(t('Config tabs'))}"></div>
      </div>
      <div class="cc-table-scroll"><div class="sethub__card scard cc-list"></div></div>
    </div>

    <div class="scard-group cc-danger-group">
      <div class="sethub__card sethub__card--danger">
        <div class="setrow setrow--danger cc-delete-all" role="button" tabindex="0">
          <span class="setrow__icon"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12h10l1-12M9 7V4h6v3"/></svg></span>
          <span class="setrow__text"><span class="setrow__title">${esc(t('Delete all configs'))}</span><span class="setrow__sub">${esc(t('Removes every imported config from this PC.'))}</span></span>
        </div>
      </div>
    </div>`

  wireTabScroll(root.querySelector('.cc-tabs'))
  const sw = root.querySelector('.cc-enable')
  const swHint = root.querySelector('.cc-enable-hint')
  const pickRow = root.querySelector('.cc-pick')
  const sheet = root.querySelector('.cc-sheet')
  const modesBox = root.querySelector('.cc-modes')
  const chain = root.querySelector('.cc-chain')
  const chainHops = root.querySelector('.cc-pick__hops')
  let modesSig = ''
  const list = root.querySelector('.cc-list')
  let paintScanUi = null // تعریفش پایین‌تر است (به tabIds/scanTabBtn نیاز دارد)
  const danger = root.querySelector('.cc-danger-group')
  const pingAllBtn = root.querySelector('.cc-ping-all')
  const pingCard = root.querySelector('.cc-ping-card')
  const healthSel = root.querySelector('.cc-health')
  const healthChip = root.querySelector('.cc-health__chip-text')
  healthChip.textContent = healthText(Number(healthSel.value))
  const fileInput = root.querySelector('.cc-file-input')
  const qrInput = root.querySelector('.cc-qr-input')
  let fileDestination = null, qrDestination = null
  // «افزودن کانفیگ» → برگهٔ انتخاب روش (a4 موبایل، بدونِ اسکنِ دوربین).
  const openForTab = (id = currentTab) => {
    setTab(id)
    const destination = id.startsWith('user:') ? id : null
    sync()
    openAddMenu({
      text: () => openTextImport(destination),
      file: () => { fileDestination=destination; fileInput.click() },
      qr: () => { qrDestination=destination; qrInput.click() },
    })
  }
  root.querySelector('.cc-add').addEventListener('click', () => openForTab())

  const sync = () => {
    const has = !!CC.activeId
    sw.classList.toggle('is-on', !!CC.enabled)
    sw.setAttribute('aria-checked', String(!!CC.enabled))
    sw.disabled = !has && !CC.enabled
    swHint.textContent = has
      ? t('Off: Aether runs exactly as before. On: the next connection runs the chain below.')
      : t('Import a config first, then pick it in the list.')
    // برچسبِ هر زنجیره نامِ پروتکلِ کانفیگِ انتخاب‌شده را دارد (`VLESS → Tor`،
    // `Npvt → Aether`) — همان `chainLabel` موبایل. فقط وقتی هنوز کانفیگی انتخاب
    // نشده، Rust واژهٔ عمومیِ «Config» را می‌فرستد که ترجمه می‌شود.
    const sig = `${getLang()}|${CC.mode}|${CC.modes.map((m) => `${m.id}=${m.label}`).join(',')}`
    if (sig !== modesSig) {
      modesSig = sig
      modesBox.innerHTML = CC.modes.map((m) => {
        const on = m.id === CC.mode
        return `<button type="button" role="radio" class="seg__item cc-opt ${on ? 'is-active' : ''}" data-value="${esc(m.id)}" aria-checked="${on}">
            <span class="seg__text"><span class="cc-opt__title ltr" dir="ltr">${esc(chainText(m.label))}</span><span class="cc-opt__sub">${esc(hopsText(m.hops))}</span></span>
            <span class="seg__check">${CHECK_ICON}</span>
          </button>`
      }).join('')
    }
    const current = CC.modes.find((m) => m.id === CC.mode)
    chain.textContent = chainText(CC.modeLabel || current?.label || '')
    chainHops.textContent = current ? hopsText(current.hops) : ''
    const tabs=catalogTabs()
    if(CCLoaded && !tabs.some((g)=>g.id===currentTab)) setTab('all')
    const tabBox=root.querySelector('.cc-tabs');const tabScroll=tabBox.scrollLeft;tabBox.replaceChildren()
    for(const g of tabs){
      const wrap=document.createElement('span');wrap.className='cc-tab'
      const pick=document.createElement('button');pick.type='button';pick.className='btn btn--small cc-tab__pick';pick.setAttribute('role','tab');pick.setAttribute('aria-selected',String(currentTab===g.id));pick.innerHTML=`<span class="cc-tab__count">${g.count}</span><span class="cc-tab__name"></span>`;pick.querySelector('.cc-tab__name').textContent=g.name
      pick.onclick=()=>{setTab(g.id);sync()};wrap.append(pick)
      // آیکون مداد → مدالِ «ویرایش تب» (a6 موبایل). تبِ پیش‌فرض «همه» دکمهٔ حذف ندارد.
      const pen=document.createElement('button');pen.type='button';pen.className='btn btn--small cc-tab-edit__btn';pen.innerHTML=icon('edit',18);pen.setAttribute('aria-label',t('Edit tab'));pen.title=t('Edit tab')
      pen.onclick=(e)=>{e.stopPropagation();editTab(g, openForTab)}
      wrap.classList.toggle('is-active', currentTab === g.id)
      wrap.append(pen)
      tabBox.append(wrap)
    }
    tabBox.scrollLeft=tabScroll
    const visible=catalogRows(CC.configs,currentTab,PING,CC.subscriptions,sortByPing())
    const sids=assignServerIds(currentTab,catalogRows(CC.configs,currentTab,PING,CC.subscriptions,false).map((c)=>c.id))
    list.replaceChildren(...(visible.length
      ? visible.map((c, i) => configRow(c, CC.activeId, i, sids[c.id]))
      : [Object.assign(document.createElement('p'), { className: 'cc-empty', textContent: t('No configs yet.') })]))
    if (paintScanUi) paintScanUi()
    danger.hidden = CC.configs.length === 0
    pingAllBtn.hidden = CC.configs.length === 0
    pingCard.hidden = CC.configs.length === 0
    pingAllBtn.disabled = pingAllBusy
    pingAllBtn.querySelector('.cc-ping-all__title').textContent = pingAllBusy ? t('Testing…') : t('Test all')
  }
  // صفحه‌ای که کاربر از آن بیرون رفته (از DOM جدا شده) دیگر گوش نمی‌دهد.
  const unwatch = onCustomConfigs(() => {
    if (!root.isConnected) { unwatch(); return }
    sync()
  })

  root.querySelector('.cc-auto').onclick=async()=>{const on=!app.profile?.customAutoSelect;await saveProfile({customAutoSelect:on});root.querySelector('.cc-auto').classList.toggle('is-on',on);root.querySelector('.cc-auto').setAttribute('aria-checked',String(on))}
  healthSel.onchange=(e)=>{healthChip.textContent=healthText(Number(e.target.value));saveProfile({customHealthSecs:Number(e.target.value)})}
  root.querySelector('.cc-sort').onclick=()=>{const on=!sortByPing();setSortByPing(on);const b=root.querySelector('.cc-sort');b.classList.toggle('is-on',on);b.setAttribute('aria-checked',String(on));sync()}
  root.querySelector('.cc-new-tab').onclick=()=>saveTab()
  // اسکن IP تمیزِ تبِ فعلی: شناسهٔ سرورهای همین تب صریحاً فرستاده می‌شود (نه همهٔ کانفیگ‌ها).
  const scanTabBtn = root.querySelector('.cc-scan-tab')
  const tabIds = () => catalogRows(CC.configs, currentTab, PING, CC.subscriptions, false).map((c) => c.id)
  // پاپ‌آپ نتیجه (معادل CleanIpScanResultCard موبایل): قدیمی‌ترین نتیجهٔ ردنشده پایین صفحه می‌ماند تا کاربر ببندد.
  const resultCard = document.createElement('div')
  resultCard.className = 'cc-scan-result'
  resultCard.setAttribute('role', 'status')
  resultCard.hidden = true
  resultCard.innerHTML = '<span class="cc-scan-result__text ltr" dir="ltr"></span><span class="cc-scan-result__note"></span><button type="button" class="cc-scan-result__close"></button>'
  const resultClose = resultCard.querySelector('.cc-scan-result__close')
  resultClose.innerHTML = icon('close', 18)
  resultClose.setAttribute('aria-label', t('Dismiss'))
  root.append(resultCard)
  const paintResult = (s) => {
    const r = (s.results || [])[0]
    resultCard.hidden = !r
    if (!r) return
    const cfg = CC.configs.find((c) => c.id === r.id)
    const label = cfg ? cleanServerName(cfg.name, cfg.chainLabel || cfg.name) : String(r.protocol || '')
    resultCard.dataset.outcome = String(r.outcome || '')
    resultCard.dataset.id = r.id
    resultCard.querySelector('.cc-scan-result__text').textContent = r.outcome === 'applied' && r.next
      ? `${label}: ${r.previous ? `${r.previous} → ` : ''}${r.next} · ${r.pingMs} ms`
      : label
    const note = { applied: 'Clean IP applied', unchanged: 'Not better than current', cancelled: 'Cancelled', failed: 'Failed' }[r.outcome] || 'Failed'
    resultCard.querySelector('.cc-scan-result__note').textContent = t(note)
  }
  resultClose.onclick = () => dismissScanResult(resultCard.dataset.id || null)
  paintScanUi = () => {
    const s = scanState()
    paintResult(s)
    scanTabBtn.textContent = s.running ? `${t('Stop')} · ${groupProgressText(s)}` : t('Scan tab')
    scanTabBtn.disabled = !s.running && tabIds().length === 0
    for (const row of list.querySelectorAll('.ccfg[data-id]')) paintScanLine(row, scanLineFor(row.dataset.id, s))
  }
  scanTabBtn.onclick = () => { if (scanState().running) stopScan(); else startScan(tabIds()) }
  onScan(paintScanUi, root)
  root.querySelector('.cc-verify').onclick=async(e)=>{
    const on=app.profile?.customVerifyConnection===false
    await saveProfile({customVerifyConnection:on})
    root.querySelector('.cc-verify').setAttribute('aria-checked',String(on))
    root.querySelector('.cc-verify').classList.toggle('is-on',on)
  }
  sw.addEventListener('click', async () => {
    adopt(await invoke('cc_set_enabled', { enabled: !CC.enabled }))
  })
  // برگهٔ پایینیِ «زنجیره» — همان `SettingsChoiceRow` موبایل (a4): کارت‌های گرد،
  // عنوانِ زنجیره + زیرنویسِ تکی/دوتایی/سه‌تایی، انتخاب‌شده با قابِ آبی و تیک.
  const sheetKeys = (e) => {
    const items = [...modesBox.querySelectorAll('.seg__item')]
    if (e.key === 'Escape') { e.preventDefault(); closeSheet(); pickRow.focus() }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const at = items.indexOf(document.activeElement)
      const next = at === -1 ? 0 : (at + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length
      items[next]?.focus()
    }
  }
  const openSheet = () => {
    if (!sheet.hidden) return
    sheet.hidden = false
    requestAnimationFrame(() => sheet.classList.add('is-open'))
    document.addEventListener('keydown', sheetKeys, true)
    const items = [...modesBox.querySelectorAll('.seg__item')]
    ;(items.find((i) => i.classList.contains('is-active')) ?? items[0])?.focus()
  }
  function closeSheet() {
    if (sheet.hidden) return
    sheet.classList.remove('is-open')
    sheet.hidden = true
    document.removeEventListener('keydown', sheetKeys, true)
  }
  pickRow.addEventListener('click', openSheet)
  pickRow.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openSheet() }
  })
  sheet.querySelector('.sheet__scrim').addEventListener('click', closeSheet)
  modesBox.addEventListener('click', async (e) => {
    const item = e.target.closest('.seg__item')
    if (!item || !modesBox.contains(item)) return
    closeSheet()
    pickRow.focus()
    if (item.dataset.value !== CC.mode) adopt(await invoke('cc_set_mode', { mode: item.dataset.value }))
  })
  pingAllBtn.addEventListener('click', pingAll)
  qrInput.onchange=async()=>{for(const f of qrInput.files??[])await importQr(f,qrDestination);qrInput.value=''}
  fileInput.addEventListener('change', async () => {
    await importFiles([...(fileInput.files ?? [])],fileDestination)
    fileInput.value = ''
  })
  const delAll = root.querySelector('.cc-delete-all')
  delAll.addEventListener('click', deleteAll)
  delAll.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); deleteAll() }
  })

  sync()
  // پس از نشستنِ پنل در DOM (همین تیک) نمای تازه از Rust می‌آید.
  setTimeout(refreshCustomConfigs, 0)
  return root
}
