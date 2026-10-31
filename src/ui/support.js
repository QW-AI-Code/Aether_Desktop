// =============================================================================
//  src/ui/support.js — پنجرهٔ «حمایت از سازندهٔ هستهٔ اتر» (معادل CreatorSupportDialog)
//
//  همیشه فارسی/راست‌به‌چپ است. یک بار پس از بسته‌شدن پنجرهٔ «تازه‌ها» نشان داده
//  می‌شود، مگر کاربر «دیگر نمایش نده» را زده باشد؛ از آرشیو پیام‌ها هم باز می‌شود.
// =============================================================================

import { open } from '@tauri-apps/plugin-shell'
import creatorUrl from '../creator.png'

export const SUPPORT_URL = 'https://t.me/CluvexStudio/140'
const LS_SUPPRESSED = 'aether.support.suppressed'
const LS_SHOWN = 'aether.support.shown'

const lsGet = (k) => { try { return localStorage.getItem(k) } catch { return null } }
const lsSet = (k, v) => { try { localStorage.setItem(k, v) } catch { /* ignore */ } }

export const supportSuppressed = () => lsGet(LS_SUPPRESSED) === '1'

const CLOSE_ICON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>'
const TG_ICON =
  '<svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true" fill="#2AABEE"><path d="M21.94 4.35c.25-1.02-.38-1.47-1.09-1.2L2.7 10.14c-1.19.46-1.18 1.13-.21 1.42l4.63 1.44 10.75-6.77c.51-.33.97-.15.59.18l-8.7 7.85-.34 4.9c.5 0 .72-.23 1-.5l2.4-2.33 4.98 3.68c.92.51 1.58.25 1.81-.85z"/></svg>'

export function openSupportDialog({ showDontShowAgain = false, onClose = () => {} } = {}) {
  document.querySelector('.news--support')?.remove()
  const root = document.createElement('div')
  root.className = 'news news--support'
  root.setAttribute('role', 'dialog')
  root.setAttribute('aria-modal', 'true')
  root.setAttribute('dir', 'rtl')
  root.setAttribute('lang', 'fa')
  root.innerHTML = `
    <div class="news__card">
      <div class="news__head">
        <div class="news__headtext"><div class="news__title">حمایت از سازندهٔ هستهٔ اتر</div></div>
        <button type="button" class="news__close" aria-label="بستن" title="بستن">${CLOSE_ICON}</button>
      </div>
      <div class="news__body" tabindex="0">
        <div class="support__avatar"><img src="${creatorUrl}" alt="تصویر پروفایل تلگرام سازندهٔ هستهٔ اتر" width="104" height="104"></div>
        <p class="support__text">برای حمایت از سازندهٔ هستهٔ اتر، لطفاً به کانال تلگرام زیر مراجعه کنید:</p>
        <p class="support__text support__warn">لطفاً برای این موضوع هیچ پیامی به <bdi>QW-AI-Code</bdi> ارسال نکنید. <bdi>QW-AI-Code</bdi> فقط توسعه‌دهندهٔ رابط کاربری (<bdi>GUI</bdi>) اتر است و سازندهٔ هستهٔ اتر نیست. برای حمایت و قدردانی از سازندهٔ هسته، مستقیماً به آدرس تلگرام زیر مراجعه کنید.</p>
        <button type="button" class="support__link" dir="ltr">${TG_ICON}<span>${SUPPORT_URL}</span></button>
      </div>
      <div class="news__foot">
        <label class="news__check"${showDontShowAgain ? '' : ' hidden'}>
          <input type="checkbox" class="news__checkbox" />
          <span>دیگر این پیام را نمایش نده</span>
        </label>
        <button type="button" class="news__ok">متوجه شدم</button>
      </div>
    </div>`
  const checkbox = root.querySelector('.news__checkbox')
  let closed = false
  const close = () => {
    if (closed) return
    closed = true
    document.removeEventListener('keydown', onKey, true)
    root.remove()
    const dont = showDontShowAgain && checkbox.checked
    lsSet(LS_SHOWN, '1')
    if (dont) lsSet(LS_SUPPRESSED, '1')
    onClose(dont)
  }
  const onKey = (ev) => {
    if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); close() }
  }
  document.addEventListener('keydown', onKey, true)
  root.querySelector('.news__close').addEventListener('click', close)
  root.querySelector('.news__ok').addEventListener('click', close)
  root.querySelector('.support__link').addEventListener('click', () => { open(SUPPORT_URL).catch(() => {}) })
  document.body.append(root)
  root.querySelector('.news__ok').focus({ preventScroll: true })
  return { root, close }
}
