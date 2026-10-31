// =============================================================================
//  src/views/announcements.js — تنظیمات › «پیام‌ها و اطلاعیه‌ها»
//
//  بایگانیِ دائمیِ همهٔ اطلاعیه‌ها. هر ردیف همان پنجرهٔ سرمه‌ایِ «تازه‌ها» را
//  دوباره باز می‌کند (بدون چک‌باکس — آن فقط مالِ پنجرهٔ خودکارِ شروع است).
// =============================================================================

import { t } from '../i18n.js'
import { ANNOUNCEMENTS } from '../news/announcements.js'
import { openWhatsNew } from '../ui/whatsnew.js'
import { openSupportDialog } from '../ui/support.js'

const CHEVRON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg>'
export const MEGAPHONE =
  '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M4 10v4a1 1 0 0 0 1 1h2l6 4V5L7 9H5a1 1 0 0 0-1 1z"/><path d="M16.5 8.5a5 5 0 0 1 0 7"/><path d="M7 15l1.2 4.2"/></svg>'

export function renderAnnouncements() {
  const panel = document.createElement('div')
  panel.className = 'newsarchive'

  const card = document.createElement('div')
  card.className = 'sethub__card'
  for (const item of ANNOUNCEMENTS) {
    const row = document.createElement('div')
    row.className = 'setrow'
    row.tabIndex = 0
    row.setAttribute('role', 'button')
    row.innerHTML =
      `<span class="setrow__icon">${MEGAPHONE}</span>` +
      '<span class="setrow__text" dir="rtl"><span class="setrow__title"></span><span class="setrow__sub"></span></span>' +
      `<span class="setrow__chev">${CHEVRON}</span>`
    row.querySelector('.setrow__title').textContent = item.shortTitle
    // نسخه در یک ایزولهٔ LTR، تا «نسخهٔ 1.4.0» در هر دو زبان درست بنشیند.
    row.querySelector('.setrow__sub').textContent = t('Version {0}').replace('{0}', `\u2066${item.version}\u2069`)
    const open = () => openWhatsNew({ announcement: item, showDontShowAgain: false })
    row.addEventListener('click', open)
    row.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open() }
    })
    card.appendChild(row)
  }
  const sup = document.createElement('div')
  sup.className = 'setrow'
  sup.tabIndex = 0
  sup.setAttribute('role', 'button')
  sup.innerHTML =
    `<span class="setrow__icon">${MEGAPHONE}</span>` +
    '<span class="setrow__text" dir="rtl"><span class="setrow__title">حمایت از سازندهٔ هستهٔ اتر</span><span class="setrow__sub">پیام حمایت از سازندهٔ هسته و کانال تلگرام او</span></span>' +
    `<span class="setrow__chev">${CHEVRON}</span>`
  const openSup = () => openSupportDialog({ showDontShowAgain: false })
  sup.addEventListener('click', openSup)
  sup.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openSup() }
  })
  card.appendChild(sup)
  panel.appendChild(card)

  const foot = document.createElement('p')
  foot.className = 'newsarchive__foot'
  foot.textContent = t('Release notes and guide for the current version.')
  panel.appendChild(foot)
  return panel
}
