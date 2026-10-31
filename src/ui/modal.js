// =============================================================================
//  دیالوگِ ساده — همان کارتِ `chat__modal` صفحهٔ گفت‌وگو، برای بقیهٔ صفحه‌ها.
//
//  عمداً با کلیک بیرونِ کارت بسته نمی‌شود: کدِ یک‌بارمصرف یا رمزی که نیمه‌کاره
//  تایپ شده نباید با یک کلیکِ اشتباه از دست برود (همان `dismissOnClickOutside =
//  false` موبایل). Escape فقط وقتی `onEscape` داده شده کاری می‌کند.
// =============================================================================

/**
 * @param {{ title: string, onEscape?: () => void }} options
 * @returns {{ root: HTMLElement, body: HTMLElement, actions: HTMLElement, setTitle: (s: string) => void, close: () => void }}
 */
export function openModal({ title, onEscape } = {}) {
  const root = document.createElement('div')
  root.className = 'chat__modal'
  root.setAttribute('role', 'dialog')
  root.setAttribute('aria-modal', 'true')
  const card = document.createElement('div')
  card.className = 'chat__modalcard'
  const head = document.createElement('div')
  head.className = 'chat__modaltitle'
  head.textContent = title || ''
  const body = document.createElement('div')
  body.className = 'modal__body'
  const actions = document.createElement('div')
  actions.className = 'chat__modalrow'
  card.append(head, body, actions)
  root.append(card)

  const onKey = (ev) => {
    if (ev.key === 'Escape' && onEscape) {
      ev.preventDefault()
      ev.stopPropagation() // Escape closes the dialog, never the underlying settings page.
      onEscape()
    }
  }
  document.addEventListener('keydown', onKey, true)
  document.body.append(root)

  return {
    root,
    body,
    actions,
    setTitle: (s) => { head.textContent = s },
    close: () => {
      document.removeEventListener('keydown', onKey, true)
      root.remove()
    },
  }
}

/** یک دکمهٔ کوچک برای ردیفِ پایینِ دیالوگ. */
export function modalButton(label, kind = '', onClick = null) {
  const b = document.createElement('button')
  b.type = 'button'
  b.className = `btn btn--small ${kind}`.trim()
  b.textContent = label
  if (onClick) b.addEventListener('click', onClick)
  return b
}

/** یک خطِ توضیح زیرِ عنوان. */
export function modalNote(text, kind = '') {
  const p = document.createElement('p')
  p.className = `chat__modalnote ${kind}`.trim()
  p.textContent = text
  return p
}

/** دیالوگِ تأیید — `true` اگر کاربر دکمهٔ تأیید را زد. */
export function confirmModal({ title, body, ok, cancel, danger = false }) {
  return new Promise((resolve) => {
    let done = false
    const finish = (value) => {
      if (done) return
      done = true
      modal.close()
      resolve(value)
    }
    const modal = openModal({ title, onEscape: () => finish(false) })
    modal.body.append(modalNote(body))
    modal.actions.append(
      modalButton(cancel, 'btn--ghost', () => finish(false)),
      modalButton(ok, danger ? 'btn--danger' : 'btn--primary', () => finish(true)),
    )
  })
}
