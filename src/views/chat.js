// =============================================================================
//  src/views/chat.js — صفحهٔ گفت‌وگو با جمینای
//  پورت از ui/ai/AiChatScreen.kt (Compose → DOM)
// =============================================================================
//
//  # چرا این یک صفحهٔ مستقل است و نه یک بخش در صفحهٔ دستیار
//
//  در a2 «هر چه می‌خواهید بپرسید» یک کارتِ فشرده پایینِ صفحهٔ تنظیماتِ دستیار
//  بود: یک لاگِ ۲۲۰ پیکسلی زیر کلید API و انتخابگرِ مدل. در موبایل چت یک مقصدِ
//  ناوبریِ تمام‌صفحه است، و دلیلش ساده است — گفت‌وگو تنها چیزی در این برنامه است
//  که *رشد می‌کند*. یک لاگِ اسکرول‌شونده داخل صفحه‌ای که خودش اسکرول می‌شود، دو
//  اسکرولِ تودرتو می‌سازد و کاربر همیشه اشتباهی آن بیرونی را می‌چرخاند.
//
//  # مالکیت حالت
//
//  تاریخِ گفت‌وگو **در Rust** است (`ai_session.rs`) و اینجا فقط رندر می‌شود.
//  چیزهایی که اینجا حالتِ محلی‌اند فقط سه چیزِ گذرا هستند: انتخاب برای حذف،
//  پیامی که در حال ویرایش است، و متنی که در جعبهٔ ورودی تایپ شده. هیچ‌کدام پس از
//  بستنِ برنامه معنا ندارند و نگه‌داشتنشان در Rust یعنی یک IPC برای هر تیک.

import { t, getLang, tAiError } from '../i18n.js'
import {
  ai,
  onAiChange,
  gateMessage,
  failureText,
  sendChat,
  retryMessage,
  editMessage,
  deleteMessages,
  stopChat,
  clearChat,
  applyChanges,
} from '../ai.js'
import { consumeQueuedQuestion } from '../ui/nav.js'
import { renderMarkdown, plainText } from '../ui/markdown.js'
import { toast } from '../ui/toast.js'

/** چهار پرسشِ آماده روی صفحهٔ خالی — همان چهارتای `ai_chat_suggest_*` موبایل. */
const SUGGESTIONS = [
  'Why is my connection slow right now?',
  'Which protocol should I use on mobile data?',
  'Explain MTU and pick the best one for me',
  'Make the tunnel harder to detect',
]

const ICON = {
  copy:
    '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    '<rect x="9" y="9" width="11" height="12" rx="2"/><path d="M15 5.5H6a1.5 1.5 0 0 0-1.5 1.5v10"/></svg>',
  edit:
    '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M4 20h4L20 8l-4-4L4 16z"/><path d="M14.5 5.5 18.5 9.5"/></svg>',
  trash:
    '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M5 7h14M10 7V4.8h4V7M7 7l1 13h8l1-13"/></svg>',
  retry:
    '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 4.5V10h-5.4"/></svg>',
  check:
    '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M5 12.5 9.5 17 19 7"/></svg>',
}

function iconButton(kind, label, onClick) {
  const btn = document.createElement('button')
  btn.type = 'button'
  btn.className = 'chat__act'
  btn.innerHTML = ICON[kind]
  btn.setAttribute('aria-label', label)
  btn.title = label
  btn.addEventListener('click', (event) => {
    event.stopPropagation()
    onClick()
  })
  return btn
}

/**
 * متن را در کلیپ‌بورد می‌گذارد.
 *
 * `navigator.clipboard` در WebView2 روی یک صفحهٔ بی‌فوکوس رد می‌شود، پس شکست
 * بی‌صدا نمی‌ماند: کاربری که «کپی» زده و هیچ چیز ندیده، فرض می‌کند کپی شده و
 * بعد یک کلیپ‌بوردِ خالی را جای پاسخ می‌چسباند.
 */
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    toast(t('Copied'))
  } catch {
    toast(t('Could not copy — your system refused clipboard access.'))
  }
}

// --------------------------------------------------------------- حباب‌ها

/**
 * یک نوبتِ گفت‌وگو.
 *
 * @param {object} message نوبت، همان‌طور که از `ChatMessage` سمت Rust می‌آید.
 * @param {object} ctx کنش‌ها و حالتِ محلیِ صفحه.
 */
function bubble(message, ctx) {
  const wrap = document.createElement('div')
  wrap.className =
    'chat__row' +
    (message.fromUser ? ' is-user' : '') +
    (message.failed ? ' is-failed' : '') +
    (ctx.selection.has(message.id) ? ' is-picked' : '')
  wrap.dataset.id = String(message.id)

  const box = document.createElement('div')
  box.className = 'chat__bubble'

  const body = document.createElement('div')
  body.className = 'chat__text'
  // پاسخ مدل ترجمه‌شده نیست و می‌تواند انگلیسی برگردد، حتی در رابط فارسی: جهت را
  // از محتوای خودش بگیرد.
  body.dir = 'auto'
  if (message.failed) {
    // جملهٔ ترجمه‌شده بالا، متنِ خامِ گوگل زیرش به‌عنوان جزئیات. رجوع به
    // `failureText` در ai.js برای اینکه چرا این ترتیب است.
    const head = document.createElement('div')
    head.className = 'chat__failhead'
    head.textContent = failureText(message.errorKind)
    body.appendChild(head)
    // 1.5.0 (same version): in Persian, Google's raw English text is not shown
    // under the translated sentence (it stays in the diagnostics log).
    const rawEnglish = getLang() === 'fa' && !/[\u0600-\u06FF]/.test(message.text || '')
    if (message.text && message.text.trim() && !rawEnglish) {
      const detail = document.createElement('div')
      detail.className = 'chat__faildetail'
      detail.dir = 'auto'
      detail.textContent = message.text
      body.appendChild(detail)
    }
  } else if (message.fromUser) {
    body.textContent = message.text
  } else {
    // ۱.۴.۰-r4: پاسخِ مدل Markdown است (FORMAT در پرامپت) — رندرِ امن، بدون innerHTML.
    body.classList.add('md')
    renderMarkdown(body, message.text)
  }
  box.appendChild(body)

  if (message.edited) {
    const tag = document.createElement('span')
    tag.className = 'chat__edited'
    tag.textContent = t('edited')
    box.appendChild(tag)
  }

  // کارتِ پیشنهاد زیرِ متن و **بالای** دکمه‌های حباب: بخشی از همان پاسخ است، نه
  // یک کنشِ جدا روی آن.
  if (!message.failed && !message.fromUser && message.changes && message.changes.length) {
    box.appendChild(changesCard(message, ctx))
  }

  const acts = document.createElement('div')
  acts.className = 'chat__acts'
  if (message.failed) {
    // «تلاش مجدد» وقتی درخواستی در پرواز است غیرفعال می‌شود و **حذف نمی‌شود**:
    // دکمه‌ای که جابه‌جا می‌شود، کلیکِ بعدی را به دکمهٔ کناری می‌دهد.
    const again = iconButton('retry', t('Try again'), () => ctx.retry(message.id))
    again.disabled = ai.busy
    again.classList.add('chat__act--accent')
    const label = document.createElement('span')
    label.className = 'chat__actlabel'
    label.textContent = t('Try again')
    acts.append(again, label)
  } else if (message.fromUser) {
    acts.appendChild(iconButton('edit', t('Edit'), () => ctx.edit(message)))
  } else {
    acts.appendChild(iconButton('copy', t('Copy answer'), () => copyText(plainText(message.text))))
  }
  acts.appendChild(iconButton('trash', t('Delete'), () => ctx.remove([message.id])))
  box.appendChild(acts)

  // کلیک روی خودِ حباب در حالتِ انتخاب، تیک می‌زند؛ بیرون از آن حالت هیچ کاری
  // نمی‌کند تا کلیکِ اتفاقی چیزی را انتخاب نکند.
  wrap.addEventListener('click', () => {
    if (!ctx.selection.size) return
    ctx.toggle(message.id)
  })
  // یک فشارِ راست یا دوکلیک حالتِ انتخاب را باز می‌کند — معادلِ long-press موبایل.
  wrap.addEventListener('contextmenu', (event) => {
    event.preventDefault()
    ctx.toggle(message.id)
  })

  wrap.appendChild(box)
  return wrap
}

// ------------------------------------------------------------ گفت‌وگوهای تأیید

/**
 * یک دیالوگِ تأییدِ modal — و نه `window.confirm`.
 *
 * `window.confirm` در WebView2 یک پنجرهٔ سیستمیِ بیگانه است که عنوانِ برنامه را
 * هم غلط نشان می‌دهد، متنش راست‌به‌چپ نمی‌شود و دکمه‌هایش ترجمه‌پذیر نیستند: در
 * یک رابط فارسی، کاربر یک «OK / Cancel» انگلیسی می‌دید. این یکی همان دیالوگِ
 * `chat__modal` خودِ برنامه است، پس فارسی، قابلِ Escape و قابلِ سبک‌دهی است.
 *
 * @param {object} spec `{ title, body, confirm, danger }`
 * @param {Function} onYes فقط وقتی صدا زده می‌شود که کاربر تأیید کند.
 */
function confirmDialog({ title, body, confirm, danger = false }, onYes) {
  const back = document.createElement('div')
  back.className = 'chat__modal'
  const card = document.createElement('div')
  card.className = 'chat__modalcard'
  card.setAttribute('role', 'dialog')
  card.setAttribute('aria-modal', 'true')

  const head = document.createElement('div')
  head.className = 'chat__modaltitle'
  head.textContent = title

  const text = document.createElement('p')
  text.className = 'chat__modalnote'
  text.textContent = body

  const row = document.createElement('div')
  row.className = 'chat__modalrow'
  const no = document.createElement('button')
  no.type = 'button'
  no.className = 'btn btn--ghost'
  no.textContent = t('Cancel')
  const yes = document.createElement('button')
  yes.type = 'button'
  yes.className = danger ? 'btn btn--danger' : 'btn btn--primary'
  yes.textContent = confirm
  row.append(no, yes)

  const close = () => back.remove()
  no.addEventListener('click', close)
  back.addEventListener('click', (event) => {
    if (event.target === back) close()
  })
  back.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') close()
  })
  yes.addEventListener('click', () => {
    close()
    onYes()
  })

  card.append(head, text, row)
  back.appendChild(card)
  // فوکوس روی دکمهٔ **انصراف** و نه تأیید: Enterِ اتفاقی نباید یک گفت‌وگو را پاک
  // کند.
  requestAnimationFrame(() => no.focus())
  return back
}

/**
 * دیالوگِ «برای اتصال بعدی ذخیره شد» — پورت از `AiChangesCard` موبایل.
 *
 * # چرا این یک دیالوگ است و نه یک خط متن
 *
 * در موبایل همین جمله یک خطِ کم‌رنگِ ۱۲sp داخل کارت بود، درست بالای دکمهٔ اعمال،
 * و مهم‌ترین جملهٔ کلِ قابلیت — اینکه چیزی که کاربر همین حالا تأیید کرده هنوز
 * فعال نیست — کم‌دیده‌ترین چیز روی صفحه بود: زدنِ «اعمال» آن را از دیدرس بیرون
 * اسکرول می‌کرد. یک دیالوگ نه اسکرول می‌شود و نه تصادفی رد می‌شود، و روی **زدنِ**
 * دکمه می‌آید، پس به کاری که توضیحش می‌دهد چسبیده است. خطِ داخلِ کارت هم می‌ماند،
 * چون پس از بستنِ دیالوگ باید بشود فهمید چرا کارت «اعمال شد» نشان می‌دهد.
 */
function appliedDialog() {
  const back = document.createElement('div')
  back.className = 'chat__modal'
  const card = document.createElement('div')
  card.className = 'chat__modalcard'
  card.setAttribute('role', 'dialog')
  card.setAttribute('aria-modal', 'true')

  const head = document.createElement('div')
  head.className = 'chat__modaltitle'
  head.textContent = t('Saved for the next connection')

  const text = document.createElement('p')
  text.className = 'chat__modalnote'
  text.textContent = t(
    'The new settings are stored, but the tunnel is already running with the old ones. Tunnel settings are handed to the engine when it starts, so disconnect and connect again for them to take effect.',
  )

  const row = document.createElement('div')
  row.className = 'chat__modalrow'
  const ok = document.createElement('button')
  ok.type = 'button'
  ok.className = 'btn btn--primary'
  ok.textContent = t('Got it')
  row.appendChild(ok)

  const close = () => back.remove()
  ok.addEventListener('click', close)
  back.addEventListener('click', (event) => {
    if (event.target === back) close()
  })
  back.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') close()
  })

  card.append(head, text, row)
  back.appendChild(card)
  requestAnimationFrame(() => ok.focus())
  return back
}

// ------------------------------------------------------- کارتِ تنظیماتِ پیشنهادی

/**
 * پیشنهادِ یک پاسخ را به چیزی تبدیل می‌کند که یک انسان تأییدش می‌کند.
 *
 * هر تغییر به شکلِ `کلید: قدیم → جدید` با دلیلِ خودِ مدل نوشته می‌شود، چون
 * «اعمالِ ۴ تغییر» رضایت نیست. مقادیر از سمت Rust می‌آیند و **از قبل** از نگهبان
 * رد شده‌اند (`vet_changes` در `ai_session.rs`)، پس چیزی که اینجا دکمه دارد، چیزی
 * است که واقعاً می‌نشیند.
 */
function changesCard(message, ctx) {
  const card = document.createElement('div')
  card.className = 'chat__changes'

  const title = document.createElement('div')
  title.className = 'chat__changestitle'
  title.textContent = t('Proposed settings ({0})').replace('{0}', String(message.changes.length))
  card.appendChild(title)

  for (const change of message.changes) {
    const row = document.createElement('div')
    row.className = 'chat__change'
    const line = document.createElement('div')
    line.className = 'chat__changekey'
    // نامِ تنظیم و مقادیرش انگلیسی می‌مانند — همان قاعده‌ای که در پرامپت هم به
    // مدل گفته می‌شود: کاربر باید بتواند همان رشته را در صفحهٔ تنظیمات پیدا کند.
    line.dir = 'ltr'
    line.textContent = `${change.key}: ${change.before} → ${change.value}`
    row.appendChild(line)
    if (change.why && change.why.trim()) {
      const why = document.createElement('div')
      why.className = 'chat__changewhy'
      why.dir = 'auto'
      why.textContent = change.why
      row.appendChild(why)
    }
    card.appendChild(row)
  }

  const note = document.createElement('div')
  note.className = 'chat__changenote'
  note.textContent = t(
    'Tunnel settings are handed to the engine when it starts, so these take effect on your next connect.',
  )
  card.appendChild(note)

  if (message.applied) {
    const done = document.createElement('div')
    done.className = 'chat__applied'
    done.innerHTML = ICON.check
    const label = document.createElement('span')
    label.textContent = t('Applied')
    done.appendChild(label)
    card.appendChild(done)
  } else {
    const row = document.createElement('div')
    row.className = 'chat__changeacts'
    const apply = document.createElement('button')
    apply.type = 'button'
    apply.className = 'btn btn--primary btn--small chat__apply'
    apply.textContent = t('Apply')
    apply.addEventListener('click', (event) => {
      event.stopPropagation()
      ctx.apply(message.id, apply)
    })
    row.appendChild(apply)
    card.appendChild(row)
  }
  return card
}

/** صفحهٔ خالی: معرفی + چهار پرسشِ آماده. */
function emptyState(ctx) {
  const box = document.createElement('div')
  box.className = 'chat__empty'

  const title = document.createElement('div')
  title.className = 'chat__emptytitle'
  title.textContent = t('Hi, I am Aether AI')

  const body = document.createElement('p')
  body.className = 'chat__emptybody'
  body.textContent = t(
    'I can explain any setting in this app, read this session’s log and propose tuning, or just answer a question.',
  )

  const chips = document.createElement('div')
  chips.className = 'chat__chips'
  for (const key of SUGGESTIONS) {
    const chip = document.createElement('button')
    chip.type = 'button'
    chip.className = 'chat__chip'
    chip.textContent = t(key)
    // پرسشِ **ترجمه‌شده** فرستاده می‌شود و نه کلیدِ انگلیسی: کاربر فارسی‌زبان روی
    // جمله‌ای می‌زند که می‌بیند، و همان باید در گفت‌وگو ثبت شود.
    chip.addEventListener('click', () => ctx.send(t(key)))
    chip.disabled = ai.gateCode !== 'READY'
    chips.appendChild(chip)
  }

  box.append(title, body, chips)
  return box
}

// ------------------------------------------------------------ ویرایشگر

/**
 * ویرایشگرِ یک پیامِ فرستاده‌شده.
 *
 * هشدار **پیش از** فرستادن گفته می‌شود و نه پس از آن، چون کاری که می‌کند برگشت
 * ندارد: هر چیزی بعد از این پیام حذف می‌شود.
 */
function editorDialog(message, onSend) {
  const back = document.createElement('div')
  back.className = 'chat__modal'
  const card = document.createElement('div')
  card.className = 'chat__modalcard'
  card.setAttribute('role', 'dialog')
  card.setAttribute('aria-modal', 'true')

  const title = document.createElement('div')
  title.className = 'chat__modaltitle'
  title.textContent = t('Edit message')

  const area = document.createElement('textarea')
  area.className = 'input chat__editor'
  area.rows = 4
  area.dir = 'auto'
  area.value = message.text

  const note = document.createElement('p')
  note.className = 'chat__modalnote'
  note.textContent = t('Everything after this message will be removed and the assistant will answer the edited question.')

  const row = document.createElement('div')
  row.className = 'chat__modalrow'
  const cancel = document.createElement('button')
  cancel.type = 'button'
  cancel.className = 'btn btn--ghost'
  cancel.textContent = t('Cancel')
  const send = document.createElement('button')
  send.type = 'button'
  send.className = 'btn btn--primary'
  send.textContent = t('Send again')
  row.append(cancel, send)

  const close = () => back.remove()
  cancel.addEventListener('click', close)
  back.addEventListener('click', (event) => {
    if (event.target === back) close()
  })
  card.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') close()
  })
  send.addEventListener('click', () => {
    const text = area.value.trim()
    if (!text) return
    close()
    onSend(text)
  })

  card.append(title, area, note, row)
  back.appendChild(card)
  return back
}

// --------------------------------------------------------------- صفحه

export function renderChat() {
  const root = document.createElement('div')
  root.className = 'view view--chat'

  // ---- سرصفحه: عنوان، مدل، و نوارِ انتخاب که جایش را می‌گیرد ----
  const head = document.createElement('div')
  head.className = 'chat__head'
  const heading = document.createElement('div')
  const title = document.createElement('h2')
  title.className = 'view__title'
  title.textContent = t('Chat with Gemini')
  const sub = document.createElement('div')
  sub.className = 'chat__sub'
  heading.append(title, sub)

  const headActs = document.createElement('div')
  headActs.className = 'chat__headacts'
  const wipe = document.createElement('button')
  wipe.type = 'button'
  wipe.className = 'btn btn--ghost'
  wipe.textContent = t('Clear the conversation')
  // پاک‌کردنِ کلِ گفت‌وگو بی‌بازگشت‌ترین کنشِ این صفحه است و تا حالا بی هیچ پرسشی
  // انجام می‌شد.
  wipe.addEventListener('click', () => {
    root.appendChild(
      confirmDialog(
        {
          title: t('Clear the whole conversation?'),
          body: t(
            'This cannot be undone. Deleted messages are no longer sent to the assistant as context.',
          ),
          confirm: t('Clear'),
          danger: true,
        },
        () => clearChat(),
      ),
    )
  })
  headActs.appendChild(wipe)
  head.append(heading, headActs)
  root.appendChild(head)

  /** نوارِ حالتِ انتخاب — همان `TopAppBar`ِ جانشین در موبایل. */
  const pickbar = document.createElement('div')
  pickbar.className = 'chat__pickbar'
  pickbar.hidden = true
  const pickCount = document.createElement('span')
  pickCount.className = 'chat__pickcount'
  const pickAll = document.createElement('button')
  pickAll.type = 'button'
  pickAll.className = 'btn btn--ghost btn--small'
  pickAll.textContent = t('Select all')
  const pickDel = document.createElement('button')
  pickDel.type = 'button'
  pickDel.className = 'btn btn--danger btn--small'
  pickDel.textContent = t('Delete selected')
  const pickCancel = document.createElement('button')
  pickCancel.type = 'button'
  pickCancel.className = 'btn btn--ghost btn--small'
  pickCancel.textContent = t('Cancel selection')
  pickbar.append(pickCount, pickAll, pickDel, pickCancel)
  root.appendChild(pickbar)

  const gate = document.createElement('div')
  gate.className = 'ai__gate'
  root.appendChild(gate)

  const log = document.createElement('div')
  log.className = 'chat__log'
  root.appendChild(log)

  // ---- نویسنده ----
  const form = document.createElement('form')
  form.className = 'chat__composer'
  const input = document.createElement('textarea')
  input.className = 'input chat__input'
  input.rows = 1
  input.dir = 'auto'
  input.placeholder = t('Ask Aether AI…')
  const send = document.createElement('button')
  send.type = 'submit'
  send.className = 'btn btn--primary chat__send'
  send.textContent = t('Send')
  const stop = document.createElement('button')
  stop.type = 'button'
  stop.className = 'btn btn--ghost chat__stop'
  stop.textContent = t('Stop')
  stop.hidden = true
  stop.addEventListener('click', () => stopChat())
  form.append(input, send, stop)
  root.appendChild(form)

  // ---- حالتِ محلی ----
  const selection = new Set()
  let sticky = true // آیا کاربر پایینِ لاگ است؟

  const ctx = {
    selection,
    send: (text) => submit(text),
    retry: (id) => retryMessage(id).catch(() => {}),
    edit: (message) => {
      root.appendChild(
        editorDialog(message, (text) => {
          editMessage(message.id, text).catch(() => {})
        }),
      )
    },
    // حذف **همیشه** از یک تأیید رد می‌شود، چه یک حباب باشد چه بیست.
    //
    // ریشهٔ اشکال: تأیید فقط روی حذفِ گروهی بود، پس آیکونِ سطلِ روی هر حباب یک
    // کلیکِ بی‌بازگشت بود — و گفت‌وگو نه undo دارد، نه سبد بازیافت، نه نسخهٔ
    // سمت سرور. تعداد در خودِ پرسش می‌آید: این تفاوتِ «تأییدِ یک حذف» و «تأییدِ
    // *این* حذف» است.
    remove: (ids) => {
      if (!ids.length) return
      root.appendChild(
        confirmDialog(
          {
            title: t('Delete {0} message(s)?').replace('{0}', String(ids.length)),
            body: t(
              'This cannot be undone. Deleted messages are no longer sent to the assistant as context.',
            ),
            confirm: t('Delete'),
            danger: true,
          },
          () => {
            deleteMessages(ids).catch(() => {})
            for (const id of ids) selection.delete(id)
            sync()
          },
        ),
      )
    },
    /**
     * تنظیماتِ یک حباب را می‌نویسد و بعد پنجرهٔ «قطع و وصل کنید» را باز می‌کند.
     *
     * دیالوگ فقط پس از یک نوشتنِ **موفق** می‌آید. اگر ذخیره شکست بخورد، همان
     * خطا نشان داده می‌شود و نه یک پنجره که می‌گوید «ذخیره شد» — که بدترین شکلِ
     * ممکن است، چون کاربر برای تنظیمی که وجود ندارد قطع و وصل می‌کند.
     */
    apply: (id, button) => {
      if (button) button.disabled = true
      applyChanges(id)
        .then(() => {
          root.appendChild(appliedDialog())
        })
        .catch((error) => {
          if (button) button.disabled = false
          toast(tAiError(error))
        })
    },
    toggle: (id) => {
      if (selection.has(id)) selection.delete(id)
      else selection.add(id)
      sync()
    },
  }

  async function submit(text) {
    const trimmed = String(text ?? '').trim()
    if (!trimmed) return
    try {
      await sendChat(trimmed)
    } catch {
      // شکست حالا خودش یک حبابِ قابلِ «تلاش مجدد» در گفت‌وگو است (رجوع به
      // `dispatch` در ai_session.rs)، پس اینجا چیزی برای نشان‌دادن نمانده.
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault()
    const text = input.value
    input.value = ''
    autoGrow()
    submit(text)
  })
  // Enter می‌فرستد، Shift+Enter خط می‌شکند — همان قرارِ هر جعبهٔ چتی.
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event('submit'))
    }
  })
  function autoGrow() {
    input.style.height = 'auto'
    input.style.height = `${Math.min(input.scrollHeight, 132)}px`
  }
  input.addEventListener('input', autoGrow)

  log.addEventListener('scroll', () => {
    // «چسبیده به پایین» با یک حاشیهٔ ۴۸ پیکسلی سنجیده می‌شود: کاربری که برای
    // خواندنِ یک پاسخِ بلند کمی بالا رفته، نباید با رسیدنِ پاسخِ بعدی به زور
    // پایین کشیده شود.
    sticky = log.scrollHeight - log.scrollTop - log.clientHeight < 48
  })

  pickAll.addEventListener('click', () => {
    for (const m of ai.messages) selection.add(m.id)
    sync()
  })
  pickCancel.addEventListener('click', () => {
    selection.clear()
    sync()
  })
  // تأیید داخل `ctx.remove` است، پس هر دو مسیر — سطلِ روی حباب و حذفِ گروهی —
  // دقیقاً همان یک دیالوگ را می‌گیرند.
  pickDel.addEventListener('click', () => {
    if (!selection.size) return
    ctx.remove([...selection])
  })

  function sync() {
    // شناسه‌هایی که دیگر وجود ندارند از انتخاب پاک می‌شوند، وگرنه «حذف ۳ مورد»
    // پس از یک پاک‌کردن یا ویرایش، روی شناسه‌های مرده کار می‌کرد.
    const live = new Set(ai.messages.map((m) => m.id))
    for (const id of [...selection]) if (!live.has(id)) selection.delete(id)

    log.replaceChildren()
    if (!ai.messages.length) {
      log.appendChild(emptyState(ctx))
    } else {
      for (const message of ai.messages) log.appendChild(bubble(message, ctx))
    }
    if (ai.busy) {
      const pending = document.createElement('div')
      pending.className = 'chat__row'
      pending.innerHTML =
        '<div class="chat__bubble is-pending"><span class="aibubble__spin"></span><span class="chat__thinking"></span></div>'
      pending.querySelector('.chat__thinking').textContent = t('Thinking…')
      log.appendChild(pending)
    }
    if (sticky) log.scrollTop = log.scrollHeight

    const blocked = ai.gateCode !== 'READY'
    const message = gateMessage()
    gate.textContent = message ?? ''
    gate.hidden = !message
    input.disabled = blocked
    send.disabled = blocked || ai.busy
    send.hidden = ai.busy
    stop.hidden = !ai.busy
    wipe.hidden = !ai.messages.length
    sub.textContent = ai.selectedModel
      ? t('Model: {0}').replace('{0}', ai.selectedModel)
      : t('Ask anything, or say what you want changed')

    pickbar.hidden = selection.size === 0
    pickCount.textContent = t('{0} selected').replace('{0}', String(selection.size))
  }

  onAiChange(sync, root)
  sync()

  // پرسشی که از حبابِ ✨ منتقل شده، همان لحظهٔ نمایشِ صفحه فرستاده می‌شود.
  root.__onShow = () => {
    const queued = consumeQueuedQuestion()
    if (queued) submit(queued)
    // فوکوس روی جعبه، تا صفحه‌ای که برای تایپ باز شده منتظرِ یک کلیکِ اضافه نماند.
    if (!input.disabled) input.focus()
  }

  return root
}
