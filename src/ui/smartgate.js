// =============================================================================
//  src/ui/smartgate.js — کارتِ «دروازهٔ هوشمند اتصال» (۱.۵.۰، همان نسخه)
//
//  جای کلیدِ قدیمیِ «راستی‌آزمایی اتصال» را در صفحهٔ اتصال و صفحهٔ کانفیگ‌های
//  سفارشی می‌گیرد. فقط اطلاع‌رسانی است و هیچ کنترلی ندارد: دروازهٔ هوشمند برای
//  همهٔ نشست‌ها (Aether، Psiphon، Tor، زنجیره‌ها و کانفیگ‌های سفارشی) همیشه
//  فعال است و «متصل» فقط پس از عبورِ واقعیِ داده از تونل نشان داده می‌شود.
// =============================================================================

const GATE_ICON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="currentColor"/><path d="M12 11v5.5M12 7.6v.1" stroke="#0B111D" stroke-width="2.2" stroke-linecap="round"/></svg>'

export const SMART_GATE_TITLE = 'Smart connection gate'
export const SMART_GATE_TEXT =
  'Always on, nothing to set. Connected is shown only after real data has crossed the tunnel, usually within a second, so a fake connection cannot pass. The old optional verification is gone: it kept MASQUE from connecting and made connects slow.'

/** HTMLِ کارت؛ `t` تابعِ ترجمه است و `esc` (اختیاری) فرارِ HTML. */
export function smartGateCard(t, esc = (s) => s) {
  return `<section class="field field--gate" data-smart-gate="1">
          <div class="gate__row">
            <span class="pick__icon" aria-hidden="true">${GATE_ICON}</span>
            <span class="field__label">${esc(t(SMART_GATE_TITLE))}</span>
          </div>
          <span class="field__hint">${esc(t(SMART_GATE_TEXT))}</span>
        </section>`
}
