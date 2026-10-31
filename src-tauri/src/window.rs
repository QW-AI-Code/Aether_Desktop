//! هندسهٔ پنجره: به یاد آوردن، و جا دادنِ آن در نمایشگرِ واقعی.
//!
//! دو ایرادِ جدا در یک جا حل می‌شوند، چون یک ریشه دارند — برنامه هیچ‌وقت
//! نمی‌پرسید «این پنجره کجا و چقدر بود؟»:
//!
//! ۱. اندازهٔ دستیِ کاربر با بستنِ برنامه از دست می‌رفت و هر بار پنجره به
//!    ۱۱۸۰×۷۸۰ برمی‌گشت.
//! ۲. همان ۱۱۸۰×۷۸۰ روی نمایشگرِ ۱۳۶۶×۷۶۸ از صفحه بیرون می‌زد: ارتفاعِ
//!    پیش‌فرض از خودِ صفحه بلندتر بود، پس نوارِ پایینِ پنجره — و با
//!    `decorations: false` تنها راهِ تغییرِ اندازه — زیرِ لبهٔ صفحه می‌ماند.
//!
//! این فایل عمداً **هیچ چیزی از tauri وارد نمی‌کند**: ورودی‌اش دو مستطیل است و
//! خروجی‌اش یک مستطیل. چسبِ پنجره در `main.rs` است. به این شکل همین منطق در
//! هارنسِ آزمون اجرا می‌شود، همان فایلی که تحویل می‌رود.
//!
//! واحدها **منطقی** (logical) هستند و نه فیزیکی: اگر کاربر پنجره را روی
//! نمایشگرِ ۱۰۰٪ تنظیم کند و بعد آن را روی نمایشگرِ ۱۵۰٪ باز کند، پنجره باید
//! همان‌قدر *بزرگ به نظر برسد*، نه اینکه ۱٫۵ برابر شود.

use serde::{Deserialize, Serialize};

/// کمینه‌ای که `tauri.conf.json` هم اعلام می‌کند (`minWidth`/`minHeight`).
///
/// این‌جا تکرار شده چون این منطق پیش از ساختِ پنجره اجرا می‌شود و آن فایل JSON
/// در همین لحظه در دسترسِ کد نیست. `verify-package.sh` هر دو را با هم می‌سنجد،
/// تا این دو عدد بی‌صدا از هم جدا نشوند.
pub const MIN_W: u32 = 360;
pub const MIN_H: u32 = 720;

/// یک مستطیل در واحدِ منطقی.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn new(x: i32, y: i32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }

    fn right(&self) -> i32 {
        self.x.saturating_add(self.w as i32)
    }

    fn bottom(&self) -> i32 {
        self.y.saturating_add(self.h as i32)
    }

    /// آیا این مستطیل با آن مستطیل هم‌پوشانی دارد؟
    fn overlaps(&self, other: &Rect) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }
}

/// چیزی که میانِ اجراها ذخیره می‌شود.
///
/// `maximized` جدا نگه داشته می‌شود، چون پنجرهٔ بیشینه‌شده اندازهٔ *خودش* را هم
/// دارد: کاربری که بیشینه را لغو می‌کند باید پنجرهٔ قبلی‌اش را ببیند و نه یک
/// پنجرهٔ به‌اندازهٔ صفحه.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Geometry {
    #[serde(flatten)]
    pub rect: Rect,
    #[serde(default)]
    pub maximized: bool,
}

/// کلیدِ ذخیره در `prefs.json` (همان‌جایی که زبان و مدلِ هوش مصنوعی می‌نشینند).
pub const PREFS_KEY: &str = "windowGeometryMobile";

pub fn encode(g: &Geometry) -> String {
    serde_json::to_string(g).unwrap_or_default()
}

/// خواندنِ هندسهٔ ذخیره‌شده. هر ورودیِ خراب یعنی «چیزی ذخیره نشده».
///
/// یک اندازهٔ صفرْ خراب است: پنجره‌ای با عرضِ صفر روی ویندوز باز می‌شود و دیده
/// نمی‌شود، و کاربر فکر می‌کند برنامه اجرا نشد.
pub fn decode(raw: &str) -> Option<Geometry> {
    let g: Geometry = serde_json::from_str(raw).ok()?;
    if g.rect.w == 0 || g.rect.h == 0 {
        return None;
    }
    Some(g)
}

/// اندازه و جای پنجره، با توجه به آنچه ذخیره شده و آنچه صفحه اجازه می‌دهد.
///
/// `work` ناحیهٔ کارِ نمایشگر است — یعنی صفحه **منهای** نوار وظیفه. استفاده از
/// کلِ صفحه به‌جای آن، پنجره را دقیقاً به‌اندازهٔ نوار وظیفه بلندتر می‌کرد و
/// همان ایرادِ اولیه را در ابعادِ کوچک‌تر تکرار می‌کرد.
pub fn place(saved: Option<Geometry>, work: Rect, default_w: u32, default_h: u32) -> Geometry {
    let maximized = saved.map(|g| g.maximized).unwrap_or(false);
    let (mut w, mut h) = match saved {
        Some(g) => (g.rect.w, g.rect.h),
        None => (default_w, default_h),
    };

    // هرگز بزرگ‌تر از ناحیهٔ کار. این تنها قدمی است که ایرادِ «۷۸۰ روی صفحهٔ
    // ۷۶۸» را می‌بندد، و برای پنجرهٔ ذخیره‌شده هم لازم است: کاربر ممکن است
    // برنامه را روی نمایشگرِ بزرگ‌تری بسته و اکنون روی لپ‌تاپ باز کند.
    w = w.min(work.w);
    h = h.min(work.h);
    // و هرگز کوچک‌تر از کمینه — مگر آنکه خودِ صفحه از کمینه کوچک‌تر باشد، که
    // در آن حالت اندازهٔ صفحه از یک پنجرهٔ بیرون‌زده بهتر است.
    w = w.max(MIN_W.min(work.w));
    h = h.max(MIN_H.min(work.h));

    let centered = Rect::new(
        work.x + ((work.w.saturating_sub(w)) / 2) as i32,
        work.y + ((work.h.saturating_sub(h)) / 2) as i32,
        w,
        h,
    );

    let Some(g) = saved else {
        return Geometry {
            rect: centered,
            maximized: false,
        };
    };

    // جای ذخیره‌شده تنها وقتی معنا دارد که پنجره واقعاً روی همین ناحیه دیده
    // شود. نمایشگرِ دومی که جدا شده، یا صفحه‌ای که رزولوشنش عوض شده، پنجره را
    // جایی می‌گذارد که کاربر هیچ‌وقت پیدایش نمی‌کند — و برنامه‌ای که «اجرا شد و
    // پیدا نیست» از برنامه‌ای که اجرا نشد بدتر است.
    let wanted = Rect::new(g.rect.x, g.rect.y, w, h);
    if !wanted.overlaps(&work) {
        return Geometry {
            rect: centered,
            maximized,
        };
    }
    // داخلِ ناحیه کشیده می‌شود تا نوارِ عنوان و لبهٔ تغییرِ اندازه در دسترس
    // بمانند (پنجره `decorations: false` است و نوارِ خودش را دارد).
    let x = wanted
        .x
        .max(work.x)
        .min(work.x + (work.w.saturating_sub(w)) as i32);
    let y = wanted
        .y
        .max(work.y)
        .min(work.y + (work.h.saturating_sub(h)) as i32);
    Geometry {
        rect: Rect::new(x, y, w, h),
        maximized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ناحیهٔ کارِ یک لپ‌تاپِ ۱۳۶۶×۷۶۸ با نوار وظیفهٔ ۴۸ پیکسلی.
    fn small_screen() -> Rect {
        Rect::new(0, 0, 1366, 720)
    }

    fn big_screen() -> Rect {
        Rect::new(0, 0, 2560, 1400)
    }

    #[test]
    fn the_default_size_never_exceeds_the_work_area() {
        // همان ایرادِ گزارش‌شده: ۱۱۸۰×۷۸۰ روی صفحهٔ کوچک.
        let g = place(None, small_screen(), 1180, 780);
        assert!(g.rect.w <= 1366 && g.rect.h <= 720, "{:?}", g.rect);
        assert_eq!(g.rect.h, 720, "ارتفاع باید تا لبهٔ ناحیهٔ کار کوتاه شود");
    }

    #[test]
    fn on_a_big_screen_the_default_is_left_alone() {
        let g = place(None, big_screen(), 1180, 780);
        assert_eq!((g.rect.w, g.rect.h), (1180, 780));
    }

    #[test]
    fn a_window_with_no_saved_geometry_is_centred() {
        let g = place(None, big_screen(), 1180, 780);
        assert_eq!(g.rect.x, (2560 - 1180) / 2);
        assert_eq!(g.rect.y, (1400 - 780) / 2);
    }

    #[test]
    fn the_users_own_size_survives() {
        let saved = Geometry {
            rect: Rect::new(100, 80, 1000, 760),
            maximized: false,
        };
        let g = place(Some(saved), big_screen(), 1180, 780);
        assert_eq!(g.rect, Rect::new(100, 80, 1000, 760));
    }

    #[test]
    fn a_saved_size_from_a_bigger_screen_is_shrunk_not_dropped() {
        let saved = Geometry {
            rect: Rect::new(0, 0, 2400, 1300),
            maximized: false,
        };
        let g = place(Some(saved), small_screen(), 1180, 780);
        assert_eq!((g.rect.w, g.rect.h), (1366, 720));
    }

    #[test]
    fn a_window_saved_on_a_monitor_that_is_gone_comes_back_centred() {
        // نمایشگرِ دوم در x=2560 بود و جدا شده.
        let saved = Geometry {
            rect: Rect::new(3000, 200, 1000, 700),
            maximized: false,
        };
        let g = place(Some(saved), big_screen(), 1180, 780);
        assert_eq!(g.rect.x, (2560 - 1000) / 2, "{:?}", g.rect);
    }

    #[test]
    fn a_window_hanging_off_the_right_edge_is_pulled_back_in() {
        let saved = Geometry {
            rect: Rect::new(1300, 600, 1000, 700),
            maximized: false,
        };
        let g = place(Some(saved), big_screen(), 1180, 780);
        assert!(g.rect.x + 1000 <= 2560, "{:?}", g.rect);
        assert!(g.rect.y + 700 <= 1400, "{:?}", g.rect);
    }

    #[test]
    fn nothing_smaller_than_the_declared_minimum() {
        let saved = Geometry {
            rect: Rect::new(0, 0, 300, 200),
            maximized: false,
        };
        let g = place(Some(saved), big_screen(), 1180, 780);
        assert_eq!((g.rect.w, g.rect.h), (MIN_W, MIN_H));
    }

    #[test]
    fn a_screen_smaller_than_the_minimum_wins_over_the_minimum() {
        // ۸۰۰×۶۰۰ کمتر از کمینهٔ اعلام‌شده است. پنجره‌ای که از صفحه بزند بدتر
        // از پنجره‌ای است که از کمینه کوچک‌تر باشد.
        let tiny = Rect::new(0, 0, 800, 560);
        let g = place(None, tiny, 1180, 780);
        assert_eq!((g.rect.w, g.rect.h), (800, 560));
    }

    #[test]
    fn the_maximized_flag_survives_but_the_restored_size_stays_underneath() {
        let saved = Geometry {
            rect: Rect::new(100, 80, 1000, 760),
            maximized: true,
        };
        let g = place(Some(saved), big_screen(), 1180, 780);
        assert!(g.maximized);
        assert_eq!(g.rect, Rect::new(100, 80, 1000, 760));
    }

    #[test]
    fn a_work_area_not_starting_at_zero_is_respected() {
        // نوار وظیفه در بالا/چپ، یا نمایشگرِ دوم به‌عنوان نمایشگرِ فعلی.
        let work = Rect::new(2560, 100, 1920, 1000);
        let g = place(None, work, 1180, 780);
        assert!(g.rect.x >= 2560 && g.rect.y >= 100, "{:?}", g.rect);
        assert!(g.rect.x + g.rect.w as i32 <= 2560 + 1920);
    }

    #[test]
    fn round_trips_through_prefs() {
        let g = Geometry {
            rect: Rect::new(12, 34, 1000, 700),
            maximized: true,
        };
        assert_eq!(decode(&encode(&g)), Some(g));
    }

    #[test]
    fn a_corrupt_or_zero_entry_is_treated_as_nothing_saved() {
        assert_eq!(decode("not json"), None);
        assert_eq!(decode("{}"), None);
        assert_eq!(
            decode(r#"{"x":0,"y":0,"w":0,"h":700,"maximized":false}"#),
            None
        );
    }

    #[test]
    fn an_older_entry_without_the_maximized_field_still_loads() {
        let g = decode(r#"{"x":10,"y":20,"w":1000,"h":700}"#).expect("should load");
        assert!(!g.maximized);
        assert_eq!(g.rect.w, 1000);
    }
}
