//! Цвета и шрифты в духе Windows 11. Все цвета интерфейса берутся отсюда,
//! светлая и тёмная схемы переключаются вместе с системной темой.
//! Контраст текста проверен: основной и вторичный текст не ниже 4.5:1
//! на фоне окна и карточек, текст на акцентной кнопке не ниже 4.5:1.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, Shadow, Stroke, Theme,
    Visuals,
};
use std::sync::Arc;

pub struct Palette {
    /// Фон окна.
    pub bg: Color32,
    /// Карточки и списки.
    pub surface: Color32,
    pub surface_hover: Color32,
    /// Выбранная строка списка.
    pub surface_selected: Color32,
    /// Декоративные границы и разделители.
    pub border: Color32,
    /// Границы элементов управления (не ниже 3:1 к фону).
    pub border_strong: Color32,
    pub text: Color32,
    pub text_weak: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    /// Фон метки «Обход ограничений ИИ».
    pub accent_soft: Color32,
    /// Текст на `accent_soft` и акцентные надписи.
    pub accent_text: Color32,
    pub danger_fill: Color32,
    pub on_danger: Color32,
    pub danger_text: Color32,
    pub warn_text: Color32,
    pub success_text: Color32,
}

const fn hex(rgb: u32) -> Color32 {
    Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8)
}

pub const LIGHT: Palette = Palette {
    bg: hex(0xF3F3F3),
    surface: hex(0xFFFFFF),
    surface_hover: hex(0xF6F6F6),
    surface_selected: hex(0xE8F1FB),
    border: hex(0xE3E3E3),
    border_strong: hex(0x8A8A8A),
    text: hex(0x1B1B1B),
    text_weak: hex(0x5C5C5C),
    accent: hex(0x005FB8),
    on_accent: hex(0xFFFFFF),
    accent_soft: hex(0xE0EDFA),
    accent_text: hex(0x00508F),
    danger_fill: hex(0xC42B1C),
    on_danger: hex(0xFFFFFF),
    danger_text: hex(0xB3261E),
    warn_text: hex(0x8A5300),
    success_text: hex(0x0E700E),
};

pub const DARK: Palette = Palette {
    bg: hex(0x202020),
    surface: hex(0x2B2B2B),
    surface_hover: hex(0x323232),
    surface_selected: hex(0x1F3447),
    border: hex(0x3B3B3B),
    border_strong: hex(0x8F8F8F),
    text: hex(0xF3F3F3),
    text_weak: hex(0xB4B4B4),
    accent: hex(0x60CDFF),
    on_accent: hex(0x000000),
    accent_soft: hex(0x1B3A52),
    accent_text: hex(0x8FDCFF),
    danger_fill: hex(0xC42B1C),
    on_danger: hex(0xFFFFFF),
    danger_text: hex(0xFF99A4),
    warn_text: hex(0xFCE100),
    success_text: hex(0x6CCB5F),
};

pub fn palette(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode { &DARK } else { &LIGHT }
}

pub const SEMIBOLD: &str = "semibold";

pub fn semibold() -> FontFamily {
    FontFamily::Name(SEMIBOLD.into())
}

pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT, false));
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK, true));
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(12.0, 5.0);
        // Не меньше 24 px по высоте для любой кнопки и флажка.
        style.spacing.interact_size.y = 28.0;
        style.spacing.window_margin = egui::Margin::same(20);
        for (text_style, font) in style.text_styles.iter_mut() {
            font.size = match text_style {
                egui::TextStyle::Heading => 22.0,
                egui::TextStyle::Small => 12.0,
                egui::TextStyle::Monospace => 13.5,
                _ => 14.0,
            };
        }
        if let Some(h) = style.text_styles.get_mut(&egui::TextStyle::Heading) {
            h.family = semibold();
        }
    });
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let fallbacks = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let mut load = |name: &str, file: &str| -> bool {
        match std::fs::read(format!(r"C:\Windows\Fonts\{file}")) {
            Ok(bytes) => {
                fonts.font_data.insert(name.into(), Arc::new(FontData::from_owned(bytes)));
                true
            }
            Err(_) => false,
        }
    };
    let regular = load("segoe", "segoeui.ttf");
    let bold = load("segoe-semibold", "seguisb.ttf");
    let mono = load("consolas", "consola.ttf");

    if regular {
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "segoe".into());
    }
    let mut semi = Vec::new();
    if bold {
        semi.push("segoe-semibold".to_string());
    } else if regular {
        semi.push("segoe".to_string());
    }
    semi.extend(fallbacks);
    fonts.families.insert(semibold(), semi);
    if mono {
        fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "consolas".into());
    }
    ctx.set_fonts(fonts);
}

fn visuals(p: &Palette, dark: bool) -> Visuals {
    let mut v = if dark { Visuals::dark() } else { Visuals::light() };
    let radius = CornerRadius::same(6);

    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(10);
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 28,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 110 } else { 40 }),
    };
    v.faint_bg_color = p.surface;
    v.extreme_bg_color = if dark { hex(0x1C1C1C) } else { p.surface };
    v.override_text_color = None;
    v.weak_text_color = Some(p.text_weak);
    v.hyperlink_color = p.accent_text;
    v.warn_fg_color = p.warn_text;
    v.error_fg_color = p.danger_text;
    v.selection.bg_fill = p.accent;
    v.selection.stroke = Stroke::new(1.5, p.on_accent);

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = radius;

    let control = if dark { hex(0x373737) } else { hex(0xFBFBFB) };
    w.inactive.bg_fill = control;
    w.inactive.weak_bg_fill = control;
    // Рамки флажков и переключателей: не ниже 3:1 к фону карточки.
    w.inactive.bg_stroke = Stroke::new(1.0, if dark { hex(0x7A7A7A) } else { hex(0x8A8A8A) });
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.inactive.corner_radius = radius;

    let hover = if dark { hex(0x3F3F3F) } else { hex(0xF2F2F2) };
    w.hovered.bg_fill = hover;
    w.hovered.weak_bg_fill = hover;
    w.hovered.bg_stroke = Stroke::new(1.0, p.border_strong);
    w.hovered.fg_stroke = Stroke::new(1.5, p.text);
    w.hovered.corner_radius = radius;
    w.hovered.expansion = 0.0;

    let pressed = if dark { hex(0x2F2F2F) } else { hex(0xEAEAEA) };
    w.active.bg_fill = pressed;
    w.active.weak_bg_fill = pressed;
    w.active.bg_stroke = Stroke::new(1.0, p.border_strong);
    w.active.fg_stroke = Stroke::new(1.5, p.text);
    w.active.corner_radius = radius;
    w.active.expansion = 0.0;

    w.open = w.active;
    v
}
