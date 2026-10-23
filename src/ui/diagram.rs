//! Схемы «кто кого спрашивает»: узлы с состоянием и стрелки между ними.
//! Состояние узла передаётся значком и словами, а не только цветом.

use super::*;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum NodeState {
    Ok,
    Warn,
    Bad,
    Neutral,
}

pub(super) struct Node {
    pub title: String,
    pub detail: String,
    pub state: NodeState,
}

impl Node {
    pub fn new(title: impl Into<String>, detail: impl Into<String>, state: NodeState) -> Self {
        Self { title: title.into(), detail: detail.into(), state }
    }
}

const ARROW_GAP: f32 = 30.0;
const MIN_NODE: f32 = 110.0;
const PAD: f32 = 12.0;

/// Цепочка узлов слева направо; на узком окне — сверху вниз.
pub(super) fn chain(ui: &mut egui::Ui, p: &Palette, nodes: &[Node]) {
    if nodes.is_empty() {
        return;
    }
    let width = ui.available_width();
    let n = nodes.len() as f32;
    let horizontal = width >= n * MIN_NODE + (n - 1.0) * ARROW_GAP;
    let node_w = if horizontal { (width - (n - 1.0) * ARROW_GAP) / n } else { width };

    let body = TextStyle::Body.resolve(ui.style());
    let small = TextStyle::Small.resolve(ui.style());
    let title_font = egui::FontId::new(body.size, semibold());
    let text_w = node_w - 2.0 * PAD;
    let laid: Vec<_> = nodes
        .iter()
        .map(|nd| {
            let t = ui.painter().layout(nd.title.clone(), title_font.clone(), p.text, text_w - 26.0);
            let d = ui.painter().layout(nd.detail.clone(), small.clone(), p.text_weak, text_w);
            (t, d)
        })
        .collect();
    let node_h = laid
        .iter()
        .map(|(t, d)| PAD + t.size().y.max(20.0) + 4.0 + d.size().y + PAD)
        .fold(0.0_f32, f32::max);

    let total = if horizontal {
        Vec2::new(width, node_h)
    } else {
        Vec2::new(width, n * node_h + (n - 1.0) * ARROW_GAP * 0.8)
    };
    let (rect, resp) = ui.allocate_exact_size(total, Sense::hover());
    let label = nodes.iter().map(|nd| format!("{}: {}", nd.title, nd.detail)).collect::<Vec<_>>().join(" → ");
    resp.widget_info(|| WidgetInfo::labeled(Role::Image, true, &label));

    let painter = ui.painter();
    for (i, (nd, (t, d))) in nodes.iter().zip(laid).enumerate() {
        let min = if horizontal {
            pos2(rect.left() + i as f32 * (node_w + ARROW_GAP), rect.top())
        } else {
            pos2(rect.left(), rect.top() + i as f32 * (node_h + ARROW_GAP * 0.8))
        };
        let r = Rect::from_min_size(min, Vec2::new(node_w, node_h));
        let (fill, stroke) = node_colors(p, nd.state);
        painter.rect(r, CornerRadius::same(8), fill, Stroke::new(1.0, stroke), StrokeKind::Inside);
        let icon_c = pos2(r.left() + PAD + 9.0, r.top() + PAD + 10.0);
        state_icon(painter, p, icon_c, 9.0, nd.state);
        painter.galley(pos2(r.left() + PAD + 26.0, r.top() + PAD + (20.0 - t.size().y).max(0.0) / 2.0), t.clone(), p.text);
        painter.galley(pos2(r.left() + PAD, r.top() + PAD + t.size().y.max(20.0) + 4.0), d, p.text_weak);

        if i + 1 < nodes.len() {
            if horizontal {
                let y = r.center().y;
                arrow(painter, p, pos2(r.right() + 5.0, y), pos2(r.right() + ARROW_GAP - 5.0, y));
            } else {
                let x = r.center().x;
                arrow(painter, p, pos2(x, r.bottom() + 4.0), pos2(x, r.bottom() + ARROW_GAP * 0.8 - 4.0));
            }
        }
    }
}

fn node_colors(p: &Palette, state: NodeState) -> (Color32, Color32) {
    match state {
        NodeState::Ok => (p.surface, p.success_text),
        NodeState::Warn => (p.surface, p.warn_text),
        NodeState::Bad => (p.surface, p.danger_text),
        NodeState::Neutral => (p.surface, p.border_strong),
    }
}

fn arrow(painter: &egui::Painter, p: &Palette, from: egui::Pos2, to: egui::Pos2) {
    let stroke = Stroke::new(1.6, p.text_weak);
    painter.line_segment([from, to], stroke);
    let dir = (to - from).normalized();
    let side = Vec2::new(-dir.y, dir.x);
    let head = 6.0;
    painter.line_segment([to, to - dir * head + side * head * 0.6], stroke);
    painter.line_segment([to, to - dir * head - side * head * 0.6], stroke);
}

/// Значок состояния: галочка, крест, восклицательный знак или точка.
pub(super) fn state_icon(painter: &egui::Painter, p: &Palette, c: egui::Pos2, r: f32, state: NodeState) {
    let k = r / 9.0;
    match state {
        NodeState::Ok => {
            painter.circle_filled(c, r, p.success_text);
            let s = Stroke::new(2.0 * k, p.surface);
            painter.line_segment([c + Vec2::new(-4.0, 0.5) * k, c + Vec2::new(-1.2, 3.3) * k], s);
            painter.line_segment([c + Vec2::new(-1.2, 3.3) * k, c + Vec2::new(4.5, -3.0) * k], s);
        }
        NodeState::Bad => {
            painter.circle_filled(c, r, p.danger_text);
            let s = Stroke::new(2.0 * k, p.surface);
            painter.line_segment([c + Vec2::new(-3.5, -3.5) * k, c + Vec2::new(3.5, 3.5) * k], s);
            painter.line_segment([c + Vec2::new(3.5, -3.5) * k, c + Vec2::new(-3.5, 3.5) * k], s);
        }
        NodeState::Warn => {
            painter.circle_filled(c, r, p.warn_text);
            let s = Stroke::new(2.0 * k, p.surface);
            painter.line_segment([c + Vec2::new(0.0, -4.5) * k, c + Vec2::new(0.0, 1.0) * k], s);
            painter.circle_filled(c + Vec2::new(0.0, 4.0) * k, 1.2 * k, p.surface);
        }
        NodeState::Neutral => {
            painter.circle_stroke(c, r - 1.0, Stroke::new(1.5, p.border_strong));
            painter.circle_filled(c, 2.5 * k, p.border_strong);
        }
    }
}

// ---------- «Как это работает» ----------

impl DnsApp {
    pub(super) fn help_view(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        ui.horizontal(|ui| {
            if ui.button("Назад").clicked() {
                self.view = View::Main;
            }
            ui.label(RichText::new("Как это работает").family(semibold()).size(20.0));
        });
        ui.add_space(12.0);
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
          centered(ui, 900.0, |ui| {
            let section = |ui: &mut egui::Ui, title: &str, text: &str, nodes: &[Node]| {
                card(p).inner_margin(Margin::same(18)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(title).family(semibold()).size(17.0));
                    ui.add_space(6.0);
                    ui.add(egui::Label::new(RichText::new(text).color(p.text_weak)).wrap());
                    if !nodes.is_empty() {
                        ui.add_space(12.0);
                        chain(ui, p, nodes);
                    }
                });
                ui.add_space(14.0);
            };

            section(
                ui,
                "Что такое DNS",
                "Когда вы набираете адрес сайта, компьютер сначала спрашивает у DNS-сервера, где этот сайт \
                 находится, и получает в ответ его адрес в интернете. Это как телефонная книга: имя → номер.",
                &[
                    Node::new("Вы", "набираете chatgpt.com", NodeState::Neutral),
                    Node::new("DNS-сервер", "отвечает, где сайт", NodeState::Neutral),
                    Node::new("Адрес сайта", "например 104.18.32.47", NodeState::Neutral),
                    Node::new("Браузер", "открывает сайт по адресу", NodeState::Neutral),
                ],
            );
            section(
                ui,
                "Почему ИИ-сервисы не открываются",
                "ChatGPT, Gemini, Claude и другие сервисы видят, из какой страны пришёл запрос, и не \
                 обслуживают Россию. Обычный DNS даёт настоящий адрес, и сервис сразу видит, откуда вы.",
                &[
                    Node::new("Ваш компьютер", "в России", NodeState::Neutral),
                    Node::new("Обычный DNS", "провайдер, Google, Cloudflare", NodeState::Neutral),
                    Node::new("Настоящий адрес", "сервиса", NodeState::Neutral),
                    Node::new("Сервис", "«недоступно в вашей стране»", NodeState::Bad),
                ],
            );
            section(
                ui,
                "Как помогает DNS для обхода",
                "Специальный DNS (GeoHide, MagicDNS, dns-ai и другие) на адреса ИИ-сервисов отвечает адресом \
                 своего прокси за границей. Браузер идёт к прокси, а тот передаёт запрос дальше. Сервис видит \
                 Европу и открывается. Ваши данные по-прежнему зашифрованы: прокси передаёт их, не читая. \
                 Остальные сайты открываются напрямую, как обычно. Это не VPN.",
                &[
                    Node::new("Ваш компьютер", "спрашивает адрес", NodeState::Neutral),
                    Node::new("DNS для обхода", "отвечает адресом прокси", NodeState::Ok),
                    Node::new("Прокси", "за границей", NodeState::Ok),
                    Node::new("Сервис", "открывается", NodeState::Ok),
                ],
            );
            section(
                ui,
                "Защита от сбоев",
                "Такие DNS иногда перестают отвечать. Программа регулярно проверяет выбранный сервер вплоть \
                 до самих сервисов. Если он сломался, а интернет есть, она сама включает лучший из остальных \
                 и возвращает ваш, когда тот снова заработает. Вдобавок в Windows прописаны запасные Cloudflare \
                 и Google: даже если все серверы упали, интернет не пропадёт (ИИ-сервисы в это время могут \
                 не открываться).",
                &[
                    Node::new("Выбранный сервер", "перестал отвечать", NodeState::Bad),
                    Node::new("Программа", "проверяет остальные", NodeState::Neutral),
                    Node::new("Лучший резервный", "включается сам", NodeState::Ok),
                    Node::new("Ваш сервер ожил", "программа вернёт его", NodeState::Ok),
                ],
            );
            section(
                ui,
                "Браузер со своим DNS",
                "Chrome, Edge, Яндекс Браузер и Firefox умеют спрашивать DNS сами, мимо Windows. Тогда \
                 программа на них не влияет, и обход в таком браузере не работает. Программа это находит и \
                 предлагает исправить: браузер начнёт пользоваться DNS Windows, а шифрование запросов \
                 возьмёт на себя Windows.",
                &[
                    Node::new("Браузер", "свой защищённый DNS", NodeState::Warn),
                    Node::new("Windows и программа", "не участвуют", NodeState::Neutral),
                    Node::new("Сервис", "может не открыться", NodeState::Bad),
                ],
            );

            card(p).inner_margin(Margin::same(18)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Что значат состояния серверов").family(semibold()).size(17.0));
                ui.add_space(8.0);
                let rows = [
                    ("работает", "DNS отвечает быстро, сервисы открываются через все прокси.", NodeState::Ok),
                    ("часть прокси не отвечает", "Сервисы открываются, но иногда может понадобиться обновить страницу.", NodeState::Warn),
                    ("медленно", "DNS отвечает дольше 1,5 с: Windows не дождётся и пойдёт к запасным Cloudflare и Google.", NodeState::Warn),
                    ("… не открывается", "Сервер не подменяет адрес этого сервиса или его прокси не работает.", NodeState::Bad),
                    ("не отвечает", "DNS-сервер недоступен.", NodeState::Bad),
                ];
                for (word, text, state) in rows {
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                        state_icon(ui.painter(), p, r.center(), 8.0, state);
                        ui.label(RichText::new(word).family(semibold()));
                        ui.add(egui::Label::new(RichText::new(text).color(p.text_weak)).wrap());
                    });
                    ui.add_space(4.0);
                }
            });
            ui.add_space(14.0);

            card(p).inner_margin(Margin::same(18)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Частые вопросы").family(semibold()).size(17.0));
                ui.add_space(8.0);
                let faq = [
                    (
                        "Это VPN?",
                        "Нет. Через прокси идут только адреса ИИ-сервисов, всё остальное открывается напрямую.",
                    ),
                    (
                        "Почему программа просит права администратора?",
                        "Настройки DNS в Windows меняются только с правами администратора.",
                    ),
                    (
                        "Сервис всё равно не открывается",
                        "Нажмите «Проверить сейчас»: программа покажет, на каком шаге цепочки проблема. Если всё \
                         зелёное, а сервис пишет про страну, обновите страницу или войдите в аккаунт заново: \
                         некоторые сервисы запоминают страну в аккаунте.",
                    ),
                    (
                        "Как вернуть всё как было?",
                        "Кнопка «Вернуть как было» включает DNS от роутера или провайдера, как до установки.",
                    ),
                ];
                for (q, a) in faq {
                    ui.label(RichText::new(q).family(semibold()));
                    ui.add(egui::Label::new(RichText::new(a).color(p.text_weak)).wrap());
                    ui.add_space(8.0);
                }
            });
            ui.add_space(8.0);
          });
        });
    }
}

/// Колонка шириной не больше `max`, по центру окна.
pub(super) fn centered(ui: &mut egui::Ui, max: f32, add: impl FnOnce(&mut egui::Ui)) {
    let width = ui.available_width().min(max);
    let pad = ((ui.available_width() - width) / 2.0).max(0.0);
    ui.horizontal(|ui| {
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.set_width(width);
            add(ui);
        });
    });
}
