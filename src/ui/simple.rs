//! Простой режим: одна карточка «что сейчас происходит» со схемой цепочки,
//! крупная кнопка «Подобрать лучший сервер» и минимум слов.

use super::diagram::{Node, NodeState, chain, state_icon};
use super::*;

impl DnsApp {
    /// Сервер, который сейчас стоит на отмеченных подключениях.
    pub(super) fn active_server(&self) -> Option<DnsServer> {
        let mut idx: Vec<usize> = self.servers_in_use().into_iter().collect();
        idx.sort();
        idx.first().map(|&i| self.config.servers[i].clone())
    }

    fn active_health(&self) -> Option<&Health> {
        let s = self.active_server()?;
        match self.health.get(&s.name)? {
            HealthView::Done(h) => Some(h),
            HealthView::Running => None,
        }
    }

    pub(super) fn bypassing_browsers(&self) -> Vec<&browsers::BrowserDns> {
        self.browsers.iter().filter(|b| b.bypasses_windows()).collect()
    }

    fn chain_nodes(&self) -> Vec<Node> {
        let mut nodes = Vec::new();
        let chosen = self.chosen_adapters();
        let up: Vec<&Adapter> = chosen.iter().filter(|a| a.up).collect();
        nodes.push(if up.is_empty() {
            Node::new("Компьютер", "нет подключения к сети", NodeState::Bad)
        } else {
            Node::new("Компьютер", up.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", "), NodeState::Neutral)
        });

        let own = self.bypassing_browsers();
        nodes.push(if !own.is_empty() {
            let names: Vec<&str> = own.iter().map(|b| b.name).collect();
            Node::new("Браузер", format!("{} спрашивает DNS сам, мимо Windows", names.join(", ")), NodeState::Warn)
        } else if self.browsers.is_empty() {
            Node::new("Браузер", "пользуется DNS Windows", NodeState::Neutral)
        } else {
            Node::new("Браузер", "пользуется DNS Windows", NodeState::Ok)
        });

        let Some(active) = self.active_server() else {
            nodes.push(Node::new("DNS для обхода", "не выбран", NodeState::Neutral));
            nodes.push(Node::new("Прокси", "—", NodeState::Neutral));
            nodes.push(Node::new("ИИ-сервисы", "откроются после выбора сервера", NodeState::Neutral));
            return nodes;
        };
        let Some(h) = self.active_health() else {
            nodes.push(Node::new(active.name.clone(), "проверка…", NodeState::Neutral));
            nodes.push(Node::new("Прокси", "проверка…", NodeState::Neutral));
            nodes.push(Node::new("ИИ-сервисы", "проверка…", NodeState::Neutral));
            return nodes;
        };

        let ms = h.best_ms().map(health::seconds).unwrap_or_default();
        let e2e_bad = self.e2e.as_ref().is_some_and(|e| !e.ok());
        nodes.push(match h.grade() {
            Grade::Dead => Node::new(active.name.clone(), "не отвечает", NodeState::Bad),
            Grade::Slow => Node::new(active.name.clone(), format!("отвечает медленно, {ms}"), NodeState::Warn),
            _ if e2e_bad => Node::new(active.name.clone(), "Windows получает ответы не от него", NodeState::Warn),
            _ => Node::new(active.name.clone(), format!("отвечает за {ms}"), NodeState::Ok),
        });

        if !active.ai_bypass || h.services.is_empty() {
            nodes.push(Node::new("Прокси", "не используется: обычный DNS", NodeState::Neutral));
            nodes.push(Node::new("ИИ-сервисы", "через обычный DNS не открываются", NodeState::Warn));
            return nodes;
        }
        let total: usize = h.services.iter().map(|s| s.proxies.len()).sum();
        let ok: usize = h.services.iter().map(|s| s.ok_count()).sum();
        nodes.push(if total == 0 || ok == 0 {
            Node::new("Прокси", "не отвечают", NodeState::Bad)
        } else if ok < total {
            Node::new("Прокси", format!("отвечают {ok} из {total}"), NodeState::Warn)
        } else {
            Node::new("Прокси", "все отвечают", NodeState::Ok)
        });

        let works: Vec<&str> = h.services.iter().filter(|s| s.works()).map(|s| s.name.as_str()).collect();
        let down: Vec<&str> = h.services.iter().filter(|s| !s.works()).map(|s| s.name.as_str()).collect();
        nodes.push(if down.is_empty() {
            Node::new("ИИ-сервисы", format!("{} открываются", works.join(", ")), NodeState::Ok)
        } else if works.is_empty() {
            Node::new("ИИ-сервисы", format!("{} не открываются", down.join(", ")), NodeState::Bad)
        } else {
            Node::new(
                "ИИ-сервисы",
                format!("{} открываются, {} нет", works.join(", "), down.join(", ")),
                NodeState::Warn,
            )
        });
        nodes
    }

    /// Итог одной фразой и пояснение к ней.
    fn overall(&self) -> (NodeState, String, String) {
        if !self.is_admin {
            return (
                NodeState::Warn,
                "Нужны права администратора".into(),
                "Без них программа не может менять настройки DNS. Нажмите «Перезапустить с правами \
                 администратора» в жёлтой плашке выше."
                    .into(),
            );
        }
        if self.chosen_adapters().iter().all(|a| !a.up) {
            return (
                NodeState::Warn,
                "Нет подключения к сети".into(),
                "Подключитесь к интернету по кабелю или Wi-Fi. Программа увидит подключение сама.".into(),
            );
        }
        let Some(active) = self.active_server() else {
            return (
                NodeState::Neutral,
                "Обход ограничений ещё не включён".into(),
                "Нажмите «Подобрать лучший сервер»: программа проверит все серверы и включит самый \
                 надёжный. Это займёт около 15 секунд."
                    .into(),
            );
        };
        let Some(h) = self.active_health() else {
            return (NodeState::Neutral, "Проверяю…".into(), format!("Смотрю, как работает «{}».", active.name));
        };
        if !active.ai_bypass {
            return (
                NodeState::Warn,
                format!("Включён обычный DNS «{}»", active.name),
                "Интернет работает, но ИИ-сервисы через обычный DNS не открываются. Нажмите «Подобрать \
                 лучший сервер», чтобы включить сервер для обхода."
                    .into(),
            );
        }
        let own = self.bypassing_browsers();
        if !own.is_empty() {
            let names: Vec<&str> = own.iter().map(|b| b.name).collect();
            return (
                NodeState::Warn,
                format!("{} обходит настройки", names.join(" и ")),
                "В этом браузере обход не работает, в остальных всё в порядке. Нажмите «Исправить» в жёлтой \
                 плашке выше."
                    .into(),
            );
        }
        let e2e_bad = self.e2e.as_ref().is_some_and(|e| !e.ok());
        if h.grade().acceptable() && !e2e_bad {
            let watch = if self.config.failover.enabled {
                if self.config.failover.background {
                    " Защита от сбоев следит за ним, даже когда окно закрыто."
                } else {
                    " Защита от сбоев следит за ним, пока окно открыто."
                }
            } else {
                ""
            };
            return (
                NodeState::Ok,
                "ИИ-сервисы открываются".into(),
                format!("Работает через «{}».{watch}", active.name),
            );
        }
        let why = if e2e_bad {
            "Windows получает ответы не от этого сервера".to_string()
        } else {
            h.problem().unwrap_or_default()
        };
        (
            if h.grade() == Grade::Dead { NodeState::Bad } else { NodeState::Warn },
            format!("«{}» сейчас работает плохо", active.name),
            format!(
                "{}: {why}. Защита от сбоев переключит на резервный сервер сама, или нажмите «Подобрать \
                 лучший сервер» прямо сейчас.",
                active.name
            ),
        )
    }

    pub(super) fn simple_view(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let ctx = ui.ctx().clone();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let width = ui.available_width().min(900.0);
            let pad = ((ui.available_width() - width) / 2.0).max(0.0);
            ui.horizontal(|ui| {
                ui.add_space(pad);
                ui.vertical(|ui| {
                    ui.set_width(width);

                    // Главная карточка: итог, схема, действия.
                    let (state, title, subtitle) = self.overall();
                    card(p).inner_margin(Margin::same(22)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                            state_icon(ui.painter(), p, r.center(), 18.0, state);
                            ui.add_space(6.0);
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&title).family(semibold()).size(24.0));
                                ui.add(egui::Label::new(RichText::new(&subtitle).color(p.text_weak)).wrap());
                            });
                        });
                        ui.add_space(18.0);
                        chain(ui, p, &self.chain_nodes());
                        ui.add_space(20.0);

                        ui.horizontal_wrapped(|ui| {
                            let busy = self.auto_picking || self.busy.is_some();
                            let label = if self.auto_picking { "Подбираю сервер…" } else { "Подобрать лучший сервер" };
                            let size = Vec2::new(250.0, 44.0);
                            let btn = egui::Button::new((
                                egui::Atom::grow(),
                                RichText::new(label).family(semibold()).size(15.0).color(p.on_accent),
                                egui::Atom::grow(),
                            ))
                            .fill(p.accent)
                            .stroke(Stroke::NONE)
                            .min_size(size);
                            let resp = ui
                                .add_enabled(self.blocker().is_none(), btn)
                                .on_hover_text("Проверить все серверы для ИИ и включить самый надёжный.")
                                .on_disabled_hover_text(self.blocker().unwrap_or_default());
                            if busy {
                                let r = resp.rect;
                                egui::Spinner::new()
                                    .color(p.on_accent)
                                    .paint_at(ui, Rect::from_center_size(pos2(r.left() + 24.0, r.center().y), Vec2::splat(16.0)));
                            }
                            if resp.clicked() && !busy {
                                self.start_auto_pick(&ctx);
                            }
                            let checking = self.health.values().any(|h| matches!(h, HealthView::Running));
                            let check_label = if checking { "Проверяю…" } else { "Проверить сейчас" };
                            if ui
                                .add(egui::Button::new(check_label).min_size(Vec2::new(0.0, 44.0)))
                                .on_hover_text("Ещё раз проверить всю цепочку: DNS, прокси и сервисы.")
                                .clicked()
                                && !checking
                            {
                                self.start_sweep(&ctx);
                            }
                            if ui
                                .add_enabled(
                                    self.blocker().is_none() && self.busy.is_none(),
                                    egui::Button::new("Вернуть как было").min_size(Vec2::new(0.0, 44.0)),
                                )
                                .on_hover_text("Выключить обход: DNS снова будет от роутера или провайдера.")
                                .clicked()
                            {
                                self.confirm = Some(Confirm::Reset);
                            }
                        });
                        self.status_block(ui, p);
                    });
                    ui.add_space(14.0);

                    // Защита от сбоев простыми словами.
                    card(p).inner_margin(Margin::same(18)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let on = self.config.failover.enabled;
                            let (r, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
                            state_icon(ui.painter(), p, r.center(), 10.0, if on { NodeState::Ok } else { NodeState::Neutral });
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(if on { "Защита от сбоев включена" } else { "Защита от сбоев выключена" })
                                        .family(semibold())
                                        .size(16.0),
                                );
                                let text = if on {
                                    "Если сервер перестанет отвечать, программа сама включит лучший из остальных, а потом \
                                     вернёт ваш. Запасные Cloudflare и Google не дадут пропасть интернету."
                                } else {
                                    "Если выбранный сервер перестанет отвечать, ИИ-сервисы не откроются, пока вы не \
                                     выберете другой. Включите защиту в настройках."
                                };
                                ui.add(egui::Label::new(RichText::new(text).color(p.text_weak)).wrap());
                                if let Some(last) = self.log_tail.last() {
                                    ui.add(
                                        egui::Label::new(RichText::new(format!("Последнее событие: {last}")).small().color(p.text_weak))
                                            .truncate(),
                                    );
                                }
                            });
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("Журнал событий").clicked() {
                                self.log_tail = state::read_log(200);
                                self.show_log = true;
                            }
                            if ui.button("Настроить защиту").clicked() {
                                self.view = View::Settings(Section::Protection);
                            }
                        });
                    });
                    ui.add_space(14.0);

                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("Применяется к: {}", self.chosen_names())).color(p.text_weak));
                        ui.label(RichText::new("·").color(p.text_weak));
                        if ui.link(RichText::new("Выбрать сервер вручную").color(p.accent_text)).clicked() {
                            self.config.ui_mode = UiMode::Advanced;
                            self.save_config();
                        }
                        ui.label(RichText::new("·").color(p.text_weak));
                        if ui.link(RichText::new("Как это работает").color(p.accent_text)).clicked() {
                            self.view = View::Help;
                        }
                    });
                    ui.add_space(12.0);
                });
            });
        });
    }
}
