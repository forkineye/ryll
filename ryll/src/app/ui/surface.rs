use eframe::egui;
use shakenfist_spice_renderer::InputEvent;

use crate::app::RyllApp;
use crate::input_egui::mouse_button_to_spice;

// Values the central panel produces that its caller needs. Both are
// frame-scoped: they are recomputed from scratch on every draw.
pub(in crate::app) struct SurfaceOutcome {
    pub(in crate::app) open_channel_bug_report: bool,
    pub(in crate::app) pointer_on_surface: bool,
}

impl RyllApp {
    pub(in crate::app) fn draw_surface(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
    ) -> SurfaceOutcome {
        let mut outcome = SurfaceOutcome {
            open_channel_bug_report: false,
            pointer_on_surface: false,
        };
        // Main display area (no margin so the surface fills edge-to-edge)
        let panel_frame = egui::Frame::NONE.inner_margin(0.0);
        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                self.draw_surface_error_banner(ui, &mut outcome);

                if !self.connected {
                    ui.centered_and_justified(|ui| {
                        ui.label("Connecting...");
                    });
                    return;
                }

                self.draw_surface_image(ui, ctx, &mut outcome);

                if self.surfaces.surfaces.is_empty() {
                    ui.centered_and_justified(|ui| {
                        ui.label("Waiting for display...");
                    });
                }
            });

        outcome
    }

    fn draw_surface_error_banner(&mut self, ui: &mut egui::Ui, outcome: &mut SurfaceOutcome) {
        if let Some(msg) = self.error_message.clone() {
            ui.colored_label(egui::Color32::RED, format!("Error: {}", msg));
            ui.horizontal(|ui| {
                if ui.small_button("Dismiss").clicked() {
                    self.error_message = None;
                }
                if ui.small_button("Report this as a bug").clicked() {
                    outcome.open_channel_bug_report = true;
                }
            });
            ui.separator();
        }
    }

    fn draw_surface_image(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        outcome: &mut SurfaceOutcome,
    ) {
        let mut keys: Vec<(u8, u32)> = self.surfaces.surfaces.keys().copied().collect();
        keys.sort_unstable();
        let primary_key = keys
            .iter()
            .copied()
            .find(|(_, sid)| *sid == 0)
            .or_else(|| keys.first().copied());

        if let Some(primary_key) = primary_key {
            if let Some(surface) = self.surfaces.surfaces.get_mut(&primary_key) {
                let (width, height) = (surface.width, surface.height);
                let texture = self.textures.texture(ctx, primary_key, surface);
                let size = egui::vec2(width as f32, height as f32);

                let response = ui.add(
                    egui::Image::new(texture)
                        .fit_to_exact_size(size)
                        .sense(egui::Sense::click_and_drag()),
                );

                self.surface_rect = response.rect;
                // False where an egui window or popup covers the
                // surface, as egui hit-tests the layers above it.
                outcome.pointer_on_surface = response.contains_pointer();

                self.handle_surface_input(ctx, &response, outcome);
            }
        }
    }

    fn handle_surface_input(
        &mut self,
        ctx: &egui::Context,
        response: &egui::Response,
        outcome: &SurfaceOutcome,
    ) {
        let input_suppressed = self.show_bug_dialog || self.region_select_active;
        if !input_suppressed {
            if let Some(tx) = &self.input_tx {
                if let Some(pos) = response.hover_pos() {
                    let x = (pos.x - response.rect.min.x).max(0.0) as u32;
                    let y = (pos.y - response.rect.min.y).max(0.0) as u32;
                    // Relative deltas in server mode, absolute
                    // positions in client mode.
                    if let Some(event) = self.pointer.motion(self.mouse_mode, x, y) {
                        let _ = tx.try_send(event);
                    }
                }

                // Gate button-press / scroll-wheel forwarding on
                // whether the pointer is over the SPICE surface,
                // so clicks on the status-bar widgets (volume,
                // mute, reconnect indicator, etc.) do not leak
                // phantom clicks into the guest at the last
                // pointer position. Button-release is forwarded
                // unconditionally when the corresponding bit is
                // set in `forwarded_buttons`, so a press inside
                // the image followed by a release outside it
                // does not leave a stuck button in the guest
                // (symmetric with the `input_suppressed` path
                // below).
                ctx.input(|i| {
                    let mode = self.mouse_mode;
                    for button in [
                        egui::PointerButton::Primary,
                        egui::PointerButton::Secondary,
                        egui::PointerButton::Middle,
                    ] {
                        let spice_btn = mouse_button_to_spice(button);
                        if outcome.pointer_on_surface && i.pointer.button_pressed(button) {
                            self.forwarded_buttons |= spice_btn;
                            for event in self.pointer.button(mode, spice_btn, true, None) {
                                let _ = tx.try_send(event);
                            }
                        }
                        if i.pointer.button_released(button)
                            && self.forwarded_buttons & spice_btn != 0
                        {
                            self.forwarded_buttons &= !spice_btn;
                            for event in self.pointer.button(mode, spice_btn, false, None) {
                                let _ = tx.try_send(event);
                            }
                        }
                    }

                    if outcome.pointer_on_surface {
                        let clicks = self.wheel.clicks(&i.events, response.rect.height());
                        for event in self.pointer.wheel(clicks) {
                            let _ = tx.try_send(event);
                        }
                    } else {
                        self.wheel.reset();
                    }
                });
            }
        } else if self.forwarded_buttons != 0 {
            if let Some(tx) = &self.input_tx {
                let pos = self.pointer.last_pos().unwrap_or((0, 0));
                for bit in 0..5u32 {
                    let mask = 1 << bit;
                    if self.forwarded_buttons & mask != 0 {
                        let _ = tx.try_send(InputEvent::MouseUp {
                            button: mask,
                            x: pos.0,
                            y: pos.1,
                        });
                    }
                }
            }
            self.forwarded_buttons = 0;
        }
    }
}
