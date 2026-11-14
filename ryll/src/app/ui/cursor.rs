use eframe::egui;

use crate::app::RyllApp;
use shakenfist_spice_renderer::CursorImage;

impl RyllApp {
    pub(in crate::app) fn draw_cursor_overlay(&mut self, ctx: &egui::Context) {
        // Create a default cursor if the server hasn't sent one yet
        if self.cursor_image.is_none() && self.connected {
            self.cursor_image = Some(CursorImage {
                width: 12,
                height: 19,
                hot_spot_x: 0,
                hot_spot_y: 0,
                pixels: default_arrow_cursor(),
            });
            self.cursor_texture = None;
        }

        // Create cursor texture if we have a new shape
        if self.cursor_image.is_some() && self.cursor_texture.is_none() {
            if let Some(ref img) = self.cursor_image {
                let color_image = egui::ColorImage::from_rgba_unmultiplied(
                    [img.width as usize, img.height as usize],
                    &img.pixels,
                );
                let options = egui::TextureOptions {
                    magnification: egui::TextureFilter::Nearest,
                    minification: egui::TextureFilter::Nearest,
                    ..Default::default()
                };
                self.cursor_texture = Some(ctx.load_texture("spice_cursor", color_image, options));
            }
        }

        // Draw cursor overlay using the painter so it doesn't
        // interfere with mouse input on the surface below.
        // (hidden during region selection — crosshair cursor is shown instead)
        if self.cursor_visible
            && !self.region_select_active
            && self.surface_rect != egui::Rect::NOTHING
        {
            if let (Some(ref tex), Some(ref img)) = (&self.cursor_texture, &self.cursor_image) {
                // In client mode (2) the host controls cursor position, so
                // use the last pointer position for immediate feedback.  In
                // server mode (1) the guest is the authority — use cursor_pos
                // reported by the cursor channel to stay in sync with the
                // guest.
                let mode = self.mouse_mode;
                let (cx, cy) = if mode == 1 {
                    // Server mode: guest-reported position is authoritative
                    (self.cursor_pos.0 as f32, self.cursor_pos.1 as f32)
                } else {
                    // Client mode: use host-tracked position for responsiveness
                    self.pointer
                        .last_pos()
                        .map(|(x, y)| (x as f32, y as f32))
                        .unwrap_or((self.cursor_pos.0 as f32, self.cursor_pos.1 as f32))
                };

                let x = self.surface_rect.min.x + cx - img.hot_spot_x as f32;
                let y = self.surface_rect.min.y + cy - img.hot_spot_y as f32;
                let size = egui::vec2(img.width as f32, img.height as f32);
                let rect = egui::Rect::from_min_size(egui::pos2(x, y), size);

                let painter = ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::unique("spice_cursor"),
                ));
                let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
                painter.image(tex.id(), rect, uv, egui::Color32::WHITE);
            }
        }
    }

    pub(in crate::app) fn hide_host_cursor(
        &mut self,
        ctx: &egui::Context,
        pointer_on_surface: bool,
    ) {
        // Hide the host cursor where ryll draws the guest's. Not
        // `egui_wants_pointer_input()`: the central panel is shown in the
        // root ui, so egui counts the whole surface as egui's and that is
        // always true (#526).
        if self.cursor_image.is_some() && !self.region_select_active && pointer_on_surface {
            ctx.output_mut(|o| o.cursor_icon = egui::CursorIcon::None);
        }
    }
}

/// Generate a simple 12x19 white arrow cursor with a black outline (RGBA).
fn default_arrow_cursor() -> Vec<u8> {
    #[rustfmt::skip]
    let shape: &[&[u8]] = &[
        &[1,0,0,0,0,0,0,0,0,0,0,0],
        &[1,1,0,0,0,0,0,0,0,0,0,0],
        &[1,2,1,0,0,0,0,0,0,0,0,0],
        &[1,2,2,1,0,0,0,0,0,0,0,0],
        &[1,2,2,2,1,0,0,0,0,0,0,0],
        &[1,2,2,2,2,1,0,0,0,0,0,0],
        &[1,2,2,2,2,2,1,0,0,0,0,0],
        &[1,2,2,2,2,2,2,1,0,0,0,0],
        &[1,2,2,2,2,2,2,2,1,0,0,0],
        &[1,2,2,2,2,2,2,2,2,1,0,0],
        &[1,2,2,2,2,2,2,2,2,2,1,0],
        &[1,2,2,2,2,2,2,2,2,2,2,1],
        &[1,2,2,2,2,2,2,1,1,1,1,1],
        &[1,2,2,2,1,2,2,1,0,0,0,0],
        &[1,2,2,1,0,1,2,2,1,0,0,0],
        &[1,2,1,0,0,1,2,2,1,0,0,0],
        &[1,1,0,0,0,0,1,2,2,1,0,0],
        &[1,0,0,0,0,0,1,2,2,1,0,0],
        &[0,0,0,0,0,0,0,1,1,0,0,0],
    ];

    let mut pixels = vec![0u8; 12 * 19 * 4];
    for (y, row) in shape.iter().enumerate() {
        for (x, &val) in row.iter().enumerate() {
            let idx = (y * 12 + x) * 4;
            match val {
                1 => {
                    // Black outline
                    pixels[idx] = 0;
                    pixels[idx + 1] = 0;
                    pixels[idx + 2] = 0;
                    pixels[idx + 3] = 255;
                }
                2 => {
                    // White fill
                    pixels[idx] = 255;
                    pixels[idx + 1] = 255;
                    pixels[idx + 2] = 255;
                    pixels[idx + 3] = 255;
                }
                _ => {} // transparent (already 0)
            }
        }
    }
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Host cursor over the surface (issue #526)
    //
    // `RyllApp::ui` hides the host cursor when the surface image's response
    // contains the pointer. These pin that egui answers true over the
    // surface in ryll's layout, and false where a window covers it.
    // -------------------------------------------------------------------------

    /// Lay out a status bar, a central panel holding a 200x100 surface and
    /// optionally a window over the surface, as `RyllApp::ui` does. Returns
    /// whether the surface contains a pointer at `pointer` on the last pass.
    fn surface_contains_pointer(pointer: egui::Pos2, covering_window: bool) -> bool {
        let ctx = egui::Context::default();
        let mut contains = false;
        // egui hit-tests against the previous pass's layout, and a window
        // only appears after its sizing pass, so run a few.
        for _ in 0..3 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(400.0, 300.0),
                )),
                events: vec![egui::Event::PointerMoved(pointer)],
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                egui::Panel::bottom("stats").show(ui, |ui| {
                    ui.label("status");
                });
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE.inner_margin(0.0))
                    .show(ui, |ui| {
                        let image = egui::Image::new((
                            egui::TextureId::default(),
                            egui::vec2(200.0, 100.0),
                        ))
                        .fit_to_exact_size(egui::vec2(200.0, 100.0))
                        .sense(egui::Sense::click_and_drag());
                        contains = ui.add(image).contains_pointer();
                    });
                if covering_window {
                    egui::Window::new("overlay")
                        .fixed_pos(egui::pos2(100.0, 20.0))
                        .show(ui.ctx(), |ui| {
                            ui.label("a dialog over the surface");
                        });
                }
            })
            .drop_without_applying_deltas();
        }
        contains
    }

    #[test]
    fn host_cursor_hides_over_the_surface() {
        assert!(surface_contains_pointer(egui::pos2(50.0, 50.0), false));
    }

    #[test]
    fn host_cursor_shows_off_the_surface() {
        // Inside the central panel but beyond the 200x100 image.
        assert!(!surface_contains_pointer(egui::pos2(300.0, 50.0), false));
        // Over the status bar.
        assert!(!surface_contains_pointer(egui::pos2(50.0, 295.0), false));
    }

    #[test]
    fn host_cursor_shows_over_a_window_on_the_surface() {
        assert!(!surface_contains_pointer(egui::pos2(120.0, 40.0), true));
        // Elsewhere on the surface the window does not matter.
        assert!(surface_contains_pointer(egui::pos2(20.0, 80.0), true));
    }
}
