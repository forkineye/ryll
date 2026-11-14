use eframe::egui;

use crate::app::trigger_snapshot::{validate_region, RegionSelectEnd};
use crate::app::RyllApp;
use crate::notifications::NotificationSource;
use shakenfist_spice_protocol::NotifySeverity;

impl RyllApp {
    pub(in crate::app) fn draw_region_select(&mut self, ctx: &egui::Context) {
        // Region selection mode: crosshair, drag tracking, overlays
        if self.region_select_active && self.surface_rect != egui::Rect::NOTHING {
            // Show crosshair cursor over the surface
            ctx.output_mut(|o| o.cursor_icon = egui::CursorIcon::Crosshair);

            // Get surface dimensions for clamping
            let surf_w = self.surface_rect.width() as u32;
            let surf_h = self.surface_rect.height() as u32;

            // Track drag (two-pass: collect action, execute outside)
            let mut region_completed = false;
            ctx.input(|i| {
                if i.pointer.primary_pressed() {
                    if let Some(pos) = i.pointer.interact_pos() {
                        let x = ((pos.x - self.surface_rect.min.x).max(0.0) as u32).min(surf_w);
                        let y = ((pos.y - self.surface_rect.min.y).max(0.0) as u32).min(surf_h);
                        self.region_drag_start = Some((x, y));
                        self.region_drag_end = Some((x, y));
                    }
                }
                if i.pointer.primary_down() {
                    if let Some(pos) = i.pointer.interact_pos() {
                        let x = ((pos.x - self.surface_rect.min.x).max(0.0) as u32).min(surf_w);
                        let y = ((pos.y - self.surface_rect.min.y).max(0.0) as u32).min(surf_h);
                        self.region_drag_end = Some((x, y));
                    }
                }
                if i.pointer.primary_released() && self.region_drag_start.is_some() {
                    region_completed = true;
                }
            });

            // Draw instruction banner
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::unique("region_select_banner"),
            ));
            let banner_rect = egui::Rect::from_min_size(
                self.surface_rect.min,
                egui::vec2(self.surface_rect.width(), 28.0),
            );
            painter.rect_filled(
                banner_rect,
                0.0,
                egui::Color32::from_rgba_unmultiplied(0, 0, 0, 180),
            );
            painter.text(
                banner_rect.center(),
                egui::Align2::CENTER_CENTER,
                "Click and drag to select the affected region. Press Escape to skip.",
                egui::FontId::proportional(13.0),
                egui::Color32::WHITE,
            );

            // Draw selection rectangle while dragging
            if let (Some((sx, sy)), Some((ex, ey))) = (self.region_drag_start, self.region_drag_end)
            {
                let left = sx.min(ex) as f32 + self.surface_rect.min.x;
                let top = sy.min(ey) as f32 + self.surface_rect.min.y;
                let right = sx.max(ex) as f32 + self.surface_rect.min.x;
                let bottom = sy.max(ey) as f32 + self.surface_rect.min.y;
                let sel_rect =
                    egui::Rect::from_min_max(egui::pos2(left, top), egui::pos2(right, bottom));
                let sel_painter = ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::unique("region_select_rect"),
                ));
                sel_painter.rect_filled(
                    sel_rect,
                    0.0,
                    egui::Color32::from_rgba_unmultiplied(255, 0, 0, 60),
                );
                sel_painter.rect_stroke(
                    sel_rect,
                    0.0,
                    egui::Stroke::new(2.0, egui::Color32::from_rgb(255, 0, 0)),
                    egui::StrokeKind::Middle,
                );
            }

            // Generate report on drag release
            if let (true, Some((sx, sy)), Some((ex, ey))) = (
                region_completed,
                self.region_drag_start,
                self.region_drag_end,
            ) {
                match validate_region(sx, sy, ex, ey) {
                    Some(region) => {
                        self.end_region_select(RegionSelectEnd::Selected(region));
                    }
                    None => {
                        // Click without drag, or any other
                        // degenerate input (K4 guard). Stay in
                        // region-select mode and tell the user
                        // what went wrong; reset the drag state
                        // so they can try again without having
                        // to re-enter region-select.
                        self.push_notification(
                            NotifySeverity::Warn,
                            NotificationSource::BugReport,
                            "Drag a region with non-zero area, or press \
                             Escape to save the report without one."
                                .to_string(),
                        );
                        self.region_drag_start = None;
                        self.region_drag_end = None;
                    }
                }
            }
        }
    }
}
