use std::time::{Duration, Instant};

use eframe::egui;

use crate::app::RyllApp;
use crate::bugreport::{format_size, TrafficDirection};

/// Maximum entries shown in the traffic viewer.
const TRAFFIC_VIEWER_MAX_ENTRIES: usize = 200;

/// How often the traffic viewer refreshes from the ring buffers.
const TRAFFIC_VIEWER_REFRESH_MS: u64 = 250;

impl RyllApp {
    pub(in crate::app) fn refresh_traffic_entries(&mut self) {
        // Refresh traffic viewer entries periodically
        if self.show_traffic_viewer
            && !self.traffic_viewer_paused
            && self.traffic_viewer_last_refresh.elapsed()
                >= Duration::from_millis(TRAFFIC_VIEWER_REFRESH_MS)
        {
            self.traffic_viewer_entries =
                self.traffic.recent_view_entries(TRAFFIC_VIEWER_MAX_ENTRIES);
            self.traffic_viewer_last_refresh = Instant::now();
        }
    }

    pub(in crate::app) fn draw_traffic_panel(&mut self, ui: &mut egui::Ui) {
        // Traffic viewer side panel (conditional)
        if self.show_traffic_viewer {
            egui::Panel::right("traffic_viewer")
                .default_size(350.0)
                .show(ui, |ui| {
                    // Header
                    ui.horizontal(|ui| {
                        ui.heading("Traffic");
                        if ui
                            .small_button(if self.traffic_viewer_paused {
                                "Resume"
                            } else {
                                "Pause"
                            })
                            .clicked()
                        {
                            self.traffic_viewer_paused = !self.traffic_viewer_paused;
                        }
                        ui.label(format!("{} msgs", self.traffic_viewer_entries.len()));
                    });

                    // Channel filters
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.traffic_filter_main, "Main");
                        ui.checkbox(&mut self.traffic_filter_display, "Display");
                        ui.checkbox(&mut self.traffic_filter_inputs, "Inputs");
                        ui.checkbox(&mut self.traffic_filter_cursor, "Cursor");
                        ui.checkbox(&mut self.traffic_filter_usbredir, "USB");
                        ui.checkbox(&mut self.traffic_filter_webdav, "WebDAV");
                        ui.checkbox(&mut self.traffic_filter_playback, "Playback");
                    });
                    ui.separator();

                    // Scrollable message list
                    let stick = !self.traffic_viewer_paused;
                    let now_elapsed = self.traffic.elapsed();
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(stick)
                        .show(ui, |ui| {
                            for entry in &self.traffic_viewer_entries {
                                // Apply channel filter
                                let visible = match entry.channel {
                                    "main" => self.traffic_filter_main,
                                    "display" => self.traffic_filter_display,
                                    "inputs" => self.traffic_filter_inputs,
                                    "cursor" => self.traffic_filter_cursor,
                                    "usbredir" => self.traffic_filter_usbredir,
                                    "webdav" => self.traffic_filter_webdav,
                                    "playback" => self.traffic_filter_playback,
                                    _ => true,
                                };
                                if !visible {
                                    continue;
                                }

                                let relative =
                                    entry.timestamp.as_secs_f64() - now_elapsed.as_secs_f64();
                                let dir = match entry.direction {
                                    TrafficDirection::Sent => "\u{2192}",
                                    TrafficDirection::Received => "\u{2190}",
                                };
                                let channel_color = match entry.channel {
                                    "main" => egui::Color32::from_rgb(120, 160, 255),
                                    "display" => egui::Color32::from_rgb(100, 200, 100),
                                    "inputs" => egui::Color32::from_rgb(255, 180, 80),
                                    "cursor" => egui::Color32::from_rgb(200, 130, 255),
                                    "usbredir" => egui::Color32::from_rgb(255, 100, 100),
                                    "webdav" => egui::Color32::from_rgb(100, 200, 200),
                                    _ => egui::Color32::GRAY,
                                };
                                let size_str = format_size(entry.wire_size);

                                ui.horizontal(|ui| {
                                    ui.monospace(format!("{:>7.1}s", relative));
                                    ui.colored_label(
                                        channel_color,
                                        format!("{:<8}", entry.channel),
                                    );
                                    ui.monospace(dir);
                                    ui.label(entry.message_name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.monospace(size_str);
                                        },
                                    );
                                });
                            }
                        });
                });
        }
    }
}
