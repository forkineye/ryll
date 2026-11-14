use std::time::{Duration, Instant};

use eframe::egui;
use shakenfist_spice_renderer::WebdavCommand;

use crate::app::RyllApp;

impl RyllApp {
    pub(in crate::app) fn draw_webdav_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // ── WebDAV Folders panel ─────────────────────────
        if self.show_webdav_panel {
            // Poll directory picker result
            let mut picked_dir = None;
            if let Some(ref rx) = self.webdav_pick_dir_rx {
                if let Ok(result) = rx.try_recv() {
                    picked_dir = Some(result);
                }
            }
            if picked_dir.is_some() {
                self.webdav_pick_dir_rx = None;
            }

            let mut webdav_action = None;

            if let Some(Some(path)) = picked_dir {
                if path.is_dir() {
                    webdav_action = Some(WebdavCommand::ShareDirectory {
                        path,
                        read_only: self.webdav_pick_dir_readonly,
                    });
                }
            }

            // Auto-clear WebDAV errors after 10 seconds
            if let Some(error_time) = self.webdav_error_time {
                if error_time.elapsed() > Duration::from_secs(10) {
                    self.webdav_error_message = None;
                    self.webdav_error_time = None;
                }
            }

            // Request repaint for elapsed timer and error auto-clear
            if self.webdav_connected_at.is_some() || self.webdav_error_time.is_some() {
                ctx.request_repaint_after(Duration::from_secs(1));
            }

            egui::Panel::right("webdav_panel")
                .default_size(300.0)
                .show(ui, |ui| {
                    ui.heading("Shared Folders");
                    ui.separator();

                    // Channel status
                    if self.webdav_channel_ready {
                        ui.label("Channel: Ready");
                    } else {
                        ui.colored_label(egui::Color32::GRAY, "Channel: Not available");
                    }

                    // Active share with elapsed timer
                    if self.webdav_sharing_active {
                        if let Some(ref dir) = self.webdav_shared_dir {
                            ui.separator();
                            let elapsed = self
                                .webdav_connected_at
                                .map(|t| t.elapsed().as_secs())
                                .unwrap_or(0);
                            let mins = elapsed / 60;
                            let secs = elapsed % 60;
                            let ro = if self.webdav_read_only { " [RO]" } else { "" };
                            ui.label(format!("Sharing: {}{} ({}m {}s)", dir, ro, mins, secs));
                            if ui.button("Stop Sharing").clicked() {
                                webdav_action = Some(WebdavCommand::StopSharing);
                            }
                        }
                    }

                    // Error display
                    if let Some(msg) = self.webdav_error_message.clone() {
                        ui.separator();
                        ui.colored_label(egui::Color32::RED, msg);
                        ui.horizontal(|ui| {
                            if ui.small_button("Dismiss").clicked() {
                                self.webdav_error_message = None;
                                self.webdav_error_time = None;
                            }
                        });
                    }

                    // Share controls (when not sharing)
                    if !self.webdav_sharing_active {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.webdav_pick_dir_readonly, "Read-only");
                            let picker_active = self.webdav_pick_dir_rx.is_some();
                            let enabled = self.webdav_channel_ready && !picker_active;
                            if ui
                                .add_enabled(enabled, egui::Button::new("Share Directory..."))
                                .clicked()
                            {
                                let (tx, rx) = std::sync::mpsc::channel();
                                std::thread::spawn(move || {
                                    let result = rfd::FileDialog::new()
                                        .set_title("Select directory to share")
                                        .pick_folder();
                                    let _ = tx.send(result);
                                });
                                self.webdav_pick_dir_rx = Some(rx);
                            }
                        });
                    }
                });

            // Execute WebDAV action outside the closure
            if let Some(cmd) = webdav_action {
                self.webdav_error_message = None;
                self.webdav_error_time = None;
                if let Some(ref tx) = self.webdav_tx {
                    if let Err(e) = tx.try_send(cmd) {
                        self.webdav_error_message = Some(format!("Failed to send command: {}", e));
                        self.webdav_error_time = Some(Instant::now());
                    }
                }
            }
        }
    }
}
