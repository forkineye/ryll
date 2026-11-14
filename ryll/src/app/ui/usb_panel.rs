use std::time::{Duration, Instant};

use eframe::egui;
use shakenfist_spice_renderer::usb::{self, DeviceSource};
use shakenfist_spice_renderer::UsbCommand;

use crate::app::RyllApp;
use crate::bugreport::BugReportType;

impl RyllApp {
    pub(in crate::app) fn draw_usb_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // USB device management panel (conditional)
        if self.show_usb_panel {
            self.poll_usb_state(ctx);

            let mut usb_action = None;
            let mut open_usb_bug_report = false;

            egui::Panel::right("usb_panel")
                .default_size(300.0)
                .show(ui, |ui| {
                    self.draw_usb_header(ui);
                    self.draw_usb_channel_status(ui);
                    self.draw_usb_connected_device(ui);
                    self.draw_usb_error_message(ui, &mut open_usb_bug_report);
                    self.draw_usb_operation_status(ui);

                    ui.separator();

                    self.draw_usb_device_list(ui, &mut usb_action);
                    self.draw_usb_add_disk(ui);
                });

            // Execute USB action outside the closure
            if let Some(cmd) = usb_action {
                self.usb_error_message = None;
                self.usb_error_time = None;
                let is_disconnect = matches!(cmd, UsbCommand::DisconnectDevice);
                if is_disconnect {
                    self.usb_disconnecting = true;
                } else {
                    self.usb_connecting = true;
                }
                if let Some(ref tx) = self.usb_tx {
                    if let Err(e) = tx.try_send(cmd) {
                        self.usb_connecting = false;
                        self.usb_disconnecting = false;
                        self.usb_error_message = Some(format!("Failed to send command: {}", e));
                        self.usb_error_time = Some(Instant::now());
                    }
                }
            }

            // Open bug report dialog for USB error (two-pass)
            if open_usb_bug_report {
                let description = self.usb_error_message.clone().unwrap_or_default();
                self.open_bug_dialog(BugReportType::Usb, description);
            }
        }
    }

    fn poll_usb_state(&mut self, ctx: &egui::Context) {
        // Auto-enumerate on first open
        if !self.usb_devices_enumerated {
            self.usb_available_devices = usb::enumerate_devices(&self.usb_virtual_disks);
            self.usb_devices_enumerated = true;
        }

        // Poll for file picker result
        let mut picked_path = None;
        if let Some(ref rx) = self.usb_add_disk_rx {
            if let Ok(result) = rx.try_recv() {
                picked_path = Some(result);
            }
        }
        if picked_path.is_some() {
            self.usb_add_disk_rx = None;
        }
        if let Some(Some(path)) = picked_path {
            self.usb_add_disk_message = None;
            match std::fs::metadata(&path) {
                Ok(meta) => {
                    if !meta.is_file() {
                        self.usb_add_disk_message =
                            Some("Selected path is not a regular file.".to_string());
                    } else if meta.len() < 512 {
                        self.usb_add_disk_message =
                            Some("File is too small (< 512 bytes).".to_string());
                    } else {
                        let read_only = self.usb_add_disk_readonly;
                        self.usb_virtual_disks.push((path.clone(), read_only));
                        self.usb_available_devices =
                            usb::enumerate_devices(&self.usb_virtual_disks);
                        let warn = if meta.len() % 512 != 0 {
                            " (warning: size not a multiple of 512)"
                        } else {
                            ""
                        };
                        let ro = if read_only { " [RO]" } else { "" };
                        self.usb_add_disk_message =
                            Some(format!("Added: {}{}{}", path.display(), ro, warn));
                    }
                }
                Err(e) => {
                    self.usb_add_disk_message = Some(format!("Cannot read file: {}", e));
                }
            }
        }

        // Auto-clear USB errors after 10 seconds
        if let Some(error_time) = self.usb_error_time {
            if error_time.elapsed() > Duration::from_secs(10) {
                self.usb_error_message = None;
                self.usb_error_time = None;
            }
        }

        // Request repaint for elapsed timer and error auto-clear
        if self.usb_connected_at.is_some() || self.usb_error_time.is_some() {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }

    fn draw_usb_header(&mut self, ui: &mut egui::Ui) {
        // Header with refresh button
        ui.horizontal(|ui| {
            ui.heading("USB Devices");
            if ui.small_button("Refresh").clicked() {
                self.usb_available_devices = usb::enumerate_devices(&self.usb_virtual_disks);
            }
        });
        ui.separator();
    }

    fn draw_usb_channel_status(&self, ui: &mut egui::Ui) {
        // Channel status
        if self.usb_channel_ready {
            ui.label("Channel: Ready");
        } else {
            ui.colored_label(egui::Color32::GRAY, "Channel: Not available");
        }
    }

    fn draw_usb_connected_device(&self, ui: &mut egui::Ui) {
        // Connected device with elapsed time
        if let Some(ref desc) = self.usb_device_description {
            ui.separator();
            let elapsed = self
                .usb_connected_at
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);
            let mins = elapsed / 60;
            let secs = elapsed % 60;
            ui.label(format!("Connected: {} ({}m {}s)", desc, mins, secs));
        }
    }

    fn draw_usb_error_message(&mut self, ui: &mut egui::Ui, open_usb_bug_report: &mut bool) {
        // Error message with dismiss and bug report buttons
        if let Some(msg) = self.usb_error_message.clone() {
            ui.separator();
            ui.colored_label(egui::Color32::RED, msg);
            ui.horizontal(|ui| {
                if ui.small_button("Dismiss").clicked() {
                    self.usb_error_message = None;
                    self.usb_error_time = None;
                }
                if ui.small_button("Report this as a bug").clicked() {
                    *open_usb_bug_report = true;
                }
            });
        }
    }

    fn draw_usb_operation_status(&self, ui: &mut egui::Ui) {
        // Operation in progress indicator
        if self.usb_connecting {
            ui.separator();
            ui.label("Connecting...");
        } else if self.usb_disconnecting {
            ui.separator();
            ui.label("Disconnecting...");
        }
    }

    fn draw_usb_device_list(&self, ui: &mut egui::Ui, usb_action: &mut Option<UsbCommand>) {
        // Device list with connect/disconnect buttons
        let buttons_disabled =
            !self.usb_channel_ready || self.usb_connecting || self.usb_disconnecting;
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.usb_available_devices.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "No USB devices found.");
            } else {
                for device in &self.usb_available_devices {
                    let label = device.label();
                    let is_connected = self
                        .usb_device_description
                        .as_ref()
                        .is_some_and(|d| *d == label);

                    ui.horizontal(|ui| {
                        if is_connected {
                            ui.colored_label(egui::Color32::GREEN, "\u{25CF}");
                            ui.label(&label);
                            if ui
                                .add_enabled(!buttons_disabled, egui::Button::new("Disconnect"))
                                .clicked()
                            {
                                *usb_action = Some(UsbCommand::DisconnectDevice);
                            }
                        } else {
                            ui.label(&label);
                            let connect_enabled =
                                !buttons_disabled && self.usb_device_description.is_none();
                            if ui
                                .add_enabled(connect_enabled, egui::Button::new("Connect"))
                                .clicked()
                            {
                                *usb_action = Some(match &device.source {
                                    #[cfg(target_os = "linux")]
                                    DeviceSource::Physical { bus, address } => {
                                        UsbCommand::ConnectPhysical {
                                            bus: *bus,
                                            address: *address,
                                        }
                                    }
                                    DeviceSource::VirtualDisk { path, read_only } => {
                                        UsbCommand::ConnectVirtualDisk {
                                            path: path.clone(),
                                            read_only: *read_only,
                                        }
                                    }
                                });
                            }
                        }
                    });
                }
            }
        });
    }

    fn draw_usb_add_disk(&mut self, ui: &mut egui::Ui) {
        // Add virtual disk section
        ui.separator();
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.usb_add_disk_readonly, "Read-only");
            let picker_active = self.usb_add_disk_rx.is_some();
            if ui
                .add_enabled(!picker_active, egui::Button::new("Add Disk..."))
                .clicked()
            {
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result = rfd::FileDialog::new()
                        .set_title("Select RAW disk image")
                        .add_filter("Disk images", &["raw", "img"])
                        .add_filter("All files", &["*"])
                        .pick_file();
                    let _ = tx.send(result);
                });
                self.usb_add_disk_rx = Some(rx);
            }
        });

        // Add-disk message
        if let Some(ref msg) = self.usb_add_disk_message {
            if msg.starts_with("Added:") {
                ui.label(msg);
            } else {
                ui.colored_label(egui::Color32::RED, msg);
            }
        }
    }
}
