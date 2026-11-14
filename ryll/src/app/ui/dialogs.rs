use eframe::egui;

use crate::app::reconnect::{format_expiry_local, server_ended_body, ModalVariant, ReconnectState};
use crate::app::RyllApp;
use crate::bugreport::BugReportType;

impl RyllApp {
    pub(in crate::app) fn draw_bug_report_dialog(&mut self, ctx: &egui::Context) {
        // Bug report dialog (two-pass: render then act)
        let mut dialog_action = None;
        let dialog_held = self.show_bug_dialog && self.window_shot_holds_dialog();
        if dialog_held {
            ctx.request_repaint();
        }
        if self.show_bug_dialog && !dialog_held {
            egui::Window::new("Bug Report")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(350.0);

                    ui.label(
                        "Bug reports may contain sensitive data including \
                         screen contents, typed keystrokes, and protocol \
                         traffic. Review the report before sharing and \
                         ensure no confidential information is visible on \
                         screen or was recently typed.",
                    );
                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);

                    ui.label("Report type:");
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Display,
                        "Display (screenshot + image state)",
                    );
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Input,
                        "Input (keyboard + mouse state)",
                    );
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Cursor,
                        "Cursor (cursor cache + position)",
                    );
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Connection,
                        "Connection (session + main channel)",
                    );
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Usb,
                        "USB (usbredir channel + device state)",
                    );
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Audio,
                        "Audio (playback channel + output device)",
                    );
                    ui.radio_value(
                        &mut self.bug_report_type,
                        BugReportType::Ui,
                        "ryll itself (its panels, menus and dialogs + window screenshot)",
                    );

                    ui.add_space(4.0);
                    ui.separator();
                    ui.add_space(4.0);

                    ui.label("Description (optional):");
                    ui.text_edit_singleline(&mut self.bug_description);

                    if self.bug_report_type == BugReportType::Display {
                        ui.add_space(4.0);
                        ui.label(
                            "After Capture, drag a rectangle over the problem. \
                             Escape saves the report without one.",
                        );
                    }

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Capture").clicked() {
                            dialog_action = Some(true);
                        }
                        if ui.button("Cancel").clicked() {
                            dialog_action = Some(false);
                        }
                    });
                });
        }

        // Execute dialog action outside the closure
        match dialog_action {
            Some(true) => {
                // While another report is still sampling, a Display report
                // goes straight to `finish_bug_report`, which refuses it
                // with a notification, rather than into a region
                // selection whose ending would then be refused out of the
                // user's sight (on a reconnect, or as the window closes).
                // Nothing can start a report during a selection, so one
                // begun with none pending ends with none pending.
                if self.bug_report_type == BugReportType::Display
                    && self.pending_bug_report.is_none()
                {
                    self.begin_region_select();
                } else {
                    // Non-display: generate immediately
                    let report_type = self.bug_report_type.clone();
                    let description = self.bug_description.clone();
                    self.finish_bug_report(report_type, description, None);
                }
                self.show_bug_dialog = false;
            }
            Some(false) => {
                self.show_bug_dialog = false;
                self.discard_trigger_snapshot();
            }
            None => {}
        }
    }

    pub(in crate::app) fn draw_paste_error_dialog(&mut self, ctx: &egui::Context) {
        // Paste error dialog (two-pass: render then act)
        let mut paste_dialog_action = None;
        if let Some(ref msg) = self.paste_error_message {
            egui::Window::new("Cannot paste as keystrokes")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(350.0);
                    ui.label(msg);
                    ui.add_space(8.0);
                    if ui.button("OK").clicked() {
                        paste_dialog_action = Some(());
                    }
                });
        }
        if paste_dialog_action.is_some() {
            self.paste_error_message = None;
        }

        // Escape also dismisses the paste error dialog
        if self.paste_error_message.is_some() {
            let esc = ctx.input(|i| i.key_pressed(egui::Key::Escape));
            if esc {
                self.paste_error_message = None;
            }
        }
    }

    pub(in crate::app) fn draw_protocol_gaps_window(&mut self, ctx: &egui::Context) {
        // Protocol gaps floating window (toggled by the Gaps: N button)
        egui::Window::new("Protocol gaps")
            .open(&mut self.gaps_popup_open)
            .resizable(true)
            .default_width(400.0)
            .default_height(300.0)
            .show(ctx, |ui| {
                let mut keys = shakenfist_spice_protocol::logging::warn_once_keys();
                keys.sort();
                if keys.is_empty() {
                    ui.label("No protocol gaps seen this session.");
                } else {
                    ui.label(format!("{} distinct gaps:", keys.len()));
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for key in &keys {
                            ui.monospace(*key);
                        }
                    });
                }
            });
    }

    pub(in crate::app) fn draw_reconnect_modal(&mut self, ctx: &egui::Context) {
        // The modal only appears when auto-reconnect has given
        // up. Pending state shows the status-bar indicator
        // (rendered in the bottom stats panel) instead, so the
        // user is not interrupted while we are still trying.
        let mut wants_reconnect = false;
        if let ReconnectState::Modal(variant) = &self.reconnect_state {
            let (title, body, allow_reconnect) = match variant {
                ModalVariant::Generic { latest_error } => (
                    "Connection lost",
                    format!(
                        "Three automatic reconnect attempts failed: {}",
                        latest_error
                    ),
                    true,
                ),
                ModalVariant::OneShotConsumed => (
                    "Session ended — cannot reconnect",
                    "This connection used a single-use ticket. \
                     Request a new connection from the system that \
                     issued the original link."
                        .to_string(),
                    false,
                ),
                ModalVariant::TicketExpired { expired_at } => (
                    "Session ended — ticket expired",
                    format!(
                        "The ticket for this session expired at {}. \
                         Request a new connection.",
                        format_expiry_local(*expired_at),
                    ),
                    false,
                ),
                ModalVariant::ConnectFailed { error } => (
                    "Could not connect",
                    format!("Could not connect to {}.\n\n{}", self.target, error),
                    true,
                ),
                ModalVariant::ServerEnded { notice, ticket } => {
                    let (body, allow_reconnect) = server_ended_body(notice.as_deref(), *ticket);
                    ("Session ended by the server", body, allow_reconnect)
                }
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    // The body can carry text from the server or an error
                    // string of any length; scroll it rather than let it
                    // push the buttons below the bottom of the window.
                    egui::ScrollArea::vertical()
                        .max_height(ctx.content_rect().height() * 0.5)
                        .show(ui, |ui| ui.label(body));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if allow_reconnect && ui.button("Reconnect").clicked() {
                            wants_reconnect = true;
                        }
                        if ui.button("Close").clicked() {
                            if let Some(ref capture) = self.capture {
                                capture.close();
                            }
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                });
        }
        if wants_reconnect {
            self.reconnect_manual();
        }
    }
}
