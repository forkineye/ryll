use std::time::Instant;

use eframe::egui;

use crate::app::RyllApp;
use crate::notifications;

impl RyllApp {
    pub(in crate::app) fn draw_notifications_panel(&mut self, ui: &mut egui::Ui) {
        // Notifications side panel (conditional)
        if self.show_notifications_panel {
            egui::Panel::right("notifications")
                .default_size(360.0)
                .show(ui, |ui| {
                    self.draw_notifications_header(ui);
                    let snapshot = self.snapshot_notification_entries(ui);
                    let live_ids = self.live_notification_ids(&snapshot);
                    self.draw_notification_rows(ui, snapshot, &live_ids);
                });
        }

        // Mark all read on the panel-open → panel-closed transition,
        // so the bell dot clears and the user gets one chance to triage
        // before the unread state resets.
        if !self.show_notifications_panel && self.notifications_panel_was_open_last_frame {
            if let Ok(mut s) = self.notifications.lock() {
                s.mark_all_read();
            }
        }
        self.notifications_panel_was_open_last_frame = self.show_notifications_panel;
    }

    fn draw_notifications_header(&self, ui: &mut egui::Ui) {
        // Header: title + actions
        ui.horizontal(|ui| {
            ui.heading("Notifications");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Clear all").clicked() {
                    if let Ok(mut s) = self.notifications.lock() {
                        s.clear();
                    }
                }
                if ui.small_button("Mark all read").clicked() {
                    if let Ok(mut s) = self.notifications.lock() {
                        s.mark_all_read();
                    }
                }
            });
        });
    }

    fn snapshot_notification_entries(
        &self,
        ui: &mut egui::Ui,
    ) -> Vec<notifications::NotificationEntry> {
        // Snapshot the state under one lock so rendering is off-lock
        let (total, unread, snapshot) = match self.notifications.lock() {
            Ok(s) => (
                s.len(),
                s.unread_count(),
                s.iter_newest_first().cloned().collect::<Vec<_>>(),
            ),
            Err(_) => (0, 0, Vec::new()),
        };
        ui.label(format!("{} total / {} unread", total, unread));
        ui.separator();
        snapshot
    }

    fn live_notification_ids(
        &self,
        snapshot: &[notifications::NotificationEntry],
    ) -> std::collections::HashSet<u64> {
        // Collect notification-snapshot live-state flags under one lock
        // outside the per-row render, so each row's button knows whether to
        // render in the at-fire (solid) or post-event-only (dim) state
        // without re-locking per entry.
        let live_now = Instant::now();
        let live_ids: std::collections::HashSet<u64> = match self.notification_snapshots.lock() {
            Ok(mut store) => {
                store.prune_expired(live_now);
                snapshot
                    .iter()
                    .filter(|e| store.has_live(e.id, live_now))
                    .map(|e| e.id)
                    .collect()
            }
            Err(_) => std::collections::HashSet::new(),
        };
        live_ids
    }

    fn draw_notification_rows(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: Vec<notifications::NotificationEntry>,
        live_ids: &std::collections::HashSet<u64>,
    ) {
        let mut to_remove: Vec<u64> = Vec::new();
        let mut pending_bug_report_id: Option<u64> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            if snapshot.is_empty() {
                ui.label("No notifications.");
            }
            for entry in &snapshot {
                ui.horizontal(|ui| {
                    let (glyph, colour) = notifications::severity_visuals(entry.severity);
                    let mut g = egui::RichText::new(glyph);
                    if let Some(c) = colour {
                        g = g.color(c);
                    }
                    if entry.read {
                        g = g.weak();
                    }
                    ui.label(g);

                    ui.monospace(notifications::format_relative(entry.when));

                    ui.colored_label(egui::Color32::GRAY, entry.source.label());

                    let mut msg_text = egui::RichText::new(&entry.message);
                    if entry.read {
                        msg_text = msg_text.weak();
                    }
                    ui.label(msg_text);

                    if entry.count > 1 {
                        ui.label(egui::RichText::new(format!("[{}\u{00D7}]", entry.count)).weak());
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Dismiss").clicked() {
                            to_remove.push(entry.id);
                        }
                        // File-as-bug-report button. Always
                        // present; visual state and tooltip
                        // vary by whether a live snapshot still
                        // exists for this notification.
                        let snapshot_live = live_ids.contains(&entry.id);
                        let (label, tooltip) = if snapshot_live {
                            (
                                egui::RichText::new("File…"),
                                "File bug report (at-fire snapshot available)",
                            )
                        } else {
                            (
                                egui::RichText::new("File…").weak(),
                                "File bug report (post-event context only — snapshot expired)",
                            )
                        };
                        if ui.small_button(label).on_hover_text(tooltip).clicked() {
                            pending_bug_report_id = Some(entry.id);
                        }
                    });
                });
            }
        });

        if !to_remove.is_empty() {
            if let Ok(mut s) = self.notifications.lock() {
                for id in to_remove {
                    s.remove(id);
                }
            }
        }
        if let Some(id) = pending_bug_report_id {
            self.file_notification_bug_report(id);
        }
    }
}
