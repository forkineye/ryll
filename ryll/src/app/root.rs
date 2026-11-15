//! The eframe root application.
//!
//! Before Proxmox support, `RyllApp` was the eframe `App` and its
//! constructor immediately spawned the SPICE connection. A Proxmox
//! launch needs a login and a VM picker first, which means the window
//! has to exist before there is a `Config` at all. `RyllRoot` supplies
//! that gap:
//!
//! - a `--file` / `--url` / `--direct` launch builds `RyllApp`
//!   immediately, exactly as before;
//! - a GUI `--proxmox` launch shows [`ProxmoxLauncher`] and builds
//!   `RyllApp` only once the user picks a guest and Proxmox returns its
//!   console document.
//!
//! The session UI is unchanged. This is a small router in front of it,
//! not a second implementation.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;

use super::proxmox_ui::ProxmoxLauncher;
use super::RyllApp;
use crate::bugreport::PedanticConfig;
use crate::capture::CaptureSession;
use crate::config::{Args, Config, ShareDirConfig, VirtualDiskConfig};
use crate::proxmox::{ProxmoxLaunchSettings, ProxmoxLogin};
use shakenfist_spice_protocol::link::H264Offer;

/// Everything a session needs apart from the resolved connection
/// source and the capture session.
///
/// The fields are the non-connection half of `run_gui`'s old argument
/// list. Keeping them in one value lets both the fixed-source path and
/// the Proxmox path construct the same `RyllApp` when their `Config`
/// finally exists.
pub(crate) struct SessionSetup {
    cadence: bool,
    enable_paste: bool,
    paste_char_delay_ms: u32,
    virtual_disks: Vec<VirtualDiskConfig>,
    share_dir: Option<ShareDirConfig>,
    monitors: u8,
    pedantic_config: Option<PedanticConfig>,
    bug_report_dir: Option<PathBuf>,
    obey_guest_size: bool,
    debug_single_thread_runtime: bool,
    auto_snapshot_interval: Option<u64>,
    auto_snapshot_cap: Option<usize>,
    h264: H264Offer,
    image_cache_cap_bytes: usize,
    glz_dictionary_cap_bytes: usize,
    preferred_compression: u8,
}

impl SessionSetup {
    pub(crate) fn from_args(
        args: &Args,
        virtual_disks: Vec<VirtualDiskConfig>,
        share_dir: Option<ShareDirConfig>,
        pedantic_config: Option<PedanticConfig>,
        obey_guest_size: bool,
    ) -> Self {
        Self {
            cadence: args.cadence,
            enable_paste: args.enable_paste_as_keystrokes,
            paste_char_delay_ms: args.paste_char_delay_ms,
            virtual_disks,
            share_dir,
            monitors: args.monitors,
            pedantic_config,
            bug_report_dir: args.bug_report_dir.clone(),
            obey_guest_size,
            debug_single_thread_runtime: args.debug_single_thread_runtime,
            auto_snapshot_interval: args.auto_snapshot_interval,
            auto_snapshot_cap: args.auto_snapshot_cap,
            h264: args.h264_offer(),
            image_cache_cap_bytes: crate::mib_to_usize_bytes(args.image_cache_cap_mib),
            glz_dictionary_cap_bytes: crate::mib_to_usize_bytes(args.glz_dictionary_cap_mib),
            preferred_compression: args.preferred_compression.wire_value(),
        }
    }

    fn build(
        &self,
        ctx: &egui::Context,
        config: Config,
        capture: Option<Arc<CaptureSession>>,
    ) -> RyllApp {
        RyllApp::new(
            ctx,
            config,
            self.cadence,
            self.enable_paste,
            self.paste_char_delay_ms,
            self.virtual_disks.clone(),
            self.share_dir.clone(),
            capture,
            self.monitors,
            self.pedantic_config.clone(),
            self.bug_report_dir.clone(),
            self.obey_guest_size,
            self.debug_single_thread_runtime,
            self.auto_snapshot_interval,
            self.auto_snapshot_cap,
            self.h264,
            self.image_cache_cap_bytes,
            self.glz_dictionary_cap_bytes,
            self.preferred_compression,
        )
    }
}

/// The eframe `App`: either a live session or the Proxmox launcher.
pub(crate) struct RyllRoot {
    session: Option<RyllApp>,
    launcher: Option<ProxmoxLauncher>,
    setup: SessionSetup,
    /// Directory for `--capture`, retained for a Proxmox launch so the
    /// capture session can be created once the guest is known. `None`
    /// for a fixed source, whose capture was created by `run_gui`.
    capture_dir: Option<PathBuf>,
    /// Shared with `run_gui`'s exit path, which waits for the writers so
    /// the MP4 has its moov atom. A Proxmox launch creates the capture
    /// after `run_gui` has already built its own handle, so the handle
    /// has to be published back through this slot.
    capture_slot: Arc<Mutex<Option<Arc<CaptureSession>>>>,
}

impl RyllRoot {
    /// A launch whose connection source is already known.
    pub(crate) fn with_session(
        ctx: &egui::Context,
        setup: SessionSetup,
        config: Config,
        capture: Option<Arc<CaptureSession>>,
        capture_slot: Arc<Mutex<Option<Arc<CaptureSession>>>>,
    ) -> Self {
        if let Some(capture) = &capture {
            *capture_slot.lock().expect("capture slot poisoned") = Some(capture.clone());
        }
        let session = setup.build(ctx, config, capture);
        Self {
            session: Some(session),
            launcher: None,
            setup,
            capture_dir: None,
            capture_slot,
        }
    }

    /// A GUI `--proxmox` launch: show the launcher until it produces a
    /// `Config`. A `login` already performed from saved credentials starts
    /// the launcher on the VM list, so no connection dialog appears.
    pub(crate) fn with_proxmox(
        setup: SessionSetup,
        settings: ProxmoxLaunchSettings,
        login: Option<ProxmoxLogin>,
        capture_dir: Option<PathBuf>,
        capture_slot: Arc<Mutex<Option<Arc<CaptureSession>>>>,
    ) -> Self {
        let mut launcher = ProxmoxLauncher::new(settings);
        if let Some(login) = login {
            launcher.start_logged_in(login);
        }
        Self {
            session: None,
            launcher: Some(launcher),
            setup,
            capture_dir,
            capture_slot,
        }
    }

    fn create_capture(&self, config: &Config) -> Result<Option<Arc<CaptureSession>>, String> {
        let Some(dir) = &self.capture_dir else {
            return Ok(None);
        };
        #[cfg(feature = "capture")]
        {
            let connection_config: shakenfist_spice_protocol::ConnectionConfig = config.into();
            let capture = CaptureSession::new(
                dir.clone(),
                &connection_config.display_target(),
                config.tls_port,
            )
            .map_err(|e| format!("{e:#}"))?;
            Ok(Some(Arc::new(capture)))
        }
        #[cfg(not(feature = "capture"))]
        {
            let _ = (dir, config);
            Ok(None)
        }
    }
}

impl eframe::App for RyllRoot {
    /// A started bug report must survive the window closing even when
    /// the session is nested one level down, so the session's exit hook
    /// is delegated rather than duplicated.
    fn on_exit(&mut self) {
        if let Some(session) = &mut self.session {
            session.on_exit();
        }
    }

    /// `RyllApp` drains its event queue and advances reconnect, cadence
    /// and auto-snapshot timers here. eframe calls this before `ui`, and
    /// on its own while the window is hidden, so a session whose `logic`
    /// stopped running would back up the renderer's producers. The
    /// launcher has no such work, but it does own the Ctrl+C path while
    /// it is on screen.
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if let Some(session) = &mut self.session {
            session.logic(ctx, frame);
            return;
        }
        if crate::SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        if let Some(session) = &mut self.session {
            session.ui(ui, frame);
            return;
        }

        if let Some(launcher) = &mut self.launcher {
            launcher.ui(ui);
        }

        let Some(config) = self
            .launcher
            .as_mut()
            .and_then(ProxmoxLauncher::take_ready_config)
        else {
            return;
        };

        match self.create_capture(&config) {
            Ok(capture) => {
                let ctx = ui.ctx().clone();
                // The launcher ran as a compact dialog. Hand the shared
                // window back to the session at its usual size and title;
                // the session's auto-fit may resize it again once the
                // guest's primary surface arrives.
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(
                    "Ryll - SPICE Client".to_owned(),
                ));
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
                    crate::SESSION_WINDOW_SIZE[0],
                    crate::SESSION_WINDOW_SIZE[1],
                )));
                let session = self.setup.build(&ctx, config, capture.clone());
                *self.capture_slot.lock().expect("capture slot poisoned") = capture.clone();
                self.session = Some(session);
                // The launcher was the frame's content; draw the new
                // session on the next pass rather than waiting for the
                // first channel event.
                ctx.request_repaint();
            }
            Err(error) => {
                if let Some(launcher) = &mut self.launcher {
                    launcher.fail(error);
                }
                // The launcher already drew this frame; a failure that
                // arrived after it is only visible on the next pass.
                ui.ctx().request_repaint();
            }
        }
    }
}
