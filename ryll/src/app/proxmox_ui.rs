//! The Proxmox login and VM picker.
//!
//! Network work happens on plain threads and reports back over an mpsc
//! channel, because `ProxmoxClient` is the synchronous reqwest client and
//! the eframe UI thread must never block on a login or a list request.
//! The UI polls the channel once per frame while a request is in flight.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

use eframe::egui;

use crate::config::Config;
use crate::config_dir::{self, SavedProxmox};
use crate::proxmox::{ProxmoxAuth, ProxmoxClient, ProxmoxLaunchSettings, ProxmoxTls, ProxmoxVm};

/// What the launcher is doing. `client` distinguishes the two non-busy
/// screens: no client means "log in", a client means "choose a VM".
#[derive(Copy, Clone, PartialEq, Eq)]
enum Stage {
    /// A saved endpoint/token was detected on a no-argument launch and
    /// the user has not opted into connecting automatically.
    SavedPrompt,
    Login,
    Busy,
    Vms,
}

enum LauncherEvent {
    LoggedIn(Result<(ProxmoxClient, Vec<ProxmoxVm>), String>),
    Listed(Result<Vec<ProxmoxVm>, String>),
    Spice(Result<Config, String>),
}

pub(crate) struct ProxmoxLauncher {
    // Form state
    url: String,
    use_token: bool,
    username: String,
    password: String,
    token_id: String,
    token_secret: String,
    insecure: bool,
    ca_pem: Option<Vec<u8>>,
    ca_path: Option<std::path::PathBuf>,
    ca_label: Option<String>,
    proxy: String,

    // Flow state
    auto_login: bool,
    auto_vm: Option<u32>,
    stage: Stage,
    busy_message: String,
    client: Option<ProxmoxClient>,
    vms: Vec<ProxmoxVm>,
    error: Option<String>,
    rx: Option<Receiver<LauncherEvent>>,
    ready_config: Option<Config>,

    // Saved configuration
    remember_token: bool,
    save_requested: bool,
    saved_token_present: bool,
    token_from_saved: bool,
    saved_url: Option<String>,
    auto_connect: bool,
    dont_ask_again: bool,
    /// The prompt's "connect automatically" choice, applied only after
    /// a successful login so a rejected token is not persisted with it.
    pending_auto_connect: bool,
}

impl ProxmoxLauncher {
    pub(crate) fn new(settings: ProxmoxLaunchSettings) -> Self {
        let token_parts = settings.token_parts();
        let (use_token, token_id, token_secret) = match token_parts {
            Some((id, secret)) => (true, id, secret),
            None => (false, String::new(), String::new()),
        };
        let prompt_saved = settings.prompt_saved;
        let auto_login = !prompt_saved && settings.can_auto_login();
        let ca_label = settings
            .ca_path
            .as_ref()
            .map(|path| path.display().to_string());
        Self {
            url: settings.url,
            use_token,
            username: settings.username,
            password: settings.password.unwrap_or_default(),
            token_id,
            token_secret,
            insecure: settings.tls.insecure,
            ca_pem: settings.tls.ca_pem,
            ca_path: settings.ca_path,
            ca_label,
            proxy: settings.proxy.unwrap_or_default(),
            auto_login,
            auto_vm: settings.auto_vm,
            stage: if prompt_saved {
                Stage::SavedPrompt
            } else {
                Stage::Login
            },
            busy_message: String::new(),
            client: None,
            vms: Vec::new(),
            error: None,
            rx: None,
            ready_config: None,
            remember_token: settings.save_requested,
            save_requested: settings.save_requested,
            saved_token_present: settings.saved_token_present,
            token_from_saved: settings.token_from_saved,
            saved_url: settings.saved_url,
            auto_connect: settings.auto_connect,
            dont_ask_again: false,
            pending_auto_connect: false,
        }
    }

    /// The root application takes the resolved console config and builds
    /// the SPICE session.
    pub(crate) fn take_ready_config(&mut self) -> Option<Config> {
        self.ready_config.take()
    }

    /// A session could not start after a console was requested (for
    /// example the capture directory could not be created). Show the
    /// error on the VM list rather than dropping the user on a blank
    /// window.
    pub(crate) fn fail(&mut self, error: String) {
        self.error = Some(error);
        self.stage = if self.client.is_some() {
            Stage::Vms
        } else {
            Stage::Login
        };
    }

    pub(crate) fn ui(&mut self, ui: &mut egui::Ui) {
        self.poll();

        if self.auto_login && self.stage == Stage::Login && self.rx.is_none() {
            self.auto_login = false;
            self.begin_login();
        }

        match self.stage {
            Stage::SavedPrompt => self.saved_prompt_ui(ui),
            Stage::Busy => self.busy_ui(ui),
            Stage::Login => self.login_ui(ui),
            Stage::Vms => self.vms_ui(ui),
        }

        if self.rx.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else {
            return;
        };
        match rx.try_recv() {
            Ok(event) => {
                self.rx = None;
                self.handle(event);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.rx = None;
                self.error = Some(
                    "the Proxmox request thread stopped without a result; try again".to_string(),
                );
                self.stage = if self.client.is_some() {
                    Stage::Vms
                } else {
                    Stage::Login
                };
            }
        }
    }

    fn handle(&mut self, event: LauncherEvent) {
        match event {
            LauncherEvent::LoggedIn(Ok((client, vms))) => {
                tracing::info!("Proxmox: logged in; {} QEMU VM(s) visible", vms.len());
                self.client = Some(client);
                self.vms = vms;
                self.stage = Stage::Vms;
                self.error = None;
                let promote_auto_connect = std::mem::take(&mut self.pending_auto_connect);
                if promote_auto_connect {
                    self.auto_connect = true;
                }
                if self.save_requested && !self.use_token {
                    self.error = Some(
                        "--proxmox-save stores only API tokens; the password login was not saved"
                            .to_string(),
                    );
                } else if self.use_token
                    && (self.remember_token || self.save_requested || promote_auto_connect)
                {
                    self.save_current_token();
                }
                self.maybe_auto_vm();
            }
            LauncherEvent::LoggedIn(Err(error)) => {
                self.pending_auto_connect = false;
                self.error = Some(error);
                self.stage = Stage::Login;
            }
            LauncherEvent::Listed(Ok(vms)) => {
                self.vms = vms;
                self.stage = Stage::Vms;
            }
            LauncherEvent::Listed(Err(error)) => {
                self.error = Some(error);
                self.stage = Stage::Vms;
            }
            LauncherEvent::Spice(Ok(config)) => {
                self.ready_config = Some(config);
                self.stage = Stage::Busy;
                self.busy_message = "Opening the SPICE console…".to_string();
                self.error = None;
            }
            LauncherEvent::Spice(Err(error)) => {
                self.error = Some(error);
                self.stage = Stage::Vms;
            }
        }
    }

    fn maybe_auto_vm(&mut self) {
        let Some(vmid) = self.auto_vm.take() else {
            return;
        };
        match self.vms.iter().find(|vm| vm.vmid == vmid).cloned() {
            Some(vm) => self.begin_spice(vm),
            None => {
                self.error = Some(format!(
                    "VM {vmid} is not visible to these credentials; pick one from the list"
                ));
            }
        }
    }

    fn begin_login(&mut self) {
        let url = self.url.trim().to_string();
        if url.is_empty() {
            self.error = Some("Enter the Proxmox VE URL, such as https://pve.example:8006".into());
            return;
        }

        let auth = if self.use_token {
            if self.token_from_saved {
                if let Some(saved_url) = &self.saved_url {
                    if !crate::proxmox::endpoint_matches(&self.url, saved_url) {
                        // The form token came from a saved server. Do not
                        // send it to a different endpoint the user has
                        // just typed; clear it and make them re-enter one
                        // for the new server deliberately.
                        self.token_id.clear();
                        self.token_secret.clear();
                        self.saved_token_present = false;
                        self.token_from_saved = false;
                        self.error = Some(format!(
                            "The saved token belongs to {saved_url} and was cleared because \
                             the URL changed. Enter a token for the new endpoint."
                        ));
                        return;
                    }
                }
            }
            let token_id = self.token_id.trim().to_string();
            if token_id.is_empty() || self.token_secret.is_empty() {
                self.error = Some(
                    "An API token needs both its ID (user@realm!tokenid) and its secret".into(),
                );
                return;
            }
            ProxmoxAuth::Token {
                token: format!("{token_id}={}", self.token_secret),
            }
        } else {
            if self.username.trim().is_empty() || self.password.is_empty() {
                self.error = Some("Enter both the Proxmox username and password".into());
                return;
            }
            ProxmoxAuth::Password {
                username: self.username.trim().to_string(),
                password: self.password.clone(),
            }
        };

        if self.insecure && self.ca_pem.is_some() {
            self.error = Some(
                "Choose either a CA or the insecure checkbox, not both; clear one of them".into(),
            );
            return;
        }
        let tls = ProxmoxTls {
            insecure: self.insecure,
            ca_pem: self.ca_pem.clone(),
        };
        let proxy = self.proxy.trim().to_string();
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.stage = Stage::Busy;
        self.busy_message = "Connecting to Proxmox VE and listing VMs…".to_string();
        self.error = None;

        std::thread::spawn(move || {
            let result = ProxmoxClient::connect(
                &url,
                auth,
                tls,
                if proxy.is_empty() { None } else { Some(proxy) },
            )
            .and_then(|client| client.list_vms().map(|vms| (client, vms)));
            let _ = tx.send(LauncherEvent::LoggedIn(
                result.map_err(|error| format!("{error:#}")),
            ));
        });
    }

    fn begin_list(&mut self) {
        let Some(client) = self.client.clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.stage = Stage::Busy;
        self.busy_message = "Refreshing the VM list…".to_string();
        self.error = None;

        std::thread::spawn(move || {
            let result = client.list_vms().map_err(|error| format!("{error:#}"));
            let _ = tx.send(LauncherEvent::Listed(result));
        });
    }

    fn begin_spice(&mut self, vm: ProxmoxVm) {
        if !vm.is_connectable() {
            self.error = Some(format!(
                "VM {} ({}) is {}{}; a SPICE console needs a running, non-template guest",
                vm.vmid,
                vm.display_name(),
                vm.status.as_deref().unwrap_or("not running"),
                if vm.template { " template" } else { "" }
            ));
            return;
        }
        let Some(client) = self.client.clone() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.stage = Stage::Busy;
        self.busy_message = format!(
            "Requesting the SPICE console for VM {} ({})…",
            vm.vmid,
            vm.display_name()
        );
        self.error = None;

        tracing::info!(
            "Proxmox: requesting the SPICE console for VM {} ({}) on {}",
            vm.vmid,
            vm.display_name(),
            vm.node
        );
        std::thread::spawn(move || {
            let result = client
                .spice_config(&vm)
                .map_err(|error| format!("{error:#}"));
            let _ = tx.send(LauncherEvent::Spice(result));
        });
    }

    /// Persist the endpoint, token and TLS choice in `~/.ryll/config.json`.
    ///
    /// Only API tokens are represented in the saved file; the caller
    /// checks `use_token` first.
    fn save_current_token(&mut self) {
        let token_id = self.token_id.trim().to_string();
        if token_id.is_empty() || self.token_secret.is_empty() {
            return;
        }
        let saved = SavedProxmox {
            url: self.url.trim().to_string(),
            token: Some(format!("{token_id}={}", self.token_secret)),
            insecure: self.insecure,
            // A CA and `insecure` are mutually exclusive. The form
            // disables the checkbox when a CA is present, but a saved
            // file edited by hand can still reach here.
            ca: if self.insecure {
                None
            } else {
                self.ca_path.clone()
            },
            auto_connect: self.auto_connect,
        };
        match config_dir::save_proxmox(&saved) {
            Ok(path) => {
                self.saved_token_present = true;
                self.token_from_saved = true;
                self.saved_url = Some(saved.url);
                tracing::info!(
                    "Proxmox: saved endpoint and API token in {}",
                    path.display()
                );
            }
            Err(error) => {
                let message = format!("Could not save the Proxmox token: {error:#}");
                tracing::warn!("{message}");
                self.error = Some(message);
            }
        }
    }

    /// Remove the token from `~/.ryll`, keeping the endpoint and TLS
    /// settings. The current authenticated session is unaffected.
    fn forget_saved_token(&mut self) {
        match config_dir::forget_proxmox_token() {
            Ok(changed) => {
                self.saved_token_present = false;
                self.token_from_saved = false;
                self.saved_url = None;
                self.auto_connect = false;
                self.remember_token = false;
                self.token_id.clear();
                self.token_secret.clear();
                if changed {
                    tracing::info!("Proxmox: removed the saved API token");
                }
            }
            Err(error) => {
                let message = format!("Could not remove the saved Proxmox token: {error:#}");
                tracing::warn!("{message}");
                self.error = Some(message);
            }
        }
    }

    fn saved_prompt_ui(&mut self, ui: &mut egui::Ui) {
        let mut connect = false;
        let mut skip = false;

        ui.add_space(70.0);
        ui.vertical_centered(|ui| {
            ui.heading("Saved Proxmox connection");
            ui.add_space(6.0);
            ui.label(format!(
                "Ryll found a saved API token for {}.",
                self.url.trim()
            ));
            ui.label("Connect and list its VMs?");
            ui.add_space(14.0);
            ui.checkbox(
                &mut self.dont_ask_again,
                "Don't ask again; connect automatically",
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Connect").clicked() {
                    connect = true;
                }
                if ui.button("Not now").clicked() {
                    skip = true;
                }
            });
        });

        self.error_ui(ui);

        if connect {
            if self.dont_ask_again {
                // Applied after the login succeeds, so a rejected token
                // is not persisted together with automatic connect.
                self.pending_auto_connect = true;
            }
            self.begin_login();
        } else if skip {
            self.dont_ask_again = false;
            self.stage = Stage::Login;
        }
    }

    fn logout(&mut self) {
        self.client = None;
        self.vms.clear();
        self.error = None;
        self.stage = Stage::Login;
    }

    fn error_ui(&self, ui: &mut egui::Ui) {
        if let Some(error) = &self.error {
            ui.add_space(6.0);
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), error);
        }
    }

    fn login_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            ui.heading("Connect to Proxmox VE");
            ui.add_space(4.0);
            ui.label(
                "Ryll lists the QEMU guests this login can see and connects to the one you \
                 choose. It does not create, start, stop or reconfigure guests.",
            );
        });
        ui.add_space(16.0);

        let mut submit = false;
        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.set_max_width(560.0);
                egui::Grid::new("proxmox_login")
                    .num_columns(2)
                    .spacing([14.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Proxmox URL");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.url)
                                .hint_text("https://pve.example:8006")
                                .desired_width(360.0),
                        );
                        ui.end_row();

                        ui.label("Authentication");
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut self.use_token, false, "Username / password");
                            ui.radio_value(&mut self.use_token, true, "API token");
                        });
                        ui.end_row();

                        if self.use_token {
                            ui.label("Token ID");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.token_id)
                                    .hint_text("user@realm!tokenid")
                                    .desired_width(360.0),
                            );
                            ui.end_row();

                            ui.label("Token secret");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.token_secret)
                                    .password(true)
                                    .desired_width(360.0),
                            );
                            ui.end_row();
                        } else {
                            ui.label("Username");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.username)
                                    .hint_text("user@realm")
                                    .desired_width(360.0),
                            );
                            ui.end_row();

                            ui.label("Password");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .password(true)
                                    .desired_width(360.0),
                            );
                            ui.end_row();
                        }

                        ui.label("TLS");
                        ui.add_enabled(
                            self.ca_label.is_none(),
                            egui::Checkbox::new(
                                &mut self.insecure,
                                "Accept the certificate without verifying it",
                            ),
                        )
                        .on_disabled_hover_text(
                            "A CA is configured; certificate verification stays on",
                        )
                        .on_hover_text(
                            "Proxmox installs a self-signed certificate by default. Prefer \
                             --proxmox-ca when the certificate is stable.",
                        );
                        ui.end_row();

                        if let Some(ca_label) = &self.ca_label {
                            ui.label("CA");
                            ui.monospace(ca_label);
                            ui.end_row();
                        }

                        ui.label("SPICE proxy");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.proxy)
                                .hint_text("leave blank to let Proxmox choose the node")
                                .desired_width(360.0),
                        );
                        ui.end_row();

                        ui.label("Saved");
                        ui.add_enabled(
                            self.use_token,
                            egui::Checkbox::new(
                                &mut self.remember_token,
                                "Remember this token in ~/.ryll",
                            ),
                        )
                        .on_disabled_hover_text("Passwords are never saved");
                        ui.end_row();
                    });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Connect").clicked() {
                        submit = true;
                    }
                    ui.label(if self.use_token {
                        "Saves to ~/.ryll when Remember is ticked or --proxmox-save is used."
                    } else {
                        "Passwords are never stored."
                    });
                });
            });

        self.error_ui(ui);
        if ui.ctx().input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
        if submit {
            self.begin_login();
        }
    }

    fn busy_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(80.0);
        ui.vertical_centered(|ui| {
            ui.spinner();
            ui.add_space(8.0);
            ui.label(&self.busy_message);
        });
        self.error_ui(ui);
        let label = if self.client.is_some() {
            "Back to the VM list"
        } else {
            "Cancel"
        };
        if ui.button(label).clicked() {
            // Drop the receiver so a result that arrives after the user
            // left this screen cannot start a session behind their back.
            self.rx = None;
            self.stage = if self.client.is_some() {
                Stage::Vms
            } else {
                Stage::Login
            };
            self.busy_message.clear();
        }
    }

    fn vms_ui(&mut self, ui: &mut egui::Ui) {
        let mut refresh = false;
        let mut logout = false;
        let mut forget = false;
        ui.horizontal(|ui| {
            ui.heading("Choose a VM");
            ui.separator();
            if ui.button("Refresh").clicked() {
                refresh = true;
            }
            if ui.button("Use a different account").clicked() {
                logout = true;
            }
            if self.saved_token_present && ui.button("Forget saved token").clicked() {
                forget = true;
            }
        });
        ui.label(format!(
            "{} visible QEMU guest(s). Only running, non-template guests can be connected.",
            self.vms.len()
        ));
        self.error_ui(ui);
        ui.add_space(6.0);
        ui.separator();

        let mut connect: Option<ProxmoxVm> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("proxmox_vms")
                    .striped(true)
                    .num_columns(5)
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.strong("VMID");
                        ui.strong("Node");
                        ui.strong("Status");
                        ui.strong("");
                        ui.end_row();

                        for vm in &self.vms {
                            ui.label(vm.display_name());
                            ui.monospace(vm.vmid.to_string());
                            ui.label(&vm.node);
                            let status = vm.status.as_deref().unwrap_or("unknown");
                            let colour = if vm.is_running() {
                                egui::Color32::from_rgb(110, 190, 120)
                            } else {
                                egui::Color32::from_gray(150)
                            };
                            ui.label(egui::RichText::new(status).color(colour));
                            let response = ui
                                .add_enabled(vm.is_connectable(), egui::Button::new("Connect"))
                                .on_disabled_hover_text(if vm.template {
                                    "This guest is a template; start a clone to get a console"
                                } else {
                                    "The guest must be running to get a SPICE console"
                                });
                            if response.clicked() {
                                connect = Some(vm.clone());
                            }
                            ui.end_row();
                        }
                    });
            });

        if let Some(vm) = connect {
            self.begin_spice(vm);
        }
        if forget {
            self.forget_saved_token();
        }
        if refresh {
            self.begin_list();
        }
        if logout {
            self.logout();
        }
    }
}
