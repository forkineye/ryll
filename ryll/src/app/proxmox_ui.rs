//! The Proxmox login and VM picker.
//!
//! Network work happens on plain threads and reports back over an mpsc
//! channel, because `ProxmoxClient` is the synchronous reqwest client and
//! the eframe UI thread must never block on a login or a list request.
//! The UI polls the channel once per frame while a request is in flight.
//!
//! The launcher runs in its own compact, centred window (see
//! `gui_proxmox_native_options` in `main.rs`) and paints its own
//! background and palette: eframe hands an app a bare `Ui` with no
//! background, and the session's central panel does not exist while the
//! launcher is the only thing on screen.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

use eframe::egui;

use crate::config::Config;
use crate::config_dir::{self, ProxmoxProfile};
use crate::proxmox::{
    ProxmoxAuth, ProxmoxClient, ProxmoxLaunchSettings, ProxmoxLogin, ProxmoxTls, ProxmoxVm,
};

/// What the launcher is doing. `client` distinguishes the two non-busy
/// screens: no client means "log in", a client means "choose a VM".
#[derive(Copy, Clone, PartialEq, Eq)]
enum Stage {
    Login,
    Busy,
    Vms,
}

enum LauncherEvent {
    /// The client, its VM list, and the Proxmox node name used to label
    /// the saved profile.
    LoggedIn(Result<(ProxmoxClient, Vec<ProxmoxVm>, String), String>),
    Listed(Result<Vec<ProxmoxVm>, String>),
    Spice(Result<Config, String>),
}

/// The widest the dialog's content column gets. A widened window centres
/// the column instead of stretching every field across it.
const CONTENT_WIDTH: f32 = 460.0;

/// Air between the window edge and the content column when the window is
/// too narrow for the column's cap.
const SIDE_MARGIN: f32 = 28.0;

/// Air above and below the content column.
const VERTICAL_MARGIN: f32 = 24.0;

/// Colours for the launcher, taken from the Shaken Fist web UI's design
/// tokens (`ryll/src/web/assets/sfui/tokens.css`): the same surfaces,
/// text weights and accent in each theme, so the native dialog and the
/// browser page agree on what ryll looks like.
#[derive(Clone, Copy)]
struct Palette {
    bg: egui::Color32,
    surface: egui::Color32,
    inset: egui::Color32,
    border: egui::Color32,
    text: egui::Color32,
    dim: egui::Color32,
    accent: egui::Color32,
    accent_hover: egui::Color32,
    /// Text drawn on top of `accent`, as a filled button's label.
    on_accent: egui::Color32,
    button: egui::Color32,
    button_hover: egui::Color32,
    green: egui::Color32,
    red: egui::Color32,
    amber: egui::Color32,
    /// Background behind selected text.
    selection: egui::Color32,
}

impl Palette {
    /// Pick the palette matching the egui theme in force, so the dialog
    /// follows the user's light/dark preference like the rest of the app.
    fn for_style(style: &egui::Style) -> Self {
        if style.visuals.dark_mode {
            Self {
                bg: egui::Color32::from_rgb(0x0f, 0x11, 0x17),
                surface: egui::Color32::from_rgb(0x1a, 0x1d, 0x27),
                inset: egui::Color32::from_rgb(0x12, 0x15, 0x1d),
                border: egui::Color32::from_rgb(0x2a, 0x2d, 0x3a),
                text: egui::Color32::from_rgb(0xe1, 0xe4, 0xed),
                dim: egui::Color32::from_rgb(0x8b, 0x8f, 0xa3),
                accent: egui::Color32::from_rgb(0x6c, 0x9e, 0xff),
                accent_hover: egui::Color32::from_rgb(0x8b, 0xb4, 0xff),
                on_accent: egui::Color32::from_rgb(0x0b, 0x12, 0x20),
                button: egui::Color32::from_rgb(0x23, 0x28, 0x38),
                button_hover: egui::Color32::from_rgb(0x2d, 0x34, 0x46),
                green: egui::Color32::from_rgb(0x4a, 0xde, 0x80),
                red: egui::Color32::from_rgb(0xf8, 0x71, 0x71),
                amber: egui::Color32::from_rgb(0xfb, 0xbf, 0x24),
                selection: egui::Color32::from_rgb(0x31, 0x45, 0x6b),
            }
        } else {
            Self {
                bg: egui::Color32::from_rgb(0xf4, 0xf5, 0xf8),
                surface: egui::Color32::WHITE,
                inset: egui::Color32::from_rgb(0xf7, 0xf8, 0xfb),
                border: egui::Color32::from_rgb(0xd7, 0xda, 0xe2),
                text: egui::Color32::from_rgb(0x1c, 0x1f, 0x28),
                dim: egui::Color32::from_rgb(0x5a, 0x61, 0x72),
                accent: egui::Color32::from_rgb(0x25, 0x63, 0xeb),
                accent_hover: egui::Color32::from_rgb(0x1d, 0x4e, 0xd8),
                on_accent: egui::Color32::WHITE,
                button: egui::Color32::from_rgb(0xee, 0xf1, 0xf6),
                button_hover: egui::Color32::from_rgb(0xe2, 0xe7, 0xf0),
                green: egui::Color32::from_rgb(0x15, 0x80, 0x3d),
                red: egui::Color32::from_rgb(0xb9, 0x1c, 0x1c),
                amber: egui::Color32::from_rgb(0xb4, 0x53, 0x09),
                selection: egui::Color32::from_rgb(0xcb, 0xdc, 0xff),
            }
        }
    }
}

/// `color` at `alpha`, for the tinted fills and outlines that carry
/// status and error colour without shouting.
fn tint(color: egui::Color32, alpha: u8) -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), alpha)
}

/// Adopt the launcher palette for `ui` and everything drawn inside it.
///
/// The change is scoped to this `Ui`'s descendants, so the session that
/// replaces the launcher later is unaffected.
fn apply_dialog_style(ui: &mut egui::Ui, palette: &Palette) {
    let style = ui.style_mut();
    // Tighter than the default 10px: the form's rhythm comes from its
    // explicit `add_space` calls, and the default spacing between every
    // label and field is what pushes the card past a dialog-sized
    // window.
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(14.0, 6.0);
    style.spacing.interact_size.y = 32.0;
    style.spacing.icon_width = 15.0;
    style.spacing.icon_width_inner = 9.0;
    style.spacing.icon_spacing = 6.0;

    let visuals = &mut style.visuals;
    visuals.panel_fill = palette.bg;
    visuals.window_fill = palette.surface;
    visuals.window_stroke = egui::Stroke::new(1.0, palette.border);
    visuals.window_corner_radius = egui::CornerRadius::same(10);
    visuals.menu_corner_radius = egui::CornerRadius::same(8);
    visuals.extreme_bg_color = palette.inset;
    visuals.text_edit_bg_color = Some(palette.inset);
    visuals.override_text_color = Some(palette.text);
    visuals.weak_text_color = Some(palette.dim);
    visuals.hyperlink_color = palette.accent;
    visuals.error_fg_color = palette.red;
    visuals.warn_fg_color = palette.amber;
    visuals.selection.bg_fill = palette.selection;
    // Also the outline of a focused text edit.
    visuals.selection.stroke = egui::Stroke::new(1.0, palette.accent);

    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = palette.surface;
    widgets.noninteractive.weak_bg_fill = palette.surface;
    widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, palette.border);
    widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, palette.text);
    widgets.noninteractive.corner_radius = egui::CornerRadius::same(6);
    widgets.noninteractive.expansion = 0.0;

    widgets.inactive.bg_fill = palette.inset;
    widgets.inactive.weak_bg_fill = palette.button;
    widgets.inactive.bg_stroke = egui::Stroke::new(1.0, palette.border);
    widgets.inactive.fg_stroke = egui::Stroke::new(1.0, palette.text);
    widgets.inactive.corner_radius = egui::CornerRadius::same(6);
    widgets.inactive.expansion = 0.0;

    for hovered in [&mut widgets.hovered, &mut widgets.active, &mut widgets.open] {
        hovered.bg_fill = palette.inset;
        hovered.weak_bg_fill = palette.button_hover;
        hovered.bg_stroke = egui::Stroke::new(1.0, palette.accent);
        hovered.fg_stroke = egui::Stroke::new(1.0, palette.text);
        hovered.corner_radius = egui::CornerRadius::same(6);
        hovered.expansion = 0.0;
    }
}

/// The small brand labels, for a header that also carries a widget on
/// the right.
fn kicker_labels(ui: &mut egui::Ui, palette: &Palette) {
    ui.label(
        egui::RichText::new("RYLL")
            .size(10.5)
            .strong()
            .color(palette.accent),
    );
    ui.label(
        egui::RichText::new("\u{00b7}")
            .size(10.5)
            .color(palette.dim),
    );
    ui.label(
        egui::RichText::new("PROXMOX VE")
            .size(10.5)
            .strong()
            .color(palette.dim),
    );
}

/// The small brand line above each screen's heading.
fn kicker(ui: &mut egui::Ui, palette: &Palette) {
    ui.horizontal(|ui| kicker_labels(ui, palette));
}

/// A profile's label in the picker: node name and endpoint.
fn profile_choice_label(profile: &ProxmoxProfile) -> String {
    let endpoint = crate::proxmox::profile_endpoint_string(profile)
        .unwrap_or_else(|| format!("{}:{}", profile.host, profile.port));
    format!("{}  \u{00b7}  {endpoint}", profile.name)
}

/// A rounded surface for a group of related controls.
fn card<R>(ui: &mut egui::Ui, palette: &Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(palette.surface)
        .stroke(egui::Stroke::new(1.0, palette.border))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(16))
        .show(ui, add)
        .inner
}

/// A sunken, bordered surface for read-only values.
fn inset<R>(ui: &mut egui::Ui, palette: &Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(palette.inset)
        .stroke(egui::Stroke::new(1.0, palette.border))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// The shared look for every text field in the login card.
fn text_edit<'a>(value: &'a mut String, hint: &str, password: bool) -> egui::TextEdit<'a> {
    let mut edit = egui::TextEdit::singleline(value)
        .hint_text(hint)
        .desired_width(f32::INFINITY)
        .margin(egui::Margin::symmetric(10, 7));
    if password {
        edit = edit.password(true);
    }
    edit
}

/// A labelled, full-width text field for the login card.
fn text_field(
    ui: &mut egui::Ui,
    palette: &Palette,
    label: &str,
    value: &mut String,
    hint: &str,
    password: bool,
) {
    ui.label(egui::RichText::new(label).size(12.0).color(palette.dim));
    ui.add_space(4.0);
    ui.add(text_edit(value, hint, password));
}

/// Split a stored endpoint into the URL the form shows (without its
/// port) and the port, so the two can be edited separately. A missing
/// port becomes Proxmox's 8006, and a path suffix such as `/api2/json`
/// is stripped by the same normalisation the connection uses.
fn split_endpoint(raw: &str) -> (String, String) {
    match crate::proxmox::normalize_base_url(raw) {
        Ok(mut url) => {
            let port = url
                .port_or_known_default()
                .unwrap_or(crate::proxmox::DEFAULT_PORT);
            let _ = url.set_port(None);
            (
                url.to_string().trim_end_matches('/').to_string(),
                port.to_string(),
            )
        }
        Err(_) => (
            raw.trim().to_string(),
            crate::proxmox::DEFAULT_PORT.to_string(),
        ),
    }
}

/// Compose the URL and Port form fields into the endpoint to connect to.
///
/// A blank port means 8006. A port typed into the URL itself is refused
/// rather than silently overridden, because the two fields would
/// otherwise disagree about where the request goes.
fn compose_endpoint(url: &str, port: &str) -> Result<String, String> {
    let raw = url.trim();
    if raw.is_empty() {
        return Err("Enter the Proxmox VE URL, such as https://pve.example".to_string());
    }
    let port = match port.trim() {
        "" => crate::proxmox::DEFAULT_PORT,
        text => match text.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => return Err("Enter the Proxmox port as a number between 1 and 65535".to_string()),
        },
    };
    let endpoint = crate::proxmox::normalize_base_url(raw)
        .map_err(|error| friendly_endpoint_error(&format!("{error:#}")))?;
    if crate::proxmox::has_explicit_port(raw) {
        let named = endpoint
            .port()
            .or_else(|| endpoint.port_or_known_default())
            .unwrap_or(port);
        return Err(format!(
            "The URL names port {named}; remove the port from the URL and set the Port field instead."
        ));
    }
    Ok(crate::proxmox::endpoint_with_port(endpoint, port))
}

/// Drop the `--proxmox:` prefix from URL errors so they read as form
/// validation messages rather than command-line ones.
fn friendly_endpoint_error(message: &str) -> String {
    message
        .strip_prefix("--proxmox: ")
        .unwrap_or(message)
        .to_string()
}

/// A dim caption indented to sit under a checkbox.
fn indented_hint(ui: &mut egui::Ui, palette: &Palette, text: &str) {
    ui.horizontal_top(|ui| {
        ui.add_space(22.0);
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(text).size(11.0).color(palette.dim));
        });
    });
}

/// The dialog's single filled action, drawn at a caller-chosen width so
/// it can fill a footer or share a row with a secondary button.
fn primary_button(
    ui: &mut egui::Ui,
    palette: &Palette,
    label: &str,
    width: f32,
    height: f32,
) -> egui::Response {
    ui.scope(|ui| {
        let widgets = &mut ui.style_mut().visuals.widgets;
        for visuals in [
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ] {
            visuals.weak_bg_fill = palette.accent;
            visuals.bg_fill = palette.accent;
            visuals.bg_stroke = egui::Stroke::NONE;
            visuals.fg_stroke = egui::Stroke::new(1.0, palette.on_accent);
            visuals.corner_radius = egui::CornerRadius::same(7);
            visuals.expansion = 0.0;
        }
        widgets.hovered.weak_bg_fill = palette.accent_hover;
        widgets.active.weak_bg_fill = palette.accent_hover;
        ui.add_sized(
            [width, height],
            egui::Button::new(egui::RichText::new(label).size(13.5).strong()),
        )
    })
    .inner
}

/// One half of the authentication selector: filled with the accent when
/// selected, a quiet bordered button when not.
fn segment_button(
    ui: &mut egui::Ui,
    palette: &Palette,
    selected: bool,
    label: &str,
    width: f32,
) -> egui::Response {
    let text = egui::RichText::new(label).size(12.5).color(if selected {
        palette.on_accent
    } else {
        palette.text
    });
    // `selected` carries the accessibility state as well as the look;
    // the explicit fill keeps the accent style instead of `visuals.selection`.
    let button = if selected {
        egui::Button::new(text)
            .selected(true)
            .fill(palette.accent)
            .stroke(egui::Stroke::NONE)
    } else {
        egui::Button::new(text).selected(false)
    };
    ui.add_sized(
        [width, 32.0],
        button.corner_radius(egui::CornerRadius::same(6)),
    )
}

/// A small status chip for a guest row.
fn status_pill(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(tint(color, 30))
        .stroke(egui::Stroke::new(1.0, tint(color, 90)))
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(10.5).strong().color(color));
        });
}

/// The guest row's action label. A guest whose display cannot carry SPICE
/// says so where the user would otherwise click Connect, rather than
/// adding another chip to the row; `SPICE?` covers the case where the
/// display configuration could not be read.
fn connect_label(vm: &ProxmoxVm) -> &'static str {
    if vm.template {
        return "Connect";
    }
    match vm.supports_spice() {
        Some(false) => "No SPICE",
        None => "SPICE?",
        Some(true) => "Connect",
    }
}

/// One guest in the picker: name and identity on the left, display and
/// run state, then the connect action on the right.
fn vm_row(ui: &mut egui::Ui, palette: &Palette, vm: &ProxmoxVm, connect: &mut Option<ProxmoxVm>) {
    egui::Frame::new()
        .fill(palette.surface)
        .stroke(egui::Stroke::new(1.0, palette.border))
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::symmetric(13, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_max_width((ui.available_width() - 200.0).max(100.0));
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(vm.display_name())
                                .size(13.0)
                                .strong()
                                .color(palette.text),
                        )
                        .truncate(),
                    );
                    ui.add_space(3.0);
                    let identity = match vm.display_type() {
                        Some(display) => format!(
                            "VMID {}  \u{00b7}  node {}  \u{00b7}  display {display}",
                            vm.vmid, vm.node
                        ),
                        None => format!("VMID {}  \u{00b7}  node {}", vm.vmid, vm.node),
                    };
                    ui.label(egui::RichText::new(identity).size(11.0).color(palette.dim));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let connectable = vm.is_connectable();
                    let label = connect_label(vm);
                    let button = if connectable {
                        egui::Button::new(
                            egui::RichText::new(label)
                                .size(11.5)
                                .strong()
                                .color(palette.on_accent),
                        )
                        .fill(palette.accent)
                        .stroke(egui::Stroke::NONE)
                        .corner_radius(egui::CornerRadius::same(6))
                        .min_size(egui::vec2(88.0, 27.0))
                    } else {
                        egui::Button::new(egui::RichText::new(label).size(11.5))
                            .corner_radius(egui::CornerRadius::same(6))
                            .min_size(egui::vec2(88.0, 27.0))
                    };
                    let response = ui
                        .add_enabled(connectable, button)
                        .on_disabled_hover_text(vm.connection_blocker().unwrap_or_default());
                    if response.clicked() {
                        *connect = Some(vm.clone());
                    }
                    ui.add_space(6.0);
                    let (label, colour) = if vm.template {
                        ("template", palette.dim)
                    } else if vm.is_running() {
                        ("running", palette.green)
                    } else {
                        (vm.status.as_deref().unwrap_or("unknown"), palette.amber)
                    };
                    status_pill(ui, label, colour);
                });
            });
        });
}

pub(crate) struct ProxmoxLauncher {
    // Form state
    url: String,
    /// The API port, kept apart from the URL so the form can default it
    /// to Proxmox's 8006 rather than making the user type it.
    port: String,
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
    /// Every saved profile, shown by the login form's picker.
    profiles: Vec<ProxmoxProfile>,
    /// The picker selection; `None` is "New connection".
    selected_profile: Option<usize>,
    remember_token: bool,
    save_requested: bool,
    saved_token_present: bool,
    token_from_saved: bool,
    saved_url: Option<String>,
}

impl ProxmoxLauncher {
    pub(crate) fn new(settings: ProxmoxLaunchSettings) -> Self {
        let token_parts = settings.token_parts();
        let (use_token, token_id, token_secret) = match token_parts {
            Some((id, secret)) => (true, id, secret),
            None => (false, String::new(), String::new()),
        };
        let auto_login = settings.can_auto_login();
        let ca_label = settings
            .ca_path
            .as_ref()
            .map(|path| path.display().to_string());
        let (url, port) = split_endpoint(&settings.url);
        Self {
            url,
            port,
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
            stage: Stage::Login,
            busy_message: String::new(),
            client: None,
            vms: Vec::new(),
            error: None,
            rx: None,
            ready_config: None,
            profiles: settings.profiles,
            selected_profile: settings.selected_profile,
            remember_token: settings.save_requested,
            save_requested: settings.save_requested,
            saved_token_present: settings.saved_token_present,
            token_from_saved: settings.token_from_saved,
            saved_url: settings.saved_url,
        }
    }

    /// Start on the VM list for a login that finished before the window
    /// existed. It is handled exactly like a login performed in the
    /// launcher — the profile is saved and `--proxmox-vm` is honoured — so
    /// an automatic login behaves like pressing **Connect**.
    pub(crate) fn start_logged_in(&mut self, login: ProxmoxLogin) {
        self.accept_login(login.client, login.vms, login.node_name);
    }

    fn accept_login(&mut self, client: ProxmoxClient, vms: Vec<ProxmoxVm>, node_name: String) {
        tracing::info!("Proxmox: logged in; {} QEMU VM(s) visible", vms.len());
        self.client = Some(client);
        self.vms = vms;
        self.stage = Stage::Vms;
        self.error = None;
        if self.save_requested && !self.use_token {
            tracing::warn!(
                "--proxmox-save stores only API tokens; the endpoint was saved \
                 without a token"
            );
        }
        self.save_profile(&node_name);
        self.maybe_auto_vm();
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

    /// The endpoint the form currently describes, with the Port field
    /// applied.
    fn endpoint(&self) -> Result<String, String> {
        compose_endpoint(&self.url, &self.port)
    }

    pub(crate) fn ui(&mut self, ui: &mut egui::Ui) {
        if self.poll() {
            // A request finished and changed the screen. Ask for another
            // pass: the one that handled the event can race the window
            // becoming visible, and without a follow-up repaint a
            // background auto-login's VM list can sit on an unpresented
            // surface until the next input event.
            ui.ctx().request_repaint();
        }

        if self.auto_login && self.stage == Stage::Login && self.rx.is_none() {
            self.auto_login = false;
            self.begin_login();
        }

        let palette = Palette::for_style(ui.style());
        apply_dialog_style(ui, &palette);

        // eframe hands an app a bare `Ui` with no background, and the
        // session's own panels are not drawing while the launcher owns
        // the window.
        ui.painter().rect_filled(ui.max_rect(), 0, palette.bg);

        egui::Frame::new()
            .inner_margin(egui::Margin {
                left: 0,
                right: 0,
                top: VERTICAL_MARGIN as i8,
                bottom: VERTICAL_MARGIN as i8,
            })
            .show(ui, |ui| {
                // Cap the column and centre it, so a widened dialog keeps
                // a readable measure instead of stretching its fields.
                let width = (ui.available_width() - 2.0 * SIDE_MARGIN).clamp(260.0, CONTENT_WIDTH);
                let left = ((ui.available_width() - width) * 0.5).max(0.0);
                ui.horizontal_top(|ui| {
                    ui.add_space(left);
                    ui.vertical(|ui| {
                        ui.set_width(width);
                        match self.stage {
                            Stage::Busy => self.busy_ui(ui, &palette),
                            Stage::Login => self.login_ui(ui, &palette),
                            Stage::Vms => self.vms_ui(ui, &palette),
                        }
                    });
                });
            });

        if self.rx.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
    }

    /// Poll the in-flight request, returning whether it finished (and so
    /// whether the screen changed this frame).
    fn poll(&mut self) -> bool {
        let Some(rx) = &self.rx else {
            return false;
        };
        match rx.try_recv() {
            Ok(event) => {
                self.rx = None;
                self.handle(event);
                true
            }
            Err(TryRecvError::Empty) => false,
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
                true
            }
        }
    }

    fn handle(&mut self, event: LauncherEvent) {
        match event {
            LauncherEvent::LoggedIn(Ok((client, vms, node_name))) => {
                self.accept_login(client, vms, node_name);
            }
            LauncherEvent::LoggedIn(Err(error)) => {
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
        let url = match self.endpoint() {
            Ok(url) => url,
            Err(message) => {
                self.error = Some(message);
                return;
            }
        };

        let auth = if self.use_token {
            if self.token_from_saved {
                // The form token came from a saved server. Do not send it
                // to an endpoint that does not match, and treat a saved
                // token with no comparable endpoint the same way: clear
                // it and make the user re-enter one deliberately.
                let mismatch = self
                    .saved_url
                    .as_deref()
                    .map(|saved| !crate::proxmox::endpoint_matches(&url, saved))
                    .unwrap_or(true);
                if mismatch {
                    let message = match self.saved_url.as_deref() {
                        Some(saved_url) => format!(
                            "The saved token belongs to {saved_url} and was cleared because \
                             the URL changed. Enter a token for the new endpoint."
                        ),
                        None => "The saved token has no endpoint to check, so it was cleared. \
                                 Enter a token for this endpoint."
                            .to_string(),
                    };
                    self.token_id.clear();
                    self.token_secret.clear();
                    self.saved_token_present = false;
                    self.token_from_saved = false;
                    self.error = Some(message);
                    return;
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
            .and_then(|client| {
                let (vms, nodes) = client.list_inventory()?;
                let node = client.server_node_name(&nodes);
                Ok((client, vms, node))
            });
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
        if let Some(blocker) = vm.connection_blocker() {
            self.error = Some(format!("VM {} ({}): {blocker}", vm.vmid, vm.display_name()));
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

    /// The endpoint the form describes, split into the host and port a
    /// saved profile stores.
    fn profile_endpoint(&self) -> Result<(String, u16), String> {
        let endpoint = compose_endpoint(&self.url, &self.port)?;
        crate::proxmox::endpoint_parts(&endpoint)
            .map_err(|error| friendly_endpoint_error(&format!("{error:#}")))
    }

    /// Persist the connected endpoint as a profile named after the
    /// Proxmox node. Called after every successful login, so the profile
    /// list grows with the servers the user actually reaches.
    fn save_profile(&mut self, node_name: &str) {
        let (host, port) = match self.profile_endpoint() {
            Ok(parts) => parts,
            Err(message) => {
                tracing::warn!("Proxmox: not saving the profile: {message}");
                return;
            }
        };
        let existing = self
            .profiles
            .iter()
            .find(|profile| config_dir::profile_is(profile, &host, port))
            .cloned();
        let token_dirty = self.use_token && (self.remember_token || self.save_requested);
        let token = if token_dirty {
            let id = self.token_id.trim();
            if id.is_empty() || self.token_secret.is_empty() {
                existing.as_ref().and_then(|profile| profile.token.clone())
            } else {
                Some(format!("{id}={}", self.token_secret))
            }
        } else {
            // A password login (or a token login that did not ask to be
            // remembered) still updates the endpoint, but must not
            // discard a token already saved for this host.
            existing.as_ref().and_then(|profile| profile.token.clone())
        };
        let profile = ProxmoxProfile {
            name: node_name.to_string(),
            host: host.clone(),
            port,
            token,
            insecure: self.insecure,
            ca: if self.insecure {
                None
            } else {
                self.ca_path.clone()
            },
        };
        match config_dir::upsert_proxmox_profile(&profile) {
            Ok((path, saved)) => {
                tracing::info!(
                    "Proxmox: saved profile '{}' ({}:{}) in {}",
                    profile.name,
                    profile.host,
                    profile.port,
                    path.display()
                );
                self.profiles = saved.profiles;
                self.selected_profile = self
                    .profiles
                    .iter()
                    .position(|saved| config_dir::profile_is(saved, &host, port));
                self.saved_token_present = profile.token.is_some();
                self.token_from_saved = profile.token.is_some();
                self.saved_url = crate::proxmox::profile_endpoint_string(&profile);
                self.remember_token = profile.token.is_some() || self.save_requested;
            }
            Err(error) => {
                let message = format!("Could not save the Proxmox profile: {error:#}");
                tracing::warn!("{message}");
                self.error = Some(message);
            }
        }
    }

    /// Remove the saved token from the profile for the endpoint in the
    /// form, keeping the profile's endpoint and TLS settings.
    fn forget_saved_token(&mut self) {
        let (host, port) = match self.profile_endpoint() {
            Ok(parts) => parts,
            Err(message) => {
                self.error = Some(message);
                return;
            }
        };
        match config_dir::forget_proxmox_token(&host, port) {
            Ok(true) => {
                self.saved_token_present = false;
                self.token_from_saved = false;
                self.saved_url = None;
                self.remember_token = false;
                self.use_token = false;
                self.token_id.clear();
                self.token_secret.clear();
                if let Some(profile) = self
                    .profiles
                    .iter_mut()
                    .find(|profile| config_dir::profile_is(profile, &host, port))
                {
                    profile.token = None;
                }
                tracing::info!("Proxmox: removed the saved token for {host}:{port}");
            }
            Ok(false) => {
                self.error = Some(format!(
                    "No saved token was found for {host}:{port}; nothing was removed."
                ));
            }
            Err(error) => {
                let message = format!("Could not remove the saved Proxmox token: {error:#}");
                tracing::warn!("{message}");
                self.error = Some(message);
            }
        }
    }

    /// The login form's saved-profile picker. "New connection" clears
    /// the form for a host that is not saved yet.
    fn profile_picker(&mut self, ui: &mut egui::Ui, palette: &Palette) {
        if self.profiles.is_empty() {
            return;
        }
        let choices: Vec<(Option<usize>, String)> =
            std::iter::once((None, "New connection".to_string()))
                .chain(
                    self.profiles
                        .iter()
                        .enumerate()
                        .map(|(index, profile)| (Some(index), profile_choice_label(profile))),
                )
                .collect();
        let selected_text = self
            .selected_profile
            .and_then(|index| self.profiles.get(index))
            .map(profile_choice_label)
            .unwrap_or_else(|| "New connection".to_string());
        let mut choice = self.selected_profile;
        // In a narrow window the combo shares the header row with the
        // brand labels, so cap it to what is left rather than overlap.
        let width = ui.available_width().clamp(120.0, 235.0);
        egui::ComboBox::from_id_salt("proxmox_profile")
            .selected_text(
                egui::RichText::new(selected_text)
                    .size(11.0)
                    .color(palette.text),
            )
            .width(width)
            .show_ui(ui, |ui| {
                for (value, label) in &choices {
                    ui.selectable_value(&mut choice, *value, label);
                }
            });
        if choice != self.selected_profile {
            self.select_profile(choice);
        }
    }

    /// Load a profile into the form, or clear it for a new connection.
    fn select_profile(&mut self, choice: Option<usize>) {
        self.error = None;
        self.selected_profile = choice;
        self.saved_url = None;
        self.token_from_saved = false;
        self.saved_token_present = false;
        self.token_id.clear();
        self.token_secret.clear();
        // Credentials typed for another host must not follow the
        // selection to this one.
        self.username.clear();
        self.password.clear();
        let Some(profile) = choice.and_then(|index| self.profiles.get(index)).cloned() else {
            self.url.clear();
            self.port = crate::proxmox::DEFAULT_PORT.to_string();
            self.remember_token = self.save_requested;
            self.use_token = false;
            self.insecure = false;
            self.ca_pem = None;
            self.ca_path = None;
            self.ca_label = None;
            return;
        };
        self.url = profile.host.clone();
        self.port = profile.port.to_string();
        match crate::proxmox::tls_from_profile(&profile) {
            Ok(tls) => {
                self.ca_pem = tls.ca_pem;
                self.insecure = tls.insecure;
            }
            Err(error) => {
                self.ca_pem = None;
                self.insecure = profile.insecure;
                self.error = Some(format!("{error:#}"));
            }
        }
        self.ca_path = profile.ca.clone();
        self.ca_label = profile.ca.as_ref().map(|path| path.display().to_string());
        self.use_token = profile.token.is_some();
        if let Some(token) = profile.token.as_deref() {
            if let Some((id, secret)) = token.split_once('=') {
                self.token_id = id.to_string();
                self.token_secret = secret.to_string();
            }
        }
        self.remember_token = profile.token.is_some() || self.save_requested;
        self.token_from_saved = profile.token.is_some();
        self.saved_token_present = profile.token.is_some();
        self.saved_url = crate::proxmox::profile_endpoint_string(&profile);
    }

    fn logout(&mut self) {
        self.client = None;
        self.vms.clear();
        self.error = None;
        self.stage = Stage::Login;
    }

    /// A tinted banner for a failed login, list or console request.
    fn error_banner(&self, ui: &mut egui::Ui, palette: &Palette) {
        let Some(error) = &self.error else {
            return;
        };
        egui::Frame::new()
            .fill(tint(palette.red, 26))
            .stroke(egui::Stroke::new(1.0, tint(palette.red, 110)))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(12, 9))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_top(|ui| {
                    ui.label(
                        egui::RichText::new("\u{26a0}")
                            .size(13.0)
                            .color(palette.red),
                    );
                    ui.add_space(2.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(error).size(12.0).color(palette.red));
                    });
                });
            });
        ui.add_space(12.0);
    }

    fn login_ui(&mut self, ui: &mut egui::Ui, palette: &Palette) {
        let mut submit = false;

        // Reserve the footer before the form is laid out: the form
        // scrolls when the window is short or an error banner appears,
        // but Connect stays visible. The budget is a fixed estimate
        // because the footer is drawn after the scroll area; it is
        // deliberately generous, since overshooting only leaves a gap
        // while undershooting clips the caption.
        let footer_height = 96.0;
        let content_height = (ui.available_height() - footer_height).max(160.0);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(content_height)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    kicker_labels(ui, palette);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        self.profile_picker(ui, palette);
                    });
                });
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Connect to Proxmox VE")
                        .size(24.0)
                        .strong()
                        .color(palette.text),
                );
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Sign in to list this account's QEMU guests, then open a SPICE console.",
                    )
                    .size(12.5)
                    .color(palette.dim),
                );
                ui.add_space(14.0);
                self.error_banner(ui, palette);

                card(ui, palette, |ui| {
                    ui.set_width(ui.available_width());

                    // The port has its own field, prefilled with
                    // Proxmox's standard 8006, so the URL is just the
                    // scheme and host in the common case.
                    let port_width = 82.0;
                    let spacing = ui.spacing().item_spacing.x;
                    let url_width = (ui.available_width() - port_width - spacing).max(160.0);
                    ui.horizontal_top(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(url_width);
                            ui.label(
                                egui::RichText::new("Proxmox URL")
                                    .size(12.0)
                                    .color(palette.dim),
                            );
                            ui.add_space(4.0);
                            ui.add(text_edit(&mut self.url, "https://pve.example", false));
                        });
                        ui.vertical(|ui| {
                            ui.set_width(port_width);
                            ui.label(
                                egui::RichText::new("Port").size(12.0).color(palette.dim),
                            );
                            ui.add_space(4.0);
                            ui.add(text_edit(&mut self.port, "8006", false).char_limit(5));
                        });
                    });
                    ui.add_space(12.0);

                    let spacing = ui.spacing().item_spacing.x;
                    let segment_width = ((ui.available_width() - spacing) * 0.5).max(80.0);
                    let mut use_token = self.use_token;
                    ui.horizontal(|ui| {
                        if segment_button(
                            ui,
                            palette,
                            !use_token,
                            "Username / password",
                            segment_width,
                        )
                        .clicked()
                        {
                            use_token = false;
                        }
                        if segment_button(ui, palette, use_token, "API token", segment_width)
                            .clicked()
                        {
                            use_token = true;
                        }
                    });
                    self.use_token = use_token;
                    ui.add_space(11.0);

                    if self.use_token {
                        text_field(
                            ui,
                            palette,
                            "Token ID",
                            &mut self.token_id,
                            "user@realm!tokenid",
                            false,
                        );
                        ui.add_space(9.0);
                        text_field(
                            ui,
                            palette,
                            "Token secret",
                            &mut self.token_secret,
                            "",
                            true,
                        );
                        ui.add_space(9.0);
                        ui.checkbox(
                            &mut self.remember_token,
                            egui::RichText::new("Remember this token").size(12.5),
                        );
                    } else {
                        text_field(
                            ui,
                            palette,
                            "Username",
                            &mut self.username,
                            "user@realm",
                            false,
                        );
                        ui.add_space(9.0);
                        text_field(ui, palette, "Password", &mut self.password, "", true);
                    }

                    ui.add_space(12.0);
                    ui.add_enabled(
                        self.ca_label.is_none(),
                        egui::Checkbox::new(
                            &mut self.insecure,
                            egui::RichText::new("Accept the certificate without verifying it")
                                .size(12.5),
                        ),
                    )
                    .on_disabled_hover_text("A CA is configured; certificate verification stays on")
                    .on_hover_text(
                        "Proxmox installs a self-signed certificate by default. Prefer \
                         --proxmox-ca when the certificate is stable.",
                    );
                    ui.add_space(3.0);
                    indented_hint(
                        ui,
                        palette,
                        if self.ca_label.is_some() {
                            "Verification stays on: a certificate authority is configured below."
                        } else {
                            "Self-signed certificates are common; prefer --proxmox-ca when available."
                        },
                    );

                    ui.add_space(8.0);
                    ui.collapsing(
                        egui::RichText::new("Advanced")
                            .size(12.5)
                            .color(palette.dim),
                        |ui| {
                            if let Some(ca_label) = &self.ca_label {
                                ui.label(
                                    egui::RichText::new("Certificate authority")
                                        .size(12.0)
                                        .color(palette.dim),
                                );
                                ui.add_space(5.0);
                                inset(ui, palette, |ui| {
                                    ui.label(
                                        egui::RichText::new(ca_label)
                                            .monospace()
                                            .size(11.5)
                                            .color(palette.text),
                                    );
                                });
                                ui.add_space(10.0);
                            }
                            text_field(
                                ui,
                                palette,
                                "SPICE proxy",
                                &mut self.proxy,
                                "leave blank to let Proxmox choose the node",
                                false,
                            );
                        },
                    );
                });
            });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(12.0);
        let connect_width = ui.available_width();
        if primary_button(ui, palette, "Connect", connect_width, 38.0).clicked() {
            submit = true;
        }
        ui.add_space(7.0);
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new(if self.use_token {
                    "Saves to ~/.ryll when Remember is ticked. Passwords are never stored."
                } else {
                    "Passwords are never stored."
                })
                .size(11.0)
                .color(palette.dim),
            );
        });

        if ui.ctx().input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
        if submit {
            self.begin_login();
            // The form was drawn before the submit, so a validation
            // error only exists now; draw it on the next pass.
            ui.ctx().request_repaint();
        }
    }

    fn busy_ui(&mut self, ui: &mut egui::Ui, palette: &Palette) {
        ui.add_space(56.0);
        ui.vertical_centered(|ui| {
            ui.add(egui::Spinner::new().size(24.0).color(palette.accent));
            ui.add_space(14.0);
            ui.label(
                egui::RichText::new(&self.busy_message)
                    .size(13.0)
                    .color(palette.text),
            );
            ui.add_space(22.0);
            let label = if self.client.is_some() {
                "Back to the VM list"
            } else {
                "Cancel"
            };
            if ui
                .add_sized(
                    [160.0, 32.0],
                    egui::Button::new(egui::RichText::new(label).size(12.5)),
                )
                .clicked()
            {
                // Drop the receiver so a result that arrives after the
                // user left this screen cannot start a session behind
                // their back.
                self.rx = None;
                self.stage = if self.client.is_some() {
                    Stage::Vms
                } else {
                    Stage::Login
                };
                self.busy_message.clear();
                ui.ctx().request_repaint();
            }
        });
        self.error_banner(ui, palette);
    }

    fn vms_ui(&mut self, ui: &mut egui::Ui, palette: &Palette) {
        let mut refresh = false;
        let mut logout = false;
        let mut forget = false;

        // Templates cannot mint a console, so the picker leaves them
        // out rather than showing a row whose Connect is always disabled.
        let guests: Vec<&ProxmoxVm> = self.vms.iter().filter(|vm| !vm.template).collect();

        kicker(ui, palette);
        ui.add_space(10.0);
        ui.label(
            egui::RichText::new("Choose a guest")
                .size(24.0)
                .strong()
                .color(palette.text),
        );
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(if guests.is_empty() {
                "Only running guests with a SPICE-capable display can be connected.".to_owned()
            } else {
                format!(
                    "{} QEMU guest(s). Only running guests with a SPICE-capable display \
                     can be connected.",
                    guests.len()
                )
            })
            .size(12.5)
            .color(palette.dim),
        );
        ui.add_space(14.0);
        self.error_banner(ui, palette);

        ui.horizontal_wrapped(|ui| {
            if ui
                .add(egui::Button::new(egui::RichText::new("Refresh").size(12.0)))
                .clicked()
            {
                refresh = true;
            }
            if ui
                .add(egui::Button::new(
                    egui::RichText::new("Use a different account").size(12.0),
                ))
                .clicked()
            {
                logout = true;
            }
            if self.saved_token_present
                && ui
                    .add(egui::Button::new(
                        egui::RichText::new("Forget saved token").size(12.0),
                    ))
                    .clicked()
            {
                forget = true;
            }
        });
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(10.0);

        if guests.is_empty() {
            inset(ui, palette, |ui| {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("No connectable QEMU guests")
                            .size(13.0)
                            .color(palette.text),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(if self.vms.is_empty() {
                            "No QEMU guests are visible to this account. Check that the login has \
                             VM.Audit on the guest's /vms path, or use a different account."
                        } else {
                            "Every QEMU guest visible to this account is a template. Start a \
                             clone from a template in Proxmox to get a console."
                        })
                        .size(11.5)
                        .color(palette.dim),
                    );
                });
                ui.add_space(20.0);
            });
        } else {
            let mut connect: Option<ProxmoxVm> = None;
            let height = ui.available_height().max(120.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(height)
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 8.0;
                    for vm in &guests {
                        vm_row(ui, palette, vm, &mut connect);
                    }
                });
            if let Some(vm) = connect {
                self.begin_spice(vm);
                // A refused console (or the busy screen) is a new state
                // drawn on the next pass.
                ui.ctx().request_repaint();
            }
        }

        if forget {
            self.forget_saved_token();
            ui.ctx().request_repaint();
        }
        if refresh {
            self.begin_list();
        }
        if logout {
            self.logout();
            ui.ctx().request_repaint();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{compose_endpoint, connect_label, split_endpoint};
    use crate::proxmox::ProxmoxVm;

    #[test]
    fn the_action_label_says_when_spice_is_missing() {
        let vm = |display: Option<&str>, status: &str, template: bool| ProxmoxVm {
            vmid: 100,
            name: None,
            node: "pve1".to_string(),
            status: Some(status.to_string()),
            template,
            display: display.map(str::to_string),
        };
        assert_eq!(connect_label(&vm(Some("qxl"), "running", false)), "Connect");
        assert_eq!(
            connect_label(&vm(Some("virtio"), "running", false)),
            "Connect"
        );
        assert_eq!(
            connect_label(&vm(Some("std"), "running", false)),
            "No SPICE"
        );
        assert_eq!(connect_label(&vm(None, "running", false)), "SPICE?");
        // A stopped guest's action stays Connect; the disabled hover
        // carries the run-state reason.
        assert_eq!(connect_label(&vm(Some("qxl"), "stopped", false)), "Connect");
        assert_eq!(connect_label(&vm(None, "stopped", true)), "Connect");
    }

    #[test]
    fn split_endpoint_separates_the_port_and_defaults_to_8006() {
        assert_eq!(
            split_endpoint("https://pve.example:8006"),
            ("https://pve.example".to_string(), "8006".to_string())
        );
        assert_eq!(
            split_endpoint("https://pve.example:8443"),
            ("https://pve.example".to_string(), "8443".to_string())
        );
        assert_eq!(
            split_endpoint("https://pve.example"),
            ("https://pve.example".to_string(), "8006".to_string())
        );
        assert_eq!(
            split_endpoint("pve.example"),
            ("https://pve.example".to_string(), "8006".to_string())
        );
    }

    #[test]
    fn split_endpoint_keeps_the_scheme_and_strips_the_api_path() {
        assert_eq!(
            split_endpoint("http://pve.example:8006"),
            ("http://pve.example".to_string(), "8006".to_string())
        );
        assert_eq!(
            split_endpoint("https://pve.example:8006/api2/json"),
            ("https://pve.example".to_string(), "8006".to_string())
        );
        assert_eq!(
            split_endpoint("https://[::1]:8006"),
            ("https://[::1]".to_string(), "8006".to_string())
        );
    }

    #[test]
    fn split_endpoint_shows_an_explicit_default_port() {
        assert_eq!(
            split_endpoint("https://pve.example:443"),
            ("https://pve.example".to_string(), "443".to_string())
        );
    }

    #[test]
    fn compose_endpoint_applies_the_port_field() {
        assert_eq!(
            compose_endpoint("https://pve.example", "").expect("endpoint"),
            "https://pve.example:8006"
        );
        assert_eq!(
            compose_endpoint("pve.example", "8006").expect("endpoint"),
            "https://pve.example:8006"
        );
        assert_eq!(
            compose_endpoint("https://pve.example", "8443").expect("endpoint"),
            "https://pve.example:8443"
        );
        assert_eq!(
            compose_endpoint("https://pve.example/api2/json", "8443").expect("endpoint"),
            "https://pve.example:8443"
        );
    }

    #[test]
    fn compose_endpoint_keeps_a_scheme_default_port() {
        assert_eq!(
            compose_endpoint("https://pve.example", "443").expect("endpoint"),
            "https://pve.example:443"
        );
        assert_eq!(
            compose_endpoint("http://pve.example", "80").expect("endpoint"),
            "http://pve.example:80"
        );
    }

    #[test]
    fn compose_endpoint_rejects_a_port_in_the_url() {
        let error = compose_endpoint("https://pve.example:8443", "8006").expect_err("refused");
        assert!(error.contains("remove the port from the URL"), "{error}");
        assert!(error.contains("8443"), "{error}");
    }

    #[test]
    fn compose_endpoint_rejects_an_invalid_port() {
        for port in ["0", "65536", "eight", "-1"] {
            let error = compose_endpoint("https://pve.example", port).expect_err("refused");
            assert!(error.contains("between 1 and 65535"), "{port}: {error}");
        }
    }

    #[test]
    fn compose_endpoint_rejects_an_empty_or_unsupported_url() {
        assert!(compose_endpoint("", "8006")
            .expect_err("refused")
            .contains("Proxmox VE URL"));
        assert!(compose_endpoint("ssh://pve.example", "8006")
            .expect_err("refused")
            .contains("unsupported URL scheme"));
    }
}
