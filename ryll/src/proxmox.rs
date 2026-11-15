//! Proxmox VE as a connection source.
//!
//! Proxmox exposes a guest's SPICE console as a `.vv` document:
//! `POST /api2/spiceconfig/nodes/{node}/qemu/{vmid}/spiceproxy` returns
//! the same INI keys a virt-viewer `.vv` file carries, including the
//! `proxy=` key that names the node's `spiceproxy` and the short-lived
//! ticket in `password`. That means the rest of ryll does not need a
//! Proxmox-specific connection path: this module logs in, lists the QEMU
//! guests the credentials can see, and hands the chosen guest's document
//! to [`Config::parse_vv_content`], exactly as `--url` and `--file` do.
//!
//! Two authentication methods are supported:
//!
//! - **Ticket**: `POST /api2/json/access/ticket` with a username and
//!   password. The returned ticket is sent as the `PVEAuthCookie`
//!   cookie, and mutating requests also carry `CSRFPreventionToken`.
//! - **API token**: `Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET`.
//!   Tokens are stateless and need no CSRF header.
//!
//! This module never calls a VM lifecycle endpoint: creating, starting,
//! stopping and reconfiguring guests are explicitly out of scope. It reads
//! each guest's configuration only to learn its display type, so the list
//! can say whether a SPICE console is possible.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, COOKIE};
use reqwest::StatusCode;
use serde::Deserialize;
use url::Url;

use crate::config::{read_secret_file, Args, Config};
use crate::config_dir::{self, ProxmoxProfile, SavedProxmox};

/// The port the Proxmox VE web/API daemon listens on by default. A URL
/// with no explicit port gets this one, so `--proxmox pve.example` works
/// as an operator expects.
pub const DEFAULT_PORT: u16 = 8006;

/// How many display-configuration probes run at once while a VM list is
/// built. One request per guest is required because the QEMU index does
/// not carry the display model; a handful at a time keeps a large
/// cluster's list from becoming a long serial chain without opening a
/// connection per guest at once.
const DISPLAY_PROBE_WORKERS: usize = 8;

/// How a [`ProxmoxClient`] authenticates.
#[derive(Clone)]
pub enum ProxmoxAuth {
    /// Username and password, exchanged for a short-lived ticket.
    Password { username: String, password: String },
    /// A Proxmox API token, normalised to
    /// `USER@REALM!TOKENID=SECRET` (without the `PVEAPIToken=` prefix).
    Token { token: String },
}

impl ProxmoxAuth {
    /// A human-readable label for the authentication method, safe to
    /// log because it contains no credential.
    pub fn method_name(&self) -> &'static str {
        match self {
            ProxmoxAuth::Password { .. } => "username/password",
            ProxmoxAuth::Token { .. } => "API token",
        }
    }
}

/// TLS settings for the Proxmox API connection.
#[derive(Clone, Default)]
pub struct ProxmoxTls {
    /// Accept any certificate. Proxmox's default self-signed certificate
    /// needs this, or `ca_pem`.
    pub insecure: bool,
    /// Additional trust anchors, in PEM form.
    pub ca_pem: Option<Vec<u8>>,
}

/// A QEMU guest as the Proxmox cluster resources endpoint describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxmoxVm {
    pub vmid: u32,
    pub name: Option<String>,
    pub node: String,
    pub status: Option<String>,
    /// Templates have a console configuration but cannot be started, so
    /// no SPICE ticket can be minted for them.
    pub template: bool,
    /// The guest's Proxmox display type (the type in its `vga`
    /// configuration, such as `qxl`, `virtio` or `std`), when the
    /// configuration could be read. `None` means the type is unknown:
    /// either the guest is a template, whose configuration ryll does not
    /// probe, or the request failed.
    pub display: Option<String>,
}

impl ProxmoxVm {
    /// The guest's name, or a stable fallback when Proxmox has none.
    pub fn display_name(&self) -> String {
        self.name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("VM {}", self.vmid))
    }

    /// Whether Proxmox reports the guest as running. Only a running
    /// guest can produce a SPICE console ticket.
    pub fn is_running(&self) -> bool {
        self.status.as_deref() == Some("running")
    }

    /// The guest's display type, when its configuration was read.
    pub fn display_type(&self) -> Option<&str> {
        self.display.as_deref()
    }

    /// Whether the display configuration runs a SPICE server.
    ///
    /// Proxmox only starts one for the QXL family and the VirtIO GPU
    /// family; a standard VGA, VMware, Cirrus, serial or absent display
    /// gets VNC or no graphical console, so no console document can be
    /// produced for it. `None` means the configuration could not be
    /// read, so support is unknown.
    pub fn supports_spice(&self) -> Option<bool> {
        self.display_type().map(display_type_supports_spice)
    }

    /// Why this guest cannot be given a SPICE console, or `None` when
    /// nothing rules it out. The message completes the sentence
    /// "VM 100 (web) …".
    ///
    /// An unreadable display configuration blocks the console. The list
    /// probes the configuration precisely so the picker can answer this
    /// question, and offering Connect for a guest whose display type is
    /// unknown is how a non-SPICE guest slips through: a failed probe
    /// must read as "not known to support SPICE", not as permission to
    /// try. Refreshing the list retries the probe.
    pub fn connection_blocker(&self) -> Option<String> {
        if self.template {
            return Some("is a template; start a clone to get a console".to_string());
        }
        if !self.is_running() {
            return Some(format!(
                "is {}; a SPICE console needs the guest running",
                self.status.as_deref().unwrap_or("not running")
            ));
        }
        match self.supports_spice() {
            Some(false) => Some(format!(
                "uses the display type '{}', which has no SPICE server; set the guest's \
                 Display to SPICE (qxl) or VirtIO-GPU",
                self.display_type().unwrap_or("unknown")
            )),
            None => Some(
                "has a display configuration ryll could not read; retry the list to check \
                 whether it supports SPICE"
                    .to_string(),
            ),
            Some(true) => None,
        }
    }

    /// Whether the picker should offer Connect. A stopped guest is
    /// listed with its button disabled; templates are filtered out of
    /// the GUI picker entirely because Proxmox cannot mint a console for
    /// them. A guest whose display type could not be read is not offered
    /// either, until a refresh reads it. The non-GUI path reports every
    /// condition in `spice_config`.
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    pub fn is_connectable(&self) -> bool {
        self.connection_blocker().is_none()
    }
}

/// Whether Proxmox's QEMU command line starts a SPICE server for a
/// display type.
///
/// `config_to_command` enables SPICE for the QXL family and for any
/// `virtio*` type, and the VM status endpoint reports the same set. The
/// QEMU index does not carry the model, which is why the list reads each
/// guest's configuration.
fn display_type_supports_spice(display_type: &str) -> bool {
    display_type.starts_with("virtio") || matches!(display_type, "qxl" | "qxl2" | "qxl3" | "qxl4")
}

/// An authenticated Proxmox API client.
///
/// The client is deliberately synchronous: it is used from startup code
/// and from the GUI's background login/list threads, never from inside a
/// tokio runtime.
#[derive(Clone)]
pub struct ProxmoxClient {
    http: Client,
    base: Url,
    auth: AuthState,
    /// Optional `proxy` field for the console document. `None` lets
    /// Proxmox choose the node the VM is running on.
    proxy: Option<String>,
}

#[derive(Clone)]
enum AuthState {
    Ticket { ticket: String, csrf: String },
    Token { header: String },
}

impl ProxmoxClient {
    /// Authenticate against `url`.
    ///
    /// Password authentication exchanges the credentials for a ticket
    /// immediately, so bad credentials fail here rather than at the
    /// first list request. API tokens are validated by the first request
    /// (`list_vms`), because Proxmox has no token-login endpoint.
    pub fn connect(
        url: &str,
        auth: ProxmoxAuth,
        tls: ProxmoxTls,
        proxy: Option<String>,
    ) -> Result<Self> {
        let base = normalize_base_url(url)?;
        if base.scheme() == "http" {
            tracing::warn!(
                "Proxmox: using plaintext HTTP; the login and console tickets are not protected. \
                 Use https unless this is a trusted network or a loopback test."
            );
        }
        let http = build_http_client(&tls)?;

        let auth = match auth {
            ProxmoxAuth::Password { username, password } => {
                let (ticket, csrf) = request_ticket(&http, &base, &username, &password)?;
                AuthState::Ticket { ticket, csrf }
            }
            ProxmoxAuth::Token { token } => AuthState::Token {
                header: normalize_token(&token)?,
            },
        };

        Ok(Self {
            http,
            base,
            auth,
            proxy: proxy.filter(|host| !host.trim().is_empty()),
        })
    }

    /// Ask Proxmox for the QEMU guests these credentials can see.
    ///
    /// The per-node QEMU index is the primary source because Proxmox
    /// documents it as returning only VMs where the caller has
    /// `VM.Audit` on `/vms/<vmid>`. That is exactly the per-VM ACL case:
    /// a user who may see VMs 100 and 104 but not the rest of `/vms`
    /// gets those two and nothing else, without needing cluster-wide
    /// audit access.
    ///
    /// `/cluster/resources?type=vm` is retained as a fallback for a
    /// Proxmox version or proxy that does not expose the per-node index
    /// usefully. LXC containers are excluded because they have no SPICE
    /// console.
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    pub fn list_vms(&self) -> Result<Vec<ProxmoxVm>> {
        self.list_inventory().map(|(vms, _nodes)| vms)
    }

    /// List the visible VMs and the node names that were consulted.
    ///
    /// The GUI names a saved profile after the node it connected to, so
    /// it needs the node list that `list_vms` throws away. Each guest's
    /// display configuration is read as well, so the picker and
    /// `--proxmox-list` can say whether a SPICE console is possible.
    pub fn list_inventory(&self) -> Result<(Vec<ProxmoxVm>, Vec<String>)> {
        let (mut vms, nodes) = self.list_inventory_unenriched()?;
        self.annotate_displays(&mut vms);
        Ok((vms, nodes))
    }

    /// The VM list as the Proxmox indexes describe it, before the
    /// per-guest display probes.
    fn list_inventory_unenriched(&self) -> Result<(Vec<ProxmoxVm>, Vec<String>)> {
        match self.list_vms_per_node() {
            Ok((vms, nodes)) if !vms.is_empty() => Ok((vms, nodes)),
            Ok((per_node_empty, nodes)) => match self.list_vms_from_resources() {
                Ok(resource_vms) if !resource_vms.is_empty() => {
                    let resource_nodes = Self::node_names_from_vms(&resource_vms);
                    let nodes = if resource_nodes.is_empty() {
                        nodes
                    } else {
                        resource_nodes
                    };
                    Ok((resource_vms, nodes))
                }
                Ok(_) => Ok((per_node_empty, nodes)),
                Err(error) => {
                    // The per-node path succeeded, so an empty result is
                    // authoritative; a failure of the optional fallback
                    // should not turn "no VMs visible" into an error.
                    tracing::debug!(
                        "Proxmox: cluster-resource fallback failed after an empty per-node list: {error:#}"
                    );
                    Ok((per_node_empty, nodes))
                }
            },
            Err(per_node_error) => match self.list_vms_from_resources() {
                Ok(vms) => {
                    let nodes = Self::node_names_from_vms(&vms);
                    Ok((vms, nodes))
                }
                Err(resource_error) => Err(anyhow!(
                    "could not list Proxmox VMs: per-node index: {per_node_error:#}; \
                     cluster resources: {resource_error:#}"
                )),
            },
        }
    }

    /// The Proxmox node name to label a saved profile with.
    ///
    /// Prefer a node whose name matches the API host or its first DNS
    /// label, then the first node the server listed, and finally the
    /// host itself. A cluster can serve its API from any member, so the
    /// match is a heuristic; it is exact for the standalone hosts most
    /// profiles use.
    pub fn server_node_name(&self, nodes: &[String]) -> String {
        let host = self.base.host_str().unwrap_or_default();
        let short = host.split('.').next().unwrap_or(host);
        nodes
            .iter()
            .find(|node| node.as_str() == host || node.as_str() == short)
            .cloned()
            .or_else(|| nodes.first().cloned())
            .unwrap_or_else(|| short.to_string())
    }

    /// Walk `/nodes/{node}/qemu` on every node.
    ///
    /// A node that cannot be reached is skipped so one offline or
    /// restricted node does not hide the VMs on the others. The error is
    /// returned only when no node produced a usable answer, which lets
    /// `list_vms` try the cluster-resource fallback.
    fn list_vms_per_node(&self) -> Result<(Vec<ProxmoxVm>, Vec<String>)> {
        let nodes = self.list_node_names()?;
        let mut vms = Vec::new();
        let mut successful_nodes = 0usize;
        let mut first_error: Option<(String, anyhow::Error)> = None;

        for node in &nodes {
            match self.list_node_vms(node) {
                Ok(mut node_vms) => {
                    successful_nodes += 1;
                    vms.append(&mut node_vms);
                }
                Err(error) => {
                    tracing::debug!("Proxmox: could not list VMs on node {node}: {error:#}");
                    if first_error.is_none() {
                        first_error = Some((node.clone(), error));
                    }
                }
            }
        }

        if successful_nodes == 0 {
            if let Some((node, error)) = first_error {
                return Err(error).with_context(|| format!("could not list VMs on node {node}"));
            }
            // No nodes were returned. Let the caller try the fallback.
            return Ok((Vec::new(), nodes));
        }

        // VMIDs are cluster-unique, but a proxy or a future API quirk
        // could repeat one across nodes. Keep the first and sort stably.
        let mut by_vmid = std::collections::BTreeMap::new();
        for vm in vms {
            by_vmid.entry(vm.vmid).or_insert(vm);
        }
        let mut vms: Vec<ProxmoxVm> = by_vmid.into_values().collect();
        vms.sort_by(|a, b| a.node.cmp(&b.node).then(a.vmid.cmp(&b.vmid)));
        Ok((vms, nodes))
    }

    fn list_node_names(&self) -> Result<Vec<String>> {
        let url = api_url(&self.base, "/api2/json/nodes")?;
        let request = self.authorize(self.http.get(url), false);
        let response = request
            .send()
            .map_err(|e| anyhow!("could not reach the Proxmox API: {e}"))?;
        let body = read_success(response, "Listing Proxmox nodes")?;
        let envelope: Envelope<Vec<NodeEntry>> =
            serde_json::from_str(&body).context("Proxmox returned an unexpected node list")?;
        let nodes = envelope
            .data
            .ok_or_else(|| anyhow!("Proxmox returned no node list"))?;

        let mut names: Vec<String> = nodes
            .into_iter()
            .map(|entry| entry.node)
            .filter(|node| valid_node_name(node))
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn list_node_vms(&self, node: &str) -> Result<Vec<ProxmoxVm>> {
        let url = api_url(&self.base, &format!("/api2/json/nodes/{node}/qemu"))?;
        let request = self.authorize(self.http.get(url), false);
        let response = request
            .send()
            .map_err(|e| anyhow!("could not reach the Proxmox API: {e}"))?;
        let body = read_success(response, &format!("Listing VMs on node {node}"))?;
        let envelope: Envelope<Vec<NodeVm>> =
            serde_json::from_str(&body).context("Proxmox returned an unexpected VM list")?;
        let entries = envelope
            .data
            .ok_or_else(|| anyhow!("Proxmox returned no VM list for node {node}"))?;

        Ok(entries
            .into_iter()
            .filter(|vm| vm.vmid > 0)
            .map(|vm| ProxmoxVm {
                vmid: vm.vmid,
                name: vm.name,
                node: node.to_string(),
                status: vm.status,
                template: vm.template,
                display: None,
            })
            .collect())
    }

    /// The legacy cluster-resource listing, used only when the per-node
    /// index yields nothing or fails.
    fn list_vms_from_resources(&self) -> Result<Vec<ProxmoxVm>> {
        let url = api_url(&self.base, "/api2/json/cluster/resources?type=vm")?;
        let request = self.authorize(self.http.get(url), false);
        let response = request
            .send()
            .map_err(|e| anyhow!("could not reach the Proxmox API: {e}"))?;
        let body = read_success(response, "Listing Proxmox VMs")?;

        let envelope: Envelope<Vec<Resource>> =
            serde_json::from_str(&body).context("Proxmox returned an unexpected resource list")?;
        let resources = envelope
            .data
            .ok_or_else(|| anyhow!("Proxmox returned no resource list"))?;

        let mut vms: Vec<ProxmoxVm> = resources
            .into_iter()
            .filter(|resource| resource.kind.as_deref() == Some("qemu"))
            .filter(|resource| resource.vmid > 0)
            .filter_map(|resource| {
                let node = resource.node?;
                if node.trim().is_empty() || !valid_node_name(&node) {
                    return None;
                }
                Some(ProxmoxVm {
                    vmid: resource.vmid,
                    name: resource.name,
                    node,
                    status: resource.status,
                    template: resource.template,
                    display: None,
                })
            })
            .collect();

        vms.sort_by(|a, b| a.node.cmp(&b.node).then(a.vmid.cmp(&b.vmid)));
        Ok(vms)
    }

    /// The unique node names named by a VM list, for the cluster-resource
    /// fallback where no `/nodes` answer was available.
    fn node_names_from_vms(vms: &[ProxmoxVm]) -> Vec<String> {
        let mut nodes: Vec<String> = vms.iter().map(|vm| vm.node.clone()).collect();
        nodes.sort();
        nodes.dedup();
        nodes
    }

    /// Read each guest's display configuration and record its type.
    ///
    /// The QEMU index does not carry the display model, so telling
    /// whether a SPICE console is possible costs one `config` request
    /// per guest. The probes run on a few threads at once, because a
    /// cluster with many guests would otherwise turn the list into a
    /// long serial chain of round trips. A probe that fails leaves
    /// `display` as `None`, which is reported as unknown and, with the
    /// rest of `connection_blocker`, keeps Connect disabled until a
    /// refresh succeeds. Templates are skipped, since Proxmox cannot
    /// give them a console whatever their display says.
    fn annotate_displays(&self, vms: &mut [ProxmoxVm]) {
        let probes: Vec<usize> = vms
            .iter()
            .enumerate()
            .filter(|(_, vm)| !vm.template)
            .map(|(index, _)| index)
            .collect();
        if probes.is_empty() {
            return;
        }

        let workers = DISPLAY_PROBE_WORKERS.min(probes.len());
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel();
        let guests: &[ProxmoxVm] = vms;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                let tx = tx.clone();
                let next = &next;
                let probes = &probes;
                scope.spawn(move || loop {
                    let position = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&index) = probes.get(position) else {
                        break;
                    };
                    let display = self.display_for(&guests[index]);
                    if tx.send((index, display)).is_err() {
                        break;
                    }
                });
            }
        });

        // The workers' senders are gone once the scope joins; dropping
        // this one lets the receiver drain without a blocking wait.
        drop(tx);
        for (index, display) in rx {
            vms[index].display = display;
        }
    }

    /// The guest's display type, or `None` when its configuration could
    /// not be read. A failed probe is logged and leaves the guest listed
    /// but un-connectable, rather than offering a console ryll cannot
    /// vouch for.
    fn display_for(&self, vm: &ProxmoxVm) -> Option<String> {
        match self.vm_config(vm) {
            Ok(config) => Some(config.display_type()),
            Err(error) => {
                tracing::warn!(
                    "Proxmox: could not read the display configuration for VM {} on {}: {error:#}",
                    vm.vmid,
                    vm.node
                );
                None
            }
        }
    }

    fn vm_config(&self, vm: &ProxmoxVm) -> Result<VmConfig> {
        if !valid_node_name(&vm.node) {
            bail!("Proxmox returned an invalid node name: {:?}", vm.node);
        }
        // A running guest keeps the display model it was started with,
        // so read its current values: a pending `vga` change only takes
        // effect at the next start. A stopped guest has no running
        // instance, and its pending value is what a start would use, so
        // the default (pending applied) view is the right one there.
        let suffix = if vm.is_running() {
            format!(
                "/api2/json/nodes/{}/qemu/{}/config?current=1",
                vm.node, vm.vmid
            )
        } else {
            format!("/api2/json/nodes/{}/qemu/{}/config", vm.node, vm.vmid)
        };
        let url = api_url(&self.base, &suffix)?;
        let response = self
            .authorize(self.http.get(url), false)
            .send()
            .map_err(|e| anyhow!("could not reach the Proxmox API: {e}"))?;
        let body = read_success(
            response,
            &format!("Reading the configuration of VM {}", vm.vmid),
        )?;
        let envelope: Envelope<VmConfig> = serde_json::from_str(&body)
            .context("Proxmox returned an unexpected VM configuration")?;
        envelope
            .data
            .ok_or_else(|| anyhow!("Proxmox returned no configuration for VM {}", vm.vmid))
    }

    /// Fetch the guest's `.vv` document and turn it into a [`Config`].
    ///
    /// The `delete-this-file` interpretation ryll already gives a
    /// Proxmox `.vv` is forced on here: the ticket in the document is
    /// short-lived and bound to the request that produced it, so a
    /// reconnect must ask Proxmox for a fresh document. Treating it as
    /// single-use is what suppresses a pointless reconnect loop.
    pub fn spice_config(&self, vm: &ProxmoxVm) -> Result<Config> {
        if let Some(blocker) = vm.connection_blocker() {
            bail!("VM {} ({}) {blocker}", vm.vmid, vm.display_name());
        }

        let url = self.spice_url(vm)?;
        let mut request = self.http.post(url);
        if let Some(proxy) = &self.proxy {
            request = request.form(&[("proxy", proxy.as_str())]);
        }
        let response = self
            .authorize(request, true)
            .send()
            .map_err(|e| anyhow!("could not reach the Proxmox API: {e}"))?;
        let body = read_success(response, "Requesting the SPICE console")?;

        let mut config = Config::parse_vv_content(&body).with_context(|| {
            format!(
                "Proxmox returned an unusable SPICE console document for VM {}",
                vm.vmid
            )
        })?;
        if config.proxy.is_none() {
            bail!(
                "Proxmox returned a SPICE console document for VM {} with no `proxy=` key; \
                 ryll cannot reach the signed spiceproxy hostname directly",
                vm.vmid
            );
        }
        config.ticket_is_single_use = true;
        Ok(config)
    }

    fn authorize(&self, request: RequestBuilder, mutating: bool) -> RequestBuilder {
        match &self.auth {
            AuthState::Ticket { ticket, csrf } => {
                let request = request.header(COOKIE, format!("PVEAuthCookie={ticket}"));
                if mutating {
                    request.header("CSRFPreventionToken", csrf)
                } else {
                    request
                }
            }
            AuthState::Token { header } => {
                request.header(AUTHORIZATION, format!("PVEAPIToken={header}"))
            }
        }
    }

    fn spice_url(&self, vm: &ProxmoxVm) -> Result<Url> {
        if !valid_node_name(&vm.node) {
            bail!("Proxmox returned an invalid node name: {:?}", vm.node);
        }
        api_url(
            &self.base,
            &format!(
                "/api2/spiceconfig/nodes/{}/qemu/{}/spiceproxy",
                vm.node, vm.vmid
            ),
        )
    }
}

fn build_http_client(tls: &ProxmoxTls) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("ryll/", env!("CARGO_PKG_VERSION")));

    if tls.insecure {
        builder = builder.tls_danger_accept_invalid_certs(true);
    }

    if let Some(pem) = &tls.ca_pem {
        let certificates = reqwest::Certificate::from_pem_bundle(pem)
            .context("--proxmox-ca: the file does not contain a usable PEM certificate")?;
        if certificates.is_empty() {
            bail!("--proxmox-ca: the file contains no certificates");
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }

    builder
        .build()
        .context("failed to build the Proxmox HTTP client")
}

fn request_ticket(
    http: &Client,
    base: &Url,
    username: &str,
    password: &str,
) -> Result<(String, String)> {
    let url = api_url(base, "/api2/json/access/ticket")?;
    let response = http
        .post(url)
        .form(&[("username", username), ("password", password)])
        .send()
        .map_err(|e| anyhow!("could not reach the Proxmox API: {e}"))?;
    let body = read_success(response, "Proxmox login")?;

    let envelope: Envelope<TicketResponse> =
        serde_json::from_str(&body).context("Proxmox returned an unexpected login response")?;
    let ticket = envelope
        .data
        .ok_or_else(|| anyhow!("Proxmox returned no login ticket"))?;
    if ticket.ticket.is_empty() || ticket.csrf_prevention_token.is_empty() {
        bail!("Proxmox returned an empty login ticket");
    }
    Ok((ticket.ticket, ticket.csrf_prevention_token))
}

fn read_success(response: Response, what: &str) -> Result<String> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        let hint = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            " (check the credentials, and that the user or token has VM.Audit to list VMs \
             and VM.Console to open a console)"
        } else {
            ""
        };
        bail!(
            "{} failed with HTTP {}{}: {}",
            what,
            status.as_u16(),
            hint,
            summarize_error_body(&body)
        );
    }
    response
        .text()
        .context("could not read the Proxmox API response body")
}

/// Turn whatever an error response contained into one short line.
///
/// Proxmox's JSON errors carry `errors` or `message`; a reverse proxy in
/// front of it may return HTML. Neither is safe to echo in full, and the
/// body can be large, so the result is clamped and stripped of newlines.
fn summarize_error_body(body: &str) -> String {
    let body = body.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
            return truncate_one_line(message);
        }
        if let Some(errors) = value.get("errors").and_then(serde_json::Value::as_object) {
            let joined = errors
                .iter()
                .map(|(field, message)| {
                    let message = message
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| message.to_string());
                    format!("{field}: {message}")
                })
                .collect::<Vec<_>>()
                .join("; ");
            if !joined.is_empty() {
                return truncate_one_line(&joined);
            }
        }
    }
    if body.is_empty() {
        return "the response had no body".to_string();
    }
    truncate_one_line(body)
}

fn truncate_one_line(text: &str) -> String {
    let flattened = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut truncated: String = flattened.chars().take(300).collect();
    if flattened.chars().count() > 300 {
        truncated.push('…');
    }
    truncated
}

/// Normalise the API's base URL.
///
/// A scheme is optional (`pve.example:8006` means HTTPS); a missing port
/// means [`DEFAULT_PORT`]; a trailing slash and a pasted
/// `/api2/json` path are tolerated. Credentials in the URL are refused:
/// they would leak into logs and bug reports, and the flags exist.
pub fn normalize_base_url(raw: &str) -> Result<Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("--proxmox needs a URL, such as https://pve.example:8006");
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    // Deliberately not echoing `raw`: it may contain credentials, and an
    // error message is exactly where they must not end up.
    let mut url = Url::parse(&with_scheme).context("--proxmox: the URL could not be parsed")?;

    match url.scheme() {
        "http" | "https" => {}
        other => bail!(
            "--proxmox: unsupported URL scheme {:?}; use https (or http on a trusted network)",
            other
        ),
    }
    if url.host_str().is_none() {
        bail!("--proxmox: the URL names no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!(
            "--proxmox: put credentials in --proxmox-user/--proxmox-password or --proxmox-token, \
             not in the URL"
        );
    }

    // `Url::port()` returns `None` for an explicit default port too
    // (`https://host:443`), so the decision has to come from the text:
    // only a URL with no port at all gets Proxmox's 8006.
    if !has_explicit_port(&with_scheme) {
        let _ = url.set_port(Some(DEFAULT_PORT));
    }
    url.set_query(None);
    url.set_fragment(None);

    let path = url.path().trim_end_matches('/').to_string();
    let path = path.strip_suffix("/api2/json").unwrap_or(&path);
    let path = path.strip_suffix("/api2").unwrap_or(path);
    url.set_path(if path.is_empty() { "/" } else { path });
    Ok(url)
}

/// Whether `raw` names a port explicitly, before `Url` normalises a
/// default port away. IPv6 literals are bracketed, so only a colon
/// outside the brackets is the port separator.
///
/// The GUI's endpoint form keeps the URL and port in separate fields, so
/// it uses this to reject a port pasted into the URL field rather than
/// silently replacing it with the Port field's value.
pub(crate) fn has_explicit_port(raw: &str) -> bool {
    let after_scheme = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once("]:").is_some()
    } else {
        authority.contains(':')
    }
}

/// Join an API suffix onto a normalised base URL.
///
/// The query is separated before `set_path`, which would otherwise
/// percent-encode the `?` into the path and turn the cluster-resource
/// filter into a 404.
fn api_url(base: &Url, suffix: &str) -> Result<Url> {
    let (suffix_path, query) = match suffix.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (suffix, None),
    };
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}{suffix_path}"));
    url.set_query(query);
    Ok(url)
}

/// Proxmox node names are host names. Rejecting anything else keeps a
/// compromised or unexpected API response from altering the request path.
fn valid_node_name(node: &str) -> bool {
    !node.is_empty()
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Normalise a Proxmox API token to `USER@REALM!TOKENID=SECRET`.
///
/// The `PVEAPIToken=` prefix is accepted because that is the form the
/// API documentation and curl examples show, and splitting on the first
/// `=` keeps secrets that contain `=` intact.
pub fn normalize_token(raw: &str) -> Result<String> {
    let token = raw.trim();
    let token = token.strip_prefix("PVEAPIToken=").unwrap_or(token).trim();
    let (id, secret) = token.split_once('=').ok_or_else(|| {
        anyhow!(
            "--proxmox-token: expected USER@REALM!TOKENID=SECRET (or PVEAPIToken=USER@REALM!TOKENID=SECRET)"
        )
    })?;
    if id.is_empty() || secret.is_empty() {
        bail!("--proxmox-token: the token ID and secret must both be non-empty");
    }
    if !id.contains('@') || !id.contains('!') {
        bail!("--proxmox-token: the token ID must look like USER@REALM!TOKENID");
    }
    Ok(format!("{id}={secret}"))
}

/// Whether the user asked for a Proxmox source.
pub fn requested(args: &Args) -> bool {
    args.proxmox.is_some()
}

/// Build a [`ProxmoxAuth`] from the CLI flags, or `None` if the flags do
/// not supply one.
///
/// The GUI calls this to decide whether it can auto-submit; non-GUI
/// modes require a value and reject `None` in [`validate_args`].
pub fn auth_from_args(args: &Args) -> Result<Option<ProxmoxAuth>> {
    let token = match (&args.proxmox_token, &args.proxmox_token_file) {
        (Some(token), None) => Some(token.clone()),
        (None, Some(path)) => Some(read_secret_file(path, "--proxmox-token-file")?),
        (Some(_), Some(_)) => {
            bail!("--proxmox-token and --proxmox-token-file cannot be used together")
        }
        (None, None) => None,
    };
    if let Some(token) = token {
        return Ok(Some(ProxmoxAuth::Token {
            token: normalize_token(&token)?,
        }));
    }

    let password = match (&args.proxmox_password, &args.proxmox_password_file) {
        (Some(password), None) => Some(password.clone()),
        (None, Some(path)) => Some(read_secret_file(path, "--proxmox-password-file")?),
        (Some(_), Some(_)) => {
            bail!("--proxmox-password and --proxmox-password-file cannot be used together")
        }
        (None, None) => None,
    };

    match (args.proxmox_user.as_deref(), password) {
        (Some(username), Some(password)) => {
            if username.trim().is_empty() {
                bail!("--proxmox-user must not be empty");
            }
            Ok(Some(ProxmoxAuth::Password {
                username: username.to_string(),
                password,
            }))
        }
        (Some(_), None) | (None, Some(_)) => Ok(None),
        (None, None) => Ok(None),
    }
}

/// Whether two endpoint strings normalise to the same Proxmox URL.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn endpoint_matches(left: &str, right: &str) -> bool {
    match (normalize_base_url(left), normalize_base_url(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// The endpoint a profile describes, with its port applied.
fn profile_endpoint(profile: &ProxmoxProfile) -> Option<Url> {
    let mut endpoint = normalize_base_url(&profile.host).ok()?;
    endpoint.set_port(Some(profile.port)).ok()?;
    Some(endpoint)
}

/// Render an endpoint with its port kept explicit.
///
/// `Url::to_string` omits a scheme-default port (`https` 443, `http` 80).
/// A bare `https://host` is later read as Proxmox's 8006, so the port
/// must stay visible in the string even when it is the scheme default.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub(crate) fn endpoint_with_port(mut endpoint: Url, port: u16) -> String {
    let _ = endpoint.set_port(None);
    let text = endpoint.to_string();
    let authority_end = text
        .find("://")
        .map(|index| index + 3)
        .and_then(|start| text[start..].find('/').map(|index| start + index))
        .unwrap_or(text.len());
    let (origin, path) = text.split_at(authority_end);
    let path = if path == "/" { "" } else { path };
    format!("{origin}:{port}{path}")
}

/// The profile endpoint as a display/comparison string, without a
/// trailing slash.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub(crate) fn profile_endpoint_string(profile: &ProxmoxProfile) -> Option<String> {
    let endpoint = profile_endpoint(profile)?;
    Some(endpoint_with_port(endpoint, profile.port))
}

/// Whether `url` names the same endpoint as `profile`.
fn profile_matches(url: &str, profile: &ProxmoxProfile) -> bool {
    match (normalize_base_url(url), profile_endpoint(profile)) {
        (Ok(url), Some(profile)) => url == profile,
        _ => false,
    }
}

/// Split an endpoint into the host URL (without its port) and the port,
/// the shape a saved profile uses.
pub(crate) fn endpoint_parts(raw: &str) -> Result<(String, u16)> {
    let mut endpoint = normalize_base_url(raw)?;
    let port = endpoint.port_or_known_default().unwrap_or(DEFAULT_PORT);
    endpoint
        .set_port(None)
        .map_err(|_| anyhow!("the endpoint has no usable host"))?;
    Ok((endpoint.to_string().trim_end_matches('/').to_string(), port))
}

/// The profile whose endpoint matches `url`.
fn matching_profile<'a>(url: &str, saved: Option<&'a SavedProxmox>) -> Option<&'a ProxmoxProfile> {
    saved?
        .profiles
        .iter()
        .find(|profile| profile_matches(url, profile))
}

/// The URL named explicitly on the command line, if any.
///
/// `--proxmox` may be given without a value to open the GUI's connection
/// form; an empty value asks for the form rather than naming an endpoint.
fn requested_url(args: &Args) -> Option<&str> {
    args.proxmox
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
}

/// The saved profile that applies to this command line, if any.
///
/// Only an explicit, non-empty `--proxmox` URL can match a profile here.
/// Bare `--proxmox` (the GUI form) chooses the saved endpoint in
/// [`ProxmoxLaunchSettings::from_args`], not in the non-interactive
/// credential paths.
fn saved_for_url<'a>(args: &Args, saved: Option<&'a SavedProxmox>) -> Option<&'a ProxmoxProfile> {
    matching_profile(requested_url(args)?, saved)
}

/// Whether the command line explicitly asked for password
/// authentication. A username or a password flag disables the saved
/// token fallback even when the pair is incomplete, so a typo cannot
/// silently become a different login method.
fn cli_password_requested(args: &Args) -> bool {
    args.proxmox_user.is_some()
        || args.proxmox_password.is_some()
        || args.proxmox_password_file.is_some()
}

/// Build a [`ProxmoxAuth`] from the CLI flags, falling back to a saved
/// API token when the endpoint matches.
pub fn auth_for_source(args: &Args, saved: Option<&SavedProxmox>) -> Result<Option<ProxmoxAuth>> {
    if let Some(auth) = auth_from_args(args)? {
        return Ok(Some(auth));
    }
    if cli_password_requested(args) {
        return Ok(None);
    }
    let Some(profile) = saved_for_url(args, saved) else {
        return Ok(None);
    };
    let Some(token) = profile.token.as_deref() else {
        return Ok(None);
    };
    Ok(Some(ProxmoxAuth::Token {
        token: normalize_token(token)?,
    }))
}

/// Build the TLS settings from the CLI flags.
pub fn tls_from_args(args: &Args) -> Result<ProxmoxTls> {
    let ca_pem = match &args.proxmox_ca {
        Some(path) => Some(read_ca_file(path, "--proxmox-ca")?),
        None => None,
    };
    Ok(ProxmoxTls {
        insecure: args.proxmox_insecure,
        ca_pem,
    })
}

/// TLS settings for a saved profile.
pub(crate) fn tls_from_profile(profile: &ProxmoxProfile) -> Result<ProxmoxTls> {
    if profile.insecure && profile.ca.is_some() {
        bail!(
            "the saved Proxmox profile for {}:{} sets both `insecure` and `ca`; \
             remove one from config.json",
            profile.host,
            profile.port
        );
    }
    let ca_pem = match &profile.ca {
        Some(path) => Some(read_ca_file(path, "saved Proxmox CA")?),
        None => None,
    };
    Ok(ProxmoxTls {
        insecure: profile.insecure,
        ca_pem,
    })
}

/// TLS settings for a command-line session, using the CLI flags first and
/// then the saved profile with the same endpoint.
pub fn tls_for_source(args: &Args, saved: Option<&SavedProxmox>) -> Result<ProxmoxTls> {
    if args.proxmox_insecure || args.proxmox_ca.is_some() {
        return tls_from_args(args);
    }
    if let Some(profile) = saved_for_url(args, saved) {
        return tls_from_profile(profile);
    }
    tls_from_args(args)
}

fn read_ca_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("{label} {}: could not read it", path.display()))
}

/// Reject Proxmox flag combinations that are merely confusing (clap
/// already handles the mechanical conflicts) and enforce the extra
/// requirements of the non-interactive modes.
pub fn validate_args(args: &Args, saved: Option<&SavedProxmox>) -> Result<()> {
    // No Proxmox source: there is nothing to validate.
    if !requested(args) {
        return Ok(());
    }
    if args.proxmox_insecure && args.proxmox_ca.is_some() {
        bail!("--proxmox-insecure and --proxmox-ca cannot be used together");
    }

    // The GUI form can collect the URL after launch; every other path
    // (including --proxmox-list) needs it now. Bare `--proxmox` without a
    // saved endpoint still opens the GUI, so only reject the missing URL
    // when there is no form to fill in.
    let interactive_gui = !args.headless && !args.web && !args.rdp;
    if requested_url(args).is_none() && (!interactive_gui || args.proxmox_list) {
        bail!("--proxmox needs a URL, such as https://pve.example:8006");
    }

    // auth_for_source also reads any secret file, so a missing or empty
    // file fails at startup instead of when the user finally picks a VM.
    let auth = auth_for_source(args, saved)?;

    if args.proxmox_list {
        if auth.is_none() {
            bail!(
                "--proxmox-list needs credentials: pass --proxmox-user and a password \
                 (or --proxmox-password-file), or --proxmox-token/--proxmox-token-file. \
                 A saved token under ~/.ryll is used when the endpoint matches."
            );
        }
        return Ok(());
    }

    if !interactive_gui {
        if auth.is_none() {
            bail!(
                "--proxmox in --headless, --web and --rdp mode needs credentials: pass \
                 --proxmox-user with a password, or --proxmox-token, or save a token \
                 under ~/.ryll"
            );
        }
        if args.proxmox_vm.is_none() {
            bail!(
                "--proxmox in --headless, --web and --rdp mode needs --proxmox-vm <VMID>; \
                 run with --proxmox-list to see the IDs this login can reach"
            );
        }
    }

    Ok(())
}

/// Resolve a Proxmox source to a concrete SPICE [`Config`] for a
/// non-interactive mode.
pub fn resolve_session(args: &Args, saved: Option<&SavedProxmox>) -> Result<Config> {
    let (client, vms) = connect_and_list(args, saved)?;
    let vmid = args.proxmox_vm.ok_or_else(|| {
        anyhow!(
            "--proxmox-vm <VMID> is required outside the GUI. Visible VMs:\n{}",
            format_vm_table(&vms)
        )
    })?;
    let vm = vms.iter().find(|vm| vm.vmid == vmid).ok_or_else(|| {
        anyhow!(
            "VM {} is not visible to these credentials. Visible VMs:\n{}",
            vmid,
            format_vm_table(&vms)
        )
    })?;
    let config = client.spice_config(vm)?;
    tracing::info!(
        "Proxmox: VM {} ({}) on {} via {}",
        vm.vmid,
        vm.display_name(),
        vm.node,
        config
            .proxy
            .as_ref()
            .map(|proxy| format!("{}:{}", proxy.host, proxy.port))
            .unwrap_or_else(|| "a direct connection".to_string())
    );
    Ok(config)
}

/// Print the visible VM table and return. Used by `--proxmox-list`.
pub fn print_vm_list(args: &Args, saved: Option<&SavedProxmox>) -> Result<()> {
    let (_client, vms) = connect_and_list(args, saved)?;
    // audit-allow-println: operator-facing list output, not for logs.
    print!("{}", format_vm_table(&vms));
    Ok(())
}

/// The result of authenticating and listing the visible guests.
///
/// Both the non-interactive path ([`connect_and_list`]) and the GUI's
/// saved-credential auto-login use this: the GUI starts on the VM list,
/// and the node name labels the profile a successful login saves.
pub struct ProxmoxLogin {
    pub client: ProxmoxClient,
    pub vms: Vec<ProxmoxVm>,
    /// The Proxmox node name a saved profile is labelled with.
    pub node_name: String,
    /// The API token used, so `--proxmox-save` can store it. `None` after
    /// a password login, which is never saved.
    token: Option<String>,
}

/// Authenticate and list the visible guests, returning everything a
/// login has to offer once the network work succeeds.
fn login_and_list(args: &Args, saved: Option<&SavedProxmox>) -> Result<ProxmoxLogin> {
    let url = requested_url(args).ok_or_else(|| {
        anyhow!("--proxmox needs a URL outside the GUI, such as https://pve.example:8006")
    })?;
    let auth = auth_for_source(args, saved)?.ok_or_else(|| {
        anyhow!(
            "--proxmox needs credentials: pass --proxmox-user with a password, \
             --proxmox-token, or save a token under ~/.ryll"
        )
    })?;
    let token = match &auth {
        ProxmoxAuth::Token { token } => Some(token.clone()),
        ProxmoxAuth::Password { .. } => None,
    };
    let tls = tls_for_source(args, saved)?;

    tracing::debug!("Proxmox: authenticating with {}", auth.method_name());
    let client = ProxmoxClient::connect(url, auth, tls, args.proxmox_proxy.clone())?;
    let (vms, nodes) = client.list_inventory()?;
    let node_name = client.server_node_name(&nodes);

    Ok(ProxmoxLogin {
        client,
        vms,
        node_name,
        token,
    })
}

/// Log in and list the visible guests for a GUI launch whose credentials
/// came from the saved config.
///
/// The caller runs this before the window exists, so a rejected token or
/// an unreachable endpoint is reported on the command line and exits
/// rather than falling back to the connection dialog the saved token was
/// meant to skip.
#[cfg(feature = "gui")]
pub fn preconnect(args: &Args, saved: Option<&SavedProxmox>) -> Result<ProxmoxLogin> {
    // The window does not exist yet, so this line is the only sign of life
    // while the login and display probes run.
    if let Some(url) = requested_url(args) {
        tracing::info!("Proxmox: logging in with the saved credentials for {url}");
    }
    login_and_list(args, saved)
}

/// Whether a GUI `--proxmox <url>` launch can log in from the saved
/// config without showing the connection dialog.
///
/// The trigger is an explicit endpoint that matches a saved profile with
/// a token, with no credentials of its own on the command line. Bare
/// `--proxmox` keeps the prefilled form: with no URL there is nothing to
/// match the token against, and the user is choosing among profiles.
#[cfg(feature = "gui")]
pub fn uses_saved_credentials(args: &Args, saved: Option<&SavedProxmox>) -> Result<bool> {
    if requested_url(args).is_none() {
        return Ok(false);
    }
    if auth_from_args(args)?.is_some() || cli_password_requested(args) {
        return Ok(false);
    }
    Ok(saved_for_url(args, saved)
        .and_then(|profile| profile.token.as_deref())
        .is_some())
}

fn connect_and_list(
    args: &Args,
    saved: Option<&SavedProxmox>,
) -> Result<(ProxmoxClient, Vec<ProxmoxVm>)> {
    let login = login_and_list(args, saved)?;

    if args.proxmox_save {
        let token_to_save = login.token.clone();
        if token_to_save.is_none() {
            tracing::warn!(
                "--proxmox-save stores only API tokens; saving the endpoint without a token"
            );
        }
        let profile = profile_for_save(args, saved, token_to_save, &login.node_name);
        match config_dir::upsert_proxmox_profile(&profile) {
            Ok((path, _)) => tracing::info!(
                "Proxmox: saved profile '{}' in {}",
                profile.name,
                path.display()
            ),
            Err(error) => {
                tracing::warn!("Proxmox: could not save the profile: {error:#}")
            }
        }
    }

    Ok((login.client, login.vms))
}

/// Build the profile `--proxmox-save` writes, preserving the TLS settings
/// in force.
fn profile_for_save(
    args: &Args,
    saved: Option<&SavedProxmox>,
    token: Option<String>,
    node_name: &str,
) -> ProxmoxProfile {
    let url = requested_url(args).unwrap_or_default();
    let (host, port) = endpoint_parts(url).unwrap_or_else(|_| (url.to_string(), DEFAULT_PORT));
    let matching = matching_profile(url, saved);
    let (insecure, ca) = if args.proxmox_insecure || args.proxmox_ca.is_some() {
        (args.proxmox_insecure, args.proxmox_ca.clone())
    } else if let Some(profile) = matching {
        (profile.insecure, profile.ca.clone())
    } else {
        (false, None)
    };

    ProxmoxProfile {
        name: node_name.to_string(),
        host,
        port,
        token,
        insecure,
        ca,
    }
}

/// A stable, tab-separated table for `--proxmox-list`, diagnostics and
/// the error that names the VMs when `--proxmox-vm` is missing.
///
/// The `SPICE` column is the display question the picker also answers:
/// `yes` when the guest's display type runs a SPICE server, `no` when it
/// cannot (templates included, since no console can be minted for them),
/// and `unknown` when the configuration could not be read. It is the
/// last column so the existing columns keep their positions.
pub fn format_vm_table(vms: &[ProxmoxVm]) -> String {
    let mut table = String::from("VMID\tNODE\tSTATUS\tNAME\tSPICE\n");
    if vms.is_empty() {
        table.push_str("(no QEMU VMs are visible to these credentials)\n");
        return table;
    }
    for vm in vms {
        table.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            vm.vmid,
            vm.node,
            vm.status.as_deref().unwrap_or("unknown"),
            vm.display_name(),
            spice_column(vm),
        ));
    }
    table
}

/// The `SPICE` cell for a guest.
fn spice_column(vm: &ProxmoxVm) -> &'static str {
    if vm.template {
        return "no";
    }
    match vm.supports_spice() {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

/// The settings the GUI launcher needs, with credentials already read
/// from any files.
#[cfg(feature = "gui")]
#[derive(Clone)]
pub struct ProxmoxLaunchSettings {
    pub url: String,
    /// Every saved profile, for the form's profile picker.
    pub profiles: Vec<ProxmoxProfile>,
    /// The profile the form starts on: the matching one for an explicit
    /// URL, or the most recent one for a bare `--proxmox`.
    pub selected_profile: Option<usize>,
    pub username: String,
    pub password: Option<String>,
    pub token: Option<String>,
    pub tls: ProxmoxTls,
    pub ca_path: Option<std::path::PathBuf>,
    pub proxy: Option<String>,
    pub auto_vm: Option<u32>,
    /// `--proxmox-save`: after a successful token login, persist without
    /// requiring the Remember checkbox.
    pub save_requested: bool,
    /// Whether a token for this endpoint is already in `~/.ryll`.
    pub saved_token_present: bool,
    /// Whether the token in the form was loaded from `~/.ryll` (rather
    /// than supplied with `--proxmox-token`).
    pub token_from_saved: bool,
    /// The saved endpoint the token belongs to, used to stop a form edit
    /// from sending that token to a different server.
    pub saved_url: Option<String>,
}

#[cfg(feature = "gui")]
impl ProxmoxLaunchSettings {
    /// Build the launcher settings, or `None` when this is not a
    /// Proxmox launch.
    ///
    /// `saved` is the Proxmox section loaded from `~/.ryll`, if any.
    /// For a bare `--proxmox` it supplies the most recent profile; for
    /// an explicit URL it is only consulted when the endpoint matches,
    /// so a saved token is never sent to a different server.
    pub fn from_args(args: &Args, saved: Option<&SavedProxmox>) -> Result<Option<Self>> {
        if args.proxmox.is_none() {
            return Ok(None);
        }
        let profiles: Vec<ProxmoxProfile> = saved
            .map(|saved| saved.profiles.clone())
            .unwrap_or_default();
        let explicit_url = requested_url(args);
        let selected_profile = match explicit_url {
            Some(url) => profiles
                .iter()
                .position(|profile| profile_matches(url, profile)),
            None => (!profiles.is_empty()).then_some(0),
        };
        let chosen = selected_profile.map(|index| &profiles[index]);
        // Bare `--proxmox` names no endpoint: use the saved profile when
        // one exists, otherwise start the form with an empty URL for the
        // user to fill in.
        let url = match explicit_url {
            Some(url) => url.to_string(),
            None => chosen.and_then(profile_endpoint_string).unwrap_or_default(),
        };
        let matching_saved = chosen.filter(|profile| profile_matches(&url, profile));

        let cli_token = match (&args.proxmox_token, &args.proxmox_token_file) {
            (Some(token), None) => Some(token.clone()),
            (None, Some(path)) => Some(read_secret_file(path, "--proxmox-token-file")?),
            (Some(_), Some(_)) => {
                bail!("--proxmox-token and --proxmox-token-file cannot be used together")
            }
            (None, None) => None,
        };
        let cli_explicit_auth = cli_token.is_some() || cli_password_requested(args);
        let token = match cli_token {
            Some(token) => Some(normalize_token(&token)?),
            None if cli_password_requested(args) => None,
            None => match matching_saved.and_then(|profile| profile.token.as_deref()) {
                Some(token) => Some(normalize_token(token)?),
                None => None,
            },
        };

        let password = match (&args.proxmox_password, &args.proxmox_password_file) {
            (Some(password), None) => Some(password.clone()),
            (None, Some(path)) => Some(read_secret_file(path, "--proxmox-password-file")?),
            (Some(_), Some(_)) => {
                bail!("--proxmox-password and --proxmox-password-file cannot be used together")
            }
            (None, None) => None,
        };

        let (tls, ca_path) = if args.proxmox_insecure || args.proxmox_ca.is_some() {
            (tls_from_args(args)?, args.proxmox_ca.clone())
        } else if let Some(profile) = matching_saved {
            (tls_from_profile(profile)?, profile.ca.clone())
        } else {
            (tls_from_args(args)?, args.proxmox_ca.clone())
        };

        let saved_token_present = matching_saved
            .and_then(|profile| profile.token.as_ref())
            .is_some();
        let saved_url = matching_saved.and_then(profile_endpoint_string);

        Ok(Some(Self {
            url,
            profiles,
            selected_profile,
            username: args.proxmox_user.clone().unwrap_or_default(),
            password,
            token,
            tls,
            ca_path,
            proxy: args.proxmox_proxy.clone(),
            auto_vm: args.proxmox_vm,
            save_requested: args.proxmox_save,
            saved_token_present,
            token_from_saved: saved_token_present && !cli_explicit_auth,
            saved_url,
        }))
    }

    /// Whether the settings can log in without the user touching the
    /// form: only explicit command-line credentials qualify.
    ///
    /// A token loaded from a saved profile always leaves the form up,
    /// prefilled and ready for the user to press **Connect**. Ryll never
    /// connects to a saved Proxmox profile automatically.
    pub fn can_auto_login(&self) -> bool {
        if self.url.trim().is_empty() {
            return false;
        }
        let credentials =
            self.token.is_some() || (!self.username.trim().is_empty() && self.password.is_some());
        credentials && !self.token_from_saved
    }

    /// Split a normalised token into the token ID and secret the login
    /// form shows separately. `None` when there is no token.
    pub fn token_parts(&self) -> Option<(String, String)> {
        let token = self.token.as_deref()?;
        token
            .split_once('=')
            .map(|(id, secret)| (id.to_string(), secret.to_string()))
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: Option<T>,
}

#[derive(Deserialize)]
struct TicketResponse {
    ticket: String,
    #[serde(rename = "CSRFPreventionToken")]
    csrf_prevention_token: String,
}

#[derive(Deserialize)]
struct NodeEntry {
    node: String,
}

#[derive(Deserialize)]
struct NodeVm {
    #[serde(default)]
    vmid: u32,
    name: Option<String>,
    status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_template")]
    template: bool,
}

#[derive(Deserialize)]
struct Resource {
    #[serde(default)]
    vmid: u32,
    name: Option<String>,
    node: Option<String>,
    status: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "deserialize_template")]
    template: bool,
}

/// The parts of a guest configuration that say whether a SPICE console
/// is possible. Every other key is irrelevant here and ignored.
#[derive(Deserialize)]
struct VmConfig {
    vga: Option<String>,
    arch: Option<String>,
}

impl VmConfig {
    /// The effective display type.
    ///
    /// With no `vga` key, Proxmox's own default applies: `virtio` on an
    /// aarch64 guest and `std` everywhere else. A `vga` property with no
    /// type in it is the schema's default key (`std`) by the time QEMU
    /// builds its command line.
    fn display_type(&self) -> String {
        match self.vga.as_deref() {
            Some(value) => vga_display_type(value).unwrap_or_else(|| "std".to_string()),
            None if self
                .arch
                .as_deref()
                .is_some_and(|arch| arch.eq_ignore_ascii_case("aarch64")) =>
            {
                "virtio".to_string()
            }
            None => "std".to_string(),
        }
    }
}

/// The display type out of a Proxmox `vga` property string.
///
/// The value is a comma-separated property list whose first positional
/// element is the type, as in `qxl,memory=64`, `virtio-gl` or
/// `std,clipboard=vnc`. The named form (`type=qxl`) is accepted too,
/// because that is what the property parser does.
fn vga_display_type(value: &str) -> Option<String> {
    let mut named = None;
    let mut positional = None;
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((key, value)) if key.trim().eq_ignore_ascii_case("type") => {
                named = normalize_display_type(value);
            }
            Some(_) => {}
            None if positional.is_none() => positional = normalize_display_type(part),
            None => {}
        }
    }
    named.or(positional)
}

/// Normalise a display type for comparison: Proxmox writes it lower-case,
/// but the value comes from an API response and is not worth trusting.
fn normalize_display_type(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"').trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_ascii_lowercase())
    }
}

/// Proxmox has returned `template` as both a number and a boolean across
/// versions, so accept either.
fn deserialize_template<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Bool(value)) => value,
        Some(serde_json::Value::Number(value)) => value.as_u64().is_some_and(|n| n != 0),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::collections::HashMap;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Instant;

    /// Read one HTTP/1.1 request from `stream`, returning the request
    /// line, lower-cased headers, and body. Test-only and deliberately
    /// minimal: these tests exercise ryll's requests, not HTTP.
    fn read_request(stream: &mut TcpStream) -> (String, HashMap<String, String>, String) {
        let mut data = Vec::new();
        let mut buffer = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).expect("read request");
            assert!(read > 0, "connection closed before the headers ended");
            data.extend_from_slice(&buffer[..read]);
            if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };

        let head = String::from_utf8_lossy(&data[..header_end]).to_string();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().expect("request line").to_string();
        let mut headers = HashMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let length: usize = headers
            .get("content-length")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        while data.len() < header_end + length {
            let read = stream.read(&mut buffer).expect("read request body");
            assert!(read > 0, "connection closed before the body ended");
            data.extend_from_slice(&buffer[..read]);
        }
        let body = String::from_utf8_lossy(&data[header_end..header_end + length]).to_string();
        (request_line, headers, body)
    }

    fn respond_status(stream: &mut TcpStream, status: u16, body: &str, content_type: &str) {
        let reason = match status {
            200 => "OK",
            403 => "Forbidden",
            500 => "Internal Server Error",
            _ => "Error",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    fn respond(stream: &mut TcpStream, body: &str, content_type: &str) {
        respond_status(stream, 200, body, content_type);
    }

    /// Accept with a deadline so a broken request path fails the test
    /// instead of hanging it.
    fn accept_with_deadline(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    // BSD-derived systems, macOS included, let the
                    // accepted socket inherit the listener's non-blocking
                    // flag. Clear it, or a read that races the client's
                    // first byte returns WouldBlock instead of waiting
                    // out the timeout.
                    stream.set_nonblocking(false).expect("blocking stream");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .expect("read timeout");
                    return stream;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "timed out waiting for a request");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    }

    fn mock_listener() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("local address");
        (listener, format!("http://{address}"))
    }

    fn resource_json() -> &'static str {
        r#"{
            "data": [
                {"type": "qemu", "vmid": 101, "name": "web", "node": "pve2", "status": "running", "template": 0},
                {"type": "lxc", "vmid": 102, "name": "container", "node": "pve2", "status": "running"},
                {"type": "qemu", "vmid": 100, "name": "db", "node": "pve1", "status": "stopped", "template": false},
                {"type": "qemu", "vmid": 103, "name": "template", "node": "pve1", "status": "stopped", "template": true},
                {"type": "qemu", "vmid": 104, "name": "odd-node", "node": "bad/node", "status": "running"},
                {"type": "qemu", "vmid": 0, "name": "no-id", "node": "pve1", "status": "running"}
            ]
        }"#
    }

    #[test]
    fn normalizes_bare_host_to_https_and_default_port() {
        let url = normalize_base_url("pve.example").expect("url");
        assert_eq!(url.as_str(), "https://pve.example:8006/");
    }

    #[test]
    fn keeps_explicit_port_and_scheme() {
        let url = normalize_base_url("http://pve.example:8006/").expect("url");
        assert_eq!(url.as_str(), "http://pve.example:8006/");
        let url = normalize_base_url("https://pve.example:443").expect("url");
        assert_eq!(url.as_str(), "https://pve.example/");
    }

    #[test]
    fn strips_pasted_api_path() {
        let url = normalize_base_url("https://pve.example:8006/api2/json").expect("url");
        assert_eq!(url.as_str(), "https://pve.example:8006/");
        let url = normalize_base_url("https://pve.example:8006/api2/").expect("url");
        assert_eq!(url.as_str(), "https://pve.example:8006/");
    }

    #[test]
    fn keeps_a_reverse_proxy_prefix() {
        let url = normalize_base_url("https://example/proxmox/").expect("url");
        assert_eq!(url.as_str(), "https://example:8006/proxmox");
        let endpoint = api_url(&url, "/api2/json/version").expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://example:8006/proxmox/api2/json/version"
        );
    }

    #[test]
    fn api_url_keeps_the_query_out_of_the_path() {
        let url = normalize_base_url("https://pve.example:8006").expect("url");
        let endpoint = api_url(&url, "/api2/json/cluster/resources?type=vm").expect("endpoint");
        assert_eq!(
            endpoint.path(),
            "/api2/json/cluster/resources",
            "the query must not be percent-encoded into the path"
        );
        assert_eq!(endpoint.query(), Some("type=vm"));
    }

    #[test]
    fn refuses_url_credentials() {
        let err = normalize_base_url("https://user:secret@pve.example:8006").expect_err("refused");
        assert!(format!("{err:#}").contains("not in the URL"));
    }

    #[test]
    fn refuses_non_http_schemes() {
        let err = normalize_base_url("ssh://pve.example").expect_err("refused");
        assert!(format!("{err:#}").contains("unsupported URL scheme"));
    }

    #[test]
    fn token_normalization_accepts_both_forms() {
        assert_eq!(
            normalize_token("PVEAPIToken=root@pam!ryll=deadbeef").expect("token"),
            "root@pam!ryll=deadbeef"
        );
        assert_eq!(
            normalize_token("root@pam!ryll=dead=beef").expect("token"),
            "root@pam!ryll=dead=beef"
        );
    }

    #[test]
    fn token_normalization_rejects_missing_secret() {
        let err = normalize_token("root@pam!ryll").expect_err("refused");
        assert!(format!("{err:#}").contains("TOKENID=SECRET"));
    }

    #[test]
    fn parses_and_filters_cluster_resources() {
        let envelope: Envelope<Vec<Resource>> =
            serde_json::from_str(resource_json()).expect("json");
        let mut vms: Vec<ProxmoxVm> = envelope
            .data
            .expect("data")
            .into_iter()
            .filter(|resource| resource.kind.as_deref() == Some("qemu"))
            .filter(|resource| resource.vmid > 0)
            .filter_map(|resource| {
                let node = resource.node?;
                if !valid_node_name(&node) {
                    return None;
                }
                Some(ProxmoxVm {
                    vmid: resource.vmid,
                    name: resource.name,
                    node,
                    status: resource.status,
                    template: resource.template,
                    // Parsing and filtering do not probe; a display is
                    // supplied so the connectability checks below are
                    // about status and templates only.
                    display: Some("qxl".to_string()),
                })
            })
            .collect();
        vms.sort_by(|a, b| a.node.cmp(&b.node).then(a.vmid.cmp(&b.vmid)));

        assert_eq!(vms.len(), 3);
        assert_eq!(vms[0].vmid, 100);
        assert_eq!(vms[1].vmid, 103);
        assert!(vms[1].template);
        assert_eq!(vms[2].vmid, 101);
        assert!(vms[2].is_connectable());
        assert!(!vms[0].is_connectable());
    }

    #[test]
    fn table_is_tab_separated_and_names_an_empty_result() {
        let table = format_vm_table(&[]);
        assert!(table.starts_with("VMID\tNODE\tSTATUS\tNAME\tSPICE\n"));
        assert!(table.contains("no QEMU VMs"));
    }

    fn guest(vmid: u32, status: &str, display: Option<&str>) -> ProxmoxVm {
        ProxmoxVm {
            vmid,
            name: Some(format!("vm{vmid}")),
            node: "pve1".to_string(),
            status: Some(status.to_string()),
            template: false,
            display: display.map(str::to_string),
        }
    }

    #[test]
    fn table_shows_whether_each_guest_supports_spice() {
        let mut template = guest(103, "stopped", None);
        template.template = true;
        let vms = vec![
            guest(100, "running", Some("qxl")),
            guest(101, "stopped", Some("std")),
            guest(102, "running", None),
            template,
        ];
        let table = format_vm_table(&vms);
        assert_eq!(
            table.lines().next(),
            Some("VMID\tNODE\tSTATUS\tNAME\tSPICE")
        );
        let rows: Vec<&str> = table.lines().skip(1).collect();
        assert_eq!(rows[0], "100\tpve1\trunning\tvm100\tyes");
        assert_eq!(rows[1], "101\tpve1\tstopped\tvm101\tno");
        assert_eq!(rows[2], "102\tpve1\trunning\tvm102\tunknown");
        assert_eq!(rows[3], "103\tpve1\tstopped\tvm103\tno");
    }

    #[test]
    fn display_type_is_split_out_of_the_vga_property() {
        assert_eq!(vga_display_type("qxl").as_deref(), Some("qxl"));
        assert_eq!(vga_display_type("qxl,memory=64").as_deref(), Some("qxl"));
        assert_eq!(vga_display_type("virtio-gl").as_deref(), Some("virtio-gl"));
        assert_eq!(
            vga_display_type("type=virtio,memory=32").as_deref(),
            Some("virtio")
        );
        assert_eq!(
            vga_display_type("std,clipboard=vnc").as_deref(),
            Some("std")
        );
        assert_eq!(vga_display_type(" std ").as_deref(), Some("std"));
        assert_eq!(vga_display_type(""), None);
        assert_eq!(vga_display_type("memory=64"), None);
    }

    #[test]
    fn spice_support_needs_a_qxl_or_virtio_display() {
        for display in ["qxl", "qxl2", "qxl3", "qxl4", "virtio", "virtio-gl"] {
            assert!(display_type_supports_spice(display), "{display}");
        }
        for display in ["std", "cirrus", "vmware", "none", "serial0", "qxl5"] {
            assert!(!display_type_supports_spice(display), "{display}");
        }
    }

    #[test]
    fn display_type_defaults_follow_proxmox() {
        let x86: VmConfig = serde_json::from_str("{}").expect("config");
        assert_eq!(x86.display_type(), "std");
        let arm: VmConfig = serde_json::from_str(r#"{"arch":"aarch64"}"#).expect("config");
        assert_eq!(arm.display_type(), "virtio");
        let explicit: VmConfig =
            serde_json::from_str(r#"{"vga":"qxl,memory=64","arch":"aarch64"}"#).expect("config");
        assert_eq!(explicit.display_type(), "qxl");
        let typeless: VmConfig = serde_json::from_str(r#"{"vga":"memory=64"}"#).expect("config");
        assert_eq!(typeless.display_type(), "std");
    }

    #[test]
    fn a_display_without_spice_is_refused_before_asking_proxmox() {
        // Port 1 is never listening: the refusal must come from the
        // display check, not from a failed request.
        let client = token_client("http://127.0.0.1:1");
        let mut vm = guest(100, "running", Some("std"));
        vm.name = Some("web".to_string());
        let error = client.spice_config(&vm).expect_err("refused");
        let message = format!("{error:#}");
        assert!(message.contains("VM 100 (web)"), "{message}");
        assert!(message.contains("display type 'std'"), "{message}");
        assert!(message.contains("SPICE (qxl)"), "{message}");
    }

    #[test]
    fn error_body_prefers_proxmox_message() {
        let message =
            summarize_error_body(r#"{"data":null,"errors":{"vmid":"VM 100 is not running"}}"#);
        assert!(message.contains("VM 100 is not running"));
        assert!(!message.contains('\n'));
    }

    #[test]
    fn error_body_is_truncated() {
        let body = "x".repeat(1000);
        let message = summarize_error_body(&body);
        assert!(message.chars().count() <= 301);
        assert!(message.ends_with('…'));
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_split_token_for_the_form() {
        let settings = ProxmoxLaunchSettings {
            url: "https://pve.example:8006".to_string(),
            profiles: Vec::new(),
            selected_profile: None,
            username: String::new(),
            password: None,
            token: Some("root@pam!ryll=secret".to_string()),
            tls: ProxmoxTls::default(),
            ca_path: None,
            proxy: None,
            auto_vm: None,
            save_requested: false,
            saved_token_present: false,
            token_from_saved: false,
            saved_url: None,
        };
        assert!(settings.can_auto_login());
        assert_eq!(
            settings.token_parts(),
            Some(("root@pam!ryll".to_string(), "secret".to_string()))
        );
    }

    #[test]
    fn cli_flags_parse_a_proxmox_source() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "https://pve.example:8006",
            "--proxmox-user",
            "root@pam",
            "--proxmox-password",
            "secret",
            "--proxmox-vm",
            "100",
        ]);
        assert_eq!(args.proxmox.as_deref(), Some("https://pve.example:8006"));
        assert_eq!(args.proxmox_user.as_deref(), Some("root@pam"));
        assert_eq!(args.proxmox_vm, Some(100));
        validate_args(&args, None).expect("valid");
    }

    #[test]
    fn proxmox_conflicts_with_other_sources() {
        let err = Args::try_parse_from([
            "ryll",
            "--proxmox",
            "https://pve.example:8006",
            "--direct",
            "host:5900",
        ])
        .expect_err("sources conflict");
        assert!(err.to_string().contains("cannot be used with"));
    }

    #[test]
    fn non_gui_proxmox_requires_a_vm() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "https://pve.example:8006",
            "--proxmox-token",
            "root@pam!ryll=secret",
            "--headless",
        ]);
        let err = validate_args(&args, None).expect_err("vm required");
        assert!(format!("{err:#}").contains("--proxmox-vm"));
    }

    #[test]
    fn gui_proxmox_may_prompt_without_credentials() {
        let args = Args::parse_from(["ryll", "--proxmox", "https://pve.example:8006"]);
        validate_args(&args, None).expect("GUI prompts");
        assert!(auth_from_args(&args).expect("auth").is_none());
    }

    #[test]
    fn token_and_user_conflict_at_parse_time() {
        let err = Args::try_parse_from([
            "ryll",
            "--proxmox",
            "https://pve.example:8006",
            "--proxmox-token",
            "root@pam!ryll=secret",
            "--proxmox-user",
            "root@pam",
        ])
        .expect_err("conflict");
        assert!(err.to_string().contains("cannot be used with"));
    }

    #[test]
    fn ticket_login_then_listing_walks_the_per_node_index() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut login = accept_with_deadline(&listener);
            let (request_line, _headers, body) = read_request(&mut login);
            assert_eq!(request_line, "POST /api2/json/access/ticket HTTP/1.1");
            assert!(
                body.contains("username=root%40pam"),
                "unexpected login body: {body}"
            );
            respond(
                &mut login,
                r#"{"data":{"ticket":"ticket","CSRFPreventionToken":"csrf"}}"#,
                "application/json",
            );

            let mut nodes = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut nodes);
            assert_eq!(request_line, "GET /api2/json/nodes HTTP/1.1");
            assert_eq!(
                headers.get("cookie").map(String::as_str),
                Some("PVEAuthCookie=ticket")
            );
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"}]}"#,
                "application/json",
            );

            let mut list = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut list);
            assert_eq!(request_line, "GET /api2/json/nodes/pve1/qemu HTTP/1.1");
            assert_eq!(
                headers.get("cookie").map(String::as_str),
                Some("PVEAuthCookie=ticket")
            );
            respond(
                &mut list,
                r#"{"data":[
                    {"vmid":100,"name":"web","status":"running","template":0}
                ]}"#,
                "application/json",
            );

            // The display probe follows the list, and a running guest is
            // read with its current (not pending) values.
            let mut config = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut config);
            assert_eq!(
                request_line,
                "GET /api2/json/nodes/pve1/qemu/100/config?current=1 HTTP/1.1"
            );
            assert_eq!(
                headers.get("cookie").map(String::as_str),
                Some("PVEAuthCookie=ticket")
            );
            respond(&mut config, r#"{"data":{"vga":"qxl"}}"#, "application/json");
        });

        let client = ProxmoxClient::connect(
            &url,
            ProxmoxAuth::Password {
                username: "root@pam".to_string(),
                password: "secret".to_string(),
            },
            ProxmoxTls::default(),
            None,
        )
        .expect("login");
        let vms = client.list_vms().expect("list");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].vmid, 100);
        assert_eq!(vms[0].node, "pve1");
        assert_eq!(vms[0].display_type(), Some("qxl"));
        assert_eq!(vms[0].supports_spice(), Some(true));
        assert!(vms[0].is_connectable());
        server.join().expect("mock server");
    }

    #[test]
    fn api_token_lists_and_fetches_the_console_document() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut nodes);
            assert_eq!(request_line, "GET /api2/json/nodes HTTP/1.1");
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some("PVEAPIToken=root@pam!ryll=secret")
            );
            assert!(
                !headers.contains_key("cookie"),
                "an API token should not also send a ticket cookie"
            );
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"}]}"#,
                "application/json",
            );

            let mut list = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut list);
            assert_eq!(request_line, "GET /api2/json/nodes/pve1/qemu HTTP/1.1");
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some("PVEAPIToken=root@pam!ryll=secret")
            );
            respond(
                &mut list,
                r#"{"data":[
                    {"vmid":100,"name":"web","status":"running","template":0}
                ]}"#,
                "application/json",
            );

            let mut config = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut config);
            assert_eq!(
                request_line,
                "GET /api2/json/nodes/pve1/qemu/100/config?current=1 HTTP/1.1"
            );
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some("PVEAPIToken=root@pam!ryll=secret")
            );
            respond(
                &mut config,
                r#"{"data":{"vga":"virtio,memory=32"}}"#,
                "application/json",
            );

            let mut spice = accept_with_deadline(&listener);
            let (request_line, headers, body) = read_request(&mut spice);
            assert_eq!(
                request_line,
                "POST /api2/spiceconfig/nodes/pve1/qemu/100/spiceproxy HTTP/1.1"
            );
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some("PVEAPIToken=root@pam!ryll=secret")
            );
            assert_eq!(body, "", "no proxy parameter when Proxmox should choose");
            respond(
                &mut spice,
                "[virt-viewer]\n\
                 type=spice\n\
                 host=pvespiceproxy:abcdef:100:pve1:61000::ticket\n\
                 tls-port=61000\n\
                 password=spice-ticket\n\
                 proxy=http://127.0.0.1:3128\n\
                 host-subject=OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve1.example\n\
                 delete-this-file=1\n",
                "text/plain",
            );
        });

        let client = ProxmoxClient::connect(
            &url,
            ProxmoxAuth::Token {
                token: "PVEAPIToken=root@pam!ryll=secret".to_string(),
            },
            ProxmoxTls::default(),
            None,
        )
        .expect("token setup");
        let vms = client.list_vms().expect("list");
        let config = client.spice_config(&vms[0]).expect("console document");
        assert_eq!(config.host, "pvespiceproxy:abcdef:100:pve1:61000::ticket");
        assert_eq!(config.tls_port, Some(61000));
        assert_eq!(config.password.as_deref(), Some("spice-ticket"));
        assert!(config.proxy.is_some());
        assert!(config.ticket_is_single_use);
        server.join().expect("mock server");
    }

    fn profile(name: &str, host: &str, port: u16, token: Option<&str>) -> ProxmoxProfile {
        ProxmoxProfile {
            name: name.to_string(),
            host: host.to_string(),
            port,
            token: token.map(str::to_string),
            insecure: false,
            ca: None,
        }
    }

    fn saved(profiles: Vec<ProxmoxProfile>) -> SavedProxmox {
        SavedProxmox { profiles }
    }

    fn saved_proxmox(host: &str, port: u16) -> SavedProxmox {
        saved(vec![profile(
            "pve1",
            host,
            port,
            Some("root@pam!ryll=secret"),
        )])
    }

    #[test]
    fn scheme_default_ports_survive_endpoint_strings() {
        let profile = profile("pve", "https://pve.example", 443, None);
        assert_eq!(
            profile_endpoint_string(&profile).as_deref(),
            Some("https://pve.example:443")
        );
        assert!(profile_matches("https://pve.example:443", &profile));
        assert!(!profile_matches("https://pve.example", &profile));
        assert!(endpoint_matches(
            "https://pve.example:443",
            "https://pve.example:443"
        ));
        assert!(!endpoint_matches(
            "https://pve.example:443",
            "https://pve.example"
        ));
    }

    #[test]
    fn profile_matching_normalises_the_endpoint() {
        let saved = saved_proxmox("https://pve.example", 8006);
        let profile = &saved.profiles[0];
        assert!(profile_matches("pve.example", profile));
        assert!(profile_matches("https://pve.example:8006/", profile));
        assert!(profile_matches("https://pve.example", profile));
        assert!(!profile_matches("https://other.example:8006", profile));
        assert!(!profile_matches("https://pve.example:8443", profile));
    }

    #[test]
    fn endpoint_parts_splits_the_host_and_port() {
        assert_eq!(
            endpoint_parts("https://pve.example:8443").expect("endpoint"),
            ("https://pve.example".to_string(), 8443)
        );
        assert_eq!(
            endpoint_parts("https://pve.example").expect("endpoint"),
            ("https://pve.example".to_string(), 8006)
        );
        assert_eq!(
            endpoint_parts("pve.example").expect("endpoint"),
            ("https://pve.example".to_string(), 8006)
        );
    }

    #[test]
    fn a_saved_token_is_used_only_for_its_host() {
        let args = Args::parse_from(["ryll", "--proxmox", "pve.example"]);
        let saved = saved_proxmox("https://pve.example", 8006);
        match auth_for_source(&args, Some(&saved))
            .expect("auth")
            .expect("saved token")
        {
            ProxmoxAuth::Token { token } => {
                assert_eq!(token, "root@pam!ryll=secret");
            }
            ProxmoxAuth::Password { .. } => panic!("expected the saved token"),
        }

        // A profile for a different host must not answer for this one.
        let other = saved_proxmox("https://other.example", 8006);
        let same_host_other_port = Args::parse_from(["ryll", "--proxmox", "pve.example:8443"]);
        assert!(auth_for_source(&same_host_other_port, Some(&saved))
            .expect("auth")
            .is_none());
        assert!(auth_for_source(&args, Some(&other))
            .expect("auth")
            .is_none());
        assert!(auth_for_source(&args, None).expect("auth").is_none());
    }

    #[cfg(feature = "gui")]
    #[test]
    fn matching_profile_is_chosen_among_several() {
        let saved = saved(vec![
            profile("pve1", "https://one.example", 8006, Some("a@pve!t=one")),
            profile("pve2", "https://two.example", 8443, Some("b@pve!t=two")),
        ]);
        let args = Args::parse_from(["ryll", "--proxmox", "https://two.example:8443"]);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert_eq!(settings.url, "https://two.example:8443");
        assert_eq!(settings.token.as_deref(), Some("b@pve!t=two"));
        assert_eq!(settings.selected_profile, Some(1));
        assert_eq!(
            settings.saved_url.as_deref(),
            Some("https://two.example:8443")
        );
    }

    #[cfg(feature = "gui")]
    #[test]
    fn bare_proxmox_uses_the_most_recent_profile() {
        let saved = saved(vec![
            profile("pve1", "https://one.example", 8006, Some("a@pve!t=one")),
            profile("pve2", "https://two.example", 8006, Some("b@pve!t=two")),
        ]);
        let args = Args::parse_from(["ryll", "--proxmox"]);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert_eq!(settings.url, "https://one.example:8006");
        assert_eq!(settings.token.as_deref(), Some("a@pve!t=one"));
        assert_eq!(settings.selected_profile, Some(0));
        assert!(
            !settings.can_auto_login(),
            "a saved token must never log in without Connect"
        );
    }

    #[test]
    fn non_gui_validation_accepts_a_matching_saved_token() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "pve.example",
            "--headless",
            "--proxmox-vm",
            "100",
        ]);
        let saved = saved_proxmox("https://pve.example", 8006);
        validate_args(&args, Some(&saved)).expect("saved token satisfies the requirement");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_prefill_a_saved_connection_without_auto_login() {
        let args = Args::parse_from(["ryll", "--proxmox"]);
        let saved = saved_proxmox("https://pve.example", 8006);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert_eq!(settings.url, "https://pve.example:8006");
        assert_eq!(settings.token.as_deref(), Some("root@pam!ryll=secret"));
        assert!(settings.saved_token_present);
        assert_eq!(settings.selected_profile, Some(0));
        assert!(
            !settings.can_auto_login(),
            "bare --proxmox always shows the prefilled form"
        );
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_require_the_proxmox_flag() {
        let args = Args::parse_from(["ryll"]);
        let saved = saved_proxmox("https://pve.example", 8006);
        assert!(
            ProxmoxLaunchSettings::from_args(&args, Some(&saved))
                .expect("settings")
                .is_none(),
            "a bare launch must not adopt a saved connection"
        );
    }

    #[cfg(feature = "gui")]
    #[test]
    fn bare_proxmox_opens_an_empty_form_without_a_saved_endpoint() {
        let args = Args::parse_from(["ryll", "--proxmox"]);
        let settings = ProxmoxLaunchSettings::from_args(&args, None)
            .expect("settings")
            .expect("proxmox settings");
        assert_eq!(settings.url, "");
        assert!(settings.token.is_none());
        assert!(settings.profiles.is_empty());
        assert_eq!(settings.selected_profile, None);
        assert!(!settings.can_auto_login());
    }

    #[test]
    fn bare_proxmox_parses_as_an_empty_url() {
        let args = Args::parse_from(["ryll", "--proxmox"]);
        assert_eq!(args.proxmox.as_deref(), Some(""));
        let args = Args::parse_from(["ryll", "--proxmox", "https://pve.example:8006"]);
        assert_eq!(args.proxmox.as_deref(), Some("https://pve.example:8006"));
    }

    #[test]
    fn bare_proxmox_needs_a_url_outside_the_gui() {
        for mode in ["--headless", "--web", "--rdp"] {
            let args = Args::parse_from(["ryll", "--proxmox", mode]);
            let error = validate_args(&args, None).expect_err(mode);
            assert!(
                format!("{error:#}").contains("needs a URL"),
                "{mode}: {error:#}"
            );
        }
        let args = Args::parse_from(["ryll", "--proxmox", "--proxmox-list"]);
        assert!(validate_args(&args, None).is_err());
        let args = Args::parse_from(["ryll", "--proxmox"]);
        validate_args(&args, None).expect("the GUI can collect the URL");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_do_not_reuse_a_token_for_a_different_endpoint() {
        let args = Args::parse_from(["ryll", "--proxmox", "https://other.example:8006"]);
        let saved = saved_proxmox("https://pve.example", 8006);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert_eq!(settings.url, "https://other.example:8006");
        assert!(settings.token.is_none());
        assert!(!settings.saved_token_present);
        assert_eq!(settings.selected_profile, None);
    }

    #[test]
    fn saving_preserves_tls() {
        let args = Args::parse_from(["ryll", "--proxmox", "https://pve.example:8006"]);
        let saved = saved(vec![ProxmoxProfile {
            name: "old-name".to_string(),
            host: "https://pve.example".to_string(),
            port: 8006,
            token: None,
            insecure: true,
            ca: None,
        }]);
        let out = profile_for_save(
            &args,
            Some(&saved),
            Some("root@pam!ryll=secret".to_string()),
            "pve1",
        );
        assert_eq!(out.name, "pve1");
        assert_eq!(out.host, "https://pve.example");
        assert_eq!(out.port, 8006);
        assert_eq!(out.token.as_deref(), Some("root@pam!ryll=secret"));
        assert!(out.insecure);
    }

    #[test]
    fn saving_a_password_profile_stores_no_token() {
        let args = Args::parse_from(["ryll", "--proxmox", "https://pve.example:8006"]);
        let out = profile_for_save(&args, None, None, "pve1");
        assert_eq!(out.name, "pve1");
        assert_eq!(out.host, "https://pve.example");
        assert_eq!(out.port, 8006);
        assert!(out.token.is_none());
    }

    #[test]
    fn proxmox_save_flag_parses() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "https://pve.example:8006",
            "--proxmox-token",
            "root@pam!ryll=secret",
            "--proxmox-save",
        ]);
        assert!(args.proxmox_save);
    }

    #[test]
    fn password_flags_disable_the_saved_token_fallback() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "pve.example",
            "--proxmox-user",
            "root@pam",
        ]);
        let saved = saved_proxmox("https://pve.example", 8006);
        assert!(auth_for_source(&args, Some(&saved))
            .expect("auth")
            .is_none());
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_prefer_explicit_password_login_over_a_saved_token() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "pve.example",
            "--proxmox-user",
            "root@pam",
        ]);
        let saved = saved_proxmox("https://pve.example", 8006);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert!(settings.token.is_none());
        assert_eq!(settings.username, "root@pam");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_prefill_an_explicit_url_with_a_saved_token() {
        let args = Args::parse_from(["ryll", "--proxmox", "pve.example"]);
        let saved = saved_proxmox("https://pve.example", 8006);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert!(settings.token.is_some());
        assert!(settings.token_from_saved);
        assert!(!settings.can_auto_login());
    }

    #[cfg(feature = "gui")]
    #[test]
    fn launch_settings_auto_login_with_an_explicit_token() {
        let args = Args::parse_from([
            "ryll",
            "--proxmox",
            "pve.example",
            "--proxmox-token",
            "root@pam!other=secret",
        ]);
        let saved = saved_proxmox("https://pve.example", 8006);
        let settings = ProxmoxLaunchSettings::from_args(&args, Some(&saved))
            .expect("settings")
            .expect("proxmox settings");
        assert!(!settings.token_from_saved);
        assert!(settings.can_auto_login());
    }

    #[cfg(feature = "gui")]
    #[test]
    fn an_explicit_url_with_a_saved_token_logs_in_before_the_window() {
        let args = Args::parse_from(["ryll", "--proxmox", "pve.example"]);
        let saved = saved_proxmox("https://pve.example", 8006);
        assert!(
            uses_saved_credentials(&args, Some(&saved)).expect("decision"),
            "the saved token should skip the connection dialog"
        );
    }

    #[cfg(feature = "gui")]
    #[test]
    fn a_saved_token_alone_does_not_trigger_an_automatic_login() {
        let saved = saved_proxmox("https://pve.example", 8006);

        // Bare `--proxmox` selects among profiles; it names no endpoint to
        // match a token against.
        let bare = Args::parse_from(["ryll", "--proxmox"]);
        assert!(!uses_saved_credentials(&bare, Some(&saved)).expect("decision"));

        // A different endpoint keeps the form, and the token stays home.
        let other = Args::parse_from(["ryll", "--proxmox", "https://other.example:8006"]);
        assert!(!uses_saved_credentials(&other, Some(&saved)).expect("decision"));

        // Explicit command-line credentials keep the in-window login.
        let token = Args::parse_from([
            "ryll",
            "--proxmox",
            "pve.example",
            "--proxmox-token",
            "root@pam!other=secret",
        ]);
        assert!(!uses_saved_credentials(&token, Some(&saved)).expect("decision"));

        // A half-entered password login must not fall back to the saved
        // token and log in as somebody else.
        let user = Args::parse_from([
            "ryll",
            "--proxmox",
            "pve.example",
            "--proxmox-user",
            "root@pam",
        ]);
        assert!(!uses_saved_credentials(&user, Some(&saved)).expect("decision"));
    }

    #[cfg(feature = "gui")]
    #[test]
    fn a_profile_without_a_token_only_prefills_the_form() {
        let args = Args::parse_from(["ryll", "--proxmox", "pve.example"]);
        let saved = saved(vec![profile("pve1", "https://pve.example", 8006, None)]);
        assert!(!uses_saved_credentials(&args, Some(&saved)).expect("decision"));
    }

    #[test]
    fn server_node_name_prefers_the_matching_node() {
        let client = token_client("https://epyc.example:8006");
        assert_eq!(
            client.server_node_name(&["pve1".to_string(), "epyc".to_string()]),
            "epyc"
        );
        assert_eq!(
            client.server_node_name(&["pve1".to_string(), "pve2".to_string()]),
            "pve1"
        );
        assert_eq!(client.server_node_name(&[]), "epyc");
    }

    fn token_client(url: &str) -> ProxmoxClient {
        ProxmoxClient::connect(
            url,
            ProxmoxAuth::Token {
                token: "root@pam!ryll=secret".to_string(),
            },
            ProxmoxTls::default(),
            None,
        )
        .expect("token client")
    }

    #[test]
    fn per_vm_acl_listing_returns_only_the_vms_the_node_index_offers() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut nodes);
            assert_eq!(request_line, "GET /api2/json/nodes HTTP/1.1");
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"},{"node":"pve2"}]}"#,
                "application/json",
            );

            // pve1 returns one VM the token may audit.
            let mut pve1 = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut pve1);
            assert_eq!(request_line, "GET /api2/json/nodes/pve1/qemu HTTP/1.1");
            respond(
                &mut pve1,
                r#"{"data":[{"vmid":100,"name":"web","status":"running","template":0}]}"#,
                "application/json",
            );

            // pve2 returns none: the token has no ACL on its guests.
            let mut pve2 = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut pve2);
            assert_eq!(request_line, "GET /api2/json/nodes/pve2/qemu HTTP/1.1");
            respond(&mut pve2, r#"{"data":[]}"#, "application/json");

            let mut config = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut config);
            assert_eq!(
                request_line,
                "GET /api2/json/nodes/pve1/qemu/100/config?current=1 HTTP/1.1"
            );
            respond(&mut config, r#"{"data":{"vga":"qxl"}}"#, "application/json");
        });

        let vms = token_client(&url).list_vms().expect("list");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].vmid, 100);
        assert_eq!(vms[0].node, "pve1");
        assert_eq!(vms[0].supports_spice(), Some(true));
        server.join().expect("mock server");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn preconnect_uses_the_saved_token_and_returns_the_picker_state() {
        let (listener, url) = mock_listener();
        let (host, port) = endpoint_parts(&url).expect("endpoint parts");
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            let (request_line, headers, _body) = read_request(&mut nodes);
            assert_eq!(request_line, "GET /api2/json/nodes HTTP/1.1");
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some("PVEAPIToken=root@pam!ryll=secret")
            );
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"}]}"#,
                "application/json",
            );

            let mut list = accept_with_deadline(&listener);
            read_request(&mut list);
            respond(
                &mut list,
                r#"{"data":[{"vmid":100,"name":"web","status":"running","template":0}]}"#,
                "application/json",
            );

            let mut config = accept_with_deadline(&listener);
            read_request(&mut config);
            respond(&mut config, r#"{"data":{"vga":"qxl"}}"#, "application/json");
        });

        let saved = saved(vec![profile(
            "pve1",
            &host,
            port,
            Some("root@pam!ryll=secret"),
        )]);
        let args = Args::parse_from(["ryll", "--proxmox", &url]);
        let login = preconnect(&args, Some(&saved)).expect("preconnect");
        assert_eq!(login.node_name, "pve1");
        assert_eq!(login.vms.len(), 1);
        assert_eq!(login.vms[0].vmid, 100);
        server.join().expect("mock server");
    }

    #[test]
    fn one_restricted_node_does_not_hide_vms_on_another() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            read_request(&mut nodes);
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"},{"node":"pve2"}]}"#,
                "application/json",
            );

            let mut pve1 = accept_with_deadline(&listener);
            read_request(&mut pve1);
            respond_status(
                &mut pve1,
                403,
                r#"{"data":null,"errors":{"permission":"denied"}}"#,
                "application/json",
            );

            let mut pve2 = accept_with_deadline(&listener);
            read_request(&mut pve2);
            respond(
                &mut pve2,
                r#"{"data":[{"vmid":104,"name":"db","status":"stopped","template":0}]}"#,
                "application/json",
            );

            // A stopped guest has no running instance, so its pending
            // configuration is the one a start would use.
            let mut config = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut config);
            assert_eq!(
                request_line,
                "GET /api2/json/nodes/pve2/qemu/104/config HTTP/1.1"
            );
            respond(
                &mut config,
                r#"{"data":{"vga":"virtio-gl"}}"#,
                "application/json",
            );
        });

        let vms = token_client(&url).list_vms().expect("list");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].vmid, 104);
        assert_eq!(vms[0].node, "pve2");
        assert_eq!(vms[0].supports_spice(), Some(true));
        assert!(!vms[0].is_connectable(), "the guest is stopped");
        server.join().expect("mock server");
    }

    /// Answer the display probes `annotate_displays` issues, in whatever
    /// order its worker threads produce them.
    fn serve_display_probes(listener: &TcpListener, count: usize) {
        for _ in 0..count {
            let mut stream = accept_with_deadline(listener);
            let (request_line, _headers, _body) = read_request(&mut stream);
            let body = if request_line.contains("/qemu/100/") {
                r#"{"data":{"vga":"qxl,memory=64"}}"#
            } else if request_line.contains("/qemu/101/") {
                r#"{"data":{"vga":"std"}}"#
            } else if request_line.contains("/qemu/102/") {
                // No `vga` key: Proxmox's aarch64 default is virtio.
                r#"{"data":{"arch":"aarch64"}}"#
            } else {
                panic!("unexpected display probe: {request_line}");
            };
            respond(&mut stream, body, "application/json");
        }
    }

    #[test]
    fn listing_records_each_guests_display_type() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            read_request(&mut nodes);
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"}]}"#,
                "application/json",
            );

            let mut list = accept_with_deadline(&listener);
            read_request(&mut list);
            respond(
                &mut list,
                r#"{"data":[
                    {"vmid":100,"name":"web","status":"running","template":0},
                    {"vmid":101,"name":"vga","status":"running","template":0},
                    {"vmid":102,"name":"arm","status":"running","template":0},
                    {"vmid":103,"name":"tmpl","status":"stopped","template":1}
                ]}"#,
                "application/json",
            );

            // The template is not probed: it cannot get a console
            // whatever its display says.
            serve_display_probes(&listener, 3);
        });

        let vms = token_client(&url).list_vms().expect("list");
        assert_eq!(vms.len(), 4);
        assert_eq!(vms[0].display_type(), Some("qxl"));
        assert!(vms[0].is_connectable());
        assert_eq!(vms[1].display_type(), Some("std"));
        assert_eq!(vms[1].supports_spice(), Some(false));
        assert!(!vms[1].is_connectable());
        assert!(
            vms[1]
                .connection_blocker()
                .expect("blocked")
                .contains("display type 'std'"),
            "the blocker should name the display type"
        );
        assert_eq!(vms[2].display_type(), Some("virtio"));
        assert!(vms[2].is_connectable());
        assert_eq!(vms[3].display_type(), None);
        assert!(!vms[3].is_connectable());
        server.join().expect("mock server");
    }

    #[test]
    fn a_failed_display_probe_does_not_offer_the_console() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            read_request(&mut nodes);
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"}]}"#,
                "application/json",
            );

            let mut list = accept_with_deadline(&listener);
            read_request(&mut list);
            respond(
                &mut list,
                r#"{"data":[{"vmid":100,"name":"web","status":"running","template":0}]}"#,
                "application/json",
            );

            let mut config = accept_with_deadline(&listener);
            read_request(&mut config);
            respond_status(
                &mut config,
                403,
                r#"{"data":null,"errors":{"permission":"denied"}}"#,
                "application/json",
            );
        });

        let client = token_client(&url);
        let vms = client.list_vms().expect("list");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].display_type(), None);
        assert_eq!(vms[0].supports_spice(), None);
        assert!(
            !vms[0].is_connectable(),
            "an unreadable display must not be offered as connectable"
        );
        let blocker = vms[0].connection_blocker().expect("blocked");
        assert!(blocker.contains("could not read"), "{blocker}");
        let error = client.spice_config(&vms[0]).expect_err("refused");
        assert!(format!("{error:#}").contains("could not read"));
        server.join().expect("mock server");
    }

    #[test]
    fn falls_back_to_cluster_resources_when_the_per_node_index_fails() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut nodes);
            assert_eq!(request_line, "GET /api2/json/nodes HTTP/1.1");
            respond_status(
                &mut nodes,
                403,
                r#"{"data":null,"errors":{"permission":"denied"}}"#,
                "application/json",
            );

            let mut resources = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut resources);
            assert_eq!(
                request_line,
                "GET /api2/json/cluster/resources?type=vm HTTP/1.1"
            );
            respond(
                &mut resources,
                r#"{"data":[{"type":"qemu","vmid":100,"name":"web","node":"pve1","status":"running","template":0}]}"#,
                "application/json",
            );

            let mut config = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut config);
            assert_eq!(
                request_line,
                "GET /api2/json/nodes/pve1/qemu/100/config?current=1 HTTP/1.1"
            );
            respond(&mut config, r#"{"data":{"vga":"qxl"}}"#, "application/json");
        });

        let vms = token_client(&url).list_vms().expect("fallback list");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].vmid, 100);
        assert_eq!(vms[0].supports_spice(), Some(true));
        server.join().expect("mock server");
    }

    #[test]
    fn falls_back_when_the_per_node_index_is_empty() {
        let (listener, url) = mock_listener();
        let server = thread::spawn(move || {
            let mut nodes = accept_with_deadline(&listener);
            read_request(&mut nodes);
            respond(
                &mut nodes,
                r#"{"data":[{"node":"pve1"}]}"#,
                "application/json",
            );

            let mut pve1 = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut pve1);
            assert_eq!(request_line, "GET /api2/json/nodes/pve1/qemu HTTP/1.1");
            respond(&mut pve1, r#"{"data":[]}"#, "application/json");

            let mut resources = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut resources);
            assert_eq!(
                request_line,
                "GET /api2/json/cluster/resources?type=vm HTTP/1.1"
            );
            respond(
                &mut resources,
                r#"{"data":[{"type":"qemu","vmid":100,"name":"web","node":"pve1","status":"running","template":0}]}"#,
                "application/json",
            );

            let mut config = accept_with_deadline(&listener);
            let (request_line, _, _) = read_request(&mut config);
            assert_eq!(
                request_line,
                "GET /api2/json/nodes/pve1/qemu/100/config?current=1 HTTP/1.1"
            );
            respond(
                &mut config,
                r#"{"data":{"vga":"virtio"}}"#,
                "application/json",
            );
        });

        let vms = token_client(&url).list_vms().expect("fallback list");
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].vmid, 100);
        assert_eq!(vms[0].supports_spice(), Some(true));
        server.join().expect("mock server");
    }
}
