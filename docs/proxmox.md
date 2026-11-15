# Proxmox VE connection source

Ryll can log in to Proxmox VE, list the QEMU guests the login can see, and
connect to a chosen guest's SPICE console. It does **not** create, start,
stop, clone or reconfigure virtual machines: the only lifecycle endpoint it
calls is the one that returns a console document.

The GUI opens a login form and a VM picker. The other modes take the login
and the VM ID on the command line, and `--proxmox-list` prints the same table
for scripted discovery.

## How it works

Proxmox exposes a guest console as a `.vv` document at:

```
POST /api2/spiceconfig/nodes/{node}/qemu/{vmid}/spiceproxy
```

The document carries the same keys a virt-viewer `.vv` file does, including
the `proxy=` key that names the node's `spiceproxy` service and a short-lived
ticket in `password`. Ryll feeds that document through its existing `.vv`
parser, so the SPICE handshake, the HTTP CONNECT tunnel, TLS and
`host-subject` checking are the same code paths a `.vv` launch uses.

A few API calls precede it:

| Request | Purpose |
|---------|---------|
| `POST /api2/json/access/ticket` | Password login, returns a ticket and `CSRFPreventionToken`. API-token logins skip it. |
| `GET /api2/json/nodes` | The cluster's node names. |
| `GET /api2/json/nodes/{node}/qemu` | The primary VM list. Proxmox returns only the VMs where the caller has `VM.Audit` on `/vms/{vmid}`, which is exactly what per-VM ACLs need. |
| `GET /api2/json/cluster/resources?type=vm` | Fallback list if the per-node index is unavailable or empty. Ryll keeps the `type: qemu` rows and discards LXC containers. |
| `POST /api2/spiceconfig/nodes/{node}/qemu/{vmid}/spiceproxy` | The selected guest's `.vv` document. |

## Authentication

Both Proxmox authentication methods are supported.

### Username and password

The username is a Proxmox user ID such as `root@pam` or
`alice@pve`. Ryll exchanges it for a ticket, which is used as the
`PVEAuthCookie` cookie; the console request also sends the CSRF token.
Tickets expire on Proxmox's schedule (30 seconds by default), and ryll
requests the console document immediately before connecting.

### API token

An API token is sent as:

```
Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET
```

The `PVEAPIToken=` prefix is optional on the command line and in the GUI.
Token permissions are the intersection of the token's own permissions and
the backing user's. The privileges ryll needs, and a per-VM `pveum` example,
are in [Required privileges](#required-privileges).

API tokens are the better choice for automation: there is no ticket
exchange, no CSRF token, and the secret can be revoked independently of the
user's password.

!!! note

    Ryll never writes credentials to its log, capture metadata or bug
    reports. A password or token passed directly on the command line is
    nevertheless visible to other users of the host in the process list;
    prefer `--proxmox-password-file` / `--proxmox-token-file`, or the GUI
    form, on a shared machine.

## Required privileges

Ryll needs exactly two privileges:

| Privilege | Granted on | Why |
|-----------|------------|-----|
| `VM.Audit` | `/vms/<vmid>` (or `/vms`, or a pool containing it) | Discover the guest and its node in the picker |
| `VM.Console` | `/vms/<vmid>` | Request the SPICE console document |

`VM.PowerMgmt` is **not** required: ryll does not start, stop or reconfigure
guests.

Per-VM access is a first-class case, not a requirement to grant `/vms`
recursively. A login with:

```
VM.Audit   on /vms/100
VM.Console on /vms/100
VM.Audit   on /vms/104
VM.Console on /vms/104
```

sees and can open exactly VMs 100 and 104. Ryll's primary listing is
`GET /nodes/{node}/qemu`, which Proxmox documents as returning only VMs where
the caller has `VM.Audit` on `/vms/<vmid>`. A guest the login cannot audit
does not appear, even if it can be opened by ID.

`VM.Console` alone is not enough to discover a guest: Proxmox has no
"console-only" listing. Grant `VM.Audit` on the guest as well if it should
appear in the picker.

A custom role with only those privileges, granted to a user and to a
privilege-separated API token on one VM, looks like this on the Proxmox host:

```bash
pveum role add RyllConsole -privs "VM.Audit VM.Console"
pveum acl modify /vms/100 --roles RyllConsole --users alice@pve
pveum acl modify /vms/100 --roles RyllConsole --tokens 'alice@pve!ryll'
```

Grant the role on `/pool/<pool>` or `/vms` instead of `/vms/<vmid>` when the
login should reach more than one guest. With a privilege-separated token,
grant the role to both the user and the token: the token's effective
permissions are the intersection of the two.

The built-in `PVEVMUser` role also works but grants more than ryll needs.
`PVEAuditor` is not sufficient: it has `VM.Audit` but not `VM.Console`.

## TLS

Proxmox installs a self-signed certificate by default, so a fresh
installation fails certificate verification until you tell ryll what to
trust. There are two options:

- `--proxmox-ca <PATH>` adds a PEM certificate or chain to the platform
  trust roots. This is the preferred option when the certificate is stable.
- `--proxmox-insecure` accepts any certificate. Use it only as a stop-gap.

The flags are mutually exclusive. TLS is used for the **API** connection;
the SPICE side's TLS comes from the console document's `tls-port` and
`host-subject` keys, exactly as it does for a `.vv` file.

An `http://` URL is accepted for a lab or a loopback test, but it sends the
password or token in clear. Use `https://` anywhere the network is not
trusted.

## Display configuration

For the guest desktop to follow ryll's window (or the browser viewport) when
it is resized, configure the VM with **VirtIO-GPU** and enough video memory.
Proxmox labels the display model `virtio` and calls it VirtIO-GPU in the web
UI. A recommended starting point is **32 MiB** of video memory.

In the Proxmox web UI:

- Open the VM → **Hardware** → **Display**.
- Set **Graphic card** to **VirtIO-GPU**.
- Set **Memory** to **32 MiB**.

From the Proxmox host shell:

```bash
qm set <vmid> --vga virtio,memory=32
```

The corresponding line in `/etc/pve/qemu-server/<vmid>.conf` is:

```
vga: virtio,memory=32
```

Stop the VM and start it again after changing the display model or its
memory. A guest reboot does not reconfigure the virtual display. Raise the
memory above 32 MiB if a high-resolution guest stops following the window
once the desktop is large; the video memory limits the usable resolution.

The guest side matters as well:

- the guest must have a VirtIO-GPU driver (the in-tree `virtio_gpu` driver on
  Linux, the virtio-gpu driver on Windows), and
- `spice-vdagent` must be installed and running, because ryll's resize path
  sends `VDAgentMonitorsConfig` through the SPICE guest agent.

A VM with another display model can still show a SPICE console, but ryll's
desktop resize is tested against VirtIO-GPU and is not guaranteed to follow
the host window with QXL or standard VGA.

## GUI

```bash
# Open the connection dialog, prefilled from the most recent saved profile
ryll --proxmox

# Or open it with this endpoint already filled in
ryll --proxmox https://pve.example:8006
```

A bare `ryll` with no flags prints the usage instead of opening a saved
connection; `--proxmox` is the explicit way into the Proxmox dialog. With no
URL, the most recent saved profile is used when one exists, and the URL field is left
empty when there is not.

Without credentials the window opens as a compact connection dialog with a
login form. The endpoint is entered as a URL and a port; the **Port** field is
prefilled with Proxmox's standard **8006**, so `https://pve.example` is enough
unless the installation listens elsewhere. Choose username and password or
API token, optionally accept the self-signed certificate, and press
**Connect**. The dialog keeps its primary action pinned at the foot, so a
long error message or an expanded **Advanced** section scrolls without
hiding it. Ryll then lists the visible QEMU guests with their node and
status, and **Connect** is enabled only for running guests. Templates are not
shown: Proxmox cannot mint a console for them.
Choosing a guest hands the window to the session, which is sized for the
guest desktop; the dialog itself exists only for the connection.

When a saved token is available, the login form's **Remember this token**
checkbox is how ryll learns it may write one; see
[Saved configuration](#saved-configuration).

Supplying credentials on the command line skips the form but still shows the
list:

```bash
ryll --proxmox https://pve.example:8006 \
     --proxmox-user root@pam \
     --proxmox-password-file ~/.ryll/pve.pass
```

`--proxmox-vm 100` selects that guest automatically once the list arrives,
without showing the picker. The rest of the window is the normal ryll
session.


## Saved configuration

Ryll can remember multiple Proxmox VE profiles, each with its own API token,
so the GUI does not ask for credentials on every launch. Password
authentication is never saved.

The file is `~/.ryll/config.json` (or
`$RYLL_CONFIG_DIR/config.json` when that environment variable names another
directory). It is created on the first save:

```json
{
  "version": 1,
  "proxmox": {
    "profiles": [
      {
        "name": "pve1",
        "host": "https://pve-one.example",
        "port": 8006,
        "token": "user@realm!tokenid=secret",
        "insecure": false,
        "ca": "/etc/ssl/certs/pve-ca.pem"
      },
      {
        "name": "pve2",
        "host": "http://pve-two.example",
        "port": 8443,
        "token": "other@pve!tokenid=secret",
        "insecure": true
      }
    ]
  }
}
```

`host` is the endpoint URL without its port (the scheme defaults to `https`);
`port` is stored separately. `name` is the Proxmox node name ryll captured when
the connection succeeded, and is how the profile appears in the login form's
picker. On a cluster it is the node whose name matches the endpoint host,
falling back to the first node the cluster lists. A token belongs to the host
and port it was saved with, so profiles for different servers never share
credentials. Reconnecting to the same host and port updates that profile in
place; the most recently used profile is kept first.

Only endpoints, API tokens and TLS choices are stored. There is no password
or username field: the token already contains the token ID
(`user@realm!tokenid`). On Unix the directory is `0700` and the file `0600`,
and an existing file with looser permissions is tightened on the next read.

### Saving from the GUI

The login form's header has a profile picker. Choosing a saved profile fills
in its host, port, token and TLS settings; **New connection** clears the
endpoint fields for another host.

Press **Connect**. After the login and VM list succeed, ryll saves the
connection as a profile named after the Proxmox node it reached, updating the
entry for that host and port. Tick **Remember this token** to keep the token;
ryll always shows this form before connecting to a saved profile. A profile
whose token was not remembered is still saved — with its endpoint and TLS
settings but no token.

The VM list's **Forget saved token** button removes the token from the profile
for the connected endpoint; the profile itself (host, port and TLS) remains.

### Saving from the command line

`--proxmox-save` writes or updates the profile after a successful login and
list, named after the node ryll connected to. Only API tokens are stored:
with `--proxmox-user` / `--proxmox-password` it logs a warning and saves the
endpoint and TLS settings without a token.

```bash
# Save the endpoint and token, then list the guests
ryll --proxmox https://pve.example:8006 \
     --proxmox-token-file ~/.ryll/pve.token \
     --proxmox-list --proxmox-save

# Later, the matching profile's saved token is reused
ryll --proxmox https://pve.example:8006 --proxmox-list
```

### Saved profiles

`ryll --proxmox` with no URL uses the most recently used saved profile. The
normal **Connect to Proxmox VE** form opens with that profile selected; the
header picker switches to another profile or to **New connection**. A token
prefilled from a profile is not sent anywhere until **Connect** is pressed:
in the GUI, ryll never connects to a saved profile automatically.

A profile with no token opens the login form with its URL, port and TLS
settings prefilled. Headless, web and RDP launches require an explicit
`--proxmox <URL>`; the matching profile supplies the token and TLS settings,
and a saved token is never sent to a different endpoint.

### Precedence and safety

Command-line values always win over the saved file. A saved token is only
reused for the host and port of its own profile: changing the URL does not
send the old token to a new server. If the URL is edited in the login form,
ryll clears the prefilled token rather than submitting it.

The TLS choice is saved too: `insecure` or the `ca` path. A file that sets
both is refused; remove one of them. A file with an unrecognised schema
`version` is ignored with a warning, and one written by a newer ryll is not
overwritten. A malformed file is ignored with a warning, and
`--proxmox-token` still works.

The token is stored in plaintext, protected by the file mode. Use a
privilege-separated Proxmox API token rather than a full account token, and
keep the file out of backups or shared directories you do not control.

## Headless, web and RDP modes

These modes cannot display a picker, so they require an explicit
`--proxmox <URL>`, credentials and `--proxmox-vm`. Use `--proxmox-list`
first to discover the ID:

```bash
# Print the visible guests and exit
ryll --proxmox https://pve.example:8006 \
     --proxmox-token-file ~/.ryll/pve.token \
     --proxmox-list

# Headless session against VM 100
ryll --proxmox https://pve.example:8006 \
     --proxmox-token-file ~/.ryll/pve.token \
     --proxmox-vm 100 --headless

# Serve VM 100 to a browser or an RDP client
ryll --proxmox https://pve.example:8006 \
     --proxmox-user root@pam --proxmox-password-file ~/.ryll/pve.pass \
     --proxmox-vm 100 --web
ryll --proxmox https://pve.example:8006 \
     --proxmox-user root@pam --proxmox-password-file ~/.ryll/pve.pass \
     --proxmox-vm 100 --rdp
```

`--proxmox-list` is a plain tab-separated table (header included), so it can
be piped into `awk` or `cut`:

```
VMID	NODE	STATUS	NAME
100	pve1	running	web
101	pve2	stopped	db
```

## Reconnecting

A Proxmox console ticket is short-lived and bound to the request that
produced it. Ryll marks the resulting configuration as single-use, the same
way it treats a `.vv` with `delete-this-file=1`, so automatic reconnect is
suppressed and the session shows the single-use ticket state instead of
retrying a ticket that cannot work. To reconnect, relaunch; the GUI picker
and the `--proxmox-vm` path each ask Proxmox for a fresh document.

## What ryll will not connect to

- **LXC containers.** They have no SPICE console and are filtered out of the
  list.
- **Stopped guests and templates.** Proxmox cannot mint a console ticket for
  them; the GUI hides templates and disables Connect for stopped guests, and
  the CLI reports why.
- **A guest whose display is not SPICE.** Proxmox returns an API error when
  the console document cannot be produced; ryll shows that error rather than
  dialling a stale address.
- **A guest the login cannot see.** The cluster-resource endpoint is already
  ACL-filtered, and `--proxmox-vm` names an ID that is not in the returned
  list as an error with the visible list attached.

Ryll deliberately does not probe every guest's display configuration while
building the list: that would cost a request per VM and would require
console permission on every guest merely to draw the picker.

## Options

| Option | Description |
|--------|-------------|
| `--proxmox [URL]` | Proxmox VE API URL. The scheme defaults to `https` and the port to 8006; a pasted `/api2/json` suffix is tolerated. In the GUI the URL may be omitted to open the form with the saved profile. |
| `--proxmox-user <USER>` | Proxmox user ID for password authentication, such as `root@pam`. |
| `--proxmox-password <PASSWORD>` | Password. Visible in the process list. |
| `--proxmox-password-file <PATH>` | Read the password from a file, stripping one trailing newline. |
| `--proxmox-token <TOKEN>` | API token as `USER@REALM!TOKENID=SECRET`. |
| `--proxmox-token-file <PATH>` | Read the token from a file, stripping one trailing newline. |
| `--proxmox-ca <PATH>` | PEM CA or chain to trust for the API connection. |
| `--proxmox-insecure` | Accept any API certificate. Conflicts with `--proxmox-ca`. |
| `--proxmox-proxy <HOST>` | Ask Proxmox to put this host in the console document's `proxy=` key. Omit to let Proxmox choose the guest's node. |
| `--proxmox-vm <VMID>` | Guest to connect to. Required outside the GUI. |
| `--proxmox-list` | Log in, print the visible QEMU guests, and exit. |
| `--proxmox-save` | Save or update a node-named profile in `~/.ryll/config.json` after a successful token login: endpoint host and port, API token and TLS choice. Password logins are never saved. |

## Troubleshooting

**HTTP 401 or 403 from the login or list.** Wrong password, revoked token,
or a token whose permissions do not include `VM.Audit` on `/vms` or on the
specific `/vms/<vmid>` paths. Proxmox returns `403` for a token that
authenticated but is not allowed to see the requested resource.

**A certificate error before the login.** The Proxmox certificate is not
trusted. Pass `--proxmox-ca` with the CA that signed it, or use
`--proxmox-insecure` while testing.

**"VM 100 is not running."** Start the guest with Proxmox's own tooling
(the web UI, `qm start`, or the API); ryll does not start guests.

**"Proxmox returned a SPICE console document ... with no `proxy=` key."**
The response did not look like Proxmox's console document. Check that the
URL points at the Proxmox API (port 8006) and not a reverse proxy that
rewrites the `spiceconfig` path.

**The list is empty.** The login can audit no QEMU guests. Confirm the user
or token has `VM.Audit` on the cluster, the relevant pool, or the individual
`/vms/<vmid>` paths, and that the guests are QEMU VMs rather than LXC
containers.

**A VM is missing from the list.** Ryll lists what Proxmox says the login
may audit. Grant `VM.Audit` on that guest's `/vms/<vmid>` path (and
`VM.Console` on the same path to open its console). Per-VM grants are
enough; `/vms` itself does not need to be granted.

**The saved token is rejected.** It may have expired or been revoked. Use
**Forget saved token** in the VM list, or delete `~/.ryll/config.json`, then
log in and save a new one.

**`~/.ryll/config.json` is ignored.** Ryll logs the reason. A malformed file
or one whose schema version this build does not use is not read; a file whose
`ca` and `insecure` are both set is refused. Fix or remove the file. Set
`RYLL_CONFIG_DIR` to use a different directory.

## See also

- [Configuration](configuration.md) for every CLI option and the `.vv` key
  reference.
- [Multi-mode feature parity](multi-mode-parity.md) for what each mode
  reaches.
- [Session lifecycle](session-lifecycle.md) for how single-use tickets
  affect reconnect.
