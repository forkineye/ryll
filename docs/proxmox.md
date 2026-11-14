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
the backing user's, so grant the token at least:

- `VM.Audit` on `/vms` or on each guest's `/vms/<vmid>` (to see the guest in
  the list), and
- `VM.Console` on `/vms/<vmid>` for each guest whose console it should open.

Per-VM access is a first-class case, not a requirement to grant `/vms`
recursively. A token with:

```
VM.Audit  on /vms/100
VM.Console on /vms/100
VM.Audit  on /vms/104
VM.Console on /vms/104
```

sees and can open exactly VMs 100 and 104. Ryll's primary listing is
`GET /nodes/{node}/qemu`, which Proxmox documents as returning only VMs where
the caller has `VM.Audit` on `/vms/<vmid>`. A guest the token cannot audit
does not appear, even if it can be opened by ID.

`VM.Console` alone is not enough to discover a guest: Proxmox has no
"console-only" listing. Grant `VM.Audit` on the guest as well if it should
appear in the picker.

API tokens are the better choice for automation: there is no ticket
exchange, no CSRF token, and the secret can be revoked independently of the
user's password.

!!! note

    Ryll never writes credentials to its log, capture metadata or bug
    reports. A password or token passed directly on the command line is
    nevertheless visible to other users of the host in the process list;
    prefer `--proxmox-password-file` / `--proxmox-token-file`, or the GUI
    form, on a shared machine.

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

## GUI

```bash
ryll --proxmox https://pve.example:8006
```

Without credentials the window opens on a login form. Choose username and
password or API token, optionally accept the self-signed certificate, and
press **Connect**. Ryll lists the visible QEMU guests with their node and
status. **Connect** is enabled only for running, non-template guests.

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

Ryll can remember a Proxmox API token so the GUI does not ask for it on every
launch. Password authentication is never saved.

The file is `~/.ryll/config.json` (or
`$RYLL_CONFIG_DIR/config.json` when that environment variable names another
directory). It is created on the first save:

```json
{
  "version": 1,
  "proxmox": {
    "url": "https://pve.example:8006",
    "token": "user@realm!tokenid=secret",
    "insecure": false,
    "ca": "/etc/ssl/certs/pve-ca.pem",
    "auto_connect": false
  }
}
```

Only the endpoint, API token, TLS choice and the automatic-connect preference
are stored. There is no password or username field: the token already contains
the token ID (`user@realm!tokenid`). On Unix the directory is `0700` and the
file `0600`, and an existing file with looser permissions is tightened on the
next read.

### Saving from the GUI

Tick **Remember this token** on the login form before pressing **Connect**.
The token is written only after the login and VM list succeed. The VM list has
a **Forget saved token** button; it removes the token and the automatic-connect
preference but keeps the endpoint and TLS settings.

### Saving from the command line

`--proxmox-save` writes the endpoint and token after a successful login and
list. It stores only API tokens: with `--proxmox-user` /
`--proxmox-password` it logs a warning and writes nothing.

```bash
# Save the endpoint and token, then list the guests
ryll --proxmox https://pve.example:8006 \
     --proxmox-token-file ~/.ryll/pve.token \
     --proxmox-list --proxmox-save

# Later, the saved token is used automatically
ryll --proxmox https://pve.example:8006 --proxmox-list
```

### Launch prompt and auto-connect

A GUI launch that would use a saved token — no explicit `--proxmox-token` /
`--proxmox-token-file` and no username/password on the command line — asks
before doing so. If the saved file holds an API token:

- with `auto_connect: false`, ryll asks whether to use the saved connection.
  **Connect** proceeds; **Not now** opens the prefilled login form. Ticking
  **Don't ask again; connect automatically** before **Connect** sets
  `auto_connect: true` once the login succeeds, so a rejected token is not
  saved as an automatic connection.
- with `auto_connect: true`, ryll logs in and lists the guests without asking.

A saved endpoint with no token opens the login form with the URL and TLS
settings prefilled. Headless, web and RDP launches do not use a saved
configuration unless `--proxmox` is given explicitly.

### Precedence and safety

Command-line values always win over the saved file. A saved token is only
reused when its endpoint normalises to the same URL as `--proxmox`: changing
the URL does not send the old token to the new server. If the URL is edited in
the login form, ryll clears the prefilled token rather than submitting it.

The TLS choice is saved too: `insecure` or the `ca` path. A file that sets
both is refused; remove one of them. A file written by a newer ryll carries a
higher schema `version`; ryll warns and refuses to overwrite it. A malformed
file is ignored with a warning, and `--proxmox-token` still works.

The token is stored in plaintext, protected by the file mode. Use a
privilege-separated Proxmox API token rather than a full account token, and
keep the file out of backups or shared directories you do not control.

## Headless, web and RDP modes

These modes cannot display a picker, so they require both credentials and
`--proxmox-vm`. Use `--proxmox-list` first to discover the ID:

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
  them; the GUI disables their button and the CLI reports why.
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
| `--proxmox <URL>` | Proxmox VE API URL. The scheme defaults to `https` and the port to 8006; a pasted `/api2/json` suffix is tolerated. |
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
| `--proxmox-save` | Save the endpoint, API token and TLS choice to `~/.ryll/config.json` after a successful token login. Password logins are never saved. |

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
or one written by a newer schema is not used; a file whose `ca` and
`insecure` are both set is refused. Fix or remove the file. Set
`RYLL_CONFIG_DIR` to use a different directory.

## See also

- [Configuration](configuration.md) for every CLI option and the `.vv` key
  reference.
- [Multi-mode feature parity](multi-mode-parity.md) for what each mode
  reaches.
- [Session lifecycle](session-lifecycle.md) for how single-use tickets
  affect reconnect.
