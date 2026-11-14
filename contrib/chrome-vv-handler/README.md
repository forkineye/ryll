# Chrome `.vv` handler for ryll

A small Chrome extension plus a native messaging host that runs

```sh
ryll --file /path/to/downloaded.vv
```

whenever a `.vv` download completes. It is aimed at Proxmox VE's **SPICE**
console button, which downloads a `.vv` file instead of opening a viewer.

This is a local desktop integration, not part of the `ryll` binary and not
exercised by CI.

## Why it needs an extension and a native host

Chrome will not start an arbitrary executable when a download finishes:

- `chrome.downloads.open()` only works in response to a user gesture, so it
  cannot be called from a download-completed event.
- The "Always open files of this type" preference is filtered through Safe
  Browsing's `IsAllowedToOpenAutomatically()` allowlist, which is built around
  a fixed set of common file types rather than arbitrary extensions.
- Protocol handlers (`navigator.registerProtocolHandler`) work on URLs;
  Proxmox hands the browser a file, not a `spice://` link.

Extensions also cannot spawn processes directly, so the launch goes through
Chrome's [native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
host, which is a normal executable Chrome runs on the extension's behalf.

## What is here

| Path | Purpose |
|------|---------|
| `extension/` | Manifest V3 extension. Watches completed downloads, calls the host. |
| `native/ryll-vv-host.py` | The native messaging host. Validates the path and starts ryll. |
| `native/install.sh` | Writes the host manifest for each Chrome-family browser found. |
| `native/uninstall.sh` | Removes those host manifests. |
| `test/serve.py` | Serves a sample `.vv` download so the flow can be checked without Proxmox. |
| `test/test_host.py` | Unit tests for the host's protocol and path validation. |

## Requirements

- macOS (the installer uses `~/Library/Application Support` paths).
- Google Chrome, or a Chromium sibling with the same native messaging layout
  (Chrome Beta/Dev/Canary, Chromium, Edge, Brave are all detected).
- `ryll` installed. Homebrew's `/opt/homebrew/bin/ryll` is found
  automatically, as are `/usr/local/bin/ryll`, `~/.cargo/bin/ryll` and
  whatever `PATH` Chrome happens to have.
- `/usr/bin/python3` (the Xcode command line tools provide it).

## Install

Run these from this directory (`contrib/chrome-vv-handler/`).

1. Install the native messaging host:

   ```sh
   ./native/install.sh
   ```

   It prints the extension ID and the browser(s) it configured.

2. In Chrome, open `chrome://extensions`, turn on **Developer mode**, click
   **Load unpacked**, and select the `extension/` directory from this repo.

3. Check that the extension card shows this ID:

   ```
   gamfdpehogangeopghajiahmelamijmd
   ```

   That ID is derived from the public key pinned in `extension/manifest.json`.
   If Chrome shows a different one (which should not happen), rerun the
   installer with that ID and reload the extension, otherwise the native host
   will reject it:

   ```sh
   ./native/install.sh --extension-id <id-from-chrome>
   ```

4. Download a `.vv` file. ryll should start as soon as Chrome finishes
   writing it.

If Chrome was already running when you ran `install.sh`, restart it before
testing. That guarantees the new native host manifest is picked up.

## Test without Proxmox

```sh
./test/serve.py
```

Open <http://127.0.0.1:8765/> in Chrome and click the download link. The
sample points at `127.0.0.1:5900`, so ryll will open and report that it cannot
connect -- the launch is what is being tested.

The sample sets `delete-this-file=1`, so ryll removes the downloaded copy
after parsing it. Proxmox's `qemu-server` sets the same key for its generated
`.vv` files.

The host's protocol and path checks have unit tests that need no Chrome:

```sh
python3 test/test_host.py
```

## How it works

1. `chrome.downloads.onChanged` fires with `state: "complete"`.
2. `background.js` looks the item up, keeps it if the local filename ends in
   `.vv`, and calls `chrome.runtime.sendNativeMessage("com.shakenfist.ryll",
   {path})`.
3. Chrome starts `native/ryll-vv-host.py` and writes the length-prefixed JSON
   request.
4. The host checks that the path is absolute, ends in `.vv`, is a regular
   readable file, and is at most 1 MiB, then runs
   `ryll --file <path>` in a new session and exits immediately.
5. ryll parses the `.vv`, deletes it if it set `delete-this-file=1`, and
   connects.

The host deliberately does not wait for ryll, and starts it in a new session
so it survives Chrome reaping the native host process.

## Troubleshooting

**Nothing happens.** Open `chrome://extensions`, find the extension, and click
**service worker** to see its console. The usual messages are:

- `Specified native messaging host not found` -- `install.sh` was not run for
  the browser or user-data directory you are actually using.
- `Access to the specified native messaging host is forbidden` -- the
  extension ID does not match `allowed_origins` in the installed manifest.

**Check the installed manifest.** For the stable Chrome channel it is:

```sh
cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.shakenfist.ryll.json
```

**Check the host directly.** This bypasses Chrome and prints the host's
length-prefixed reply (the first four bytes are the length):

```sh
cat >/tmp/test.vv <<'EOF'
[virt-viewer]
host=127.0.0.1
port=5900
delete-this-file=1
EOF

/usr/bin/python3 - <<'PY' | ./native/ryll-vv-host.py | tail -c +5
import json, struct, sys
body = json.dumps({"path": "/tmp/test.vv"}).encode()
sys.stdout.buffer.write(struct.pack("=I", len(body)) + body)
PY
```

A successful reply looks like `{"ok":true,"pid":12345}` and opens ryll.

**Check the log.** The host appends launches and errors to:

```
~/Library/Logs/ryll/chrome-vv-handler.log
```

It is rotated to `.1` at 256 KiB and never records `.vv` contents. ryll's own
stdout and stderr are appended to `ryll-stderr.log` beside it (rotated at
1 MiB), so a launch that exits before showing a window leaves its error there.

**ryll is not found.** Install it (`brew install shakenfist/tap/ryll`) or add
its path to `RYLL_CANDIDATES` in `native/ryll-vv-host.py`. Setting `RYLL_BIN`
in a shell profile will not usually reach Chrome, which is started by
launchd rather than from that shell.

## Uninstall

```sh
./native/uninstall.sh
```

Then remove the extension from `chrome://extensions`.

## Security notes

- The host accepts connections only from the extension ID in the installed
  manifest's `allowed_origins`; that ID is pinned by the public key in
  `extension/manifest.json`.
- The host launches only absolute paths that end in `.vv`, resolve to a
  regular readable file, and are at most 1 MiB. It passes the path as an
  argument, never through a shell.
- Every `.vv` download triggers a launch, not only Proxmox's. That is
  intentional -- oVirt and OpenStack also hand out `.vv` files -- but it does
  mean a hostile site can cause a download that ryll then opens. A `.vv` is
  only a connection descriptor, and ryll still has to connect and
  authenticate.
- `.vv` files can contain a one-time SPICE ticket. Proxmox sets
  `delete-this-file=1`, so ryll removes the file after parsing it. A `.vv`
  from another source without that key is left in place.
- The extension has no site access and no host permissions. It uses the
  `downloads` permission only to see completed downloads, and `nativeMessaging`
  only to call the fixed host name above.

## Customising

To change the command, edit the `subprocess.Popen` argument list in
`native/ryll-vv-host.py`. For example, pinning the window size:

```python
[ryll, "--no-obey-guest-size", "--file", path]
```

To restrict the handler to Proxmox, add a check in `background.js` before
`sendNativeMessage`, for example on `item.finalUrl` or `item.referrer`:

```js
const fromPve = /\/spiceproxy\b/.test(item.finalUrl || item.url || "");
if (!fromPve) return;
```

Adjust the pattern to match your PVE endpoint; the download URL is visible in
the extension's service worker console.
