#!/bin/bash
# Install the native messaging host used by the ryll .vv launcher extension.
#
# This writes one small JSON file per Chromium-family browser found under
# ~/Library/Application Support.  It does not touch Chrome's preferences and
# needs no sudo.  Run it after (or before) loading the unpacked extension;
# the extension ID is derived from the key pinned in manifest.json, so the
# two sides always agree.
set -euo pipefail

HOST_NAME="com.shakenfist.ryll"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR="$(cd "$SCRIPT_DIR/../extension" && pwd)"
HOST_PATH="$SCRIPT_DIR/ryll-vv-host.py"
MANIFEST="$EXTENSION_DIR/manifest.json"

if [ ! -f "$MANIFEST" ]; then
    echo "error: $MANIFEST is missing" >&2
    exit 1
fi
if [ ! -x /usr/bin/python3 ]; then
    echo "error: /usr/bin/python3 is required (install the Xcode command line tools)" >&2
    exit 1
fi

chmod +x "$HOST_PATH"

# Normally the ID is derived from the public key pinned in manifest.json.  The
# override exists for the unlikely case where Chrome ignores the key and
# assigns a path-derived ID; chrome://extensions shows which one it used.
if [ "${1:-}" = "--extension-id" ]; then
    if [ -z "${2:-}" ]; then
        echo "usage: $0 [--extension-id <32-character id>]" >&2
        exit 2
    fi
    EXT_ID="$2"
else
    EXT_ID="$(/usr/bin/python3 - "$MANIFEST" <<'PY'
import base64
import hashlib
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
key = manifest.get("key")
if not key:
    sys.exit("manifest.json has no 'key'; the extension ID would not be stable")
digest = hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
print("".join(chr(ord("a") + int(nibble, 16)) for nibble in digest))
PY
)"
fi

case "$EXT_ID" in
    *[!a-p]* | "")
        echo "error: invalid extension ID: '$EXT_ID'" >&2
        exit 1
        ;;
esac
if [ "${#EXT_ID}" -ne 32 ]; then
    echo "error: extension ID must be 32 characters: '$EXT_ID'" >&2
    exit 1
fi

# label|user-data-directory, relative to ~/Library/Application Support.
BROWSERS=(
    "Google Chrome|Google/Chrome"
    "Google Chrome Beta|Google/Chrome Beta"
    "Google Chrome Dev|Google/Chrome Dev"
    "Google Chrome Canary|Google/Chrome Canary"
    "Chromium|Chromium"
    "Microsoft Edge|Microsoft Edge"
    "Brave|BraveSoftware/Brave-Browser"
)

installed=0
for entry in "${BROWSERS[@]}"; do
    label="${entry%%|*}"
    relative="${entry#*|}"
    base="$HOME/Library/Application Support/$relative"
    if [ ! -d "$base" ]; then
        continue
    fi

    host_dir="$base/NativeMessagingHosts"
    mkdir -p "$host_dir"
    target="$host_dir/$HOST_NAME.json"

    /usr/bin/python3 - "$target" "$HOST_NAME" "$HOST_PATH" "$EXT_ID" <<'PY'
import json
import sys

target, name, host_path, ext_id = sys.argv[1:5]
payload = {
    "name": name,
    "description": "Launch ryll for downloaded .vv SPICE console files",
    "path": host_path,
    "type": "stdio",
    "allowed_origins": [f"chrome-extension://{ext_id}/"],
}
with open(target, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")
PY

    echo "installed native host for $label"
    echo "  $target"
    installed=$((installed + 1))
done

if [ "$installed" -eq 0 ]; then
    echo "error: no Chrome/Chromium user data directory found under" >&2
    echo "       $HOME/Library/Application Support" >&2
    exit 1
fi

RYLL_PATH="$(command -v ryll || true)"
echo
echo "extension ID: $EXT_ID"
if [ -n "$RYLL_PATH" ]; then
    echo "ryll binary:  $RYLL_PATH"
else
    echo "warning: ryll is not on PATH; the host will look in /opt/homebrew/bin,"
    echo "         /usr/local/bin and ~/.cargo/bin"
fi
echo
echo "Next, load the extension:"
echo "  1. Open chrome://extensions"
echo "  2. Turn on Developer mode"
echo "  3. Click 'Load unpacked' and choose:"
echo "       $EXTENSION_DIR"
echo "  4. Confirm the card shows ID $EXT_ID"
echo
echo "Then download a .vv file (or run test/serve.py) and ryll should open."
