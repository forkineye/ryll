#!/bin/bash
# Remove the native messaging host manifests installed by install.sh.
#
# The unpacked extension is not touched: remove it from chrome://extensions if
# you no longer want the handler.
set -euo pipefail

HOST_NAME="com.shakenfist.ryll"

BROWSERS=(
    "Google Chrome|Google/Chrome"
    "Google Chrome Beta|Google/Chrome Beta"
    "Google Chrome Dev|Google/Chrome Dev"
    "Google Chrome Canary|Google/Chrome Canary"
    "Chromium|Chromium"
    "Microsoft Edge|Microsoft Edge"
    "Brave|BraveSoftware/Brave-Browser"
)

removed=0
for entry in "${BROWSERS[@]}"; do
    label="${entry%%|*}"
    relative="${entry#*|}"
    target="$HOME/Library/Application Support/$relative/NativeMessagingHosts/$HOST_NAME.json"
    if [ -f "$target" ]; then
        rm -f "$target"
        echo "removed $label: $target"
        removed=$((removed + 1))
    fi
done

if [ "$removed" -eq 0 ]; then
    echo "no native host manifests found"
else
    echo
    echo "Remove the extension itself from chrome://extensions if it is listed."
fi
