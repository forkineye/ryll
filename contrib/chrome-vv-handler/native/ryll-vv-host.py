#!/usr/bin/python3
"""Chrome native messaging host for the ryll .vv launcher extension.

Chrome runs this once per `chrome.runtime.sendNativeMessage()` call, writes a
length-prefixed JSON request to stdin, and expects a length-prefixed JSON
response on stdout.  The request is::

    {"path": "/Users/me/Downloads/console.vv"}

The host validates the path, launches ``ryll --file <path>`` detached, and
replies ``{"ok": true, "pid": <pid>}``.  It deliberately does not wait for
ryll: the GUI process outlives Chrome's short-lived native host.

The host is only reachable from the extension ID pinned in the installed
manifest's ``allowed_origins``, which is derived from the public key in
``extension/manifest.json``.
"""

import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

# Chrome caps host-to-browser messages at 1 MiB.  A .vv file is a few hundred
# bytes; the same ceiling is plenty for the request and stops a malformed
# message from allocating without bound.
MAX_MESSAGE_BYTES = 1 << 20
MAX_VV_BYTES = 1 << 20

LOG_PATH = Path.home() / "Library" / "Logs" / "ryll" / "chrome-vv-handler.log"
RYLL_STDERR_PATH = LOG_PATH.with_name("ryll-stderr.log")
RYLL_CANDIDATES = (
    "/opt/homebrew/bin/ryll",
    "/usr/local/bin/ryll",
    str(Path.home() / ".cargo" / "bin" / "ryll"),
)


def log(message):
    """Append one line to the log, rotating it once it gets large."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > 256 * 1024:
            LOG_PATH.replace(LOG_PATH.with_name(LOG_PATH.name + ".1"))
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
    except OSError:
        # Logging must never be the reason a launch fails.
        pass


def read_message():
    header = sys.stdin.buffer.read(4)
    if len(header) != 4:
        raise ValueError("truncated message header")
    (length,) = struct.unpack("=I", header)
    if length > MAX_MESSAGE_BYTES:
        raise ValueError(f"message is too large ({length} bytes)")
    body = sys.stdin.buffer.read(length)
    if len(body) != length:
        raise ValueError("truncated message body")
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON message: {error}") from error
    if not isinstance(message, dict):
        raise ValueError("message is not a JSON object")
    return message


def send_message(message):
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(body)))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def find_ryll():
    override = os.environ.get("RYLL_BIN")
    if override:
        return override
    found = shutil.which("ryll")
    if found:
        return found
    for candidate in RYLL_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def validate_path(message):
    raw = message.get("path")
    if not isinstance(raw, str) or not raw:
        raise ValueError("missing 'path' in request")
    if "\x00" in raw:
        raise ValueError("path contains a NUL byte")
    if not os.path.isabs(raw):
        raise ValueError("path is not absolute")

    path = os.path.normpath(raw)
    if not path.lower().endswith(".vv"):
        raise ValueError(f"refusing non-.vv file: {path}")

    try:
        info = os.stat(path)
    except OSError as error:
        raise ValueError(f"cannot stat {path}: {error.strerror}") from error
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"not a regular file: {path}")
    if info.st_size > MAX_VV_BYTES:
        raise ValueError(f"file is too large ({info.st_size} bytes)")
    if not os.access(path, os.R_OK):
        raise ValueError(f"file is not readable: {path}")
    return path


def open_ryll_output():
    """Open the file ryll's stdout/stderr are appended to, or None."""
    try:
        RYLL_STDERR_PATH.parent.mkdir(parents=True, exist_ok=True)
        if (
            RYLL_STDERR_PATH.exists()
            and RYLL_STDERR_PATH.stat().st_size > MAX_MESSAGE_BYTES
        ):
            RYLL_STDERR_PATH.replace(
                RYLL_STDERR_PATH.with_name(RYLL_STDERR_PATH.name + ".1")
            )
        return RYLL_STDERR_PATH.open("ab")
    except OSError:
        return None


def launch(ryll, path):
    # A new session keeps ryll alive when Chrome reaps the native host, and
    # the redirected descriptors stop ryll from holding Chrome's message
    # pipes.  ryll's stderr is captured so a failed launch is diagnosable
    # after the fact; a GUI app that exits before showing a window otherwise
    # leaves no trace.
    output = open_ryll_output()
    sink = output if output is not None else subprocess.DEVNULL
    try:
        process = subprocess.Popen(
            [ryll, "--file", path],
            stdin=subprocess.DEVNULL,
            stdout=sink,
            stderr=sink,
            close_fds=True,
            start_new_session=True,
            cwd=str(Path.home()),
        )
    finally:
        if output is not None:
            output.close()
    return process.pid


def main():
    try:
        message = read_message()
    except Exception as error:  # noqa: BLE001 - report every protocol failure
        send_message({"ok": False, "error": str(error)})
        return 1

    try:
        path = validate_path(message)
        ryll = find_ryll()
        if not ryll:
            raise RuntimeError(
                "ryll not found; install it (brew install shakenfist/tap/ryll) "
                "or set RYLL_BIN"
            )
        if not os.access(ryll, os.X_OK):
            raise RuntimeError(f"ryll is not executable: {ryll}")
        pid = launch(ryll, path)
    except Exception as error:  # noqa: BLE001 - report every launch failure
        log(f"error: {error}")
        send_message({"ok": False, "error": str(error)})
        return 1

    log(f"launched pid {pid}: {ryll} --file {path}")
    send_message({"ok": True, "pid": pid})
    return 0


if __name__ == "__main__":
    sys.exit(main())
