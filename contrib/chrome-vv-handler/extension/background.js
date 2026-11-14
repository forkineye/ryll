// Launch ryll for every completed .vv download.
//
// Chrome itself cannot start a native process on behalf of an extension, so
// the launch is delegated to the native messaging host in ../native/.  The
// host receives the download's absolute path and runs:
//
//     ryll --file <path>
//
// Chrome's built-in "always open files of this type" is not used because
// DownloadPrefs filters user extensions through Safe Browsing's
// IsAllowedToOpenAutomatically(), which does not include .vv.

const NATIVE_HOST = "com.shakenfist.ryll";
const VV_PATH = /\.vv$/i;

chrome.downloads.onChanged.addListener((delta) => {
  if (!delta.state || delta.state.current !== "complete") {
    return;
  }
  void launchFor(delta.id);
});

async function launchFor(downloadId) {
  try {
    const [item] = await chrome.downloads.search({ id: downloadId });
    if (!item || item.state !== "complete" || !item.filename) {
      return;
    }
    if (!VV_PATH.test(item.filename)) {
      return;
    }

    const reply = await chrome.runtime.sendNativeMessage(NATIVE_HOST, {
      path: item.filename,
    });
    if (!reply || reply.ok !== true) {
      const reason = reply && reply.error ? reply.error : "no response";
      console.error(`ryll launcher: ${reason} (${item.filename})`);
    }
  } catch (error) {
    // A missing native host lands here.  The extension worker console at
    // chrome://extensions is the place to see it.
    console.error("ryll launcher:", error);
  }
}
