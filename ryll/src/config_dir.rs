//! Persistent user configuration.
//!
//! Ryll keeps one small JSON file under the user's home directory:
//! `~/.ryll/config.json` (or `$RYLL_CONFIG_DIR/config.json`). At present
//! it stores only a Proxmox VE connection: the endpoint, an API token,
//! the TLS choice and whether the GUI should connect automatically.
//!
//! A password is deliberately not represented by this module's types.
//! Proxmox password authentication is per-session; only API tokens are
//! persisted, and the token file is written `0600` inside a `0700`
//! directory on Unix.
//!
//! Writes go through a temporary file in the same directory and a
//! rename, so a crash cannot leave a truncated token file behind. The
//! file carries a schema version so a future ryll can recognise a file
//! written by a newer build rather than overwriting it silently.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// The dot directory ryll creates in the user's home directory.
pub const CONFIG_DIR_NAME: &str = ".ryll";
/// The file inside [`CONFIG_DIR_NAME`].
pub const CONFIG_FILE_NAME: &str = "config.json";
/// The schema version this build writes.
pub const CONFIG_VERSION: u32 = 1;

/// The whole persisted configuration.
///
/// This type intentionally has no `Debug` implementation: it can hold an
/// API token, and a stray `{:?}` in a log or bug report must not be able
/// to print it.
#[derive(Clone, Serialize, Deserialize)]
pub struct SavedConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<SavedProxmox>,
}

impl Default for SavedConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            proxmox: None,
        }
    }
}

/// A saved Proxmox VE connection.
///
/// `token` is the normalised `USER@REALM!TOKENID=SECRET` form. There is
/// no password field by design; password logins are never persisted.
#[derive(Clone, Serialize, Deserialize)]
pub struct SavedProxmox {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    /// Set by the launch prompt's "don't ask again" checkbox. The GUI
    /// skips the prompt and logs in with the saved token when true.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_connect: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn default_version() -> u32 {
    CONFIG_VERSION
}

/// The configuration directory: `$RYLL_CONFIG_DIR` when set (useful for
/// tests and portable installations), otherwise `~/.ryll`.
pub fn config_dir() -> Option<PathBuf> {
    if let Some(override_dir) = std::env::var_os("RYLL_CONFIG_DIR") {
        if !override_dir.is_empty() {
            return Some(PathBuf::from(override_dir));
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())?;
    Some(PathBuf::from(home).join(CONFIG_DIR_NAME))
}

/// The configuration file path, or `None` when no home directory can be
/// found.
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join(CONFIG_FILE_NAME))
}

/// Load the user configuration, logging and ignoring any error.
///
/// A missing file is not an error and returns `None`. A malformed or
/// newer file also returns `None` after a warning: the GUI can still ask
/// for a fresh login, and a command-line `--proxmox-token` can still be
/// used. Saving refuses to overwrite a newer schema.
pub fn load() -> Option<SavedConfig> {
    let Some(path) = config_path() else {
        warn!("config: could not find a home directory; saved settings are unavailable");
        return None;
    };
    match load_from_path(&path) {
        Ok(config) => config,
        Err(error) => {
            warn!("config: ignoring {}: {error:#}", path.display());
            None
        }
    }
}

/// Load a configuration from an explicit path. Testable without touching
/// the real home directory.
pub fn load_from_path(path: &Path) -> Result<Option<SavedConfig>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {}", path.display()))
        }
    };

    let config: SavedConfig = serde_json::from_str(&text)
        .with_context(|| format!("could not parse {}", path.display()))?;
    if config.version > CONFIG_VERSION {
        bail!(
            "{} was written by a newer ryll (config version {}; this build understands {})",
            path.display(),
            config.version,
            CONFIG_VERSION
        );
    }

    tighten_permissions(path);
    Ok(Some(config))
}

/// Save a configuration to an explicit path.
pub fn save_to_path(path: &Path, config: &SavedConfig) -> Result<()> {
    if config.version > CONFIG_VERSION {
        bail!(
            "refusing to write config version {} to {}; this build writes version {}",
            config.version,
            path.display(),
            CONFIG_VERSION
        );
    }
    ensure_not_newer(path)?;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_existed = parent.exists();
    fs::create_dir_all(parent)
        .with_context(|| format!("could not create config directory {}", parent.display()))?;
    if parent_existed {
        // Never chmod an arbitrary pre-existing directory: a relative or
        // overridden config path can be the user's home or another shared
        // directory. The standard ~/.ryll is ours, so it is safe to fix.
        if parent.file_name().and_then(|name| name.to_str()) == Some(CONFIG_DIR_NAME) {
            set_dir_mode(parent)?;
        } else {
            warn_if_dir_insecure(parent);
        }
    } else {
        set_dir_mode(parent)?;
    }

    let mut json = serde_json::to_vec_pretty(config).context("could not serialise the config")?;
    json.push(b'\n');

    let temporary = temporary_path(parent);
    let write_result = write_atomically(&temporary, path, &json);
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

/// Save (or replace) the Proxmox section, preserving other settings.
pub fn save_proxmox(proxmox: &SavedProxmox) -> Result<PathBuf> {
    let path = config_path().ok_or_else(|| {
        anyhow!("could not find a home directory for ~/.ryll; set RYLL_CONFIG_DIR")
    })?;
    save_proxmox_to_path(&path, proxmox)?;
    Ok(path)
}

/// Save the Proxmox section to an explicit path.
pub fn save_proxmox_to_path(path: &Path, proxmox: &SavedProxmox) -> Result<()> {
    let mut config = match load_from_path(path) {
        Ok(config) => config.unwrap_or_default(),
        Err(error) => {
            // A malformed file may be replaced. A newer file is refused
            // by `save_to_path`'s `ensure_not_newer` check, so defaulting
            // here cannot clobber a future schema.
            warn!(
                "config: replacing unusable {} while saving: {error:#}",
                path.display()
            );
            SavedConfig::default()
        }
    };
    config.version = CONFIG_VERSION;
    config.proxmox = Some(proxmox.clone());
    save_to_path(path, &config)
}

/// Remove the saved token and the automatic-connect preference, keeping
/// the endpoint and TLS settings. Returns whether anything changed.
#[cfg(feature = "gui")]
pub fn forget_proxmox_token() -> Result<bool> {
    let Some(path) = config_path() else {
        return Ok(false);
    };
    forget_proxmox_token_in(&path)
}

/// [`forget_proxmox_token`] against an explicit path.
#[cfg(feature = "gui")]
pub fn forget_proxmox_token_in(path: &Path) -> Result<bool> {
    let Some(mut config) = load_from_path(path)? else {
        return Ok(false);
    };
    let Some(proxmox) = config.proxmox.as_mut() else {
        return Ok(false);
    };
    let changed = proxmox.token.is_some() || proxmox.auto_connect;
    proxmox.token = None;
    proxmox.auto_connect = false;
    if changed {
        save_to_path(path, &config)?;
    }
    Ok(changed)
}

/// Refuse to replace a file whose schema version is newer than this
/// build understands. Malformed JSON is allowed to be replaced: it
/// cannot be a future schema this build failed to parse, and refusing
/// would strand the user with an unusable file.
fn ensure_not_newer(path: &Path) -> Result<()> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not inspect existing {}", path.display()))
        }
    };
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(version) = value.get("version").and_then(serde_json::Value::as_u64) {
            if version > u64::from(CONFIG_VERSION) {
                bail!(
                    "refusing to overwrite {}: it was written by a newer ryll \
                     (config version {}; this build understands {})",
                    path.display(),
                    version,
                    CONFIG_VERSION
                );
            }
        }
    }
    Ok(())
}

fn write_atomically(temporary: &Path, path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(temporary)
        .with_context(|| format!("could not create {}", temporary.display()))?;
    file.write_all(contents)
        .with_context(|| format!("could not write {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("could not flush {}", temporary.display()))?;
    drop(file);

    // Windows cannot rename over an existing file. The fallback window
    // is small and the file still carries a complete document from the
    // previous save if the process dies between the two calls.
    #[cfg(windows)]
    {
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("could not replace {}", path.display()))?;
        }
    }
    fs::rename(temporary, path).with_context(|| {
        format!(
            "could not move {} into place at {}",
            temporary.display(),
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("could not restrict permissions on {}", path.display()))?;
    }
    Ok(())
}

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temporary_path(parent: &Path) -> PathBuf {
    let counter = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(
        ".{}.{}.{}.{}.tmp",
        CONFIG_FILE_NAME,
        std::process::id(),
        nanos,
        counter
    ))
}

/// Warn, without changing anything, when a pre-existing custom config
/// directory is readable by other users. The file itself is still
/// tightened and is what holds the token.
fn warn_if_dir_insecure(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(dir) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "config: directory {} is mode {:o}; expected 0700 for a directory holding a token",
                    dir.display(),
                    mode
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

fn set_dir_mode(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Never chmod the process's current directory: a relative
        // `RYLL_CONFIG_DIR=.` is a supported test shortcut and must not
        // change the permissions of the checkout or home directory.
        if dir != Path::new(".") {
            let metadata = fs::metadata(dir)
                .with_context(|| format!("could not inspect {}", dir.display()))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).with_context(|| {
                    format!("could not restrict permissions on {}", dir.display())
                })?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn tighten_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "config: {} is mode {:o}; tightening it to 0600 because it holds an API token",
                    path.display(),
                    mode
                );
                if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
                    warn!(
                        "config: could not tighten permissions on {}: {}",
                        path.display(),
                        error
                    );
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ryll-config-test-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn sample(token: Option<&str>) -> SavedProxmox {
        SavedProxmox {
            url: "https://pve.example:8006".to_string(),
            token: token.map(str::to_string),
            insecure: true,
            ca: None,
            auto_connect: false,
        }
    }

    #[test]
    fn round_trips_endpoint_token_and_tls() {
        let dir = temp_dir("round-trip");
        let path = dir.join(CONFIG_FILE_NAME);
        save_proxmox_to_path(
            &path,
            &SavedProxmox {
                url: "https://pve.example:8006".to_string(),
                token: Some("root@pam!ryll=secret".to_string()),
                insecure: false,
                ca: Some(PathBuf::from("/etc/ryll/pve-ca.pem")),
                auto_connect: true,
            },
        )
        .expect("save");

        let config = load_from_path(&path).expect("load").expect("present");
        let proxmox = config.proxmox.expect("proxmox section");
        assert_eq!(proxmox.url, "https://pve.example:8006");
        assert_eq!(proxmox.token.as_deref(), Some("root@pam!ryll=secret"));
        assert!(!proxmox.insecure);
        assert_eq!(proxmox.ca, Some(PathBuf::from("/etc/ryll/pve-ca.pem")));
        assert!(proxmox.auto_connect);
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn missing_file_is_none() {
        let dir = temp_dir("missing");
        let path = dir.join(CONFIG_FILE_NAME);
        assert!(load_from_path(&path).expect("load").is_none());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn malformed_file_is_an_error() {
        let dir = temp_dir("malformed");
        let path = dir.join(CONFIG_FILE_NAME);
        fs::write(&path, "this is not json").expect("write");
        let error = match load_from_path(&path) {
            Ok(_) => panic!("malformed config must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("could not parse"));
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn newer_schema_is_refused_and_not_overwritten() {
        let dir = temp_dir("newer");
        let path = dir.join(CONFIG_FILE_NAME);
        fs::write(&path, r#"{"version":999}"#).expect("write");

        let error = match load_from_path(&path) {
            Ok(_) => panic!("a newer schema must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("newer ryll"));

        let save_error = save_proxmox_to_path(&path, &sample(Some("root@pam!ryll=secret")))
            .expect_err("save must refuse a newer file");
        assert!(format!("{save_error:#}").contains("refusing to overwrite"));
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .contains("\"version\":999"),
            "the newer document must survive"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn forgetting_a_token_keeps_the_endpoint_and_tls() {
        let dir = temp_dir("forget");
        let path = dir.join(CONFIG_FILE_NAME);
        save_proxmox_to_path(
            &path,
            &SavedProxmox {
                url: "https://pve.example:8006".to_string(),
                token: Some("root@pam!ryll=secret".to_string()),
                insecure: true,
                ca: None,
                auto_connect: true,
            },
        )
        .expect("save");

        assert!(forget_proxmox_token_in(&path).expect("forget"));
        let config = load_from_path(&path).expect("load").expect("present");
        let proxmox = config.proxmox.expect("proxmox");
        assert_eq!(proxmox.url, "https://pve.example:8006");
        assert!(proxmox.token.is_none());
        assert!(proxmox.insecure);
        assert!(!proxmox.auto_connect);
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn password_and_username_are_not_serialized() {
        let config = SavedConfig {
            version: CONFIG_VERSION,
            proxmox: Some(sample(Some("root@pam!ryll=secret"))),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        assert!(json.contains("\"token\""));
        assert!(!json.contains("password"));
        assert!(!json.contains("username"));
    }

    #[cfg(unix)]
    #[test]
    fn token_file_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_dir("permissions");
        let dir = root.join(CONFIG_DIR_NAME);
        let path = dir.join(CONFIG_FILE_NAME);
        save_proxmox_to_path(&path, &sample(Some("root@pam!ryll=secret"))).expect("save");

        let file_mode = fs::metadata(&path)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = fs::metadata(&dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "token file must not be group/world readable"
        );
        assert_eq!(dir_mode, 0o700, "config directory must be private");
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
