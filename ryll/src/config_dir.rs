//! Persistent user configuration.
//!
//! Ryll keeps one small JSON file under the user's home directory:
//! `~/.ryll/config.json` (or `$RYLL_CONFIG_DIR/config.json`). It stores
//! named Proxmox VE profiles, each holding the endpoint (host and port),
//! an API token tied to that host, and the TLS choice.
//!
//! A password is deliberately not represented by this module's types.
//! Proxmox password authentication is per-session; only API tokens are
//! persisted, and the token file is written `0600` inside a `0700`
//! directory on Unix.
//!
//! Writes go through a temporary file in the same directory and a
//! rename, so a crash cannot leave a truncated token file behind. The
//! file carries a schema version so a build can refuse a document it
//! does not understand instead of reading it as something else.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

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

/// The saved Proxmox VE profiles.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SavedProxmox {
    pub profiles: Vec<ProxmoxProfile>,
}

/// One saved Proxmox VE endpoint and its credentials.
///
/// `host` is the endpoint URL without its port (`https://pve.example`,
/// or a bare host such as `pve.example` for the default HTTPS scheme).
/// The port lives in its own field. `name` is the Proxmox node name
/// captured after the connection succeeded, used as the profile label.
///
/// `token` is the normalised `USER@REALM!TOKENID=SECRET` form. There is
/// no password field by design; password logins are never persisted.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProxmoxProfile {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
}

impl SavedProxmox {
    /// The profile for a host and port, if one is saved.
    pub fn profile(&self, host: &str, port: u16) -> Option<&ProxmoxProfile> {
        self.profiles
            .iter()
            .find(|profile| profile_is(profile, host, port))
    }
}

/// Normalise a stored profile host for identity comparisons.
///
/// The GUI and CLI write the canonical URL form, but the schema permits a
/// bare host such as `pve.example` and a hand-edited file may use one.
/// Both spellings must update and forget the same profile.
fn normalized_profile_host(host: &str) -> String {
    let raw = host.trim();
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    match Url::parse(&with_scheme) {
        Ok(mut url) => {
            let _ = url.set_port(None);
            url.set_query(None);
            url.set_fragment(None);
            let text = url.to_string();
            text.trim_end_matches('/').to_string()
        }
        Err(_) => raw.trim_end_matches('/').to_string(),
    }
}

/// Whether `profile` is the saved entry for `host` and `port`.
pub(crate) fn profile_is(profile: &ProxmoxProfile, host: &str, port: u16) -> bool {
    profile.port == port && normalized_profile_host(&profile.host) == normalized_profile_host(host)
}

fn is_false(value: &bool) -> bool {
    !*value
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
/// A missing file is not an error and returns `None`. A malformed,
/// unsupported-version or newer file also returns `None` after a
/// warning: the GUI can still ask for a fresh login, and a
/// command-line `--proxmox-token` can still be used. Saving refuses to
/// overwrite a newer schema.
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

    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("could not parse {}", path.display()))?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if version > u64::from(CONFIG_VERSION) {
        bail!(
            "{} was written by a newer ryll (config version {}; this build understands {})",
            path.display(),
            version,
            CONFIG_VERSION
        );
    }
    if version != u64::from(CONFIG_VERSION) {
        bail!(
            "{} uses unsupported config version {}; this build uses version {}",
            path.display(),
            version,
            CONFIG_VERSION
        );
    }

    tighten_permissions(path);
    let config: SavedConfig = serde_json::from_value(value)
        .with_context(|| format!("could not parse {}", path.display()))?;
    Ok(Some(config))
}

/// Save a configuration to an explicit path.
pub fn save_to_path(path: &Path, config: &SavedConfig) -> Result<()> {
    if config.version != CONFIG_VERSION {
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

/// Replace the whole Proxmox section. Used by the profile tests to seed
/// a file; the application upserts one profile at a time.
#[cfg(test)]
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

/// Insert or update one profile, matching an existing entry by host and
/// port, and return the resulting profile list.
///
/// The updated profile is moved to the front, so the first entry is the
/// most recently used one.
pub fn upsert_proxmox_profile(profile: &ProxmoxProfile) -> Result<(PathBuf, SavedProxmox)> {
    let path = config_path().ok_or_else(|| {
        anyhow!("could not find a home directory for ~/.ryll; set RYLL_CONFIG_DIR")
    })?;
    let profiles = upsert_proxmox_profile_in(&path, profile)?;
    Ok((path, profiles))
}

/// [`upsert_proxmox_profile`] against an explicit path.
pub fn upsert_proxmox_profile_in(path: &Path, profile: &ProxmoxProfile) -> Result<SavedProxmox> {
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
    let mut profiles = config.proxmox.take().unwrap_or_default();
    let existing_token = profiles
        .profile(&profile.host, profile.port)
        .and_then(|existing| existing.token.clone());
    profiles
        .profiles
        .retain(|existing| !profile_is(existing, &profile.host, profile.port));
    let mut updated = profile.clone();
    if updated.token.is_none() {
        // Preserve a token the caller did not touch: a password login
        // still saves the endpoint, but must not erase an existing token
        // for the same host.
        updated.token = existing_token;
    }
    profiles.profiles.insert(0, updated);
    config.proxmox = Some(profiles.clone());
    save_to_path(path, &config)?;
    Ok(profiles)
}

/// Remove the saved token from the profile for `host`:`port`, keeping
/// its endpoint and TLS settings. Returns whether anything changed.
#[cfg(feature = "gui")]
pub fn forget_proxmox_token(host: &str, port: u16) -> Result<bool> {
    let Some(path) = config_path() else {
        return Ok(false);
    };
    forget_proxmox_token_in(&path, host, port)
}

/// [`forget_proxmox_token`] against an explicit path.
#[cfg(feature = "gui")]
pub fn forget_proxmox_token_in(path: &Path, host: &str, port: u16) -> Result<bool> {
    let Some(mut config) = load_from_path(path)? else {
        return Ok(false);
    };
    let Some(proxmox) = config.proxmox.as_mut() else {
        return Ok(false);
    };
    let Some(profile) = proxmox
        .profiles
        .iter_mut()
        .find(|profile| profile_is(profile, host, port))
    else {
        return Ok(false);
    };
    let changed = profile.token.is_some();
    profile.token = None;
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

    fn profile(name: &str, host: &str, port: u16, token: Option<&str>) -> ProxmoxProfile {
        ProxmoxProfile {
            name: name.to_string(),
            host: host.to_string(),
            port,
            token: token.map(str::to_string),
            insecure: true,
            ca: None,
        }
    }

    fn saved(profiles: Vec<ProxmoxProfile>) -> SavedProxmox {
        SavedProxmox { profiles }
    }

    #[test]
    fn round_trips_multiple_profiles() {
        let dir = temp_dir("round-trip");
        let path = dir.join(CONFIG_FILE_NAME);
        save_proxmox_to_path(
            &path,
            &saved(vec![
                profile("pve1", "https://pve-one.example", 8006, Some("a@pve!t=one")),
                ProxmoxProfile {
                    name: "pve2".to_string(),
                    host: "http://pve-two.example".to_string(),
                    port: 8443,
                    token: Some("b@pve!t=two".to_string()),
                    insecure: false,
                    ca: Some(PathBuf::from("/etc/ryll/pve-ca.pem")),
                },
            ]),
        )
        .expect("save");

        let config = load_from_path(&path).expect("load").expect("present");
        assert_eq!(config.version, CONFIG_VERSION);
        let proxmox = config.proxmox.expect("proxmox section");
        assert_eq!(proxmox.profiles.len(), 2);
        assert_eq!(proxmox.profiles[0].name, "pve1");
        assert_eq!(proxmox.profiles[0].host, "https://pve-one.example");
        assert_eq!(proxmox.profiles[0].port, 8006);
        assert_eq!(proxmox.profiles[0].token.as_deref(), Some("a@pve!t=one"));
        assert_eq!(proxmox.profiles[1].name, "pve2");
        assert_eq!(proxmox.profiles[1].port, 8443);
        assert_eq!(
            proxmox.profiles[1].ca,
            Some(PathBuf::from("/etc/ryll/pve-ca.pem"))
        );
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
    fn profiles_array_is_required() {
        let dir = temp_dir("missing-profiles");
        let path = dir.join(CONFIG_FILE_NAME);
        fs::write(&path, r#"{"version":1,"proxmox":{}}"#).expect("write");

        let error = match load_from_path(&path) {
            Ok(_) => panic!("a proxmox section without profiles must fail"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("missing field `profiles`"),
            "{error:#}"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let dir = temp_dir("unsupported-version");
        let path = dir.join(CONFIG_FILE_NAME);
        fs::write(&path, r#"{"version":0,"proxmox":{"profiles":[]}}"#).expect("write");

        let error = match load_from_path(&path) {
            Ok(_) => panic!("an unsupported schema version must fail"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("unsupported config version"),
            "{error:#}"
        );

        // A document with no version field is equally unsupported.
        fs::write(&path, r#"{"proxmox":{"profiles":[]}}"#).expect("write");
        let error = match load_from_path(&path) {
            Ok(_) => panic!("a versionless document must fail"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("unsupported config version"),
            "{error:#}"
        );

        // A save may replace an unusable file; it must not be blocked by
        // the version that this build cannot read.
        let profiles = upsert_proxmox_profile_in(
            &path,
            &profile("pve1", "https://pve.example", 8006, Some("a@pve!t=secret")),
        )
        .expect("replace unsupported");
        assert_eq!(profiles.profiles.len(), 1);
        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("\"version\": 1"), "{text}");
        assert!(text.contains("pve.example"), "{text}");
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

        let save_error = match upsert_proxmox_profile_in(
            &path,
            &profile("pve1", "https://pve.example", 8006, Some("a@pve!t=secret")),
        ) {
            Ok(_) => panic!("save must refuse a newer file"),
            Err(error) => error,
        };
        assert!(format!("{save_error:#}").contains("refusing to overwrite"));
        assert!(
            fs::read_to_string(&path)
                .expect("read")
                .contains("\"version\":999"),
            "the newer document must survive"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn upsert_updates_by_host_and_port_and_keeps_others() {
        let dir = temp_dir("upsert");
        let path = dir.join(CONFIG_FILE_NAME);
        upsert_proxmox_profile_in(
            &path,
            &profile("pve1", "https://one.example", 8006, Some("a@pve!t=one")),
        )
        .expect("profile one");
        upsert_proxmox_profile_in(
            &path,
            &profile("pve2", "https://two.example", 8006, Some("b@pve!t=two")),
        )
        .expect("profile two");

        let renamed = profile(
            "pve1-renamed",
            "https://one.example",
            8006,
            Some("a@pve!t=new"),
        );
        let profiles = upsert_proxmox_profile_in(&path, &renamed).expect("update");
        assert_eq!(profiles.profiles.len(), 2);
        assert_eq!(profiles.profiles[0].name, "pve1-renamed");
        assert_eq!(profiles.profiles[0].token.as_deref(), Some("a@pve!t=new"));
        assert_eq!(profiles.profiles[1].name, "pve2");
        assert_eq!(profiles.profiles[1].token.as_deref(), Some("b@pve!t=two"));
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn upsert_preserves_an_existing_token_when_none_is_given() {
        let dir = temp_dir("preserve-token");
        let path = dir.join(CONFIG_FILE_NAME);
        upsert_proxmox_profile_in(
            &path,
            &profile("pve1", "https://one.example", 8006, Some("a@pve!t=one")),
        )
        .expect("initial");
        let profiles =
            upsert_proxmox_profile_in(&path, &profile("pve1", "https://one.example", 8006, None))
                .expect("password update");
        assert_eq!(
            profiles.profiles[0].token.as_deref(),
            Some("a@pve!t=one"),
            "a password login must not erase the host's saved token"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn forgetting_one_profile_token_leaves_the_others() {
        let dir = temp_dir("forget");
        let path = dir.join(CONFIG_FILE_NAME);
        save_proxmox_to_path(
            &path,
            &saved(vec![
                profile("pve1", "https://one.example", 8006, Some("a@pve!t=one")),
                profile("pve2", "https://two.example", 8006, Some("b@pve!t=two")),
            ]),
        )
        .expect("save");

        assert!(forget_proxmox_token_in(&path, "https://one.example", 8006).expect("forget"));
        let config = load_from_path(&path).expect("load").expect("present");
        let proxmox = config.proxmox.expect("proxmox");
        let one = proxmox
            .profile("https://one.example", 8006)
            .expect("first profile");
        assert!(one.token.is_none());
        assert_eq!(one.host, "https://one.example");
        assert_eq!(one.port, 8006);
        assert!(one.insecure, "the profile's TLS choice must survive");
        let two = proxmox
            .profile("https://two.example", 8006)
            .expect("second profile");
        assert_eq!(two.token.as_deref(), Some("b@pve!t=two"));
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(feature = "gui")]
    #[test]
    fn profile_identity_accepts_a_bare_host() {
        let dir = temp_dir("bare-host");
        let path = dir.join(CONFIG_FILE_NAME);
        let mut bare = profile("pve1", "https://one.example", 8006, Some("a@pve!t=one"));
        bare.host = "one.example".to_string();
        save_proxmox_to_path(&path, &saved(vec![bare])).expect("save");

        let updated = upsert_proxmox_profile_in(
            &path,
            &profile("pve1-new", "https://one.example", 8006, None),
        )
        .expect("upsert");
        assert_eq!(
            updated.profiles.len(),
            1,
            "the bare host must update in place"
        );
        assert_eq!(updated.profiles[0].name, "pve1-new");
        assert_eq!(updated.profiles[0].token.as_deref(), Some("a@pve!t=one"));

        assert!(forget_proxmox_token_in(&path, "https://one.example", 8006).expect("forget"));
        let config = load_from_path(&path).expect("load").expect("present");
        assert!(config
            .proxmox
            .expect("proxmox")
            .profile("one.example", 8006)
            .expect("profile")
            .token
            .is_none());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn password_and_username_are_not_serialized() {
        let config = SavedConfig {
            version: CONFIG_VERSION,
            proxmox: Some(saved(vec![profile(
                "pve1",
                "https://pve.example",
                8006,
                Some("root@pam!ryll=secret"),
            )])),
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
        upsert_proxmox_profile_in(
            &path,
            &profile(
                "pve1",
                "https://pve.example",
                8006,
                Some("root@pam!ryll=secret"),
            ),
        )
        .expect("save");

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
