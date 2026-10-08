//! The OpenRouter key (ADR 0002 §8): the one secret the appliance holds.
//!
//! It lives in `<data dir>/openrouter.key`, mode 0600, and nowhere else on disk: not in SQLite,
//! so never in a `.pre-v2` copy, a `VACUUM INTO` backup or the WAL. It is never returned by a
//! route and never logged. `SecretKey` has no `Display` and no `Serialize`, and its `Debug` prints
//! nothing of the value, so the type system keeps it out of every format string and JSON body.

use crate::config::AppConfig;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// The file the key is saved in, beside the database.
const KEY_FILE: &str = "openrouter.key";

/// Where a key is written before the rename that makes it the saved one.
const KEY_TMP: &str = "openrouter.key.tmp";

/// The longest key the environment may carry: past this it is not a key, it is a pasted file.
const MAX_ENV_KEY: usize = 512;

/// The bounds of a key typed into the UI. Real keys are about 73 characters.
const UI_KEY_MIN: usize = 20;
const UI_KEY_MAX: usize = 256;

/// An OpenRouter API key.
///
/// Cloned into every job, because a request in flight must keep the key it started with even if
/// the household replaces it meanwhile (the generation check then discards the answer).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(Box<str>);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// The key itself, for the one place it has to be spelled out: the `Authorization` header
    /// `client.rs` sets with `bearer_auth`, which marks the value sensitive.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A keyed hash of the key, to recognise it again within this process (a Test pass reused by
    /// the Turn on that follows it). The hasher's keys are random per process, and the value
    /// never leaves memory.
    pub fn fingerprint(&self) -> u64 {
        static HASHER: LazyLock<RandomState> = LazyLock::new(RandomState::new);
        HASHER.hash_one(&*self.0)
    }

    /// A key from `COGWHEEL_AI__OPENROUTER_API_KEY`. `Ok(None)` for an empty value, which counts
    /// as unset; `Err` for anything that cannot be a header value. No `sk-or-` check, so a
    /// future key format does not stop boot.
    pub fn from_env(value: &str) -> Result<Option<Self>, ()> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        if value.len() > MAX_ENV_KEY || !header_safe(value) {
            return Err(());
        }
        Ok(Some(Self(value.into())))
    }

    /// A key typed into the UI: after trimming, 20–256 characters, each a visible ASCII byte.
    /// The hint the UI shows mentions `sk-or-`, but the check does not require it.
    pub fn from_ui(value: &str) -> Option<Self> {
        let value = value.trim();
        let fits = (UI_KEY_MIN..=UI_KEY_MAX).contains(&value.len()) && header_safe(value);
        fits.then(|| Self(value.into()))
    }
}

/// Every byte is 0x21–0x7E: no space, no control character, nothing outside ASCII. That is what
/// a header value can carry without escaping, and it is a strict superset of every key format.
fn header_safe(value: &str) -> bool {
    value.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
}

/// `<dir of the database>/openrouter.key`, or `./openrouter.key` for a bare filename; `None` for
/// an in-memory database, whose key lives in memory only (and so tests never write one).
pub fn key_path(config: &AppConfig) -> Option<PathBuf> {
    let database = config.database_path();
    let spelled = database.to_string_lossy();
    if spelled.is_empty() || spelled.contains(":memory:") || spelled.starts_with("file::memory") {
        return None;
    }
    let dir = database
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Some(dir.join(KEY_FILE))
}

/// What reading the saved key found.
#[derive(Debug)]
pub enum Saved {
    /// No file: nobody has saved a key.
    Missing,
    /// A key of the right shape.
    Key(SecretKey),
    /// A file that is not a key. Left in place, not deleted: it is the household's file.
    Unreadable,
}

/// Read the saved key at boot, tightening a file mode wider than 0600 on the way.
pub fn load(path: &Path) -> Saved {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Saved::Missing,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "the saved OpenRouter key is unreadable; AI review is waiting for a key");
            return Saved::Unreadable;
        }
    };
    tighten(path);
    match SecretKey::from_ui(&text) {
        Some(key) => Saved::Key(key),
        None => {
            tracing::warn!(path = %path.display(), "the saved OpenRouter key is unreadable; AI review is waiting for a key");
            Saved::Unreadable
        }
    }
}

/// Bring a key file that group or others can read back to 0600, saying so.
#[cfg(unix)]
fn tighten(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o177 == 0 {
        return;
    }
    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            mode = %format_args!("{mode:o}"),
            "the saved OpenRouter key was readable by others; it is now 0600"
        ),
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "could not restrict the saved OpenRouter key to its owner")
        }
    }
}

#[cfg(not(unix))]
fn tighten(_path: &Path) {}

/// Save `key` at `path`, replacing any saved one: a fresh owner-only temporary, synced, then
/// renamed over the old file and the directory synced, so a crash leaves the old key or the new
/// one and never half of either.
pub fn store(path: &Path, key: &SecretKey) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = dir.join(KEY_TMP);
    // A stale temporary from a save that died mid-write: `create_new` below refuses to reuse it,
    // which is the point (nobody else's file, or a symlink, can be written through).
    match std::fs::remove_file(&tmp) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = open_owner_only(&tmp)?;
    file.write_all(key.0.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    sync_dir(dir)
}

#[cfg(unix)]
fn open_owner_only(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_owner_only(path: &Path) -> io::Result<std::fs::File> {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!("this platform cannot restrict the OpenRouter key file to its owner");
    });
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Make the rename durable: the directory entry is what a crash would otherwise lose.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Remove the saved key: overwrite it with zero bytes of the same length, sync, unlink. Best
/// effort on flash, whose wear levelling may keep the old block; DEPLOYMENT says so. A missing
/// file is already removed.
pub fn remove(path: &Path) -> io::Result<()> {
    let mut file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let length = usize::try_from(file.metadata()?.len()).unwrap_or(0);
    file.write_all(&vec![0u8; length])?;
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path)
}
