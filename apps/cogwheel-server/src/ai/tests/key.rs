//! `key.rs`: the key's shape, where it lives, and how it is saved and removed (§8).

use super::KEY;
use crate::ai::key::{self, Saved, SecretKey};
use crate::config::{AppConfig, Profile};
use crate::tests::TempDir;
use std::path::{Path, PathBuf};

fn config_at(database_url: &str) -> AppConfig {
    let mut config = AppConfig::for_profile(Profile::Home);
    config.database_url = database_url.to_owned();
    config
}

fn saved_key(dir: &TempDir) -> PathBuf {
    dir.path().join("openrouter.key")
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("the key file exists")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
#[test]
fn a_saved_key_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("key-mode");
    let path = saved_key(&dir);
    let secret = SecretKey::from_ui(KEY).expect("a key");
    key::store(&path, &secret).expect("the key saves");
    assert_eq!(mode(&path), 0o600);
    assert_eq!(
        std::fs::read_to_string(&path).expect("readable by its owner"),
        KEY
    );
    assert!(
        !dir.path().join("openrouter.key.tmp").exists(),
        "the temporary was renamed into place"
    );

    // Saving again replaces it, through a stale temporary from a save that died mid-write.
    std::fs::write(dir.path().join("openrouter.key.tmp"), "half a key").expect("plant a stale tmp");
    let other = SecretKey::from_ui(&format!("{KEY}-2")).expect("a key");
    key::store(&path, &other).expect("the key saves over the old one");
    assert_eq!(mode(&path), 0o600);
    assert!(matches!(key::load(&path), Saved::Key(loaded) if loaded == other));

    // A file someone loosened is brought back to 0600 when it is read at boot.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen it");
    assert!(matches!(key::load(&path), Saved::Key(_)));
    assert_eq!(mode(&path), 0o600);
}

#[cfg(unix)]
#[test]
fn removing_the_key_zeroes_and_unlinks_the_file() {
    let dir = TempDir::new("key-remove");
    let path = saved_key(&dir);
    key::store(&path, &SecretKey::from_ui(KEY).expect("a key")).expect("the key saves");
    // A second name for the same inode sees what `remove` wrote before it unlinked.
    let witness = dir.path().join("witness");
    std::fs::hard_link(&path, &witness).expect("link the key file");

    key::remove(&path).expect("the key is removed");
    assert!(!path.exists(), "unlinked");
    let left = std::fs::read(&witness).expect("the witness still reads");
    assert_eq!(left.len(), KEY.len(), "overwritten in place, same length");
    assert!(
        left.iter().all(|byte| *byte == 0),
        "zeroed before the unlink"
    );

    // Removing a key that is not there is not an error: it is already removed.
    key::remove(&path).expect("a missing key file is removed already");
}

#[test]
fn an_in_memory_database_never_writes_a_key_file() {
    assert_eq!(key::key_path(&config_at(":memory:")), None);
    assert_eq!(key::key_path(&config_at("sqlite://:memory:")), None);
    assert_eq!(
        key::key_path(&config_at("file::memory:?cache=shared")),
        None
    );
    assert_eq!(
        key::key_path(&config_at("sqlite:///var/lib/cogwheel/cogwheel.db")),
        Some(PathBuf::from("/var/lib/cogwheel/openrouter.key"))
    );
    assert_eq!(
        key::key_path(&config_at("cogwheel.db")),
        Some(PathBuf::from("./openrouter.key")),
        "a bare filename keeps the key beside it, in the working directory"
    );
}

#[test]
fn a_key_of_the_wrong_shape_is_refused() {
    // From the UI: 20–256 visible ASCII characters once trimmed. No `sk-or-` requirement.
    assert!(SecretKey::from_ui(KEY).is_some());
    assert_eq!(
        SecretKey::from_ui(&format!("  {KEY}\n"))
            .expect("surrounding space is trimmed")
            .expose(),
        KEY
    );
    assert!(SecretKey::from_ui("a-future-key-format-0001").is_some());
    for refused in [
        "",
        "sk-or-v1-short",
        "sk-or-v1-0123456789 abcdef0123456789",
        "sk-or-v1-0123456789\tabcdef0123456789",
        "sk-or-v1-ключ-0123456789abcdef0123",
        &"k".repeat(257),
    ] {
        assert!(SecretKey::from_ui(refused).is_none(), "{refused:?}");
    }

    // From the environment: anything a header can carry, up to 512; empty is unset.
    assert_eq!(SecretKey::from_env(""), Ok(None));
    assert_eq!(SecretKey::from_env("   "), Ok(None));
    assert!(matches!(SecretKey::from_env("short"), Ok(Some(_))));
    assert!(matches!(SecretKey::from_env(&"k".repeat(512)), Ok(Some(_))));
    assert_eq!(SecretKey::from_env(&"k".repeat(513)), Err(()));
    assert_eq!(SecretKey::from_env("two words"), Err(()));

    // Nothing of it is ever printed.
    let secret = SecretKey::from_ui(KEY).expect("a key");
    assert_eq!(format!("{secret:?}"), "SecretKey(..)");

    // A saved file that is not a key is reported unreadable and left where it is.
    let dir = TempDir::new("key-shape");
    let path = saved_key(&dir);
    std::fs::write(&path, "not a key").expect("plant a bad key file");
    assert!(matches!(key::load(&path), Saved::Unreadable));
    assert!(path.exists(), "the household's file is not deleted");
    assert!(matches!(
        key::load(&dir.path().join("absent")),
        Saved::Missing
    ));
}
