//! Persistence of the Ed25519 secret key used for iroh node identity.
//!
//! Separate from the SV2 secp256k1 authority key. NodeId persistence
//! semantics differ from authority-key semantics; operators want to back
//! these up separately.
//!
//! The on-disk format is the raw 32-byte Ed25519 secret scalar — no
//! envelope, no header. This matches Fedimint's iroh secret-key file
//! layout and lets operators inspect/back up the file with `xxd` without
//! a parser. On Unix the file is created with mode `0600`.
//!
//! `~`, `$VAR`, and `${VAR}` in the configured path are expanded via
//! [`shellexpand::full`], the same helper already used by
//! [`crate::config_helpers::toml::opt_path_from_toml`].

use std::{
    fmt,
    io::Write,
    path::{Path, PathBuf},
};

use iroh::SecretKey;

/// Errors returned by [`load`], [`load_or_generate`], and [`persist`].
///
/// Hand-rolled rather than derived via `thiserror` to avoid pulling a new
/// crate into `stratum-apps`'s direct dependencies. The `Display` strings
/// match the layout the spec calls out so log/parser consumers see a
/// stable surface.
#[derive(Debug)]
pub enum IdentityError {
    /// I/O failure (open, read, write, rename, permission set, mkdir).
    Io {
        /// Path the operation was targeting, after shell expansion.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// File existed but was not exactly 32 bytes.
    WrongSize {
        /// Path the file was loaded from, after shell expansion.
        path: String,
        /// Number of bytes actually read.
        got: usize,
    },
    /// `~` / `$VAR` expansion failed (e.g. unset env var, no home dir).
    PathExpansion(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Io { path, source } => write!(f, "io error at {path}: {source}"),
            IdentityError::WrongSize { path, got } => {
                write!(f, "expected 32 bytes at {path}, got {got}")
            }
            IdentityError::PathExpansion(msg) => write!(f, "path expansion failed: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IdentityError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Expand `~` and `$VAR` / `${VAR}` references in `path` against the
/// current process environment.
///
/// Reuses the same `shellexpand::full` helper that
/// [`crate::config_helpers::toml::opt_path_from_toml`] uses for TOML
/// path fields, so behavior is consistent with operator expectations.
fn expand_path(path: &Path) -> Result<PathBuf, IdentityError> {
    // `Path::to_string_lossy` is fine here: the input is configuration data
    // that we will subsequently feed to the OS as a path; any non-UTF-8
    // bytes would have round-tripped through TOML/serde already.
    let raw = path.to_string_lossy();
    let expanded =
        shellexpand::full(raw.as_ref()).map_err(|e| IdentityError::PathExpansion(e.to_string()))?;
    Ok(PathBuf::from(expanded.into_owned()))
}

/// Loads a `SecretKey` from `path`, generating and persisting a new one if
/// the file doesn't exist. The file is 32 raw bytes.
///
/// On Unix, creates the file with mode `0600`. The parent directory is
/// created recursively if missing.
///
/// `~` and `$VAR` / `${VAR}` in the path are expanded.
pub fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<SecretKey, IdentityError> {
    let expanded = expand_path(path.as_ref())?;

    match read_secret_bytes(&expanded) {
        Ok(bytes) => Ok(SecretKey::from_bytes(&bytes)),
        Err(IdentityError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            // Auto-generate. iroh 1.0-rc's `SecretKey::generate` takes no
            // arguments and uses `rand::random` internally to obtain entropy.
            let key = SecretKey::generate();
            persist_inner(&expanded, &key)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// Loads a `SecretKey` from `path`. Errors if the file is missing or
/// the file is not exactly 32 bytes long.
pub fn load<P: AsRef<Path>>(path: P) -> Result<SecretKey, IdentityError> {
    let expanded = expand_path(path.as_ref())?;
    let bytes = read_secret_bytes(&expanded)?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Persists `secret_key` to `path` atomically (write to a temp file, then
/// rename over the destination). On Unix, sets mode `0600` on the temp
/// file before the rename so the destination is never visible with looser
/// permissions.
///
/// Creates the parent directory recursively if it doesn't already exist.
pub fn persist<P: AsRef<Path>>(path: P, secret_key: &SecretKey) -> Result<(), IdentityError> {
    let expanded = expand_path(path.as_ref())?;
    persist_inner(&expanded, secret_key)
}

/// Read exactly 32 bytes from `path` or report a structured error.
///
/// `path` must already be shell-expanded.
fn read_secret_bytes(path: &Path) -> Result<[u8; 32], IdentityError> {
    let bytes = std::fs::read(path).map_err(|e| IdentityError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    if bytes.len() != 32 {
        return Err(IdentityError::WrongSize {
            path: path.display().to_string(),
            got: bytes.len(),
        });
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Atomic write: tmp file in the same directory, set perms, then rename.
///
/// `path` must already be shell-expanded.
fn persist_inner(path: &Path, secret_key: &SecretKey) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        // Skip if `parent` is empty (relative path with no directory part).
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| IdentityError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
    }

    // Use a sibling-of-final-path tmp file so the rename is on the same
    // filesystem (cross-fs renames fall back to copy+delete, which is not
    // atomic).
    let tmp = path.with_extension("ed25519.tmp");

    // Open with create-truncate so a stale tmp from a previous failed run
    // is overwritten.
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| IdentityError::Io {
                path: tmp.display().to_string(),
                source: e,
            })?;
        f.write_all(&secret_key.to_bytes())
            .map_err(|e| IdentityError::Io {
                path: tmp.display().to_string(),
                source: e,
            })?;
        f.sync_all().map_err(|e| IdentityError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            IdentityError::Io {
                path: tmp.display().to_string(),
                source: e,
            }
        })?;
    }

    std::fs::rename(&tmp, path).map_err(|e| IdentityError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// 1. `load_or_generate` creates the file if missing.
    #[test]
    fn load_or_generate_creates_file_when_missing() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("iroh-secret.ed25519");
        assert!(!path.exists(), "precondition: file must not exist");

        let key = load_or_generate(&path).expect("load_or_generate");
        assert!(path.exists(), "file should now exist");

        let on_disk = std::fs::read(&path).expect("read");
        assert_eq!(on_disk.len(), 32, "file should be 32 bytes");

        // Roundtrip: SecretKey may not impl PartialEq, so compare via to_bytes().
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&on_disk);
        let reloaded = SecretKey::from_bytes(&bytes);
        assert_eq!(
            key.to_bytes(),
            reloaded.to_bytes(),
            "roundtrip from on-disk bytes must equal the returned key"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "file mode should be 0600");
        }
    }

    /// 2. `load_or_generate` is idempotent — calling twice returns the
    ///    same persisted key.
    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("iroh-secret.ed25519");

        let first = load_or_generate(&path).expect("first call");
        let second = load_or_generate(&path).expect("second call");

        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "subsequent loads must return the persisted key"
        );
    }

    /// 3. `load` errors with `Io` (kind = NotFound) on a missing file.
    #[test]
    fn load_fails_on_missing_file() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("does-not-exist.ed25519");

        let err = load(&path).expect_err("expected error");
        match err {
            IdentityError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }

    /// 4. `load` errors with `WrongSize { got: 31 }` on a 31-byte file.
    #[test]
    fn load_fails_on_wrong_size() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("short.ed25519");
        std::fs::write(&path, [0u8; 31]).expect("write short file");

        let err = load(&path).expect_err("expected error");
        match err {
            IdentityError::WrongSize { got, .. } => {
                assert_eq!(got, 31);
            }
            other => panic!("expected WrongSize {{ got: 31 }}, got {other:?}"),
        }
    }

    /// 5. `persist` creates parent directories recursively.
    #[test]
    fn persist_creates_parent_directories() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("a").join("b").join("c").join("key");
        assert!(!path.parent().unwrap().exists());

        let key = SecretKey::generate();
        persist(&path, &key).expect("persist");

        assert!(path.exists(), "key file should exist");
        assert!(
            path.parent().unwrap().exists(),
            "parent directory chain should exist"
        );
    }

    /// 6. `~` expansion actually expands.
    ///
    /// We run this against a path under the user's home directory and
    /// clean up afterwards. The test name suffix is randomized to avoid
    /// stomping on a real config file.
    #[test]
    fn tilde_expansion() {
        // Pick a unique sub-path. Use process id + monotonic nanos to keep
        // it unique across parallel test runs.
        let unique = format!(
            "sv2-iroh-identity-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let raw_path = format!("~/.cache/{unique}/iroh-secret.ed25519");

        // Resolve what the expansion *should* produce so we can verify the
        // file was created at the right place and so we can clean up.
        let home = std::env::var("HOME").expect("HOME env var");
        let expected_dir = PathBuf::from(&home).join(".cache").join(&unique);
        let expected_path = expected_dir.join("iroh-secret.ed25519");

        // Defensive cleanup in case a previous run aborted mid-test.
        let _ = std::fs::remove_dir_all(&expected_dir);

        let result = load_or_generate(&raw_path);

        // Always clean up — even if the assertion below would otherwise
        // fail — to keep the user's filesystem tidy.
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&expected_dir);
        };

        match result {
            Ok(_) => {
                let exists = expected_path.exists();
                cleanup();
                assert!(
                    exists,
                    "tilde expansion should have created {}",
                    expected_path.display()
                );
            }
            Err(e) => {
                cleanup();
                panic!("load_or_generate(~/...) failed: {e}");
            }
        }
    }

    /// 7. (Unix only) the persisted file has mode 0600.
    #[cfg(unix)]
    #[test]
    fn unix_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("mode-check.ed25519");

        let _ = load_or_generate(&path).expect("load_or_generate");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "expected mode 0o600, got {mode:o}");
    }
}
