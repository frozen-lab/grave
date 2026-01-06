// #![deny(missing_docs)]
#![deny(unused_must_use)]
#![allow(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

mod errors;

#[allow(unused)]
mod cfg;

#[allow(unused)]
mod pool;

#[allow(unused)]
mod hints;

#[allow(unused)]
mod file;

#[allow(unused)]
mod mmap;

pub use cfg::{GraveConfig, GraveConfigValue};
pub use errors::{GraveError, GraveResult};

/// A page based storage engine with fire-and-forget writes and crash-safe durability semantics
///
/// # Example
///
/// ```
/// use grave::Grave;
///
/// const fn assert_send_sync<T: Send + Sync>() {}
/// const _: () = assert_send_sync::<Grave>();
/// ```
#[allow(unused)]
pub struct Grave {
    cfg: GraveConfig,
    dirpath: std::path::PathBuf,
}

unsafe impl Send for Grave {}
unsafe impl Sync for Grave {}

impl Grave {
    ///
    pub fn new<P: AsRef<std::path::PathBuf>>(dirpath: P, cfg: GraveConfig) -> GraveResult<Self> {
        Self::prep_directory(dirpath.as_ref())?;

        Ok(Self {
            cfg,
            dirpath: dirpath.as_ref().clone(),
        })
    }

    fn prep_directory(dirpath: &std::path::PathBuf) -> GraveResult<()> {
        if dirpath.exists() {
            if dirpath.is_dir() {
                return Ok(());
            }

            return Err(GraveError::IO(format!(
                "Failed to init Grave, as path={:?} is not a directory",
                dirpath
            )));
        }

        std::fs::create_dir_all(dirpath).map_err(|e| {
            GraveError::IO(format!(
                "Failed to init Grave, as following error occurred while creating a directory, error: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{NamedTempFile, TempDir};

    mod prep_directory {
        use super::*;

        #[test]
        fn creates_dir_when_missing() {
            let tmp = TempDir::new().expect("New temp dir");
            let dir = tmp.path().join("dummy");

            assert!(
                Grave::prep_directory(&dir).is_ok(),
                "Should create a new directory when missing"
            );

            // sanity checks for validity
            assert!(dir.exists(), "New directory should be created");
            assert!(dir.is_dir(), "New directory must be a directory");
        }

        #[test]
        fn does_nothing_when_dir_already_exists() {
            let tmp = TempDir::new().expect("New temp dir");
            let dir = tmp.path().join("dummy");
            std::fs::create_dir_all(&dir).expect("create new directory");

            assert!(Grave::prep_directory(&dir).is_ok(), "Should open existing dir");

            // sanity checks for validity
            assert!(dir.exists(), "New directory should be created");
            assert!(dir.is_dir(), "New directory must be a directory");
        }

        #[test]
        fn fails_when_path_is_file() {
            let invalid_dir = NamedTempFile::new().expect("new temp file");

            match Grave::prep_directory(&invalid_dir.path().to_path_buf()) {
                Ok(_) => panic!("must throw error when path is a file"),
                Err(e) => match e {
                    GraveError::IO(_) => {}
                    _ => panic!("expected IO error"),
                },
            }
        }
    }
}
