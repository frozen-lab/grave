#![deny(missing_docs)]
#![deny(unused_must_use)]
#![allow(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

mod cfg;
mod common;
mod errors;
mod mmap;

#[allow(unused)]
mod coffin;

#[allow(unused)]
mod pool;

#[allow(unused)]
mod file;

#[allow(unused)]
mod index;

pub use cfg::{GraveConfig, GraveConfigValue};
use coffin::Coffin;
pub use errors::{GraveError, GraveResult};
use index::{GraveOff, Index, TGraveOff, PAGES_PER_BLOCK};
use pool::{BufPool, PoolSlot};

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
    index: Index,
    pool: BufPool,
    coffin: Coffin,
    cfg: GraveConfig,
    dirpath: std::path::PathBuf,
}

unsafe impl Send for Grave {}
unsafe impl Sync for Grave {}

impl Grave {
    /// Create new instance of [`Grave`]
    pub fn new<P: AsRef<std::path::PathBuf>>(dirpath: P, cfg: GraveConfig) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        let is_new = dirpath.as_ref().exists();

        #[cfg(target_os = "linux")]
        Self::prep_directory(dirpath.as_ref())?;

        let (index, coffin) = if is_new {
            (
                Index::new(dirpath.as_ref(), &cfg)?,
                Coffin::new(dirpath.as_ref(), PAGES_PER_BLOCK, cfg.page_size.to_u32() as usize)?,
            )
        } else {
            (Index::open(dirpath.as_ref())?, Coffin::open(dirpath.as_ref())?)
        };

        let pool = BufPool::new(cfg.num_block as u32, cfg.page_size.to_u32() as usize);

        Ok(Self {
            cfg,
            pool,
            index,
            coffin,
            dirpath: dirpath.as_ref().clone(),
        })
    }

    ///
    pub fn write(&self, data: &[u8]) -> GraveResult<TGraveOff> {
        // sanity check (for now)
        debug_assert!(data.len() <= self.cfg.page_size.to_u32() as usize);

        let off = self.index.alloc_single_slot()?;
        let slot = (off.slot_idx as usize) * (off.block_idx as usize);

        let mut pool_slot: Option<PoolSlot> = None;

        while pool_slot.is_none() {
            if let Some(pslot) = self.pool.alloc() {
                pool_slot = Some(pslot);
                break;
            } else {
                self.pool.wait();
            }
        }

        let pslot = if pool_slot.is_some() {
            pool_slot.unwrap()
        } else {
            return Err(GraveError::Miscellaneous("".into()));
        };

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), pslot.ptr(), data.len());
        }

        self.coffin
            .write(data.as_ptr(), slot, self.cfg.page_size.to_u32() as usize)?;
        self.pool.free(&pslot);
        Ok(0)
    }

    ///
    pub fn read(&self, off: TGraveOff) -> GraveResult<Option<Vec<u8>>> {
        let grave_off = GraveOff::decode(off);
        let slot = (grave_off.slot_idx as usize) * (grave_off.block_idx as usize);

        let mut data = vec![0u8; self.cfg.page_size.to_u32() as usize];
        self.coffin
            .read(data.as_mut_ptr(), slot, self.cfg.page_size.to_u32() as usize)?;

        Ok(Some(data))
    }

    ///
    pub fn del(&self, off: TGraveOff) -> GraveResult<()> {
        self.index.free_single_slot(off)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn prep_directory(dirpath: &std::path::PathBuf) -> GraveResult<()> {
        use libc::{faccessat, O_DIRECTORY, R_OK, W_OK};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        // S1: create directory if missing
        match std::fs::create_dir(dirpath) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }

        // S2: open directory
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY)
            .open(dirpath)?;

        // S3: validate metadata
        let metadata = dir.metadata()?;
        if !metadata.is_dir() {
            return Err(GraveError::IO(format!(
                "Failed to init Grave, as path={:?} is not a directory",
                dirpath
            )));
        }

        // S4: write/read perm check
        let ret = unsafe { faccessat(dir.as_raw_fd(), b".\0".as_ptr() as _, R_OK | W_OK, 0) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // TODO: create status + sanity flag for Index & RawData file

        Ok(())
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

            assert!(
                Grave::prep_directory(&dir)
                    .map_err(|e| {
                        eprintln!("{:?}", e);
                        e
                    })
                    .is_ok(),
                "Should open existing dir"
            );

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
