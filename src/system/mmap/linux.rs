use crate::{
    error::{ErrorCode, GraveResult},
    hints::likely,
    GraveError,
};
use libc::{
    c_void, mmap, msync, munmap, off_t, size_t, EACCES, EBADF, EBUSY, EINVAL, EIO, ENOMEM, EOVERFLOW, MAP_FAILED,
    MAP_SHARED, MS_SYNC, PROT_READ, PROT_WRITE,
};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub(super) struct LinuxMMap {
    len: size_t,
    ptr: *mut c_void,
    unmapped: AtomicBool,
}

unsafe impl Send for LinuxMMap {}
unsafe impl Sync for LinuxMMap {}

impl LinuxMMap {
    pub(super) unsafe fn new(fd: i32, len: size_t) -> GraveResult<Self> {
        // sanity check
        debug_assert!(len > 0, "mmap length must be non-zero");

        let ptr = mmap(
            std::ptr::null_mut(),
            len,
            PROT_WRITE | PROT_READ,
            MAP_SHARED,
            fd,
            0 as off_t,
        );

        if ptr == MAP_FAILED {
            let err = last_os_error();
            let err_raw = err.raw_os_error();

            // invalid fd, invalid fd type, invalid length, etc.
            if err_raw == Some(EINVAL)
                || err_raw == Some(EBADF)
                || err_raw == Some(EACCES)
                || err_raw == Some(EOVERFLOW)
            {
                return GraveError::io_err(ErrorCode::MMHcf, err);
            }

            // no more memory space available
            if err_raw == Some(ENOMEM) {
                return GraveError::io_err(ErrorCode::MMNsp, err);
            }

            // unknown (unsupported, etc.)
            return GraveError::io_err(ErrorCode::MMUnk, err);
        }

        return Ok(Self {
            len,
            ptr,
            unmapped: AtomicBool::new(false),
        });
    }

    pub(super) unsafe fn munmap(&self) -> GraveResult<()> {
        // NOTE: To avoid another thread/process from executing munmap, we mark unmapped before even
        // trying to unmap, this kind of wroks like mutex, as we reassign to false on failure
        if self
            .unmapped
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        if munmap(self.ptr, self.len) != 0 {
            // make it available so it can be unmapped again
            self.unmapped.store(false, Ordering::Release);

            let err = last_os_error();
            let err_raw = err.raw_os_error();

            // invalid or unaligned pointer
            if err_raw == Some(EINVAL) || err_raw == Some(ENOMEM) {
                return GraveError::io_err(ErrorCode::MMHcf, err);
            }

            // unknown
            return GraveError::io_err(ErrorCode::MMUnk, err);
        }

        Ok(())
    }

    #[inline]
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) unsafe fn msync(&self) -> GraveResult<()> {
        // sanity check
        self.sanity_check();

        // only for EIO and EBUSY errors
        const MAX_RETRIES: usize = 4;
        let mut retries = 0;

        loop {
            if likely(msync(self.ptr, self.len, MS_SYNC) == 0) {
                return Ok(());
            }

            let error = last_os_error();
            let error_raw = error.raw_os_error();

            // IO interrupt (must retry)
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            // invalid fd or lack of support for sync
            if error_raw == Some(ENOMEM) || error_raw == Some(EINVAL) {
                return GraveError::io_err(ErrorCode::MMHcf, error);
            }

            // locked file or fatel error, i.e. unable to sync
            //
            // NOTE: this is handled seperately, as if this error occurs, we must
            // notify users that the sync failed, hence the data is not persisted
            if error_raw == Some(EIO) || error_raw == Some(EBUSY) {
                if retries < MAX_RETRIES {
                    retries += 1;
                    std::hint::spin_loop();
                    continue;
                }

                // retries exhausted and durability is broken in the current window
                return GraveError::io_err(ErrorCode::MMSyn, error);
            }

            return GraveError::io_err(ErrorCode::MMUnk, error);
        }
    }

    #[inline]
    pub(super) const unsafe fn get<T>(&self, offset: usize) -> *const T {
        debug_assert!(offset % 0x40 == 0, "Offset must be 64 bytes aligned");
        debug_assert!(
            offset + std::mem::size_of::<T>() <= self.len,
            "Offset must not exceed mmap size"
        );

        self.ptr.add(offset) as *const T
    }

    #[inline]
    pub(super) const unsafe fn get_mut<T>(&self, offset: usize) -> *mut T {
        debug_assert!(offset % 0x40 == 0, "Offset must be 64 bytes aligned");
        debug_assert!(
            offset + std::mem::size_of::<T>() <= self.len,
            "Offset must not exceed mmap size"
        );

        self.ptr.add(offset) as *mut T
    }

    #[inline]
    fn sanity_check(&self) {
        debug_assert!(!self.unmapped.load(Ordering::Acquire), "Trying to access dropped mmap");
    }
}

#[inline]
fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::system::{file::OsFile, IOFlushMode};
    use std::path::PathBuf;
    use tempfile::{tempdir, TempDir};

    const LEN: usize = 0x80;

    fn new_tmp() -> (TempDir, PathBuf, OsFile, LinuxMMap) {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        let file = unsafe { OsFile::new(tmp.clone(), IOFlushMode::Manual, LEN as u64) }.expect("new LinuxFile");
        let mmap = unsafe { LinuxMMap::new(file.fd(), LEN) }.expect("new LinuxMMap");

        (dir, tmp, file, mmap)
    }

    mod map_unmap {
        use super::*;

        #[test]
        fn map_unmap_cycle() {
            let (_dir, _tmp, _file, map) = new_tmp();

            assert!(!map.ptr.is_null());
            assert_eq!(map.len(), LEN);

            assert!(unsafe { map.munmap() }.is_ok());
        }

        #[test]
        fn map_fails_on_invalid_fd() {
            unsafe { assert!(LinuxMMap::new(-1, LEN).is_err()) };
        }

        #[test]
        #[cfg(debug_assertions)]
        #[should_panic]
        fn map_fails_on_invalid_len_debug_only() {
            // NOTE: 0 is a valid fd, and points to stdin
            unsafe { LinuxMMap::new(0, 0) };
        }

        #[test]
        fn unmap_after_unmap_does_not_fails() {
            let (_dir, _tmp, _file, map) = new_tmp();

            unsafe {
                assert!(map.munmap().is_ok());
                assert!(map.munmap().is_ok());
                assert!(map.munmap().is_ok());
            }
        }
    }

    mod write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            let (_dir, _tmp, _file, map) = new_tmp();

            unsafe {
                // write + sync
                let ptr = map.get_mut::<u64>(0);
                *ptr = 0xDEAD_C0DE_DEAD_C0DE;
                assert!(map.msync().is_ok());

                // read + validate
                let val = *map.get::<u64>(0);
                assert_eq!(val, 0xDEAD_C0DE_DEAD_C0DE);

                assert!(map.munmap().is_ok());
            }
        }

        #[test]
        fn write_read_across_sessions() {
            let (_dir, tmp, file, map) = new_tmp();

            // write + sync + unmap + close
            unsafe {
                let ptr = map.get_mut::<u64>(0);
                *ptr = 0xDEAD_C0DE_DEAD_C0DE;
                assert!(map.msync().is_ok());

                assert!(map.munmap().is_ok());
                drop(file);
            }

            // open + map + read + validate
            unsafe {
                let file = OsFile::open(tmp, IOFlushMode::Manual).expect("existing open");
                let map = LinuxMMap::new(file.fd(), LEN).expect("linux mmap");

                // read + validate
                let val = *map.get::<u64>(0);
                assert_eq!(val, 0xDEAD_C0DE_DEAD_C0DE);

                assert!(map.munmap().is_ok());
            }
        }

        #[test]
        fn mmap_write_is_in_synced_with_file_read() {
            let (_dir, _tmp, file, map) = new_tmp();

            unsafe {
                // write + sync
                let ptr = map.get_mut::<u64>(0);
                *ptr = 0xDEAD_C0DE_DEAD_C0DE;
                assert!(map.msync().is_ok());

                // pread
                let mut buf = [0u8; 8];
                file.read(buf.as_mut_ptr(), 0, 8).expect("failed to read");
                assert_eq!(u64::from_le_bytes(buf), 0xDEAD_C0DE_DEAD_C0DE);

                assert!(map.munmap().is_ok());
            }
        }
    }

    mod concurrency {
        use super::*;

        #[test]
        fn munmap_is_thread_safe() {
            let (_dir, _tmp, _file, map) = new_tmp();

            let mut handles = Vec::new();
            let map = std::sync::Arc::new(map);

            for _ in 0..8 {
                let m = map.clone();
                handles.push(std::thread::spawn(move || unsafe {
                    assert!(m.munmap().is_ok());
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }
        }

        #[test]
        fn msync_is_thread_safe() {
            let (_dir, _tmp, _file, map) = new_tmp();

            let mut handles = Vec::new();
            let map = std::sync::Arc::new(map);

            unsafe {
                *map.get_mut::<u64>(0) = 42;
            }

            for _ in 0..8 {
                let m = map.clone();
                handles.push(std::thread::spawn(move || unsafe {
                    assert!(m.msync().is_ok());
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }

            unsafe {
                assert_eq!(*map.get::<u64>(0), 42);
                assert!(map.munmap().is_ok());
            }
        }

        #[test]
        fn concurrent_writes_then_sync() {
            let (_dir, _tmp, _file, map) = new_tmp();

            let mut handles = Vec::new();
            let map = std::sync::Arc::new(map);

            for i in 0..8u64 {
                let m = map.clone();
                handles.push(std::thread::spawn(move || unsafe {
                    let ptr = m.get_mut::<u64>(0);
                    *ptr = i;
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }

            unsafe {
                assert!(map.msync().is_ok());
                assert!(map.munmap().is_ok());
            }
        }
    }

    #[test]
    fn msync_works() {
        let (_dir, _tmp, _file, map) = new_tmp();

        unsafe {
            assert!(map.msync().is_ok());
            assert!(map.munmap().is_ok());
        }
    }
}
