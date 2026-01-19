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
                return GraveError::map_err(ErrorCode::MMHcf, err);
            }

            // no more memory space available
            if err_raw == Some(ENOMEM) {
                return GraveError::map_err(ErrorCode::MMNsp, err);
            }

            // unknown (unsupported, etc.)
            return GraveError::map_err(ErrorCode::MMUnk, err);
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
                return GraveError::map_err(ErrorCode::MMHcf, err);
            }

            // unknown
            return GraveError::map_err(ErrorCode::MMUnk, err);
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
                return GraveError::map_err(ErrorCode::MMHcf, error);
            }

            // fatel error, i.e. unable to sync
            //
            // NOTE: this is handled seperately, as if this error occurs, we must
            // notify users that the sync failed, hence the data is not persisted
            if error_raw == Some(EIO) || error_raw == Some(EBUSY) {
                return GraveError::map_err(ErrorCode::MMSyn, error);
            }

            return GraveError::map_err(ErrorCode::MMUnk, error);
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
