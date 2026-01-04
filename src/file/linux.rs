use crate::errors::{GraveError, GraveResult};
use libc::{
    c_int, c_void, close, fdatasync, fstat, ftruncate, iovec, off_t, open, pread, pwrite, pwritev, size_t, stat, EPERM,
    O_CLOEXEC, O_CREAT, O_NOATIME, O_RDWR, O_TRUNC,
};
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};

#[derive(Debug, Clone)]
pub(super) struct File(i32);

unsafe impl Send for File {}
unsafe impl Sync for File {}

impl File {
    /// Creates a new [`File`] at given `Path`
    pub(crate) unsafe fn new(path: &Path) -> GraveResult<Self> {
        let fd = Self::open_with_flags(path, Self::prep_flags(true))?;
        Ok(Self(fd))
    }

    /// Opens an existing [`File`] at given `Path`
    pub(crate) unsafe fn open(path: &Path) -> GraveResult<Self> {
        let fd = Self::open_with_flags(path, Self::prep_flags(false))?;
        Ok(Self(fd))
    }

    /// Fetches file descriptor for [`File`]
    pub(super) const fn fd(&self) -> i32 {
        self.0
    }

    /// Fetches current length of [`File`]
    pub(crate) unsafe fn len(&self) -> GraveResult<usize> {
        let st = self.stats()?;
        Ok(st.st_size as usize)
    }

    /// Syncs dirty pages of [`File`] to disk
    ///
    /// ## `fsync` vs `fdatasync`
    ///
    /// We use `fdatasync()` instead of `fsync()` for persistence
    ///
    /// `fdatasync()` guarantees, all modified file data and any metadata required to
    /// retrieve that data, like file size changes are flushed to stable storage
    ///
    /// This way we avoid non-essential metadata updates, such as access time (`atime`),
    /// modification time (`mtime`), and other inode bookkeeping information!
    pub(crate) unsafe fn sync(&self) -> GraveResult<()> {
        let res = fdatasync(self.fd() as c_int);
        if res != 0 {
            return Self::last_os_error();
        }

        Ok(())
    }

    /// Closes [`File`] via `fd`
    pub(super) unsafe fn close(&self) -> GraveResult<()> {
        let res = close(self.fd());
        if res != 0 {
            return Self::last_os_error();
        }

        Ok(())
    }

    /// Truncates/extends length of [`File`]
    ///
    /// **WARN:** If `len` is smaller then the current length of [`File`] it'll be shrinked,
    /// which may result in data loss
    #[inline]
    pub(crate) unsafe fn ftruncate(&self, len: usize) -> GraveResult<()> {
        let res = ftruncate(self.fd(), len as off_t);
        if res != 0 {
            return Self::last_os_error();
        }

        Ok(())
    }

    /// Positional read from [`File`]
    #[inline(always)]
    pub(crate) unsafe fn pread(&self, ptr: *mut u8, off: usize, len: usize) -> GraveResult<()> {
        let mut read = 0usize;
        while read < len {
            let res = pread(
                self.fd(),
                ptr.add(read) as *mut c_void,
                (len - read) as size_t,
                (off + read) as i64,
            );

            if res == 0 {
                return Err(GraveError::IO("unexpected EOF during pread".into()));
            }

            if res < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }

            read += res as usize;
        }

        Ok(())
    }

    /// Positional write to [`File`]
    #[inline(always)]
    pub(crate) unsafe fn pwrite(&self, ptr: *const u8, off: usize, page_size: usize) -> GraveResult<()> {
        let mut written = 0usize;
        while written < page_size {
            let res = pwrite(
                self.fd(),
                ptr.add(written) as *const c_void,
                (page_size - written) as size_t,
                (off + written) as i64,
            );

            if res < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }

                return Err(err.into());
            }

            if res == 0 {
                return Err(GraveError::IO("unexpected EOF during pwrite".into()));
            }

            written += res as usize;
        }

        Ok(())
    }

    /// Positional vectored write to [`File`]
    #[inline(always)]
    pub(super) unsafe fn pwritev(&self, ptrs: &[*const u8], off: usize, page_size: usize) -> GraveResult<()> {
        // sanity checks
        debug_assert!(page_size > 0, "invalid page_size");
        debug_assert!(!ptrs.is_empty(), "ptrs must never be empty");
        debug_assert!(off % page_size != 0, "off is not page aligned");

        let nptrs = ptrs.len();
        let total_len = nptrs * page_size;
        let mut iovecs: Vec<iovec> = ptrs
            .iter()
            .map(|ptr| iovec {
                iov_base: *ptr as *mut c_void,
                iov_len: page_size,
            })
            .collect();

        let mut written = 0usize;
        while written < total_len {
            let res = pwritev(
                self.fd(),
                iovecs.as_ptr(),
                iovecs.len() as c_int,
                (off + written) as off_t,
            );

            if res < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }

            if res == 0 {
                return Err(GraveError::IO("unexpected EOF during pwritev".into()));
            }

            // NOTE: In posix systems, pwritev may write fewer bytes than requested, stop mid iovec
            // or in-between iovec. Even though this behavior is situation/filesystem dependent,
            // we must handle it for correctness across different systems

            let mut remaining = res as usize;
            let mut idx = 0;

            while remaining > 0 {
                let current_iov = &mut iovecs[0];
                if remaining >= current_iov.iov_len {
                    idx += 1;
                    written += current_iov.iov_len;
                    remaining -= current_iov.iov_len;
                } else {
                    current_iov.iov_base = (current_iov.iov_base as *mut u8).add(remaining) as *mut c_void;
                    current_iov.iov_len -= remaining;
                    written += remaining;
                    remaining = 0;
                }
            }

            if idx > 0 {
                iovecs.drain(0..idx);
            }
        }

        Ok(())
    }

    /// Fetches metadata for [`File`] via `fstat` syscall
    unsafe fn stats(&self) -> GraveResult<stat> {
        let mut st = std::mem::zeroed::<stat>();
        let res = fstat(self.fd(), &mut st);
        if res != 0 {
            return Self::last_os_error();
        }

        Ok(st)
    }

    /// Creates/opens a [`File`] w/ provided `flags`
    ///
    /// ## Limitations on Use of `O_NOATIME` (`EPERM` Error)
    ///
    /// `open()` with `O_NOATIME` may fail with `EPERM` instead of silently ignoring the flag
    ///
    /// `EPERM` indicates a kernel level permission violation, as the kernel rejects the
    /// request outright, even though the flag only affects metadata behavior
    ///
    /// To remain sane across ownership models, containers, and shared filesystems,
    /// we explicitly retry the `open()` w/o `O_NOATIME` when `EPERM` is encountered
    unsafe fn open_with_flags(path: &Path, flags: i32) -> GraveResult<i32> {
        let cpath = File::path_to_cstring(path)?;

        let fd = open(cpath.as_ptr(), flags);
        if fd >= 0 {
            return Ok(fd);
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(EPERM) {
            #[cfg(test)]
            debug_assert!((flags & O_NOATIME) != 0, "O_NOATIME flag is not being used");

            let fd = open(cpath.as_ptr(), flags & !O_NOATIME);
            if fd >= 0 {
                return Ok(fd);
            }
        }

        Err(err.into())
    }

    /// Prepares kernel flags for syscall
    ///
    /// ## Access Time Updates (O_NOATIME)
    ///
    /// We use the `O_NOATIME` flag to disable access time updates on the [File]
    /// Normally every I/O operation triggers an `atime` update/write to disk
    ///
    /// This is counter productive and increases latency for I/O ops in our case!
    ///
    /// ## Limitations of `O_NOATIME`
    ///
    /// Not all filesystems support this flag, on many it is silently ignored, but some rejects
    /// it with `EPERM` error
    ///
    /// Also, this flag only works when UID's match for calling processe and file owner
    const fn prep_flags(is_new: bool) -> i32 {
        const BASE: i32 = O_RDWR | O_NOATIME | O_CLOEXEC;
        const NEW: i32 = O_CREAT | O_TRUNC;
        BASE | ((is_new as i32) * NEW)
    }

    fn path_to_cstring(path: &Path) -> GraveResult<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|e| GraveError::IO(format!("Error due to invalid Path: {e}")))
    }

    fn last_os_error<T>() -> GraveResult<T> {
        Err(std::io::Error::last_os_error().into())
    }
}
