use crate::errors::{GraveError, GraveResult};
use libc::{
    c_int, c_void, close, fdatasync, fstat, ftruncate, iovec, off_t, open, pread, pwrite, pwritev, size_t, stat, EPERM,
    O_CLOEXEC, O_CREAT, O_NOATIME, O_RDWR, O_TRUNC, S_IRUSR, S_IWUSR,
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
        debug_assert!(off % page_size == 0, "off is not page aligned");

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
                let current_iov = &mut iovecs[idx];
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

        let fd = if flags & O_CREAT != 0 {
            open(
                cpath.as_ptr(),
                flags,
                S_IRUSR | S_IWUSR, // write + read permissions
            )
        } else {
            open(cpath.as_ptr(), flags)
        };

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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn new_file_creation() {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        let file = unsafe { File::new(&tmp) };
        assert!(file.is_ok());

        let file = file.unwrap();
        assert!(file.fd() >= 0);
        unsafe { assert!(file.close().is_ok(), "failed to close file") }

        // sanity check
        assert!(tmp.exists(), "file must exists on the disk");
    }

    #[test]
    fn open_accepts_existing_file() {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        // create file + sanity check
        unsafe { assert!(File::new(&tmp).is_ok()) };
        assert!(&tmp.exists(), "file must exists on the disk");

        let file = unsafe { File::open(&tmp) };
        assert!(file.is_ok());

        let file = file.unwrap();
        assert!(file.fd() >= 0);
        unsafe { assert!(file.close().is_ok(), "failed to close file") }

        // sanity check
        assert!(tmp.exists(), "file must remain existing on the disk");
    }

    #[test]
    fn open_fails_on_missing_file() {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        unsafe {
            assert!(File::open(&tmp).is_err(), "open should fail on missing file");
        }
    }

    #[test]
    fn ftruncate_correctly_zero_extends_file() {
        const LEN: usize = 0x20;
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        // create + zero_extend
        let file = unsafe { File::new(&tmp).expect("new tmp file") };
        unsafe { assert!(file.ftruncate(LEN).is_ok(), "ftruncate failed") }
        unsafe { assert!(file.sync().is_ok(), "fdatasync failed") }

        // validate by read
        let file_contents = std::fs::read(&tmp).expect("read from file");

        assert_eq!(file_contents.len(), LEN, "len mismatch for file");
        assert!(
            file_contents.iter().all(|b| *b == 0u8),
            "file must be zero byte extended"
        );

        unsafe { assert!(file.close().is_ok(), "failed to close file") }
    }

    #[test]
    fn open_preserves_existing_len() {
        const LEN: usize = 0x20;
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        // create file + zero_extend + sanity check
        unsafe {
            let file = File::new(&tmp).expect("create new tmp file");
            assert!(file.ftruncate(LEN).is_ok());
            assert!(file.sync().is_ok());

            assert!(file.close().is_ok(), "failed to close file");
        }

        let file = unsafe { File::open(&tmp).expect("open existing file") };
        let file_len = unsafe { file.len().expect("read file len") };

        assert_eq!(file_len, LEN, "open must preserve length of the file");
        unsafe { assert!(file.close().is_ok(), "failed to close file") }
    }

    #[test]
    fn close_fails_after_file_is_closed() {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        unsafe {
            let file = File::new(&tmp).expect("open existing file");
            assert!(file.close().is_ok(), "failed to close the file");
            assert!(file.close().is_err(), "should fail after file is closed");
        }
    }

    mod pwrite_pread {
        use super::*;

        #[test]
        fn write_read_cycle() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            unsafe {
                let file = File::new(&tmp).expect("open existing file");

                // write
                assert!(file.pwrite(DATA.as_ptr(), 0, PAGE_SIZE).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, PAGE_SIZE, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; PAGE_SIZE];
                assert!(file.pread(buf.as_mut_ptr(), 0, PAGE_SIZE).is_ok(), "pread failed");
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }

        #[test]
        fn write_read_cycle_across_sessions() {
            const PAGE_SIZE: usize = 0x40;
            const DATA: [u8; PAGE_SIZE] = [0x1C; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            // create + write + sync + close
            unsafe {
                let file = File::new(&tmp).expect("open existing file");

                assert!(file.pwrite(DATA.as_ptr(), 0, PAGE_SIZE).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = File::open(&tmp).expect("open existing file");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, PAGE_SIZE, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; PAGE_SIZE];
                assert!(file.pread(buf.as_mut_ptr(), 0, PAGE_SIZE).is_ok(), "pread failed");
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }
    }

    mod pwritev_pread {
        use super::*;

        #[test]
        fn write_read_cycle() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            let ptrs = vec![DATA.as_ptr(); 0x10];
            let total_len = ptrs.len() * PAGE_SIZE;

            unsafe {
                let file = File::new(&tmp).expect("open existing file");

                // write
                assert!(file.pwritev(&ptrs, 0, PAGE_SIZE).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, total_len, "file len does not match expected len");

                let mut buf = vec![0u8; total_len];
                assert!(file.pread(buf.as_mut_ptr(), 0, total_len).is_ok(), "pread failed");
                assert_eq!(buf.len(), total_len, "mismatch between read and write");

                for chunk in buf.chunks_exact(PAGE_SIZE) {
                    assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
                }

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }

        #[test]
        fn write_read_cycle_across_sessions() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            let ptrs = vec![DATA.as_ptr(); 0x10];
            let total_len = ptrs.len() * PAGE_SIZE;

            // create + write + sync + close
            unsafe {
                let file = File::new(&tmp).expect("open existing file");

                assert!(file.pwritev(&ptrs, 0, PAGE_SIZE).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = File::open(&tmp).expect("open existing file");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, total_len, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; total_len];
                assert!(file.pread(buf.as_mut_ptr(), 0, total_len).is_ok(), "pread failed");
                assert_eq!(buf.len(), total_len, "mismatch between read and write");

                for chunk in buf.chunks_exact(PAGE_SIZE) {
                    assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
                }

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }
    }
}
