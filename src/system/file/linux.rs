use crate::{
    error::ErrorCode,
    hints::{likely, unlikely},
    GraveError, GraveResult,
};
use libc::{
    c_int, c_short, c_void, close, fcntl, fdatasync, flock, fstat, ftruncate, iovec, off_t, open, pread, pwrite,
    pwritev, size_t, stat, sysconf, unlink, EBADF, EDQUOT, EFAULT, EINVAL, EIO, EISDIR, EMSGSIZE, ENOSPC, EPERM, EROFS,
    ESPIPE, F_SETLKW, F_UNLCK, F_WRLCK, O_CLOEXEC, O_CREAT, O_NOATIME, O_RDWR, O_TRUNC, SEEK_SET, S_IRUSR, S_IWUSR,
    _SC_IOV_MAX,
};
use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    sync::atomic::{AtomicI32, AtomicU64, Ordering},
};

/// Low level abstraction for `File` on Linux systems
///
/// ## Retry Rules
///
/// - Any `EINTR` is always retried immediately
/// - Any `EIO` during `fdatasync` is retried **bounded**
/// - Writes are never retried after partial failure
///
/// ## HCF (Hault & Catch Fire) errors
///
/// Errors w/ `ErrorCode::IOHcf` indicates **internal or implementation bugs**.
///
/// ## IOSyn (Sync) errors
///
/// Errors w/ `ErrorCode::IOSyn` indicates **durability failure**.
///
/// Upon durability failures, we must:
///
/// - mark writes in current window as **un-synced**
/// - **do not accept** more write/read ops as system is in critical failure mode.
///
/// Linux ABI is ❤️ (◔ ◡ ◔)
#[derive(Debug)]
pub(super) struct LinuxFile {
    fd: AtomicI32,
    len: AtomicU64,
    path: std::path::PathBuf,
}

impl LinuxFile {
    pub(super) unsafe fn new(path: std::path::PathBuf) -> GraveResult<Self> {
        let fd = open_with_flags(&path, prep_flags(true))?;
        let meta = metadata(fd)?;
        let len = meta.st_size as u64;

        Ok(Self {
            path,
            fd: AtomicI32::new(fd),
            len: AtomicU64::new(len),
        })
    }

    pub(super) unsafe fn open(path: std::path::PathBuf) -> GraveResult<Self> {
        let fd = open_with_flags(&path, prep_flags(false))?;
        let meta = metadata(fd)?;
        let len = meta.st_size as u64;

        Ok(Self {
            path,
            fd: AtomicI32::new(fd),
            len: AtomicU64::new(len),
        })
    }

    #[inline]
    pub(super) fn fd(&self) -> i32 {
        self.fd.load(Ordering::Acquire)
    }

    #[inline]
    pub(super) fn len(&self) -> u64 {
        self.len.load(Ordering::Acquire)
    }

    /// ## `fsync` vs `fdatasync`
    ///
    /// We use `fdatasync()` instead of `fsync()` for persistence
    ///
    /// `fdatasync()` guarantees, all modified file data and any metadata required to
    /// retrieve that data, like file size changes are flushed to stable storage
    ///
    /// This way we avoid non-essential metadata updates, such as access time (`atime`),
    /// modification time (`mtime`), and other inode bookkeeping information!
    #[inline]
    pub(super) unsafe fn sync(&self) -> GraveResult<()> {
        // sanity check (debug_only)
        self.sanity_check();

        const MAX_RETRIES: usize = 4;
        let mut retries = 0; // only for EIO errors

        loop {
            if likely(fdatasync(self.fd() as c_int) == 0) {
                return Ok(());
            }

            let error = last_os_error();
            let error_raw = error.raw_os_error();

            // IO interrupt (must retry)
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            // invalid fd or lack of support for sync
            if error_raw == Some(EINVAL) || error_raw == Some(EBADF) {
                return GraveError::io_err(ErrorCode::IOHcf, error);
            }

            // read-only file (can also be caused by TOCTOU)
            if error_raw == Some(EROFS) {
                return GraveError::io_err(ErrorCode::PMWrt, error);
            }

            // fatel error, i.e. unable to sync
            //
            // NOTE: this is handled seperately, as if this error occurs, we must
            // notify users that the sync failed, hence the data is not persisted
            if error_raw == Some(EIO) {
                if retries < MAX_RETRIES {
                    retries += 1;
                    std::hint::spin_loop();
                    continue;
                }

                // retries exhausted and durability is broken in the current window
                return GraveError::io_err(ErrorCode::IOSyn, error);
            }

            return GraveError::io_err(ErrorCode::IOUnk, error);
        }
    }

    #[inline]
    pub(super) unsafe fn close(&self) -> GraveResult<()> {
        let fd = self.fd();
        if fd < 0 || close(fd) == 0 {
            self.fd.store(-1, Ordering::Release);
            return Ok(());
        }

        let error = last_os_error();
        let error_raw = error.raw_os_error();

        // NOTE: In posix systems, kernal may report delayed writeback failures on `close`,
        // this are fatel errors, and can not be retried! So all the writes in the sync window
        // were not persisted!
        //
        // We handle this seperately, so the layer above would be able to act on this error!
        if error_raw == Some(EIO) {
            return GraveError::io_err(ErrorCode::IOSyn, error);
        }

        return GraveError::io_err(ErrorCode::IOUnk, error);
    }

    /// Unlinks (possibly deletes) [`LinuxFile`] from filesystem
    ///
    /// **WARN**: File must be closed beforehand, to avoid I/O errors
    #[inline]
    pub(super) unsafe fn unlink(&self) -> GraveResult<()> {
        let cpath = path_to_cstring(&self.path)?;
        if unlikely(unlink(cpath.as_ptr()) != 0) {
            let error = last_os_error();
            return GraveError::io_err(ErrorCode::IOUnk, error);
        }

        Ok(())
    }

    #[inline]
    pub(super) unsafe fn extend(&self, len_to_add: u64) -> GraveResult<()> {
        // sanity check (debug_only)
        self.sanity_check();

        let new_len = self.len() + len_to_add;
        if ftruncate(self.fd(), new_len as off_t) == 0 {
            self.len.store(new_len, Ordering::Release);
            return Ok(());
        }

        let error = last_os_error();
        let error_raw = error.raw_os_error();

        // invalid fd or lack of support for sync
        if error_raw == Some(EINVAL) || error_raw == Some(EBADF) {
            return GraveError::io_err(ErrorCode::IOHcf, error);
        }

        // read-only fs (can also be caused by TOCTOU)
        if error_raw == Some(EROFS) {
            return GraveError::io_err(ErrorCode::PMWrt, error);
        }

        // no space available on disk
        if error_raw == Some(ENOSPC) {
            return GraveError::io_err(ErrorCode::IONsp, error);
        }

        GraveError::io_err(ErrorCode::IOUnk, error)
    }

    /// Acquire an exclusive write lock
    pub(super) unsafe fn lock(&self) -> GraveResult<()> {
        // sanity check (debug_only)
        self.sanity_check();

        self.flock_impl(F_WRLCK)
    }

    /// Release the acquired lock (shared/exclusive)
    pub(super) unsafe fn unlock(&self) -> GraveResult<()> {
        // sanity check (debug_only)
        self.sanity_check();

        self.flock_impl(F_UNLCK)
    }

    /// Read from [`LinuxFile`] at a given `offset`
    #[inline(always)]
    pub(super) unsafe fn pread(&self, buf_ptr: *mut u8, offset: usize, len_to_read: usize) -> GraveResult<()> {
        // sanity checks
        self.sanity_check();
        debug_assert_ne!(len_to_read, 0, "invalid length");
        debug_assert!(!buf_ptr.is_null(), "invalid buffer pointer");

        let mut read = 0usize;
        while read < len_to_read {
            let res = pread(
                self.fd(),
                buf_ptr.add(read) as *mut c_void,
                (len_to_read - read) as size_t,
                (offset + read) as i64,
            );

            if unlikely(res <= 0) {
                let error = std::io::Error::last_os_error();
                let error_raw = error.raw_os_error();

                // IO interrupt
                if likely(error.kind() == std::io::ErrorKind::Interrupted) {
                    continue;
                }

                // unexpected EOF
                if unlikely(res == 0) {
                    return GraveError::io_err(ErrorCode::IOEof, error);
                }

                // invalid fd, invalid fd type, bad pointer, etc.
                if unlikely(
                    error_raw == Some(EINVAL)
                        || error_raw == Some(EBADF)
                        || error_raw == Some(EFAULT)
                        || error_raw == Some(ESPIPE),
                ) {
                    return GraveError::io_err(ErrorCode::IOHcf, error);
                }

                return GraveError::io_err(ErrorCode::IOUnk, error);
            }

            read += res as usize;
        }

        Ok(())
    }

    /// Write to [`LinuxFile`] at a given `offset`
    #[inline(always)]
    pub(super) unsafe fn pwrite(&self, buf_ptr: *const u8, offset: usize, len_to_write: usize) -> GraveResult<()> {
        // sanity checks
        self.sanity_check();
        debug_assert_ne!(len_to_write, 0, "invalid length");
        debug_assert!(!buf_ptr.is_null(), "invalid buffer pointer");
        debug_assert!(offset + len_to_write <= self.len() as usize, "Write overflow");

        let mut written = 0usize;
        while written < len_to_write {
            let res = pwrite(
                self.fd(),
                buf_ptr.add(written) as *const c_void,
                (len_to_write - written) as size_t,
                (offset + written) as i64,
            );

            if unlikely(res <= 0) {
                let error = std::io::Error::last_os_error();
                let error_raw = error.raw_os_error();

                // IO interrupt
                if likely(error.kind() == std::io::ErrorKind::Interrupted) {
                    continue;
                }

                // unexpected EOF
                if unlikely(res == 0) {
                    return GraveError::io_err(ErrorCode::IOEof, error);
                }

                // read-only file (can also be caused by TOCTOU)
                if error_raw == Some(EROFS) {
                    return GraveError::io_err(ErrorCode::PMWrt, error);
                }

                // invalid fd, invalid fd type, bad pointer, etc.
                if unlikely(
                    error_raw == Some(EINVAL)
                        || error_raw == Some(EBADF)
                        || error_raw == Some(EFAULT)
                        || error_raw == Some(ESPIPE),
                ) {
                    return GraveError::io_err(ErrorCode::IOHcf, error);
                }

                return GraveError::io_err(ErrorCode::IOUnk, error);
            }

            written += res as usize;
        }

        Ok(())
    }

    /// Write (Vectored) to [`LinuxFile`] from multiple buffers starting from a given `offset`
    #[inline(always)]
    pub(super) unsafe fn pwritev(&self, buf_ptrs: &[*const u8], offset: usize, buffer_size: usize) -> GraveResult<()> {
        // sanity checks
        #[cfg(debug_assertions)]
        {
            let len = self.len();
            let buf_len = buf_ptrs.len();

            self.sanity_check();
            debug_assert_ne!(buffer_size, 0, "invalid buffer length");
            debug_assert!(offset + (buffer_size * buf_len) <= len as usize, "Write overflow");

            // NOTE: On some systems, `_SC_IOV_MAX` is not set, hence it can return `-1`
            let iov_max = sysconf(_SC_IOV_MAX);
            if iov_max > 0 {
                debug_assert!(buf_len <= iov_max as usize, "Buffer overflow beyound IOV_MAX");
            }
        }

        let nptrs = buf_ptrs.len();
        let total_len = nptrs * buffer_size;
        let mut iovecs: Vec<iovec> = buf_ptrs
            .iter()
            .map(|ptr| iovec {
                iov_base: *ptr as *mut c_void,
                iov_len: buffer_size,
            })
            .collect();

        let mut written = 0usize;
        while written < total_len {
            let res = pwritev(
                self.fd(),
                iovecs.as_ptr(),
                iovecs.len() as c_int,
                (offset + written) as off_t,
            );

            if unlikely(res <= 0) {
                let error = std::io::Error::last_os_error();
                let error_raw = error.raw_os_error();

                // IO interrupt
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }

                // unexpected EOF
                if unlikely(res == 0) {
                    return GraveError::io_err(ErrorCode::IOEof, error);
                }

                // read-only file (can also be caused by TOCTOU)
                if error_raw == Some(EROFS) {
                    return GraveError::io_err(ErrorCode::PMWrt, error);
                }

                // no space available on disk
                if unlikely(error_raw == Some(ENOSPC) || error_raw == Some(EDQUOT)) {
                    return GraveError::io_err(ErrorCode::IONsp, error);
                }

                // invalid fd, invalid fd type, bad pointer, etc.
                if unlikely(
                    error_raw == Some(EINVAL)
                        || error_raw == Some(EBADF)
                        || error_raw == Some(EFAULT)
                        || error_raw == Some(ESPIPE)
                        || error_raw == Some(EMSGSIZE),
                ) {
                    return GraveError::io_err(ErrorCode::IOHcf, error);
                }

                return GraveError::io_err(ErrorCode::IOUnk, error);
            }

            // NOTE: In posix systems, pwritev may -
            //
            // - write fewer bytes than requested
            // - stop in-between iovec's
            // - stop mid iovec
            //
            // Even though this behavior is situation or filesystem dependent (according to my short research),
            // we opt to handle it for correctness across different systems

            let mut idx = 0;
            let mut remaining = res as usize;

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

    #[inline]
    unsafe fn flock_impl(&self, lock_type: c_int) -> GraveResult<()> {
        let mut fl = flock {
            l_type: lock_type as c_short,
            l_whence: SEEK_SET as c_short,
            l_start: 0,
            l_len: 0, // whole file
            l_pid: 0,
        };

        loop {
            if fcntl(self.fd(), F_SETLKW, &mut fl) == 0 {
                return Ok(());
            }

            let err = std::io::Error::last_os_error();

            // NOTE: We must retry on interuption errors (EINTR retry)
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            return GraveError::io_err(ErrorCode::IOLck, err);
        }
    }

    #[inline]
    #[cfg(debug_assertions)]
    fn sanity_check(&self) {
        debug_assert!(self.fd() >= 0, "Invalid fd for LinuxFile");
    }
}

//
// thread safety
//

unsafe impl Send for LinuxFile {}
unsafe impl Sync for LinuxFile {}

//
// helpers
//

/// ## Caveats of `O_NOATIME` (`EPERM` Error)
///
/// `open()` with `O_NOATIME` may fail with `EPERM` instead of silently ignoring the flag
///
/// `EPERM` indicates a kernel level permission violation, as the kernel rejects the
/// request outright, even though the flag only affects metadata behavior
///
/// To remain sane across ownership models, containers, and shared filesystems,
/// we explicitly retry the `open()` w/o `O_NOATIME` when `EPERM` is encountered
unsafe fn open_with_flags(path: &std::path::PathBuf, mut flags: i32) -> GraveResult<i32> {
    let cpath = path_to_cstring(path)?;
    let mut tried_noatime = false;

    loop {
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

        let err = last_os_error();
        let err_raw = err.raw_os_error();

        // NOTE: We must retry on interuption errors (EINTR retry)
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }

        // NOTE: Fallback for `EPERM` error, when `O_NOATIME` is not supported by current FS
        if err_raw == Some(EPERM) && (flags & O_NOATIME) != 0 && !tried_noatime {
            flags &= !O_NOATIME;
            tried_noatime = true;
            continue;
        }

        // no space available on disk
        if err_raw == Some(ENOSPC) {
            return GraveError::io_err(ErrorCode::IONsp, err);
        }

        // no space available on disk
        if err_raw == Some(EISDIR) {
            return GraveError::io_err(ErrorCode::IOHcf, err);
        }

        return GraveError::io_err(ErrorCode::IOUnk, err);
    }
}

unsafe fn metadata(fd: i32) -> GraveResult<stat> {
    let mut st = std::mem::zeroed::<stat>();
    let res = fstat(fd, &mut st);
    if likely(res == 0) {
        return Ok(st);
    }

    let error = last_os_error();
    let error_raw = error.raw_os_error();

    // bad or invalid fd
    if error_raw == Some(EBADF) || error_raw == Some(EFAULT) {
        return GraveError::io_err(ErrorCode::IOHcf, error);
    }

    GraveError::io_err(ErrorCode::IOUnk, error)
}

/// ## Access Time Updates (O_NOATIME)
///
/// We use the `O_NOATIME` flag to disable access time updates on the [`File`]
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

fn path_to_cstring(path: &std::path::PathBuf) -> GraveResult<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| GraveError::new(ErrorCode::PHInv, format!("Invalid Path: {e}")))
}

#[inline]
fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::{tempdir, TempDir};

    fn new_tmp() -> (TempDir, PathBuf, LinuxFile) {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");
        let file = unsafe { LinuxFile::new(tmp.clone()) }.expect("new LinuxFile");

        (dir, tmp, file)
    }

    mod new_open {
        use super::*;

        #[test]
        fn new_works() {
            let (_dir, tmp, file) = new_tmp();
            assert!(file.fd() >= 0);

            // sanity check
            assert!(tmp.exists());
            assert!(unsafe { file.close().is_ok() });
        }

        #[test]
        fn open_works() {
            let (_dir, tmp, file) = new_tmp();
            unsafe {
                assert!(file.fd() >= 0);
                assert!(file.close().is_ok());

                match LinuxFile::open(tmp) {
                    Ok(file) => {
                        assert!(file.fd() >= 0);
                        assert!(file.close().is_ok());
                    }
                    Err(e) => panic!("failed to open file due to E: {e}"),
                }
            }
        }

        #[test]
        fn open_fails_when_file_is_unlinked() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.fd() >= 0);
                assert!(file.close().is_ok());
                assert!(file.unlink().is_ok());

                let file = LinuxFile::open(tmp);
                assert!(file.is_err());
            }
        }
    }

    mod close {
        use super::*;

        #[test]
        fn close_works() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.close().is_ok());

                // sanity check
                assert!(tmp.exists());
            }
        }

        #[test]
        fn close_after_close_does_not_fail() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                // should never fail
                assert!(file.close().is_ok());
                assert!(file.close().is_ok());
                assert!(file.close().is_ok());

                // sanity check
                assert!(tmp.exists());
            }

            // NOTE: We need this protection, cause in multithreaded env's, more then one thread
            // could try to close the file at same time, hence the system should not panic in these cases
        }
    }

    mod unlink {
        use super::*;

        #[test]
        fn unlink_correctly_deletes_file() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.close().is_ok());
                assert!(file.unlink().is_ok());
                assert!(!tmp.exists());
            }
        }

        #[test]
        fn unlink_fails_on_unlinked_file() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.close().is_ok());
                assert!(file.unlink().is_ok());
                assert!(!tmp.exists());

                // should fail on missing
                assert!(file.unlink().is_err());
            }
        }
    }

    mod extend {
        use super::*;

        #[test]
        fn extend_zero_extends_file() {
            const NEW_LEN: u64 = 0x80;
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.extend(NEW_LEN).is_ok());
                assert_eq!(file.len(), NEW_LEN);
                assert!(file.close().is_ok());
            }

            // strict sanity check to ensure file is zero byte extended
            let file_contents = std::fs::read(&tmp).expect("read from file");
            assert_eq!(file_contents.len(), NEW_LEN as usize, "len mismatch for file");
            assert!(
                file_contents.iter().all(|b| *b == 0u8),
                "file must be zero byte extended"
            );
        }

        #[test]
        fn open_preserves_existing_length() {
            const NEW_LEN: u64 = 0x80;
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.extend(NEW_LEN).is_ok());
                assert_eq!(file.len(), NEW_LEN);
                assert!(file.sync().is_ok());
                assert!(file.close().is_ok());

                match LinuxFile::open(tmp) {
                    Err(e) => panic!("{e}"),
                    Ok(file) => {
                        assert_eq!(file.len(), NEW_LEN);
                    }
                }
            }
        }
    }

    mod lock_unlock {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};

        #[test]
        fn lock_unlock_cycle() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.lock().is_ok());
                assert!(file.unlock().is_ok());

                assert!(file.lock().is_ok());
                assert!(file.unlock().is_ok());

                assert!(file.close().is_ok());
            }
        }

        #[test]
        fn lock_survives_io_operation() {
            let (_dir, tmp, file) = new_tmp();

            unsafe {
                assert!(file.lock().is_ok());

                let data = vec![1u8; 0x20];
                file.extend(data.len() as u64).expect("resize file");
                file.pwrite(data.as_ptr(), 0, data.len()).expect("write to file");

                assert!(file.unlock().is_ok());
                assert!(file.close().is_ok());
            }
        }
    }

    mod write_read {
        use super::*;

        #[test]
        fn pwrite_pread_cycle() {
            let (_dir, tmp, file) = new_tmp();

            const LEN: usize = 0x20;
            const DATA: [u8; LEN] = [0x1A; LEN];

            unsafe {
                file.extend(LEN as u64).expect("resize file");
                assert!(file.pwrite(DATA.as_ptr(), 0, LEN).is_ok());

                let mut buf = vec![0u8; LEN];
                assert!(file.pread(buf.as_mut_ptr(), 0, LEN).is_ok());
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");
                assert!(file.close().is_ok());
            }
        }

        #[test]
        fn pwritev_pread_cycle() {
            let (_dir, tmp, file) = new_tmp();

            const LEN: usize = 0x20;
            const DATA: [u8; LEN] = [0x1A; LEN];

            let ptrs = vec![DATA.as_ptr(); 0x10];
            let total_len = ptrs.len() * LEN;

            unsafe {
                file.extend(total_len as u64).expect("resize file");
                assert!(file.pwritev(&ptrs, 0, LEN).is_ok());

                let mut buf = vec![0u8; total_len];
                assert!(file.pread(buf.as_mut_ptr(), 0, total_len).is_ok(), "pread failed");
                assert_eq!(buf.len(), total_len, "mismatch between read and write");

                for chunk in buf.chunks_exact(LEN) {
                    assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
                }

                assert!(file.close().is_ok());
            }
        }

        #[test]
        fn pwrite_pread_cycle_across_sessions() {
            let (_dir, tmp, file) = new_tmp();

            const LEN: usize = 0x20;
            const DATA: [u8; LEN] = [0x1A; LEN];

            // create + write + sync + close
            unsafe {
                file.extend(LEN as u64).expect("resize file");
                assert!(file.pwrite(DATA.as_ptr(), 0, LEN).is_ok());
                assert!(file.sync().is_ok());
                assert!(file.close().is_ok());
            }

            // open + read + verify
            unsafe {
                let file = LinuxFile::open(tmp).expect("open file");

                let mut buf = vec![0u8; LEN];
                assert!(file.pread(buf.as_mut_ptr(), 0, LEN).is_ok());
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");
                assert!(file.close().is_ok());
            }
        }
    }
}
