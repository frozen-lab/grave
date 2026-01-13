use crate::{
    common::{likely, IOFlushMode},
    GraveResult,
};
use std::{
    cell, mem,
    sync::{self, atomic, Arc},
};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug)]
struct FileCore {
    mode: IOFlushMode,
    cv: sync::Condvar,
    lock: sync::Mutex<()>,
    version: atomic::AtomicU8,
    dirty: atomic::AtomicBool,
    closed: atomic::AtomicBool,

    #[cfg(target_os = "linux")]
    file: cell::UnsafeCell<mem::ManuallyDrop<linux::File>>,

    #[cfg(not(target_os = "linux"))]
    file: (),
}

unsafe impl Send for FileCore {}
unsafe impl Sync for FileCore {}

#[derive(Debug)]
pub(crate) struct OsFile {
    core: Arc<FileCore>,
}

unsafe impl Send for OsFile {}
unsafe impl Sync for OsFile {}

impl std::fmt::Display for OsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(
            f,
            "OsFile {{fd: {}, len: {:?}, version: {}, closed: {}, mode: {:?}}}",
            unsafe { mem::ManuallyDrop::take(&mut *self.core.file.get()).fd() },
            unsafe { mem::ManuallyDrop::take(&mut *self.core.file.get()).len() },
            self.core.version.load(atomic::Ordering::Acquire),
            self.core.closed.load(atomic::Ordering::Acquire),
            self.core.mode,
        )
    }
}

impl OsFile {
    /// Creates a new [`OsFile`] at given `Path`
    ///
    /// ## RAII Safe
    ///
    /// The file handle (`fd` on `Linux`), is tied to the [`OsFile`] itself, hence the
    /// underlying resource is automatically released when [`OsFile`] goes out of scope
    pub(crate) fn new(path: &std::path::PathBuf, mode: IOFlushMode) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let file = ();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::File::new(path) }?;

        let core = Arc::new(FileCore {
            mode: mode.clone(),
            cv: sync::Condvar::new(),
            lock: sync::Mutex::new(()),
            version: atomic::AtomicU8::new(0),
            dirty: atomic::AtomicBool::new(false),
            closed: atomic::AtomicBool::new(false),
            file: cell::UnsafeCell::new(mem::ManuallyDrop::new(file)),
        });

        if mode == IOFlushMode::Background {
            Self::spawn_tx(core.clone());
        }

        Ok(Self { core })
    }

    /// Opens an existing [`OsFile`] at given `Path`
    ///
    /// ## RAII Safe
    ///
    /// The file handle (`fd` on `Linux`), is tied to the [`OsFile`] itself, hence the
    /// underlying resource is automatically released when [`OsFile`] goes out of scope    
    pub(crate) fn open(path: &std::path::PathBuf, mode: IOFlushMode) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let file = ();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::File::open(path) }?;

        let core = Arc::new(FileCore {
            mode: mode.clone(),
            cv: sync::Condvar::new(),
            lock: sync::Mutex::new(()),
            version: atomic::AtomicU8::new(0),
            dirty: atomic::AtomicBool::new(false),
            closed: atomic::AtomicBool::new(false),
            file: cell::UnsafeCell::new(mem::ManuallyDrop::new(file)),
        });

        if mode == IOFlushMode::Background {
            Self::spawn_tx(core.clone());
        }

        Ok(Self { core })
    }

    /// Fetches file handle for [`OsFile`] (**Linux Only**)
    #[cfg(target_os = "linux")]
    pub(crate) fn fd(&self) -> i32 {
        unsafe { mem::ManuallyDrop::take(&mut *self.core.file.get()).fd() }
    }

    /// Close + Delete [`OsFile`] at given [`Path`]
    pub(crate) fn delete(&self, path: &std::path::PathBuf) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            let file = self.get_file();
            match file.close() {
                Err(e) => Err(e),
                Ok(_) => file.unlink(path),
            }
        }
    }

    /// Syncs dirty pages of [`OsFile`] to disk
    pub(crate) fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            Self::sync_internal(&self.core)
        }
    }

    /// Truncates/extends length of [`OsFile`]
    ///
    /// **WARN:** If `len` is smaller then the current length of [`OsFile`] it'll be shrinked,
    /// which may result in data loss
    pub(crate) fn zero_extend(&self, new_len: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().ftruncate(new_len)
        }
    }

    /// Fetches current length of [`OsFile`]
    pub(crate) fn len(&self) -> GraveResult<usize> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().len()
        }
    }

    /// Gives an excluive (cross-process) access to the [`OsFile`]
    ///
    /// ## RAII Safe
    ///
    /// The file lock is tied to [`OsFileLockGuard`], when it's dropped,
    /// the resource is automatically be freed
    #[inline]
    pub(crate) fn lock(&self) -> GraveResult<OsFileLockGuard<'_>> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().lock()?;
            Ok(OsFileLockGuard(self))
        }
    }

    /// Performs a blocking read from [`OsFile`]
    #[inline(always)]
    pub(crate) fn read(&self, ptr: *mut u8, off: usize, len: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().pread(ptr, off, len)
        }
    }

    /// Performs **single page** blocking write to [`OsFile`]
    #[inline(always)]
    pub(crate) fn write(&self, ptr: *const u8, off: usize, page_size: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        let res = unsafe { self.get_file().pwrite(ptr, off, page_size) };

        if likely(res.is_ok() && self.core.mode == IOFlushMode::Background) {
            self.core.dirty.store(true, atomic::Ordering::Release);
            self.core.cv.notify_one();
        }

        res
    }

    /// Performs **multi page** blocking write to [`OsFile`]
    #[inline(always)]
    pub(crate) fn writev(&self, ptr: &[*const u8], off: usize, page_size: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        let res = unsafe { self.get_file().pwritev(ptr, off, page_size) };

        match self.core.mode {
            IOFlushMode::Background => {
                self.core.dirty.store(true, atomic::Ordering::Release);
                self.core.cv.notify_one();
            }
            _ => {}
        }

        res
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn get_file(&self) -> linux::File {
        unsafe { mem::ManuallyDrop::take(&mut *self.core.file.get()) }
    }

    fn unlock(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().unlock()
        }
    }

    fn close(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().close()
        }
    }

    #[inline]
    fn sync_internal(core: &FileCore) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            (&*core.file.get()).sync()
        }
    }

    fn spawn_tx(core: Arc<FileCore>) {
        std::thread::spawn(move || unsafe {
            let mut guard = match core.lock.lock() {
                Ok(ret) => ret,
                Err(err) => {
                    eprint!("ERROR: OsFile tx: {err}");
                    return;
                }
            };

            loop {
                if core.closed.load(atomic::Ordering::Acquire) {
                    break;
                }

                guard = match core.cv.wait_timeout(guard, std::time::Duration::from_secs(1)) {
                    Ok((g, _)) => g,
                    Err(e) => {
                        eprintln!("OsFile tx condvar poisoned: {e}");
                        return;
                    }
                };

                if core.dirty.swap(false, atomic::Ordering::AcqRel) {
                    // release lock before I/O
                    drop(guard);

                    unsafe {
                        let _ = (&*core.file.get()).sync();
                    }

                    // require for next loop
                    guard = match core.lock.lock() {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("OsFile tx mutex poisoned: {e}");
                            return;
                        }
                    };
                }
            }
        });
    }
}

impl Drop for OsFile {
    fn drop(&mut self) {
        self.core.closed.store(true, atomic::Ordering::Release);
        self.core.cv.notify_one();

        let _ = Self::sync_internal(&self.core);
        let _ = self.close();
    }
}

//
// RAII guard for Locks
//

pub(crate) struct OsFileLockGuard<'a>(&'a OsFile);

impl<'a> Drop for OsFileLockGuard<'a> {
    fn drop(&mut self) {
        // NOTE: We silently consume the error, as we can't panic in Drop ^_~
        let _ = self.0.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const PAGE_SIZE: usize = 0x20;

    #[test]
    fn new_file_creation() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = OsFile::new(&path, IOFlushMode::Manual).expect("create new file");
        assert_eq!(file.len().expect("read file len"), 0);

        assert!(file.close().is_ok(), "failed to close file");
        assert!(path.exists(), "file must exist on disk");
    }

    #[test]
    fn open_accepts_existing_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        {
            let file = OsFile::new(&path, IOFlushMode::Manual).expect("create new file");
            assert!(file.close().is_ok(), "failed to close file");
        }

        let file = OsFile::open(&path, IOFlushMode::Manual).expect("open existing file");
        assert_eq!(file.len().expect("read file len"), 0);

        assert!(file.close().is_ok(), "failed to close file");
    }

    #[test]
    fn open_fails_on_missing_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("missing_file");

        assert!(
            OsFile::open(&path, IOFlushMode::Manual).is_err(),
            "open must fail for missing file"
        );
    }

    #[test]
    fn zero_extend_correctly_extends_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = OsFile::new(&path, IOFlushMode::Manual).expect("create new file");
        assert!(file.zero_extend(PAGE_SIZE * 2).is_ok(), "zero_extend failed");
        assert!(file.sync().is_ok(), "fdatasync failed");

        assert_eq!(file.len().expect("read file len"), PAGE_SIZE * 2, "file len mismatch");

        let data = std::fs::read(&path).expect("read file");
        assert!(data.iter().all(|b| *b == 0), "file must be zero extended");
    }

    #[test]
    fn close_fails_after_close() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = OsFile::new(&path, IOFlushMode::Manual).expect("create new file");
        assert!(file.close().is_ok(), "failed to close file");
        assert!(file.close().is_err(), "close must fail after close");
    }

    #[test]
    fn delete_correctly_yanks_file() {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");

        unsafe {
            let file = OsFile::new(&tmp, IOFlushMode::Manual).expect("open existing file");

            // close + unlink
            assert!(file.delete(&tmp).is_ok(), "failed to unlink the file");

            // sanity check
            assert!(!tmp.exists(), "failed to delete file");
        }
    }

    mod write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            unsafe {
                let file = OsFile::new(&tmp, IOFlushMode::Manual).expect("open existing file");

                // write
                assert!(file.write(DATA.as_ptr(), 0, PAGE_SIZE).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, PAGE_SIZE, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; PAGE_SIZE];
                assert!(file.read(buf.as_mut_ptr(), 0, PAGE_SIZE).is_ok(), "pread failed");
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
                let file = OsFile::new(&tmp, IOFlushMode::Manual).expect("open existing file");

                assert!(file.write(DATA.as_ptr(), 0, PAGE_SIZE).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = OsFile::open(&tmp, IOFlushMode::Manual).expect("open existing file");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, PAGE_SIZE, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; PAGE_SIZE];
                assert!(file.read(buf.as_mut_ptr(), 0, PAGE_SIZE).is_ok(), "pread failed");
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }
    }

    mod writev_read {
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
                let file = OsFile::new(&tmp, IOFlushMode::Manual).expect("open existing file");

                // write
                assert!(file.writev(&ptrs, 0, PAGE_SIZE).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, total_len, "file len does not match expected len");

                let mut buf = vec![0u8; total_len];
                assert!(file.read(buf.as_mut_ptr(), 0, total_len).is_ok(), "pread failed");
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
                let file = OsFile::new(&tmp, IOFlushMode::Manual).expect("open existing file");

                assert!(file.writev(&ptrs, 0, PAGE_SIZE).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = OsFile::open(&tmp, IOFlushMode::Manual).expect("open existing file");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, total_len, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; total_len];
                assert!(file.read(buf.as_mut_ptr(), 0, total_len).is_ok(), "pread failed");
                assert_eq!(buf.len(), total_len, "mismatch between read and write");

                for chunk in buf.chunks_exact(PAGE_SIZE) {
                    assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
                }

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }
    }

    mod concurrent_write_read {
        use super::*;
        use std::sync::Arc;
        use std::thread;

        #[test]
        fn concurrent_writes_to_disjoint_offsets() {
            const PAGE_SIZE: usize = 0x20;
            const NTHREADS: usize = 8;

            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("tmp_file");
            let file = Arc::new(OsFile::new(&path, IOFlushMode::Manual).expect("create new file"));

            let mut handles = Vec::with_capacity(NTHREADS);
            for i in 0..NTHREADS {
                let file = Arc::clone(&file);
                handles.push(thread::spawn(move || {
                    let data = vec![i as u8; PAGE_SIZE];
                    let off = i * PAGE_SIZE;
                    assert!(
                        file.write(data.as_ptr(), off, PAGE_SIZE).is_ok(),
                        "concurrent write failed"
                    );
                }));
            }

            for h in handles {
                assert!(h.join().is_ok(), "thread panicked");
            }

            assert!(file.sync().is_ok(), "fdatasync failed");

            let len = file.len().expect("read file len");
            assert_eq!(len, NTHREADS * PAGE_SIZE, "file len mismatch");

            let mut buf = vec![0u8; len];
            assert!(
                file.read(buf.as_mut_ptr(), 0, NTHREADS * PAGE_SIZE).is_ok(),
                "read failed"
            );

            for (i, chunk) in buf.chunks_exact(PAGE_SIZE).enumerate() {
                assert!(
                    chunk.iter().all(|b| *b == i as u8),
                    "data corruption in concurrent write"
                );
            }

            assert!(file.close().is_ok(), "failed to close file");
        }

        #[test]
        fn concurrent_reads_after_write() {
            const PAGE_SIZE: usize = 0x20;
            const NTHREADS: usize = 4;

            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("tmp_file");
            let file = Arc::new(OsFile::new(&path, IOFlushMode::Manual).expect("create new file"));

            let data = vec![0xABu8; PAGE_SIZE];
            assert!(file.write(data.as_ptr(), 0, PAGE_SIZE).is_ok(), "initial write failed");
            assert!(file.sync().is_ok(), "fdatasync failed");

            let mut handles = Vec::with_capacity(NTHREADS);
            for _ in 0..NTHREADS {
                let file = Arc::clone(&file);
                handles.push(thread::spawn(move || {
                    let mut buf = vec![0u8; PAGE_SIZE];
                    assert!(
                        file.read(buf.as_mut_ptr(), 0, PAGE_SIZE).is_ok(),
                        "concurrent read failed"
                    );
                    assert_eq!(buf, vec![0xABu8; PAGE_SIZE], "read data mismatch");
                }));
            }

            for h in handles {
                assert!(h.join().is_ok(), "thread panicked");
            }

            assert!(file.close().is_ok(), "failed to close file");
        }

        #[test]
        fn concurrent_writev_and_reads() {
            const PAGE_SIZE: usize = 0x20;
            const NPAGES: usize = 4;

            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("tmp_file");
            let file = Arc::new(OsFile::new(&path, IOFlushMode::Manual).expect("create new file"));

            let pages: Vec<Vec<u8>> = (0..NPAGES).map(|i| vec![i as u8; PAGE_SIZE]).collect();
            let ptrs: Vec<*const u8> = pages.iter().map(|p| p.as_ptr()).collect();

            assert!(file.writev(&ptrs, 0, PAGE_SIZE).is_ok(), "writev failed");
            assert!(file.sync().is_ok(), "fdatasync failed");

            let mut handles = Vec::with_capacity(NPAGES);
            for i in 0..NPAGES {
                let file = Arc::clone(&file);
                handles.push(thread::spawn(move || {
                    let mut buf = vec![0u8; PAGE_SIZE];
                    let off = i * PAGE_SIZE;

                    assert!(file.read(buf.as_mut_ptr(), off, PAGE_SIZE).is_ok(), "read failed");
                    assert!(buf.iter().all(|b| *b == i as u8), "data mismatch in concurrent read");
                }));
            }

            for h in handles {
                assert!(h.join().is_ok(), "thread panicked");
            }

            assert!(file.close().is_ok(), "failed to close file");
        }
    }

    mod lock_unlock {
        use super::*;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        #[test]
        fn lock_unlock_cycle() {
            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("lock_file");

            let file = OsFile::new(&path, IOFlushMode::Manual).expect("create file");

            assert!(file.lock().is_ok());
            assert!(file.unlock().is_ok());

            assert!(file.lock().is_ok());
            assert!(file.unlock().is_ok());

            assert!(file.close().is_ok());
        }

        #[test]
        fn lock_is_exclusive_across_handles() {
            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("lock_file");

            static ENTERED: AtomicBool = AtomicBool::new(false);

            let f1 = OsFile::new(&path, IOFlushMode::Manual).expect("create file");
            let f2 = OsFile::open(&path, IOFlushMode::Manual).expect("open file");

            assert!(f1.lock().is_ok());

            let t = std::thread::spawn(move || {
                ENTERED.store(true, Ordering::SeqCst);
                assert!(f2.lock().is_ok());
                assert!(f2.unlock().is_ok());
            });

            while !ENTERED.load(Ordering::SeqCst) {}

            // if lock is broken, thread would have passed already
            std::thread::sleep(std::time::Duration::from_millis(50));

            assert!(f1.unlock().is_ok());
            assert!(t.join().is_ok());

            assert!(f1.close().is_ok());
        }

        #[test]
        fn lock_survives_io() {
            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("lock_file");

            let file = OsFile::new(&path, IOFlushMode::Manual).expect("create file");

            assert!(file.lock().is_ok());

            let data = [0xAAu8; 16];
            assert!(file.write(data.as_ptr(), 0, 16).is_ok());

            assert!(file.unlock().is_ok());
            assert!(file.close().is_ok());
        }
    }
}
