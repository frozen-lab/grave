#[cfg(target_os = "linux")]
mod linux;

use super::{IOFlushMode, FLUSH_DURATION};
use crate::{
    error::ErrorCode,
    hints::{likely, unlikely},
    GraveError, GraveResult,
};
use std::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    sync::{atomic, mpsc, Arc, Condvar, Mutex, MutexGuard},
};

#[cfg(target_os = "linux")]
type TFile = linux::LinuxFile;

#[cfg(not(target_os = "linux"))]
type TFile = ();

#[derive(Debug)]
pub(crate) struct OsFile {
    core: Arc<InternalFile>,
}

unsafe impl Send for OsFile {}
unsafe impl Sync for OsFile {}

impl OsFile {
    pub(crate) fn new(path: std::path::PathBuf, mode: IOFlushMode, init_len: u64) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::LinuxFile::new(path) }?;
        let core = InternalFile::new(file, mode.clone());
        let slf = Self { core: core.clone() };

        // init_len
        slf.extend(init_len).map_err(|e| {
            // clear up so the new_init could work well
            slf.delete();
            e
        })?;

        if mode == IOFlushMode::Background {
            InternalFile::spawn_tx(core)?;
        }

        Ok(slf)
    }

    pub(crate) fn open(path: std::path::PathBuf, mode: IOFlushMode) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::LinuxFile::open(path) }?;

        let core = InternalFile::new(file, mode.clone());
        if mode == IOFlushMode::Background {
            InternalFile::spawn_tx(core.clone())?;
        }

        Ok(Self { core })
    }

    #[inline]
    pub(crate) fn len(&self) -> u64 {
        self.get_file().len()
    }

    #[cfg(target_os = "linux")]
    #[inline]
    pub(crate) fn fd(&self) -> i32 {
        self.get_file().fd()
    }

    #[inline]
    pub(crate) fn extend(&self, len_to_add: u64) -> GraveResult<()> {
        // sanity check
        self.sanity_check()?;

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe { self.get_file().extend(len_to_add) }?;

        self.core.dirty.store(true, atomic::Ordering::Release);
        Ok(())
    }

    #[inline]
    pub(crate) fn sync(&self) -> GraveResult<()> {
        // sanity check
        self.sanity_check()?;

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().sync()
        }
    }

    #[inline]
    pub(crate) fn lock(&self) -> GraveResult<OsFileLockGuard<'_>> {
        // sanity check
        self.sanity_check()?;

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe { self.get_file().lock() }?;

        Ok(OsFileLockGuard(self))
    }

    #[inline]
    pub(crate) fn delete(&self) -> GraveResult<()> {
        let file = self.get_file();

        // NOTE: sanity check is invalid here, cause we are deleting the file, hence we don't
        // actually care if the state is sane or not ;)

        // mark file as close
        self.core.closed.store(true, atomic::Ordering::Release);

        // close flusher thread
        if self.core.mode == IOFlushMode::Background {
            self.core.cv.notify_one();
        }

        // NOTE: we must wait for sync thread to exit to avoid use of operations using
        // invalid fd (which is after close, i.e. fd = -1)
        if let Err(e) = self.core.lock.lock() {
            return GraveError::poison_err::<std::sync::MutexGuard<'_, _>, ()>(ErrorCode::MTMpn, e);
        }

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            match file.close() {
                Ok(_) => file.unlink(),
                Err(e) => Err(e),
            }
        }
    }

    #[inline]
    pub(crate) fn read(&self, buf_ptr: *mut u8, offset: usize, len_to_read: usize) -> GraveResult<()> {
        // sanity check
        self.sanity_check()?;

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().pread(buf_ptr, offset, len_to_read)
        }
    }

    #[inline]
    pub(crate) fn write_single(&self, buf_ptr: *const u8, offset: usize, len_to_write: usize) -> GraveResult<()> {
        // sanity check
        self.sanity_check()?;

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe { self.get_file().pwrite(buf_ptr, offset, len_to_write) }?;

        self.core.dirty.store(true, atomic::Ordering::Release);
        Ok(())
    }

    #[inline]
    pub(crate) fn write_multi(&self, buf_ptrs: &[*const u8], offset: usize, buffer_size: usize) -> GraveResult<()> {
        // sanity check
        self.sanity_check()?;

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe { self.get_file().pwritev(buf_ptrs, offset, buffer_size) }?;

        self.core.dirty.store(true, atomic::Ordering::Release);
        Ok(())
    }

    /// Close the [`OsFile`]
    ///
    /// **For internal use only**
    ///
    /// ## Usage
    ///
    /// We only use close in following scenerios:
    ///
    /// - When deleting the file
    /// - When dropping the file
    fn _close(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().close()
        }
    }

    fn unlock(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().unlock()
        }
    }

    #[inline(always)]
    fn sanity_check(&self) -> GraveResult<()> {
        if likely(!self.core.errored.load(atomic::Ordering::Acquire)) {
            return Ok(());
        }

        let raw = self.core.err_code.load(atomic::Ordering::Acquire);
        let code = ErrorCode::from_u16(raw);

        Err(GraveError::new(code, "OsFile is in errored state".into()))
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn get_file(&self) -> &ManuallyDrop<linux::LinuxFile> {
        unsafe { (&*self.core.file.get()) }
    }
}

impl Drop for OsFile {
    fn drop(&mut self) {
        if self.core.closed.swap(true, atomic::Ordering::AcqRel) {
            return;
        }

        // close flusher thread
        if self.core.mode == IOFlushMode::Background {
            self.core.cv.notify_one();
        }

        // sync if dirty
        if self.core.dirty.swap(false, atomic::Ordering::AcqRel) {
            let _ = self.sync();
        }

        let _ = self._close();
    }
}

impl std::fmt::Display for OsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(
            f,
            "OsFile {{fd: {}, len: {}, mode: {}, closed: {}, version: {}}}",
            self.fd(),
            self.len(),
            self.core.mode,
            self.core.closed.load(atomic::Ordering::Acquire),
            self.core.version.load(atomic::Ordering::Acquire),
        )
    }
}

//
// Internal Structure
//

#[derive(Debug)]
struct InternalFile {
    cv: Condvar,
    lock: Mutex<()>,
    mode: IOFlushMode,
    version: atomic::AtomicU8,
    dirty: atomic::AtomicBool,
    closed: atomic::AtomicBool,
    errored: atomic::AtomicBool,
    err_code: atomic::AtomicU16,
    file: UnsafeCell<ManuallyDrop<TFile>>,
}

impl InternalFile {
    #[cfg(target_os = "linux")]
    fn new(file: TFile, mode: IOFlushMode) -> Arc<Self> {
        let core = InternalFile {
            mode: mode.clone(),
            cv: Condvar::new(),
            lock: Mutex::new(()),
            version: atomic::AtomicU8::new(0),
            err_code: atomic::AtomicU16::new(0),
            dirty: atomic::AtomicBool::new(false),
            closed: atomic::AtomicBool::new(false),
            errored: atomic::AtomicBool::new(false),
            file: UnsafeCell::new(ManuallyDrop::new(file)),
        };

        Arc::new(core)
    }

    fn spawn_tx(core: Arc<Self>) -> GraveResult<()> {
        let (tx, rx) = mpsc::sync_channel::<GraveResult<()>>(1);

        std::thread::Builder::new()
            .name("grave-osfile-tx".into())
            .spawn(move || Self::tx_thread(core, tx))
            .map_err(|_| GraveError::new(ErrorCode::MTMpn, "grave tx thread spawn failed for OsFile".into()))?;

        rx.recv().map_err(|_| {
            GraveError::new(
                ErrorCode::MTUnk,
                "grave tx thread died before init could be completed for OsFile".into(),
            )
        })?;

        Ok(())
    }

    fn tx_thread(core: Arc<Self>, init: mpsc::SyncSender<GraveResult<()>>) {
        // init phase (acquiring locks)
        let mut guard = match core.lock.lock() {
            Ok(g) => {
                // NOTE: We can supress the error here, as this may never panic, unless the receiver
                // is shut, which is preveneted by design
                let _ = init.send(Ok(()));
                g
            }
            Err(_) => {
                let _ = init.send(Err(GraveError::new(
                    ErrorCode::MTMpn,
                    "tx mutex poisoned during init".into(),
                )));
                return;
            }
        };

        // init done, now is detached from thread
        drop(init);

        // sync loop w/ non-busy waiting
        loop {
            guard = match core.cv.wait_timeout(guard, FLUSH_DURATION) {
                Ok((g, _)) => g,
                Err(_) => {
                    core.err_code.store(ErrorCode::MTTpn as u16, atomic::Ordering::Release);
                    core.errored.store(true, atomic::Ordering::Release);
                    return;
                }
            };

            if core.closed.load(atomic::Ordering::Acquire) {
                return;
            }

            if core.dirty.swap(false, atomic::Ordering::AcqRel) {
                drop(guard);

                if unsafe { (&*core.file.get()).sync() }.is_err() {
                    core.err_code.store(ErrorCode::IOSyn as u16, atomic::Ordering::Release);
                    core.errored.store(true, atomic::Ordering::Release);
                    return;
                }

                guard = match core.lock.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        core.errored.store(true, atomic::Ordering::Release);
                        return;
                    }
                };
            }
        }
    }
}

unsafe impl Send for InternalFile {}
unsafe impl Sync for InternalFile {}

//
// RAII safe lock guard
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
    use std::path::PathBuf;
    use tempfile::{tempdir, TempDir};

    const LEN: usize = 0x20;
    const MODE: IOFlushMode = IOFlushMode::Background;

    fn new_tmp() -> (TempDir, PathBuf, OsFile) {
        let dir = tempdir().expect("temp dir");
        let tmp = dir.path().join("tmp_file");
        let file = OsFile::new(tmp.clone(), MODE, LEN as u64).expect("new OsFile");

        (dir, tmp, file)
    }

    mod new_open {
        use super::*;

        #[test]
        fn new_works() {
            let (_dir, tmp, file) = new_tmp();
            assert!(file.fd() >= 0);
            assert_eq!(file.len(), LEN as u64);
            assert!(!file.core.closed.load(atomic::Ordering::Acquire));
            assert!(!file.core.errored.load(atomic::Ordering::Acquire));

            // sanity check
            assert!(tmp.exists());
        }

        #[test]
        fn open_works() {
            let (_dir, tmp, file) = new_tmp();

            assert!(file.fd() >= 0);
            assert_eq!(file.len(), LEN as u64);
            assert!(!file.core.closed.load(atomic::Ordering::Acquire));
            assert!(!file.core.errored.load(atomic::Ordering::Acquire));
            drop(file);

            match OsFile::open(tmp, MODE) {
                Ok(file) => {
                    assert!(file.fd() >= 0);
                    assert_eq!(file.len(), LEN as u64);
                    assert!(!file.core.closed.load(atomic::Ordering::Acquire));
                    assert!(!file.core.errored.load(atomic::Ordering::Acquire));
                }
                Err(e) => panic!("failed to open file due to E: {e}"),
            }
        }

        #[test]
        fn open_fails_when_file_is_deleted() {
            let (_dir, tmp, file) = new_tmp();

            assert!(file.fd() >= 0);
            assert_eq!(file.len(), LEN as u64);
            assert!(file.delete().is_ok());

            let file = OsFile::open(tmp, MODE);
            assert!(file.is_err());
        }
    }

    mod delete {
        use super::*;

        #[test]
        fn delete_works() {
            let (_dir, tmp, file) = new_tmp();

            assert!(file.delete().is_ok());

            // sanity checks
            assert!(!tmp.exists());
            assert!(file.core.closed.load(atomic::Ordering::Acquire));
        }

        #[test]
        fn delete_fails_on_deleted_file() {
            let (_dir, tmp, file) = new_tmp();

            assert!(file.delete().is_ok());

            // sanity checks
            assert!(file.core.closed.load(atomic::Ordering::Acquire));
            assert!(!tmp.exists());

            // should fail on missing
            assert!(file.delete().is_err());
        }
    }

    mod extend {
        use super::*;

        #[test]
        fn extend_zero_extends_file() {
            const NEW_LEN: u64 = 0x80;
            let (_dir, tmp, file) = new_tmp();

            assert!(file.extend(NEW_LEN).is_ok());
            assert_eq!(file.len(), NEW_LEN + LEN as u64);

            // strict sanity check to ensure file is zero byte extended
            let file_contents = std::fs::read(&tmp).expect("read from file");
            assert_eq!(file_contents.len(), NEW_LEN as usize + LEN, "len mismatch for file");
            assert!(
                file_contents.iter().all(|b| *b == 0u8),
                "file must be zero byte extended"
            );
        }

        #[test]
        fn open_preserves_existing_length() {
            const NEW_LEN: u64 = 0x80;
            let (_dir, tmp, file) = new_tmp();

            assert!(file.extend(NEW_LEN).is_ok());
            assert_eq!(file.len(), NEW_LEN + LEN as u64);

            // allow sync thread to run and persist
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(file);

            match OsFile::open(tmp, MODE) {
                Err(e) => panic!("{e}"),
                Ok(file) => {
                    assert_eq!(file.len(), NEW_LEN + LEN as u64);
                }
            }
        }
    }

    mod lock_unlock {
        use super::*;

        #[test]
        fn lock_unlock_cycle() {
            let (_dir, tmp, file) = new_tmp();

            let l1 = file.lock().expect("obtain file lock");
            drop(l1);

            let l2 = file.lock().expect("obtain file lock");
            drop(l2);
        }

        #[test]
        fn io_op_with_lock_on() {
            let (_dir, tmp, file) = new_tmp();

            let _l1 = file.lock().expect("obtain file lock");
            let data = vec![1u8; 0x20];

            file.extend(data.len() as u64).expect("resize file");
            file.write_single(data.as_ptr(), 0, data.len()).expect("write to file");
        }
    }

    mod write_read {
        use super::*;

        #[test]
        fn single_write_read_cycle() {
            const DATA: [u8; LEN] = [0x1A; LEN];

            let (_dir, tmp, file) = new_tmp();
            let mut buf = vec![0u8; LEN];

            assert!(file.write_single(DATA.as_ptr(), 0, LEN).is_ok());

            assert!(file.read(buf.as_mut_ptr(), 0, LEN).is_ok());
            assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");
        }

        #[test]
        fn multi_write_read_cycle() {
            const DATA: [u8; LEN] = [0x1A; LEN];
            let (_dir, tmp, file) = new_tmp();

            let ptrs = vec![DATA.as_ptr(); 0x10];
            let total_len = ptrs.len() * LEN;
            let mut buf = vec![0u8; total_len];

            file.extend(total_len as u64).expect("resize file");
            assert!(file.write_multi(&ptrs, 0, LEN).is_ok());

            assert!(file.read(buf.as_mut_ptr(), 0, total_len).is_ok(), "read failed");
            assert_eq!(buf.len(), total_len, "mismatch between read and write");

            for chunk in buf.chunks_exact(LEN) {
                assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
            }
        }

        #[test]
        fn single_write_read_cycle_across_sessions() {
            const DATA: [u8; LEN] = [0x1A; LEN];
            let (_dir, tmp, file) = new_tmp();

            // create + write + sync + close
            {
                file.extend(LEN as u64).expect("resize file");
                assert!(file.write_single(DATA.as_ptr(), 0, LEN).is_ok());

                // allow sync thread to run and persist
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            // open + read + verify
            {
                let mut buf = vec![0u8; LEN];
                let file = OsFile::open(tmp, MODE).expect("open file");

                assert!(file.read(buf.as_mut_ptr(), 0, LEN).is_ok());
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");
            }
        }
    }

    mod concurrency {
        use super::*;

        #[test]
        fn concurrent_writes_then_read() {
            const THREADS: usize = 8;
            const CHUNK: usize = 0x100;

            let (_dir, _tmp, file) = new_tmp();
            let file = Arc::new(file);

            // required len
            file.extend((THREADS * CHUNK) as u64).expect("extend");

            let mut handles = Vec::new();
            for i in 0..THREADS {
                let f = file.clone();
                handles.push(std::thread::spawn(move || {
                    let data = vec![i as u8; CHUNK];
                    f.write_single(data.as_ptr(), i * CHUNK, CHUNK).expect("write");
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }

            //
            // read back (sanity check)
            //

            let mut read_buf = vec![0u8; THREADS * CHUNK];
            assert!(file.read(read_buf.as_mut_ptr(), 0, read_buf.len()).is_ok());

            for i in 0..THREADS {
                let chunk = &read_buf[i * CHUNK..(i + 1) * CHUNK];
                assert!(chunk.iter().all(|b| *b == i as u8));
            }
        }

        #[test]
        fn concurrent_writes_with_lock() {
            const THREADS: usize = 4;
            const LEN: usize = 0x80;

            let (_dir, _tmp, file) = new_tmp();
            let file = Arc::new(file);

            file.extend(LEN as u64).expect("extend");

            let mut handles = Vec::new();
            for _ in 0..THREADS {
                let f = file.clone();
                handles.push(std::thread::spawn(move || {
                    let _guard = f.lock().expect("lock");
                    let data = vec![0xAB; LEN];
                    assert!(f.write_single(data.as_ptr(), 0, LEN).is_ok());
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }
        }
    }

    mod sync_tx {
        use super::*;

        #[test]
        fn background_sync_persists_data() {
            let (_dir, tmp, file) = new_tmp();
            let data = vec![0xCD; LEN];

            file.extend(LEN as u64).expect("extend");
            file.write_single(data.as_ptr(), 0, LEN).expect("write");

            // allow background flusher to run
            std::thread::sleep(FLUSH_DURATION + FLUSH_DURATION);
            drop(file);

            // reopen and verify persistence
            let mut buf = vec![0u8; LEN];
            let file = OsFile::open(tmp, MODE).expect("reopen");

            assert!(file.read(buf.as_mut_ptr(), 0, LEN).is_ok());
            assert_eq!(buf, data);
        }
    }
}
