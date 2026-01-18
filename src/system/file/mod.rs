#[cfg(target_os = "linux")]
mod linux;

use super::{IOFlushMode, FLUSH_DURATION};
use crate::{error::ErrorCode, GraveError, GraveResult};
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
    pub(crate) fn new(path: std::path::PathBuf, mode: IOFlushMode) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::LinuxFile::new(path) }?;

        let core = InternalFile::new(file, mode.clone());
        if mode == IOFlushMode::Background {
            InternalFile::spawn_tx(core.clone())?;
        }

        Ok(Self { core })
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
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().extend(len_to_add)
        }
    }

    #[inline]
    pub(crate) fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().sync()
        }
    }

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

    #[inline]
    pub(crate) fn delete(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            let file = self.get_file();
            match file.close() {
                Ok(_) => file.unlink(),
                Err(e) => Err(e),
            }
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

    fn unlock(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_file().unlock()
        }
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn get_file(&self) -> &ManuallyDrop<linux::LinuxFile> {
        unsafe { (&*self.core.file.get()) }
    }
}

impl Drop for OsFile {
    fn drop(&mut self) {
        // close flusher thread
        if self.core.mode == IOFlushMode::Background {
            self.core.closed.store(true, atomic::Ordering::Release);
            self.core.cv.notify_one();
        }

        // sync if dirty
        if self.core.dirty.load(atomic::Ordering::Acquire) {
            let _ = self.sync();
        }

        let _ = self.close();
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
            if core.closed.load(atomic::Ordering::Acquire) {
                return;
            }

            guard = match core.cv.wait_timeout(guard, FLUSH_DURATION) {
                Ok((g, _)) => g,
                Err(_) => {
                    core.errored.store(true, atomic::Ordering::Release);
                    return;
                }
            };

            if core.dirty.swap(false, atomic::Ordering::AcqRel) {
                drop(guard);

                if unsafe { (&*core.file.get()).sync() }.is_err() {
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
