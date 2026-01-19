#[cfg(target_os = "linux")]
mod linux;

use super::{file::OsFile, IOFlushMode, FLUSH_DURATION};
use crate::{error::ErrorCode, hints::likely, GraveError, GraveResult};
use std::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    sync::{atomic, mpsc, Arc, Condvar, Mutex},
};

#[cfg(target_os = "linux")]
type TMap = linux::LinuxMMap;

#[cfg(not(target_os = "linux"))]
type TMap = ();

#[derive(Debug)]
pub(crate) struct OsMMap {
    core: Arc<InternalMap>,
}

unsafe impl Send for OsMMap {}
unsafe impl Sync for OsMMap {}

impl OsMMap {
    pub(crate) fn new(file: &OsFile, len: usize, mode: IOFlushMode) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        let mmap = unsafe { linux::LinuxMMap::new(file.fd(), len) }?;

        let core = InternalMap::new(mmap, mode.clone());
        if mode == IOFlushMode::Background {
            InternalMap::spawn_tx(core.clone())?;
        }

        Ok(Self { core })
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        self.get_mmap().len()
    }

    #[inline]
    pub(crate) fn sync(&self) -> GraveResult<()> {
        // sanity check
        self.sanity_check()?;
        self.core.sync()
    }

    #[inline]
    pub(crate) fn reader<'a, T>(&'a self, offset: usize) -> GraveResult<MemMapReader<'a, T>> {
        self.core.acquire_instance()?;
        let reader = MemMapReader {
            ptr: unsafe { self.get_mmap().get(offset) },
            _guard: ActiveGuard { core: &self.core },
        };

        Ok(reader)
    }

    #[inline]
    pub(crate) fn writer<'a, T>(&'a self, offset: usize) -> GraveResult<MemMapWriter<'a, T>> {
        self.core.acquire_instance()?;
        let writer = MemMapWriter {
            map: self,
            ptr: unsafe { self.get_mmap().get_mut(offset) },
            _guard: ActiveGuard { core: &self.core },
        };

        Ok(writer)
    }

    /// Unmap the [`OsMMap`]
    ///
    /// **We only use unmap when [`OsMMap`] is dropped**
    ///
    /// For internal use only
    fn munmap(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.get_mmap().munmap()?;
        }

        Ok(())
    }

    #[inline]
    fn get_mmap(&self) -> &ManuallyDrop<TMap> {
        unsafe { &*self.core.mmap.get() }
    }

    #[inline(always)]
    fn sanity_check(&self) -> GraveResult<()> {
        if likely(!self.core.errored.load(atomic::Ordering::Acquire)) {
            return Ok(());
        }

        let raw = self.core.err_code.load(atomic::Ordering::Acquire);
        let code = ErrorCode::from_u16(raw);

        Err(GraveError::new(code, "OsMMap is in errored state".into()))
    }
}

impl Drop for OsMMap {
    fn drop(&mut self) {
        if self.core.dropped.swap(true, atomic::Ordering::AcqRel) {
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

        let mut guard = match self.core.lock.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        while self.core.active.load(atomic::Ordering::Acquire) != 0 {
            guard = self.core.shutdown_cv.wait(guard).expect("shutdown cv poisoned");
        }

        let _ = self.munmap();
    }
}

impl std::fmt::Display for OsMMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(
            f,
            "OsMMap {{len: {}, mode: {}, closed: {}}}",
            self.len(),
            self.core.mode,
            self.core.dropped.load(atomic::Ordering::Acquire),
        )
    }
}

//
// read & write guard
//

#[derive(Debug)]
struct ActiveGuard<'a> {
    core: &'a InternalMap,
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        if self.core.active.fetch_sub(1, atomic::Ordering::Release) == 1 {
            // last user
            if let Ok(_g) = self.core.lock.lock() {
                self.core.shutdown_cv.notify_one();
            }
        }
    }
}

//
// Reader
//

#[derive(Debug)]
pub(crate) struct MemMapReader<'a, T> {
    ptr: *const T,
    _guard: ActiveGuard<'a>,
}

impl<'a, T> MemMapReader<'a, T> {
    #[inline]
    pub(crate) fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        unsafe { f(&*self.ptr) }
    }
}

//
// Writer
//

#[derive(Debug)]
pub(crate) struct MemMapWriter<'a, T> {
    ptr: *mut T,
    map: &'a OsMMap,
    _guard: ActiveGuard<'a>,
}

impl<'a, T> MemMapWriter<'a, T> {
    #[inline]
    pub(crate) fn write<R>(&self, f: impl FnOnce(&mut T) -> R) -> GraveResult<R> {
        let res = unsafe { f(&mut *self.ptr) };
        match self.map.core.mode {
            IOFlushMode::Manual => {
                self.map.sync()?;
            }
            IOFlushMode::Background => {
                self.map.core.dirty.store(true, atomic::Ordering::Release);
                self.map.core.cv.notify_one();
            }
        }

        Ok(res)
    }
}

//
// Internal Structure
//

#[derive(Debug)]
struct InternalMap {
    cv: Condvar,
    lock: Mutex<()>,
    mode: IOFlushMode,
    shutdown_cv: Condvar,
    dirty: atomic::AtomicBool,
    active: atomic::AtomicUsize,
    dropped: atomic::AtomicBool,
    errored: atomic::AtomicBool,
    err_code: atomic::AtomicU16,
    mmap: UnsafeCell<ManuallyDrop<TMap>>,
}

unsafe impl Send for InternalMap {}
unsafe impl Sync for InternalMap {}

impl InternalMap {
    #[cfg(target_os = "linux")]
    fn new(file: TMap, mode: IOFlushMode) -> Arc<Self> {
        let core = Self {
            mode: mode.clone(),
            cv: Condvar::new(),
            lock: Mutex::new(()),
            shutdown_cv: Condvar::new(),
            active: atomic::AtomicUsize::new(0),
            err_code: atomic::AtomicU16::new(0),
            dirty: atomic::AtomicBool::new(false),
            dropped: atomic::AtomicBool::new(false),
            errored: atomic::AtomicBool::new(false),
            mmap: UnsafeCell::new(ManuallyDrop::new(file)),
        };

        Arc::new(core)
    }

    #[inline]
    fn acquire_instance(&self) -> GraveResult<()> {
        let mut cur = self.active.load(atomic::Ordering::Acquire);

        loop {
            if self.dropped.load(atomic::Ordering::Acquire) {
                return Err(GraveError::new(
                    ErrorCode::MMHcf,
                    "trying to access OsMMap after dropped".into(),
                ));
            }

            match self
                .active
                .compare_exchange_weak(cur, cur + 1, atomic::Ordering::AcqRel, atomic::Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(v) => cur = v,
            }
        }
    }

    #[inline]
    fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            (&*self.mmap.get()).msync()
        }
    }

    fn spawn_tx(core: Arc<Self>) -> GraveResult<()> {
        let (tx, rx) = mpsc::sync_channel::<GraveResult<()>>(1);

        std::thread::Builder::new()
            .name("grave-osmmap-tx".into())
            .spawn(move || Self::tx_thread(core, tx))
            .map_err(|_| GraveError::new(ErrorCode::MTMpn, "grave tx thread spawn failed for OsMMap".into()))?;

        let _ = rx.recv().map_err(|_| {
            GraveError::new(
                ErrorCode::MTUnk,
                "grave tx thread died before init could be completed for OsMMap".into(),
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

            if core.dropped.load(atomic::Ordering::Acquire) {
                return;
            }

            if core.dirty.swap(false, atomic::Ordering::AcqRel) {
                drop(guard);

                if core.sync().is_err() {
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
