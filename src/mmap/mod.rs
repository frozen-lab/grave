use crate::{common::IOFlushMode, errors::GraveResult, file::OsFile};
use std::{
    cell, mem,
    sync::{self, atomic, Arc},
};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug)]
struct MapCore {
    mode: IOFlushMode,
    cv: sync::Condvar,
    lock: sync::Mutex<()>,
    version: atomic::AtomicU8,
    dirty: atomic::AtomicBool,
    dropped: atomic::AtomicBool,

    #[cfg(target_os = "linux")]
    mmap: cell::UnsafeCell<mem::ManuallyDrop<linux::MMap>>,

    #[cfg(not(target_os = "linux"))]
    mmap: (),
}

unsafe impl Sync for MapCore {}
unsafe impl Send for MapCore {}

#[derive(Debug)]
pub(crate) struct MemMap {
    core: Arc<MapCore>,
}

unsafe impl Send for MemMap {}
unsafe impl Sync for MemMap {}

impl std::fmt::Display for MemMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(
            f,
            "GraveMMap {{len: {}, version: {}, dropped: {}, mode: {:?}}}",
            unsafe { mem::ManuallyDrop::take(&mut *self.core.mmap.get()).len() },
            self.core.version.load(atomic::Ordering::Acquire),
            self.core.dropped.load(atomic::Ordering::Acquire),
            self.core.mode,
        )
    }
}

impl MemMap {
    /// Create a memory mapping as [`MemMap`] for the given [`OsFile`]
    pub(crate) fn map(file: &OsFile, len: usize, mode: IOFlushMode) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let mmap = ();

        #[cfg(target_os = "linux")]
        let mmap = unsafe { linux::MMap::map(file.fd(), len) }?;

        let core = Arc::new(MapCore {
            mode: mode.clone(),
            cv: sync::Condvar::new(),
            lock: sync::Mutex::new(()),
            version: atomic::AtomicU8::new(0),
            dirty: atomic::AtomicBool::new(false),
            dropped: atomic::AtomicBool::new(false),
            mmap: cell::UnsafeCell::new(mem::ManuallyDrop::new(mmap)),
        });

        if mode == IOFlushMode::Background {
            Self::spawn_tx(core.clone());
        }

        Ok(Self { core })
    }

    /// Unmap the mapped memory for [`MemMap`]
    ///
    /// ## Safety
    ///
    /// `unmap` is idempotent, hence calling it multiple times would not result into
    /// any errors or UB
    pub(crate) fn unmap(&mut self) -> GraveResult<()> {
        // sanity protection to avoid unmap after unmap
        if self.core.dropped.load(atomic::Ordering::Acquire) {
            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            mem::ManuallyDrop::take(&mut *self.core.mmap.get()).unmap()?;
        }

        self.core.version.fetch_add(1, atomic::Ordering::Release);
        self.core.dropped.store(true, atomic::Ordering::Release);
        Ok(())
    }

    /// Fetches current length of [`MemMap`]
    #[inline]
    pub(crate) fn len(&self) -> usize {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            mem::ManuallyDrop::take(&mut *self.core.mmap.get()).len()
        }
    }

    /// Syncs dirty pages of [`MemMap`] to disk
    #[inline]
    pub(crate) fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            (&*self.core.mmap.get()).sync()
        }
    }

    #[inline]
    pub(crate) fn reader<'a, T>(&'a self, off: usize) -> MemMapReader<'a, T> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            let ptr = mem::ManuallyDrop::take(&mut *self.core.mmap.get()).get::<T>(off);
            MemMapReader {
                ptr,
                map: self,
                version: self.core.version.load(atomic::Ordering::Acquire),
            }
        }
    }

    #[inline]
    pub(crate) fn writer<'a, T>(&'a self, off: usize) -> MemMapWriter<'a, T> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            let ptr = mem::ManuallyDrop::take(&mut *self.core.mmap.get()).get_mut::<T>(off);
            MemMapWriter {
                ptr,
                map: self,
                version: self.core.version.load(atomic::Ordering::Acquire),
            }
        }
    }

    #[inline]
    fn sync_internal(core: &MapCore) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            (&*core.mmap.get()).sync()
        }
    }

    fn spawn_tx(core: Arc<MapCore>) {
        std::thread::spawn(move || unsafe {
            let mut guard = core.lock.lock().expect("mutex poisoned");

            while !core.dropped.load(atomic::Ordering::Acquire) {
                let (g, _) = core
                    .cv
                    .wait_timeout(guard, std::time::Duration::from_secs(1))
                    .expect("condvar poisoned");
                guard = g;
            }

            if core.dirty.swap(false, atomic::Ordering::AcqRel) {
                drop(guard);
                unsafe {
                    let _ = (&*core.mmap.get()).sync();
                }
                guard = core.lock.lock().expect("mutex poisoned");
            }
        });
    }
}

impl Drop for MemMap {
    fn drop(&mut self) {
        self.core.dropped.store(true, atomic::Ordering::Release);
        self.core.cv.notify_one();

        unsafe {
            let _ = Self::sync_internal(&self.core);
            let _ = mem::ManuallyDrop::take(&mut *self.core.mmap.get()).unmap();
        }
    }
}

//
// Reader
//

#[derive(Debug)]
pub(crate) struct MemMapReader<'a, T> {
    version: u8,
    ptr: *const T,
    map: &'a MemMap,
}

impl<'a, T> MemMapReader<'a, T> {
    #[inline]
    pub(crate) fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        // sanity check (to avoid use of pointers after unmap is done)
        debug_assert!(!self.map.core.dropped.load(atomic::Ordering::Acquire));
        debug_assert_eq!(
            self.version,
            self.map.core.version.load(atomic::Ordering::Acquire),
            "detected use of pointer to unmapped memmap"
        );

        unsafe { f(&*self.ptr) }
    }
}

//
// Writer
//

#[derive(Debug)]
pub(crate) struct MemMapWriter<'a, T> {
    version: u8,
    ptr: *mut T,
    map: &'a MemMap,
}

impl<'a, T> MemMapWriter<'a, T> {
    #[inline]
    pub(crate) fn write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // sanity check (to avoid use of pointers after unmap is done)
        debug_assert!(!self.map.core.dropped.load(atomic::Ordering::Acquire));
        debug_assert_eq!(
            self.version,
            self.map.core.version.load(atomic::Ordering::Acquire),
            "detected use of pointer to unmapped memmap"
        );

        let res = unsafe { f(&mut *self.ptr) };
        match self.map.core.mode {
            IOFlushMode::Immediate => {
                let _ = self.map.sync();
            }
            IOFlushMode::Background => {
                self.map.core.dirty.store(true, atomic::Ordering::Release);
                self.map.core.cv.notify_one();
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use tempfile::tempdir;

    const PAGE_SIZE: usize = 0x20;
    const MODE: IOFlushMode = IOFlushMode::Immediate;

    fn tmp_file(len: usize) -> OsFile {
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("tmp_memmap");

        let file = OsFile::new(&path).expect("new file");
        file.zero_extend(len).expect("zero extend");
        file.sync().expect("sync");
        file
    }

    #[test]
    fn map_unmap_cycle() {
        let file = tmp_file(PAGE_SIZE);

        let mmap = MemMap::map(&file, PAGE_SIZE, MODE).expect("map");
        assert_eq!(mmap.len(), PAGE_SIZE);
    }

    #[test]
    fn sync_sanity() {
        let file = tmp_file(PAGE_SIZE);
        let mmap = MemMap::map(&file, PAGE_SIZE, MODE).expect("map");

        assert!(mmap.sync().is_ok(), "sync failed");
    }

    mod write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            let file = tmp_file(PAGE_SIZE);
            let mmap = MemMap::map(&file, PAGE_SIZE, MODE).expect("map");

            {
                let w = mmap.writer::<u64>(0);
                w.write(|v| *v = 0xDEAD_C0DE_DEAD_C0DE);
                mmap.sync().expect("sync");
            }

            {
                let r = mmap.reader::<u64>(0);
                assert_eq!(r.read(|val| *val), 0xDEAD_C0DE_DEAD_C0DE);
            }
        }

        #[test]
        fn write_read_cycle_across_sessions() {
            let dir = tempdir().expect("tmp dir");
            let path = dir.path().join("persist");

            // create_file + mmap + write + sync
            {
                let file = OsFile::new(&path).expect("new");
                file.zero_extend(PAGE_SIZE).unwrap();
                file.sync().expect("failed to sync");

                let mmap = MemMap::map(&file, PAGE_SIZE, MODE).expect("map");
                mmap.writer::<u64>(0).write(|v| *v = 0xAABBCCDDEEFF0011);
                mmap.sync().expect("failed to sync");
            }

            // open_file + mmap + read
            {
                let file = OsFile::open(&path).expect("open");
                let mmap = MemMap::map(&file, PAGE_SIZE, MODE).expect("map");

                let r = mmap.reader::<u64>(0);
                assert_eq!(r.read(|val| *val), 0xAABBCCDDEEFF0011);
            }
        }

        #[test]
        fn mmap_and_pread_see_same_data() {
            let file = tmp_file(PAGE_SIZE);
            let mmap = MemMap::map(&file, PAGE_SIZE, MODE).expect("map");

            // write
            {
                mmap.writer::<u64>(0).write(|v| *v = 0xDEAD_C0DE_DEAD_C0DE);
                mmap.sync().expect("failed to sync");
            }

            // read
            {
                let mut buf = [0u8; 8];
                file.read(buf.as_mut_ptr(), 0, 8).expect("failed to read");
                assert_eq!(u64::from_le_bytes(buf), 0xDEAD_C0DE_DEAD_C0DE);
            }
        }
    }

    mod concurrent_write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            let file = tmp_file(PAGE_SIZE);
            let mmap = Arc::new(MemMap::map(&file, PAGE_SIZE, MODE).expect("map"));

            mmap.writer::<u64>(0).write(|v| *v = 0x1122334455667788);
            mmap.sync().expect("failed to sync");

            let mut handles = Vec::new();
            for _ in 0..4 {
                let mmap = Arc::clone(&mmap);
                handles.push(thread::spawn(move || {
                    let r = mmap.reader::<u64>(0);
                    assert_eq!(r.read(|val| *val), 0x1122334455667788);
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }
        }

        #[test]
        fn concurrent_writes_to_disjoint_offsets() {
            const N: usize = 4;

            let file = tmp_file(PAGE_SIZE * N);
            let mmap = Arc::new(MemMap::map(&file, PAGE_SIZE * N, MODE).expect("map"));

            let mut handles = Vec::new();
            for i in 0..N {
                let mmap = Arc::clone(&mmap);
                handles.push(thread::spawn(move || {
                    let off = i * PAGE_SIZE;
                    mmap.writer::<u64>(off).write(|v| *v = i as u64);
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }

            mmap.sync().expect("failed to sync");

            for i in 0..N {
                let r = mmap.reader::<u64>(i * PAGE_SIZE);
                assert_eq!(r.read(|val| *val), i as u64);
            }
        }
    }
}
