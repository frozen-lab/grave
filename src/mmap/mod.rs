use crate::{errors::GraveResult, file::OsFile};
use std::{mem, sync::atomic};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug)]
pub(crate) struct MemMap {
    version: atomic::AtomicU8,
    dropped: atomic::AtomicBool,

    #[cfg(target_os = "linux")]
    mmap: mem::ManuallyDrop<linux::MMap>,

    #[cfg(not(target_os = "linux"))]
    mmap: (),
}

unsafe impl Send for MemMap {}
unsafe impl Sync for MemMap {}

impl std::fmt::Display for MemMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(f, "GraveMMap {{len: {}}}", self.mmap.len())
    }
}

impl MemMap {
    /// Create a memory mapping as [`MemMap`] for the given [`OsFile`]
    pub(crate) fn map(file: &OsFile, len: usize) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let mmap = ();

        #[cfg(target_os = "linux")]
        let mmap = unsafe { linux::MMap::map(file.fd(), len) }?;

        Ok(Self {
            version: atomic::AtomicU8::new(0),
            mmap: mem::ManuallyDrop::new(mmap),
            dropped: atomic::AtomicBool::new(false),
        })
    }

    /// Unmap the mapped memory for [`MemMap`]
    ///
    /// ## Safety
    ///
    /// `unmap` is idempotent, hence calling it multiple times would not result into
    /// any errors or UB
    pub(crate) fn unmap(&mut self) -> GraveResult<()> {
        // sanity protection to avoid unmap after unmap
        if self.dropped.load(atomic::Ordering::Acquire) {
            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            mem::ManuallyDrop::take(&mut self.mmap).unmap()?;
        }

        self.version.fetch_add(1, atomic::Ordering::Release);
        self.dropped.store(true, atomic::Ordering::Release);
        Ok(())
    }

    /// Syncs dirty pages of [`MemMap`] to disk
    #[inline]
    pub(crate) fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.mmap.sync()
        }
    }

    /// Fetches current length of [`MemMap`]
    #[inline]
    pub(crate) fn len(&self) -> usize {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        self.mmap.len()
    }

    #[inline]
    pub(crate) fn reader<'a, T>(&'a self, off: usize) -> MemMapReader<'a, T> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            let ptr = self.mmap.get::<T>(off);
            MemMapReader {
                ptr,
                map: self,
                version: self.version.load(atomic::Ordering::Acquire),
            }
        }
    }

    #[inline]
    pub(crate) fn writer<'a, T>(&'a self, off: usize) -> MemMapWriter<'a, T> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            let ptr = self.mmap.get_mut::<T>(off);
            MemMapWriter {
                ptr,
                map: self,
                version: self.version.load(atomic::Ordering::Acquire),
            }
        }
    }
}

impl Drop for MemMap {
    fn drop(&mut self) {
        unsafe {
            let _ = self.unmap();
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
        debug_assert!(!self.map.dropped.load(atomic::Ordering::Acquire));
        debug_assert_eq!(
            self.version,
            self.map.version.load(atomic::Ordering::Acquire),
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
        debug_assert!(!self.map.dropped.load(atomic::Ordering::Acquire));
        debug_assert_eq!(
            self.version,
            self.map.version.load(atomic::Ordering::Acquire),
            "detected use of pointer to unmapped memmap"
        );

        unsafe { f(&mut *self.ptr) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use tempfile::tempdir;

    const PAGE_SIZE: usize = 0x20;

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

        let mmap = MemMap::map(&file, PAGE_SIZE).expect("map");
        assert_eq!(mmap.len(), PAGE_SIZE);
    }

    #[test]
    fn sync_sanity() {
        let file = tmp_file(PAGE_SIZE);
        let mmap = MemMap::map(&file, PAGE_SIZE).expect("map");

        assert!(mmap.sync().is_ok(), "sync failed");
    }

    mod write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            let file = tmp_file(PAGE_SIZE);
            let mmap = MemMap::map(&file, PAGE_SIZE).expect("map");

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

                let mmap = MemMap::map(&file, PAGE_SIZE).expect("map");
                mmap.writer::<u64>(0).write(|v| *v = 0xAABBCCDDEEFF0011);
                mmap.sync().expect("failed to sync");
            }

            // open_file + mmap + read
            {
                let file = OsFile::open(&path).expect("open");
                let mmap = MemMap::map(&file, PAGE_SIZE).expect("map");

                let r = mmap.reader::<u64>(0);
                assert_eq!(r.read(|val| *val), 0xAABBCCDDEEFF0011);
            }
        }

        #[test]
        fn mmap_and_pread_see_same_data() {
            let file = tmp_file(PAGE_SIZE);
            let mmap = MemMap::map(&file, PAGE_SIZE).expect("map");

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
            let mmap = Arc::new(MemMap::map(&file, PAGE_SIZE).expect("map"));

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
            let mmap = Arc::new(MemMap::map(&file, PAGE_SIZE * N).expect("map"));

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
