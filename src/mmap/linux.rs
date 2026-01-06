use crate::errors::GraveResult;
use libc::{c_void, mmap, msync, munmap, off_t, MAP_FAILED, MAP_SHARED, MS_ASYNC, MS_SYNC, PROT_READ, PROT_WRITE};

#[derive(Debug)]
pub(crate) struct MMap {
    ptr: *mut c_void,
    len: usize,
}

unsafe impl Send for MMap {}
unsafe impl Sync for MMap {}

impl MMap {
    /// Creates a new [`MMap`] instance w/ read + write permissions
    ///
    /// ## Persistence
    ///
    /// We use the `MAP_SHARED` flag, which ensures that all modifications to the
    /// mapped memory are reflected in the underlying file and tracked by the kernel
    ///
    /// Use of `MAP_SHARED` does not provide durability guarantees by itself
    ///
    /// Explicit calls to `sync()` are required to establish durability boundaries
    /// and ensure that modified pages are written to stable storage
    pub(crate) unsafe fn map(fd: i32, len: usize) -> GraveResult<Self> {
        let ptr = mmap(
            std::ptr::null_mut(),
            len,
            PROT_WRITE | PROT_READ,
            MAP_SHARED,
            fd,
            0 as off_t,
        );

        if ptr == MAP_FAILED {
            return Self::last_os_error();
        }

        Ok(Self { ptr, len })
    }

    /// Unmap the [`MMap`] region
    pub(crate) unsafe fn unmap(&self) -> GraveResult<()> {
        if munmap(self.ptr, self.len) != 0 {
            return Self::last_os_error();
        }
        Ok(())
    }

    /// Asynchronously syncs dirty pages of [`MMap`] to disk
    #[allow(unused)]
    pub(crate) unsafe fn async_sync(&self) -> GraveResult<()> {
        if msync(self.ptr, self.len, MS_ASYNC) != 0 {
            return Self::last_os_error();
        }
        Ok(())
    }

    /// Syncs dirty pages of [`MMap`] to disk
    pub(crate) unsafe fn sync(&self) -> GraveResult<()> {
        if msync(self.ptr, self.len, MS_SYNC) != 0 {
            return Self::last_os_error();
        }
        Ok(())
    }

    /// Get an immutable reference of [`T`] from [`MMap`]
    #[inline]
    pub(crate) const unsafe fn get<T>(&self, off: usize) -> *const T {
        #[cfg(debug_assertions)]
        {
            let size = std::mem::size_of::<T>();
            let align = std::mem::align_of::<T>();

            debug_assert!(off + size <= self.len, "Offset must not exceed mmap size");
            debug_assert!(off % align == 0, "Detected unaligned access for type");
        }

        self.ptr().add(off) as *const T
    }

    /// Get a mutable reference of [`T`] from [`MMap`]
    #[inline]
    pub(crate) const unsafe fn get_mut<T>(&self, off: usize) -> *mut T {
        #[cfg(debug_assertions)]
        {
            let size = std::mem::size_of::<T>();
            let align = std::mem::align_of::<T>();

            debug_assert!(off + size <= self.len, "Offset must not exceed mmap size");
            debug_assert!(off % align == 0, "Detected unaligned access for type");
        }

        self.ptr_mut().add(off) as *mut T
    }

    /// Fetches current length of [`MMap`]
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    const fn ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    #[inline]
    const fn ptr_mut(&self) -> *mut u8 {
        self.ptr as *mut u8
    }

    #[inline]
    fn last_os_error<T>() -> GraveResult<T> {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::file::OsFile;
    use tempfile::tempdir;

    const PAGE: usize = 0x100;

    fn tmp_file(len: usize) -> OsFile {
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join(&format!("test_mmap_{len}"));

        unsafe {
            let file = OsFile::new(&path, len).expect("new file");
            file.zero_extend(len).expect("set init len");
            file.sync().expect("flush to disk");
            file
        }
    }

    #[test]
    fn map_unmap_cycle() {
        let file = tmp_file(PAGE);

        let map = unsafe { MMap::map(file.fd(), PAGE) };
        assert!(map.is_ok());

        let map = map.unwrap();
        assert_eq!(map.len, PAGE);
        assert!(!map.ptr.is_null());

        unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
        assert!(file.close().is_ok(), "failed to close the file");
    }

    #[test]
    fn map_fails_on_invalid_fd() {
        let file = tmp_file(PAGE);
        unsafe {
            assert!(MMap::map(-1, PAGE).is_err());
        }
    }

    #[test]
    fn unmap_after_unmap_does_not_fails() {
        let file = tmp_file(PAGE);

        unsafe {
            let map = MMap::map(file.fd(), PAGE).expect("new map");

            assert!(map.unmap().is_ok(), "failed to unmap");
            assert!(map.unmap().is_ok(), "should not fail");
        }

        assert!(file.close().is_ok(), "failed to close the file");
    }

    #[test]
    fn sanity_check_for_sync() {
        let file = tmp_file(PAGE);
        let map = unsafe { MMap::map(file.fd(), PAGE).expect("new map") };

        assert!(unsafe { map.sync().is_ok() }, "sync failed");

        unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
        assert!(file.close().is_ok(), "failed to close the file");
    }

    #[test]
    fn sanity_check_for_async_sync() {
        let file = tmp_file(PAGE);
        let map = unsafe { MMap::map(file.fd(), PAGE).expect("new map") };

        assert!(unsafe { map.async_sync().is_ok() }, "async sync failed");

        unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
        assert!(file.close().is_ok(), "failed to close the file");
    }

    mod write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            let file = tmp_file(PAGE);
            let map = unsafe { MMap::map(file.fd(), PAGE).expect("new map") };

            // write + sync
            unsafe {
                let ptr = map.get_mut::<u64>(0);
                *ptr = 0xDEAD_C0DE_DEAD_C0DE;
                map.sync().expect("sync failed");
            }

            // read
            unsafe {
                let val = *map.get::<u64>(0);
                assert_eq!(val, 0xDEAD_C0DE_DEAD_C0DE);
            }

            unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
            assert!(file.close().is_ok(), "failed to close the file");
        }

        #[test]
        fn write_read_cycle_across_sessions() {
            let dir = tempdir().expect("tmp dir");
            let path = dir.path().join("test_mmap");

            // new_file + mmap + write + sync
            unsafe {
                let file = OsFile::new(&path, PAGE).expect("new file");
                file.zero_extend(PAGE).expect("set init len");
                file.sync().expect("flush to disk");

                let map = unsafe { MMap::map(file.fd(), PAGE).expect("new map") };
                let ptr = map.get_mut::<u64>(0);

                *ptr = 0xDEAD_C0DE_DEAD_C0DE;
                map.sync().expect("sync failed");

                unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open_file + mmap + read
            unsafe {
                let file = OsFile::open(&path, PAGE).expect("new file");
                let map = unsafe { MMap::map(file.fd(), PAGE).expect("new map") };

                let val = *map.get::<u64>(0);
                assert_eq!(val, 0xDEAD_C0DE_DEAD_C0DE);

                unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
                assert!(file.close().is_ok(), "failed to close the file");
            }
        }

        #[test]
        fn mmap_read_and_pread_reads_same_data() {
            let file = tmp_file(8);
            let map = unsafe { MMap::map(file.fd(), PAGE).expect("new map") };

            // write + sync
            unsafe {
                let ptr = map.get_mut::<u64>(0);
                *ptr = 0xDEAD_C0DE_DEAD_C0DE;
                map.sync().expect("sync failed");
            }

            // pread
            unsafe {
                let mut buf = [0u8; 8];
                file.read(buf.as_mut_ptr(), 0, 1).expect("failed to read");
                assert_eq!(u64::from_le_bytes(buf), 0xDEAD_C0DE_DEAD_C0DE);
            }

            unsafe { assert!(map.unmap().is_ok(), "failed to unmap") };
            assert!(file.close().is_ok(), "failed to close the file");
        }
    }
}
