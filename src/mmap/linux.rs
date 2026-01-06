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
