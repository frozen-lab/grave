use std::marker::PhantomData;

use crate::{errors::GraveResult, file::OsFile};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug)]
pub(crate) struct MemMap {
    #[cfg(target_os = "linux")]
    mmap: linux::MMap,

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
    pub(crate) fn map(file: &OsFile, len: usize) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let mmap = ();

        #[cfg(target_os = "linux")]
        let mmap = unsafe { linux::MMap::map(file.fd(), len) }?;

        Ok(Self { mmap })
    }

    pub(crate) fn unmap(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.mmap.unmap()
        }
    }

    #[inline]
    pub(crate) fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.mmap.sync()
        }
    }

    #[inline]
    pub(crate) const fn len(&self) -> usize {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        self.mmap.len()
    }

    #[inline]
    pub(crate) const fn reader<'a, T>(&'a self, off: usize) -> MemMapReader<'a, T> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            MemMapReader::new(self.mmap.get::<T>(off))
        }
    }

    #[inline]
    pub(crate) fn writer<'a, T>(&'a self, off: usize) -> MemMapWriter<'a, T> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            MemMapWriter::new(self.mmap.get_mut::<T>(off))
        }
    }
}

//
// Reader
//

#[derive(Debug)]
pub(crate) struct MemMapReader<'a, T> {
    ptr: *const T,
    _pd: PhantomData<&'a T>,
}

impl<'a, T> MemMapReader<'a, T> {
    #[inline]
    const fn new(ptr: *const T) -> Self {
        Self { ptr, _pd: PhantomData }
    }

    #[inline]
    pub(crate) const fn read(&self) -> &T {
        unsafe { &*self.ptr }
    }
}

//
// Writer
//

#[derive(Debug)]
pub(crate) struct MemMapWriter<'a, T> {
    ptr: *mut T,
    _pd: PhantomData<&'a T>,
}

impl<'a, T> MemMapWriter<'a, T> {
    #[inline]
    const fn new(ptr: *mut T) -> Self {
        Self { ptr, _pd: PhantomData }
    }

    #[inline]
    pub(crate) fn write(&self, f: impl FnOnce(&mut T)) {
        unsafe { f(&mut *self.ptr) }
    }
}
