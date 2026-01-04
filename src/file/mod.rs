use crate::GraveResult;

#[cfg(target_os = "linux")]
mod linux;

pub(crate) struct GraveFile {
    page_size: usize,

    #[cfg(target_os = "linux")]
    file: linux::File,

    #[cfg(not(target_os = "linux"))]
    file: (),
}

unsafe impl Send for GraveFile {}
unsafe impl Sync for GraveFile {}

impl std::fmt::Display for GraveFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(f, "GraveFile {{fd: {:?}}}", self.file.fd())
    }
}

impl GraveFile {
    pub(crate) fn new(path: &std::path::PathBuf, page_size: usize) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let file = ();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::File::new(path) }?;

        Ok(Self { file, page_size })
    }

    pub(crate) fn open(path: &std::path::PathBuf, page_size: usize) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let file = ();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::File::open(path) }?;

        Ok(Self { file, page_size })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fd(&self) -> i32 {
        self.file.fd()
    }

    pub(crate) fn close(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.close()
        }
    }

    pub(crate) fn sync(&self) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.sync()
        }
    }

    pub(crate) fn zero_extend(&self, new_len: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.ftruncate(new_len)
        }
    }

    pub(crate) fn len(&self) -> GraveResult<usize> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.len()
        }
    }

    #[inline(always)]
    pub(crate) fn read(&self, ptr: *mut u8, off: usize, npages: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.pread(ptr, off, npages * self.page_size)
        }
    }

    #[inline(always)]
    pub(crate) fn write(&self, ptr: *const u8, off: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.pwrite(ptr, off, self.page_size)
        }
    }

    #[inline(always)]
    pub(crate) fn writev(&self, ptr: &[*const u8], off: usize) -> GraveResult<()> {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        unsafe {
            self.file.pwritev(ptr, off, self.page_size)
        }
    }
}
