use crate::GraveResult;

#[cfg(target_os = "linux")]
mod linux;

pub(crate) struct GraveFile {
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
    pub(crate) fn new(path: &std::path::PathBuf) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let file = ();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::File::new(path) }?;

        Ok(Self { file })
    }

    pub(crate) fn open(path: &std::path::PathBuf) -> GraveResult<Self> {
        #[cfg(not(target_os = "linux"))]
        let file = ();

        #[cfg(target_os = "linux")]
        let file = unsafe { linux::File::open(path) }?;

        Ok(Self { file })
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
}
