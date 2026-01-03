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

impl GraveFile {}
