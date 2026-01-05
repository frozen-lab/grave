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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const PAGE_SIZE: usize = 0x20;

    #[test]
    fn new_file_creation() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = GraveFile::new(&path, PAGE_SIZE).expect("create new file");
        assert_eq!(file.len().expect("read file len"), 0);

        assert!(file.close().is_ok(), "failed to close file");
        assert!(path.exists(), "file must exist on disk");
    }

    #[test]
    fn open_accepts_existing_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        {
            let file = GraveFile::new(&path, PAGE_SIZE).expect("create new file");
            assert!(file.close().is_ok(), "failed to close file");
        }

        let file = GraveFile::open(&path, PAGE_SIZE).expect("open existing file");
        assert_eq!(file.len().expect("read file len"), 0);

        assert!(file.close().is_ok(), "failed to close file");
    }

    #[test]
    fn open_fails_on_missing_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("missing_file");

        assert!(
            GraveFile::open(&path, PAGE_SIZE).is_err(),
            "open must fail for missing file"
        );
    }

    #[test]
    fn zero_extend_correctly_extends_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = GraveFile::new(&path, PAGE_SIZE).expect("create new file");
        assert!(file.zero_extend(PAGE_SIZE * 2).is_ok(), "zero_extend failed");
        assert!(file.sync().is_ok(), "fdatasync failed");

        assert_eq!(file.len().expect("read file len"), PAGE_SIZE * 2, "file len mismatch");
        assert!(file.close().is_ok(), "failed to close file");

        let data = std::fs::read(&path).expect("read file");
        assert!(data.iter().all(|b| *b == 0), "file must be zero extended");
    }

    #[test]
    fn close_fails_after_close() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = GraveFile::new(&path, PAGE_SIZE).expect("create new file");
        assert!(file.close().is_ok(), "failed to close file");
        assert!(file.close().is_err(), "close must fail after close");
    }

    mod write_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            unsafe {
                let file = GraveFile::new(&tmp, PAGE_SIZE).expect("open existing file");

                // write
                assert!(file.write(DATA.as_ptr(), 0).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, PAGE_SIZE, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; PAGE_SIZE];
                assert!(file.read(buf.as_mut_ptr(), 0, 1).is_ok(), "pread failed");
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }

        #[test]
        fn write_read_cycle_across_sessions() {
            const PAGE_SIZE: usize = 0x40;
            const DATA: [u8; PAGE_SIZE] = [0x1C; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            // create + write + sync + close
            unsafe {
                let file = GraveFile::new(&tmp, PAGE_SIZE).expect("open existing file");

                assert!(file.write(DATA.as_ptr(), 0).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = GraveFile::open(&tmp, PAGE_SIZE).expect("open existing file");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, PAGE_SIZE, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; PAGE_SIZE];
                assert!(file.read(buf.as_mut_ptr(), 0, 1).is_ok(), "pread failed");
                assert_eq!(DATA.to_vec(), buf, "mismatch between read and write");

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }
    }

    mod writev_read {
        use super::*;

        #[test]
        fn write_read_cycle() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            let ptrs = vec![DATA.as_ptr(); 0x10];
            let total_len = ptrs.len() * PAGE_SIZE;

            unsafe {
                let file = GraveFile::new(&tmp, PAGE_SIZE).expect("open existing file");

                // write
                assert!(file.writev(&ptrs, 0).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, total_len, "file len does not match expected len");

                let mut buf = vec![0u8; total_len];
                assert!(file.read(buf.as_mut_ptr(), 0, ptrs.len()).is_ok(), "pread failed");
                assert_eq!(buf.len(), total_len, "mismatch between read and write");

                for chunk in buf.chunks_exact(PAGE_SIZE) {
                    assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
                }

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }

        #[test]
        fn write_read_cycle_across_sessions() {
            const PAGE_SIZE: usize = 0x20;
            const DATA: [u8; PAGE_SIZE] = [0x1A; PAGE_SIZE];

            let dir = tempdir().expect("temp dir");
            let tmp = dir.path().join("tmp_file");

            let ptrs = vec![DATA.as_ptr(); 0x10];
            let total_len = ptrs.len() * PAGE_SIZE;

            // create + write + sync + close
            unsafe {
                let file = GraveFile::new(&tmp, PAGE_SIZE).expect("open existing file");

                assert!(file.writev(&ptrs, 0).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = GraveFile::open(&tmp, PAGE_SIZE).expect("open existing file");

                // len validation
                let len = file.len().expect("read len for file");
                assert_eq!(len, total_len, "file len does not match expected len");

                // readback
                let mut buf = vec![0u8; total_len];
                assert!(file.read(buf.as_mut_ptr(), 0, ptrs.len()).is_ok(), "pread failed");
                assert_eq!(buf.len(), total_len, "mismatch between read and write");

                for chunk in buf.chunks_exact(PAGE_SIZE) {
                    assert_eq!(chunk, DATA, "data mismatch in pwritev readback");
                }

                assert!(file.close().is_ok(), "failed to close the file");
            }
        }
    }
}
