use crate::GraveResult;

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug)]
pub(crate) struct OsFile {
    page_size: usize,

    #[cfg(target_os = "linux")]
    file: linux::File,

    #[cfg(not(target_os = "linux"))]
    file: (),
}

unsafe impl Send for OsFile {}
unsafe impl Sync for OsFile {}

impl std::fmt::Display for OsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        unimplemented!();

        #[cfg(target_os = "linux")]
        write!(f, "OsFile {{fd: {:?}}}", self.file.fd())
    }
}

impl OsFile {
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

        let file = OsFile::new(&path, PAGE_SIZE).expect("create new file");
        assert_eq!(file.len().expect("read file len"), 0);

        assert!(file.close().is_ok(), "failed to close file");
        assert!(path.exists(), "file must exist on disk");
    }

    #[test]
    fn open_accepts_existing_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        {
            let file = OsFile::new(&path, PAGE_SIZE).expect("create new file");
            assert!(file.close().is_ok(), "failed to close file");
        }

        let file = OsFile::open(&path, PAGE_SIZE).expect("open existing file");
        assert_eq!(file.len().expect("read file len"), 0);

        assert!(file.close().is_ok(), "failed to close file");
    }

    #[test]
    fn open_fails_on_missing_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("missing_file");

        assert!(
            OsFile::open(&path, PAGE_SIZE).is_err(),
            "open must fail for missing file"
        );
    }

    #[test]
    fn zero_extend_correctly_extends_file() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("tmp_file");

        let file = OsFile::new(&path, PAGE_SIZE).expect("create new file");
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

        let file = OsFile::new(&path, PAGE_SIZE).expect("create new file");
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
                let file = OsFile::new(&tmp, PAGE_SIZE).expect("open existing file");

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
                let file = OsFile::new(&tmp, PAGE_SIZE).expect("open existing file");

                assert!(file.write(DATA.as_ptr(), 0).is_ok(), "pwrite failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = OsFile::open(&tmp, PAGE_SIZE).expect("open existing file");

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
                let file = OsFile::new(&tmp, PAGE_SIZE).expect("open existing file");

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
                let file = OsFile::new(&tmp, PAGE_SIZE).expect("open existing file");

                assert!(file.writev(&ptrs, 0).is_ok(), "pwritev failed");
                assert!(file.sync().is_ok(), "fdatasync failed");

                assert!(file.close().is_ok(), "failed to close the file");
            }

            // open + read + close
            unsafe {
                let file = OsFile::open(&tmp, PAGE_SIZE).expect("open existing file");

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

    mod concurrent_write_read {
        use super::*;
        use std::sync::Arc;
        use std::thread;

        #[test]
        fn concurrent_writes_to_disjoint_offsets() {
            const PAGE_SIZE: usize = 0x20;
            const NTHREADS: usize = 8;

            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("tmp_file");
            let file = Arc::new(OsFile::new(&path, PAGE_SIZE).expect("create new file"));

            let mut handles = Vec::with_capacity(NTHREADS);
            for i in 0..NTHREADS {
                let file = Arc::clone(&file);
                handles.push(thread::spawn(move || {
                    let data = vec![i as u8; PAGE_SIZE];
                    let off = i * PAGE_SIZE;
                    assert!(file.write(data.as_ptr(), off).is_ok(), "concurrent write failed");
                }));
            }

            for h in handles {
                assert!(h.join().is_ok(), "thread panicked");
            }

            assert!(file.sync().is_ok(), "fdatasync failed");

            let len = file.len().expect("read file len");
            assert_eq!(len, NTHREADS * PAGE_SIZE, "file len mismatch");

            let mut buf = vec![0u8; len];
            assert!(file.read(buf.as_mut_ptr(), 0, NTHREADS).is_ok(), "read failed");

            for (i, chunk) in buf.chunks_exact(PAGE_SIZE).enumerate() {
                assert!(
                    chunk.iter().all(|b| *b == i as u8),
                    "data corruption in concurrent write"
                );
            }

            assert!(file.close().is_ok(), "failed to close file");
        }

        #[test]
        fn concurrent_reads_after_write() {
            const PAGE_SIZE: usize = 0x20;
            const NTHREADS: usize = 4;

            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("tmp_file");
            let file = Arc::new(OsFile::new(&path, PAGE_SIZE).expect("create new file"));

            let data = vec![0xABu8; PAGE_SIZE];
            assert!(file.write(data.as_ptr(), 0).is_ok(), "initial write failed");
            assert!(file.sync().is_ok(), "fdatasync failed");

            let mut handles = Vec::with_capacity(NTHREADS);
            for _ in 0..NTHREADS {
                let file = Arc::clone(&file);
                handles.push(thread::spawn(move || {
                    let mut buf = vec![0u8; PAGE_SIZE];
                    assert!(file.read(buf.as_mut_ptr(), 0, 1).is_ok(), "concurrent read failed");
                    assert_eq!(buf, vec![0xABu8; PAGE_SIZE], "read data mismatch");
                }));
            }

            for h in handles {
                assert!(h.join().is_ok(), "thread panicked");
            }

            assert!(file.close().is_ok(), "failed to close file");
        }

        #[test]
        fn concurrent_writev_and_reads() {
            const PAGE_SIZE: usize = 0x20;
            const NPAGES: usize = 4;

            let dir = tempdir().expect("temp dir");
            let path = dir.path().join("tmp_file");
            let file = Arc::new(OsFile::new(&path, PAGE_SIZE).expect("create new file"));

            let pages: Vec<Vec<u8>> = (0..NPAGES).map(|i| vec![i as u8; PAGE_SIZE]).collect();
            let ptrs: Vec<*const u8> = pages.iter().map(|p| p.as_ptr()).collect();

            assert!(file.writev(&ptrs, 0).is_ok(), "writev failed");
            assert!(file.sync().is_ok(), "fdatasync failed");

            let mut handles = Vec::with_capacity(NPAGES);
            for i in 0..NPAGES {
                let file = Arc::clone(&file);
                handles.push(thread::spawn(move || {
                    let mut buf = vec![0u8; PAGE_SIZE];
                    let off = i * PAGE_SIZE;

                    assert!(file.read(buf.as_mut_ptr(), off, 1).is_ok(), "read failed");
                    assert!(buf.iter().all(|b| *b == i as u8), "data mismatch in concurrent read");
                }));
            }

            for h in handles {
                assert!(h.join().is_ok(), "thread panicked");
            }

            assert!(file.close().is_ok(), "failed to close file");
        }
    }
}
