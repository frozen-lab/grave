use crate::{
    system::{IOFlushMode, OsFile},
    GraveResult,
};

const PATH: &'static str = "coffin";
const FLUSH_MODE: IOFlushMode = IOFlushMode::Background;

#[derive(Debug)]
pub(super) struct Coffin {
    file: OsFile,
}

impl Coffin {
    pub(super) fn new(dirpath: &std::path::PathBuf, init_len: u64) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);
        let file = OsFile::new(filepath, FLUSH_MODE, init_len)?;
        Ok(Self { file })
    }

    pub(super) fn open(dirpath: &std::path::PathBuf) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);
        let file = OsFile::open(filepath, FLUSH_MODE)?;
        Ok(Self { file })
    }

    #[inline]
    pub(super) fn len(&self) -> u64 {
        self.file.len()
    }

    #[inline]
    pub(super) fn read(&self, buf_ptr: *mut u8, offset: usize, len_to_read: usize) -> GraveResult<()> {
        self.file.read(buf_ptr, offset, len_to_read)
    }

    #[inline]
    pub(super) fn write_single(&self, buf_ptr: *const u8, offset: usize, len_to_write: usize) -> GraveResult<()> {
        self.file.write_single(buf_ptr, offset, len_to_write)
    }

    #[inline]
    pub(super) fn write_multi(&self, buf_ptrs: &[*const u8], offset: usize, len_to_write: usize) -> GraveResult<()> {
        self.file.write_multi(buf_ptrs, offset, len_to_write)
    }
}
