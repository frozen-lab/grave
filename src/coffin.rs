use crate::{common::IOFlushMode, file::OsFile, GraveResult};

const PATH: &'static str = "coffin";
const FILE_FLUSH_MODE: IOFlushMode = IOFlushMode::Background;

#[derive(Debug)]
pub(crate) struct Coffin {
    file: OsFile,
    len: usize,
}

impl Coffin {
    pub(crate) fn new(dirpath: &std::path::PathBuf, nslots: usize, page_size: usize) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);
        let file_len = nslots * page_size;

        let file = OsFile::new(&filepath, FILE_FLUSH_MODE)?;
        file.zero_extend(file_len).map_err(|e| {
            // as `zero_extend` operation is not atomic, we clear up the created file,
            // so new init call would process correctly!
            Self::clear_file(&file, &filepath);
            e
        })?;

        Ok(Self { file, len: file_len })
    }

    pub(crate) fn open(dirpath: &std::path::PathBuf) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);

        let file = OsFile::open(&filepath, FILE_FLUSH_MODE)?;
        let len = file.len()?;

        Ok(Self { file, len })
    }

    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn write(&self, ptr: *const u8, slot_idx: usize, page_size: usize) -> GraveResult<()> {
        let off = slot_idx * page_size;
        self.file.write(ptr, off, page_size)
    }

    #[inline]
    pub(crate) fn read(&self, ptr: *mut u8, slot_idx: usize, page_size: usize) -> GraveResult<()> {
        let off = slot_idx * page_size;
        self.file.read(ptr, off, page_size)
    }

    /// Closes and Deletes the [`OsFile`]
    ///
    /// ## Why
    ///
    /// Init failures on operations like `zero_extend` which are not atomic and can partially execute,
    /// they might make the init process stuck in an error loop or might create invalid structure.
    ///
    /// To avoid this, we must clear up the created file, so the new init could work w/ a fresh start.
    /// So we close + delete the created new file!
    ///
    /// ## HACK
    ///
    /// Any thrown I/O errors are supressed, as this function will be called in an already errored state
    /// where the original error should get more privilege.
    fn clear_file(file: &OsFile, filepath: &std::path::PathBuf) {
        file.delete(filepath);
    }
}
