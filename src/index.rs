use crate::{file::OsFile, mmap::MemMap, GraveConfig, GraveError, GraveResult};

const VERSION: u32 = 0;
const MAGIC: [u8; 4] = *b"indx";
const BLOCK_SIZE: usize = 0x200;
const PATH: &'static str = "index";

#[derive(Debug)]
pub(crate) struct Index {
    file: OsFile,
    mmap: MemMap,
}

impl Index {
    pub(crate) fn new(dirpath: &std::path::PathBuf, cfg: &GraveConfig) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);
        let meta = Metadata::new(cfg);

        // NOTE: Index file is initialized as, Metadata + 1 BitMap Block
        let file_len = METADATA_SIZE + BLOCK_SIZE;

        // S1: New file (creation + prep)
        let file = OsFile::new(&filepath)?;
        file.zero_extend(file_len).map_err(|e| {
            // as `zero_extend` operation is not atomic, we clear up the created file,
            // so new init call would process correctly!
            Self::clear_file(&file, &filepath);
            e
        })?;

        // S2: MMap the file
        let mmap = MemMap::map(&file, file_len).map_err(|e| {
            // we clear up the created file, so new init call would process correctly!
            Self::clear_file(&file, &filepath);
            e
        })?;

        Ok(Self { file, mmap })
    }

    pub(crate) fn open(dirpath: &std::path::PathBuf) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);

        // sanity checks
        debug_assert!(filepath.exists());
        debug_assert!(filepath.is_file());

        // S1: Open existing file
        let file = OsFile::new(&filepath)?;

        // S2: Read and validate len
        let file_len = file.len()?;
        if file_len <= METADATA_SIZE || (file_len - METADATA_SIZE) % BLOCK_SIZE != 0 {
            return Err(GraveError::InvalidState(format!(
                "Index file has invalid len={file_len}"
            )));
        }

        // S3: MMap the file
        let mmap = MemMap::map(&file, file_len)?;

        // S4: Read & Validate Metadata
        let meta_reader = mmap.reader::<Metadata>(0);
        let metadata = meta_reader.read();
        if metadata.version != VERSION || metadata.magic != MAGIC {
            return Err(GraveError::InvalidState("Invalid metadata for Index file".into()));
        }

        Ok(Self { file, mmap })
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
        if file.close().is_ok() {
            file.delete(filepath);
        }
    }
}

//
// Metadata
//

#[repr(C, align(0x40))]
struct Metadata {
    version: u32,
    magic: [u8; 4],
    page_size: u32,
    _padd: [u8; 0x34],
}

// Metadata values:
//
// - page_size = for on disk usgae
// - block_size = for bitmap and adjarr
// - total_slots = init w/ init_cap,
// - available_slots = init w/ init_cap,
// - total_entries = total entries

const METADATA_OFF: usize = 0;
const METADATA_SIZE: usize = std::mem::size_of::<Metadata>();

// sanity check
const _: () = assert!(METADATA_SIZE == 0x40);

impl Metadata {
    #[inline]
    fn new(cfg: &GraveConfig) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            page_size: cfg.page_size.to_u32(),
            _padd: [0u8; 0x34],
        }
    }
}
