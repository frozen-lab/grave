use crate::{file::OsFile, mmap::MemMap, GraveConfig, GraveResult};

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
        let path = dirpath.join(PATH);
        let meta = Metadata::new(cfg);

        // NOTE: Index file is initialized as, Metadata + 1 BitMap Block
        let file_len = METADATA_SIZE + BLOCK_SIZE;

        // S1: New file (creation + prep)
        let file = OsFile::new(&path)?;
        file.zero_extend(file_len).map_err(|e| {
            //
            e
        })?;

        todo!()
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
