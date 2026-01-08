use crate::{file::OsFile, mmap::MemMap, GraveConfig, GraveError, GraveResult};

const VERSION: u32 = 0;
const MAGIC: [u8; 4] = *b"indx";
const PATH: &'static str = "index";

// NOTE: When this values are updated, all the docs must be updated accordingly for [`GraveConfig`]
// w/ corrected calculations for Memory and Disk overheads.

/// Type describing raw structure of [`BlockHeader`]
///
/// ## Structure
///
/// - [0 (0th bit)] => flag (1 bit)
/// - [0(1..7 bits), 1, 2, 3 (half)] => next page idx (27 bits)
/// - [3(half), 4] => total free (12 bits)
/// - [5] =>  current pointer (8 bits)
type TBlockHeader = [u8; 6];

const BITMAP_BLOCK_FLAG: u8 = 0;
const ADJARR_BLOCK_FLAG: u8 = 1;

const BLOCK_SIZE: usize = 0x200;
const MIN_BLOCKS_ON_INIT: usize = 2;
const BLOCK_HEADER_SIZE: usize = std::mem::size_of::<TBlockHeader>();
const PAGES_PER_BLOCK: usize = (BLOCK_SIZE - BLOCK_HEADER_SIZE) * 8;

const DEFAULT_BITMAP_IDX: usize = 0;
const DEFAULT_ADJARR_IDX: usize = 1;

// sanity checks
const _: () = assert!(BLOCK_HEADER_SIZE == std::mem::size_of::<TBlockHeader>());
const _: () = assert!(PAGES_PER_BLOCK == 0xFD0, "each block must contain 4048 pages");
const _: () = assert!(MIN_BLOCKS_ON_INIT >= 2, "Must be space for BitMap and AdjArr block");

#[derive(Debug)]
pub(crate) struct Index {
    file: OsFile,
    mmap: MemMap,
}

impl Index {
    pub(crate) fn new(dirpath: &std::path::PathBuf, cfg: &GraveConfig) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);
        let meta = Metadata::new(cfg);

        // NOTE: Index file is initialized as, Metadata + min 1 BitMap Block + 1 AdjArr Block
        let num_block = if cfg.num_block <= 1 {
            MIN_BLOCKS_ON_INIT
        } else {
            cfg.num_block + 1
        };
        let file_len = METADATA_SIZE + (num_block * BLOCK_SIZE);

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

        // S3: Init blocks (creating links, etc.)

        // TODO: Create links for BitMap blocks
        // NOTE: Skip the block at idx 1 for now, reserved for AdjArr

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
    num_blocks: u32,
    bitmap_idx: u32,
    adjarr_idx: u32,
    current_cap: u64,
    total_entries: u64,
    _padd: [u8; 0x18],
}

const METADATA_OFF: usize = 0;
const METADATA_SIZE: usize = std::mem::size_of::<Metadata>();

// sanity check
const _: () = assert!(METADATA_SIZE == 0x40);

impl Metadata {
    #[inline]
    const fn new(cfg: &GraveConfig) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            total_entries: 0,
            _padd: [0u8; 0x18],
            num_blocks: cfg.num_block as u32,
            page_size: cfg.page_size.to_u32(),
            bitmap_idx: DEFAULT_BITMAP_IDX as u32,
            adjarr_idx: DEFAULT_ADJARR_IDX as u32,
            current_cap: (cfg.num_block * PAGES_PER_BLOCK) as u64,
        }
    }
}

//
// Block Header
//

#[derive(Debug)]
struct BlockHeader {
    cptr: u8,  // all 8 bits lower in use
    flag: u8,  // only lower 1 bit in use
    free: u16, // only lower 12 bits are in use
    nidx: u32, // only lower 27 bits are in use
}

impl BlockHeader {
    #[inline]
    const fn unpack(raw: &TBlockHeader) -> Self {
        // sanity check
        debug_assert!(raw.len() == 6);

        let flag = raw[0] >> 7;
        let free = ((raw[3] as u16 & 0x0F) << 8) | (raw[4] as u16);
        let nidx = ((raw[0] as u32 & 0x7F) << 0x14)
            | ((raw[1] as u32) << 12)
            | ((raw[2] as u32) << 4)
            | ((raw[3] as u32 >> 4) & 15);

        Self {
            flag,
            cptr: raw[5],
            free: free & 0x0FFF,
            nidx: nidx & 0x07FF_FFFF,
        }
    }

    #[inline]
    const fn pack(&self) -> TBlockHeader {
        // sanity checks
        debug_assert!(self.flag <= 1, "flag overflow (1 bit)");
        debug_assert!(self.free <= 0x0FFF, "all_free overflow (12 bits)");
        debug_assert!(self.nidx <= 0x07FF_FFFF, "nidx overflow (27 bits)");

        [
            ((self.flag & 0x01) << 7) as u8 | ((self.nidx >> 0x14) as u8 & 0x7F),
            ((self.nidx >> 12) & 0xFF) as u8,
            ((self.nidx >> 4) & 0xFF) as u8,
            (((self.nidx & 0x0F) << 4) as u8) | ((self.free >> 8) as u8 & 0x0F),
            (self.free & 0xFF) as u8,
            self.cptr,
        ]
    }
}

//
// BitMap
//

const BITMAP_WORDS_PER_BLOCK: usize = (BLOCK_SIZE - BLOCK_HEADER_SIZE) / 2;

#[repr(C)]
struct BitMap {
    header: TBlockHeader,
    words: [u16; BITMAP_WORDS_PER_BLOCK],
}

// sanity check
const _: () = assert!(std::mem::size_of::<BitMap>() == BLOCK_SIZE);
