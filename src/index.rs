use crate::{
    file::OsFile,
    mmap::{MemMap, MemMapReader},
    GraveConfig, GraveError, GraveResult,
};

const VERSION: u32 = 0;
const MAGIC: [u8; 4] = *b"indx";
const PATH: &'static str = "index";

// NOTE: When this values are updated, all the docs must be updated accordingly
// for [`GraveConfig`], w/ corrected calculations for Memory and Disk overheads.

const BLOCK_SIZE: usize = 0x200;
const MIN_BLOCKS_ON_INIT: usize = 2;
const DEFAULT_BITMAP_IDX: usize = 0;
const DEFAULT_ADJARR_IDX: usize = 1;
const MAX_PAGE_INDEX: u32 = 0x07FF_FFFF;
const BLOCK_HEADER_SIZE: usize = std::mem::size_of::<BlockHeader>();
const PAGES_PER_BLOCK: usize = (BLOCK_SIZE - BLOCK_HEADER_SIZE) * 8;

// sanity checks
const _: () = assert!(BLOCK_HEADER_SIZE == std::mem::size_of::<BlockHeader>());
const _: () = assert!(PAGES_PER_BLOCK == 0xFD0, "each block must contain 4048 pages");
const _: () = assert!(MIN_BLOCKS_ON_INIT >= 2, "Must be space for BitMap and AdjArr block");

#[derive(Debug)]
pub(crate) struct Index {
    file: OsFile,
    mmap: MemMap,
    ptrs: IndexPtrs,
}

impl Index {
    pub(crate) fn new(dirpath: &std::path::PathBuf, cfg: &GraveConfig) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);

        // NOTE: Index file is initialized as, Metadata + min 1 BitMap Block + 1 AdjArr Block
        let num_block = if cfg.num_block <= 1 {
            MIN_BLOCKS_ON_INIT
        } else {
            cfg.num_block + 1
        };
        let meta = Metadata::new(cfg, num_block as u32);
        let file_len = METADATA_SIZE + (num_block * BLOCK_SIZE);

        // S1: New file (creation + prep)
        let file = OsFile::new(&filepath)?;
        file.zero_extend(file_len).map_err(|e| {
            // as `zero_extend` operation is not atomic, we clear up the created file,
            // so new init call would process correctly!
            Self::clear_file(&file, &filepath);
            e
        })?;

        // S2: MMap file & write new meta
        let mmap = MemMap::map(&file, file_len).map_err(|e| {
            // we clear up the created file, so new init call would process correctly!
            Self::clear_file(&file, &filepath);
            e
        })?;
        mmap.writer::<Metadata>(METADATA_OFF).write(|m| *m = meta);

        // S3: create init block ptrs + prep block headers
        for block_idx in 0..num_block {
            let off = METADATA_SIZE + block_idx * BLOCK_SIZE;
            let writer = mmap.writer::<BlockHeader>(off);

            // first bitmap
            if block_idx == DEFAULT_BITMAP_IDX {
                let next = if num_block > 2 { 2 } else { 0 };
                writer.write(|h| *h = BlockHeader::new(BlockHeaderFlag::BITMAP, next as u32));
                continue;
            }

            // first adjarr
            if block_idx == DEFAULT_BITMAP_IDX {
                writer.write(|h| {
                    *h = BlockHeader::new(
                        BlockHeaderFlag::ADJARR,
                        0, // next is null, as we only create one adjarr block on init
                    )
                });
                continue;
            }

            let next = if block_idx + 1 < num_block {
                (block_idx + 1) as u32
            } else {
                0
            };
            writer.write(|h| *h = BlockHeader::new(BlockHeaderFlag::BITMAP, next));
        }

        Ok(Self {
            ptrs: IndexPtrs::new(&mmap),
            file,
            mmap,
        })
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
            // NOTE: Closing the file to avoid resource leak on error path. This is important
            // becuase, as the [`Index`] was never fully constructed, so drop is never called.
            //
            // HACK: We consume the close error as we are already in an errored state, and the og
            // error should get more priority
            let _ = file.close();

            return Err(GraveError::InvalidState(format!(
                "Index file has invalid len={file_len}"
            )));
        }

        // S3: MMap file
        let mmap = MemMap::map(&file, file_len).map_err(|e| {
            // same as above
            let _ = file.close();
            e
        })?;

        // S4: Read & Validate Metadata
        let meta_reader = mmap.reader::<Metadata>(METADATA_OFF);
        let metadata = meta_reader.read();
        if metadata.version != VERSION || metadata.magic != MAGIC {
            // same as above
            let _ = file.close();
            return Err(GraveError::InvalidState("Invalid metadata for Index file".into()));
        }

        Ok(Self {
            ptrs: IndexPtrs::new(&mmap),
            file,
            mmap,
        })
    }

    pub(crate) const fn current_capacity(&self) -> usize {
        unsafe { (*self.ptrs.meta).current_cap as usize }
    }

    pub(crate) const fn total_entries(&self) -> usize {
        unsafe { (*self.ptrs.meta).total_entries as usize }
    }

    fn grow(&self) -> GraveResult<()> {
        // unmap the current mmap, then grow file and then re-map again

        // 2x of the current size of blocks, e.g. 2 => 4 blocks, etc.
        let new_file_len = {
            let curr = self.file.len()?;
            curr + (curr - METADATA_SIZE)
        };

        self.file.zero_extend(new_file_len)?;
        self.mmap.unmap()?;

        let new_map = MemMap::map(&self.file, new_file_len)?;

        Ok(())
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
// Index Pointers
//

#[derive(Debug)]
struct IndexPtrs {
    meta: *mut Metadata,
    bitmap: *mut BitMap,
    adjarr: *mut AdjArr,
}

impl IndexPtrs {
    fn new(mmap: &MemMap) -> Self {
        Self {
            meta: mmap.get_mut::<Metadata>(METADATA_OFF),
            bitmap: mmap.get_mut::<BitMap>(METADATA_SIZE + (DEFAULT_BITMAP_IDX * BLOCK_SIZE)),
            adjarr: mmap.get_mut::<AdjArr>(METADATA_SIZE + (DEFAULT_ADJARR_IDX * BLOCK_SIZE)),
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
    num_block: u32,
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
    const fn new(cfg: &GraveConfig, num_block: u32) -> Self {
        Self {
            num_block,
            magic: MAGIC,
            version: VERSION,
            total_entries: 0,
            page_size: cfg.page_size.to_u32(),
            bitmap_idx: DEFAULT_BITMAP_IDX as u32,
            adjarr_idx: DEFAULT_ADJARR_IDX as u32,
            current_cap: (cfg.num_block * PAGES_PER_BLOCK) as u64,
            _padd: [0u8; 0x18],
        }
    }
}

//
// Block Header
//

#[repr(u8)]
#[derive(Debug, PartialEq, Clone)]
enum BlockHeaderFlag {
    BITMAP = 0,
    ADJARR = 1,
}

impl BlockHeaderFlag {
    #[inline]
    const fn new(byte: u8) -> Self {
        // sanity check
        debug_assert!(byte <= 1, "invalid flag byte");
        unsafe { core::mem::transmute(byte) }
    }

    #[inline]
    fn is_bitmap(self) -> bool {
        self == Self::BITMAP
    }

    #[inline]
    fn is_adjarr(self) -> bool {
        self == Self::ADJARR
    }
}

/// Header containing metadata for BitMap or AdjArr
///
/// ## Structure
///
/// - [0 (0th bit)] => flag (1 bit)
/// - [0 (1..7 bits), 1, 2, 3 (half)] => next page idx (27 bits)
/// - [3 (half), 4] => total free (12 bits)
/// - [5] =>  current pointer (8 bits)
///
/// ## Repr
///
/// - `flag`: u8 w/ all 8 bits in use
/// - `next_page_index`: u32 w/ only lower 27 bits in use
/// - `total_free`: u16 w/ only lower 12 bits in use
/// - `current_pointer`: u8 w/ all 8 bits in use
#[repr(transparent)]
struct BlockHeader([u8; 6]);

impl BlockHeader {
    #[inline]
    fn new(flag: BlockHeaderFlag, next_index: u32) -> Self {
        // sanity check
        debug_assert!(next_index <= 0x07FF_FFFF, "nidx overflow (27 bits)");

        let total_free = if flag == BlockHeaderFlag::BITMAP {
            PAGES_PER_BLOCK
        } else {
            AARR_PER_BLOCK
        };

        Self([
            ((flag as u8 & 0x01) << 7) as u8 | ((next_index >> 0x14) as u8 & 0x7F),
            ((next_index >> 12) & 0xFF) as u8,
            ((next_index >> 4) & 0xFF) as u8,
            (((next_index & 0x0F) << 4) as u8) | ((total_free >> 8) as u8 & 0x0F),
            (total_free & 0xFF) as u8,
            0u8, // current_ptr (always starts from 0)
        ])
    }

    #[inline]
    fn is_bitmap(&self) -> bool {
        let byte = self.0[0] >> 7;
        let flag = BlockHeaderFlag::new(byte);
        flag.is_bitmap()
    }

    #[inline]
    fn is_adjarr(&self) -> bool {
        let byte = self.0[0] >> 7;
        let flag = BlockHeaderFlag::new(byte);
        flag.is_adjarr()
    }

    #[inline]
    const fn get_cptr(&self) -> u8 {
        self.0[5]
    }

    #[inline]
    const fn get_free(&self) -> u16 {
        ((self.0[3] as u16 & 0x0F) << 8) | (self.0[4] as u16)
    }

    #[inline]
    const fn get_nidx(&self) -> u32 {
        ((self.0[0] as u32 & 0x7F) << 0x14)
            | ((self.0[1] as u32) << 12)
            | ((self.0[2] as u32) << 4)
            | ((self.0[3] as u32 >> 4) & 15)
    }

    #[inline]
    const fn set_cptr(&mut self, cptr: u8) {
        self.0[5] = cptr;
    }

    #[inline]
    const fn decr_free(&mut self, slots: u16) {
        let old = self.get_free();
        let new = old - slots;

        // sanity check
        debug_assert!(slots <= old, "free underflow");
        debug_assert!(new <= 0x0FFF, "free overflow");

        self.0[3] = (self.0[3] & 0xF0) | ((new >> 8) as u8 & 0x0F);
        self.0[4] = (new & 0xFF) as u8;
    }

    #[inline]
    const fn set_nidx(&mut self, nidx: u32) {
        debug_assert!(nidx <= 0x07FF_FFFF, "nidx overflow (27 bits)");

        self.0[0] = (self.0[0] & 0x80) | ((nidx >> 0x14) as u8 & 0x7F);
        self.0[1] = ((nidx >> 12) & 0xFF) as u8;
        self.0[2] = ((nidx >> 4) & 0xFF) as u8;
        self.0[3] = (self.0[3] & 0x0F) | (((nidx & 0x0F) << 4) as u8);
    }
}

//
// BitMap
//

const BITMAP_WORDS_PER_BLOCK: usize = (BLOCK_SIZE - BLOCK_HEADER_SIZE) / 2;

#[repr(C)]
struct BitMap {
    header: BlockHeader,
    words: [u16; BITMAP_WORDS_PER_BLOCK],
}

// sanity check
const _: () = assert!(std::mem::size_of::<BitMap>() == BLOCK_SIZE);

//
// AdjArr
//

const AARR_PER_BLOCK: usize = 0x15;

#[repr(transparent)]
struct AArrHead([u8; 6]);

#[repr(transparent)]
struct AArrEntry([u8; 6]);

/// Adjcent array
///
/// ## Structure
///
/// - Head (6 bytes) [`AArrHead`] (at 0th idx)
/// - Entry (6 bytes) [`AArrEntry`] (3 per array, 1..=3)
#[repr(transparent)]
struct AArr([[u8; 6]; 4]);

#[repr(C)]
struct AdjArr {
    header: BlockHeader,
    arrays: [AArr; AARR_PER_BLOCK],
    _padd: [u8; 2],
}

// sanity check
const _: () = assert!(std::mem::size_of::<AdjArr>() == BLOCK_SIZE);
