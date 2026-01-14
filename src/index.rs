use crate::{
    common,
    file::OsFile,
    mmap::{MemMap, MemMapReader},
    GraveConfig, GraveError, GraveResult,
};
use std::{cell::UnsafeCell, sync::RwLock};

const VERSION: u32 = 0;
const MAGIC: [u8; 4] = *b"indx";
const PATH: &'static str = "index";

const MAP_FLUSH_MODE: common::IOFlushMode = common::IOFlushMode::Background;
const FILE_FLUSH_MODE: common::IOFlushMode = common::IOFlushMode::Manual;

// NOTE: When this values are updated, all the docs must be updated accordingly
// for [`GraveConfig`], w/ corrected calculations for Memory and Disk overheads.

const BLOCK_SIZE: usize = 0x200;
const MIN_BLOCKS_ON_INIT: usize = 2;
const DEFAULT_BITMAP_IDX: usize = 0;
const DEFAULT_ADJARR_IDX: usize = 1;
const BLOCK_HEADER_SIZE: usize = std::mem::size_of::<BlockHeader>();
const PAGES_PER_BLOCK: usize = (BLOCK_SIZE - BLOCK_HEADER_SIZE) * 8;

const MAX_CURRNET_PTR: u8 = 0xFF; // 8 bits  (0..=255)
const MAX_FREE_PER_BLOCK: u16 = 0x0FFF; // 12 bits (0..=4095)
const MAX_NUM_SLOTS: u32 = 0x00FF_FFFF; // 24 bits (0..=16,777,215)
const MAX_PAGE_INDEX: u32 = 0x07FF_FFFF; // 27 bits (0..=134,217,727)

// sanity checks
const _: () = assert!(BLOCK_HEADER_SIZE == std::mem::size_of::<BlockHeader>());
const _: () = assert!(PAGES_PER_BLOCK == 0xFD0, "each block must contain 4048 pages");
const _: () = assert!(MIN_BLOCKS_ON_INIT >= 2, "Must be space for BitMap and AdjArr block");

#[derive(Debug)]
pub(crate) struct Index {
    file: OsFile,
    lock: RwLock<()>,
    mmap: UnsafeCell<MemMap>,
}

unsafe impl Send for Index {}
unsafe impl Sync for Index {}

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
        let file = OsFile::new(&filepath, FILE_FLUSH_MODE)?;
        file.zero_extend(file_len).map_err(|e| {
            // as `zero_extend` operation is not atomic, we clear up the created file,
            // so new init call would process correctly!
            Self::clear_file(&file, &filepath);
            e
        })?;

        // S2: MMap file & write new meta
        let mmap = MemMap::map(&file, file_len, MAP_FLUSH_MODE).map_err(|e| {
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
            if block_idx == DEFAULT_ADJARR_IDX {
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
            file,
            lock: RwLock::new(()),
            mmap: UnsafeCell::new(mmap),
        })
    }

    pub(crate) fn open(dirpath: &std::path::PathBuf) -> GraveResult<Self> {
        let filepath = dirpath.join(PATH);

        // S1: Open existing file
        let file = OsFile::open(&filepath, FILE_FLUSH_MODE)?;

        // S2: Read and validate len
        let file_len = file.len()?;
        if file_len <= METADATA_SIZE || (file_len - METADATA_SIZE) % BLOCK_SIZE != 0 {
            return Err(GraveError::InvalidState(format!(
                "Index file has invalid len={file_len}"
            )));
        }

        // S3: MMap file
        let mmap = MemMap::map(&file, file_len, MAP_FLUSH_MODE)?;

        // S4: Read & Validate Metadata
        let meta_reader = mmap.reader::<Metadata>(METADATA_OFF);
        meta_reader.read(|meta| {
            if meta.version != VERSION || meta.magic != MAGIC {
                return Err(GraveError::InvalidState("Invalid metadata for Index file".into()));
            }
            return Ok(());
        })?;

        Ok(Self {
            mmap: UnsafeCell::new(mmap),
            lock: RwLock::new(()),
            file,
        })
    }

    #[inline]
    pub(crate) fn alloc_single_slot(&self) -> GraveResult<TGraveOff> {
        loop {
            // PHASE 1: scan existing bitmap chain
            {
                let _r = self.lock.read()?;

                // FIX: Start from the beginning (Head), not the Tail.
                // This ensures we fill holes and traverse the linked list correctly
                // to reach the new block added by grow().
                let mut block_idx = DEFAULT_BITMAP_IDX as u32;

                loop {
                    let off = METADATA_SIZE + block_idx as usize * BLOCK_SIZE;

                    // We need to be careful not to read OOB if the file was just grown
                    // and we are chasing pointers faster than the mmap view updates,
                    // but the lock protects us here.
                    let writer = unsafe { (*self.mmap.get()).writer::<BitMap>(off) };

                    if let Some(slot_idx) = writer.write(|b| b.alloc_single()) {
                        let off = GraveOff {
                            flag: 0,
                            block_idx,
                            slot_idx,
                            num_slots: 1,
                        };
                        return Ok(off.encode());
                    }

                    // walk bitmap chain
                    let next = unsafe { (*self.mmap.get()).reader::<BlockHeader>(off).read(|h| h.get_nidx()) };

                    if next == 0 {
                        break; // exhausted all bitmap blocks
                    }

                    block_idx = next;
                }
            }

            // PHASE 2: no space anywhere -> grow & retry
            self.grow(GrowKind::BitMap)?;
        }
    }

    #[inline]
    pub(crate) fn free_single_slot(&self, off: TGraveOff) -> GraveResult<()> {
        // allow parallel frees
        let _r = self.lock.read()?;

        let grave_off = GraveOff::decode(off);
        let block_off = METADATA_SIZE + grave_off.block_idx as usize * BLOCK_SIZE;

        let writer = unsafe { (*self.mmap.get()).writer::<BitMap>(block_off) };
        writer.write(|b| {
            debug_assert!(grave_off.num_slots == 1, "range free not implemented yet");
            b.free_single(grave_off.slot_idx);
        });

        Ok(())
    }

    fn is_tail_block_full_nolock(&self, kind: GrowKind) -> bool {
        let (bmap_tail_idx, aarr_tail_idx) = self.meta_read(|a| (a.bmap_tail_idx, a.aarr_tail_idx));
        let block_offset = match kind {
            GrowKind::BitMap => METADATA_SIZE + (bmap_tail_idx as usize * BLOCK_SIZE),
            GrowKind::AdjArr => METADATA_SIZE + (aarr_tail_idx as usize * BLOCK_SIZE),
        };

        let reader = unsafe { (*self.mmap.get()).reader::<BlockHeader>(block_offset) };
        let free_count = reader.read(|header| header.get_free());

        free_count == 0
    }

    fn is_tail_block_full(&self, kind: GrowKind) -> GraveResult<bool> {
        let _r = self.lock.read()?;
        Ok(self.is_tail_block_full_nolock(kind))
    }

    fn grow(&self, kind: GrowKind) -> GraveResult<()> {
        // NOTE: ensures block has no space left to avoid TOCTOU situations
        if !self.is_tail_block_full(kind)? {
            return Ok(());
        }

        // NOTE: Both lock guards are RAII, and are unlocked when the values are dropped
        let _write_guard = self.lock.write()?; // process-wide exclusion
        let _file_guard = self.file.lock()?; // cross-process exclusion

        // re-check under exclusive access
        //
        // NOTE: stronger validations are theere to prevent allocating more then required resources
        if !self.is_tail_block_full_nolock(kind) {
            return Ok(());
        }

        // NOTE: the file locks are RAII, hence the underlying resource is released
        // automatically when the value is dropped. So, We just ball ^0^

        self.grow_locked(kind)
    }

    fn grow_locked(&self, kind: GrowKind) -> GraveResult<()> {
        // S0: Get an exclusive (cross-process) access to [`Index`]
        let mmap = unsafe { &mut *self.mmap.get() };

        // S1: calc new len (extended) for file
        let old_len = self.file.len()?;
        let old_blocks = (old_len - METADATA_SIZE) / BLOCK_SIZE;
        let new_block_idx = old_blocks as u32;
        let new_len = old_len + BLOCK_SIZE;

        // sanity check
        debug_assert!(new_block_idx <= MAX_PAGE_INDEX, "block index overflow");

        // S2: Unmap, Extend, Remap (SAFETY FIX)
        // ---------------------------------------------------------
        // We use unsafe ptr::read/write to manage the lifecycle manually.
        // 1. Read the old map out (ownership moves to `old_map`).
        //    The `mmap` reference now points to uninitialized memory temporarily.
        let old_map = unsafe { std::ptr::read(mmap) };

        // 2. Drop the old map. This triggers the underlying munmap ONCE.
        drop(old_map);

        // 3. Now it is safe to resize the file.
        self.file.zero_extend(new_len)?;
        self.file.sync()?;

        // 4. Create the new mapping.
        let new_map = MemMap::map(&self.file, new_len, MAP_FLUSH_MODE)?;

        // 5. Write the new map back into the reference.
        //    We use ptr::write to avoid trying to Drop the garbage
        //    that was sitting in `mmap` (since we moved it out in step 1).
        unsafe { std::ptr::write(mmap, new_map) };
        // ---------------------------------------------------------

        // S3: update current & new tail
        // (This logic remains exactly the same as your previous code)
        let meta = mmap.reader::<Metadata>(METADATA_OFF);
        let (tail_idx, flag) = meta.read(|meta| match kind {
            GrowKind::BitMap => (unsafe { (*meta).bmap_tail_idx }, BlockHeaderFlag::BITMAP),
            GrowKind::AdjArr => (unsafe { (*meta).aarr_tail_idx }, BlockHeaderFlag::ADJARR),
        });

        let old_tail_off = METADATA_SIZE + tail_idx as usize * BLOCK_SIZE;
        let new_tail_off = METADATA_SIZE + new_block_idx as usize * BLOCK_SIZE;

        mmap.writer::<BlockHeader>(old_tail_off)
            .write(|header| header.set_nidx(new_block_idx));
        mmap.writer::<BlockHeader>(new_tail_off)
            .write(|h| *h = BlockHeader::new(flag, 0));

        // S4: Update metadata & rebuild index pointers
        unsafe {
            self.meta_write(|meta| {
                match kind {
                    GrowKind::BitMap => {
                        meta.current_cap += PAGES_PER_BLOCK as u64;
                        meta.bmap_tail_idx = new_block_idx;
                    }
                    GrowKind::AdjArr => {
                        meta.aarr_tail_idx = new_block_idx;
                    }
                }
                meta.num_block += 1;
            });
        }

        Ok(())
    }

    #[inline]
    fn meta_read<R>(&self, f: impl FnOnce(&Metadata) -> R) -> R {
        unsafe { (*self.mmap.get()).reader::<Metadata>(METADATA_OFF).read(f) }
    }

    #[inline]
    fn meta_write<R>(&self, f: impl FnOnce(&mut Metadata) -> R) -> R {
        unsafe { (*self.mmap.get()).writer::<Metadata>(METADATA_OFF).write(f) }
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

//
// Grow Kinds
//

#[derive(Debug, PartialEq, Clone, Copy)]
enum GrowKind {
    BitMap,
    AdjArr,
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
    bmap_tail_idx: u32,
    aarr_tail_idx: u32,
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
            bmap_tail_idx: DEFAULT_BITMAP_IDX as u32,
            aarr_tail_idx: DEFAULT_ADJARR_IDX as u32,
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
    const fn incr_free(&mut self, slots: u16) {
        let old = self.get_free();
        let new = old + slots;

        // sanity check
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
// Grave Offset
//

pub(crate) type TGraveOff = u64;

#[derive(Debug)]
pub(crate) struct GraveOff {
    flag: u8, // 0 or 1
    block_idx: u32,
    slot_idx: u16,
    num_slots: u32,
}

impl GraveOff {
    const FLAG_BITS: u64 = 1;
    const BLOCK_IDX_BITS: u64 = 27;
    const SLOT_IDX_BITS: u64 = 12;
    const NUM_SLOTS_BITS: u64 = 24;

    const NUM_SLOTS_MASK: u64 = (1u64 << Self::NUM_SLOTS_BITS) - 1;
    const SLOT_IDX_MASK: u64 = (1u64 << Self::SLOT_IDX_BITS) - 1;
    const BLOCK_IDX_MASK: u64 = (1u64 << Self::BLOCK_IDX_BITS) - 1;
    const FLAG_MASK: u64 = 1;

    const NUM_SLOTS_SHIFT: u64 = 0;
    const SLOT_IDX_SHIFT: u64 = Self::NUM_SLOTS_BITS;
    const BLOCK_IDX_SHIFT: u64 = Self::NUM_SLOTS_BITS + Self::SLOT_IDX_BITS;
    const FLAG_SHIFT: u64 = Self::NUM_SLOTS_BITS + Self::SLOT_IDX_BITS + Self::BLOCK_IDX_BITS;

    #[inline]
    pub(crate) fn encode(&self) -> TGraveOff {
        debug_assert!(self.flag <= 1);
        debug_assert!(self.num_slots > 0);
        debug_assert!(self.block_idx <= MAX_PAGE_INDEX);
        debug_assert!((self.slot_idx as usize) < PAGES_PER_BLOCK);
        debug_assert!((self.num_slots as u64) <= Self::NUM_SLOTS_MASK);

        ((self.flag as u64 & Self::FLAG_MASK) << Self::FLAG_SHIFT)
            | ((self.block_idx as u64 & Self::BLOCK_IDX_MASK) << Self::BLOCK_IDX_SHIFT)
            | ((self.slot_idx as u64 & Self::SLOT_IDX_MASK) << Self::SLOT_IDX_SHIFT)
            | (self.num_slots as u64 & Self::NUM_SLOTS_MASK)
    }

    #[inline]
    pub(crate) fn decode(off: TGraveOff) -> Self {
        let flag = ((off >> Self::FLAG_SHIFT) & Self::FLAG_MASK) as u8;
        let block_idx = ((off >> Self::BLOCK_IDX_SHIFT) & Self::BLOCK_IDX_MASK) as u32;
        let slot_idx = ((off >> Self::SLOT_IDX_SHIFT) & Self::SLOT_IDX_MASK) as u16;
        let num_slots = (off & Self::NUM_SLOTS_MASK) as u32;

        debug_assert!(flag <= 1);
        debug_assert!(num_slots > 0);

        Self {
            flag,
            block_idx,
            slot_idx,
            num_slots,
        }
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

impl BitMap {
    #[inline]
    fn alloc_single(&mut self) -> Option<u16> {
        // sanity check
        debug_assert!(self.header.is_bitmap(), "Invalid block");

        // current block is full
        if common::unlikely(self.header.get_free() == 0) {
            return None;
        }

        let nwords = self.words.len();
        let start_word = self.header.get_cptr() as usize;

        for word_off in 0..nwords {
            let word_idx = (start_word + word_off) % nwords;
            let word = &mut self.words[word_idx];

            // curr_word is full (instant skip)
            if *word == u16::MAX {
                continue;
            }

            let free_bit = (!*word).trailing_zeros() as usize;
            let bit = 1u16 << free_bit;

            // sanity checks
            debug_assert!(word_idx <= MAX_CURRNET_PTR as usize);
            debug_assert!((*word & bit) == 0, "bitmap corruption");
            debug_assert!(free_bit < 0x10, "invalid trailing_zeros result");

            // free => used
            *word |= bit;
            self.header.decr_free(1);
            self.header.set_cptr(word_idx as u8);

            let slot = word_idx * 0x10 + free_bit;

            // sanity check
            debug_assert!(slot < PAGES_PER_BLOCK, "slot is OOB");

            return Some(slot as u16);
        }

        unreachable!()
    }

    #[inline]
    fn free_single(&mut self, slot: u16) {
        let free = self.header.get_free();
        let slot = slot as usize;
        let widx = slot / 0x10;
        let bit = slot % 0x10;
        let mask = 1u16 << bit;

        // sanity checks
        debug_assert!(slot < PAGES_PER_BLOCK, "slot is OOB");
        debug_assert!(self.header.is_bitmap(), "invalid block");
        debug_assert!(widx < self.words.len(), "word index OOB");
        debug_assert!(free < PAGES_PER_BLOCK as u16, "free overflow");

        let word = &mut self.words[widx];

        // sanity check
        debug_assert!((*word & mask) != 0, "double free or invalid slot");

        // used => free
        *word &= !mask;
        self.header.incr_free(1);
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    mod index {
        use super::*;

        #[test]
        fn new_works() {
            let tmp = TempDir::new().expect("tmp dir");
            let dir = tmp.path().to_path_buf();
            let cfg = GraveConfig::default();

            assert!(Index::new(&dir, &cfg).is_ok());
        }

        #[test]
        fn open_works() {
            let tmp = TempDir::new().expect("tmp dir");
            let dir = tmp.path().to_path_buf();
            let cfg = GraveConfig::default();

            {
                let _ = Index::new(&dir, &cfg).is_ok();
            }

            assert!(Index::open(&dir).is_ok());
        }

        #[test]
        fn open_fails_when_missing() {
            let tmp = TempDir::new().expect("tmp dir");
            let dir = tmp.path().to_path_buf();

            assert!(Index::open(&dir).is_err());
        }

        mod alloc_free {
            use super::*;

            #[test]
            fn alloc_free_cycle() {
                let tmp = TempDir::new().expect("tmp dir");
                let dir = tmp.path().to_path_buf();
                let cfg = GraveConfig::default();
                let idx = Index::new(&dir, &cfg).expect("new Index");

                let off = idx.alloc_single_slot().expect("alloc single");
                assert!(idx.free_single_slot(off).is_ok());
            }

            #[test]
            fn alloc_with_grow() {
                let tmp = TempDir::new().expect("tmp dir");
                let dir = tmp.path().to_path_buf();
                let cfg = GraveConfig::default();
                let idx = Index::new(&dir, &cfg).expect("new Index");

                let mut offs = Vec::new();

                // force bitmap exhaustion
                for _ in 0..(PAGES_PER_BLOCK + 8) {
                    offs.push(idx.alloc_single_slot().expect("alloc"));
                }

                assert!(offs.len() > PAGES_PER_BLOCK);
            }

            #[test]
            fn free_after_grow() {
                let tmp = TempDir::new().expect("tmp dir");
                let dir = tmp.path().to_path_buf();
                let cfg = GraveConfig::default();
                let idx = Index::new(&dir, &cfg).expect("new Index");

                let mut offs = Vec::new();
                for _ in 0..(PAGES_PER_BLOCK + 4) {
                    offs.push(idx.alloc_single_slot().unwrap());
                }

                for off in offs {
                    idx.free_single_slot(off).unwrap();
                }

                // should fully reuse
                let _ = idx.alloc_single_slot().unwrap();
            }
        }
    }
}
