pub(super) const MAGIC: [u8; 4] = *b"GRV0";
pub(super) const VERSION: [u8; 4] = 0u32.to_le_bytes();

pub(super) const INDEX_PATH: &'static str = "index";
pub(super) const COFFIN_PATH: &'static str = "coffin";

pub(super) const PAGE_SIZE: usize = 0x400;

/// Maximum allowed page index with max 27 bits in use, i.e. 2^27 - 1
pub(super) const MAX_PAGE_INDEX: u32 = 0x07FF_FFFF;

// sanity cheks
const _: () = assert!(MAX_PAGE_INDEX <= u32::MAX);
const _: () = assert!(std::mem::size_of_val(&MAGIC) == 4);
const _: () = assert!(std::mem::size_of_val(&VERSION) == 4);
