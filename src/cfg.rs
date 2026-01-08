const DEFAULT_NUM_BLOCK: usize = 1;
const DEFAULT_PAGE_SIZE: GraveConfigValue = GraveConfigValue::N64;
const DEFAULT_MEM_POOL_CAP: GraveConfigValue = GraveConfigValue::N64;

// sanity check
const _: () = assert!(DEFAULT_NUM_BLOCK > 0, "NUM_BLOCK must be > 0");
const _: () = assert!(DEFAULT_PAGE_SIZE.to_u32() >= 8, "PAGE_SIZE must be >= 8 bytes");
const _: () = assert!(DEFAULT_MEM_POOL_CAP.to_u32() >= 8, "MEM_POOL_CAP must be >= 8 slots");

/// Configurations used for [`Grave`].
///
/// [`GraveConfig`] defines all the tuneable behaviour for the [`Grave`].
///
/// ## Default Config
///
/// ```md
///  | Field                  | Value      |
///  |----------------------- |------------|
///  | num_block              | 01 block   |
///  | page_size              | 32 bytes   |
///  | initial_capacity       | 256 units  |
/// ```
///
/// Which result in follow memory and disk usage,
///
/// - **in-memory: 64 * 32 = 2048 bytes (2 KiB)**
/// - **on-disk: 256 * 32 = 8192 bytes (8 KiB)**
///
/// # Example
///
/// ```
/// use grave::{GraveConfig, GraveConfigValue};
///
/// let cfg = GraveConfig {
///   num_block: 4usize,
///   page_size: GraveConfigValue::N128,
///   memory_pool_capacity: GraveConfigValue::N128,
/// };
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct GraveConfig {
    /// Controls the **number of in-memory pages** available to use for write operations
    ///
    /// Each unit represents _one page in memory_. The size of each page is defined by `page_size`.
    ///
    /// ## Working
    ///
    /// - Write operations consumes N in-memory pages, as required
    /// - After I/O completion, a background thread frees these pages
    /// - For a new write, if no new page is available, they are **polled**, increasing write latency
    ///
    /// ## Write Latency
    ///
    /// Larger writes span across more in-memory pages. If all available pages are already consumed,
    /// subsequent writes will have to wait until any of pages are freed.
    ///
    /// To reduce latency for larger writes, or higher write frequency, use larger value,
    /// e.g. `memory_pool_capacity = GraveConfigValue::N1024`, which will give `1024` pages to work with.
    ///
    /// ## Memory Overhead
    ///
    /// This value also **caps the total memory usage** of [`Grave`],
    ///
    /// ```text
    /// max_memory = memory_pool_capacity * page_size
    /// ```
    ///
    /// This makes memory usage predictable and fully configurable.
    ///
    /// e.g. when `memory_pool_size = GraveConfigValue::N32` and `page_size = GraveConfigValue::N64`,
    /// you get _32 pages_, each of _64 bytes_, resulting in _32 * 64 = 2048 bytes_ in memory which is
    /// exactly 2 KiB
    ///
    /// ## Why
    ///
    /// By design, all the write operations are fire-and-forget, offcourse only when kernel support is there,
    /// which means you make call to write operation and exit rightaway, and not wait for the completion.
    ///
    /// To enable this, [`Grave`] uses an in-memory buffer pool, which stores the raw data till it's completely
    /// written on disk, which makes sure, raw data is pinned in memory till the I/O operation is completed.
    ///
    /// # Example
    ///
    /// ```
    /// use grave::{GraveConfig, GraveConfigValue};
    ///
    /// let cfg = GraveConfig {
    ///   memory_pool_capacity: GraveConfigValue::N128,
    ///   ..Default::default()
    /// };
    /// ```
    pub memory_pool_capacity: GraveConfigValue,

    /// Controls **on disk page size** used to store raw data in [`Grave`]
    ///
    /// Internally, all raw data stored on disk is paged, e.g if you write `[0u8; 0x40]`
    /// and `page_size = GraveConfigValye::N32`, your data would be stored across _4 pages_,
    /// hence will take 4 empty slots.
    ///
    /// Unaligned write buffers are also paged, e.g. if you write `[0u8; 0x2A]` w/
    /// `page_size = GraveConfigValue::N32`, it'd be stored across _2 pages_, and will take
    /// 2 empty slots.
    ///
    /// ## Structure
    ///
    /// For a given `page_size = GraveConfigValue::N32`, on-disk structure is as follows,
    ///
    /// ```md
    ///  | Offset  | Size (bytes) | Field          |
    ///  |-------- |--------------|----------------|
    ///  | 0       | 4            | CRC32 Checksum |
    ///  | 4       | 0x1C         | Raw Data       |
    ///  ```
    ///
    /// ## Why
    ///
    /// By setting `page_size` according to your need, you could optimize space used by your
    /// writes.
    ///
    /// e.g. If you usually write large buffers, you should use large `page_size` to optimize
    /// performance and resource, and vice-versa for smaller buffers.
    ///
    /// ## Requirements
    ///
    /// For internal optimizations, `page_size` must be a power of 2 value and must be `>= 8` bytes
    ///
    /// # Example
    ///
    /// ```
    /// use grave::{GraveConfig, GraveConfigValue};
    ///
    /// let cfg = GraveConfig {
    ///   page_size: GraveConfigValue::N128,
    ///   ..Default::default()
    /// };
    /// ```
    pub page_size: GraveConfigValue,

    /// Controls the **initial number of blocks** created for [`Grave`] before any growth is triggered.
    ///
    /// Each block contains **4048 on-disk pages**, and creates **512 bytes** of memory overhead per block.
    ///
    /// ## Working of Block
    ///
    /// - On init, [`Grave`] pre-allocates N pages on disk, **4048 entries** per block
    /// - Write operations consume these pages as data is written on disk
    /// - When all pages are exhausted, [`Grave`] haults all write/read operations for a short while,
    ///   to grow the on-disk storage
    ///
    /// ## Growth & Write/Read Latency
    ///
    /// If the on-disk pages are exhausted, storage growth is triggered, which calls for file expansion.
    ///
    /// The growth process temporarily increase overall write/read latency.
    ///
    /// To avoid growth, where higher write frequency is expected, configure `num_block` w/ a
    /// large enough value, which would avoid frequent growth, decreasing operation latency.
    ///
    /// ## Block Overhead (On-Disk + Memory)
    ///
    /// For a given `num_block = 1` & `page_size = 64`,
    ///
    /// ```md
    /// > memory_usage => 512 bytes # 0.5 KiB
    /// > disk_usage => (64 * 4048) + 512 # 259584 bytes (253.5 KiB)
    /// ```
    ///
    /// Both Memory + Disk usage _grows beyond this_ only when required.
    ///
    /// # Example
    ///
    /// ```
    /// use grave::{GraveConfig, GraveConfigValue};
    ///
    /// let cfg = GraveConfig {
    ///   num_block: 4usize,
    ///   ..Default::default()
    /// };
    /// ```
    pub num_block: usize,
}

impl Default for GraveConfig {
    /// Default set of configurations used for [`Grave`].
    ///
    /// ## Config
    ///
    /// ```md
    ///  | Field                  | Value      |
    ///  |----------------------- |------------|
    ///  | num_block              | 01 block   |
    ///  | page_size              | 32 bytes   |
    ///  | memory_pool_capacity   | 64 units   |
    /// ```
    ///
    /// Which results in follow memory and disk usage,
    ///
    /// - **in-memory: (64 * 32) + 512 = 2560 bytes (2.5 KiB)**
    /// - **on-disk: (256 * 32) + 512 = 8704 bytes (8.5 KiB)**
    ///
    /// # Example
    ///
    /// ```
    /// use grave::{GraveConfig, GraveConfigValue};
    ///
    /// let cfg = GraveConfig::default();
    /// ```
    fn default() -> Self {
        Self {
            num_block: DEFAULT_NUM_BLOCK,
            page_size: DEFAULT_PAGE_SIZE,
            memory_pool_capacity: DEFAULT_MEM_POOL_CAP,
        }
    }
}

/// Discrete, power-of-two configuration values used for [`GraveConfig`].
///
/// Each variant maps to a concrete numeric value (units/bytes).
///
/// ## Why
///
/// Internally, [`Grave`] requires power-of-two values, for various optimizations.
///
/// The use of **ENUM** enables, compile-time validations, and keeps config explicit
/// and self documenting.
///
/// # Example
///
/// ```
/// use grave::{GraveConfig, GraveConfigValue};
///
/// let cfg = GraveConfig {
///   num_block: 4usize,
///   page_size: GraveConfigValue::N128,
///   memory_pool_capacity: GraveConfigValue::N128,
/// };
/// ```
#[derive(Debug, PartialEq, Clone)]
pub enum GraveConfigValue {
    /// 8 units/bytes
    N8,

    /// 0x10 units/bytes
    N16,

    /// 0x20 units/bytes
    N32,

    /// 0x40 units/bytes
    N64,

    /// 0x80 units/bytes
    N128,

    /// 0x100 units/bytes
    N256,

    /// 0x200 units/bytes
    N512,

    /// 0x400 units/bytes
    N1024,

    /// 0x800 units/bytes
    N2048,

    /// 0x1000 units/bytes
    N4096,

    /// 0x2000 units/bytes
    N8192,

    /// 0x4000 units/bytes
    N16384,
}

impl GraveConfigValue {
    #[inline]
    pub(crate) const fn to_u32(&self) -> u32 {
        match self {
            Self::N8 => 8,
            Self::N16 => 0x10,
            Self::N32 => 0x20,
            Self::N64 => 0x40,
            Self::N128 => 0x80,
            Self::N256 => 0x100,
            Self::N512 => 0x200,
            Self::N1024 => 0x400,
            Self::N2048 => 0x800,
            Self::N4096 => 0x1000,
            Self::N8192 => 0x2000,
            Self::N16384 => 0x4000,
        }
    }
}
