const DEFAULT_PAGE_SIZE: GraveConfigValue = GraveConfigValue::N64;
const DEFAULT_INIT_CAP: GraveConfigValue = GraveConfigValue::N256;
const DEFAULT_MEM_POOL_CAP: GraveConfigValue = GraveConfigValue::N64;

// sanity check
const _: () = assert!(DEFAULT_INIT_CAP.to_u32() >= 0x100, "INIT_CAP must be >= 256");
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
///  | memory_pool_capacity   | 64 units   |
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
///   page_size: GraveConfigValue::N128,
///   initial_capacity: GraveConfigValue::N4096,
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

    /// Controls the **initial number of on-disk pages** allocated for [`Grave`].
    ///
    /// Each unit represents _one on-disk page_. The size of each page is defined
    /// by [`page_size`].
    ///
    /// ## Working
    ///
    /// - On initialization, [`Grave`] pre-allocates N pages on disk
    /// - Write operations consume these pages as data is written
    /// - When all pages are exhausted, [`Grave`] grows the on-disk storage, haulting upcoming
    ///   write operations for a short while
    ///
    /// ## Growth & Write Latency
    ///
    /// If the on-disk pages are exhausted, storage growth is triggered, which triggers file expansion,
    /// which temporarily increase overall write latency.
    ///
    /// To avoid growth, where higher write frequency is expected, configure `initial_capacity` w/ a
    /// large enough value to avoid growth trigger.
    ///
    /// ## Disk Usage
    ///
    /// This value defines the **minimum disk space** reserved by [`Grave`],
    ///
    /// ```text
    /// min_disk_usage = initial_capacity * page_size
    /// ```
    ///
    /// Disk usage grows beyond this only when required.
    ///
    /// # Example
    ///
    /// ```
    /// use grave::{GraveConfig, GraveConfigValue};
    ///
    /// let cfg = GraveConfig {
    ///   initial_capacity: GraveConfigValue::N4096,
    ///   ..Default::default()
    /// };
    /// ```
    pub initial_capacity: GraveConfigValue,
}

impl Default for GraveConfig {
    /// Default set of configurations used for [`Grave`].
    ///
    /// ## Config
    ///
    /// ```md
    ///  | Field                  | Value      |
    ///  |----------------------- |------------|
    ///  | page_size              | 32 bytes   |
    ///  | memory_pool_capacity   | 64 units   |
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
    /// let cfg = GraveConfig::default();
    /// ```
    fn default() -> Self {
        Self {
            memory_pool_capacity: DEFAULT_MEM_POOL_CAP,
            page_size: DEFAULT_PAGE_SIZE,
            initial_capacity: DEFAULT_INIT_CAP,
        }
    }
}

/// Discrete, power-of-two configuration values used for [`GraveConfig`].
///
/// Each variant maps to a concrete numeric value (in bytes or in units).
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
///   page_size: GraveConfigValue::N128,
///   initial_capacity: GraveConfigValue::N4096,
///   memory_pool_capacity: GraveConfigValue::N128,
/// };
/// ```
#[derive(Debug, PartialEq, Clone)]
pub enum GraveConfigValue {
    /// 8 units
    N8,

    /// 0x10 units
    N16,

    /// 0x20 units
    N32,

    /// 0x40 units
    N64,

    /// 0x80 units
    N128,

    /// 0x100 units
    N256,

    /// 0x200 units
    N512,

    /// 0x400 units
    N1024,

    /// 0x800 units
    N2048,

    /// 0x1000 units
    N4096,

    /// 0x2000 units
    N8192,

    /// 0x4000 units
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

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct InternalConfig {
    pub(crate) memory_pool_size: usize,
    pub(crate) dirpath: std::path::PathBuf,
    pub(crate) page_size: GraveConfigValue,
    pub(crate) initial_capacity: GraveConfigValue,
}
