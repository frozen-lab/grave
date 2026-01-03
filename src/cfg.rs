#[derive(Debug, PartialEq, Clone)]
pub struct GraveConfig {
    pub memory_pool_size: usize,
    pub page_size: GraveConfigValue,
    pub initial_capacity: GraveConfigValue,
}

#[derive(Debug, PartialEq, Clone)]
pub enum GraveConfigValue {
    N8,
    N16,
    N32,
    N64,
    N128,
    N256,
    N512,
    N1024,
    N2048,
    N4096,
    N8192,
    N16384,
}

impl GraveConfigValue {
    #[inline]
    pub(crate) const fn to_usize(&self) -> usize {
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
