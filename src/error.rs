/// A specialized result type for operations in [`Grave`]
pub type GraveResult<T> = Result<T, GraveError>;

/// A custom error object, which descibes errored state exposed by [`Grave`]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct GraveError {
    code: ErrorCode,
    cntx: &'static str,
}

impl GraveError {
    #[inline]
    pub const fn code(&self) -> u16 {
        self.code as u16
    }

    #[inline]
    pub const fn context(&self) -> &'static str {
        self.cntx
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ErrorCode {
    // I/O
    IOHcf = 0x100,
    IOUnk = 0x101,
    IONsp = 0x102,
    IONpm = 0x103,
    IOSnc = 0x104,

    // Internal
    INHcf = 0x200,
    INGrt = 0x201,

    // Multi threading
    MTHcf = 0x300,
    MTLoc = 0x301,

    // Misc
    GMisc = 0xFFFF,
}
