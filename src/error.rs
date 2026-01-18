/// A specialized result type for operations in [`Grave`]
pub type GraveResult<T> = Result<T, GraveError>;

/// A custom error object, which descibes errored state exposed by [`Grave`]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GraveError {
    code: ErrorCode,
    cntx: String,
}

impl GraveError {
    /// Get the error code for [`GraveError`]
    #[inline]
    pub const fn code(&self) -> u16 {
        self.code as u16
    }

    /// Get context of the error for [`GraveError`]
    #[inline]
    pub const fn context(&self) -> &String {
        &self.cntx
    }
}

impl GraveError {
    #[inline]
    pub(crate) const fn new(code: ErrorCode, cntx: String) -> GraveError {
        Self { code, cntx }
    }

    #[inline]
    pub(crate) fn io_err<R>(code: ErrorCode, error: std::io::Error) -> GraveResult<R> {
        Err(Self {
            code,
            cntx: error.to_string(),
        })
    }
}

impl std::fmt::Display for GraveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GraveError {{code: {}, context: {}}}", self.code as u16, self.cntx)
    }
}

/// Error codes for internal use
///
/// ## HCF errors
///
/// HCF stands for Hault and Catch Fire, which indicates bad/invalid
/// implementation of systems, e.g. IO failure due to invalid file handle
#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ErrorCode {
    // path
    PHInv = 0x80, // 128

    // I/O Permissions
    PMWrt = 0x101, // 257

    // I/O
    IOHcf = 0x200, // 512
    IOUnk = 0x201, // 513
    IONsp = 0x202, // 514
    IOLck = 0x203, // 515
    IOEof = 0x204, // 516
    IOSyn = 0x205, // 517

    // multithreading
    MTUnk = 0x300, // 768
    MTMpn = 0x301, // 769 (mutext poisoned)
}
