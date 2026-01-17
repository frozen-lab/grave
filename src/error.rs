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
    PHInv = 0x80,

    // I/O Permissions
    PMWrt = 0x101,

    // I/O
    IOHcf = 0x200,
    IOUnk = 0x201,
    IONsp = 0x202,
    IOLck = 0x203,
    IOEof = 0x204,
    IOSyn = 0x205,
}
