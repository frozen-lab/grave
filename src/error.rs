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

    #[inline]
    pub(crate) fn map_err<R>(code: ErrorCode, error: std::io::Error) -> GraveResult<R> {
        Err(Self {
            code,
            cntx: error.to_string(),
        })
    }

    #[inline]
    pub(crate) fn poison_err<T, R>(code: ErrorCode, error: std::sync::PoisonError<T>) -> GraveResult<R> {
        Err(Self {
            code,
            cntx: error.to_string(),
        })
    }
}

impl std::fmt::Display for GraveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GraveError {{code: {}, context: {}}}", self.code(), self.context())
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
    /// (512) internal fuck up
    IOHcf = 0x200,
    /// (513) unknown IO error (fallback)
    IOUnk = 0x201,
    /// (514) no more space available
    IONsp = 0x202,
    /// (515) IO lock error (failed to obtain lock)
    IOLck = 0x203,
    /// (516) exexpected eof, mainly while writing
    IOEof = 0x204,
    /// (517) syncing error
    IOSyn = 0x205,

    /// (1024) internal fuck up
    MMHcf = 0x400,
    /// (1025) unknown IO error (fallback)
    MMUnk = 0x401,
    /// (1026) no more memory available
    MMNsp = 0x402,
    /// (1027) syncing error
    MMSyn = 0x403,

    /// (768) unknown thread error
    MTUnk = 0x300,
    /// (769) mutext posioned
    MTMpn = 0x301,
    /// (770) thread paniced
    MTTpn = 0x302,

    /// (128) invalid path
    PHInv = 0x80,

    /// (256) no write perm
    PMWrt = 0x100,
    /// (257) no read perm
    PMRed = 0x101,
}

impl ErrorCode {
    #[inline]
    pub(crate) const fn from_u16(code: u16) -> Self {
        match code {
            // WARN: Error code must never be 0, as its used as placeholder for sane state (non errored state)
            0 => unimplemented!(),

            0x80 => ErrorCode::PHInv,
            0x101 => ErrorCode::PMWrt,

            0x200 => ErrorCode::IOHcf,
            0x201 => ErrorCode::IOUnk,
            0x202 => ErrorCode::IONsp,
            0x203 => ErrorCode::IOLck,
            0x204 => ErrorCode::IOEof,
            0x205 => ErrorCode::IOSyn,

            0x400 => ErrorCode::MMHcf,
            0x401 => ErrorCode::MMUnk,
            0x402 => ErrorCode::MMNsp,
            0x403 => ErrorCode::MMSyn,

            0x300 => ErrorCode::MTUnk,
            0x301 => ErrorCode::MTMpn,
            0x302 => ErrorCode::MTTpn,

            _ => Self::IOUnk, // defensive fallback
        }
    }
}
