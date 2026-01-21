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
    pub fn context(&self) -> &str {
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
    pub(crate) fn from_poison<T>(code: ErrorCode, error: std::sync::PoisonError<T>) -> Self {
        Self {
            code,
            cntx: error.to_string(),
        }
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
    /// (518) mutext poisoned
    IOMpn = 0x206,
    /// (519) thread poisoned
    IOTpn = 0x207,
    /// (520) no write perm
    IOWrt = 0x208,
    /// (521) no read perm
    IORed = 0x209,

    /// (1024) internal fuck up
    MMHcf = 0x400,
    /// (1025) unknown IO error (fallback)
    MMUnk = 0x401,
    /// (1026) no more memory available
    MMNsp = 0x402,
    /// (1027) syncing error
    MMSyn = 0x403,
    /// (1028) mutext poisoned
    MMMpn = 0x404,
    /// (1029) thread poisoned
    MMTpn = 0x405,

    /// (1280) lock error
    BPLck = 0x500,
    /// (1281) mutex poisoned
    BPMpn = 0x501,

    /// (128) invalid path
    PHInv = 0x80,

    /// (10) Grave Unknown error
    GRUnk = 0x0A,
}

impl ErrorCode {
    #[inline]
    pub(crate) const fn from_u16(code: u16) -> Self {
        match code {
            // WARN: Error code must never be 0, as its used as placeholder for sane state (non errored state)
            0 => unimplemented!(),

            0x200 => Self::IOHcf,
            0x201 => Self::IOUnk,
            0x202 => Self::IONsp,
            0x203 => Self::IOLck,
            0x204 => Self::IOEof,
            0x205 => Self::IOSyn,
            0x206 => Self::IOMpn,
            0x207 => Self::IOTpn,
            0x208 => Self::IOWrt,
            0x209 => Self::IORed,

            0x400 => Self::MMHcf,
            0x401 => Self::MMUnk,
            0x402 => Self::MMNsp,
            0x403 => Self::MMSyn,
            0x404 => Self::MMMpn,
            0x405 => Self::MMTpn,

            0x500 => Self::BPLck,
            0x501 => Self::BPMpn,

            0x80 => Self::PHInv,
            0x0A => Self::GRUnk,

            _ => Self::GRUnk, // defensive fallback
        }
    }
}
