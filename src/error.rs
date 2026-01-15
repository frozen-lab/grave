//
// Grave Error
//

/// A custom finite set of errors, which are exposed by [`Grave`]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GraveError {
    /// Represents an underlying I/O error (file system, OS, etc.)
    IO(String),

    /// Represents a lack of **write/read** permissions for I/O ops on a File or Dir
    NoPerm(String),

    /// Represents a multithreading error, where a thread fails while a lock is held
    LockPoisoned(String),

    /// A fallback for unexpected or uncategorized errors.
    Miscellaneous(String),

    /// Represents invalid internal state for [`Grave`], which is caused when internal
    /// data is un-aligned, missing, is tampered or corrupted.
    InvalidState(String),
}

impl From<std::io::Error> for GraveError {
    fn from(e: std::io::Error) -> Self {
        GraveError::IO(format!("{}", e))
    }
}

impl<T> From<std::sync::PoisonError<T>> for GraveError {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        GraveError::LockPoisoned(format!("{}", e))
    }
}

impl From<InternalError> for GraveError {
    fn from(err: InternalError) -> Self {
        match err {
            InternalError::IO(e) => Self::IO(e),
            InternalError::Misc(e) => Self::Miscellaneous(e),
            InternalError::LockPoisoned(e) => Self::LockPoisoned(e),
            InternalError::InvalidState(e) => Self::InvalidState(e),
        }
    }
}

/// A specialized result type for operations in [`Grave`]
pub type GraveResult<T> = Result<T, GraveError>;

//
// Internal Error
//

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum InternalError {
    IO(String),
    Misc(String),
    LockPoisoned(String),
    InvalidState(String),
}

impl From<std::io::Error> for InternalError {
    fn from(e: std::io::Error) -> Self {
        InternalError::IO(format!("{}", e))
    }
}

impl<T> From<std::sync::PoisonError<T>> for InternalError {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        InternalError::LockPoisoned(format!("{}", e))
    }
}

pub(crate) type InternalResult<T> = Result<T, InternalError>;
