/// A specialized result type for operations in [`Grave`]
pub type GraveResult<T> = Result<T, GraveError>;

/// A custom finite set of errors, which are exposed by [`Grave`]
#[derive(Debug, PartialEq, Clone)]
pub enum GraveError {
    /// Represents an underlying I/O error (file system, OS, etc.)
    IO(String),

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

impl std::fmt::Display for GraveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(err) => write!(f, "GraveError (IO) {{err: {err}}}"),
            Self::InvalidState(err) => write!(f, "GraveError (InvalidState) {{err: {err}}}"),
            Self::LockPoisoned(err) => write!(f, "GraveError (LockPoisoned) {{err: {err}}}"),
            Self::Miscellaneous(err) => write!(f, "GraveError (Miscellaneous) {{err: {err}}}"),
        }
    }
}
