mod file;

#[cfg(not(test))]
pub(in crate::system) const FLUSH_DURATION: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(test)]
pub(in crate::system) const FLUSH_DURATION: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq)]
pub(in crate::system) enum IOFlushMode {
    Manual,
    Background,
}

impl std::fmt::Display for IOFlushMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Manual => "Manual",
            Self::Background => "Background",
        };
        write!(f, "{text}")
    }
}
