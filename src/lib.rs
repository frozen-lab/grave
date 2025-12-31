#![deny(missing_docs)]
// #![deny(unused_must_use)]
#![doc = include_str!("../README.md")]

#[allow(unused)]
mod pool;

/// A page based storage engine with fire-and-forget writes and crash-safe durability semantics
///
/// # Example
///
/// ```
/// use grave::Grave;
///
/// assert_eq!(std::mem::size_of::<Grave>(), 0);
///
/// const fn assert_send_sync<T: Send + Sync>() {}
/// const _: () = assert_send_sync::<Grave>();
/// ```
#[derive(Debug)]
pub struct Grave;

unsafe impl Send for Grave {}
unsafe impl Sync for Grave {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanity() {
        assert_eq!(std::mem::size_of::<Grave>(), 0);
    }
}
