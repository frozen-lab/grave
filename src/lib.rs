#![deny(missing_docs)]
#![deny(unused_must_use)]
#![allow(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

mod errors;

#[allow(unused)]
mod pool;

#[allow(unused)]
mod hints;

#[allow(unused)]
mod file;

pub use errors::{GraveError, GraveResult};

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
pub struct Grave;

unsafe impl Send for Grave {}
unsafe impl Sync for Grave {}
