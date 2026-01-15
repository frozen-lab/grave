// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2027 Aditya Motale <arctic_byte@proton.me>

#![deny(missing_docs)]
#![deny(unused_must_use)]
#![allow(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

#[allow(unused)]
mod error;

#[allow(unused)]
mod hints;

/// A page based storage engine with fire-and-forget writes and crash-safe durability semantics
///
/// # Example
///
/// ```
/// use grave::Grave;
///
/// const fn assert_send_sync<T: Send + Sync>() {}
/// const _: () = assert_send_sync::<Grave>();
/// ```
pub struct Grave;

unsafe impl Send for Grave {}
unsafe impl Sync for Grave {}
