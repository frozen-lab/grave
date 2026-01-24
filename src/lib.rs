// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2027 Aditya Motale <arctic_byte@proton.me>

#![deny(missing_docs)]
#![deny(unused_must_use)]
#![allow(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

mod error;
mod hints;

#[allow(unused)]
mod pool;

#[allow(unused)]
mod system;

pub use error::{GraveError, GraveResult};

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
#[derive(Debug)]
pub struct Grave {
    pool: pool::BufPool,
}

unsafe impl Send for Grave {}
unsafe impl Sync for Grave {}

impl Grave {
    /// Create new instance of [`Grave`]
    pub fn new(cap: u32, size: usize) -> GraveResult<Self> {
        Ok(Self {
            pool: pool::BufPool::new(cap, size),
        })
    }

    /// Write into [`Grave`]
    #[inline(always)]
    pub fn write(&self, page_size: usize, buf: &[u8]) -> GraveResult<()> {
        let buf_len = buf.len();
        let total_pages = (buf_len + page_size - 1) / page_size;

        let mut remaining = total_pages;
        let mut allocations = Vec::new();

        while remaining > 0 {
            let alloc = self.pool.allocate(remaining);

            if alloc.count > 0 {
                remaining -= alloc.count;
                allocations.push(alloc);
            } else {
                self.pool.wait()?;
            }
        }

        let mut src_off = 0;
        for alloc in &allocations {
            for slot in &alloc.slots {
                let dst = slot.ptr();
                let len = page_size.min(buf_len - src_off);

                unsafe {
                    std::ptr::copy_nonoverlapping(buf.as_ptr().add(src_off), dst, len);
                }

                src_off += len;
                if src_off >= buf_len {
                    break;
                }
            }
        }

        // NOTE: allocated buffers are freed automatically when the `alloc` is dropped!
        Ok(())
    }
}
