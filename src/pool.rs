use std::{
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

const INVALID_SLOT: u32 = u32::MAX;
pub(crate) type SLOT = *mut u8;

pub(crate) struct BufPool {
    start_ptr: PoolPtr,
    num_slots: u32,
    slot_size: u32,
    free_head: AtomicU32,
    free_next: Box<[AtomicU32]>,
}

unsafe impl Send for BufPool {}
unsafe impl Sync for BufPool {}

impl BufPool {
    pub(crate) fn new(num_slots: u32, slot_size: u32) -> Self {
        // sanity checks
        debug_assert_ne!(num_slots, 0, "num_slots must not be zero");
        debug_assert_ne!(slot_size, 0, "slot_size must not be zero");

        let pool_size = (slot_size * num_slots) as usize;
        let mut pool = Vec::<u8>::with_capacity(pool_size);

        // NOTE: `Vec::with_capacity(N)` allocates memory but keeps the len at 0. We use
        // raw pointers to access different slots, if the len stays at 0, it'd create
        // undefined behavior. Also, the reconstruct of vector from the pointer would become
        // invalid. To avoid memory leaks, we reconstruct the vec from the pointer in the drop.
        unsafe { pool.set_len(pool_size) };

        let start_ptr = PoolPtr::new(pool.as_mut_ptr());

        // NOTE: When the `pool` is dropped, it'll free up the entire memory. This should not happen,
        // as we own the underlying memory via mutable pointer, which is an implicit owenership,
        // so we avoid destruction of `pool` when it goes out of scope.
        std::mem::forget(pool);

        let mut next = Vec::with_capacity(num_slots as usize);
        for i in 0..num_slots {
            let n = if i + 1 < num_slots { i + 1 } else { INVALID_SLOT };
            next.push(AtomicU32::new(n));
        }

        Self {
            start_ptr,
            num_slots,
            slot_size,
            free_head: AtomicU32::new(0),
            free_next: next.into_boxed_slice(),
        }
    }

    #[inline(always)]
    pub(crate) fn alloc(&self) -> Option<PoolSlot> {
        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            if head == INVALID_SLOT {
                return None;
            }

            let next = self.free_next[head as usize].load(Ordering::Relaxed);
            match self
                .free_head
                .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(self.start_ptr.add((self.slot_size * head) as usize));
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn free(&self, ptr: PoolSlot) {
        let offset = self.start_ptr.offset_from(ptr);
        let idx = offset as u32 / self.slot_size;

        // sanity check
        debug_assert!(idx < self.num_slots, "idx is out-of-bounds");

        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            self.free_next[idx as usize].store(head, Ordering::Relaxed);
            match self
                .free_head
                .compare_exchange(head, idx, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(h) => head = h,
            }
        }
    }
}

impl Drop for BufPool {
    fn drop(&mut self) {
        let size = (self.slot_size * self.num_slots) as usize;

        // NOTE: we reconstruct original allocation from the stored pointer, so it could
        // automatically be freed by the compiler
        let _ = unsafe { Vec::from_raw_parts(self.start_ptr.0, size, size) };
    }
}

impl std::fmt::Display for BufPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut free = 0;
        let mut head = self.free_head.load(Ordering::Acquire);

        while head != INVALID_SLOT {
            free += 1;
            head = self.free_next[head as usize].load(Ordering::Relaxed);
        }

        write!(
            f,
            "BufPool {{ slots: {}, slot_size: {} bytes, free: {} }}",
            self.num_slots, self.slot_size, free,
        )
    }
}

//
// Pool Pointer
//

struct PoolPtr(SLOT);

impl PoolPtr {
    #[inline]
    const fn new(ptr: SLOT) -> Self {
        unsafe { Self(NonNull::new_unchecked(ptr).as_ptr()) }
    }

    #[inline]
    const fn add(&self, count: usize) -> PoolSlot {
        unsafe { PoolSlot::new(self.0.add(count)) }
    }

    #[inline]
    const fn offset_from(&self, ptr: PoolSlot) -> usize {
        unsafe { ptr.0.offset_from(self.0) as usize }
    }
}

//
// Pool Slot
//

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct PoolSlot(SLOT);

impl PoolSlot {
    #[inline]
    const fn new(ptr: SLOT) -> Self {
        Self(ptr)
    }

    #[inline]
    const fn ptr(&self) -> SLOT {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_validation() {
        let pool = BufPool::new(0x10, 0x10);

        assert_eq!(pool.num_slots, 0x10);
        assert_eq!(pool.slot_size, 0x10);
    }

    #[test]
    fn alloc_and_free_cycle() {
        let pool = BufPool::new(1, 0x10);

        let slot = pool.alloc();
        assert!(slot.is_some());

        let slot2 = pool.alloc();
        assert!(slot2.is_none());

        pool.free(slot.unwrap());

        let slot3 = pool.alloc();
        assert!(slot3.is_some());
    }

    #[test]
    fn alloc_reuses_same_slot() {
        let pool = BufPool::new(0x10, 0x10);

        let s1 = pool.alloc().expect("new slot");
        pool.free(s1.clone());
        let s2 = pool.alloc().expect("new slot");

        assert_eq!(s1, s2);
    }
}
