use std::{
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

pub(crate) struct BufPool {
    b_pointer: NonNull<u8>,
    num_slots: u32,
    slot_size: u32,
    free_head: AtomicU32,
    free_next: Box<[AtomicU32]>,
}

unsafe impl Send for BufPool {}
unsafe impl Sync for BufPool {}

const INVALID_SLOT: u32 = u32::MAX;
pub(crate) type SLOT = *mut u8;

impl BufPool {
    pub(crate) fn new(num_slots: u32, slot_size: u32) -> Self {
        // sanity checks
        debug_assert_ne!(num_slots, 0, "num_slots must not be zero");
        debug_assert_ne!(slot_size, 0, "slot_size must not be zero");

        let pool_size = (slot_size * num_slots) as usize;
        let mut pool = Vec::<u8>::with_capacity(pool_size);

        // NOTE: `Vec::with_capacity(N)` allocates memory but leavs `len = 0`, as we use
        // the raw pointers to access different slots, if len stays at 0, it'd be UB
        // Also for us to reconstruct vector from `b_pointer` in the `drop` becomes invalid
        unsafe { pool.set_len(pool_size) };

        let b_pointer = unsafe { NonNull::new_unchecked(pool.as_mut_ptr()) };

        // NOTE: When the `pool` is dropped, it'll free up the entire memory. This should not happen,
        // as we own the underlying memory via mutable pointer, which is an implicit owenership,
        // so we avoid destruction of `pool`, when it goes out of scope
        std::mem::forget(pool);

        let mut next = Vec::with_capacity(num_slots as usize);
        for i in 0..num_slots {
            let n = if i + 1 < num_slots { i + 1 } else { INVALID_SLOT };
            next.push(AtomicU32::new(n));
        }

        Self {
            b_pointer,
            num_slots,
            slot_size,
            free_head: AtomicU32::new(0),
            free_next: next.into_boxed_slice(),
        }
    }

    #[inline(always)]
    pub(crate) fn alloc(&self) -> Option<SLOT> {
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
                    let slot = unsafe { self.b_pointer.as_ptr().add((self.slot_size * head) as usize) };
                    return Some(slot);
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn free(&self, ptr: SLOT) {
        let offset = unsafe { ptr.offset_from(self.b_pointer.as_ptr()) } as usize;
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
        let _ = unsafe { Vec::from_raw_parts(self.b_pointer.as_ptr(), size, size) };
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
