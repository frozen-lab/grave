use std::{
    mem,
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

const INVALID: u32 = u32::MAX;

#[derive(Debug)]
pub(crate) struct BufPool {
    ptr: NonNull<u8>,
    num_slots: u32,
    slot_size: usize,
    free_head: AtomicU32,
    free_next: Box<[AtomicU32]>,
}

unsafe impl Send for BufPool {}
unsafe impl Sync for BufPool {}

impl BufPool {
    pub(crate) fn new(num_slots: u32, slot_size: usize) -> Self {
        // sanity checks
        //
        // NOTE: We can afford following checks, as the creation part
        // does not fall under the fast, perf critical path
        assert!(num_slots > 0, "num_slots must not be zero");
        assert!(slot_size > 0, "slot_size must not be zero");

        let size = slot_size * num_slots as usize;
        let mut pool = Vec::<u8>::with_capacity(size);
        unsafe {
            pool.set_len(size);
        };

        // TODO: Improve error handling (this error is unreachable, so will go under misc errors)
        let ptr = NonNull::new(pool.as_mut_ptr()).expect("mem pointer is null!");
        mem::forget(pool);

        let mut next = Vec::with_capacity(num_slots as usize);
        for i in 0..num_slots {
            let n = if i + 1 < num_slots { i + 1 } else { INVALID };
            next.push(AtomicU32::new(n));
        }

        Self {
            ptr,
            num_slots,
            slot_size,
            free_head: AtomicU32::new(0),
            free_next: next.into_boxed_slice(),
        }
    }
}

impl Drop for BufPool {
    fn drop(&mut self) {
        let size = self.slot_size * self.num_slots as usize;

        // NOTE: we reconstruct original allocation from the stored pointer, so it could
        // automatically be freed
        let _ = unsafe { Vec::from_raw_parts(self.ptr.as_ptr(), size, size) };
    }
}

impl std::fmt::Display for BufPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut free = 0;
        let mut head = self.free_head.load(Ordering::Acquire);

        while head != INVALID {
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
