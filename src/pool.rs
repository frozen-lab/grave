use std::{
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, Ordering},
        Condvar, Mutex,
    },
};

const INVALID_SLOT: u64 = u64::MAX;
pub(crate) type SLOT = *mut u8;

#[derive(Debug)]
pub(crate) struct BufPool {
    num_slots: u64,
    slot_size: u64,
    start_ptr: PoolPtr,
    wait_cdvr: Condvar,
    wait_lock: Mutex<()>,
    free_head: AtomicU64,
    free_next: Box<[AtomicU64]>,
}

unsafe impl Send for BufPool {}
unsafe impl Sync for BufPool {}

impl BufPool {
    pub(crate) fn new(slots: usize, size: usize) -> Self {
        // sanity checks
        debug_assert_ne!(size, 0, "slot_size must not be zero");
        debug_assert_ne!(slots, 0, "num_slots must not be zero");

        let pool_size = size * slots;
        let mut pool = Vec::<u8>::with_capacity(pool_size);

        let slot_size: u64 = size as u64;
        let num_slots = slots as u64;

        let start_ptr = PoolPtr::new(pool.as_mut_ptr());

        // NOTE: `Vec::with_capacity(N)` allocates memory but keeps the len at 0. We use
        // raw pointers to access different slots, if the len stays at 0, it'd create
        // undefined behavior. Also, the reconstruct of vector from the pointer would become
        // invalid. To avoid memory leaks, we reconstruct the vec from the pointer in the drop.
        unsafe { pool.set_len(pool_size) };

        // NOTE: When the `pool` is dropped, it'll free up the entire memory. This should not happen,
        // as we own the underlying memory via mutable pointer, which is an implicit owenership,
        // so we avoid destruction of `pool` when it goes out of scope.
        std::mem::forget(pool);

        let mut next = Vec::with_capacity(slots);
        for i in 0..num_slots {
            let _i = 1 + i;
            let n = if _i < num_slots { _i } else { INVALID_SLOT };
            next.push(AtomicU64::new(n));
        }

        Self {
            start_ptr,
            num_slots,
            slot_size,
            wait_cdvr: Condvar::new(),
            wait_lock: Mutex::new(()),
            free_head: AtomicU64::new(0),
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
                    return Some(self.start_ptr.add(self.slot_size * head));
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn free(&self, ptr: PoolSlot) {
        let offset = self.start_ptr.offset_from(ptr);
        let idx = offset as u64 / self.slot_size;

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

    #[inline(always)]
    pub(crate) fn alloc_n(&self, n: usize) -> AllocBatch {
        let mut batch = AllocBatch::new();
        let mut head = self.free_head.load(Ordering::Acquire);

        while head != INVALID_SLOT && batch.count < n {
            let next = self.free_next[head as usize].load(Ordering::Relaxed);
            match self
                .free_head
                .compare_exchange(head, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    batch.slots.push(self.start_ptr.add(head * self.slot_size));
                    batch.count += 1;
                }
                Err(h) => head = h,
            }
        }

        if head == INVALID_SLOT {
            batch.exhausted = true;
        }

        batch
    }

    pub(crate) fn free_n(&self, slots: Vec<PoolSlot>) {
        // sanity check
        debug_assert!(slots.len() >= 2, "slots should be >= 2");

        let mut first = INVALID_SLOT;
        let mut last = INVALID_SLOT;

        for slot in slots {
            let off = self.start_ptr.offset_from(slot);
            let idx = (off as u64) / self.slot_size;

            // TODO: Use of `unlikely` branch hint
            if first == INVALID_SLOT {
                first = idx;
                last = idx;
                continue;
            }

            self.free_next[last as usize].store(idx, Ordering::Relaxed);
            last = idx;
        }

        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            self.free_next[last as usize].store(head, Ordering::Relaxed);
            match self
                .free_head
                .compare_exchange(head, first, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(h) => head = h,
            }
        }

        self.wait_cdvr.notify_one();
    }

    #[inline]
    pub(crate) fn wait(&self) {
        let guard = self.wait_lock.lock().unwrap();
        self.wait_cdvr.wait(guard).unwrap();
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
// Pool Start Pointer
//

#[derive(Debug)]
struct PoolPtr(SLOT);

unsafe impl Send for PoolPtr {}
unsafe impl Sync for PoolPtr {}

impl PoolPtr {
    #[inline]
    const fn new(ptr: SLOT) -> Self {
        unsafe { Self(NonNull::new_unchecked(ptr).as_ptr()) }
    }

    #[inline]
    const fn add(&self, count: u64) -> PoolSlot {
        unsafe { PoolSlot::new(self.0.add(count as usize)) }
    }

    #[inline]
    const fn offset_from(&self, ptr: PoolSlot) -> usize {
        unsafe { ptr.0.offset_from(self.0) as usize }
    }
}

impl std::fmt::Display for PoolPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PoolPtr {{base_ptr: {:?}}}", self.0)
    }
}

//
// Pool Slot
//

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct PoolSlot(SLOT);

unsafe impl Send for PoolSlot {}
unsafe impl Sync for PoolSlot {}

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

impl std::fmt::Display for PoolSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PoolSlot {{ptr: {:?}}}", self.0)
    }
}

//
// Allocation batch
//

#[derive(Debug)]
pub(crate) struct AllocBatch {
    pub count: usize,
    pub exhausted: bool,
    pub slots: Vec<PoolSlot>,
}

impl AllocBatch {
    fn new() -> Self {
        Self {
            count: 0,
            exhausted: false,
            slots: Vec::<PoolSlot>::new(),
        }
    }
}

//
// destructor
//

impl Drop for BufPool {
    fn drop(&mut self) {
        let size = (self.slot_size * self.num_slots) as usize;

        // NOTE: we reconstruct original allocation from the stored pointer, so it could
        // automatically be freed by the compiler
        let _ = unsafe { Vec::from_raw_parts(self.start_ptr.0, size, size) };
    }
}

//
// test suite
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_validation() {
        let pool = BufPool::new(0x10, 0x10);

        assert_eq!(pool.num_slots, 0x10);
        assert_eq!(pool.slot_size, 0x10);
    }

    mod single_alloc_and_free {
        use super::*;

        #[test]
        fn single_alloc_and_free_cycle() {
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
        fn single_alloc_reuses_same_slot() {
            let pool = BufPool::new(0x10, 0x10);

            let s1 = pool.alloc().expect("new slot");
            pool.free(s1.clone());
            let s2 = pool.alloc().expect("new slot");

            assert_eq!(s1, s2);
        }
    }

    mod multi_alloc_and_free {
        use super::*;
    }
}
