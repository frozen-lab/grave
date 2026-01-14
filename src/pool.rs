use std::{
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, Ordering},
        Condvar, Mutex,
    },
};

const INVALID_SLOT: u64 = u32::MAX as u64;
const POOL_IDX_BITS: u64 = 0x20;
const POOL_IDX_MASK: u64 = (1 << POOL_IDX_BITS) - 1;

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
    pub(crate) fn new(num_slots: u32, size: usize) -> Self {
        // sanity checks
        debug_assert_ne!(size, 0, "slot_size must not be zero");
        debug_assert_ne!(num_slots, 0, "num_slots must not be zero");

        let pool_size = size * num_slots as usize;
        let mut pool = Vec::<u8>::with_capacity(pool_size);

        let slot_size: u64 = size as u64;
        let num_slots = num_slots as u64;

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

        let mut next = Vec::with_capacity(num_slots as usize);
        for i in 0..num_slots {
            let _i = 1 + i;
            let n = if _i < num_slots { _i } else { INVALID_SLOT };
            next.push(AtomicU64::new(n));
        }

        Self {
            start_ptr,
            num_slots,
            slot_size,
            wait_lock: Mutex::new(()),
            wait_cdvr: Condvar::new(),
            free_next: next.into_boxed_slice(),
            free_head: AtomicU64::new(_pack_pool_idx(0, 0)),
        }
    }

    #[inline(always)]
    pub(crate) fn alloc(&self) -> Option<PoolSlot> {
        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            let (idx, tag) = _unpack_pool_idx(head);
            if idx == INVALID_SLOT {
                return None;
            }

            let next = self.free_next[idx as usize].load(Ordering::Relaxed);
            let new = _pack_pool_idx(next, tag + 1);

            match self
                .free_head
                .compare_exchange(head, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(self.start_ptr.add(idx * self.slot_size));
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn free(&self, ptr: &PoolSlot) {
        let offset = self.start_ptr.offset_from(ptr);
        let idx = offset as u64 / self.slot_size;

        // sanity check
        debug_assert!(idx < self.num_slots, "idx is out-of-bounds");

        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            let (head_idx, head_tag) = _unpack_pool_idx(head);
            self.free_next[idx as usize].store(head_idx, Ordering::Relaxed);
            let new = _pack_pool_idx(idx, head_tag);

            match self
                .free_head
                .compare_exchange(head, new, Ordering::AcqRel, Ordering::Acquire)
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

        loop {
            let (idx, tag) = _unpack_pool_idx(head);
            if idx == INVALID_SLOT {
                return batch;
            }

            // local walk
            let mut cur = idx;
            let mut last = cur;
            let mut count = 1;

            while count < n {
                let next = self.free_next[last as usize].load(Ordering::Relaxed);

                // NOTE: This is valid becuse, next is already only the index (unpacked version) of
                // the slot
                if next == INVALID_SLOT {
                    break;
                }

                last = next;
                count += 1;
            }

            let new_head_idx = self.free_next[last as usize].load(Ordering::Relaxed);
            let new_head = _pack_pool_idx(new_head_idx, 1 + tag);

            match self
                .free_head
                .compare_exchange(head, new_head, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    // materialize slots
                    let mut cur = idx;
                    for _ in 0..count {
                        batch.slots.push(self.start_ptr.add(cur * self.slot_size));
                        cur = self.free_next[cur as usize].load(Ordering::Relaxed);
                    }

                    batch.count = count;
                    return batch;
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn free_n(&self, slots: &[PoolSlot]) {
        // sanity check
        debug_assert!(slots.len() >= 2, "slots should be >= 2");

        let mut first = INVALID_SLOT;
        let mut last = INVALID_SLOT;

        for slot in slots {
            let off = self.start_ptr.offset_from(slot);
            let idx = (off as u64) / self.slot_size;

            if first == INVALID_SLOT {
                first = idx;
                last = idx;
            } else {
                self.free_next[last as usize].store(idx, Ordering::Relaxed);
                last = idx;
            }
        }

        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            let (head_idx, tag) = _unpack_pool_idx(head);
            self.free_next[last as usize].store(head_idx, Ordering::Relaxed);

            let new = _pack_pool_idx(first, 1 + tag);

            match self
                .free_head
                .compare_exchange(head, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.wait_cdvr.notify_one();
                    return;
                }
                Err(h) => head = h,
            }
        }
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
    const fn offset_from(&self, ptr: &PoolSlot) -> usize {
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

#[derive(Debug, PartialEq)]
pub(crate) struct PoolSlot(SLOT);

unsafe impl Send for PoolSlot {}
unsafe impl Sync for PoolSlot {}

impl PoolSlot {
    #[inline]
    const fn new(ptr: SLOT) -> Self {
        Self(ptr)
    }

    #[inline]
    pub(crate) const fn ptr(&self) -> SLOT {
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
    pub slots: Vec<PoolSlot>,
}

impl AllocBatch {
    fn new() -> Self {
        Self {
            count: 0,
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
// pool idx helpers
//

#[inline]
const fn _pack_pool_idx(idx: u64, tag: u64) -> u64 {
    (tag << POOL_IDX_BITS) | (idx & POOL_IDX_MASK)
}

#[inline]
const fn _unpack_pool_idx(v: u64) -> (u64, u64) {
    (v & POOL_IDX_MASK, v >> POOL_IDX_BITS)
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
        use std::sync::{Arc, Barrier};
        use std::thread;

        #[test]
        fn alloc_and_free_cycle() {
            let pool = BufPool::new(1, 0x10);

            let slot = pool.alloc();
            assert!(slot.is_some());

            let slot2 = pool.alloc();
            assert!(slot2.is_none());

            pool.free(&slot.unwrap());

            let slot3 = pool.alloc();
            assert!(slot3.is_some());
        }

        #[test]
        fn alloc_until_exhaustion() {
            let pool = BufPool::new(4, 8);

            let a = pool.alloc().expect("new alloc");
            let b = pool.alloc().expect("new alloc");
            let c = pool.alloc().expect("new alloc");
            let d = pool.alloc().expect("new alloc");

            assert!(pool.alloc().is_none());
            pool.free(&a);
            assert!(pool.alloc().is_some());
        }

        #[test]
        fn pool_exhaustion_returns_none() {
            let pool = BufPool::new(3, 0x10);

            let a = pool.alloc().expect("new slot");
            let b = pool.alloc().expect("new slot");
            let c = pool.alloc().expect("new slot");

            // no space left
            assert!(pool.alloc().is_none());

            pool.free(&b);
            pool.free(&a);
            pool.free(&c);

            let s1 = pool.alloc().expect("new slot");
            let s2 = pool.alloc().expect("new slot");
            let s3 = pool.alloc().expect("new slot");

            // again, no space left
            assert!(pool.alloc().is_none());
        }

        #[test]
        fn slot_reuse_is_lifo() {
            let pool = BufPool::new(2, 8);

            let a = pool.alloc().expect("new slot");
            let b = pool.alloc().expect("new slot");

            pool.free(&a);
            pool.free(&b);

            let c = pool.alloc().expect("new slot");
            let d = pool.alloc().expect("new slot");

            // lifo order
            assert_eq!(c, b);
            assert_eq!(d, a);
        }

        #[test]
        fn stress_alloc_free_cycles_with_single_thread() {
            let pool = BufPool::new(0x10, 0x10);

            for _ in 0..0x1000 {
                let s = pool.alloc().expect("new slot");
                pool.free(&s);
            }

            assert!(pool.alloc().is_some());
        }

        #[test]
        fn stress_alloc_free_cycle_with_multi_threads() {
            const THREADS: usize = 8;
            const ITERS: usize = 0x2000;

            let pool = Arc::new(BufPool::new(THREADS as u32, 0x10));
            let barrier = Arc::new(Barrier::new(THREADS));

            let mut handles = Vec::new();
            for _ in 0..THREADS {
                let pool = pool.clone();
                let barrier = barrier.clone();

                handles.push(thread::spawn(move || {
                    barrier.wait();

                    for _ in 0..ITERS {
                        loop {
                            if let Some(slot) = pool.alloc() {
                                pool.free(&slot);
                                break;
                            }

                            std::thread::yield_now();
                        }
                    }
                }));
            }

            for h in handles {
                h.join().expect("join in");
            }

            let mut count = 0;
            while pool.alloc().is_some() {
                count += 1;
            }

            // pool should be fully intact
            assert_eq!(count, THREADS);
        }

        #[test]
        fn alloc_free_cycle_across_threads() {
            let pool = Arc::new(BufPool::new(1, 0x10));
            let slot = pool.alloc().expect("new slot");

            let pool2 = pool.clone();
            let handle = thread::spawn(move || {
                pool2.free(&slot);
            });
            handle.join().expect("join in");

            assert!(pool.alloc().is_some());
        }

        #[test]
        fn no_duplicate_slots_under_race() {
            let pool = Arc::new(BufPool::new(2, 0x10));

            let a = pool.alloc().expect("new slot");
            let b = pool.alloc().expect("new slot");

            let pa = a.ptr();
            let pb = b.ptr();

            // not the same pointer
            assert_ne!(pa, pb);

            pool.free(&a);
            pool.free(&b);

            let c = pool.alloc().expect("new slot");
            let d = pool.alloc().expect("new slot");

            let pc = c.ptr();
            let pd = d.ptr();

            // pointer reuse
            assert!(pc == pa || pc == pb);
            assert!(pd == pa || pd == pb);

            // again, not the same pointer
            assert_ne!(pc, pd);
        }
    }

    mod multi_alloc_and_free {
        use super::*;
        use std::sync::{Arc, Barrier};
        use std::thread;

        #[test]
        fn alloc_and_free_cycle() {
            let n = 0x10;
            let pool = BufPool::new(n as u32, 0x10);

            let slot = pool.alloc_n(n);
            assert_eq!(slot.count, n);

            let slot2 = pool.alloc_n(n);
            assert_eq!(slot2.count, 0);

            pool.free_n(&slot.slots);

            let slot3 = pool.alloc_n(n);
            assert_eq!(slot3.count, n);
        }

        #[test]
        fn alloc_n_partial_and_full() {
            let pool = BufPool::new(8, 8);

            let b1 = pool.alloc_n(5);
            assert_eq!(b1.count, 5);

            let b2 = pool.alloc_n(4);
            assert_eq!(b2.count, 3);
            assert!(pool.alloc().is_none());

            pool.free_n(&b1.slots);
            pool.free_n(&b2.slots);

            let b3 = pool.alloc_n(4);
            assert_eq!(b3.count, 4);
        }

        #[test]
        fn no_duplicate_slots_alloc_n() {
            let pool = BufPool::new(8, 8);

            let b = pool.alloc_n(8);
            let mut ptrs: Vec<_> = b.slots.iter().map(|s| s.ptr()).collect();

            ptrs.sort();
            ptrs.dedup();

            assert_eq!(ptrs.len(), 8);
        }

        #[test]
        fn stress_alloc_free_with_multi_threads() {
            const THREADS: usize = 8;
            const ITERS: usize = 0x2000;

            let pool = Arc::new(BufPool::new(0x10, 8));
            let barrier = Arc::new(Barrier::new(THREADS));

            let mut handles = Vec::new();

            for _ in 0..THREADS {
                let pool = pool.clone();
                let barrier = barrier.clone();

                handles.push(thread::spawn(move || {
                    barrier.wait();

                    for _ in 0..ITERS {
                        let batch = pool.alloc_n(4);
                        if batch.count > 0 {
                            pool.free_n(&batch.slots);
                        } else {
                            std::thread::yield_now();
                        }
                    }
                }));
            }

            for h in handles {
                h.join().expect("join in");
            }

            // alloc after stress
            let fnl = pool.alloc_n(0x10);
            assert_eq!(fnl.count, 0x10);
        }
    }
}
