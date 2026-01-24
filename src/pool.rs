use crate::{error::ErrorCode, GraveError, GraveResult};
use std::{
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Condvar, Mutex, MutexGuard,
    },
};

const INVALID_POOL_SLOT: u64 = u32::MAX as u64;

#[derive(Debug)]
pub(crate) struct BufPool {
    cap: u64,
    size: u64,
    ptr: PoolPtr,
    cdvr: Condvar,
    lock: Mutex<()>,
    head: AtomicU64,
    active: AtomicUsize,
    shutdown_cdvr: Condvar,
    next: Box<[AtomicU64]>,
}

unsafe impl Send for BufPool {}
unsafe impl Sync for BufPool {}

impl BufPool {
    pub(crate) fn new(cap: u32, size: usize) -> Self {
        // sanity check
        debug_assert!(cap > 0 && size > 0, "cap and size can not be 0");

        let pool_size = cap as usize * size;
        let mut pool = Vec::<u8>::with_capacity(pool_size);
        let ptr = PoolPtr(pool.as_mut_ptr());

        // NOTE: `Vec::with_capacity(N)` allocates memory but keeps the len at 0. We use raw pointers
        // to access different slots, if the len stays at 0, it'd create undefined behavior. Also, the
        // reconstruct of vector from the pointer would become invalid. To avoid memory leaks, we
        // reconstruct the vec from the pointer in the drop.
        unsafe { pool.set_len(pool_size) };

        // NOTE: When the `pool` is dropped, it'll free up the entire memory. This should not happen,
        // as we own the underlying memory via mutable pointer, which is an implicit owenership, so we
        // avoid destruction of `pool` when it goes out of scope.
        std::mem::forget(pool);

        let mut next = Vec::with_capacity(cap as usize);
        for i in 0..cap {
            let _i = 1 + i;
            let n = if _i < cap { _i as u64 } else { INVALID_POOL_SLOT };
            next.push(AtomicU64::new(n));
        }

        Self {
            ptr,
            cap: cap as u64,
            size: size as u64,
            cdvr: Condvar::new(),
            lock: Mutex::new(()),
            active: AtomicUsize::new(0),
            shutdown_cdvr: Condvar::new(),
            next: next.into_boxed_slice(),
            head: AtomicU64::new(pack_pool_idx(0, 0)),
        }
    }

    /// Allocates `N` buffers for use in write IO ops.
    ///
    /// ## Polling
    ///
    /// This function may not allocate all the `N` required buffers in one call,
    /// so the caller must poll (wait and retry) for remaining `N` buffers.
    ///
    /// ## RAII Safety
    ///
    /// All [`BufPool`] aloocations are RAII safe by default, hence when the variable
    /// which stores the result of `allocate`, is dropped, the buffer's it holds are
    /// also automatically freed. The burden of _freeing after use_ does not fall on
    /// the caller.
    #[inline(always)]
    pub(crate) fn allocate(&self, n: usize) -> Allocation {
        // NOTE: safe to pre-incr as there are no abrupt/error exit here
        self.active.fetch_add(1, Ordering::Acquire);

        let mut head = self.head.load(Ordering::Acquire);
        let mut batch = Allocation::new(self, n);

        loop {
            let (idx, tag) = unpack_pool_idx(head);

            // NOTE: If we reach the last entry (i.e. invalid ptr), we return early, despite not
            // allocating all the required buffers
            //
            // This allows caller to process allocated buffers, and avoid busy waiting for
            // more buffers
            //
            // The caller should pool to allocate, till all the required buffers are allocated
            if idx == INVALID_POOL_SLOT {
                return batch;
            }

            // local walk
            let mut cur = idx;
            let mut last = cur;
            let mut count = 1;
            while count < n {
                // This is valid as `next` is already the index (unpacked version) of the slot
                let next = self.next[last as usize].load(Ordering::Relaxed);
                if next == INVALID_POOL_SLOT {
                    break;
                }

                last = next;
                count += 1;
            }

            let new_head_idx = self.next[last as usize].load(Ordering::Relaxed);
            let new_head = pack_pool_idx(new_head_idx, 1 + tag);

            match self
                .head
                .compare_exchange(head, new_head, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    // materialize slots
                    let mut cur = idx;
                    for _ in 0..count {
                        batch.slots.push(self.ptr.add(cur * self.size));
                        cur = self.next[cur as usize].load(Ordering::Relaxed);
                    }
                    batch.count = count;
                    return batch;
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    fn free(&self, ptr: &PoolPtr) {
        let offset = self.ptr.offset_from(&ptr);
        let idx = offset as u64 / self.size;

        // sanity check
        debug_assert!(idx < self.cap, "slot index is out of bounds");

        let mut head = self.head.load(Ordering::Acquire);
        loop {
            let (head_idx, head_tag) = unpack_pool_idx(head);
            self.next[idx as usize].store(head_idx, Ordering::Relaxed);
            let new = pack_pool_idx(idx, 1 + head_tag);

            match self
                .head
                .compare_exchange(head, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.cdvr.notify_one();
                    return;
                }
                Err(h) => head = h,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn wait(&self) -> GraveResult<()> {
        let guard = self
            .lock
            .lock()
            .map_err(|e| GraveError::from_poison(ErrorCode::BPLck, e))?;
        self.cdvr
            .wait(guard)
            .map_err(|e| GraveError::from_poison(ErrorCode::BPMpn, e))?;
        Ok(())
    }
}

impl std::fmt::Display for BufPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut free_slots = 0;
        let mut head = self.head.load(Ordering::Acquire);
        while head != INVALID_POOL_SLOT {
            head = self.next[head as usize].load(Ordering::Relaxed);
            free_slots += 1;
        }

        write!(
            f,
            "BufPool {{ cap: {}, size: {}, free_slots: {} }}",
            self.cap, self.size, free_slots
        )
    }
}

impl Drop for BufPool {
    fn drop(&mut self) {
        let mut guard = match self.lock.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        while self.active.load(Ordering::Acquire) != 0 {
            guard = self.shutdown_cdvr.wait(guard).expect("shutdown cv poisoned");
        }

        let pool_size = (self.cap * self.size) as usize;

        // NOTE: We re-construct original allocation from the stored pointer! This builds up the vecotor
        // as it was created, which then is dropped by Rust destructor's automatically!
        let _ = unsafe { Vec::from_raw_parts(self.ptr.ptr(), pool_size, pool_size) };
    }
}

//
// helpers
//

const POOL_IDX_BITS: u64 = 0x20;
const POOL_IDX_MASK: u64 = (1 << POOL_IDX_BITS) - 1;

#[inline]
const fn pack_pool_idx(idx: u64, tag: u64) -> u64 {
    (tag << POOL_IDX_BITS) | (idx & POOL_IDX_MASK)
}

#[inline]
const fn unpack_pool_idx(id: u64) -> (u64, u64) {
    (id & POOL_IDX_MASK, id >> POOL_IDX_BITS)
}

//
// Pool Pointer
//

type TSlot = *mut u8;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PoolPtr(TSlot);

unsafe impl Send for PoolPtr {}
unsafe impl Sync for PoolPtr {}

impl PoolPtr {
    #[inline]
    pub(crate) const fn ptr(&self) -> TSlot {
        self.0
    }

    #[inline]
    const fn add(&self, count: u64) -> Self {
        unsafe { Self(self.0.add(count as usize)) }
    }

    #[inline]
    const fn offset_from(&self, ptr: &Self) -> u64 {
        unsafe { ptr.0.offset_from(self.0) as u64 }
    }
}

//
// Allocation
//

#[derive(Debug)]
pub(crate) struct Allocation<'a> {
    pub(crate) count: usize,
    pub(crate) slots: Vec<PoolPtr>,
    guard: AllocationGuard<'a>,
}

impl<'a> Allocation<'a> {
    #[inline]
    fn new(pool: &'a BufPool, cap: usize) -> Self {
        Self {
            count: 0,
            slots: Vec::<PoolPtr>::with_capacity(cap),
            guard: AllocationGuard(pool),
        }
    }
}

impl<'a> Drop for Allocation<'a> {
    fn drop(&mut self) {
        for ptr in &self.slots {
            self.guard.0.free(ptr);
        }
    }
}

//
// allocation guard
//

#[derive(Debug)]
struct AllocationGuard<'a>(&'a BufPool);

impl Drop for AllocationGuard<'_> {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::Release) == 1 {
            // last user
            if let Ok(_g) = self.0.lock.lock() {
                self.0.shutdown_cdvr.notify_one();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: u32 = 0x20;
    const SIZE: usize = 0x0A;

    mod sanity_check {
        use super::*;

        #[test]
        fn new_works() {
            let pool = BufPool::new(CAP, SIZE);

            assert_eq!(pool.cap, CAP as u64);
            assert_eq!(pool.size, SIZE as u64);
            assert!(!pool.ptr.ptr().is_null());
            assert_eq!(pool.next.len(), CAP as usize);
        }

        #[test]
        fn pack_unpack_cycle() {
            let pack_id = pack_pool_idx(0x20, 0x0A);
            let (idx, tag) = unpack_pool_idx(pack_id);

            assert_eq!(idx, 0x20);
            assert_eq!(tag, 0x0A);
        }
    }

    mod allocate {
        use super::*;

        #[test]
        fn alloc_exact_capacity() {
            let pool = BufPool::new(8, SIZE);
            let alloc = pool.allocate(8);

            assert_eq!(alloc.count, 8);
            assert_eq!(alloc.slots.len(), 8);
        }

        #[test]
        fn alloc_partial_when_exhausted() {
            let pool = BufPool::new(4, SIZE);

            let a1 = pool.allocate(3);
            assert_eq!(a1.count, 3);

            let a2 = pool.allocate(3);
            assert_eq!(a2.count, 1);

            let a3 = pool.allocate(1);
            assert_eq!(a3.count, 0);
        }

        #[test]
        fn alloc_returns_zero_when_empty() {
            let pool = BufPool::new(2, SIZE);

            let _a1 = pool.allocate(2);
            let a2 = pool.allocate(1);

            assert_eq!(a2.count, 0);
        }

        #[test]
        fn no_duplicate_slots_in_single_alloc() {
            let pool = BufPool::new(8, SIZE);

            let alloc = pool.allocate(8);
            let mut ptrs: Vec<_> = alloc.slots.iter().map(|s| s.ptr()).collect();

            ptrs.sort();
            ptrs.dedup();

            assert_eq!(ptrs.len(), 8);
        }
    }

    mod raii_safety {
        use super::*;

        #[test]
        fn raii_frees_on_drop() {
            let pool = BufPool::new(4, SIZE);

            {
                let alloc = pool.allocate(4);
                assert_eq!(alloc.count, 4);
            }

            let alloc2 = pool.allocate(4);
            assert_eq!(alloc2.count, 4);
        }

        #[test]
        fn raii_partial_free() {
            let pool = BufPool::new(4, SIZE);

            let a1 = pool.allocate(3);
            drop(a1);

            let a2 = pool.allocate(4);
            assert_eq!(a2.count, 4);
        }
    }

    mod concurrency {
        use super::*;
        use std::sync::{Arc, Barrier};
        use std::thread;

        #[test]
        fn concurrent_alloc_free_stress() {
            const THREADS: usize = 8;
            const ITERS: usize = 0x1000;

            let pool = Arc::new(BufPool::new(THREADS as u32, SIZE));
            let barrier = Arc::new(Barrier::new(THREADS));

            let mut handles = Vec::new();

            for _ in 0..THREADS {
                let pool = pool.clone();
                let barrier = barrier.clone();

                handles.push(thread::spawn(move || {
                    barrier.wait();

                    for _ in 0..ITERS {
                        let alloc = pool.allocate(1);
                        if alloc.count == 0 {
                            pool.wait().unwrap();
                            continue;
                        }
                        // freed on drop
                    }
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }

            let final_alloc = pool.allocate(THREADS);
            assert_eq!(final_alloc.count, THREADS);
        }

        #[test]
        fn concurrent_batch_alloc() {
            const THREADS: usize = 4;

            let pool = Arc::new(BufPool::new(8, SIZE));
            let barrier = Arc::new(Barrier::new(THREADS));

            let mut handles = Vec::new();

            for _ in 0..THREADS {
                let pool = pool.clone();
                let barrier = barrier.clone();

                handles.push(thread::spawn(move || {
                    barrier.wait();
                    let alloc = pool.allocate(2);
                    assert!(alloc.count <= 2);
                }));
            }

            for h in handles {
                assert!(h.join().is_ok());
            }

            let final_alloc = pool.allocate(8);
            assert_eq!(final_alloc.count, 8);
        }
    }

    mod shutdown_safety {
        use super::*;
        use std::sync::Arc;
        use std::thread;

        #[test]
        fn drop_waits_for_active_allocations() {
            let pool = Arc::new(BufPool::new(4, SIZE));
            let pool2 = pool.clone();

            let handle = std::thread::spawn(move || {
                let alloc = pool2.allocate(4);
                std::thread::sleep(std::time::Duration::from_millis(50));
                drop(alloc);
            });

            // give the other thread time to allocate
            std::thread::sleep(std::time::Duration::from_millis(10));

            // this must block until alloc is dropped
            drop(pool);

            assert!(handle.join().is_ok());
        }
    }
}
