use std::{
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Condvar, Mutex,
    },
};

const INVALID_POOL_SLOT: u64 = u64::MAX;

#[derive(Debug)]
pub(crate) struct BufPool {
    cap: u64,
    ptr: PoolPtr,
    size: u64,
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
    pub(crate) fn new(cap: u64, size: u64) -> Self {
        // sanity check
        debug_assert!(cap > 0 && size > 0, "cap and size can not be 0");

        let pool_size = (cap * size) as usize;
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
            let n = if _i < cap { _i } else { INVALID_POOL_SLOT };
            next.push(AtomicU64::new(n));
        }

        Self {
            ptr,
            cap,
            size,
            cdvr: Condvar::new(),
            lock: Mutex::new(()),
            active: AtomicUsize::new(0),
            shutdown_cdvr: Condvar::new(),
            next: next.into_boxed_slice(),
            head: AtomicU64::new(pack_pool_idx(0, 0)),
        }
    }
}

impl Drop for BufPool {
    fn drop(&mut self) {
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
const fn unpack_pool_idx(v: u64) -> (u64, u64) {
    (v & POOL_IDX_MASK, v >> POOL_IDX_BITS)
}

//
// Pool Pointer
//

type TSlot = *mut u8;

#[derive(Debug)]
struct PoolPtr(TSlot);

unsafe impl Send for PoolPtr {}
unsafe impl Sync for PoolPtr {}

impl PoolPtr {
    #[inline]
    const fn ptr(&self) -> TSlot {
        self.0
    }

    #[inline]
    const fn add(&self, count: u64) -> Self {
        unsafe { Self(self.0.add(count as usize)) }
    }

    #[inline]
    const fn offset_from(&self, ptr: &Self) -> usize {
        unsafe { ptr.0.offset_from(self.0) as usize }
    }
}

//
// Allocation
//

#[derive(Debug)]
pub(crate) struct Allocation {
    pub(crate) count: usize,
    pub(crate) slots: Vec<TSlot>,
}

impl Allocation {
    #[inline]
    fn new(cap: usize) -> Self {
        Self {
            count: 0,
            slots: Vec::<TSlot>::with_capacity(cap),
        }
    }
}
