// sanity checks
const _: () = assert!(likely(true));
const _: () = assert!(!likely(false));
const _: () = assert!(unlikely(true));
const _: () = assert!(!unlikely(false));

/// empty function used as a placeholder to influence branch prediction
#[cold]
#[inline]
const fn cold_fn() {}

/// Branch predictor hint, which marks given condition as *likely* to be
#[inline]
pub(crate) const fn likely(b: bool) -> bool {
    if !b {
        cold_fn();
    }
    b
}

/// Branch predictor hint, which marks given condition as *unlikely* to be
#[inline]
pub(crate) const fn unlikely(b: bool) -> bool {
    if b {
        cold_fn();
    }
    b
}
