/// empty function used as a placeholder to influence branch prediction
#[cold]
#[inline]
const fn cold_fn() {}

/// Hint for branch predictor that given branch condition is *likely* to be `true`
#[inline]
pub(crate) const fn likely(b: bool) -> bool {
    if !b {
        cold_fn();
    }
    b
}

#[test]
fn test_sanity_of_likely_hint() {
    assert!(likely(true), "true should be true");
    assert!(!likely(false), "false should be false");
}

/// Hint for branch predictor that given branch condition is *unlikely* to be `true`
#[inline]
pub(crate) const fn unlikely(b: bool) -> bool {
    if b {
        cold_fn();
    }
    b
}

#[test]
fn test_sanity_of_unlikely_hint() {
    assert!(unlikely(true), "true should be true");
    assert!(!unlikely(false), "false should be false");
}

//
// Flush modes
//

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum IOFlushMode {
    Background,
    Immediate,
}
