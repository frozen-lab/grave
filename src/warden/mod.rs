mod coffin;

#[derive(Debug)]
pub(crate) struct Warden;

unsafe impl Send for Warden {}
unsafe impl Sync for Warden {}
