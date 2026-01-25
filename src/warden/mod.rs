mod coffin;
mod common;
mod header;

#[derive(Debug)]
pub(crate) struct Warden;

unsafe impl Send for Warden {}
unsafe impl Sync for Warden {}
