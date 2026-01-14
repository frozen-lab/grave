use crate::file::OsFile;

const PATH: &'static str = "coffin";

#[derive(Debug)]
pub(crate) struct Coffin {
    file: OsFile,
}
