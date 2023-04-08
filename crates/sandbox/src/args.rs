use std::ffi::OsStr;

use crate::error::{Error, Result};

#[derive(Debug, Default)]
pub struct Flags {
    pub listen: String,
    pub dir: String,
}

pub fn parse<S: AsRef<OsStr>>(args: &[S]) -> Result<Flags> {
    let mut flags = Flags::default();

    let _: Vec<String> = go_flag::parse_args(args, |f| {
        f.add_flag("listen", &mut flags.listen);
        f.add_flag("dir", &mut flags.dir);
    })
    .map_err(|e| Error::InvalidArgument(e.to_string()))?;

    if flags.listen.is_empty() {
        return Err(Error::InvalidArgument(String::from(
            "--listen cannot be empty, should be a unix domain socket",
        )));
    }
    if flags.dir.is_empty() {
        return Err(Error::InvalidArgument(String::from(
            "--dir cannot be empty, should be a directory",
        )));
    }
    Ok(flags)
}
