use anyhow::anyhow;
use log::{debug, error};
use nix::errno::Errno;
use nix::NixPath;

use crate::error::Error;
use crate::Result;

pub async fn cleanup_mounts(parent_dir: &str) -> Result<()> {
    let parent_dir = if parent_dir.len() == 0 {
        "."
    } else {
        parent_dir
    };
    let mounts = tokio::fs::read_to_string("/proc/mounts")
        .await
        .map_err(Error::IO)?;
    for line in mounts.lines() {
        let fields = line.split_whitespace().collect::<Vec<&str>>();
        let path = fields[1];
        if path.starts_with(&parent_dir) {
            unmount(path, libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW).unwrap_or_else(|e| {
                error!("failed to remove {}, err: {}", path, e);
            });
        }
    }
    Ok(())
}

pub fn unmount(target: &str, flags: i32) -> Result<()> {
    let res = target
        .with_nix_path(|cstr| unsafe { libc::umount2(cstr.as_ptr(), flags) })
        .map_err(|e| anyhow!("failed to umount {}, {}", target, e))?;
    let err = Errno::result(res).map(drop);
    match err {
        Ok(_) => return Ok(()),
        Err(e) => {
            if e == Errno::ENOENT {
                debug!("the umount path {} not exist", target);
                return Ok(());
            }

            return Err(anyhow!("failed to umount {}, {}", target, e).into());
        }
    }
}
