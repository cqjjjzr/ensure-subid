use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
};

use crate::error::{boxed, Result};

pub(crate) fn ensure_regular_file(path: &Path, mode: u32) -> Result<()> {
    match open_regular_file(path) {
        Ok(_) => Ok(()),

        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)?;

            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            sync_parent_directory(path)?;
            Ok(())
        }

        Err(e) => Err(Box::new(e)),
    }
}

pub(crate) fn read_regular_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = open_regular_file(path)?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

/*
 * Caller must hold the corresponding shadow-utils lock for path across the
 * full read-parse-plan-replace transaction.
 */
pub(crate) fn atomic_replace_locked(path: &Path, contents: &[u8]) -> Result<()> {
    let meta = open_regular_file(path)?.metadata()?;

    let parent = path
        .parent()
        .ok_or_else(|| boxed(format!("no parent directory for {}", path.display())))?;

    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    // SAFETY: temp owns the open descriptor; IDs come from the original file metadata.
    let rc = unsafe { libc::fchown(temp.as_file().as_raw_fd(), meta.uid(), meta.gid()) };
    if rc != 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }

    temp.write_all(contents)?;
    // chown and writes can clear mode bits; restore them before publishing.
    temp.as_file().set_permissions(fs::Permissions::from_mode(
        meta.permissions().mode() & 0o7777,
    ))?;
    temp.as_file().sync_all()?;
    // Drop the staging file immediately on failure, retaining only the I/O error.
    temp.persist(path).map_err(|e| e.error)?;
    sync_parent_directory(path)?;
    Ok(())
}

pub(crate) fn open_regular_file(path: &Path) -> io::Result<File> {
    // A FIFO must not block in open() before we can inspect the descriptor.
    // O_NONBLOCK has no effect on regular-file I/O on Linux.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| map_open_error(path, e))?;

    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::other(format!(
            "not a regular file: {}",
            path.display()
        )));
    }

    Ok(file)
}

fn map_open_error(path: &Path, e: io::Error) -> io::Error {
    if e.raw_os_error() == Some(libc::ELOOP) {
        return io::Error::other(format!("refusing symlink: {}", path.display()));
    }

    e
}

pub(crate) fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(parent)?;

    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_error, isolated, make_fifo};
    use std::os::unix::fs::symlink;

    #[test]
    fn regular_file_lifecycle_preserves_metadata_under_umask() -> Result<()> {
        isolated(
            "atomic_file::tests::regular_file_lifecycle_preserves_metadata_under_umask",
            || {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("data");
                // SAFETY: this child runs one test; no other tests share its umask.
                unsafe {
                    libc::umask(0o077);
                }
                ensure_regular_file(&path, 0o644)?;
                assert_eq!(fs::metadata(&path)?.mode() & 0o7777, 0o644);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                ensure_regular_file(&path, 0o644)?;
                assert_eq!(fs::metadata(&path)?.mode() & 0o7777, 0o600);

                // As root, also exercise preservation of a different owner/group.
                // SAFETY: geteuid has no arguments; file owns the fchown descriptor.
                if unsafe { libc::geteuid() } == 0 {
                    let file = File::open(&path)?;
                    assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 65534, 65534) }, 0);
                }
                let original = fs::metadata(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o6750))?;
                atomic_replace_locked(&path, b"replacement")?;
                assert_eq!(read_regular_file(&path)?, b"replacement");
                let updated = fs::metadata(&path)?;
                assert_eq!(
                    (updated.uid(), updated.gid()),
                    (original.uid(), original.gid())
                );
                assert_eq!(updated.mode() & 0o7777, 0o6750);
                Ok(())
            },
        )
    }

    #[test]
    fn file_operations_refuse_symlinks_directories_and_fifos() -> Result<()> {
        isolated(
            "atomic_file::tests::file_operations_refuse_symlinks_directories_and_fifos",
            || {
                let dir = tempfile::tempdir()?;
                let target = dir.path().join("target");
                let link = dir.path().join("link");
                let fifo = dir.path().join("fifo");
                fs::write(&target, b"original")?;
                symlink(&target, &link)?;
                make_fifo(&fifo)?;

                for (path, reason) in [
                    (link.as_path(), "refusing symlink"),
                    (dir.path(), "not a regular file"),
                    (fifo.as_path(), "not a regular file"),
                ] {
                    assert_error(ensure_regular_file(path, 0o644), reason);
                    assert_error(read_regular_file(path), reason);
                    assert_error(atomic_replace_locked(path, b"replacement"), reason);
                }
                assert_eq!(fs::read(&target)?, b"original");
                Ok(())
            },
        )
    }
}
