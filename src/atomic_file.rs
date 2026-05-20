use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
    process,
    time::{SystemTime, UNIX_EPOCH},
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

            set_file_mode(&file, mode)?;
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
    let existing = open_regular_file(path)?;
    let meta = existing.metadata()?;

    let parent = path
        .parent()
        .ok_or_else(|| boxed(format!("no parent directory for {}", path.display())))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| boxed(format!("no filename for {}", path.display())))?
        .to_string_lossy();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let tmp_path = parent.join(format!(
        ".{}.ensure-subid.{}.{}.tmp",
        file_name,
        process::id(),
        now
    ));

    let mode = meta.permissions().mode() & 0o7777;
    let uid = meta.uid();
    let gid = meta.gid();

    let write_result = write_temp_file(&tmp_path, contents, mode, uid, gid);

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(Box::new(e));
    }

    sync_directory(parent)?;

    Ok(())
}

fn open_regular_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
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

fn write_temp_file(path: &Path, contents: &[u8], mode: u32, uid: u32, gid: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;

    // SAFETY: file.as_raw_fd() is a valid open file descriptor for file's
    // lifetime. uid and gid were read from filesystem metadata.
    let rc = unsafe { libc::fchown(file.as_raw_fd(), uid as libc::uid_t, gid as libc::gid_t) };
    if rc != 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }

    set_file_mode(&file, mode)?;
    file.write_all(contents)?;
    file.sync_all()?;

    Ok(())
}

fn set_file_mode(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?;

    dir.sync_all()?;
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| boxed(format!("no parent directory for {}", path.display())))?;

    sync_directory(parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, os::unix::fs::symlink, path::PathBuf, sync::Mutex};

    static UMASK_LOCK: Mutex<()> = Mutex::new(());

    struct TestDir {
        path: PathBuf,
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct UmaskGuard {
        old: libc::mode_t,
    }

    impl UmaskGuard {
        fn set(mask: libc::mode_t) -> Self {
            Self {
                // SAFETY: umask has no pointer arguments. Tests serialize
                // calls with UMASK_LOCK because umask is process-global.
                old: unsafe { libc::umask(mask) },
            }
        }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            // SAFETY: umask has no pointer arguments. Tests serialize calls
            // with UMASK_LOCK because umask is process-global.
            unsafe {
                libc::umask(self.old);
            }
        }
    }

    fn test_dir(name: &str) -> Result<TestDir> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!("ensure-subid-{name}-{}-{now}", process::id()));

        fs::create_dir(&path)?;
        Ok(TestDir { path })
    }

    fn mode(path: &Path) -> Result<u32> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
    }

    fn assert_error_contains(result: Result<()>, needle: &str) {
        let error = result.expect_err("expected an error");
        assert!(
            error.to_string().contains(needle),
            "expected error to contain {needle:?}, got {error}"
        );
    }

    #[test]
    fn ensure_regular_file_preserves_mode_despite_umask() -> Result<()> {
        let dir = test_dir("ensure-regular-file-mode")?;
        let path = dir.path.join("data");
        let _lock = UMASK_LOCK.lock().unwrap();
        let _umask = UmaskGuard::set(0o077);

        ensure_regular_file(&path, 0o644)?;

        let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644);

        Ok(())
    }

    #[test]
    fn ensure_regular_file_leaves_existing_file_mode_unchanged() -> Result<()> {
        let dir = test_dir("ensure-existing-file-mode")?;
        let path = dir.path.join("data");
        fs::write(&path, "")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        ensure_regular_file(&path, 0o644)?;

        assert_eq!(mode(&path)?, 0o600);
        Ok(())
    }

    #[test]
    fn ensure_regular_file_refuses_symlink_and_directory() -> Result<()> {
        let dir = test_dir("ensure-refuses-unsafe-paths")?;
        let target = dir.path.join("target");
        let link = dir.path.join("link");
        let child_dir = dir.path.join("child-dir");

        fs::write(&target, "")?;
        symlink(&target, &link)?;
        fs::create_dir(&child_dir)?;

        assert_error_contains(ensure_regular_file(&link, 0o644), "refusing symlink");
        assert_error_contains(ensure_regular_file(&child_dir, 0o644), "not a regular file");

        Ok(())
    }

    #[test]
    fn atomic_replace_replaces_contents_and_preserves_mode_despite_umask() -> Result<()> {
        let dir = test_dir("atomic-replace-mode")?;
        let path = dir.path.join("data");
        fs::write(&path, "old")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;

        let _lock = UMASK_LOCK.lock().unwrap();
        let _umask = UmaskGuard::set(0o077);
        atomic_replace_locked(&path, b"replacement")?;

        assert_eq!(fs::read(&path)?, b"replacement");
        assert_eq!(mode(&path)?, 0o644);

        let temp_files = fs::read_dir(&dir.path)?
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".ensure-subid.")
            })
            .count();
        assert_eq!(temp_files, 0);

        Ok(())
    }

    #[test]
    fn atomic_replace_refuses_symlink_and_leaves_target_unchanged() -> Result<()> {
        let dir = test_dir("atomic-replace-symlink")?;
        let target = dir.path.join("target");
        let link = dir.path.join("link");

        fs::write(&target, "original")?;
        symlink(&target, &link)?;

        assert_error_contains(
            atomic_replace_locked(&link, b"replacement"),
            "refusing symlink",
        );
        assert_eq!(fs::read_to_string(&target)?, "original");

        Ok(())
    }

    #[test]
    fn read_regular_file_refuses_directory() -> Result<()> {
        let dir = test_dir("read-regular-file-refuses-directory")?;
        let child_dir = dir.path.join("child-dir");
        fs::create_dir(&child_dir)?;

        let error = read_regular_file(&child_dir).expect_err("expected an error");
        assert!(
            error.to_string().contains("not a regular file")
                || error.to_string().contains("Is a directory"),
            "unexpected error: {error}"
        );

        Ok(())
    }
}
