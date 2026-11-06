use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use crate::{
    atomic_file::{open_regular_file, sync_parent_directory},
    error::Result,
};

// Preserve the previous wait budget: 14 sleeps between 15 attempts.
const LOCK_TIMEOUT: Duration = Duration::from_secs(14);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const LOCK_PID_MAX_BYTES: usize = 64;

#[derive(Debug)]
pub(crate) struct ShadowLocks {
    // Fields drop in declaration order, reversing the acquisition order.
    _subgid: ShadowLock,
    _subuid: ShadowLock,
}

impl ShadowLocks {
    pub(crate) fn acquire(subuid: &Path, subgid: &Path) -> Result<Self> {
        // Match shadow-utils: subuid first, then subgid (not alphabetical order).
        let subuid = ShadowLock::acquire(subuid)?;
        let subgid = ShadowLock::acquire(subgid)?;
        Ok(Self {
            _subgid: subgid,
            _subuid: subuid,
        })
    }
}

#[derive(Debug)]
struct ShadowLock {
    lock_path: PathBuf,
    lock_file: File,
}

impl ShadowLock {
    fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_with_timeout(path, LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(path: &Path, timeout: Duration) -> Result<Self> {
        let lock_path = append_to_path(path, ".lock");
        let deadline = Instant::now() + timeout;

        // Always make an initial attempt, including for a zero timeout.
        loop {
            match try_lock_once(&lock_path) {
                Ok(lock_file) => {
                    return Ok(Self {
                        lock_path,
                        lock_file,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(Box::new(e));
                    }
                    thread::sleep(LOCK_RETRY_INTERVAL.min(remaining));
                    // Scheduling may delay waking; do not start a retry after expiry.
                    if Instant::now() >= deadline {
                        return Err(Box::new(e));
                    }
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
    }
}

impl Drop for ShadowLock {
    fn drop(&mut self) {
        if remove_lock_if_owned(&self.lock_path, &self.lock_file).unwrap_or(false) {
            let _ = sync_parent_directory(&self.lock_path);
        }
    }
}

fn try_lock_once(lock_path: &Path) -> io::Result<File> {
    let parent = lock_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    write!(temp, "{}\0", process::id())?;
    temp.as_file().sync_data()?;

    match fs::hard_link(temp.path(), lock_path) {
        Ok(()) => {
            let locked = check_link_count(temp.as_file());
            let lock_file = temp.into_file();

            if locked? {
                if let Err(e) = sync_parent_directory(lock_path) {
                    let _ = remove_lock_if_owned(lock_path, &lock_file);
                    return Err(e);
                }
                Ok(lock_file)
            } else {
                let _ = remove_lock_if_owned(lock_path, &lock_file);
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "lock file link count mismatch",
                ))
            }
        }

        Err(link_error) => {
            if link_error.kind() != io::ErrorKind::AlreadyExists {
                return Err(link_error);
            }

            existing_lock_error(lock_path)
        }
    }
}

fn check_link_count(file: &File) -> io::Result<bool> {
    Ok(file.metadata()?.nlink() == 2)
}

fn existing_lock_error(lock_path: &Path) -> io::Result<File> {
    match read_lock_pid(lock_path) {
        Ok(pid) if process_alive(pid) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("lock already held by pid {pid}"),
        )),
        Ok(pid) => Err(io::Error::other(format!(
            "stale lock held by dead pid {pid}; refusing to remove automatically"
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "lock disappeared before pid could be read",
        )),
        Err(e) => Err(e),
    }
}

fn read_lock_pid(path: &Path) -> io::Result<i32> {
    let file = open_regular_file(path)?;
    let mut contents = Vec::new();
    let mut limited = file.take(LOCK_PID_MAX_BYTES as u64 + 1);
    limited.read_to_end(&mut contents)?;

    if contents.len() > LOCK_PID_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lock pid file is too large",
        ));
    }

    let pid_bytes = contents
        .split(|b| *b == b'\0' || b.is_ascii_whitespace())
        .find(|part| !part.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "lock file has no pid"))?;

    let pid_text = std::str::from_utf8(pid_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "lock pid is not UTF-8"))?;

    let pid = pid_text
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "lock pid is invalid"))?;

    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lock pid must be positive",
        ));
    }

    Ok(pid)
}

fn process_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 does not send a signal. It only checks
    // whether the process exists and whether it can be signaled.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };

    if rc == 0 {
        return true;
    }

    matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
}

fn append_to_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn remove_lock_if_owned(path: &Path, file: &File) -> io::Result<bool> {
    let file_meta = file.metadata()?;
    let path_meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    if !path_meta.file_type().is_file() {
        return Ok(false);
    }

    if path_meta.dev() != file_meta.dev() || path_meta.ino() != file_meta.ino() {
        return Ok(false);
    }

    fs::remove_file(path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_error, isolated, make_fifo};
    use std::os::unix::fs::{symlink, FileTypeExt};

    #[test]
    fn lock_pair_writes_pid_excludes_contenders_and_cleans_up() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let subuid = dir.path().join("subuid");
        let subgid = dir.path().join("subgid");
        let locks = ShadowLocks::acquire(&subuid, &subgid)?;
        for path in [&subuid, &subgid] {
            assert_eq!(
                fs::read(append_to_path(path, ".lock"))?,
                format!("{}\0", process::id()).as_bytes()
            );
            let error = ShadowLock::acquire_with_timeout(path, Duration::ZERO).unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::AlreadyExists
            );
        }
        assert_eq!(fs::read_dir(dir.path())?.count(), 2);
        drop(locks);
        assert_eq!(fs::read_dir(dir.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn live_lock_honors_retry_deadline() -> Result<()> {
        isolated("lock::tests::live_lock_honors_retry_deadline", || {
            let dir = tempfile::tempdir()?;
            let data = dir.path().join("data");
            let _held = ShadowLock::acquire(&data)?;
            let timeout = Duration::from_millis(150);
            let start = Instant::now();
            assert_error(
                ShadowLock::acquire_with_timeout(&data, timeout),
                "lock already held",
            );
            assert!(start.elapsed() >= timeout);
            Ok(())
        })
    }

    #[test]
    fn existing_locks_are_never_removed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data = dir.path().join("data");
        let lock = append_to_path(&data, ".lock");
        for (contents, reason) in [
            (
                format!("{}\0", process::id()).into_bytes(),
                "lock already held",
            ),
            (
                format!("{}\n", process::id()).into_bytes(),
                "lock already held",
            ),
            (b"999999999\0".to_vec(), "stale lock"),
            (b"0\0".to_vec(), "must be positive"),
            (b"-1\0".to_vec(), "must be positive"),
            (vec![b'1'; LOCK_PID_MAX_BYTES + 1], "too large"),
            (vec![], "no pid"),
            (vec![0xff], "not UTF-8"),
        ] {
            fs::write(&lock, &contents)?;
            assert_error(
                ShadowLock::acquire_with_timeout(&data, Duration::ZERO),
                reason,
            );
            assert_eq!(fs::read(&lock)?, contents);
            assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        }
        Ok(())
    }

    #[test]
    fn unsafe_second_lock_releases_first_without_blocking() -> Result<()> {
        isolated(
            "lock::tests::unsafe_second_lock_releases_first_without_blocking",
            || {
                let dir = tempfile::tempdir()?;
                let first = dir.path().join("subuid");
                let second = dir.path().join("subgid");
                let lock = append_to_path(&second, ".lock");
                let target = dir.path().join("target");
                fs::write(&target, format!("{}\0", process::id()))?;
                for kind in ["symlink", "directory", "fifo"] {
                    match kind {
                        "symlink" => symlink(&target, &lock)?,
                        "directory" => fs::create_dir(&lock)?,
                        _ => make_fifo(&lock)?,
                    }
                    let reason = if kind == "symlink" {
                        "refusing symlink"
                    } else {
                        "not a regular file"
                    };
                    assert_error(ShadowLocks::acquire(&first, &second), reason);
                    assert!(!append_to_path(&first, ".lock").exists());
                    let file_type = fs::symlink_metadata(&lock)?.file_type();
                    match kind {
                        "symlink" => assert!(file_type.is_symlink()),
                        "directory" => assert!(file_type.is_dir()),
                        _ => assert!(file_type.is_fifo()),
                    }
                    assert_eq!(fs::read_dir(dir.path())?.count(), 2);
                    if kind == "directory" {
                        fs::remove_dir(&lock)?;
                    } else {
                        fs::remove_file(&lock)?;
                    }
                }
                assert_eq!(fs::read(target)?, format!("{}\0", process::id()).as_bytes());
                Ok(())
            },
        )
    }

    #[test]
    fn subuid_is_attempted_before_subgid() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let subuid = dir.path().join("subuid");
        let subgid = dir.path().join("subgid");
        // Distinct immediate errors reveal which path is attempted first.
        fs::write(append_to_path(&subuid, ".lock"), b"0\0")?;
        fs::create_dir(append_to_path(&subgid, ".lock"))?;
        assert_error(
            ShadowLocks::acquire(&subuid, &subgid),
            "lock pid must be positive",
        );
        assert_eq!(fs::read_dir(dir.path())?.count(), 2);
        Ok(())
    }

    #[test]
    fn drop_preserves_a_replacement_lock() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data = dir.path().join("data");
        let path = append_to_path(&data, ".lock");
        let lock = ShadowLock::acquire(&data)?;
        fs::remove_file(&path)?;
        fs::write(&path, b"12345\0")?;
        drop(lock);
        assert_eq!(fs::read(&path)?, b"12345\0");
        Ok(())
    }

    #[test]
    fn vanished_lock_is_retryable() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let error = existing_lock_error(&dir.path().join("missing.lock")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        Ok(())
    }
}
