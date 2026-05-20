use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use crate::error::{boxed, Result};

const LOCK_TRIES: usize = 15;
const LOCK_SLEEP: Duration = Duration::from_secs(1);
const LOCK_PID_MAX_BYTES: usize = 64;
static TEMP_LOCK_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct ShadowLocks {
    locks: Vec<ShadowLock>,
}

impl ShadowLocks {
    pub(crate) fn acquire(paths: &[&Path]) -> Result<Self> {
        let mut ordered_paths = paths.to_vec();
        ordered_paths.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
        ordered_paths.dedup_by(|a, b| a.as_os_str().as_bytes() == b.as_os_str().as_bytes());

        let mut locks = Vec::with_capacity(ordered_paths.len());

        for path in ordered_paths {
            locks.push(ShadowLock::acquire(path)?);
        }

        Ok(Self { locks })
    }
}

impl Drop for ShadowLocks {
    fn drop(&mut self) {
        while let Some(lock) = self.locks.pop() {
            drop(lock);
        }
    }
}

#[derive(Debug)]
struct ShadowLock {
    lock_path: PathBuf,
    lock_file: File,
}

impl ShadowLock {
    fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_with_retry(path, LOCK_TRIES, LOCK_SLEEP)
    }

    fn acquire_with_retry(path: &Path, tries: usize, sleep: Duration) -> Result<Self> {
        let lock_path = append_to_path(path, ".lock");
        let mut last_conflict = None;

        for attempt in 0..tries {
            if attempt > 0 {
                thread::sleep(sleep);
            }

            let temp_path = temp_lock_path(path);

            match try_lock_once(&temp_path, &lock_path) {
                Ok(lock_file) => {
                    return Ok(Self {
                        lock_path,
                        lock_file,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    last_conflict = Some(e);
                    continue;
                }
                Err(e) => return Err(Box::new(e)),
            }
        }

        if let Some(e) = last_conflict {
            return Err(Box::new(e));
        }

        Err(boxed(format!(
            "failed to lock {} after {} attempts",
            lock_path.display(),
            tries
        )))
    }
}

impl Drop for ShadowLock {
    fn drop(&mut self) {
        if remove_lock_if_owned(&self.lock_path, &self.lock_file).unwrap_or(false) {
            let _ = sync_parent_directory(&self.lock_path);
        }
    }
}

fn try_lock_once(temp_path: &Path, lock_path: &Path) -> io::Result<File> {
    let lock_file = write_pid_file(temp_path)?;

    match fs::hard_link(temp_path, lock_path) {
        Ok(()) => {
            let locked = check_link_count(&lock_file);
            let _ = fs::remove_file(temp_path);

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
            let _ = fs::remove_file(temp_path);

            if link_error.kind() != io::ErrorKind::AlreadyExists {
                return Err(link_error);
            }

            existing_lock_error(lock_path)
        }
    }
}

fn write_pid_file(path: &Path) -> io::Result<File> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;

    write!(file, "{}\0", process::id())?;
    file.sync_data()?;
    Ok(file)
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
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

fn temp_lock_path(path: &Path) -> PathBuf {
    let nonce = TEMP_LOCK_NONCE.fetch_add(1, Ordering::Relaxed);
    append_to_path(path, &format!(".{}.{}", process::id(), nonce))
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
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
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_dir(name: &str) -> Result<TestDir> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ensure-subid-{name}-{}-{now}", process::id()));

        fs::create_dir(&path)?;
        Ok(TestDir { path })
    }

    #[test]
    fn shadow_lock_creates_and_removes_lock_file() -> Result<()> {
        let dir = test_dir("shadow-lock")?;
        let data = dir.path.join("data");
        let lock = append_to_path(&data, ".lock");

        {
            let _lock = ShadowLock::acquire(&data)?;
            assert!(lock.exists());
        }

        assert!(!lock.exists());
        Ok(())
    }

    #[test]
    fn shadow_lock_refuses_live_lock() -> Result<()> {
        let dir = test_dir("shadow-lock-live")?;
        let data = dir.path.join("data");
        let _lock = ShadowLock::acquire(&data)?;

        let err = ShadowLock::acquire_with_retry(&data, 1, Duration::from_secs(0))
            .expect_err("expected lock conflict");

        assert_eq!(
            err.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::AlreadyExists)
        );
        Ok(())
    }

    #[test]
    fn shadow_lock_drop_does_not_remove_replaced_lock_path() -> Result<()> {
        let dir = test_dir("shadow-lock-replaced")?;
        let data = dir.path.join("data");
        let lock_path = append_to_path(&data, ".lock");
        let lock = ShadowLock::acquire(&data)?;

        fs::remove_file(&lock_path)?;
        fs::write(&lock_path, b"12345\0")?;

        drop(lock);

        assert_eq!(fs::read(&lock_path)?, b"12345\0");
        Ok(())
    }

    #[test]
    fn shadow_lock_refuses_stale_lock_without_removing_it() -> Result<()> {
        let dir = test_dir("shadow-lock-stale")?;
        let data = dir.path.join("data");
        let lock = append_to_path(&data, ".lock");
        fs::write(&lock, b"999999999\0")?;

        let err = ShadowLock::acquire_with_retry(&data, 2, Duration::from_secs(0))
            .expect_err("expected stale lock conflict");

        let err = err.downcast_ref::<io::Error>().expect("expected io error");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains("stale lock held by dead pid"),
            "unexpected error: {err}"
        );
        assert!(lock.exists());
        assert_eq!(fs::read(&lock)?, b"999999999\0");
        Ok(())
    }

    #[test]
    fn missing_existing_lock_is_retryable() -> Result<()> {
        let dir = test_dir("shadow-lock-missing")?;
        let lock = dir.path.join("data.lock");

        let err = existing_lock_error(&lock).expect_err("expected retryable missing lock");

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        Ok(())
    }

    #[test]
    fn read_lock_pid_rejects_non_positive_and_overlong_values() -> Result<()> {
        let dir = test_dir("shadow-lock-pid-parse")?;
        let lock = dir.path.join("data.lock");

        fs::write(&lock, b"0\0")?;
        assert_eq!(
            read_lock_pid(&lock)
                .expect_err("expected zero pid rejection")
                .kind(),
            io::ErrorKind::InvalidData
        );

        fs::write(&lock, b"-1\0")?;
        assert_eq!(
            read_lock_pid(&lock)
                .expect_err("expected negative pid rejection")
                .kind(),
            io::ErrorKind::InvalidData
        );

        fs::write(&lock, vec![b'1'; LOCK_PID_MAX_BYTES + 1])?;
        assert_eq!(
            read_lock_pid(&lock)
                .expect_err("expected overlong pid rejection")
                .kind(),
            io::ErrorKind::InvalidData
        );

        Ok(())
    }

    #[test]
    fn shadow_locks_acquires_in_canonical_order_and_deduplicates() -> Result<()> {
        let dir = test_dir("shadow-lock-order")?;
        let data_a = dir.path.join("a");
        let data_b = dir.path.join("b");
        let lock_a = append_to_path(&data_a, ".lock");
        let lock_b = append_to_path(&data_b, ".lock");

        {
            let _locks = ShadowLocks::acquire(&[&data_b, &data_a, &data_b])?;
            assert!(lock_a.exists());
            assert!(lock_b.exists());
        }

        assert!(!lock_a.exists());
        assert!(!lock_b.exists());
        Ok(())
    }
}
