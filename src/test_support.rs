use std::{
    ffi::CString,
    fmt::{Debug, Display},
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::error::Result;

pub(crate) fn assert_error<T: Debug, E: Debug + Display>(
    result: std::result::Result<T, E>,
    needle: &str,
) {
    let error = result.unwrap_err();
    assert!(
        error.to_string().contains(needle),
        "expected {needle:?}, got {error}"
    );
}

pub(crate) fn make_fifo(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: path is a live NUL-terminated string; mkfifo retains no pointer.
    if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Isolate process-global state and bound potentially blocking I/O to five seconds.
pub(crate) fn isolated(test_name: &str, test: impl FnOnce() -> Result<()>) -> Result<()> {
    const MARKER: &str = "ENSURE_SUBID_TIMEOUT_TEST";
    if std::env::var(MARKER).as_deref() == Ok(test_name) {
        return test();
    }

    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", test_name, "--nocapture"])
        .env(MARKER, test_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            assert!(
                output.status.success(),
                "child test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
                "child did not run the requested test: {test_name}"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{test_name} blocked for five seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
