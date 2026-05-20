use std::{
    env::{self, VarError},
    ffi::{CStr, CString},
    io,
    os::unix::ffi::OsStrExt,
};

use crate::{
    error::{boxed, Result},
    ids::{MIN_MANAGED_UID, POOL_START},
};

#[derive(Debug, Clone)]
pub(crate) struct Account {
    pub(crate) name: String,
    pub(crate) uid: u64,
    pub(crate) gid: u64,
}

pub(crate) fn requested_user() -> Result<String> {
    if let Some(user) = pam_user()? {
        return Ok(user);
    }

    if let Some(user) = username_arg()? {
        return Ok(user);
    }

    Err(boxed("no PAM_USER or username argument"))
}

fn pam_user() -> Result<Option<String>> {
    match env::var("PAM_USER") {
        Ok(user) if !user.is_empty() => {
            validate_username(&user, "PAM_USER")?;
            return Ok(Some(user));
        }
        Ok(_) | Err(VarError::NotPresent) => {}
        Err(VarError::NotUnicode(_)) => {
            return Err(boxed("PAM_USER is not valid UTF-8"));
        }
    }

    Ok(None)
}

fn username_arg() -> Result<Option<String>> {
    /*
     * For PAM, PAM_USER is supplied by pam_exec.
     * For manual testing, allow:
     *
     *   sudo ensure-subid alice --strict
     */
    for arg in env::args_os().skip(1) {
        let bytes = arg.as_bytes();

        if bytes == b"--strict" {
            continue;
        }

        if bytes.starts_with(b"--") {
            continue;
        }

        let arg = arg
            .into_string()
            .map_err(|_| boxed("username argument is not valid UTF-8"))?;

        if !arg.is_empty() {
            validate_username(&arg, "username argument")?;
            return Ok(Some(arg));
        }
    }

    Ok(None)
}

pub(crate) fn lookup_user(name: &str) -> Result<Account> {
    validate_username(name, "username")?;

    let cname = CString::new(name)?;

    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16_384];

    loop {
        // SAFETY: cname is NUL-terminated, pwd points to writable storage,
        // buf is a writable scratch buffer of length buf.len(), and result
        // points to writable storage for getpwnam_r to fill.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };

        if rc == 0 {
            if result.is_null() {
                return Err(boxed(format!("user not found through NSS/SSSD: {name}")));
            }

            // SAFETY: getpwnam_r returned success and a non-null result,
            // which points at the initialized passwd storage for this call.
            let pwd = unsafe { &*result };
            // SAFETY: on successful lookup, pw_name is a valid NUL-terminated
            // C string owned by the getpwnam_r output buffer.
            let canonical = unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_str()
                .map_err(|_| boxed("canonical username from NSS is not valid UTF-8"))?
                .to_owned();
            validate_username(&canonical, "canonical username from NSS")?;

            return Ok(Account {
                name: canonical,
                uid: pwd.pw_uid as u64,
                gid: pwd.pw_gid as u64,
            });
        }

        if rc == libc::ERANGE {
            if buf.len() >= 1 << 20 {
                return Err(boxed("getpwnam_r buffer grew too large"));
            }
            buf.resize(buf.len() * 2, 0);
            continue;
        }

        return Err(Box::new(io::Error::from_raw_os_error(rc)));
    }
}

fn validate_username(name: &str, source: &str) -> Result<()> {
    if name.as_bytes().contains(&0) {
        return Err(boxed(format!("{source} contains NUL byte")));
    }

    if name.contains(':') {
        return Err(boxed(format!("{source} contains ':'")));
    }

    if name.contains('\n') {
        return Err(boxed(format!("{source} contains newline")));
    }

    Ok(())
}

pub(crate) fn should_manage_account(account: &Account) -> Result<bool> {
    /*
     * Do not allocate subids for local/system users, and do not allocate
     * if the user's real UID/GID overlaps the subordinate pool.
     */
    if account.uid < MIN_MANAGED_UID {
        return Ok(false);
    }

    if account.uid >= POOL_START || account.gid >= POOL_START {
        return Err(boxed(format!(
            "real uid/gid for {} overlaps subordinate pool: uid={}, gid={}, pool_start={}",
            account.name, account.uid, account.gid, POOL_START
        )));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str, uid: u64, gid: u64) -> Account {
        Account {
            name: name.to_string(),
            uid,
            gid,
        }
    }

    fn assert_error_contains(result: Result<()>, needle: &str) {
        let error = result.expect_err("expected an error");
        assert!(
            error.to_string().contains(needle),
            "expected error to contain {needle:?}, got {error}"
        );
    }

    #[test]
    fn validate_username_rejects_subid_separators_and_nul() {
        for (name, expected) in [
            ("bad:name", "contains ':'"),
            ("bad\nname", "contains newline"),
            ("bad\0name", "contains NUL byte"),
        ] {
            assert_error_contains(validate_username(name, "username"), expected);
        }

        assert!(validate_username("alice", "username").is_ok());
    }

    #[test]
    fn should_manage_account_skips_system_users_and_rejects_pool_overlap() -> Result<()> {
        assert!(!should_manage_account(&account(
            "rootish",
            MIN_MANAGED_UID - 1,
            100
        ))?);
        assert!(should_manage_account(&account(
            "alice",
            MIN_MANAGED_UID,
            MIN_MANAGED_UID
        ))?);

        assert_error_contains(
            should_manage_account(&account("alice", POOL_START, MIN_MANAGED_UID)).map(|_| ()),
            "overlaps subordinate pool",
        );
        assert_error_contains(
            should_manage_account(&account("alice", MIN_MANAGED_UID, POOL_START)).map(|_| ()),
            "overlaps subordinate pool",
        );

        Ok(())
    }
}
