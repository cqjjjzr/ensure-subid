mod account;
mod atomic_file;
mod error;
mod ids;
mod lock;
mod log;
mod subid;

use std::{env, path::Path, process};

use account::{lookup_user, requested_user, should_manage_account};
use atomic_file::{atomic_replace_locked, ensure_regular_file, read_regular_file};
use error::Result;
use lock::ShadowLocks;
use log::log_warning;
use subid::{
    append_entries, parse_entries, plan_subid_updates, validate_constants, PlannedEntry, SubidFile,
};

const SUBUID_PATH: &str = "/etc/subuid";
const SUBGID_PATH: &str = "/etc/subgid";

fn main() {
    let strict = env::args_os().any(|a| a == "--strict");

    let result = std::panic::catch_unwind(run);

    match result {
        Ok(Ok(())) => process::exit(0),

        Ok(Err(e)) => {
            log_warning(&format!("non-fatal error: {e}"));
            print_failure(strict);
            process::exit(if strict { 1 } else { 0 });
        }

        Err(_) => {
            log_warning("panic caught; treating as non-fatal");
            print_failure(strict);
            process::exit(if strict { 101 } else { 0 });
        }
    }
}

fn print_failure(strict: bool) {
    if strict {
        eprintln!("ensure-subid: failed; see syslog; returning non-zero due to strict settings");
    } else {
        eprintln!("ensure-subid: failed; see syslog; returning 0 due to non-strict settings");
    }
}

fn run() -> Result<()> {
    validate_constants()?;

    /*
     * If run by pam_exec with type=open_session, this is redundant.
     * It makes accidental execution on close_session harmless.
     */
    if let Ok(pam_type) = env::var("PAM_TYPE") {
        if pam_type != "open_session" {
            return Ok(());
        }
    }

    // SAFETY: geteuid has no arguments and does not dereference memory.
    if unsafe { libc::geteuid() } != 0 {
        return Err(error::boxed("must run as root"));
    }

    let requested_user = requested_user()?;
    let account = lookup_user(&requested_user)?;

    if !should_manage_account(&account)? {
        return Ok(());
    }

    let _locks = ShadowLocks::acquire(&[Path::new(SUBUID_PATH), Path::new(SUBGID_PATH)])?;

    ensure_regular_file(Path::new(SUBUID_PATH), 0o644)?;
    ensure_regular_file(Path::new(SUBGID_PATH), 0o644)?;

    let subuid_text = read_regular_file(Path::new(SUBUID_PATH))?;
    let subgid_text = read_regular_file(Path::new(SUBGID_PATH))?;

    let subuid_entries = parse_entries(SUBUID_PATH, &subuid_text)?;
    let subgid_entries = parse_entries(SUBGID_PATH, &subgid_text)?;

    let updates = plan_subid_updates(&account, &requested_user, &subuid_entries, &subgid_entries)?;
    apply_updates(&updates, &subuid_text, &subgid_text, &account.name)
}

fn apply_updates(
    updates: &[PlannedEntry],
    subuid_text: &[u8],
    subgid_text: &[u8],
    owner: &str,
) -> Result<()> {
    let mut subuid_ranges = Vec::new();
    let mut subgid_ranges = Vec::new();

    for update in updates {
        let range = (update.start, update.count);

        match update.file {
            SubidFile::Uid => subuid_ranges.push(range),
            SubidFile::Gid => subgid_ranges.push(range),
        }
    }

    if !subuid_ranges.is_empty() {
        let contents = append_entries(subuid_text, owner, &subuid_ranges);
        atomic_replace_locked(Path::new(SUBUID_PATH), &contents)?;
    }

    if !subgid_ranges.is_empty() {
        let contents = append_entries(subgid_text, owner, &subgid_ranges);
        atomic_replace_locked(Path::new(SUBGID_PATH), &contents)?;
    }

    Ok(())
}
