# ensure-subid

`ensure-subid` is a small helper for systems that need subordinate UID/GID
ranges created automatically when users log in.

It is designed to be run from PAM with `pam_exec.so`. On each PAM
`open_session`, it checks the login user, looks that user up through the normal
system NSS stack, and makes sure `/etc/subuid` and `/etc/subgid` contain usable
ranges for that account.

This is mainly useful on hosts where users come from LDAP, SSSD, or another NSS
source and are not pre-provisioned in `/etc/subuid` and `/etc/subgid`.

## What It Does

When a managed user opens a PAM session, `ensure-subid`:

- resolves the username through `getpwnam_r`, so NSS/SSSD rules apply;
- creates `/etc/subuid` and `/etc/subgid` if they are missing;
- leaves the files alone if both already have any range for the user;
- creates a deterministic paired UID/GID range if neither file has one;
- repairs a one-sided setup by mirroring existing ranges to the missing file
  when those ranges fit the managed slot size and the target ranges are free;
- avoids numeric ranges that are already present, even when their owner field is
  not valid UTF-8 or does not match the user.

Generated entries use the canonical username returned by NSS, not necessarily
the exact string passed by PAM.

## Who Is Managed

The helper only changes files for users that pass all checks:

- the process must run as effective UID 0;
- the PAM event must be `open_session` when `PAM_TYPE` is set;
- `PAM_USER`, or the manual username argument, must be valid UTF-8;
- usernames must not contain NUL, `:`, or newline characters;
- the user must resolve through NSS/SSSD;
- the canonical NSS username must be valid UTF-8 and must not contain NUL, `:`,
  or newline characters;
- users with UID below `1_000_000` are skipped;
- users whose real UID or GID is at or above `1_073_741_824` are rejected.

The last check keeps real user IDs out of the generated subordinate ID pool.

## Managed ID Pool

New ranges are allocated from this pool:

```text
start:      1073741824
end:        2147483648
range size: 65536
```

The preferred slot is derived from the numeric UID. If a username is renamed but
the UID stays the same, the preferred range stays the same.

## Existing Entries

`ensure-subid` matches existing ownership by canonical username and by the
requested username from PAM or the manual argument.

It does not treat numeric owner fields, such as `1234567`, as matching the user.
Those entries still reserve their numeric ranges, so new allocations will avoid
them.

If existing files contain malformed lines, invalid ranges, zero counts, range
overflows, or ranges beyond the 32-bit UID/GID space, the run fails instead of
rewriting the files.

## File Safety

Updates are intentionally conservative:

- symlinks and non-regular `/etc/subuid` or `/etc/subgid` paths are refused;
- updates are written to a temporary file and installed with `rename`;
- existing owner, group, and mode are preserved;
- the intended mode is applied explicitly, even under a restrictive umask;
- the containing directory is synced after replacement;
- `/etc/subuid.lock` and `/etc/subgid.lock` are used to coordinate with
  shadow-utils.

The lock protocol matches shadow-utils' hard-link PID-file locking. It
coordinates with tools that use `sub_uid_lock()` and `sub_gid_lock()`, but it
cannot protect against a manual editor or unrelated tool that ignores those
locks.

Stale lock files are reported as an administrative error and are not removed
automatically.

## Build

```sh
cargo build --release
```

Build for the host's normal glibc target when using LDAP, SSSD, or other NSS
sources. Static musl builds do not participate in glibc NSS in the same way as a
normal system binary.

## Install

Install the binary somewhere root-owned:

```sh
install -o root -g root -m 0755 target/release/ensure-subid /usr/local/sbin/ensure-subid
```

Add it to the relevant PAM session stack. The exact PAM file depends on your
distribution and which service should trigger subordinate ID provisioning.

Non-blocking login behavior:

```text
session optional pam_exec.so type=open_session /usr/local/sbin/ensure-subid
```

Strict behavior that fails the PAM session when setup fails:

```text
session required pam_exec.so type=open_session /usr/local/sbin/ensure-subid --strict
```

Use `optional` or `required` according to your login policy.

## Manual Use

For manual testing, pass the username as the first non-option argument:

```sh
sudo /usr/local/sbin/ensure-subid alice --strict
```

When run by PAM, `PAM_USER` takes precedence over the manual argument.

## Exit Behavior And Logging

Detailed failures are logged through syslog with the `LOG_AUTHPRIV` facility and
the `ensure-subid` identity. Stderr only gets a generic failure message that
points to syslog and states whether the helper is returning 0 because it is
running in non-strict mode.

By default, errors are treated as non-fatal: they are logged as warnings and the
helper exits successfully. Passing `--strict` makes errors produce a non-zero
exit status.

If the helper panics, the panic is caught, logged, and treated the same way:
success by default, non-zero with `--strict`.

## Development

Run the test and lint suite:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The tests cover parsing, allocation planning, username validation, UTF-8 owner
handling, atomic replacement, mode preservation under restrictive umask,
symlink/non-regular file refusal, and shadow-utils lock behavior.

## License

MIT. See [LICENSE](LICENSE).
