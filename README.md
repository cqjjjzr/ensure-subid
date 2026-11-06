# ensure-subid

`ensure-subid` is a PAM helper (`pam_exec.so`) that provisions `/etc/subuid` and `/etc/subgid` ranges on login for NSS-backed users (such as LDAP or SSSD accounts).

## How it works

On `open_session`, `ensure-subid` runs as root and:

1. Resolves `PAM_USER` (or the CLI username argument) via `getpwnam_r`. Users with UID `< 1,000,000` are skipped. Users with UID or primary GID `>= 1,073,741,824` are rejected to avoid colliding with the subordinate ID pool.
2. Acquires `shadow-utils` compatible PID locks (`/etc/subuid.lock` then `/etc/subgid.lock`), creates `/etc/subuid` and `/etc/subgid` (`0644`) if missing, and parses existing entries. Symlinks and non-regular files are refused.
3. Matches existing entries by canonical NSS username or requested username:
   - If both files have entries for the user, it does nothing.
   - If neither file has entries, it allocates a paired `65,536`-ID slot from `1,073,741,824..2,147,483,648` (`2^30..2^31`) that is free in both files. The preferred slot is hashed from the numeric UID (FNV-1a with triangular quadratic probing), so username renames keep the same preferred range.
   - If only one file has entries, it mirrors those ranges to the missing file when each range is `<= 65,536` IDs and does not overlap existing entries in the target file.
4. Appends new entries under the canonical NSS username via a temporary file in `/etc`, preserves file ownership and mode, `fsync`s the file and parent directory, and atomically renames it into place.
5. Logs errors to syslog (`LOG_AUTHPRIV`, ident `ensure-subid`). By default it exits `0` on failure so logins continue; with `--strict`, it exits `1` on error and `101` on panic.

Live-lock conflicts retry every 100 ms within a 14-second elapsed-time budget per file. Filesystem calls already in progress can exceed this deadline. Stale locks are never removed automatically.

Administrators must reserve `1,073,741,824..2,147,483,648` (and any legacy ranges mirrored between files) in both host UID and GID spaces.

## Build

Build for the host glibc target so `getpwnam_r` uses the system NSS modules (do not use a static musl build):

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/ensure-subid /usr/local/sbin/ensure-subid
```

## Debian package

On Debian 13 with Rust installed:

```sh
sudo apt install dpkg-dev liblzma-dev
cargo install cargo-deb --locked
cargo deb --locked
sudo apt install ./target/debian/*.deb
```

## Usage

Add `ensure-subid` to the PAM session stack:

```text
# Log errors to syslog without blocking login:
session optional pam_exec.so type=open_session /usr/sbin/ensure-subid

# Fail the PAM session if provisioning fails:
session required pam_exec.so type=open_session /usr/sbin/ensure-subid --strict
```

Run manually for a specific user (`PAM_USER` takes precedence when set):

```sh
sudo /usr/sbin/ensure-subid alice --strict
```

## Test

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

## License

MIT. See [LICENSE](LICENSE).
