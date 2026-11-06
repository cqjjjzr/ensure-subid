// Don't handle users with IDs below this.
pub(crate) const MIN_MANAGED_UID: u64 = 1_000_000;

pub(crate) const POOL_START: u64 = 1_073_741_824; // 2^30
pub(crate) const POOL_END_EXCLUSIVE: u64 = 2_147_483_648; // 2^31
pub(crate) const RANGE_SIZE: u64 = 65_536;

/*
 * Kernel uid_t/gid_t space is effectively 32-bit on Linux userspace tooling.
 * We keep our generated pool below 2^31 anyway, but validate existing files
 * against 2^32 to avoid parsing nonsense.
 */
pub(crate) const UID_SPACE_END: u64 = 4_294_967_296;

const _: () = {
    assert!(RANGE_SIZE > 0, "RANGE_SIZE must not be zero");
    assert!(POOL_START < POOL_END_EXCLUSIVE, "invalid pool bounds");
    assert!(
        POOL_END_EXCLUSIVE <= UID_SPACE_END,
        "pool exceeds uid/gid space"
    );
    assert!(
        POOL_END_EXCLUSIVE - POOL_START >= RANGE_SIZE,
        "pool is smaller than one range"
    );
    assert!(
        ((POOL_END_EXCLUSIVE - POOL_START) / RANGE_SIZE).is_power_of_two(),
        "slot count must be a power of two"
    );
    assert!(
        POOL_START.is_multiple_of(RANGE_SIZE),
        "pool start must be range-aligned"
    );
};
