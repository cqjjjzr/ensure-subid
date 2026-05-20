use crate::{
    account::Account,
    error::{boxed, Result},
    ids::{POOL_END_EXCLUSIVE, POOL_START, RANGE_SIZE, UID_SPACE_END},
};

#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) owner: Option<String>,
    pub(crate) start: u64,
    pub(crate) count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubidFile {
    Uid,
    Gid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedEntry {
    pub(crate) file: SubidFile,
    pub(crate) start: u64,
    pub(crate) count: u64,
}

pub(crate) fn validate_constants() -> Result<()> {
    if RANGE_SIZE == 0 {
        return Err(boxed("RANGE_SIZE must not be zero"));
    }

    if POOL_START >= POOL_END_EXCLUSIVE {
        return Err(boxed("POOL_START must be below POOL_END_EXCLUSIVE"));
    }

    if POOL_END_EXCLUSIVE > UID_SPACE_END {
        return Err(boxed("pool exceeds 32-bit uid/gid space"));
    }

    if POOL_END_EXCLUSIVE - POOL_START < RANGE_SIZE {
        return Err(boxed("pool is smaller than one subordinate range"));
    }

    let slots = (POOL_END_EXCLUSIVE - POOL_START) / RANGE_SIZE;
    if !slots.is_power_of_two() {
        return Err(boxed("subordinate range slot count must be a power of two"));
    }

    if !POOL_START.is_multiple_of(RANGE_SIZE) {
        return Err(boxed("POOL_START should be aligned to RANGE_SIZE"));
    }

    Ok(())
}

pub(crate) fn parse_entries(path_name: &str, contents: &[u8]) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();

    for (idx, raw) in contents.split(|b| *b == b'\n').enumerate() {
        if let Some(entry) = parse_entry(path_name, idx + 1, raw)? {
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub(crate) fn plan_subid_updates(
    account: &Account,
    requested_user: &str,
    subuid_entries: &[Entry],
    subgid_entries: &[Entry],
) -> Result<Vec<PlannedEntry>> {
    let mut owner_keys = vec![account.name.clone(), requested_user.to_string()];
    owner_keys.sort();
    owner_keys.dedup();

    let subuid_existing = owned_ranges(subuid_entries, &owner_keys);
    let subgid_existing = owned_ranges(subgid_entries, &owner_keys);

    /*
     * If both files already configure any subordinate space for the user, leave
     * it alone. Existing ranges do not have to match each other or the current
     * hash preference.
     */
    if !subuid_existing.is_empty() && !subgid_existing.is_empty() {
        return Ok(Vec::new());
    }

    match (subuid_existing.as_slice(), subgid_existing.as_slice()) {
        (ranges, []) if ranges_exceed_slot(ranges) => Ok(Vec::new()),

        ([], ranges) if ranges_exceed_slot(ranges) => Ok(Vec::new()),

        (ranges, []) if !ranges.is_empty() && ranges_available(subgid_entries, ranges) => {
            Ok(mirror_updates(SubidFile::Gid, ranges))
        }

        ([], ranges) if !ranges.is_empty() && ranges_available(subuid_entries, ranges) => {
            Ok(mirror_updates(SubidFile::Uid, ranges))
        }

        ([], []) => {
            /*
             * New allocation. The chosen slot must be free in both files.
             * We use the same numeric start for UID and GID subranges. UID
             * and GID spaces are separate, so this is not a conflict; it just
             * makes auditing easier.
             */
            let start = choose_range(account, subuid_entries, subgid_entries)?;
            Ok(paired_updates(start))
        }

        _ => Ok(Vec::new()),
    }
}

pub(crate) fn append_entries(old_contents: &[u8], owner: &str, ranges: &[(u64, u64)]) -> Vec<u8> {
    let mut new_contents = Vec::with_capacity(old_contents.len() + ranges.len() * 64);
    new_contents.extend_from_slice(old_contents);

    if !new_contents.is_empty() && !new_contents.ends_with(b"\n") {
        new_contents.push(b'\n');
    }

    for (start, count) in ranges {
        new_contents.extend_from_slice(owner.as_bytes());
        new_contents.push(b':');
        new_contents.extend_from_slice(start.to_string().as_bytes());
        new_contents.push(b':');
        new_contents.extend_from_slice(count.to_string().as_bytes());
        new_contents.push(b'\n');
    }

    new_contents
}

fn parse_entry(path_name: &str, line_no: usize, raw: &[u8]) -> Result<Option<Entry>> {
    let line = trim_ascii(raw);

    if line.is_empty() || line.starts_with(b"#") {
        return Ok(None);
    }

    let parts: Vec<&[u8]> = line.split(|b| *b == b':').collect();
    if parts.len() != 3 {
        return Err(boxed(format!("{path_name}:{line_no}: invalid field count")));
    }

    if parts[0].is_empty() {
        return Err(boxed(format!("{path_name}:{line_no}: empty owner")));
    }

    let owner = std::str::from_utf8(parts[0]).ok().map(ToOwned::to_owned);
    let start = parse_u64_field(path_name, line_no, parts[1], "start id")?;
    let count = parse_u64_field(path_name, line_no, parts[2], "count")?;

    if count == 0 {
        return Err(boxed(format!("{path_name}:{line_no}: zero count")));
    }

    let end = start
        .checked_add(count)
        .ok_or_else(|| boxed(format!("{path_name}:{line_no}: range overflow")))?;

    if end > UID_SPACE_END {
        return Err(boxed(format!(
            "{path_name}:{line_no}: range exceeds 32-bit uid/gid space"
        )));
    }

    Ok(Some(Entry {
        owner,
        start,
        count,
    }))
}

fn parse_u64_field(path_name: &str, line_no: usize, bytes: &[u8], field: &str) -> Result<u64> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| boxed(format!("{path_name}:{line_no}: invalid {field}")))?;

    text.parse()
        .map_err(|_| boxed(format!("{path_name}:{line_no}: invalid {field}")))
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);

    &bytes[start..end]
}

fn paired_updates(start: u64) -> Vec<PlannedEntry> {
    vec![
        PlannedEntry {
            file: SubidFile::Uid,
            start,
            count: RANGE_SIZE,
        },
        /*
         * If this second write fails, the next login repairs it because
         * the code handles the "only subuid exists" case above.
         */
        PlannedEntry {
            file: SubidFile::Gid,
            start,
            count: RANGE_SIZE,
        },
    ]
}

fn mirror_updates(file: SubidFile, ranges: &[Entry]) -> Vec<PlannedEntry> {
    ranges
        .iter()
        .map(|range| PlannedEntry {
            file,
            start: range.start,
            count: range.count,
        })
        .collect()
}

fn owned_ranges(entries: &[Entry], owner_keys: &[String]) -> Vec<Entry> {
    entries
        .iter()
        .filter(|e| owned_range(e, owner_keys))
        .cloned()
        .collect()
}

fn owned_range(entry: &Entry, owner_keys: &[String]) -> bool {
    entry
        .owner
        .as_ref()
        .map(|owner| owner_keys.iter().any(|k| k == owner))
        .unwrap_or(false)
}

fn ranges_available(entries: &[Entry], ranges: &[Entry]) -> bool {
    ranges
        .iter()
        .all(|range| range_available(entries, range.start, range.count))
}

fn ranges_exceed_slot(ranges: &[Entry]) -> bool {
    ranges.iter().any(|range| range.count > RANGE_SIZE)
}

fn choose_range(
    account: &Account,
    subuid_entries: &[Entry],
    subgid_entries: &[Entry],
) -> Result<u64> {
    let slots = (POOL_END_EXCLUSIVE - POOL_START) / RANGE_SIZE;

    if slots == 0 {
        return Err(boxed("no slots available"));
    }

    /*
     * Stable hash key. We write username owners, but keep allocation
     * preference tied to UID so username renames do not move the user.
     */
    let key = account.uid.to_string();
    let preferred = fnv1a64(key.as_bytes()) % slots;

    for probe in 0..slots {
        let slot = probe_slot(preferred, probe, slots);
        let start = POOL_START + slot * RANGE_SIZE;

        if range_available(subuid_entries, start, RANGE_SIZE)
            && range_available(subgid_entries, start, RANGE_SIZE)
        {
            return Ok(start);
        }
    }

    Err(boxed(format!(
        "subordinate id pool exhausted: start={}, end={}, range_size={}, slots={}",
        POOL_START, POOL_END_EXCLUSIVE, RANGE_SIZE, slots
    )))
}

fn probe_slot(preferred: u64, probe: u64, slots: u64) -> u64 {
    /*
     * Triangular quadratic probing. For power-of-two slot counts, these
     * offsets visit every slot exactly once while avoiding linear clustering.
     */
    let offset = probe * (probe + 1) / 2;
    (preferred + offset) % slots
}

fn range_available(entries: &[Entry], start: u64, count: u64) -> bool {
    entries
        .iter()
        .all(|e| !ranges_overlap(start, count, e.start, e.count))
}

fn ranges_overlap(a_start: u64, a_count: u64, b_start: u64, b_count: u64) -> bool {
    let Some(a_end) = a_start.checked_add(a_count) else {
        return true;
    };

    let Some(b_end) = b_start.checked_add(b_count) else {
        return true;
    };

    a_start < b_end && b_start < a_end
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;

    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(owner: &str, start: u64, count: u64) -> Entry {
        Entry {
            owner: Some(owner.to_string()),
            start,
            count,
        }
    }

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
    fn probe_slot_uses_full_cycle_quadratic_order() {
        let slots = 16;
        let preferred = 5;
        let sequence: Vec<u64> = (0..slots)
            .map(|probe| probe_slot(preferred, probe, slots))
            .collect();
        let mut sorted = sequence.clone();
        sorted.sort_unstable();

        assert_eq!(sequence[..5], [5, 6, 8, 11, 15]);
        assert_eq!(sorted, (0..slots).collect::<Vec<_>>());
    }

    #[test]
    fn parse_entries_accepts_comments_blank_lines_and_whitespace() -> Result<()> {
        let second_start = POOL_START + RANGE_SIZE;
        let entries = parse_entries(
            "/tmp/subuid",
            format!(
                "\n# managed elsewhere\n  alice:{POOL_START}:{RANGE_SIZE}  \n1001:{second_start}:{}\n",
                RANGE_SIZE * 2
            )
            .as_bytes(),
        )?;

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].owner.as_deref(), Some("alice"));
        assert_eq!(entries[0].start, POOL_START);
        assert_eq!(entries[0].count, RANGE_SIZE);
        assert_eq!(entries[1].owner.as_deref(), Some("1001"));
        assert_eq!(entries[1].start, second_start);
        assert_eq!(entries[1].count, RANGE_SIZE * 2);

        Ok(())
    }

    #[test]
    fn parse_entries_allows_non_utf8_owners_while_reserving_ranges() -> Result<()> {
        let entries = parse_entries("/tmp/subuid", b"\xffuser:1073741824:65536\n")?;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].owner, None);
        assert_eq!(entries[0].start, POOL_START);
        assert_eq!(entries[0].count, RANGE_SIZE);
        assert!(!owned_range(&entries[0], &["user".to_string()]));
        assert!(!range_available(&entries, POOL_START, RANGE_SIZE));

        Ok(())
    }

    #[test]
    fn parse_entries_rejects_malformed_lines() {
        let cases = [
            ("alice:1", "invalid field count"),
            (":1:1", "empty owner"),
            ("alice:nope:1", "invalid start id"),
            ("alice:1:nope", "invalid count"),
            ("alice:1:0", "zero count"),
            ("alice:18446744073709551615:2", "range overflow"),
            ("alice:4294967295:2", "range exceeds 32-bit uid/gid space"),
        ];

        for (text, expected) in cases {
            assert_error_contains(
                parse_entries("/tmp/subuid", text.as_bytes()).map(|_| ()),
                expected,
            );
        }
    }

    #[test]
    fn ranges_overlap_handles_boundaries_and_overflow() {
        assert!(ranges_overlap(10, 5, 14, 5));
        assert!(ranges_overlap(10, 5, 5, 6));
        assert!(!ranges_overlap(10, 5, 15, 5));
        assert!(!ranges_overlap(10, 5, 0, 10));
        assert!(ranges_overlap(u64::MAX - 1, 4, 0, 1));
        assert!(ranges_overlap(0, 1, u64::MAX - 1, 4));
    }

    #[test]
    fn range_available_rejects_any_overlap() {
        let entries = [
            entry("one", 1_000, 100),
            entry("two", 2_000, 100),
            entry("three", 3_000, 100),
        ];

        assert!(range_available(&entries, 1_100, 900));
        assert!(!range_available(&entries, 1_050, 10));
        assert!(!range_available(&entries, 1_900, 200));
    }

    #[test]
    fn owned_ranges_matches_any_owner_key() {
        let entries = [
            entry("alice", POOL_START, RANGE_SIZE - 1),
            entry("1001", POOL_START + RANGE_SIZE, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
        ];
        let owner_keys = vec!["alice".to_string(), "1001".to_string()];

        let found = owned_ranges(&entries, &owner_keys);

        assert_eq!(found.len(), 3);
        assert_eq!(found[0].owner.as_deref(), Some("alice"));
        assert_eq!(found[1].owner.as_deref(), Some("1001"));
        assert_eq!(found[2].owner.as_deref(), Some("alice"));
    }

    #[test]
    fn append_entries_adds_separator_when_existing_contents_lack_trailing_newline() {
        let contents = append_entries(b"root:0:1", "alice", &[(POOL_START, RANGE_SIZE)]);

        assert_eq!(
            contents,
            format!("root:0:1\nalice:{POOL_START}:{RANGE_SIZE}\n").into_bytes()
        );
    }

    #[test]
    fn append_entries_does_not_add_extra_separator_after_trailing_newline() {
        let contents = append_entries(b"root:0:1\n", "alice", &[(POOL_START, RANGE_SIZE)]);

        assert_eq!(
            contents,
            format!("root:0:1\nalice:{POOL_START}:{RANGE_SIZE}\n").into_bytes()
        );
    }

    #[test]
    fn append_entries_appends_multiple_ranges_in_order() {
        let contents = append_entries(
            b"",
            "alice",
            &[
                (POOL_START, RANGE_SIZE),
                (POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
            ],
        );

        assert_eq!(
            contents,
            format!(
                "alice:{POOL_START}:{RANGE_SIZE}\nalice:{}:{RANGE_SIZE}\n",
                POOL_START + RANGE_SIZE * 2
            )
            .into_bytes()
        );
    }

    #[test]
    fn choose_range_is_stable_and_avoids_subuid_and_subgid_entries() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);

        let preferred = choose_range(&account, &[], &[])?;
        assert_eq!(preferred % RANGE_SIZE, 0);
        assert!(preferred >= POOL_START);
        assert!(preferred + RANGE_SIZE <= POOL_END_EXCLUSIVE);
        assert_eq!(choose_range(&account, &[], &[])?, preferred);

        let subuid_taken = [entry("other", preferred, RANGE_SIZE)];
        let after_subuid_collision = choose_range(&account, &subuid_taken, &[])?;
        assert_ne!(after_subuid_collision, preferred);
        assert!(range_available(
            &subuid_taken,
            after_subuid_collision,
            RANGE_SIZE
        ));

        let slots = (POOL_END_EXCLUSIVE - POOL_START) / RANGE_SIZE;
        let preferred_slot = (preferred - POOL_START) / RANGE_SIZE;
        let next_linear_slot = POOL_START + probe_slot(preferred_slot, 1, slots) * RANGE_SIZE;
        let next_quadratic_slot = POOL_START + probe_slot(preferred_slot, 2, slots) * RANGE_SIZE;
        let linear_cluster = [
            entry("other", preferred, RANGE_SIZE),
            entry("other", next_linear_slot, RANGE_SIZE),
        ];
        let after_cluster = choose_range(&account, &linear_cluster, &[])?;
        assert_eq!(after_cluster, next_quadratic_slot);

        let subgid_taken = [entry("other", preferred, RANGE_SIZE)];
        let after_subgid_collision = choose_range(&account, &[], &subgid_taken)?;
        assert_ne!(after_subgid_collision, preferred);
        assert!(range_available(
            &subgid_taken,
            after_subgid_collision,
            RANGE_SIZE
        ));

        Ok(())
    }

    #[test]
    fn plan_subid_updates_returns_no_writes_when_both_files_are_configured() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("alice", POOL_START, RANGE_SIZE)];
        let subgid_entries = [entry("alice", POOL_START + RANGE_SIZE, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert!(updates.is_empty());
        Ok(())
    }

    #[test]
    fn plan_subid_updates_ignores_numeric_uid_owned_entries_for_user_matching() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("1234567", POOL_START, RANGE_SIZE)];
        let subgid_entries = [entry("1234567", POOL_START + RANGE_SIZE, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].file, SubidFile::Uid);
        assert_eq!(updates[1].file, SubidFile::Gid);
        assert_eq!(updates[0].start, updates[1].start);
        assert!(range_available(
            &subuid_entries,
            updates[0].start,
            updates[0].count
        ));
        assert!(range_available(
            &subgid_entries,
            updates[1].start,
            updates[1].count
        ));

        Ok(())
    }

    #[test]
    fn plan_subid_updates_returns_no_writes_when_both_files_have_multiple_ranges() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [
            entry("alice", POOL_START, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE, RANGE_SIZE),
        ];
        let subgid_entries = [
            entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE * 3, RANGE_SIZE),
        ];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert!(updates.is_empty());
        Ok(())
    }

    #[test]
    fn plan_subid_updates_mirrors_multiple_uid_ranges_to_missing_gid_side() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [
            entry("alice", POOL_START, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
        ];
        let subgid_entries = [entry("other", POOL_START + RANGE_SIZE * 5, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].file, SubidFile::Gid);
        assert_eq!(updates[1].file, SubidFile::Gid);
        assert_eq!(updates[0].start, POOL_START);
        assert_eq!(updates[0].count, RANGE_SIZE);
        assert_eq!(updates[1].start, POOL_START + RANGE_SIZE * 2);
        assert_eq!(updates[1].count, RANGE_SIZE);

        Ok(())
    }

    #[test]
    fn plan_subid_updates_mirrors_multiple_gid_ranges_to_missing_uid_side() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("other", POOL_START + RANGE_SIZE * 5, RANGE_SIZE)];
        let subgid_entries = [
            entry("alice", POOL_START, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
        ];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].file, SubidFile::Uid);
        assert_eq!(updates[1].file, SubidFile::Uid);
        assert_eq!(updates[0].start, POOL_START);
        assert_eq!(updates[0].count, RANGE_SIZE);
        assert_eq!(updates[1].start, POOL_START + RANGE_SIZE * 2);
        assert_eq!(updates[1].count, RANGE_SIZE);

        Ok(())
    }

    #[test]
    fn plan_subid_updates_repairs_missing_gid_with_existing_uid_range() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("alice", POOL_START, RANGE_SIZE)];
        let subgid_entries = [entry("other", POOL_START + RANGE_SIZE * 4, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert_eq!(
            updates,
            vec![PlannedEntry {
                file: SubidFile::Gid,
                start: POOL_START,
                count: RANGE_SIZE,
            }]
        );
        Ok(())
    }

    #[test]
    fn plan_subid_updates_repairs_missing_uid_with_existing_gid_range() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("other", POOL_START + RANGE_SIZE * 4, RANGE_SIZE)];
        let subgid_entries = [entry("alice", POOL_START, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert_eq!(
            updates,
            vec![PlannedEntry {
                file: SubidFile::Uid,
                start: POOL_START,
                count: RANGE_SIZE,
            }]
        );
        Ok(())
    }

    #[test]
    fn plan_subid_updates_skips_one_sided_single_range_that_exceeds_slot_size() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("alice", POOL_START, RANGE_SIZE + 1)];
        let subgid_entries = [entry("other", POOL_START + RANGE_SIZE * 4, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert!(updates.is_empty());
        Ok(())
    }

    #[test]
    fn plan_subid_updates_skips_one_sided_multiple_ranges_when_any_exceeds_slot_size() -> Result<()>
    {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [
            entry("alice", POOL_START, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE + 1),
        ];
        let subgid_entries = [entry("other", POOL_START + RANGE_SIZE * 4, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert!(updates.is_empty());
        Ok(())
    }

    #[test]
    fn plan_subid_updates_skips_single_range_mirror_when_target_range_is_taken() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [entry("alice", POOL_START, RANGE_SIZE)];
        let subgid_entries = [entry("other", POOL_START, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert!(updates.is_empty());

        Ok(())
    }

    #[test]
    fn plan_subid_updates_skips_multiple_range_mirror_when_any_target_range_is_taken() -> Result<()>
    {
        let account = account("alice", 1_234_567, 1_234_567);
        let subuid_entries = [
            entry("alice", POOL_START, RANGE_SIZE),
            entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
        ];
        let subgid_entries = [entry("other", POOL_START + RANGE_SIZE * 2, RANGE_SIZE)];

        let updates = plan_subid_updates(&account, "alice", &subuid_entries, &subgid_entries)?;

        assert!(updates.is_empty());

        Ok(())
    }

    #[test]
    fn plan_subid_updates_allocates_same_new_range_for_uid_and_gid() -> Result<()> {
        let account = account("alice", 1_234_567, 1_234_567);

        let updates = plan_subid_updates(&account, "alice", &[], &[])?;

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].file, SubidFile::Uid);
        assert_eq!(updates[1].file, SubidFile::Gid);
        assert_eq!(updates[0].start, updates[1].start);
        assert_eq!(updates[0].count, RANGE_SIZE);
        assert_eq!(updates[1].count, RANGE_SIZE);

        Ok(())
    }
}
