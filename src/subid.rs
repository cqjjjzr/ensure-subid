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
    let owner_keys = [account.name.as_str(), requested_user];

    let subuid_existing = owned_ranges(subuid_entries, &owner_keys);
    let subgid_existing = owned_ranges(subgid_entries, &owner_keys);

    match (subuid_existing.as_slice(), subgid_existing.as_slice()) {
        ([], []) => {
            /*
             * New allocation. The chosen slot must be free in both files.
             * UID and GID spaces are separate; matching numbers simplify auditing.
             */
            let start = choose_range(account, subuid_entries, subgid_entries)?;
            Ok(paired_updates(start))
        }
        (ranges, []) => plan_mirror(SubidFile::Gid, ranges, subgid_entries),
        ([], ranges) => plan_mirror(SubidFile::Uid, ranges, subuid_entries),
        // Both sides are configured. Preserve existing ranges even if they
        // differ from each other or the current allocation policy.
        _ => Ok(Vec::new()),
    }
}

fn plan_mirror(file: SubidFile, ranges: &[Entry], target: &[Entry]) -> Result<Vec<PlannedEntry>> {
    let path = match file {
        SubidFile::Uid => "/etc/subuid",
        SubidFile::Gid => "/etc/subgid",
    };
    if ranges_exceed_slot(ranges) {
        return Err(boxed(format!(
            "{path}: cannot repair missing ranges: a source range exceeds {RANGE_SIZE} IDs; manual repair required"
        )));
    }
    if !ranges_available(target, ranges) {
        return Err(boxed(format!(
            "{path}: cannot repair missing ranges: a source range overlaps an existing target allocation; manual repair required"
        )));
    }

    // Legacy mirroring deliberately allows ranges outside the generated pool.
    // Administrators must reserve those numbers in BOTH UID and GID spaces;
    // absence from the target subid file is not proof of that reservation.
    Ok(mirror_updates(file, ranges))
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
    let line = raw.trim_ascii();

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

fn owned_ranges(entries: &[Entry], owner_keys: &[&str]) -> Vec<Entry> {
    entries
        .iter()
        .filter(|e| owned_range(e, owner_keys))
        .cloned()
        .collect()
}

fn owned_range(entry: &Entry, owner_keys: &[&str]) -> bool {
    entry
        .owner
        .as_deref()
        .is_some_and(|owner| owner_keys.contains(&owner))
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
    use crate::test_support::assert_error;

    fn account() -> Account {
        Account {
            name: "alice".into(),
            uid: 1_234_567,
            gid: 1_234_567,
        }
    }

    fn entry(owner: &str, start: u64, count: u64) -> Entry {
        Entry {
            owner: Some(owner.into()),
            start,
            count,
        }
    }

    fn plan(uids: &[Entry], gids: &[Entry]) -> Result<Vec<(SubidFile, u64, u64)>> {
        Ok(plan_subid_updates(&account(), "alias", uids, gids)?
            .into_iter()
            .map(|e| (e.file, e.start, e.count))
            .collect())
    }

    #[test]
    fn parsing_preserves_ranges_and_tolerates_non_utf8_owners() -> Result<()> {
        let entries = parse_entries(
            "subuid",
            b"\n # comment\n alice:100:2 \n1001:200:3\n\xffuser:300:4\nlast:4294967295:1\n",
        )?;
        let fields: Vec<_> = entries
            .iter()
            .map(|e| (e.owner.as_deref(), e.start, e.count))
            .collect();
        assert_eq!(
            fields,
            [
                (Some("alice"), 100, 2),
                (Some("1001"), 200, 3),
                (None, 300, 4),
                (Some("last"), UID_SPACE_END - 1, 1)
            ]
        );
        assert!(!range_available(&entries, 300, 4));
        Ok(())
    }

    #[test]
    fn malformed_entries_report_file_line_and_reason() {
        for (line, reason) in [
            ("alice:1", "invalid field count"),
            (":1:1", "empty owner"),
            ("alice:nope:1", "invalid start id"),
            ("alice:1:nope", "invalid count"),
            ("alice:1:0", "zero count"),
            ("alice:18446744073709551615:2", "range overflow"),
            ("alice:4294967295:2", "range exceeds 32-bit uid/gid space"),
        ] {
            assert_error(
                parse_entries("subuid", format!("# comment\n{line}").as_bytes()),
                &format!("subuid:2: {reason}"),
            );
        }
    }

    #[test]
    fn appended_ranges_preserve_old_bytes_and_newline_boundaries() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"root:0:1", b"root:0:1\n"),
            (b"root:0:1\n", b"root:0:1\n"),
            (b"\xff:0:1", b"\xff:0:1\n"),
        ];
        for &(old, prefix) in cases {
            assert_eq!(
                append_entries(old, "alice", &[(100, 2), (200, 3)]),
                [prefix, b"alice:100:2\nalice:200:3\n"].concat()
            );
        }
    }

    #[test]
    fn overlap_checks_boundaries_and_overflow() {
        assert!(ranges_overlap(10, 5, 14, 5));
        assert!(ranges_overlap(10, 5, 5, 6));
        assert!(!ranges_overlap(10, 5, 15, 5));
        assert!(!ranges_overlap(10, 5, 0, 10));
        assert!(ranges_overlap(u64::MAX - 1, 4, 0, 1));
        assert!(ranges_overlap(0, 1, u64::MAX - 1, 4));
    }

    #[test]
    fn quadratic_probes_visit_every_slot() {
        let sequence: Vec<_> = (0..16).map(|probe| probe_slot(5, probe, 16)).collect();
        assert_eq!(sequence[..5], [5, 6, 8, 11, 15]);
        let mut sorted = sequence;
        sorted.sort_unstable();
        assert_eq!(sorted, (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn new_allocations_are_stable_paired_and_avoid_both_files() -> Result<()> {
        let preferred = choose_range(&account(), &[], &[])?;
        assert_eq!(preferred % RANGE_SIZE, 0);
        assert!(preferred >= POOL_START && preferred + RANGE_SIZE <= POOL_END_EXCLUSIVE);
        let renamed = Account {
            name: "renamed".into(),
            ..account()
        };
        assert_eq!(choose_range(&renamed, &[], &[])?, preferred);
        let next = |offset| {
            POOL_START
                + (preferred - POOL_START + offset * RANGE_SIZE) % (POOL_END_EXCLUSIVE - POOL_START)
        };
        // Numeric and undecodable owners reserve space but do not identify alice.
        let numeric = entry("1234567", preferred, RANGE_SIZE);
        let unknown = Entry {
            owner: None,
            ..numeric.clone()
        };
        for (uids, gids, expected) in [
            (vec![], vec![], preferred),
            (vec![numeric.clone()], vec![], next(1)),
            (vec![], vec![unknown.clone()], next(1)),
            (
                vec![numeric],
                vec![Entry {
                    start: next(1),
                    ..unknown
                }],
                next(3),
            ),
        ] {
            assert_eq!(
                plan(&uids, &gids)?,
                [
                    (SubidFile::Uid, expected, RANGE_SIZE),
                    (SubidFile::Gid, expected, RANGE_SIZE)
                ]
            );
        }
        assert_error(
            plan(
                &[entry("other", POOL_START, POOL_END_EXCLUSIVE - POOL_START)],
                &[],
            ),
            "pool exhausted",
        );
        Ok(())
    }

    #[test]
    fn configured_pairs_are_left_unchanged() -> Result<()> {
        for (uids, gids) in [
            (
                vec![entry("alice", POOL_START, RANGE_SIZE)],
                vec![entry("alias", POOL_START + RANGE_SIZE, RANGE_SIZE)],
            ),
            (
                vec![entry("alice", 100, 1), entry("alias", 200, 2)],
                vec![entry("alice", 300, 3), entry("alias", 400, 4)],
            ),
            (
                vec![entry("alice", 200_000_000, RANGE_SIZE * 2)],
                vec![entry("alice", 300_000_000, 1)],
            ),
        ] {
            assert!(plan(&uids, &gids)?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn one_sided_ranges_are_mirrored_in_either_direction() -> Result<()> {
        for ranges in [
            vec![("alice", POOL_START, RANGE_SIZE)],
            vec![
                ("alice", POOL_START, RANGE_SIZE),
                ("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
            ],
            // Legacy ranges may be unaligned/outside the pool and total more than one slot.
            vec![
                ("alias", 200_000_001, RANGE_SIZE),
                ("alice", 200_200_001, 1),
            ],
        ] {
            let mut source: Vec<_> = ranges
                .iter()
                .map(|&(owner, start, count)| entry(owner, start, count))
                .collect();
            source.push(entry("other", 100, 1));
            let target = [entry("other", POOL_START + RANGE_SIZE * 5, RANGE_SIZE)];
            for (uids, gids, file) in [
                (&source[..], &target[..], SubidFile::Gid),
                (&target[..], &source[..], SubidFile::Uid),
            ] {
                let expected: Vec<_> = ranges
                    .iter()
                    .map(|&(_, start, count)| (file, start, count))
                    .collect();
                assert_eq!(plan(uids, gids)?, expected);
            }
        }
        Ok(())
    }

    #[test]
    fn unrepairable_ranges_fail_without_planning_partial_repairs() {
        for (source, target, reason) in [
            (
                vec![entry("alice", POOL_START, RANGE_SIZE + 1)],
                vec![],
                "exceeds",
            ),
            (
                vec![
                    entry("alice", POOL_START, RANGE_SIZE),
                    entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE + 1),
                ],
                vec![],
                "exceeds",
            ),
            (
                vec![entry("alice", POOL_START, RANGE_SIZE)],
                vec![entry("other", POOL_START, RANGE_SIZE)],
                "overlaps",
            ),
            (
                vec![
                    entry("alice", POOL_START, RANGE_SIZE),
                    entry("alice", POOL_START + RANGE_SIZE * 2, RANGE_SIZE),
                ],
                vec![entry("other", POOL_START + RANGE_SIZE * 2 + 1, 1)],
                "overlaps",
            ),
        ] {
            for (uids, gids, missing) in [
                (&source, &target, "/etc/subgid"),
                (&target, &source, "/etc/subuid"),
            ] {
                let error = plan(uids, gids).unwrap_err().to_string();
                assert!(error.contains(missing) && error.contains(reason), "{error}");
            }
        }
    }
}
