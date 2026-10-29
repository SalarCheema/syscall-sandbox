//! Step-2 checks for the syscall sandbox carried to a second architecture:
//! each decision resolves by name through the number table of the
//! architecture it was asked about, the reasons recorded for each name
//! govern how the name is treated there, and argument-conditioned rules
//! shape allowance on ruled names, with the audit entry recording the
//! condition that changed or allowed the decision.

use syscall_sandbox::{Arch, ArgCond, Policy, Verdict};

const FIRST: Arch = Arch::X86_64;
const SECOND: Arch = Arch::Aarch64;

// Public reference numbering, from the kernel tables the skeleton doc
// records. The first table is the round-1 universe; the second table is
// the public second-architecture reference. Membership, reasons, and
// rules are never taken from these lists: they are derived at runtime.
const FIRST_TABLE: [(&str, u64); 10] = [
    ("read", 0),
    ("write", 1),
    ("open", 2),
    ("close", 3),
    ("mmap", 9),
    ("mprotect", 10),
    ("socket", 41),
    ("clone", 56),
    ("execve", 59),
    ("openat", 257),
];

const SECOND_TABLE: [(&str, u64); 9] = [
    ("read", 63),
    ("write", 64),
    ("openat", 56),
    ("close", 57),
    ("socket", 198),
    ("clone", 220),
    ("execve", 221),
    ("mmap", 222),
    ("mprotect", 226),
];

fn fresh() -> Policy {
    Policy::default_policy()
}

fn universe_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = Vec::new();
    for (name, _) in FIRST_TABLE.iter().chain(SECOND_TABLE.iter()) {
        if !names.contains(name) {
            names.push(name);
        }
    }
    names
}

fn resolves(policy: &Policy, arch: Arch, name: &str) -> bool {
    policy.table(arch).number_of(name).is_some()
}

// The recorded reason for a name, which must exist and must carry text:
// a reason that is literally empty would make every containment check
// below vacuous, so emptiness is asserted here, once, for every use.
fn recorded_reason(policy: &Policy, name: &str) -> String {
    let reason = policy
        .reason_for(name)
        .unwrap_or_else(|| panic!("name {name} must carry a recorded reason"));
    assert!(!reason.is_empty(), "name {name} carries an empty reason");
    reason
}

fn rule_index(cond: &ArgCond) -> usize {
    match *cond {
        ArgCond::Range { arg, .. } => arg,
        ArgCond::Eq { arg, .. } => arg,
    }
}

fn meeting_value(cond: &ArgCond) -> u64 {
    match *cond {
        ArgCond::Range { min, .. } => min,
        ArgCond::Eq { value, .. } => value,
    }
}

// Arguments meeting every rule on the name, built only from the rules
// themselves: long enough to reach the largest referenced index, with
// each referenced index holding a value its condition accepts.
fn satisfying_args(policy: &Policy, name: &str) -> Vec<u64> {
    let rules = policy.arg_rules_for(name);
    let len = rules.iter().map(|(c, _)| rule_index(c) + 1).max().unwrap_or(0);
    let mut args = vec![0u64; len];
    for _ in 0..=rules.len() {
        let mut pending = false;
        for (cond, _) in &rules {
            if !cond.met_by(&args) {
                args[rule_index(cond)] = meeting_value(cond);
                pending = true;
            }
        }
        if !pending {
            break;
        }
    }
    args
}

// Arguments breaking the first rule on the name while keeping the other
// indices at meeting values. Candidates step outside a range in both
// directions, off an equality value, and to the extremes, until the
// condition itself reports unmet.
fn breaking_args(policy: &Policy, name: &str) -> Vec<u64> {
    let rules = policy.arg_rules_for(name);
    assert!(!rules.is_empty(), "name {name} has no rule to break");
    let mut args = satisfying_args(policy, name);
    let cond = rules[0].0;
    let idx = rule_index(&cond);
    if args.len() <= idx {
        args.resize(idx + 1, 0);
    }
    let mut candidates: Vec<u64> = Vec::new();
    match cond {
        ArgCond::Range { min, max, .. } => {
            candidates.push(max.wrapping_add(1));
            candidates.push(max.wrapping_add(2));
            candidates.push(min.wrapping_sub(1));
            candidates.push(min.wrapping_sub(2));
            candidates.push(u64::MAX);
            candidates.push(0);
            candidates.push(u64::MAX / 2);
        }
        ArgCond::Eq { value, .. } => {
            candidates.push(value.wrapping_add(1));
            candidates.push(value.wrapping_add(2));
            candidates.push(value.wrapping_sub(1));
            candidates.push(value.wrapping_sub(2));
            candidates.push(u64::MAX);
            candidates.push(0);
            candidates.push(!value);
        }
    }
    for cand in candidates {
        args[idx] = cand;
        if !cond.met_by(&args) {
            return args;
        }
    }
    panic!("name {name}: no candidate argument breaks its first rule");
}

fn rule_notes(policy: &Policy, name: &str) -> Vec<String> {
    policy
        .arg_rules_for(name)
        .into_iter()
        .map(|(_, note)| note)
        .collect()
}

// Ruled names are derived, never listed: allowed names carrying at
// least one argument-conditioned rule.
fn ruled_allowed(policy: &Policy) -> Vec<String> {
    policy
        .allowed_names()
        .into_iter()
        .filter(|name| !policy.arg_rules_for(name).is_empty())
        .collect()
}

fn denied_names(policy: &Policy) -> Vec<String> {
    let allowed = policy.allowed_names();
    universe_names()
        .into_iter()
        .filter(|name| !allowed.iter().any(|a| a == name))
        .map(|name| name.to_string())
        .collect()
}

fn invented_names(policy: &Policy) -> Vec<String> {
    let mut names: Vec<String> = vec![
        String::new(),
        " ".to_string(),
        "frobnicate".to_string(),
        "no_such_call".to_string(),
        "ioctl".to_string(),
        "readlink".to_string(),
        "qq_nope".to_string(),
    ];
    // Near misses of every allowed name, derived at runtime: case folds,
    // padding, affixes, and doubling must not resolve to the real name.
    for name in policy.allowed_names() {
        names.push(name.to_ascii_uppercase());
        names.push(format!("{name} "));
        names.push(format!(" {name}"));
        names.push(format!("{name}x"));
        names.push(format!("x{name}"));
        names.push(format!("{name}{name}"));
        let mut capitalised = String::new();
        for (i, c) in name.chars().enumerate() {
            capitalised.push(if i == 0 { c.to_ascii_uppercase() } else { c });
        }
        names.push(capitalised);
    }
    names
}

fn broad_args() -> Vec<Vec<u64>> {
    vec![
        vec![],
        vec![0],
        vec![1],
        vec![2],
        vec![3],
        vec![4],
        vec![100],
        vec![u64::MAX],
        vec![0, 0],
        vec![1, 2],
        vec![0, 1, 2],
        vec![0, 1, 2, 3],
        vec![3, 2, 1, 0],
        vec![0, 0, 0, 0, 0],
        vec![u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX],
        vec![1, 2, 3, 4, 5, 6],
        vec![999, 999, 999],
    ]
}

fn probe_args(policy: &Policy) -> Vec<Vec<u64>> {
    let mut args = broad_args();
    for name in ruled_allowed(policy) {
        args.push(satisfying_args(policy, &name));
        args.push(breaking_args(policy, &name));
    }
    args
}

fn unused_number(policy: &Policy) -> u64 {
    let mut number = 10_000u64;
    loop {
        if policy.table(FIRST).name_of(number).is_none()
            && policy.table(SECOND).name_of(number).is_none()
        {
            return number;
        }
        number += 1;
    }
}

#[test]
fn s2_aarch64_table_matches_reference() {
    let p = fresh();
    let table = p.table(SECOND);
    assert_eq!(table.len(), SECOND_TABLE.len());
    assert!(!table.is_empty());
    let mut numbers: Vec<u64> = Vec::new();
    for (name, number) in SECOND_TABLE {
        assert_eq!(table.number_of(name), Some(number), "name {name}");
        assert_eq!(table.name_of(number), Some(name), "number {number}");
        numbers.push(number);
    }
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(
        numbers.len(),
        SECOND_TABLE.len(),
        "second-table numbers must be distinct"
    );
    // Names the second table does not carry resolve to nothing there,
    // including names that exist only on the first table.
    for name in universe_names() {
        if SECOND_TABLE.iter().all(|(n, _)| *n != name) {
            assert_eq!(table.number_of(name), None, "absent name {name}");
        }
    }
    for name in invented_names(&p) {
        assert_eq!(table.number_of(&name), None, "unknown name {name:?}");
    }
    // Numbers with no second-table entry resolve to no name, whether
    // they belong to the first table or to nothing at all.
    let second_numbers: Vec<u64> = SECOND_TABLE.iter().map(|(_, n)| *n).collect();
    for (_, number) in FIRST_TABLE {
        if !second_numbers.contains(&number) {
            assert_eq!(table.name_of(number), None, "number {number}");
        }
    }
    for number in [999u64, 1000, 65_535, u64::MAX] {
        assert_eq!(table.name_of(number), None, "number {number}");
    }
    // The first table is undisturbed by the second table's presence.
    let first = p.table(FIRST);
    assert_eq!(first.len(), FIRST_TABLE.len());
    for (name, number) in FIRST_TABLE {
        assert_eq!(first.number_of(name), Some(number), "name {name}");
        assert_eq!(first.name_of(number), Some(name), "number {number}");
    }
}

#[test]
fn s2_arch_conflict_number_56() {
    let p = fresh();
    // Every number that names different calls on the two architectures
    // is found from the tables, not assumed: the conflicting number is
    // whichever one that turns out to be.
    let mut conflicts = 0;
    for (name, number) in FIRST_TABLE {
        let Some(other) = p.table(SECOND).name_of(number) else {
            continue;
        };
        if other == name {
            continue;
        }
        conflicts += 1;
        let via_first = p.decide_by_number(FIRST, number, &[]);
        let via_second = p.decide_by_number(SECOND, number, &[]);
        assert_eq!(via_first.name, name, "number {number}");
        assert_eq!(via_second.name, other, "number {number}");
        assert_ne!(via_first.name, via_second.name, "number {number}");
        assert_eq!(via_first.number, Some(number));
        assert_eq!(via_second.number, Some(number));
        assert_eq!(via_first.arch, FIRST);
        assert_eq!(via_second.arch, SECOND);
        assert_eq!(p.table(FIRST).number_of(name), Some(number));
        assert_eq!(p.table(SECOND).number_of(other), Some(number));
        assert_eq!(
            via_first.verdict,
            p.decide(FIRST, name, &[]).verdict,
            "number {number}"
        );
        let args = satisfying_args(&p, other);
        assert_eq!(
            p.decide_by_number(SECOND, number, &args).verdict,
            p.decide(SECOND, other, &args).verdict,
            "number {number}"
        );
        for entry in [via_first, via_second] {
            assert!(!entry.reason.is_empty(), "number {number}");
            if let Some(recorded) = p.reason_for(&entry.name) {
                assert!(!recorded.is_empty(), "number {number}");
                assert!(
                    entry.reason.contains(&recorded),
                    "number {number}: verdict must carry the recorded reason"
                );
            }
        }
    }
    assert!(conflicts > 0, "the tables must conflict on at least one number");
}

#[test]
fn s2_name_resolution_uses_arch_table() {
    let p = fresh();
    for name in universe_names() {
        for arch in [FIRST, SECOND] {
            let Some(number) = p.table(arch).number_of(name) else {
                continue;
            };
            let entry = p.decide(arch, name, &[]);
            assert_eq!(entry.number, Some(number), "name {name} arch {arch:?}");
            assert_eq!(entry.name, name);
            assert_eq!(entry.arch, arch);
            let by_number = p.decide_by_number(arch, number, &[]);
            assert_eq!(by_number.name, name, "number {number}");
            assert_eq!(by_number.number, Some(number));
            assert_eq!(by_number.arch, arch);
            assert_eq!(by_number.verdict, entry.verdict, "name {name}");
        }
    }
    // At least one name carries different numbers, and each such name
    // resolves to its own number on each architecture.
    let mut differing = 0;
    for name in universe_names() {
        let (Some(a), Some(b)) = (
            p.table(FIRST).number_of(name),
            p.table(SECOND).number_of(name),
        ) else {
            continue;
        };
        if a != b {
            differing += 1;
            assert_eq!(p.decide(FIRST, name, &[]).number, Some(a));
            assert_eq!(p.decide(SECOND, name, &[]).number, Some(b));
            assert_eq!(p.decide_by_number(FIRST, a, &[]).name, name);
            assert_eq!(p.decide_by_number(SECOND, b, &[]).name, name);
        }
    }
    assert!(differing > 0, "some name must number differently per arch");
    // A fresh probe bound to a different number in each table must be
    // reached through the requesting table only: a fixed-table lookup
    // would report the same number, or the wrong name, on one side.
    let mut probe = fresh();
    let first_number = unused_number(&probe);
    let second_number = first_number + 1;
    probe.table_mut(FIRST).insert("zz_arch_probe", first_number);
    probe.table_mut(SECOND).insert("zz_arch_probe", second_number);
    probe.allow("zz_arch_probe", "probe reason");
    let on_first = probe.decide(FIRST, "zz_arch_probe", &[]);
    assert_eq!(on_first.number, Some(first_number));
    assert_eq!(on_first.verdict, Verdict::Allowed);
    let on_second = probe.decide(SECOND, "zz_arch_probe", &[]);
    assert_eq!(on_second.number, Some(second_number));
    assert_eq!(on_second.verdict, Verdict::Allowed);
    assert_eq!(
        probe.decide_by_number(FIRST, second_number, &[]).verdict,
        Verdict::DeniedDefault,
        "second-arch probe number must not resolve on the first arch"
    );
    assert_eq!(
        probe.decide_by_number(SECOND, first_number, &[]).verdict,
        Verdict::DeniedDefault,
        "first-arch probe number must not resolve on the second arch"
    );
    // A probe present in only one table resolves only there.
    let mut single = fresh();
    let single_number = unused_number(&single);
    single.table_mut(SECOND).insert("zz_second_probe", single_number);
    let probe_number = single.table(SECOND).number_of("zz_second_probe").unwrap();
    assert_eq!(single.table(SECOND).name_of(probe_number), Some("zz_second_probe"));
    assert_eq!(single.table(FIRST).number_of("zz_second_probe"), None);
    assert_eq!(single.decide(FIRST, "zz_second_probe", &[]).number, None);
}

#[test]
fn s2_open_absent_on_second_arch() {
    let p = fresh();
    // Every name the first table carries that the second table does
    // not: each such name stays denied on the second architecture,
    // whatever arguments accompany the call.
    let absent: Vec<&str> = universe_names()
        .into_iter()
        .filter(|name| !resolves(&p, SECOND, name))
        .collect();
    assert!(!absent.is_empty(), "some name must be absent on the second arch");
    for name in absent {
        assert!(resolves(&p, FIRST, name), "absent name {name} resolves on first");
        for args in probe_args(&p) {
            let entry = p.decide(SECOND, name, &args);
            assert_eq!(
                entry.verdict,
                Verdict::DeniedDefault,
                "absent name {name} args {args:?}"
            );
            assert_eq!(entry.number, None, "absent name {name}");
            assert_eq!(entry.name, name);
            assert_eq!(entry.arch, SECOND);
            assert!(!entry.reason.is_empty(), "absent name {name}");
            // No number resolves, so the verdict explains the absence
            // itself; the recorded reason is carried only by decisions
            // that resolve through a table, checked in the denied test.
        }
        // Reaching the absent name from its first-architecture number
        // on the second architecture must not land on it: either the
        // number is unassigned there, or it names a different call.
        let number = p.table(FIRST).number_of(name).unwrap();
        if p.table(SECOND).name_of(number).is_none() {
            for args in broad_args() {
                let by_number = p.decide_by_number(SECOND, number, &args);
                assert_eq!(
                    by_number.verdict,
                    Verdict::DeniedDefault,
                    "absent number {number}"
                );
                assert_eq!(by_number.number, None, "absent number {number}");
                assert_eq!(by_number.arch, SECOND);
                assert_ne!(by_number.name, name, "absent number {number}");
            }
        }
    }
}

#[test]
fn s2_denied_stays_denied_across_arches() {
    let p = fresh();
    let mut denied = denied_names(&p);
    denied.extend(invented_names(&p));
    assert!(!denied.is_empty());
    let probe = probe_args(&p);
    for name in &denied {
        for arch in [FIRST, SECOND] {
            for args in &probe {
                let entry = p.decide(arch, name, args);
                assert_eq!(
                    entry.verdict,
                    Verdict::DeniedDefault,
                    "denied name {name} arch {arch:?} args {args:?}"
                );
                assert_eq!(
                    entry.number,
                    p.table(arch).number_of(name),
                    "denied name {name}"
                );
                assert_eq!(entry.name, *name);
                assert_eq!(entry.arch, arch);
                assert!(!entry.reason.is_empty(), "denied name {name}");
                // Only a decision that resolves through the table
                // carries the recorded reason; an unresolvable name is
                // denied for lack of a number, with its own reason.
                if p.table(arch).number_of(name).is_some() {
                    if let Some(recorded) = p.reason_for(name) {
                        assert!(!recorded.is_empty(), "denied name {name}");
                        assert!(
                            entry.reason.contains(&recorded),
                            "denied name {name}: verdict must carry the recorded reason"
                        );
                    }
                }
            }
        }
    }
    // The number path agrees: numbers resolving to a denied name deny
    // under every probe argument shape, on both architectures.
    for arch in [FIRST, SECOND] {
        for name in &denied {
            let Some(number) = p.table(arch).number_of(name) else {
                continue;
            };
            for args in &probe {
                let entry = p.decide_by_number(arch, number, args);
                assert_eq!(
                    entry.verdict,
                    Verdict::DeniedDefault,
                    "denied name {name} number {number}"
                );
                assert_eq!(entry.name, *name);
                assert_eq!(entry.number, Some(number));
            }
        }
        for number in [999u64, 1000, u64::MAX] {
            if p.table(arch).name_of(number).is_some() {
                continue;
            }
            let entry = p.decide_by_number(arch, number, &[]);
            assert_eq!(entry.verdict, Verdict::DeniedDefault);
            assert_eq!(entry.number, None);
        }
    }
}

#[test]
fn s2_allowed_consistent_across_arches() {
    let p = fresh();
    let allowed = p.allowed_names();
    assert!(!allowed.is_empty(), "the allowlist must name at least one call");
    let mut checked_second = 0;
    for name in &allowed {
        let recorded = recorded_reason(&p, name);
        for arch in [FIRST, SECOND] {
            let Some(number) = p.table(arch).number_of(name) else {
                continue;
            };
            if arch == SECOND {
                checked_second += 1;
            }
            let meeting = satisfying_args(&p, name);
            let entry = p.decide(arch, name, &meeting);
            assert!(
                entry.verdict == Verdict::Allowed
                    || entry.verdict == Verdict::AllowedConditional,
                "allowed name {name} arch {arch:?}"
            );
            assert_eq!(entry.number, Some(number));
            assert_eq!(entry.name, *name);
            assert_eq!(entry.arch, arch);
            assert!(
                entry.reason.contains(&recorded),
                "allowed name {name}: verdict must carry the recorded reason"
            );
            let by_number = p.decide_by_number(arch, number, &meeting);
            assert_eq!(by_number.verdict, entry.verdict, "name {name}");
            assert_eq!(by_number.name, *name);
            assert!(by_number.reason.contains(&recorded), "name {name}");
            // A name with no rules ignores its arguments entirely.
            if p.arg_rules_for(name).is_empty() {
                for args in broad_args() {
                    let plain = p.decide(arch, name, &args);
                    assert_eq!(plain.verdict, Verdict::Allowed, "name {name}");
                    assert!(plain.reason.contains(&recorded), "name {name}");
                }
            }
        }
    }
    assert!(
        checked_second > 0,
        "allowance must reach the second architecture"
    );
}

#[test]
fn s2_reasons_carried_to_second_arch() {
    let p = fresh();
    let ruled = ruled_allowed(&p);
    assert!(!ruled.is_empty());
    let mut checked = 0;
    for name in &ruled {
        let recorded = recorded_reason(&p, name);
        let notes = rule_notes(&p, name);
        assert!(!notes.is_empty(), "ruled name {name} must carry notes");
        for note in &notes {
            assert!(!note.is_empty(), "ruled name {name} carries an empty note");
        }
        for arch in [FIRST, SECOND] {
            if !resolves(&p, arch, name) {
                continue;
            }
            checked += 1;
            let meeting = satisfying_args(&p, name);
            let met = p.decide(arch, name, &meeting);
            assert!(
                met.reason.contains(&recorded),
                "name {name}: allowed verdict carries the recorded reason"
            );
            for note in &notes {
                assert!(
                    met.reason.contains(note),
                    "name {name}: allowed verdict records the condition"
                );
            }
            let breaking = breaking_args(&p, name);
            let denied = p.decide(arch, name, &breaking);
            assert_eq!(denied.verdict, Verdict::DeniedArg, "name {name}");
            assert!(
                denied.reason.contains(&recorded),
                "name {name}: denied verdict carries the recorded reason"
            );
            let rules = p.arg_rules_for(name);
            let unmet: Vec<&String> = rules
                .iter()
                .filter(|(cond, _)| !cond.met_by(&breaking))
                .map(|(_, note)| note)
                .collect();
            assert!(!unmet.is_empty(), "name {name} breaking args break a rule");
            assert!(
                unmet.iter().any(|note| denied.reason.contains(*note)),
                "name {name}: denied verdict records the broken condition"
            );
            let by_number = p.decide_by_number(
                arch,
                p.table(arch).number_of(name).unwrap(),
                &breaking,
            );
            assert_eq!(by_number.verdict, Verdict::DeniedArg, "name {name}");
            assert!(by_number.reason.contains(&recorded), "name {name}");
        }
    }
    assert!(checked > 0);
}

#[test]
fn s2_arg_rules_present() {
    let p = fresh();
    let ruled = ruled_allowed(&p);
    assert!(!ruled.is_empty(), "at least one allowed name must carry rules");
    assert!(
        ruled.iter().any(|name| resolves(&p, SECOND, name)),
        "a ruled name must resolve on the second architecture"
    );
    for name in &ruled {
        let rules = p.arg_rules_for(name);
        assert!(!rules.is_empty(), "ruled name {name} reports no rules");
        for (cond, note) in &rules {
            assert!(!note.is_empty(), "ruled name {name} carries an empty note");
            let _ = rule_index(cond);
        }
        let _ = recorded_reason(&p, name);
    }
    // Names with no policy record at all carry no rules.
    for name in ["frobnicate", "qq_nope", "ioctl"] {
        assert!(
            p.arg_rules_for(name).is_empty(),
            "unknown name {name} must carry no rules"
        );
    }
}

#[test]
fn s2_rule_violation_denies() {
    let p = fresh();
    let mut checked = [0usize; 2];
    for (i, arch) in [FIRST, SECOND].iter().enumerate() {
        for name in ruled_allowed(&p) {
            if !resolves(&p, *arch, &name) {
                continue;
            }
            checked[i] += 1;
            let breaking = breaking_args(&p, &name);
            assert!(
                p.arg_rules_for(&name)
                    .iter()
                    .any(|(cond, _)| !cond.met_by(&breaking)),
                "name {name}: breaking args must break a rule"
            );
            let recorded = recorded_reason(&p, &name);
            let entry = p.decide(*arch, &name, &breaking);
            assert_eq!(entry.verdict, Verdict::DeniedArg, "name {name}");
            assert_eq!(entry.number, p.table(*arch).number_of(&name));
            assert_eq!(entry.name, name);
            assert_eq!(entry.arch, *arch);
            assert!(entry.reason.contains(&recorded), "name {name}");
            let unmet_notes: Vec<String> = p
                .arg_rules_for(&name)
                .into_iter()
                .filter(|(cond, _)| !cond.met_by(&breaking))
                .map(|(_, note)| note)
                .collect();
            assert!(
                unmet_notes.iter().any(|note| entry.reason.contains(note)),
                "name {name}: verdict must record the broken condition"
            );
            let number = p.table(*arch).number_of(&name).unwrap();
            let by_number = p.decide_by_number(*arch, number, &breaking);
            assert_eq!(by_number.verdict, Verdict::DeniedArg, "name {name}");
            assert!(
                unmet_notes
                    .iter()
                    .any(|note| by_number.reason.contains(note)),
                "name {name}: number path must record the broken condition"
            );
        }
    }
    assert!(checked[0] > 0 && checked[1] > 0, "rules must bite on both arches");
}

#[test]
fn s2_rule_met_allows() {
    let p = fresh();
    let mut checked = [0usize; 2];
    for (i, arch) in [FIRST, SECOND].iter().enumerate() {
        for name in ruled_allowed(&p) {
            if !resolves(&p, *arch, &name) {
                continue;
            }
            checked[i] += 1;
            let meeting = satisfying_args(&p, &name);
            assert!(
                p.arg_rules_for(&name)
                    .iter()
                    .all(|(cond, _)| cond.met_by(&meeting)),
                "name {name}: meeting args must meet every rule"
            );
            let recorded = recorded_reason(&p, &name);
            let notes = rule_notes(&p, &name);
            let entry = p.decide(*arch, &name, &meeting);
            assert_eq!(
                entry.verdict,
                Verdict::AllowedConditional,
                "name {name} arch {arch:?}"
            );
            assert_eq!(entry.number, p.table(*arch).number_of(&name));
            assert_eq!(entry.name, name);
            assert_eq!(entry.arch, *arch);
            assert!(entry.reason.contains(&recorded), "name {name}");
            for note in &notes {
                assert!(
                    entry.reason.contains(note),
                    "name {name}: verdict must record the met condition"
                );
            }
            let number = p.table(*arch).number_of(&name).unwrap();
            let by_number = p.decide_by_number(*arch, number, &meeting);
            assert_eq!(by_number.verdict, Verdict::AllowedConditional, "name {name}");
            assert!(by_number.reason.contains(&recorded), "name {name}");
            for note in &notes {
                assert!(
                    by_number.reason.contains(note),
                    "name {name}: number path must record the met condition"
                );
            }
            // Trailing arguments beyond every referenced index change
            // nothing: the rules look only at their own indices.
            let mut extended = meeting.clone();
            extended.extend([999, u64::MAX, 7]);
            let extended_entry = p.decide(*arch, &name, &extended);
            assert_eq!(
                extended_entry.verdict,
                Verdict::AllowedConditional,
                "name {name}: trailing arguments must not change the verdict"
            );
            assert!(extended_entry.reason.contains(&recorded), "name {name}");
        }
    }
    assert!(checked[0] > 0 && checked[1] > 0, "rules must allow on both arches");
}

#[test]
fn s2_missing_args_skip_rules() {
    let p = fresh();
    let mut checked = 0;
    for name in ruled_allowed(&p) {
        let recorded = recorded_reason(&p, &name);
        let notes = rule_notes(&p, &name);
        let meeting = satisfying_args(&p, &name);
        for arch in [FIRST, SECOND] {
            if !resolves(&p, arch, &name) {
                continue;
            }
            checked += 1;
            // No arguments at all: no rule applies, plain allowance.
            let empty = p.decide(arch, &name, &[]);
            assert_eq!(empty.verdict, Verdict::Allowed, "name {name}");
            assert_eq!(empty.number, p.table(arch).number_of(&name));
            assert!(empty.reason.contains(&recorded), "name {name}");
            for note in &notes {
                assert!(
                    !empty.reason.contains(note),
                    "name {name}: an unapplied condition must not be recorded"
                );
            }
            // Every prefix of the meeting vector: rules whose index
            // lies beyond the slice do not apply, rules inside it
            // are met, so the verdict is plain or conditional
            // allowance, never a denial.
            for cut in 0..=meeting.len() {
                let prefix = &meeting[..cut];
                let rules = p.arg_rules_for(&name);
                let applicable: Vec<&String> = rules
                    .iter()
                    .filter(|(cond, _)| rule_index(cond) < cut)
                    .map(|(_, note)| note)
                    .collect();
                let entry = p.decide(arch, &name, prefix);
                if applicable.is_empty() {
                    assert_eq!(
                        entry.verdict,
                        Verdict::Allowed,
                        "name {name} prefix {prefix:?}"
                    );
                    for note in &notes {
                        assert!(
                            !entry.reason.contains(note),
                            "name {name} prefix {prefix:?}"
                        );
                    }
                } else {
                    assert_eq!(
                        entry.verdict,
                        Verdict::AllowedConditional,
                        "name {name} prefix {prefix:?}"
                    );
                    for note in &applicable {
                        assert!(
                            entry.reason.contains(*note),
                            "name {name} prefix {prefix:?}"
                        );
                    }
                }
                assert!(entry.reason.contains(&recorded), "name {name}");
                assert_eq!(entry.number, p.table(arch).number_of(&name));
            }
        }
    }
    assert!(checked > 0);
}

#[test]
fn s2_entry_reports_arch() {
    let p = fresh();
    for name in universe_names() {
        for arch in [FIRST, SECOND] {
            let entry = p.decide(arch, name, &[]);
            assert_eq!(entry.arch, arch, "name {name}");
            assert_eq!(entry.name, name);
            if let Some(number) = p.table(arch).number_of(name) {
                let by_number = p.decide_by_number(arch, number, &[]);
                assert_eq!(by_number.arch, arch, "number {number}");
                assert_eq!(by_number.name, name);
            }
        }
    }
    for name in invented_names(&p) {
        for arch in [FIRST, SECOND] {
            let entry = p.decide(arch, &name, &[]);
            assert_eq!(entry.arch, arch, "unknown name {name:?}");
            assert_eq!(entry.name, name);
        }
    }
    for number in [999u64, u64::MAX] {
        for arch in [FIRST, SECOND] {
            let entry = p.decide_by_number(arch, number, &[]);
            assert_eq!(entry.arch, arch, "unknown number {number}");
            assert_eq!(entry.number, None);
        }
    }
    // The conflicting numbers, reached from either side, report the
    // architecture they were decided for.
    for (name, number) in FIRST_TABLE {
        if let Some(other) = p.table(SECOND).name_of(number) {
            if other != name {
                assert_eq!(p.decide_by_number(FIRST, number, &[]).arch, FIRST);
                assert_eq!(p.decide_by_number(SECOND, number, &[]).arch, SECOND);
            }
        }
    }
    let entry = p.decide(SECOND, universe_names()[0], &satisfying_args(&p, universe_names()[0]));
    assert_eq!(entry.arch, SECOND);
}

#[test]
fn s2_tables_independent() {
    let mut p = fresh();
    // Snapshot both tables' decisions before any probe is inserted.
    let snapshot = |policy: &Policy| -> Vec<(String, Arch, Verdict, Option<u64>)> {
        let mut rows = Vec::new();
        for name in universe_names() {
            for arch in [FIRST, SECOND] {
                let entry = policy.decide(arch, name, &[]);
                rows.push((
                    name.to_string(),
                    arch,
                    entry.verdict,
                    entry.number,
                ));
            }
        }
        rows
    };
    let before = snapshot(&p);
    // A probe inserted into the second table only is invisible from
    // the first, even once allowed there, and first-arch decisions
    // are undisturbed.
    let probe_number = unused_number(&p);
    p.table_mut(SECOND).insert("zz_second_only", probe_number);
    assert_eq!(p.table(FIRST).number_of("zz_second_only"), None);
    assert_eq!(p.table(FIRST).name_of(probe_number), None);
    assert_eq!(
        p.decide(FIRST, "zz_second_only", &[]).verdict,
        Verdict::DeniedDefault
    );
    assert_eq!(
        p.decide_by_number(FIRST, probe_number, &[]).verdict,
        Verdict::DeniedDefault
    );
    p.allow("zz_second_only", "probe reason");
    assert_eq!(
        p.decide(SECOND, "zz_second_only", &[]).verdict,
        Verdict::Allowed
    );
    assert_eq!(
        p.decide(SECOND, "zz_second_only", &[]).number,
        Some(probe_number)
    );
    assert_eq!(
        p.decide(FIRST, "zz_second_only", &[]).verdict,
        Verdict::DeniedDefault
    );
    assert_eq!(snapshot(&p), before, "second-table probe leaked into first");
    // The mirror direction: a probe in the first table only is
    // invisible from the second, and second-arch decisions for the
    // universe are undisturbed.
    let other_number = unused_number(&p) + 1;
    p.table_mut(FIRST).insert("zz_first_only", other_number);
    p.allow("zz_first_only", "probe reason");
    assert_eq!(p.table(SECOND).number_of("zz_first_only"), None);
    assert_eq!(p.table(SECOND).name_of(other_number), None);
    assert_eq!(
        p.decide(SECOND, "zz_first_only", &[]).verdict,
        Verdict::DeniedDefault
    );
    assert_eq!(
        p.decide(FIRST, "zz_first_only", &[]).number,
        Some(other_number)
    );
    // Rebinding a shared name's number in the second table only moves
    // its second-architecture number; the first table keeps the old
    // one, and first-arch decisions stay as snapshotted.
    let shared: Vec<&str> = universe_names()
        .into_iter()
        .filter(|n| resolves(&p, FIRST, n) && resolves(&p, SECOND, n))
        .collect();
    assert!(!shared.is_empty());
    let shared = shared[0];
    let first_number = p.table(FIRST).number_of(shared).unwrap();
    let rebound = unused_number(&p) + 2;
    p.table_mut(SECOND).insert(shared, rebound);
    assert_eq!(p.table(FIRST).number_of(shared), Some(first_number));
    assert_eq!(p.table(SECOND).number_of(shared), Some(rebound));
    assert_eq!(p.decide(FIRST, shared, &[]).number, Some(first_number));
    assert_eq!(p.decide(SECOND, shared, &[]).number, Some(rebound));
    assert_eq!(
        p.decide_by_number(FIRST, rebound, &[]).verdict,
        Verdict::DeniedDefault
    );
    assert_eq!(p.decide_by_number(SECOND, rebound, &[]).name, shared);
    // A probe colliding with the first table's number for the shared
    // name, inserted in the second table only, leaves the first
    // table's reverse lookup naming the shared name.
    p.table_mut(SECOND).insert("zz_collision", first_number);
    assert_eq!(p.table(FIRST).name_of(first_number), Some(shared));
    assert_eq!(
        p.table(SECOND).name_of(first_number),
        Some("zz_collision")
    );
    assert_eq!(
        p.decide_by_number(FIRST, first_number, &[]).name,
        shared
    );
}

#[test]
fn s2_r1_denied_stable_under_args() {
    let p = fresh();
    let mut denied = denied_names(&p);
    denied.extend(invented_names(&p));
    assert!(!denied.is_empty());
    let probe = probe_args(&p);
    for name in &denied {
        for arch in [FIRST, SECOND] {
            for args in &probe {
                let entry = p.decide(arch, name, args);
                assert_eq!(
                    entry.verdict,
                    Verdict::DeniedDefault,
                    "denied name {name} arch {arch:?} must stay denied under {args:?}"
                );
                assert_eq!(entry.number, p.table(arch).number_of(name));
                assert_eq!(entry.name, *name);
                assert_eq!(entry.arch, arch);
                assert!(!entry.reason.is_empty(), "denied name {name}");
                if p.table(arch).number_of(name).is_some() {
                    if let Some(recorded) = p.reason_for(name) {
                        assert!(!recorded.is_empty(), "denied name {name}");
                        assert!(
                            entry.reason.contains(&recorded),
                            "denied name {name}: verdict must carry the recorded reason"
                        );
                    }
                }
            }
            let Some(number) = p.table(arch).number_of(name) else {
                continue;
            };
            for args in &probe {
                let entry = p.decide_by_number(arch, number, args);
                assert_eq!(
                    entry.verdict,
                    Verdict::DeniedDefault,
                    "denied name {name} number {number} must stay denied"
                );
                assert_eq!(entry.name, *name);
            }
        }
    }
}
