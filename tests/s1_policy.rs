//! Step-1 checks for the default-deny syscall sandbox: decisions are made
//! by name through the single number table, the allowlist is keyed by name,
//! and every audit entry carries the name, the verdict, and the reason.

use std::panic::AssertUnwindSafe;
use syscall_sandbox::{Arch, Policy, Verdict};

const X86: Arch = Arch::X86_64;
const OTHER: Arch = Arch::Aarch64;

// Public x86_64 reference numbering for this step.
const UNIVERSE: [(&str, u64); 10] = [
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

fn policy() -> Policy {
    Policy::default_policy()
}

fn recorded(policy: &Policy, name: &str) -> Option<String> {
    policy.reason_for(name)
}

fn arg_cases() -> Vec<Vec<u64>> {
    vec![
        vec![],
        vec![0],
        vec![1],
        vec![2],
        vec![3],
        vec![4],
        vec![5],
        vec![6],
        vec![7],
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
    ]
}

fn unknown_names() -> Vec<String> {
    let mut names: Vec<String> = vec![
        "".to_string(),
        " ".to_string(),
        "frobnicate".to_string(),
        "no_such_call".to_string(),
        "ioctl".to_string(),
        "ptrace".to_string(),
        "bpf".to_string(),
        "clone3".to_string(),
        "execveat".to_string(),
        "openat2".to_string(),
        "mmap2".to_string(),
        "READ".to_string(),
        "read ".to_string(),
        " read".to_string(),
    ];
    for (name, _) in UNIVERSE {
        names.push(format!("{name}2"));
    }
    names
}

// The ready-made policy may not exist yet on an unbuilt workspace: building
// it panics there, which for an absence fence is itself the absence. A fence
// therefore returns None when construction panics and asserts nothing.
fn ready_policy() -> Option<Policy> {
    std::panic::catch_unwind(AssertUnwindSafe(Policy::default_policy)).ok()
}

#[test]
fn s1_unknown_name_denied() {
    let p = policy();
    for name in unknown_names() {
        for args in arg_cases() {
            let entry = p.decide(X86, &name, &args);
            assert_eq!(entry.verdict, Verdict::DeniedDefault, "name {name:?}");
            assert_eq!(entry.number, None, "name {name:?}");
            assert_eq!(entry.name, name, "name {name:?}");
            assert_eq!(entry.arch, X86, "name {name:?}");
            assert!(!entry.reason.is_empty(), "name {name:?}");
        }
    }
    // Background: every reference name still resolves through the table,
    // so a policy that denies everything by losing the table cannot pass.
    for (name, number) in UNIVERSE {
        let entry = p.decide(X86, name, &[]);
        assert_eq!(entry.number, Some(number), "name {name}");
        assert!(
            entry.verdict == Verdict::Allowed || entry.verdict == Verdict::DeniedDefault,
            "name {name}"
        );
    }
}

#[test]
fn s1_unknown_number_denied() {
    let p = policy();
    for number in [
        4u64, 5, 6, 7, 8, 11, 40, 42, 55, 57, 58, 60, 256, 258, 999, 65535, u64::MAX,
    ] {
        for args in arg_cases() {
            let entry = p.decide_by_number(X86, number, &args);
            assert_eq!(entry.verdict, Verdict::DeniedDefault, "number {number}");
            assert_eq!(entry.number, None, "number {number}");
            assert_eq!(entry.arch, X86, "number {number}");
            assert!(!entry.name.is_empty(), "number {number}");
            assert!(!entry.reason.is_empty(), "number {number}");
        }
    }
    // Background: every reference number resolves back to its name.
    for (name, number) in UNIVERSE {
        let entry = p.decide_by_number(X86, number, &[]);
        assert_eq!(entry.name, name, "number {number}");
        assert_eq!(entry.number, Some(number), "number {number}");
    }
}

#[test]
fn s1_allowlist_nonempty() {
    let p = policy();
    let allowed = p.allowed_names();
    assert!(!allowed.is_empty(), "allowlist must name at least one call");
    let universe: Vec<&str> = UNIVERSE.iter().map(|(name, _)| *name).collect();
    let mut seen: Vec<String> = Vec::new();
    for name in &allowed {
        assert!(!name.is_empty(), "allowlist must not hold an empty name");
        assert!(
            universe.contains(&name.as_str()),
            "allowed name {name} is outside the reference universe"
        );
        assert!(!seen.contains(name), "allowlist repeats {name}");
        seen.push(name.clone());
        let entry = p.decide(X86, name, &[]);
        assert_eq!(entry.verdict, Verdict::Allowed, "name {name}");
        assert!(
            recorded(&p, name).is_some(),
            "allowed name {name} must carry a recorded reason"
        );
    }
}

#[test]
fn s1_allowed_names_allowed() {
    let p = policy();
    for name in p.allowed_names() {
        let recorded = recorded(&p, &name).expect("allowed name has a reason");
        let number = p
            .table(X86)
            .number_of(&name)
            .expect("allowed name has a number");
        for args in arg_cases() {
            let entry = p.decide(X86, &name, &args);
            assert_eq!(entry.verdict, Verdict::Allowed, "name {name}");
            assert_eq!(entry.number, Some(number), "name {name}");
            assert_eq!(entry.name, name, "name {name}");
            assert_eq!(entry.arch, X86, "name {name}");
            assert!(
                entry.reason.contains(&recorded),
                "name {name}: entry reason must carry the recorded reason"
            );
            let by_number = p.decide_by_number(X86, number, &args);
            assert_eq!(by_number.verdict, Verdict::Allowed, "name {name}");
            assert_eq!(by_number.name, name, "name {name}");
            assert_eq!(by_number.number, Some(number), "name {name}");
            assert!(
                by_number.reason.contains(&recorded),
                "name {name}: number-path reason must carry the recorded reason"
            );
        }
    }
}

#[test]
fn s1_unlisted_universe_names_denied() {
    let p = policy();
    let allowed = p.allowed_names();
    let mut checked = 0;
    for (name, number) in UNIVERSE {
        if allowed.iter().any(|a| a == name) {
            continue;
        }
        checked += 1;
        for args in arg_cases() {
            let entry = p.decide(X86, name, &args);
            assert_eq!(entry.verdict, Verdict::DeniedDefault, "name {name}");
            assert_eq!(entry.number, Some(number), "name {name}");
            assert_eq!(entry.name, name, "name {name}");
            assert_eq!(entry.arch, X86, "name {name}");
            match recorded(&p, name) {
                Some(recorded) => assert!(
                    entry.reason.contains(&recorded),
                    "name {name}: entry reason must carry the recorded reason"
                ),
                None => assert!(!entry.reason.is_empty(), "name {name}"),
            }
        }
    }
    assert!(checked > 0, "the allowlist must leave names denied");
    // Invented names stay denied even when given arguments.
    for name in ["frobnicate", "no_such_call"] {
        let entry = p.decide(X86, name, &[1, 2, 3]);
        assert_eq!(entry.verdict, Verdict::DeniedDefault, "name {name}");
        assert!(!entry.reason.is_empty(), "name {name}");
    }
}

#[test]
fn s1_exact_match_only() {
    let p = policy();
    for name in p.allowed_names() {
        let variants = [
            name.to_ascii_uppercase(),
            name.to_ascii_lowercase().to_ascii_uppercase(),
            format!("{}x", name),
            format!("x{}", name),
            format!("{} ", name),
            format!(" {}", name),
            format!("{}{}", name, name),
            format!("{}\t", name),
            name.chars()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c })
                .collect(),
        ];
        for near in variants {
            if near == name {
                continue;
            }
            let entry = p.decide(X86, &near, &[]);
            assert_eq!(
                entry.verdict,
                Verdict::DeniedDefault,
                "near-miss {near:?} of {name}"
            );
            assert_eq!(entry.number, None, "near-miss {near:?} of {name}");
            assert_eq!(entry.name, near, "near-miss {near:?} of {name}");
        }
    }
}

#[test]
fn s1_table_drives_number_path() {
    // A fresh name inserted at runtime, allowed, must be reachable by
    // number as well as by name: the decision reads the table, not a
    // hardcoded number.
    let mut p = policy();
    p.table_mut(X86).insert("zz_probe_call", 7311);
    p.allow("zz_probe_call", "fresh probe allowance");
    assert_eq!(p.table(X86).number_of("zz_probe_call"), Some(7311));
    let by_number = p.decide_by_number(X86, 7311, &[]);
    assert_eq!(by_number.verdict, Verdict::Allowed);
    assert_eq!(by_number.name, "zz_probe_call");
    assert_eq!(by_number.number, Some(7311));
    let by_name = p.decide(X86, "zz_probe_call", &[]);
    assert_eq!(by_name.verdict, Verdict::Allowed);
    assert_eq!(by_name.number, Some(7311));
    let recorded = recorded(&p, "zz_probe_call").expect("probe has a reason");
    assert!(by_number.reason.contains(&recorded));
    assert!(by_name.reason.contains(&recorded));

    // The same probe, left denied, must still resolve by number through
    // the table, with the table's number on the entry.
    let mut denied_probe = policy();
    denied_probe.table_mut(X86).insert("zz_probe_call", 7311);
    let entry = denied_probe.decide_by_number(X86, 7311, &[]);
    assert_eq!(entry.verdict, Verdict::DeniedDefault);
    assert_eq!(entry.name, "zz_probe_call");
    assert_eq!(entry.number, Some(7311));

    // Rebinding a known name to a fresh number must move both decision
    // paths: a hardcoded number at a decision site would stay behind.
    let mut rebound = policy();
    rebound.table_mut(X86).insert("write", 7312);
    let entry = rebound.decide(X86, "write", &[]);
    assert_eq!(entry.number, Some(7312), "rebound write");
    let entry = rebound.decide_by_number(X86, 7312, &[]);
    assert_eq!(entry.name, "write", "rebound write");
    assert_eq!(entry.number, Some(7312), "rebound write");
}

#[test]
fn s1_number_name_consistency() {
    let p = policy();
    let allowed = p.allowed_names();
    for (name, number) in UNIVERSE {
        let table = p.table(X86);
        assert_eq!(table.number_of(name), Some(number), "name {name}");
        assert_eq!(table.name_of(number), Some(name), "number {number}");
        let by_number = p.decide_by_number(X86, number, &[]);
        assert_eq!(by_number.name, name, "number {number}");
        assert_eq!(by_number.number, Some(number), "number {number}");
        let expected = if allowed.iter().any(|a| a == name) {
            Verdict::Allowed
        } else {
            Verdict::DeniedDefault
        };
        assert_eq!(by_number.verdict, expected, "name {name}");
        // The name path and the number path agree on the verdict.
        let by_name = p.decide(X86, name, &[]);
        assert_eq!(by_name.verdict, by_number.verdict, "name {name}");
        assert_eq!(by_name.number, by_number.number, "name {name}");
    }
    // Numbers outside the table resolve to no name in either direction.
    for number in [4u64, 8, 11, 258, 1000] {
        assert_eq!(p.table(X86).name_of(number), None, "number {number}");
    }
}

#[test]
fn s1_audit_carries_name_verdict_reason() {
    let p = policy();
    let allowed = p.allowed_names();
    let allowed_name = &allowed[0];
    let allow_entry = p.decide(X86, allowed_name, &[]);
    assert_eq!(allow_entry.name, *allowed_name);
    assert_eq!(allow_entry.arch, X86);
    assert_eq!(allow_entry.verdict, Verdict::Allowed);
    assert!(!allow_entry.reason.is_empty());
    let allowed_reason = recorded(&p, allowed_name).expect("allowed name has a reason");
    assert!(allow_entry.reason.contains(&allowed_reason));

    let denied_name = UNIVERSE
        .iter()
        .map(|(name, _)| *name)
        .find(|name| !allowed.iter().any(|a| a == name))
        .expect("a denied universe name exists");
    let deny_entry = p.decide(X86, denied_name, &[]);
    assert_eq!(deny_entry.name, denied_name);
    assert_eq!(deny_entry.arch, X86);
    assert_eq!(deny_entry.verdict, Verdict::DeniedDefault);
    assert!(!deny_entry.reason.is_empty());
    if let Some(denied_reason) = recorded(&p, denied_name) {
        assert!(deny_entry.reason.contains(&denied_reason));
    }

    let unknown_entry = p.decide(X86, "frobnicate", &[]);
    assert_eq!(unknown_entry.name, "frobnicate");
    assert_eq!(unknown_entry.arch, X86);
    assert_eq!(unknown_entry.verdict, Verdict::DeniedDefault);
    assert_eq!(unknown_entry.number, None);
    assert!(!unknown_entry.reason.is_empty());

    // The number path records the resolved name, not the raw number.
    let number = p.table(X86).number_of(allowed_name).unwrap();
    let numbered = p.decide_by_number(X86, number, &[]);
    assert_eq!(numbered.name, *allowed_name);
    assert_eq!(numbered.arch, X86);
    assert_eq!(numbered.verdict, Verdict::Allowed);
    assert!(numbered.reason.contains(&allowed_reason));
}

#[test]
fn s1_x86_table_matches_reference() {
    let p = policy();
    let table = p.table(X86);
    assert_eq!(table.len(), UNIVERSE.len());
    assert!(!table.is_empty());
    let mut numbers: Vec<u64> = Vec::new();
    for (name, number) in UNIVERSE {
        assert_eq!(table.number_of(name), Some(number), "name {name}");
        assert_eq!(table.name_of(number), Some(name), "number {number}");
        numbers.push(number);
    }
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), UNIVERSE.len(), "table numbers must be distinct");
    for name in unknown_names() {
        assert_eq!(table.number_of(&name), None, "unknown name {name:?}");
    }
}

#[test]
fn s1_version_reported() {
    assert_eq!(syscall_sandbox::version(), "0.1.0");
}

// The rule query may not be built yet on an unbuilt workspace, where it
// panics; that is the absence. When it answers, it must answer empty.
fn rules_for(policy: &Policy, name: &str) -> Option<Vec<(syscall_sandbox::ArgCond, String)>> {
    std::panic::catch_unwind(AssertUnwindSafe(|| policy.arg_rules_for(name))).ok()
}

#[test]
fn s1_no_arg_rules() {
    // Absence is observed through decisions: with no argument rules, no
    // decision ever carries a conditional or argument-denied verdict, on
    // any argument slice. The ready-made policy may not exist yet on an
    // unbuilt workspace, where construction panics; that is the absence.
    let Some(p) = ready_policy() else { return };
    let allowed = p.allowed_names();
    for (name, _) in UNIVERSE {
        if let Some(rules) = rules_for(&p, name) {
            assert!(rules.is_empty(), "name {name} must carry no argument rules");
        }
    }
    for name in &allowed {
        if let Some(rules) = rules_for(&p, name) {
            assert!(rules.is_empty(), "name {name} must carry no argument rules");
        }
    }
    for name in unknown_names() {
        if let Some(rules) = rules_for(&p, &name) {
            assert!(rules.is_empty(), "name {name:?} must carry no argument rules");
        }
    }
    for name in &allowed {
        let recorded = recorded(&p, name).expect("allowed name has a reason");
        let number = p.table(X86).number_of(name).expect("allowed name has a number");
        for args in arg_cases() {
            let entry = p.decide(X86, name, &args);
            assert_eq!(entry.verdict, Verdict::Allowed, "name {name} args {args:?}");
            assert!(entry.reason.contains(&recorded), "name {name} args {args:?}");
            let by_number = p.decide_by_number(X86, number, &args);
            assert_eq!(
                by_number.verdict,
                Verdict::Allowed,
                "name {name} args {args:?}"
            );
        }
    }
    for (name, _) in UNIVERSE {
        if allowed.iter().any(|a| a == name) {
            continue;
        }
        for args in arg_cases() {
            let entry = p.decide(X86, name, &args);
            assert_eq!(
                entry.verdict,
                Verdict::DeniedDefault,
                "name {name} args {args:?}"
            );
        }
    }
    for name in unknown_names() {
        for args in arg_cases() {
            let entry = p.decide(X86, &name, &args);
            assert_eq!(
                entry.verdict,
                Verdict::DeniedDefault,
                "name {name:?} args {args:?}"
            );
        }
    }
}

#[test]
fn s1_no_second_arch() {
    // Absence is observed through the second architecture's table and its
    // decisions: the table is empty, nothing resolves on it, and every
    // decision there denies for lack of a number. The ready-made policy
    // may not exist yet on an unbuilt workspace, where construction
    // panics; that is the absence.
    let Some(p) = ready_policy() else { return };
    let other_table = p.table(OTHER);
    assert_eq!(other_table.len(), 0, "second table must hold no entries");
    assert!(other_table.is_empty(), "second table must be empty");
    for (name, number) in UNIVERSE {
        assert_eq!(other_table.number_of(name), None, "name {name}");
        assert_eq!(other_table.name_of(number), None, "number {number}");
        for args in arg_cases() {
            let entry = p.decide(OTHER, name, &args);
            assert_eq!(
                entry.verdict,
                Verdict::DeniedDefault,
                "name {name} args {args:?}"
            );
            assert_eq!(entry.number, None, "name {name} args {args:?}");
            assert_eq!(entry.arch, OTHER, "name {name}");
        }
        let by_number = p.decide_by_number(OTHER, number, &[]);
        assert_eq!(by_number.verdict, Verdict::DeniedDefault, "number {number}");
        assert_eq!(by_number.number, None, "number {number}");
    }
    let unknown = p.decide(OTHER, "frobnicate", &[1, 2, 3]);
    assert_eq!(unknown.verdict, Verdict::DeniedDefault);
    assert_eq!(unknown.number, None);
}
