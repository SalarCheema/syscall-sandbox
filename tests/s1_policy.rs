use syscall_sandbox::{Arch, Policy, Verdict};

const ARCH: Arch = Arch::X86_64;

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

#[test]
fn s1_unknown_name_denied() {
    let p = policy();
    for name in ["qq_nope", "readlink", "exit_group"] {
        let entry = p.decide(ARCH, name, &[]);
        assert_eq!(entry.verdict, Verdict::DeniedDefault, "name {name}");
        assert_eq!(entry.number, None, "name {name}");
        assert!(!entry.reason.is_empty(), "name {name}");
    }
}

#[test]
fn s1_unknown_number_denied() {
    let p = policy();
    for number in [0xffff, 100000] {
        let entry = p.decide_by_number(ARCH, number, &[]);
        assert_eq!(entry.verdict, Verdict::DeniedDefault, "number {number}");
        assert!(!entry.name.is_empty(), "number {number}");
        assert!(!entry.reason.is_empty(), "number {number}");
    }
}

#[test]
fn s1_allowlist_nonempty() {
    assert!(!policy().allowed_names().is_empty());
}

#[test]
fn s1_allowed_names_allowed() {
    let p = policy();
    for name in p.allowed_names() {
        let entry = p.decide(ARCH, &name, &[]);
        assert_eq!(entry.verdict, Verdict::Allowed, "name {name}");
        assert_eq!(entry.number, p.table(ARCH).number_of(&name), "name {name}");
        let recorded = p.reason_for(&name).expect("allowed name has a reason");
        assert!(
            entry.reason.contains(&recorded),
            "name {name}: entry reason carries the recorded reason"
        );
    }
}

#[test]
fn s1_unlisted_universe_names_denied() {
    let p = policy();
    let allowed = p.allowed_names();
    let mut checked = 0;
    for (name, _) in UNIVERSE {
        if allowed.iter().any(|a| a == name) {
            continue;
        }
        checked += 1;
        let entry = p.decide(ARCH, name, &[]);
        assert_eq!(entry.verdict, Verdict::DeniedDefault, "name {name}");
        match p.reason_for(name) {
            Some(recorded) => assert!(
                entry.reason.contains(&recorded),
                "name {name}: entry reason carries the recorded reason"
            ),
            None => assert!(!entry.reason.is_empty(), "name {name}"),
        }
    }
    assert!(checked > 0, "the allowlist must leave names denied");
}

#[test]
fn s1_exact_match_only() {
    let p = policy();
    for name in p.allowed_names() {
        for near in [
            name.to_uppercase(),
            format!("{name}x"),
            format!("x{name}"),
            format!("{name} "),
        ] {
            let entry = p.decide(ARCH, &near, &[]);
            assert_eq!(
                entry.verdict,
                Verdict::DeniedDefault,
                "near-miss {near} of {name}"
            );
        }
    }
}

#[test]
fn s1_table_drives_number_path() {
    let mut p = policy();
    p.table_mut(ARCH).insert("qq_nope", 4242);
    p.allow("qq_nope", "probe entry");
    let by_number = p.decide_by_number(ARCH, 4242, &[]);
    assert_eq!(by_number.verdict, Verdict::Allowed);
    assert_eq!(by_number.name, "qq_nope");
    let by_name = p.decide(ARCH, "qq_nope", &[]);
    assert_eq!(by_name.verdict, Verdict::Allowed);
    assert_eq!(by_name.number, Some(4242));
}

#[test]
fn s1_number_name_consistency() {
    let p = policy();
    for name in p.allowed_names() {
        let number = p
            .table(ARCH)
            .number_of(&name)
            .expect("allowed name has a number");
        let entry = p.decide_by_number(ARCH, number, &[]);
        assert_eq!(entry.verdict, Verdict::Allowed, "name {name}");
        assert_eq!(entry.name, name, "name {name}");
        assert_eq!(entry.number, Some(number), "name {name}");
    }
}

#[test]
fn s1_audit_carries_name_verdict_reason() {
    let p = policy();
    let name = &p.allowed_names()[0];
    let allow_entry = p.decide(ARCH, name, &[]);
    assert_eq!(allow_entry.name, *name);
    assert_eq!(allow_entry.arch, ARCH);
    assert_eq!(allow_entry.verdict, Verdict::Allowed);
    assert!(!allow_entry.reason.is_empty());
    let deny_entry = p.decide(ARCH, "qq_nope", &[]);
    assert_eq!(deny_entry.name, "qq_nope");
    assert_eq!(deny_entry.arch, ARCH);
    assert_eq!(deny_entry.verdict, Verdict::DeniedDefault);
    assert!(!deny_entry.reason.is_empty());
}

#[test]
fn s1_x86_table_matches_reference() {
    let p = policy();
    let table = p.table(ARCH);
    assert_eq!(table.len(), UNIVERSE.len());
    for (name, number) in UNIVERSE {
        assert_eq!(table.number_of(name), Some(number), "name {name}");
        assert_eq!(table.name_of(number), Some(name), "number {number}");
    }
}

#[test]
fn s1_version_reported() {
    assert_eq!(syscall_sandbox::version(), "0.1.0");
}
