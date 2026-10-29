use syscall_sandbox::{Arch, ArgCond, Policy, Verdict};

const A: Arch = Arch::X86_64;
const B: Arch = Arch::Aarch64;

const UNIVERSE: [&str; 10] = [
    "read", "write", "open", "openat", "close", "mmap", "mprotect", "execve", "clone",
    "socket",
];

const AARCH64_REF: [(&str, u64); 9] = [
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

fn policy() -> Policy {
    Policy::default_policy()
}

fn cond_arg(cond: &ArgCond) -> usize {
    match *cond {
        ArgCond::Range { arg, .. } => arg,
        ArgCond::Eq { arg, .. } => arg,
    }
}

fn meeting_args(p: &Policy, name: &str) -> Vec<u64> {
    let rules = p.arg_rules_for(name);
    let len = rules
        .iter()
        .map(|(c, _)| cond_arg(c) + 1)
        .max()
        .unwrap_or(0);
    let mut args = vec![0u64; len];
    for (cond, _) in &rules {
        match *cond {
            ArgCond::Range { arg, min, .. } => args[arg] = min,
            ArgCond::Eq { arg, value } => args[arg] = value,
        }
    }
    args
}

fn violating_args(p: &Policy, name: &str) -> Vec<u64> {
    let rules = p.arg_rules_for(name);
    assert!(!rules.is_empty(), "name {name} has no rules to violate");
    let mut args = meeting_args(p, name);
    let (cond, _) = &rules[0];
    let idx = cond_arg(cond);
    if args.len() <= idx {
        args.resize(idx + 1, 0);
    }
    let mut candidates: Vec<u64> = Vec::new();
    match *cond {
        ArgCond::Range { min, max, .. } => {
            candidates.push(max.wrapping_add(1));
            candidates.push(min.wrapping_sub(1));
            candidates.push(u64::MAX);
            candidates.push(0);
        }
        ArgCond::Eq { value, .. } => {
            candidates.push(value.wrapping_add(1));
            candidates.push(value.wrapping_sub(1));
            candidates.push(u64::MAX);
        }
    }
    for cand in candidates {
        args[idx] = cand;
        if !cond.met_by(&args) {
            return args;
        }
    }
    panic!("name {name}: rule cannot be violated by any arguments");
}

fn resolves(p: &Policy, arch: Arch, name: &str) -> bool {
    p.table(arch).number_of(name).is_some()
}

fn ruled_allowed_names(p: &Policy) -> Vec<String> {
    p.allowed_names()
        .into_iter()
        .filter(|n| !p.arg_rules_for(n).is_empty())
        .collect()
}

#[test]
fn s2_aarch64_table_matches_reference() {
    let p = policy();
    let table = p.table(B);
    assert_eq!(table.len(), AARCH64_REF.len());
    for (name, number) in AARCH64_REF {
        assert_eq!(table.number_of(name), Some(number), "name {name}");
        assert_eq!(table.name_of(number), Some(name), "number {number}");
    }
    assert_eq!(table.number_of("open"), None);
}

#[test]
fn s2_arch_conflict_number_56() {
    let p = policy();
    let on_x86 = p.decide_by_number(A, 56, &[]);
    let on_arm = p.decide_by_number(B, 56, &[]);
    assert_eq!(on_x86.name, "clone");
    assert_eq!(on_arm.name, "openat");
    assert_ne!(on_x86.name, on_arm.name);
    assert_eq!(on_x86.verdict, p.decide(A, "clone", &[]).verdict);
    assert_eq!(on_arm.verdict, p.decide(B, "openat", &[]).verdict);
}

#[test]
fn s2_name_resolution_uses_arch_table() {
    let p = policy();
    let on_arm = p.decide(B, "openat", &[]);
    assert_eq!(on_arm.number, Some(56));
    let on_x86 = p.decide(A, "openat", &[]);
    assert_eq!(on_x86.number, Some(257));
    assert_eq!(p.decide_by_number(B, 56, &[]).name, "openat");
}

#[test]
fn s2_open_absent_on_second_arch() {
    let p = policy();
    let entry = p.decide(B, "open", &[]);
    assert_eq!(entry.verdict, Verdict::DeniedDefault);
    assert_eq!(entry.number, None);
    assert!(!entry.reason.is_empty());
}

#[test]
fn s2_denied_stays_denied_across_arches() {
    let p = policy();
    let allowed = p.allowed_names();
    let mut denied: Vec<String> = UNIVERSE
        .iter()
        .filter(|n| !allowed.iter().any(|a| a == **n))
        .map(|n| n.to_string())
        .collect();
    denied.extend(["qq_nope".to_string(), "readlink".to_string()]);
    assert!(!denied.is_empty());
    for name in &denied {
        assert_eq!(
            p.decide(A, name, &[]).verdict,
            Verdict::DeniedDefault,
            "name {name} on x86_64"
        );
        let entry = p.decide(B, name, &[]);
        assert_eq!(
            entry.verdict,
            Verdict::DeniedDefault,
            "name {name} on aarch64"
        );
        assert!(!entry.reason.is_empty(), "name {name}");
    }
}

#[test]
fn s2_allowed_consistent_across_arches() {
    let p = policy();
    assert!(!p.allowed_names().is_empty());
    let mut checked = 0;
    for name in p.allowed_names() {
        if !resolves(&p, B, &name) {
            continue;
        }
        checked += 1;
        let args = meeting_args(&p, &name);
        let entry = p.decide(B, &name, &args);
        assert!(
            entry.verdict == Verdict::Allowed
                || entry.verdict == Verdict::AllowedConditional,
            "name {name}"
        );
        let recorded = p.reason_for(&name).expect("allowed name has a reason");
        assert!(
            entry.reason.contains(&recorded),
            "name {name}: second-arch reason carries the recorded reason"
        );
    }
    assert!(checked > 0, "allowance must reach the second architecture");
}

#[test]
fn s2_reasons_carried_to_second_arch() {
    let p = policy();
    let ruled = ruled_allowed_names(&p);
    assert!(!ruled.is_empty());
    let mut checked = 0;
    for name in &ruled {
        if !resolves(&p, B, name) {
            continue;
        }
        checked += 1;
        let recorded = p.reason_for(name).expect("allowed name has a reason");
        let met = p.decide(B, name, &meeting_args(&p, name));
        assert!(
            met.reason.contains(&recorded),
            "name {name}: allowed entry carries the recorded reason"
        );
        let notes: Vec<String> =
            p.arg_rules_for(name).into_iter().map(|(_, n)| n).collect();
        let denied = p.decide(B, name, &violating_args(&p, name));
        assert_eq!(denied.verdict, Verdict::DeniedArg, "name {name}");
        assert!(
            denied.reason.contains(&recorded),
            "name {name}: denied entry carries the recorded reason"
        );
        assert!(
            notes.iter().any(|n| denied.reason.contains(n)),
            "name {name}: denied entry records the condition"
        );
    }
    assert!(checked > 0);
}

#[test]
fn s2_arg_rules_present() {
    assert!(!ruled_allowed_names(&policy()).is_empty());
}

#[test]
fn s2_rule_violation_denies() {
    let p = policy();
    let mut checked = 0;
    for name in ruled_allowed_names(&p) {
        if !resolves(&p, B, &name) {
            continue;
        }
        checked += 1;
        let entry = p.decide(B, &name, &violating_args(&p, &name));
        assert_eq!(entry.verdict, Verdict::DeniedArg, "name {name}");
        let notes: Vec<String> =
            p.arg_rules_for(&name).into_iter().map(|(_, n)| n).collect();
        assert!(
            notes.iter().any(|n| entry.reason.contains(n)),
            "name {name}: verdict records the condition"
        );
        let entry_x86 = p.decide(A, &name, &violating_args(&p, &name));
        assert_eq!(entry_x86.verdict, Verdict::DeniedArg, "name {name} on x86_64");
    }
    assert!(checked > 0);
}

#[test]
fn s2_rule_met_allows() {
    let p = policy();
    let mut checked = 0;
    for name in ruled_allowed_names(&p) {
        if !resolves(&p, B, &name) {
            continue;
        }
        checked += 1;
        let entry = p.decide(B, &name, &meeting_args(&p, &name));
        assert_eq!(entry.verdict, Verdict::AllowedConditional, "name {name}");
        let recorded = p.reason_for(&name).expect("allowed name has a reason");
        assert!(
            entry.reason.contains(&recorded),
            "name {name}: verdict carries the recorded reason"
        );
        let notes: Vec<String> =
            p.arg_rules_for(&name).into_iter().map(|(_, n)| n).collect();
        for note in &notes {
            assert!(
                entry.reason.contains(note),
                "name {name}: verdict records the condition"
            );
        }
    }
    assert!(checked > 0);
}

#[test]
fn s2_missing_args_skip_rules() {
    let p = policy();
    let mut checked = 0;
    for name in ruled_allowed_names(&p) {
        for arch in [A, B] {
            if !resolves(&p, arch, &name) {
                continue;
            }
            checked += 1;
            let entry = p.decide(arch, &name, &[]);
            assert_eq!(entry.verdict, Verdict::Allowed, "name {name}");
        }
    }
    assert!(checked > 0);
}

#[test]
fn s2_entry_reports_arch() {
    let p = policy();
    let entry = p.decide(B, "read", &[]);
    assert_eq!(entry.arch, B);
    let by_number = p.decide_by_number(B, 63, &[]);
    assert_eq!(by_number.arch, B);
    assert_eq!(by_number.name, "read");
}

#[test]
fn s2_tables_independent() {
    let mut p = policy();
    p.table_mut(B).insert("qq_second", 7777);
    let on_x86 = p.decide_by_number(A, 7777, &[]);
    assert_eq!(on_x86.verdict, Verdict::DeniedDefault);
    let read_x86 = p.decide(A, "read", &[]);
    assert_eq!(read_x86.verdict, Verdict::Allowed);
    assert_eq!(read_x86.number, Some(0));
}

#[test]
fn s2_r1_denied_stable_under_args() {
    let p = policy();
    let allowed = p.allowed_names();
    let mut denied: Vec<String> = UNIVERSE
        .iter()
        .filter(|n| !allowed.iter().any(|a| a == **n))
        .map(|n| n.to_string())
        .collect();
    denied.push("qq_nope".to_string());
    let ruled = ruled_allowed_names(&p);
    let mut probe_args: Vec<Vec<u64>> = vec![vec![999, 999, 999]];
    for name in &ruled {
        probe_args.push(meeting_args(&p, name));
        probe_args.push(violating_args(&p, name));
    }
    for name in &denied {
        for args in &probe_args {
            for arch in [A, B] {
                if !resolves(&p, arch, name) {
                    continue;
                }
                let entry = p.decide(arch, name, args);
                assert_eq!(
                    entry.verdict,
                    Verdict::DeniedDefault,
                    "name {name} must stay denied under any arguments"
                );
            }
        }
    }
}
