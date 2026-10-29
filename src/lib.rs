//! A default-deny syscall sandbox.
//!
//! The sandbox decides, for each system call, whether the call is allowed.
//! Every decision is recorded in an audit entry carrying the syscall name,
//! the verdict, and the reason for the decision.
//!
//! Start from [`Policy::default_policy`]: the ready-made sandbox policy with
//! populated number tables, an allowlist, and audit reasons.

use std::collections::HashMap;

/// A CPU architecture the policy can decide for.
///
/// Each architecture has its own syscall numbering: the same name may map to
/// a different number on each architecture, and the same number may name a
/// different call on each architecture.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Arch {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}

impl Arch {
    /// The canonical name of the architecture.
    pub fn name(&self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

/// The verdict recorded in an audit entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The call is allowed.
    Allowed,
    /// The call is allowed under a satisfied argument condition.
    AllowedConditional,
    /// The call is denied: unknown, or not allowed by the policy.
    DeniedDefault,
    /// The call is denied by an argument condition.
    DeniedArg,
}

/// A condition on a call's raw arguments.
///
/// A rule pairs a condition with the allowance of one syscall name: when the
/// call's arguments meet every condition on that name, the call stays
/// allowed; when an argument that is present fails a condition, the call is
/// denied. A condition over an argument index the call did not pass does not
/// apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArgCond {
    /// The argument at `arg` must lie in `min..=max`.
    Range { arg: usize, min: u64, max: u64 },
    /// The argument at `arg` must equal `value`.
    Eq { arg: usize, value: u64 },
}

impl ArgCond {
    /// Whether the passed arguments meet this condition.
    ///
    /// A condition over an argument index beyond the passed arguments does
    /// not apply and reports met.
    pub fn met_by(&self, args: &[u64]) -> bool {
        unimplemented!()
    }
}

/// One recorded decision.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    /// The syscall name the decision was made for, or a placeholder naming
    /// the raw number when no name resolves.
    pub name: String,
    /// The architecture the decision was made for.
    pub arch: Arch,
    /// The number the name resolved to through that architecture's table,
    /// or `None` when nothing resolved.
    pub number: Option<u64>,
    /// The verdict.
    pub verdict: Verdict,
    /// Why the decision came out this way.
    pub reason: String,
}

/// The name-to-number table for one architecture.
///
/// Each decision resolves its number through this table. The table is the
/// only place names and numbers meet.
#[derive(Clone, Debug, Default)]
pub struct NumberTable {
    entries: HashMap<String, u64>,
}

impl NumberTable {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record that `name` is syscall number `number`.
    pub fn insert(&mut self, name: &str, number: u64) {
        unimplemented!()
    }

    /// The number recorded for `name`, if any.
    pub fn number_of(&self, name: &str) -> Option<u64> {
        unimplemented!()
    }

    /// The name recorded for `number`, if any.
    pub fn name_of(&self, number: u64) -> Option<&str> {
        unimplemented!()
    }

    /// How many names the table holds.
    pub fn len(&self) -> usize {
        unimplemented!()
    }

    /// Whether the table holds nothing.
    pub fn is_empty(&self) -> bool {
        unimplemented!()
    }
}

/// The sandbox policy: number tables, an allowlist, and audit reasons.
///
/// Decisions are made by name. A name on the allowlist is allowed and every
/// other name stays denied; an unknown name stays denied. Each decision
/// looks its number up through the table for the requested architecture.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    tables: HashMap<Arch, NumberTable>,
    allowed: HashMap<String, String>,
    denied: HashMap<String, String>,
    rules: HashMap<String, Vec<(ArgCond, String)>>,
}

impl Policy {
    /// An empty policy: no tables, no allowlist, no rules.
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
            allowed: HashMap::new(),
            denied: HashMap::new(),
            rules: HashMap::new(),
        }
    }

    /// The ready-made sandbox policy: populated number tables, an allowlist
    /// with a reason per name, and argument-conditioned rules where they
    /// apply.
    pub fn default_policy() -> Self {
        unimplemented!()
    }

    /// The number table for `arch`, for populating.
    pub fn table_mut(&mut self, arch: Arch) -> &mut NumberTable {
        unimplemented!()
    }

    /// The number table for `arch`.
    pub fn table(&self, arch: Arch) -> &NumberTable {
        unimplemented!()
    }

    /// Allow `name`, recording why it is allowed.
    pub fn allow(&mut self, name: &str, reason: &str) {
        unimplemented!()
    }

    /// Record why `name` stays denied.
    pub fn deny(&mut self, name: &str, reason: &str) {
        unimplemented!()
    }

    /// Every name on the allowlist.
    pub fn allowed_names(&self) -> Vec<String> {
        unimplemented!()
    }

    /// The reason recorded for `name`, whether allowed or denied, if any.
    pub fn reason_for(&self, name: &str) -> Option<String> {
        unimplemented!()
    }

    /// Make allowance of `name` depend on `cond` as well, recording `note`
    /// with each verdict the rule shapes.
    pub fn add_arg_rule(&mut self, name: &str, cond: ArgCond, note: &str) {
        unimplemented!()
    }

    /// Every argument-conditioned rule on `name` with its recorded note.
    pub fn arg_rules_for(&self, name: &str) -> Vec<(ArgCond, String)> {
        unimplemented!()
    }

    /// Decide the call `name` on `arch` with raw arguments `args`.
    pub fn decide(&self, arch: Arch, name: &str, args: &[u64]) -> AuditEntry {
        unimplemented!()
    }

    /// Decide raw number `number` on `arch` with raw arguments `args`.
    ///
    /// The number resolves to a name through that architecture's table
    /// first; the decision then proceeds by name.
    pub fn decide_by_number(
        &self,
        arch: Arch,
        number: u64,
        args: &[u64],
    ) -> AuditEntry {
        unimplemented!()
    }
}

/// The crate version.
pub fn version() -> &'static str {
    "0.1.0"
}
