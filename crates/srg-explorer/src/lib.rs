//! 有限世界枚举与独立状态搜索。这里不调用工程 SUT 或其检查器。
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use srg_core::{verdict_from_worlds, PropertyVerdict};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct World {
    pub actor: u8,
    pub prior_actor: u8,
    pub current_alias: u8,
    pub suspended: bool,
    pub credential_valid: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collision {
    pub observation: String,
    pub left: World,
    pub right: World,
    pub left_target: String,
    pub right_target: String,
}
pub fn worlds() -> Vec<World> {
    let mut out = vec![];
    for actor in 0..2 {
        for prior_actor in 0..2 {
            for current_alias in 0..2 {
                out.push(World {
                    actor,
                    prior_actor,
                    current_alias,
                    suspended: actor == 0,
                    credential_valid: true,
                })
            }
        }
    }
    out
}
pub fn collisions(historical: bool, strong: bool) -> Vec<Collision> {
    let ws = worlds();
    let mut out = vec![];
    for (i, a) in ws.iter().enumerate() {
        for b in ws.iter().skip(i + 1) {
            let obs = |w: &World| {
                if historical {
                    format!(
                        "current_alias={};event_ref=x{}",
                        w.current_alias,
                        if strong {
                            format!(";event_actor={}", w.prior_actor)
                        } else {
                            String::new()
                        }
                    )
                } else {
                    format!(
                        "credential_valid={};operation=read{}",
                        w.credential_valid,
                        if strong {
                            format!(";actor={}", w.actor)
                        } else {
                            String::new()
                        }
                    )
                }
            };
            let target = |w: &World| {
                if historical {
                    format!("actor-{}", w.prior_actor)
                } else if w.suspended {
                    "deny".into()
                } else {
                    "allow".into()
                }
            };
            if obs(a) == obs(b) && target(a) != target(b) {
                out.push(Collision {
                    observation: obs(a),
                    left: a.clone(),
                    right: b.clone(),
                    left_target: target(a),
                    right_target: target(b),
                });
            }
        }
    }
    out
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct State {
    pub stage: u8,
    pub revoked: bool,
    pub cached_revoked: bool,
    pub resolved: u8,
    pub allow: bool,
    pub effects: u8,
    pub actual_op: u8,
    pub saved: bool,
    pub admitted_after_revoke: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mutation {
    None,
    SubjectConfusion,
    ProvenanceLoss,
    AuthorityMismatch,
    Bypass,
    DenyThenEffect,
    StaleState,
    Substitution,
    Replay,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub mutation: Mutation,
    pub states: usize,
    pub transitions: usize,
    pub violations: BTreeMap<String, Vec<String>>,
    pub completed: bool,
    pub max_effects: u8,
}
fn initial() -> State {
    State {
        stage: 0,
        revoked: false,
        cached_revoked: false,
        resolved: 0,
        allow: false,
        effects: 0,
        actual_op: 0,
        saved: false,
        admitted_after_revoke: false,
    }
}
fn successors(s: State, m: Mutation) -> Vec<(String, State)> {
    let mut out = vec![];
    if s.stage == 0 {
        let mut x = s;
        x.stage = 1;
        out.push(("keep initial authority".into(), x));
        let mut x = s;
        x.stage = 1;
        x.revoked = true;
        out.push(("subject-scoped revocation takes effect".into(), x));
    } else if s.stage == 1 {
        let mut x = s;
        x.stage = 2;
        x.cached_revoked = if m == Mutation::StaleState {
            false
        } else {
            s.revoked
        };
        x.resolved = if m == Mutation::SubjectConfusion {
            1
        } else {
            0
        };
        out.push(("submit and resolve request".into(), x));
    } else if s.stage == 2 {
        let mut x = s;
        x.stage = 3;
        x.allow = !x.cached_revoked || x.resolved == 1;
        x.admitted_after_revoke = s.revoked;
        if m == Mutation::AuthorityMismatch {
            x.allow = true
        }
        out.push(("final admission decision".into(), x));
        if m == Mutation::Bypass {
            let mut x = s;
            x.stage = 4;
            x.effects = 1;
            x.admitted_after_revoke = s.revoked;
            out.push(("bypass produces effect".into(), x));
        }
    } else if s.stage == 3 {
        let mut x = s;
        x.stage = 4;
        if s.allow || m == Mutation::DenyThenEffect {
            x.effects = 1;
            x.actual_op = if m == Mutation::Substitution { 1 } else { 0 };
            x.saved = m != Mutation::ProvenanceLoss;
        }
        out.push(("resource executes and commits provenance".into(), x));
    } else if s.stage == 4 && m == Mutation::Replay && s.allow && s.effects == 1 {
        let mut x = s;
        x.effects = 2;
        out.push(("replay consumed admission".into(), x));
    }
    out
}
fn properties(s: State) -> Vec<(&'static str, bool)> {
    if s.stage < 4 {
        return vec![];
    }
    vec![
        ("O1_bounded", s.effects == 0 || (s.saved && s.resolved == 0)),
        (
            "O2_bounded",
            s.effects == 0
                || (s.allow
                    && s.resolved == 0
                    && !s.admitted_after_revoke
                    && s.actual_op == 0
                    && s.effects <= 1),
        ),
        ("O3_bounded", !s.admitted_after_revoke || s.effects == 0),
    ]
}
pub fn search(m: Mutation) -> SearchResult {
    let first = initial();
    let mut seen = BTreeSet::from([first]);
    let mut queue = VecDeque::from([(first, Vec::<String>::new())]);
    let mut violations = BTreeMap::new();
    let mut transitions = 0;
    while let Some((s, path)) = queue.pop_front() {
        for (name, holds) in properties(s) {
            if !holds {
                violations.entry(name.to_owned()).or_insert(path.clone());
            }
        }
        for (label, next) in successors(s, m) {
            transitions += 1;
            if seen.insert(next) {
                let mut p = path.clone();
                p.push(label);
                queue.push_back((next, p));
            }
        }
    }
    SearchResult {
        mutation: m,
        states: seen.len(),
        transitions,
        violations,
        completed: true,
        max_effects: 2,
    }
}
pub fn all_searches() -> Vec<SearchResult> {
    [
        Mutation::None,
        Mutation::SubjectConfusion,
        Mutation::ProvenanceLoss,
        Mutation::AuthorityMismatch,
        Mutation::Bypass,
        Mutation::DenyThenEffect,
        Mutation::StaleState,
        Mutation::Substitution,
        Mutation::Replay,
    ]
    .into_iter()
    .map(search)
    .collect()
}
/// 对固定有限候选世界集合计算四值，不读取 expected label。
pub fn finite_judgment(world_values: &[bool]) -> PropertyVerdict {
    verdict_from_worlds(world_values.iter().copied())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn p1() {
        assert!(!collisions(false, false).is_empty());
        assert!(collisions(false, true).is_empty());
    }
    #[test]
    fn p2() {
        assert!(!collisions(true, false).is_empty());
        assert!(collisions(true, true).is_empty());
    }
    #[test]
    fn full_model_safe() {
        assert!(search(Mutation::None).violations.is_empty());
    }
    #[test]
    fn all_faults_reachable() {
        for s in all_searches().into_iter().skip(1) {
            assert!(!s.violations.is_empty(), "{:?}", s.mutation)
        }
    }
    #[test]
    fn semantic_replay() {
        assert!(search(Mutation::Replay)
            .violations
            .contains_key("O2_bounded"));
    }
    #[test]
    fn stale_subject_stays_correct() {
        let s = search(Mutation::StaleState);
        assert!(!s.violations.contains_key("O1_bounded"));
        assert!(s.violations.contains_key("O3_bounded"));
    }
    #[test]
    fn exact_four_values() {
        assert_eq!(finite_judgment(&[]), PropertyVerdict::EvidenceConflict);
        assert_eq!(
            finite_judgment(&[false, true]),
            PropertyVerdict::Unadjudicable
        );
    }
}

/// TLC 与 Rust BFS 必须对「哪个故障违反哪条性质」给出同一张表。
///
/// `results/formal/tlc_matrix.json` 由 `scripts/check-formal.sh` 用官方 TLC 逐
/// (故障, 性质) 生成并随仓库提交。这个测试把它和 [`all_searches`] 的反例集合逐格比对：
/// 两个模型之一被改动而另一个没有跟上，这里就红。文件不存在同样是失败 —— 形式结果
/// 缺席不能被当成「一致」。
#[cfg(test)]
mod formal_agreement {
    use super::*;
    #[test]
    fn tlc_matrix_agrees_with_bfs() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../results/formal/tlc_matrix.json"
        );
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "results/formal/tlc_matrix.json must be present ({e}); run scripts/check-formal.sh"
            )
        });
        let tlc: BTreeMap<String, BTreeMap<String, bool>> =
            serde_json::from_str(&text).expect("tlc_matrix.json parses");
        let searches = all_searches();
        assert_eq!(
            tlc.len(),
            searches.len() - 1,
            "one TLC row per fault mutation"
        );
        for s in searches.iter().skip(1) {
            let row = tlc
                .get(&format!("{:?}", s.mutation))
                .unwrap_or_else(|| panic!("TLC row for {:?}", s.mutation));
            for prop in ["O1", "O2", "O3"] {
                let bfs = s.violations.contains_key(&format!("{prop}_bounded"));
                assert_eq!(
                    row[prop], bfs,
                    "{:?}/{prop}: TLC says violated={}, BFS says {}",
                    s.mutation, row[prop], bfs
                );
            }
        }
    }
}
