//! P4 组合报告：前提、性质和测试结论分别保存，不以全绿场景替代证明。
//!
//! 每个实例把它**实际检查过的前提**逐条列出（`premises`），`premises_established`
//! 只是它们的合取。论文 P4 的前提有哪些，这里就检查哪些；检查不到的不写成 true。
//!
//! P4(b) 的前提尤其容易写得比实际验证到的强：撤销场景里本来就没有效果，G4 检查器
//! 按设计返回 N/A，「没有效果」不能被算成「完全中介已证明」。所以这里把完全中介作为
//! 一条**可执行的有界前提**单独检查 —— 拿着那条 Deny 准入去让参考资源执行，它必须拒绝、
//! 账本必须纹丝不动 —— 而不是从场景没有效果这件事上推出来。
use crate::{
    checker,
    output::AnyResult,
    scenarios::{self, Baseline},
    services::{ControlledLedger, ResourceError},
};
use serde::{Deserialize, Serialize};
use srg_core::*;
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionCase {
    pub clause: String,
    pub instance: String,
    /// 逐条前提及其是否成立；名字就是它检查的内容。
    pub premises: Vec<(String, bool)>,
    /// `premises` 的合取。
    pub premises_established: bool,
    pub conclusions: Vec<(String, CheckOutcome<PropertyVerdict>)>,
    pub supports_in_this_instance: bool,
    pub evidence_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionReport {
    pub evidence_level: String,
    pub cases: Vec<CompositionCase>,
    pub non_vacuous_reference_cases: usize,
    pub universal_proof: bool,
}

fn satisfied(r: &scenarios::ScenarioRun, k: &str) -> bool {
    r.reports.properties[k].outcome == CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
}

/// P4(b) 的撤销侧前提，从证据里重算，不信场景自己的说法：
/// 1. 最终准入时的适用治理状态里，存在一条已生效、覆盖该请求的撤销；
/// 2. 撤销生效之后、最终准入之前，没有适用的重新授权。
fn revocation_premises(r: &scenarios::ScenarioRun) -> (bool, bool) {
    let (e, c, q) = (&r.evidence, &r.contract, &r.query);
    let Some(req) = checker::request(e, c, q) else {
        return (false, false);
    };
    let admissions = checker::admissions(e, c, q);
    let Some(final_admission) = admissions.iter().max_by_key(|a| a.fact.at) else {
        return (false, false);
    };
    let at = final_admission.fact.at;
    let Some(snapshot) = checker::applicable_snapshot(e, c, at) else {
        return (false, false);
    };
    let creds = checker::identities(e, c, q)
        .first()
        .map(|x| x.fact.credentials.clone())
        .unwrap_or_default();
    let matching: Vec<&Revocation> = snapshot
        .fact
        .revocations
        .iter()
        .filter(|rv| rv.effective_at <= at)
        .filter(|rv| {
            rv.resource
                .as_ref()
                .is_none_or(|x| x == &req.fact.action.resource)
                && rv
                    .operation
                    .as_ref()
                    .is_none_or(|x| x == &req.fact.action.operation)
        })
        .filter(|rv| match &rv.target {
            RevocationTarget::Subject(a) => a == &req.fact.subject,
            RevocationTarget::Basis(id) => snapshot
                .fact
                .bases
                .iter()
                .any(|b| &b.id == id && checker::basis_matches(b, &req.fact, at)),
            RevocationTarget::Delegation(d) => snapshot.fact.bases.iter().any(|b| {
                b.delegation.as_ref() == Some(d) && checker::basis_matches(b, &req.fact, at)
            }),
            RevocationTarget::Credential(id) => creds.contains(id),
        })
        .collect();
    let effective = !matching.is_empty();
    let reauthorized = matching.iter().any(|rv| {
        snapshot
            .fact
            .reauthorizations
            .iter()
            .any(|x| x.revocation == rv.id && x.at >= rv.effective_at && x.at <= at)
    });
    (effective, effective && !reauthorized)
}

/// 有界完全中介前提：参考资源路径拿着这条最终 Deny 准入去执行，必须被拒绝，且
/// 账本状态不变。这是对参考配置的一次真实执行，不是对「场景里没有效果」的解读。
fn complete_mediation_bounded(r: &scenarios::ScenarioRun) -> bool {
    let (e, c, q) = (&r.evidence, &r.contract, &r.query);
    let Some(req) = checker::request(e, c, q) else {
        return false;
    };
    let admissions = checker::admissions(e, c, q);
    let Some(final_admission) = admissions.iter().max_by_key(|a| a.fact.at) else {
        return false;
    };
    if final_admission.fact.decision != Decision::Deny {
        return false;
    }
    let mut ledger = ControlledLedger::new();
    let before = ledger.balances();
    let refused = matches!(
        ledger.execute(
            &final_admission.fact,
            req.fact.action.clone(),
            "p4b-probe",
            LogicalPoint(q.now.0)
        ),
        Err(ResourceError::Denied)
    );
    refused && ledger.balances() == before
}

pub fn run(out: &Path) -> AnyResult<CompositionReport> {
    let mut cases = vec![];
    for n in [0, 1, 2, 4, 9, 13] {
        let r = scenarios::run(n, Baseline::B3)?;
        let premises: Vec<(String, bool)> = ["G1", "G2", "G3", "G4", "G5", "G6"]
            .iter()
            .map(|k| (k.to_string(), satisfied(&r, k)))
            .chain([(
                "effect_occurred".to_string(),
                !r.evidence.effects.is_empty(),
            )])
            .collect();
        let established = premises.iter().all(|(_, ok)| *ok);
        let conclusions: Vec<_> = ["O1", "O2"]
            .iter()
            .map(|k| (k.to_string(), r.reports.properties[*k].outcome.clone()))
            .collect();
        let support = established
            && conclusions
                .iter()
                .all(|(_, v)| *v == CheckOutcome::Evaluated(PropertyVerdict::Satisfied));
        let file = format!("raw/p4/ret-{}.json", r.scenario_id);
        let p = out.join(&file);
        fs::create_dir_all(p.parent().unwrap())?;
        fs::write(p, serde_json::to_vec_pretty(&r)?)?;
        cases.push(CompositionCase {
            clause: "P4(a)".into(),
            instance: r.scenario_id,
            premises,
            premises_established: established,
            conclusions,
            supports_in_this_instance: support,
            evidence_file: file,
        });
    }

    let mut r = scenarios::healthy_revocation()?;
    let observed = r.reports.properties["O3"].outcome.clone();
    r.expected_property = Some("O3".into());
    r.expected_verdict = Some(PropertyVerdict::Satisfied);
    r.expected_accountability = None;
    r.expectation_matched = observed == CheckOutcome::Evaluated(PropertyVerdict::Satisfied);
    let (revocation_effective, no_reauthorization) = revocation_premises(&r);
    let final_denied = checker::admissions(&r.evidence, &r.contract, &r.query)
        .iter()
        .max_by_key(|a| a.fact.at)
        .is_some_and(|a| a.fact.decision == Decision::Deny);
    let premises: Vec<(String, bool)> = vec![
        ("G1".into(), satisfied(&r, "G1")),
        ("G5".into(), satisfied(&r, "G5")),
        (
            "revocation_effective_before_final_admission".into(),
            revocation_effective,
        ),
        ("no_applicable_reauthorization".into(), no_reauthorization),
        ("final_admission_denied".into(), final_denied),
        (
            "complete_mediation_bounded".into(),
            complete_mediation_bounded(&r),
        ),
    ];
    let established = premises.iter().all(|(_, ok)| *ok);
    let file = "raw/p4/fresh-revocation.json";
    fs::create_dir_all(out.join("raw/p4"))?;
    fs::write(out.join(file), serde_json::to_vec_pretty(&r)?)?;
    cases.push(CompositionCase {
        clause: "P4(b)".into(),
        instance: "fresh-revocation-normal-resource".into(),
        premises,
        premises_established: established,
        conclusions: vec![("O3".into(), observed.clone())],
        supports_in_this_instance: established
            && observed == CheckOutcome::Evaluated(PropertyVerdict::Satisfied),
        evidence_file: file.into(),
    });

    let non_vacuous_reference_cases = cases.iter().filter(|c| c.supports_in_this_instance).count();
    let report = CompositionReport {
        evidence_level: "bounded executable support under the declared reference contract: each instance lists the premises it actually checked; P4(b)'s complete-mediation premise is a real execution against the reference resource with the Deny admission, not an inference from the absence of effects; no general proof".into(),
        cases,
        non_vacuous_reference_cases,
        universal_proof: false,
    };
    fs::write(
        out.join("raw/p4/report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::create_dir_all(out.join("tables"))?;
    let mut csv =
        "clause,instance,premises_established,supported_in_this_instance,premises\n".to_string();
    for c in &report.cases {
        let premises = c
            .premises
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        csv.push_str(&format!(
            "{},{},{},{},\"{}\"\n",
            c.clause, c.instance, c.premises_established, c.supports_in_this_instance, premises
        ));
    }
    fs::write(out.join("tables/p4_matrix.csv"), csv)?;
    if report.cases.iter().any(|c| !c.supports_in_this_instance) {
        return Err("a P4 bounded composition instance has an unmet premise or conclusion".into());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_revocation_runs_normal_resource() {
        let r = scenarios::healthy_revocation().unwrap();
        assert!(r.evidence.effects.is_empty());
        assert_eq!(
            r.reports.properties["O3"].outcome,
            CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
        );
    }
    /// P4(b) 的每一条前提都必须被真实检查到，而且都成立。
    #[test]
    fn p4b_premises_are_checked_individually() {
        let r = scenarios::healthy_revocation().unwrap();
        assert_eq!(revocation_premises(&r), (true, true));
        assert!(complete_mediation_bounded(&r));
        // G4 检查器在这里是 N/A —— 正是因为它不能算作前提，才需要上面那条可执行前提。
        assert!(matches!(
            r.reports.properties["G4"].outcome,
            CheckOutcome::NotApplicable { .. }
        ));
    }
    /// 撤销之后有合法的重新授权，P4(b) 的前提就不成立（那是 S13 的世界，不是 P4(b) 的）。
    #[test]
    fn reauthorization_defeats_the_p4b_premise() {
        let r = scenarios::run(13, Baseline::B3).unwrap();
        let (effective, no_reauth) = revocation_premises(&r);
        assert!(effective);
        assert!(!no_reauth);
    }
    /// 陈旧准入放行了：最终准入不是 Deny，完全中介前提不成立。
    #[test]
    fn stale_allow_is_not_a_p4b_instance() {
        let r = scenarios::run(12, Baseline::B3).unwrap();
        assert!(!complete_mediation_bounded(&r));
    }
}
