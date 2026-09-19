//! P4 组合报告：前提、性质和测试结论分别保存，不以全绿场景替代证明。
use crate::{
    output::AnyResult,
    scenarios::{self, Baseline},
};
use serde::{Deserialize, Serialize};
use srg_core::*;
use std::{fs, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionCase {
    pub clause: String,
    pub instance: String,
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
pub fn run(out: &Path) -> AnyResult<CompositionReport> {
    let mut cases = vec![];
    for n in [0, 1, 2, 4, 9, 13] {
        let r = scenarios::run(n, Baseline::B3)?;
        let premises = ["G1", "G2", "G3", "G4", "G5", "G6"].iter().all(|k| {
            r.reports.properties[*k].outcome == CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
        });
        let conclusions: Vec<_> = ["O1", "O2"]
            .iter()
            .map(|k| (k.to_string(), r.reports.properties[*k].outcome.clone()))
            .collect();
        let support = premises
            && !r.evidence.effects.is_empty()
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
            premises_established: premises,
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
    let premises = ["G1", "G5"].iter().all(|k| {
        r.reports.properties[*k].outcome == CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
    }) && r
        .evidence
        .admissions
        .iter()
        .any(|a| a.fact.decision == Decision::Deny)
        && r.evidence.effects.is_empty();
    let file = "raw/p4/fresh-revocation.json";
    fs::create_dir_all(out.join("raw/p4"))?;
    fs::write(out.join(file), serde_json::to_vec_pretty(&r)?)?;
    cases.push(CompositionCase {
        clause: "P4(b)".into(),
        instance: "fresh-revocation-normal-resource".into(),
        premises_established: premises,
        conclusions: vec![("O3".into(), observed.clone())],
        supports_in_this_instance: premises
            && observed == CheckOutcome::Evaluated(PropertyVerdict::Satisfied),
        evidence_file: file.into(),
    });
    let non_vacuous_reference_cases = cases.iter().filter(|c| c.supports_in_this_instance).count();
    let report = CompositionReport {
        evidence_level:
            "composition check under the declared reference contract and bounded execution; a G4 path with no effect is not reported as a mediation PASS".into(),
        cases,
        non_vacuous_reference_cases,
        universal_proof: false,
    };
    fs::write(
        out.join("raw/p4/report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::create_dir_all(out.join("tables"))?;
    let mut csv = "clause,instance,premises_established,supported_in_this_instance\n".to_string();
    for c in &report.cases {
        csv.push_str(&format!(
            "{},{},{},{}\n",
            c.clause, c.instance, c.premises_established, c.supports_in_this_instance
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
}
