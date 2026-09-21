use srg_core::*;
use srg_harness::{
    checker::{
        self, AccountabilityChecker, CompleteMediationChecker, EffectBindingChecker,
        PropertyChecker, RevocationSafetyChecker,
    },
    scenarios::{run, Baseline},
    services::*,
};
#[test]
fn all_twenty_reference_scenarios() {
    for n in 0..20 {
        let r = run(n, Baseline::B3).unwrap();
        assert!(r.expectation_matched, "{}: {:?}", r.scenario_id, r.reports);
    }
}
#[test]
fn equivalent_label_control() {
    for n in 0..20 {
        let a = run(n, Baseline::B2).unwrap();
        let b = run(n, Baseline::B3).unwrap();
        assert_eq!(a.evidence, b.evidence);
        assert_eq!(a.reports, b.reports);
    }
}
#[test]
fn verdict_does_not_read_expected_or_truth() {
    let mut r = run(12, Baseline::B3).unwrap();
    let old = r.reports.clone();
    r.expected_verdict = Some(PropertyVerdict::Satisfied);
    r.truth.actual_actor = ActorRef::ai("wrong-answer");
    r.scenario_id = "renamed".into();
    assert_eq!(checker::check_all(&r.evidence, &r.contract, &r.query), old);
}
#[test]
fn negative_witness_is_test_pass_property_violation() {
    let r = run(11, Baseline::B3).unwrap();
    assert!(r.expectation_matched);
    assert_eq!(
        r.reports.properties["G4"].outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Violated)
    );
}
#[test]
fn missing_admission_without_inventory_is_unknown() {
    let mut r = run(10, Baseline::B3).unwrap();
    r.evidence.seals[0].channels.remove("admissions");
    assert_eq!(
        CompleteMediationChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Unadjudicable)
    );
}
#[test]
fn deny_effect_is_not_evidence_conflict() {
    let r = run(11, Baseline::B3).unwrap();
    assert_eq!(
        r.reports.properties["G4"].outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Violated)
    );
    assert_eq!(
        r.reports.accountability.outcome,
        CheckOutcome::Evaluated(AccountabilityVerdict::Closed)
    );
}
#[test]
fn duplicate_receipt_is_not_duplicate_effect() {
    let mut r = run(0, Baseline::B3).unwrap();
    r.evidence.effects.push(r.evidence.effects[0].clone());
    assert_eq!(
        EffectBindingChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
    );
}
#[test]
fn unknown_source_cannot_claim_trust() {
    let mut r = run(0, Baseline::B3).unwrap();
    let mut false_fact = r.evidence.identity[0].clone();
    false_fact.id = "untrusted-fact".into();
    false_fact.source = "attacker".into();
    false_fact.fact.actor = ActorRef::ai("B");
    r.evidence.identity.push(false_fact);
    assert_eq!(
        checker::check_all(&r.evidence, &r.contract, &r.query),
        r.reports
    );
}
#[test]
fn retention_expiry_is_not_rbh() {
    let mut r = run(18, Baseline::B3).unwrap();
    r.query.now = LogicalPoint(150);
    r.evidence.seals[0].through = r.query.now;
    assert!(matches!(
        AccountabilityChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::NotApplicable { .. }
    ));
}
#[test]
fn missing_record_does_not_prove_permanent_loss() {
    let mut r = run(18, Baseline::B3).unwrap();
    r.evidence.availability.clear();
    assert_eq!(
        AccountabilityChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(AccountabilityVerdict::Unadjudicable)
    );
}
#[test]
fn alternative_path_prevents_confirmed_rbh() {
    let mut r = run(18, Baseline::B3).unwrap();
    r.contract.recovery_paths.insert("backup".into());
    assert_eq!(
        AccountabilityChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(AccountabilityVerdict::Unadjudicable)
    );
}
#[test]
fn pre_revocation_admitted_inflight_excluded() {
    let mut r = run(0, Baseline::B3).unwrap();
    let mut s = r.evidence.snapshots[0].clone();
    s.id = "later-snapshot".into();
    s.fact.at = LogicalPoint(6);
    s.fact.version = GovernanceVersion(2);
    let mut rev = subject_suspend(&ActorRef::ai("A"));
    rev.effective_at = LogicalPoint(6);
    s.fact.revocations.push(rev);
    r.evidence.snapshots.push(s);
    r.evidence.effects[0].fact.at = LogicalPoint(7);
    assert!(matches!(
        RevocationSafetyChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::NotApplicable { .. }
    ));
}
#[test]
fn normal_ledger_retry_is_idempotent() {
    let r = run(0, Baseline::B3).unwrap();
    let a = &r.evidence.admissions[0].fact;
    let mut l = ControlledLedger::new();
    let one = l
        .execute(a, a.action.clone(), "same", LogicalPoint(6))
        .unwrap();
    let two = l
        .execute(a, a.action.clone(), "same", LogicalPoint(7))
        .unwrap();
    assert_eq!(one, two);
    assert_eq!(l.balances()["X"], 1000);
    assert!(l
        .execute(a, a.action.clone(), "different", LogicalPoint(8))
        .is_err());
}
#[test]
fn max_uses_consumption() {
    let r = run(0, Baseline::B3).unwrap();
    let mut a = r.evidence.admissions[0].fact.clone();
    a.consumption = ConsumptionPolicy::MaxUses(2);
    let mut l = ControlledLedger::new();
    l.execute(&a, a.action.clone(), "one", LogicalPoint(6))
        .unwrap();
    l.execute(&a, a.action.clone(), "two", LogicalPoint(7))
        .unwrap();
    assert!(l
        .execute(&a, a.action.clone(), "three", LogicalPoint(8))
        .is_err());
    assert_eq!(l.balances()["X"], 2000);
}
#[test]
fn unauthorized_resource_is_not_touched() {
    let r = run(11, Baseline::B3).unwrap();
    let a = &r.evidence.admissions[0].fact;
    let mut l = ControlledLedger::new();
    assert!(l
        .execute(a, a.action.clone(), "key", LogicalPoint(6))
        .is_err());
    assert_eq!(l.balances()["X"], 0);
}
#[test]
fn final_deny_cannot_be_masked_by_earlier_allow() {
    let mut r = run(0, Baseline::B3).unwrap();
    let mut deny = r.evidence.admissions[0].clone();
    deny.id = "later-deny-record".into();
    deny.fact.id = "later-deny".into();
    r.evidence.admissions[0].fact.at = LogicalPoint(4);
    deny.fact.at = LogicalPoint(5);
    deny.fact.decision = Decision::Deny;
    r.evidence.admissions.push(deny);
    assert_eq!(
        CompleteMediationChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Violated)
    );
}
#[test]
fn deterministic_evidence() {
    let a = run(15, Baseline::B3).unwrap();
    let b = run(15, Baseline::B3).unwrap();
    assert_eq!(
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&b).unwrap()
    );
}
#[test]
fn fresh_revocation_prevents_effect() {
    let mut r = run(11, Baseline::B3).unwrap();
    r.evidence.effects.clear();
    r.evidence.links.clear();
    r.evidence.attributions.clear();
    r.evidence.provenance.clear();
    assert_eq!(
        RevocationSafetyChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
    );
}
#[test]
fn late_commitment_is_g2_violation_but_not_rbh() {
    let r = run(6, Baseline::B3).unwrap();
    assert_eq!(
        r.reports.properties["G2"].outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Violated)
    );
    assert_eq!(
        r.reports.properties["O1"].outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Satisfied)
    );
    assert_eq!(
        r.reports.accountability.outcome,
        CheckOutcome::Evaluated(AccountabilityVerdict::Closed)
    );
}
#[test]
fn correction_closes_only_when_the_original_is_retained() {
    let r = run(16, Baseline::B3).unwrap();
    assert_eq!(r.evidence.provenance.len(), 2);
    assert!(r.evidence.provenance[1].fact.corrects.is_some());
    assert_eq!(
        r.reports.accountability.outcome,
        CheckOutcome::Evaluated(AccountabilityVerdict::Closed)
    );
    // 删掉被更正的原始记录：同一条更正就分不清「追加更正」还是「静默覆盖」。
    let mut r = r;
    r.evidence.provenance.remove(0);
    let o1 =
        srg_harness::checker::AttributionClosureChecker.check(&r.evidence, &r.contract, &r.query);
    assert_eq!(
        o1.outcome,
        CheckOutcome::Evaluated(PropertyVerdict::Unadjudicable)
    );
    assert_eq!(
        AccountabilityChecker
            .check(&r.evidence, &r.contract, &r.query)
            .outcome,
        CheckOutcome::Evaluated(AccountabilityVerdict::Unadjudicable)
    );
}
#[test]
fn every_scenario_has_distinct_evidence() {
    let runs: Vec<_> = (0..20).map(|n| run(n, Baseline::B3).unwrap()).collect();
    for (i, a) in runs.iter().enumerate() {
        for b in runs.iter().skip(i + 1) {
            assert_ne!(
                a.evidence, b.evidence,
                "{} and {} present identical evidence",
                a.scenario_id, b.scenario_id
            );
        }
    }
}

/// README 里的结果矩阵与测试数是手写的，这里对着真实运行核对：文档必须与代码一致。
mod readme {
    use super::*;
    use srg_harness::output::{accountability_label, label};
    fn readme() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md")).unwrap()
    }
    fn short(l: &str) -> &str {
        match l {
            "SATISFIED" => "SAT",
            "VIOLATED" => "VIOL",
            "UNADJUDICABLE" => "UNADJ",
            "EVIDENCE_CONFLICT" => "CONFLICT",
            "CONFIRMED_RBH" => "RBH",
            other => other,
        }
    }
    #[test]
    fn readme_matrix_is_the_b3_scenario_matrix() {
        check_matrix(&readme(), true);
        // 中文版的场景名是译名，不核对；判定格子必须一致。
        let zh = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../README.zh-CN.md"
        ))
        .unwrap();
        check_matrix(&zh, false);
    }
    fn check_matrix(text: &str, check_names: bool) {
        let rows: Vec<Vec<&str>> = text
            .lines()
            .filter(|l| l.starts_with("| S") && l.matches('|').count() == 13)
            .map(|l| {
                l.split('|')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .collect()
            })
            .collect();
        assert_eq!(rows.len(), 20, "README must list all 20 scenarios");
        for (n, row) in rows.iter().enumerate() {
            let r = run(n, Baseline::B3).unwrap();
            assert_eq!(row[0], r.scenario_id);
            if check_names {
                assert_eq!(row[1], r.description, "{}: name", r.scenario_id);
            }
            for (i, k) in ["G1", "G2", "G3", "G4", "G5", "G6", "O1", "O2", "O3"]
                .iter()
                .enumerate()
            {
                assert_eq!(
                    row[2 + i],
                    short(label(&r.reports.properties[*k].outcome)),
                    "{} {k}",
                    r.scenario_id
                );
            }
            assert_eq!(
                row[11],
                short(accountability_label(&r.reports.accountability.outcome)),
                "{} accountability",
                r.scenario_id
            );
        }
    }
    #[test]
    fn readme_test_count_is_real() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let mut actual = 0;
        for f in [
            "crates/srg-core/src/lib.rs",
            "crates/srg-explorer/src/lib.rs",
            "crates/srg-soulauth/src/lib.rs",
            "crates/srg-live/src/main.rs",
            "crates/srg-harness/src/composition.rs",
            "crates/srg-harness/tests/conformance.rs",
        ] {
            actual += std::fs::read_to_string(format!("{root}/{f}"))
                .unwrap()
                .lines()
                .filter(|l| l.trim() == "#[test]")
                .count();
        }
        let text = readme();
        let claimed: usize = text
            .lines()
            .find(|l| l.contains(" tests: "))
            .and_then(|l| l.rsplit('#').next())
            .and_then(|l| l.trim().split(' ').next())
            .and_then(|n| n.parse().ok())
            .expect("README quick start names the test count");
        assert_eq!(
            claimed, actual,
            "README claims {claimed} tests, sources define {actual}"
        );
    }
}
