//! 场景注册表与故障执行。Checker 输入中不包含这些类型。
use crate::{
    checker::{check_all, Reports},
    services::*,
};
use serde::{Deserialize, Serialize};
use srg_core::*;
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Baseline {
    B0,
    B1,
    B2,
    B3,
}
impl Baseline {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "B0" => Some(Self::B0),
            "B1" => Some(Self::B1),
            "B2" => Some(Self::B2),
            "B3" => Some(Self::B3),
            _ => None,
        }
    }
}
pub const NAMES: [&str; 20] = [
    "Legitimate Allow",
    "Credential Rotation",
    "Runtime Migration",
    "Subject Confusion",
    "Multi-Role Closure",
    "Missing Required Role",
    "Provenance Committed After Boundary",
    "History Rebind",
    "Authority Mismatch",
    "Independent Grant Revocation",
    "Complete Mediation Bypass",
    "Denied But Executed",
    "Stale Revocation",
    "Reauthorization",
    "Effect Substitution",
    "Admission Replay",
    "Accountability Closed",
    "Accountability Unadjudicable",
    "Confirmed RBH",
    "Evidence Conflict",
];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioTruth {
    pub actual_actor: ActorRef,
    pub actual_roles: Roles,
    pub effects: Vec<EffectReceipt>,
    pub balances: BTreeMap<String, u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRun {
    pub schema_version: String,
    pub scenario_id: String,
    pub description: String,
    pub baseline: Baseline,
    pub contract: ResearchContract,
    pub query: QueryContext,
    pub evidence: EvidenceSet,
    pub trace: Vec<TraceEvent>,
    pub truth: ScenarioTruth,
    pub reports: Reports,
    pub expected_property: Option<String>,
    pub expected_verdict: Option<PropertyVerdict>,
    pub expected_accountability: Option<AccountabilityVerdict>,
    pub expectation_matched: bool,
    pub eligible_progress: Option<bool>,
}
fn env<T>(channel: &str, id: &str, fact: T, c: &ResearchContract) -> Envelope<T> {
    Envelope {
        id: id.into(),
        source: c.sources[channel].clone(),
        fact,
    }
}
fn ev(t: u64, kind: &str, detail: impl Serialize) -> TraceEvent {
    TraceEvent {
        point: LogicalPoint(t),
        kind: kind.into(),
        detail: serde_json::to_value(detail).expect("research types serialize"),
    }
}
pub fn expected(
    n: usize,
) -> (
    Option<&'static str>,
    Option<PropertyVerdict>,
    Option<AccountabilityVerdict>,
) {
    use PropertyVerdict::*;
    match n {
        3 | 5 => (Some("G1"), Some(Violated), None),
        6 => (Some("G2"), Some(Violated), None),
        7 => (Some("O1"), Some(Violated), None),
        8 => (Some("G3"), Some(Violated), None),
        10 | 11 => (Some("G4"), Some(Violated), None),
        12 => (Some("O3"), Some(Violated), None),
        14 | 15 => (Some("G6"), Some(Violated), None),
        16 => (None, None, Some(AccountabilityVerdict::Closed)),
        17 => (None, None, Some(AccountabilityVerdict::Unadjudicable)),
        18 => (None, None, Some(AccountabilityVerdict::ConfirmedRbh)),
        19 => (None, None, Some(AccountabilityVerdict::EvidenceConflict)),
        _ => (Some("O2"), Some(Satisfied), None),
    }
}
pub fn run(n: usize, baseline: Baseline) -> Result<ScenarioRun, String> {
    run_internal(n, baseline, true)
}
pub fn healthy_revocation() -> Result<ScenarioRun, String> {
    run_internal(11, Baseline::B3, false)
}
fn run_internal(
    n: usize,
    baseline: Baseline,
    inject_deny_failure: bool,
) -> Result<ScenarioRun, String> {
    if n >= 20 {
        return Err(format!("unknown scenario S{n:02}"));
    }
    let mut c = ResearchContract::default();
    let a = ActorRef::ai("A");
    let b = ActorRef::ai("B");
    let mut rs = roles(&a);
    if n == 4 {
        rs.insert(
            Role::Delegator,
            [ActorRef {
                domain: "research".into(),
                id: "human-manager".into(),
                kind: ActorKind::Human,
            }]
            .into_iter()
            .collect(),
        );
        rs.insert(
            Role::Authorizer,
            [a.clone(), b.clone()].into_iter().collect(),
        );
        c.role_schema
            .insert(Role::Delegator, RoleRequirement { min: 1, max: 1 });
        c.role_schema
            .insert(Role::Authorizer, RoleRequirement { min: 2, max: 2 });
    }
    let query = QueryContext {
        request_id: "request-1".into(),
        now: LogicalPoint(12),
    };
    let identity = VerifiedActorFact {
        request_id: query.request_id.clone(),
        actor: a.clone(),
        credentials: vec![if n == 1 {
            "credential-new".into()
        } else {
            "credential-old".into()
        }],
        session: Some("session-1".into()),
        runtime: Some(if n == 2 {
            "runtime-new".into()
        } else {
            "runtime-old".into()
        }),
        roles: rs.clone(),
        at: LogicalPoint(4),
    };
    let mut resolved = identity.clone();
    let mut req = ActionRequest {
        id: query.request_id.clone(),
        chain: "chain-1".into(),
        subject: a.clone(),
        roles: rs.clone(),
        action: ActionDescriptor::transfer("X", 1000),
        at: LogicalPoint(4),
    };
    if n == 3 {
        resolved.actor = b.clone();
        resolved.roles = roles(&b);
        req.subject = b.clone();
        req.roles = roles(&b)
    }
    if n == 5 {
        req.roles.remove(&Role::Executor);
    }
    let mut v1 = AuthoritySnapshot {
        version: GovernanceVersion(1),
        at: LogicalPoint(1),
        bases: vec![basis("grant-A", &a), basis("grant-B", &b)],
        revocations: vec![],
        reauthorizations: vec![],
    };
    if baseline == Baseline::B0 {
        let alias = ActorRef::ai(&identity.credentials[0].0);
        resolved.actor = alias.clone();
        resolved.roles = roles(&alias);
        req.subject = alias.clone();
        req.roles = roles(&alias);
        v1.bases.push(basis("credential-grant", &alias));
    }
    let mut snapshots = vec![v1.clone()];
    if [9, 11, 12, 13].contains(&n) {
        let mut v2 = v1.clone();
        v2.version = GovernanceVersion(2);
        v2.at = LogicalPoint(3);
        if n == 9 {
            v2.bases.push(basis("independent-grant", &a));
            let mut r = subject_suspend(&a);
            r.target = RevocationTarget::Basis("grant-A".into());
            v2.revocations.push(r)
        } else {
            v2.revocations.push(subject_suspend(&a))
        }
        snapshots.push(v2.clone());
        if n == 13 {
            let mut v3 = v2;
            v3.version = GovernanceVersion(3);
            v3.at = LogicalPoint(4);
            v3.reauthorizations.push(Reauthorization {
                revocation: "revoke-1".into(),
                at: LogicalPoint(4),
            });
            snapshots.push(v3);
        }
    }
    let used = if n == 12 || baseline == Baseline::B1 {
        &v1
    } else {
        snapshots.last().unwrap()
    };
    let mut admission = decide(&req, &resolved, used, &c);
    if n == 8 {
        admission.actual_basis = Some("grant-B".into());
        admission.decision = Decision::Allow;
    }
    let mut trace = vec![ev(1, "initial authority", &v1)];
    if n == 1 {
        trace.push(ev(
            2,
            "Credential Rotation",
            (&a, "credential-old", "credential-new"),
        ))
    }
    if n == 2 {
        trace.push(ev(
            2,
            "runtime migration",
            (&a, "runtime-old", "runtime-new"),
        ))
    }
    for s in snapshots.iter().skip(1) {
        trace.push(ev(s.at.0, "governance state update", s))
    }
    trace.push(ev(4, "request", &req));
    if n != 10 {
        trace.push(ev(5, "final admission", &admission))
    }
    let mut ledger = ControlledLedger::new();
    let mut receipts = vec![];
    if n == 10 || (n == 11 && inject_deny_failure) {
        receipts.push(
            ledger
                .fault_execute(&req.chain, &req.id, req.action.clone(), LogicalPoint(6))
                .map_err(|x| x.to_string())?,
        )
    } else if n == 14 {
        receipts.push(
            ledger
                .fault_execute(
                    &req.chain,
                    &req.id,
                    ActionDescriptor::transfer("Y", 100_000),
                    LogicalPoint(6),
                )
                .map_err(|x| x.to_string())?,
        )
    } else if admission.decision == Decision::Allow {
        receipts.push(
            ledger
                .execute(
                    &admission,
                    req.action.clone(),
                    "logical-operation-1",
                    LogicalPoint(6),
                )
                .map_err(|x| x.to_string())?,
        );
        if n == 15 {
            receipts.push(
                ledger
                    .fault_execute(&req.chain, &req.id, req.action.clone(), LogicalPoint(7))
                    .map_err(|x| x.to_string())?,
            )
        }
    }
    let mut e = EvidenceSet::default();
    e.identity
        .push(env("identity", "identity-fact", identity.clone(), &c));
    e.requests
        .push(env("requests", "request-record", req.clone(), &c));
    if n != 10 {
        e.admissions
            .push(env("admissions", "admission-record", admission.clone(), &c))
    }
    for s in snapshots {
        e.snapshots.push(env(
            "snapshots",
            &format!("snapshot-{}", s.version.0),
            s,
            &c,
        ))
    }
    for r in &receipts {
        trace.push(ev(r.at.0, "real ledger effect", r));
        e.effects
            .push(env("effects", &format!("receipt-{}", r.id), r.clone(), &c));
        e.attributions.push(env(
            "attributions",
            &format!("attribution-{}", r.id),
            EffectAttribution {
                effect_id: r.id.clone(),
                subject: a.clone(),
                roles: rs.clone(),
            },
            &c,
        ));
        if n != 10 {
            e.links.push(env(
                "links",
                &format!("link-{}", r.id),
                GovernanceLink {
                    effect_id: r.id.clone(),
                    admission_id: admission.id.clone(),
                },
                &c,
            ))
        }
        let context = if admission.decision == Decision::Allow {
            admission
                .actual_basis
                .clone()
                .map(AuthorityContext::Valid)
                .unwrap_or(AuthorityContext::NoApplicableAuthority)
        } else {
            AuthorityContext::NoApplicableAuthority
        };
        let p = ProvenanceRecord {
            effect_id: r.id.clone(),
            subject: Some(req.subject.clone()),
            roles: req.roles.clone(),
            authority: Some(context),
            admission: if n == 10 {
                None
            } else {
                Some(admission.id.clone())
            },
            committed_at: Some(LogicalPoint(r.at.0 + 1)),
            corrects: None,
        };
        e.provenance
            .push(env("provenance", &format!("provenance-{}", r.id), p, &c));
    }
    if n == 6 {
        // 来源记录完整，但越过提交边界（effect.at + commitment_window）才持久化：
        // G2 的保存义务失败，历史本身仍可恢复 —— 保存失败不等于责任黑洞。
        for p in &mut e.provenance {
            p.fact.committed_at = p
                .fact
                .committed_at
                .map(|t| LogicalPoint(t.0 + c.commitment_window + 1));
        }
        trace.push(ev(
            9,
            "provenance committed after the commitment boundary",
            &e.provenance,
        ));
    }
    if n == 7 {
        for p in &mut e.provenance {
            p.fact.subject = Some(b.clone());
            p.fact.roles = roles(&b);
        }
        trace.push(ev(
            9,
            "current binding wrongly used to reconstruct the past",
            &b,
        ));
    }
    if n == 16 {
        // 问责闭合的非平凡形态：第一条来源记录把主体写错，之后追加一条更正记录，
        // 指回被更正的记录。原始记录、更正来源和更正时间都保留 —— 这是
        // 「更正历史判断」而不是「用当前状态静默覆盖过去」。
        let mut corrections = vec![];
        for p in &e.provenance {
            let mut wrong = p.clone();
            wrong.fact.subject = Some(b.clone());
            wrong.fact.roles = roles(&b);
            let mut fixed = p.clone();
            fixed.id = EvidenceId(format!("{}-correction", p.id));
            fixed.fact.corrects = Some(p.id.clone());
            fixed.fact.committed_at = p.fact.committed_at.map(|t| LogicalPoint(t.0 + 2));
            corrections.push((wrong, fixed));
        }
        e.provenance.clear();
        for (wrong, fixed) in corrections {
            trace.push(ev(9, "provenance correction appended", &fixed));
            e.provenance.push(wrong);
            e.provenance.push(fixed);
        }
    }
    if baseline == Baseline::B1 {
        e.provenance.clear();
    }
    if [17, 18].contains(&n) {
        e.identity.clear();
        e.attributions.clear();
        e.provenance.clear();
        for r in &receipts {
            e.availability.push(env(
                "availability",
                &format!("availability-{}", r.id),
                EvidenceStateFact {
                    effect_id: r.id.clone(),
                    path: "primary".into(),
                    availability: if n == 17 {
                        Availability::TemporarilyUnavailable
                    } else {
                        Availability::PermanentlyLost
                    },
                    at: LogicalPoint(10),
                },
                &c,
            ));
        }
        trace.push(ev(
            10,
            "provenance store recoverability observation",
            &e.availability,
        ));
    }
    if n == 19 {
        let mut other = identity;
        other.actor = b.clone();
        other.roles = roles(&b);
        e.identity
            .push(env("identity", "conflicting-identity", other, &c));
    }
    e.seals.push(seal(&c, query.now));
    if n == 17 {
        e.seals[0].channels.remove("provenance");
    }
    let reports = check_all(&e, &c, &query);
    let (ep, evv, ea) = expected(n);
    let matched = if let (Some(p), Some(v)) = (ep, evv) {
        reports.properties[p].outcome == CheckOutcome::Evaluated(v)
    } else if let Some(v) = ea {
        reports.accountability.outcome == CheckOutcome::Evaluated(v)
    } else {
        false
    };
    let eligible = if [0, 1, 2, 4, 9, 13, 16].contains(&n) {
        Some(!receipts.is_empty())
    } else {
        None
    };
    Ok(ScenarioRun {
        schema_version: "srg-evidence-1.0".into(),
        scenario_id: format!("S{n:02}"),
        description: NAMES[n].into(),
        baseline,
        contract: c,
        query,
        evidence: e,
        trace,
        truth: ScenarioTruth {
            actual_actor: a,
            actual_roles: rs,
            effects: receipts,
            balances: ledger.balances(),
        },
        reports,
        expected_property: ep.map(str::to_owned),
        expected_verdict: evv,
        expected_accountability: ea,
        expectation_matched: matched,
        eligible_progress: eligible,
    })
}
