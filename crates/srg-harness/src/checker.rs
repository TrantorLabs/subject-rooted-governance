//! 独立检查器：输入中没有场景编号、故障标签、预期答案或隐藏真值。
use serde::{Deserialize, Serialize};
use srg_core::*;
use std::collections::{BTreeMap, BTreeSet};
type R = CheckReport<PropertyVerdict>;

pub trait PropertyChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R;
}
pub struct SubjectRoleChecker;
pub struct ProvenanceChecker;
pub struct AuthorityBasisChecker;
pub struct CompleteMediationChecker;
pub struct GovernanceFreshnessChecker;
pub struct EffectBindingChecker;
pub struct AttributionClosureChecker;
pub struct AuthorityCorrespondenceChecker;
pub struct RevocationSafetyChecker;
pub struct AccountabilityChecker;

fn accepted<'a, T>(v: &'a [Envelope<T>], c: &ResearchContract, ch: &str) -> Vec<&'a Envelope<T>> {
    v.iter().filter(|x| c.accepts(ch, &x.source)).collect()
}
fn sealed(e: &EvidenceSet, c: &ResearchContract, q: &QueryContext, ch: &str) -> bool {
    e.seals
        .iter()
        .any(|s| c.accepts("seal", &s.source) && s.through >= q.now && s.channels.contains(ch))
}
fn request<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    q: &QueryContext,
) -> Option<&'a Envelope<ActionRequest>> {
    accepted(&e.requests, c, "requests")
        .into_iter()
        .find(|r| r.fact.id == q.request_id)
}
fn admissions<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    q: &QueryContext,
) -> Vec<&'a Envelope<AdmissionDecision>> {
    accepted(&e.admissions, c, "admissions")
        .into_iter()
        .filter(|r| r.fact.request_id == q.request_id && r.fact.at <= q.now)
        .collect()
}
fn effects<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    q: &QueryContext,
) -> Vec<&'a Envelope<EffectReceipt>> {
    let mut m = BTreeMap::new();
    for x in accepted(&e.effects, c, "effects") {
        if x.fact.request_id == q.request_id && x.fact.at <= q.now && c.in_scope(&x.fact.action) {
            m.entry(x.fact.id.clone()).or_insert(x);
        }
    }
    m.into_values().collect()
}
fn identities<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    q: &QueryContext,
) -> Vec<&'a Envelope<VerifiedActorFact>> {
    accepted(&e.identity, c, "identity")
        .into_iter()
        .filter(|x| x.fact.request_id == q.request_id && x.fact.at <= q.now)
        .collect()
}
fn report(v: PropertyVerdict, r: &str, ids: Vec<EvidenceId>) -> R {
    CheckReport::evaluated(v, r, ids)
}
fn unknown(r: &str) -> R {
    report(PropertyVerdict::Unadjudicable, r, vec![])
}
fn ok(r: &str, ids: Vec<EvidenceId>) -> R {
    report(PropertyVerdict::Satisfied, r, ids)
}
fn bad(r: &str, ids: Vec<EvidenceId>) -> R {
    report(PropertyVerdict::Violated, r, ids)
}
fn conflict(e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> bool {
    let ids = identities(e, c, q);
    if let Some(first) = ids.first() {
        if ids
            .iter()
            .skip(1)
            .any(|x| x.fact.actor != first.fact.actor || x.fact.roles != first.fact.roles)
        {
            return true;
        }
    }
    macro_rules! duplicates {
        ($field:ident,$channel:expr) => {{
            let mut seen = BTreeMap::new();
            for x in accepted(&e.$field, c, $channel) {
                if let Some(old) = seen.insert(&x.id, &x.fact) {
                    if old != &x.fact {
                        return true;
                    }
                }
            }
        }};
    }
    duplicates!(identity, "identity");
    duplicates!(snapshots, "snapshots");
    duplicates!(effects, "effects");
    duplicates!(availability, "availability");
    let mut actual = BTreeMap::new();
    for x in accepted(&e.effects, c, "effects") {
        if x.fact.request_id == q.request_id {
            if let Some(old) = actual.insert(&x.fact.id, &x.fact) {
                if old != &x.fact {
                    return true;
                }
            }
        }
    }
    let mut ats: BTreeMap<&EffectId, &EffectAttribution> = BTreeMap::new();
    for a in accepted(&e.attributions, c, "attributions") {
        if let Some(old) = ats.insert(&a.fact.effect_id, &a.fact) {
            if old.subject != a.fact.subject || old.roles != a.fact.roles {
                return true;
            }
        }
    }
    false
}
fn precheck(e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> Option<R> {
    if conflict(e, c, q) {
        Some(report(
            PropertyVerdict::EvidenceConflict,
            "incompatible trusted claims at the same fact position",
            vec![],
        ))
    } else if let Some(r) = request(e, c, q) {
        if !c.in_scope(&r.fact.action) {
            Some(R::na("request is outside the research contract scope"))
        } else {
            None
        }
    } else {
        Some(unknown("missing request fact"))
    }
}
fn merge(reports: Vec<R>) -> R {
    let mut used = BTreeSet::new();
    let mut reasons = vec![];
    let mut vs = vec![];
    for r in reports {
        used.extend(r.evidence_used);
        reasons.extend(r.reasons);
        if let CheckOutcome::Evaluated(v) = r.outcome {
            vs.push(v)
        }
    }
    let verdict = if vs.contains(&PropertyVerdict::EvidenceConflict) {
        PropertyVerdict::EvidenceConflict
    } else if vs.contains(&PropertyVerdict::Violated) {
        PropertyVerdict::Violated
    } else if vs.contains(&PropertyVerdict::Unadjudicable) {
        PropertyVerdict::Unadjudicable
    } else {
        PropertyVerdict::Satisfied
    };
    R {
        outcome: CheckOutcome::Evaluated(verdict),
        evidence_used: used.into_iter().collect(),
        reasons,
    }
}

impl PropertyChecker for SubjectRoleChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let req = request(e, c, q).unwrap();
        let facts = identities(e, c, q);
        let Some(id) = facts.first() else {
            return unknown("missing a trusted event-time subject fact");
        };
        let ids = vec![req.id.clone(), id.id.clone()];
        if req.fact.subject != id.fact.actor {
            return bad(
                "governance request subject differs from the authentication fact",
                ids,
            );
        }
        if !c.roles_complete(&req.fact.roles) || req.fact.roles != id.fact.roles {
            return bad(
                "required role missing, cardinality mismatch, or wrong subject for a role",
                ids,
            );
        }
        for a in admissions(e, c, q) {
            if a.fact.subject != id.fact.actor || a.fact.roles != id.fact.roles {
                return bad(
                    "subject or roles drifted at admission",
                    vec![id.id.clone(), a.id.clone()],
                );
            }
        }
        ok(
            "subject and every required role match the trusted fact",
            ids,
        )
    }
}

fn latest_provenance<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    id: &EffectId,
    q: &QueryContext,
) -> Option<&'a Envelope<ProvenanceRecord>> {
    accepted(&e.provenance, c, "provenance")
        .into_iter()
        .filter(|p| &p.fact.effect_id == id && p.fact.committed_at.is_some_and(|t| t <= q.now))
        .max_by_key(|p| p.fact.committed_at)
}
fn prov_complete(p: &ProvenanceRecord, c: &ResearchContract) -> bool {
    p.subject.is_some() && c.roles_complete(&p.roles) && p.authority.is_some()
}
/// 更正不是覆盖：一条声明 `corrects` 的记录，只有在它所更正的原始记录仍然在
/// 可信来源集合里时才算合法更正。原始记录不见了，就分不清「追加更正」和
/// 「用当前状态静默改写过去」。
fn correction_retained(
    e: &EvidenceSet,
    c: &ResearchContract,
    p: &Envelope<ProvenanceRecord>,
) -> bool {
    match &p.fact.corrects {
        None => true,
        Some(target) => accepted(&e.provenance, c, "provenance")
            .iter()
            .any(|x| &x.id == target && x.fact.effect_id == p.fact.effect_id),
    }
}
impl PropertyChecker for ProvenanceChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let es = effects(e, c, q);
        if es.is_empty() {
            return if sealed(e, c, q, "effects") {
                R::na("no real effect in this observation interval")
            } else {
                unknown("effect observation not sealed")
            };
        }
        let mut reports = vec![];
        for x in es {
            let deadline = LogicalPoint(x.fact.at.0.saturating_add(c.commitment_window));
            if q.now.0 > x.fact.at.0.saturating_add(c.retention) {
                reports.push(R::na("beyond the contract retention obligation"));
                continue;
            }
            if q.now < deadline {
                reports.push(R::na("provenance commitment boundary not yet reached"));
                continue;
            }
            let eligible: Vec<_> = accepted(&e.provenance, c, "provenance")
                .into_iter()
                .filter(|p| {
                    p.fact.effect_id == x.fact.id
                        && p.fact.committed_at.is_some_and(|t| t <= deadline)
                        && prov_complete(&p.fact, c)
                })
                .collect();
            if let Some(p) = eligible.first() {
                reports.push(ok(
                    "required facts durably committed within the commitment boundary",
                    vec![x.id.clone(), p.id.clone()],
                ))
            } else if sealed(e, c, q, "provenance") {
                reports.push(bad(
                    "the sealed commitment set contains no required fact committed in time",
                    vec![x.id.clone()],
                ))
            } else {
                reports.push(unknown(
                    "commitment records incomplete; absence does not prove non-commitment",
                ))
            }
        }
        if reports
            .iter()
            .all(|r| matches!(r.outcome, CheckOutcome::NotApplicable { .. }))
        {
            return R::na("no effect falls inside this commitment-obligation check window");
        }
        merge(reports)
    }
}

/// 检查器自己的匹配计算；不调用被测授权服务的决策函数。
fn basis_matches(b: &AuthorityBasis, r: &ActionRequest, at: LogicalPoint) -> bool {
    b.subject == r.subject
        && r.roles
            .get(&b.role)
            .is_some_and(|xs| xs.contains(&r.subject))
        && b.resource == r.action.resource
        && b.operation == r.action.operation
        && b.recipients.contains(&r.action.recipient)
        && r.action.amount <= b.max_amount
        && b.issued_at <= at
        && b.expires_at.is_none_or(|t| at < t)
}
fn revoked(
    s: &AuthoritySnapshot,
    b: &AuthorityBasis,
    r: &ActionRequest,
    at: LogicalPoint,
    creds: &[CredentialId],
) -> bool {
    s.revocations.iter().any(|rv| {
        if rv.effective_at > at
            || s.reauthorizations
                .iter()
                .any(|x| x.revocation == rv.id && x.at >= rv.effective_at && x.at <= at)
        {
            return false;
        }
        if rv
            .resource
            .as_ref()
            .is_some_and(|x| x != &r.action.resource)
            || rv
                .operation
                .as_ref()
                .is_some_and(|x| x != &r.action.operation)
        {
            return false;
        }
        match &rv.target {
            RevocationTarget::Subject(a) => a == &r.subject,
            RevocationTarget::Basis(id) => id == &b.id,
            RevocationTarget::Delegation(id) => b.delegation.as_ref() == Some(id),
            RevocationTarget::Credential(id) => creds.contains(id),
        }
    })
}
fn snapshot<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    v: GovernanceVersion,
) -> Option<&'a Envelope<AuthoritySnapshot>> {
    accepted(&e.snapshots, c, "snapshots")
        .into_iter()
        .find(|s| s.fact.version == v)
}
fn applicable_snapshot<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    at: LogicalPoint,
) -> Option<&'a Envelope<AuthoritySnapshot>> {
    accepted(&e.snapshots, c, "snapshots")
        .into_iter()
        .filter(|x| x.fact.at <= at)
        .max_by_key(|x| x.fact.version)
}
impl PropertyChecker for AuthorityBasisChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let req = &request(e, c, q).unwrap().fact;
        let ads = admissions(e, c, q);
        let allows: Vec<_> = ads
            .into_iter()
            .filter(|x| x.fact.decision == Decision::Allow)
            .collect();
        if allows.is_empty() {
            return if sealed(e, c, q, "admissions") {
                R::na("no positive admission")
            } else {
                unknown("admission observation incomplete")
            };
        }
        let mut rs = vec![];
        for a in allows {
            let Some(bid) = &a.fact.actual_basis else {
                rs.push(bad(
                    "allow decision records no actual authority basis",
                    vec![a.id.clone()],
                ));
                continue;
            };
            let Some(s) = snapshot(e, c, a.fact.observed_version) else {
                rs.push(unknown(
                    "missing the authority snapshot the admission actually used",
                ));
                continue;
            };
            let Some(b) = s.fact.bases.iter().find(|b| &b.id == bid) else {
                rs.push(bad(
                    "the actual basis is not part of the snapshot that was used",
                    vec![a.id.clone(), s.id.clone()],
                ));
                continue;
            };
            let creds = identities(e, c, q)
                .first()
                .map(|x| x.fact.credentials.clone())
                .unwrap_or_default();
            if !basis_matches(b, req, a.fact.at) || revoked(&s.fact, b, req, a.fact.at, &creds) {
                rs.push(bad(
                    "the actual basis does not match, or is revoked, in the snapshot that was used",
                    vec![a.id.clone(), s.id.clone()],
                ))
            } else {
                rs.push(ok(
                    "the actual basis matches in the snapshot that was used; freshness is checked separately by G5",
                    vec![a.id.clone(), s.id.clone()],
                ))
            }
        }
        merge(rs)
    }
}

fn final_before<'a>(
    e: &'a EvidenceSet,
    c: &ResearchContract,
    x: &EffectReceipt,
) -> Option<&'a Envelope<AdmissionDecision>> {
    accepted(&e.admissions, c, "admissions")
        .into_iter()
        .filter(|a| a.fact.chain == x.chain && a.fact.at < x.at)
        .max_by_key(|a| a.fact.at)
}
impl PropertyChecker for CompleteMediationChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let es = effects(e, c, q);
        if es.is_empty() {
            return if sealed(e, c, q, "effects") {
                R::na("no real effect; absence of effects is not counted as a mediation success")
            } else {
                unknown("effect set not sealed")
            };
        }
        let mut rs = vec![];
        for x in es {
            let a = final_before(e, c, &x.fact);
            let ls: Vec<_> = accepted(&e.links, c, "links")
                .into_iter()
                .filter(|l| l.fact.effect_id == x.fact.id)
                .collect();
            match a {
                Some(a) if a.fact.decision == Decision::Deny => rs.push(bad(
                    "the execution chain's final admission was Deny, yet the resource produced an effect",
                    vec![x.id.clone(), a.id.clone()],
                )),
                Some(a) => {
                    if !sealed(e, c, q, "admissions") {
                        rs.push(unknown("cannot confirm that no later final Deny exists"))
                    } else if ls.iter().any(|l| l.fact.admission_id == a.fact.id) {
                        rs.push(ok(
                            "a prior positive final admission exists with an independent execution-chain link",
                            vec![x.id.clone(), a.id.clone()],
                        ))
                    } else if sealed(e, c, q, "links") {
                        rs.push(bad(
                            "effect is not linked to the positive final admission of its execution chain",
                            vec![x.id.clone(), a.id.clone()],
                        ))
                    } else {
                        rs.push(unknown("execution-chain link evidence incomplete"))
                    }
                }
                None => {
                    if sealed(e, c, q, "admissions") {
                        rs.push(bad(
                            "the sealed admission set shows no prior final admission for this effect",
                            vec![x.id.clone()],
                        ))
                    } else {
                        rs.push(unknown("not finding an admission does not prove none exists"))
                    }
                }
            }
        }
        merge(rs)
    }
}

impl PropertyChecker for GovernanceFreshnessChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let req = &request(e, c, q).unwrap().fact;
        let ads = admissions(e, c, q);
        if ads.is_empty() {
            return if sealed(e, c, q, "admissions") {
                R::na("no admission decision")
            } else {
                unknown("missing admission evidence")
            };
        }
        if !sealed(e, c, q, "snapshots") {
            return unknown("missing proof that the governance history is complete");
        };
        let mut rs = vec![];
        for a in ads {
            let Some(s) = applicable_snapshot(e, c, a.fact.at) else {
                rs.push(unknown("no governance snapshot applicable at admission"));
                continue;
            };
            if s.fact.version != a.fact.observed_version {
                rs.push(bad(
                    "admission did not use the governance state applicable at that point",
                    vec![a.id.clone(), s.id.clone()],
                ));
                continue;
            }
            let creds = identities(e, c, q)
                .first()
                .map(|x| x.fact.credentials.clone())
                .unwrap_or_default();
            let any = s.fact.bases.iter().any(|b| {
                basis_matches(b, req, a.fact.at) && !revoked(&s.fact, b, req, a.fact.at, &creds)
            });
            if a.fact.decision == Decision::Allow && !any {
                rs.push(bad(
                    "admission saw an effective restriction but did not deny under the applicable state",
                    vec![a.id.clone(), s.id.clone()],
                ))
            } else {
                rs.push(ok(
                    "admission used the applicable state and honoured effective restrictions",
                    vec![a.id.clone(), s.id.clone()],
                ))
            }
        }
        merge(rs)
    }
}

impl PropertyChecker for EffectBindingChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let es = effects(e, c, q);
        if es.is_empty() {
            return if sealed(e, c, q, "effects") {
                R::na("no real effect")
            } else {
                unknown("effect records not sealed")
            };
        }
        let mut rs = vec![];
        for x in &es {
            let Some(a) = final_before(e, c, &x.fact) else {
                rs.push(R::na("no admission to compare against; left to G4"));
                continue;
            };
            if a.fact.decision != Decision::Allow {
                rs.push(R::na("final admission is not Allow; left to G4"));
                continue;
            }
            let actual_subject = accepted(&e.attributions, c, "attributions")
                .into_iter()
                .find(|v| v.fact.effect_id == x.fact.id);
            if actual_subject.is_some_and(|v| v.fact.subject != a.fact.subject) {
                rs.push(bad(
                    "the actual executing subject differs from the admitted subject",
                    vec![a.id.clone(), x.id.clone()],
                ));
                continue;
            }
            if a.fact.action != x.fact.action || a.fact.request_id != x.fact.request_id {
                rs.push(bad(
                    "admitted content or request link differs from the actual effect",
                    vec![a.id.clone(), x.id.clone()],
                ));
                continue;
            }
            let linked: BTreeSet<_> = accepted(&e.links, c, "links")
                .iter()
                .filter(|l| l.fact.admission_id == a.fact.id)
                .map(|l| l.fact.effect_id.clone())
                .collect();
            let count: usize = accepted(&e.effects, c, "effects")
                .iter()
                .filter(|v| linked.contains(&v.fact.id) && v.fact.at <= q.now)
                .map(|v| v.fact.id.clone())
                .collect::<BTreeSet<_>>()
                .len();
            if a.fact.consumption.limit().is_some_and(|max| count > max) {
                rs.push(bad(
                    "the same admission produced more independent real effects than its consumption bound",
                    vec![a.id.clone(), x.id.clone()],
                ))
            } else if !sealed(e, c, q, "effects") || !sealed(e, c, q, "links") {
                rs.push(unknown(
                    "effect or link set incomplete; consumption upper bound cannot be confirmed",
                ))
            } else {
                rs.push(ok(
                    "action content matches and observed effect count is within the consumption bound",
                    vec![a.id.clone(), x.id.clone()],
                ))
            }
        }
        if rs
            .iter()
            .all(|r| matches!(r.outcome, CheckOutcome::NotApplicable { .. }))
        {
            R::na("no positive admission to bind against")
        } else {
            merge(rs)
        }
    }
}

impl PropertyChecker for AttributionClosureChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let es = effects(e, c, q);
        if es.is_empty() {
            return if sealed(e, c, q, "effects") {
                R::na("no effect requires historical attribution")
            } else {
                unknown("whether an effect exists is not yet adjudicable")
            };
        }
        let mut rs = vec![];
        for x in es {
            if q.now.0 > x.fact.at.0.saturating_add(c.retention) {
                rs.push(R::na("retention obligation has ended"));
                continue;
            }
            let Some(p) = latest_provenance(e, c, &x.fact.id, q) else {
                rs.push(unknown(
                    "committed subject-role relation cannot be recovered",
                ));
                continue;
            };
            if !prov_complete(&p.fact, c) {
                rs.push(bad(
                    "recovered event-time role set does not satisfy the contract",
                    vec![p.id.clone()],
                ));
                continue;
            }
            if !correction_retained(e, c, p) {
                rs.push(unknown(
                    "latest record claims to correct an earlier one that is not retained; cannot tell correction from silent overwrite",
                ));
                continue;
            }
            let ids = identities(e, c, q);
            let ats: Vec<_> = accepted(&e.attributions, c, "attributions")
                .into_iter()
                .filter(|a| a.fact.effect_id == x.fact.id)
                .collect();
            let expected = ats
                .first()
                .map(|a| (&a.fact.subject, &a.fact.roles))
                .or_else(|| ids.first().map(|a| (&a.fact.actor, &a.fact.roles)));
            match expected {
                Some((s, roles)) => {
                    if p.fact.subject.as_ref() != Some(s) || &p.fact.roles != roles {
                        rs.push(bad(
                            "historical attribution disagrees with the independent trusted event-time relation",
                            vec![p.id.clone(), x.id.clone()],
                        ))
                    } else {
                        rs.push(ok(
                            "committed subject and multi-role relation are recoverable and agree with trusted facts",
                            vec![p.id.clone(), x.id.clone()],
                        ))
                    }
                }
                None => rs.push(unknown(
                    "only the SUT's own claim is recoverable; no independent identity support",
                )),
            }
        }
        if rs
            .iter()
            .all(|r| matches!(r.outcome, CheckOutcome::NotApplicable { .. }))
        {
            R::na("historical attribution is outside the retention window")
        } else {
            merge(rs)
        }
    }
}

impl PropertyChecker for AuthorityCorrespondenceChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        if effects(e, c, q).is_empty() {
            return if sealed(e, c, q, "effects") {
                R::na("no real effect requires authority correspondence")
            } else {
                unknown("effect set incomplete")
            };
        }
        merge(vec![
            SubjectRoleChecker.check(e, c, q),
            AuthorityBasisChecker.check(e, c, q),
            CompleteMediationChecker.check(e, c, q),
            GovernanceFreshnessChecker.check(e, c, q),
            EffectBindingChecker.check(e, c, q),
        ])
    }
}

impl PropertyChecker for RevocationSafetyChecker {
    fn check(&self, e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> R {
        if let Some(r) = precheck(e, c, q) {
            return r;
        }
        let req = &request(e, c, q).unwrap().fact;
        let identities = identities(e, c, q);
        let Some(id) = identities.first() else {
            return unknown("revocation applicability has no trusted subject");
        };
        let final_time = admissions(e, c, q)
            .iter()
            .map(|a| a.fact.at)
            .max()
            .unwrap_or(req.at);
        let Some(s) = applicable_snapshot(e, c, final_time) else {
            return unknown("missing applicable governance snapshot");
        };
        if !sealed(e, c, q, "snapshots") {
            return unknown("cannot confirm the revocation/reauthorization history is complete");
        };
        let mut actual = req.clone();
        actual.subject = id.fact.actor.clone();
        actual.roles = id.fact.roles.clone();
        let relevant: Vec<_> = s
            .fact
            .revocations
            .iter()
            .filter(|r| {
                r.effective_at <= final_time
                    && !s.fact.reauthorizations.iter().any(|a| {
                        a.revocation == r.id && a.at >= r.effective_at && a.at <= final_time
                    })
            })
            .filter(|r| {
                r.resource
                    .as_ref()
                    .is_none_or(|x| x == &req.action.resource)
                    && r.operation
                        .as_ref()
                        .is_none_or(|x| x == &req.action.operation)
            })
            .filter(|r| match &r.target {
                RevocationTarget::Subject(a) => a == &actual.subject,
                RevocationTarget::Basis(bid) => s
                    .fact
                    .bases
                    .iter()
                    .find(|b| &b.id == bid)
                    .is_some_and(|b| basis_matches(b, &actual, final_time)),
                RevocationTarget::Credential(cid) => id.fact.credentials.contains(cid),
                RevocationTarget::Delegation(d) => s.fact.bases.iter().any(|b| {
                    b.delegation.as_ref() == Some(d) && basis_matches(b, &actual, final_time)
                }),
            })
            .collect();
        if relevant.is_empty() {
            return R::na("no matching effective, un-withdrawn restriction at final admission (pre-admitted in-flight actions included)");
        };
        let available = s.fact.bases.iter().any(|b| {
            basis_matches(b, &actual, final_time)
                && !revoked(&s.fact, b, &actual, final_time, &id.fact.credentials)
        });
        if available {
            return R::na("an independent authority path remains valid; a single revocation is not widened into a blanket ban");
        };
        let es = effects(e, c, q);
        if !es.is_empty() {
            return bad(
                "a new request covered by an effective restriction still produced a real effect",
                es.iter()
                    .map(|x| x.id.clone())
                    .chain([s.id.clone()])
                    .collect(),
            );
        }
        if sealed(e, c, q, "effects") {
            ok(
                "no restricted new effect within the sealed observation interval",
                vec![s.id.clone()],
            )
        } else {
            unknown("subsequent effect observation not sealed; no claim about an unbounded future")
        }
    }
}

impl AccountabilityChecker {
    pub fn check(
        &self,
        e: &EvidenceSet,
        c: &ResearchContract,
        q: &QueryContext,
    ) -> CheckReport<AccountabilityVerdict> {
        if conflict(e, c, q) {
            return CheckReport::evaluated(
                AccountabilityVerdict::EvidenceConflict,
                "trusted facts are incompatible",
                vec![],
            );
        }
        let es = effects(e, c, q);
        if es.is_empty() {
            return if sealed(e, c, q, "effects") {
                CheckReport::na("no real effect requires accountability")
            } else {
                CheckReport::evaluated(
                    AccountabilityVerdict::Unadjudicable,
                    "effect observation incomplete",
                    vec![],
                )
            };
        }
        let mut status = AccountabilityVerdict::Closed;
        let mut used = vec![];
        for x in es {
            if q.now.0 > x.fact.at.0.saturating_add(c.retention) {
                return CheckReport::na("lawful clean-up after the retention obligation is not a responsibility black hole");
            }
            let p = latest_provenance(e, c, &x.fact.id, q);
            let ids = identities(e, c, q);
            let ats = accepted(&e.attributions, c, "attributions");
            let has_independent =
                !ids.is_empty() || ats.iter().any(|a| a.fact.effect_id == x.fact.id);
            let complete = p.is_some_and(|p| prov_complete(&p.fact, c));
            if complete && has_independent {
                let o1 = AttributionClosureChecker.check(e, c, q);
                if o1.outcome == CheckOutcome::Evaluated(PropertyVerdict::Satisfied) {
                    used.push(x.id.clone());
                    continue;
                }
            }
            let all_lost = !c.recovery_paths.is_empty()
                && c.recovery_paths.iter().all(|path| {
                    accepted(&e.availability, c, "availability")
                        .iter()
                        .filter(|f| {
                            f.fact.effect_id == x.fact.id
                                && &f.fact.path == path
                                && f.fact.at <= q.now
                        })
                        .max_by_key(|f| f.fact.at)
                        .is_some_and(|f| f.fact.availability == Availability::PermanentlyLost)
                });
            let beyond = q.now.0 >= x.fact.at.0.saturating_add(c.commitment_window);
            if all_lost && beyond && !has_independent && !complete {
                status = AccountabilityVerdict::ConfirmedRbh
            } else if status != AccountabilityVerdict::ConfirmedRbh {
                status = AccountabilityVerdict::Unadjudicable
            };
            used.push(x.id.clone());
        }
        CheckReport::evaluated(
            status,
            match status {
                AccountabilityVerdict::Closed => "required historical relations close against independent trusted facts",
                AccountabilityVerdict::ConfirmedRbh => {
                    "within the retention obligation, every contract recovery path is confirmed unrecoverable by trusted observation"
                }
                AccountabilityVerdict::Unadjudicable => "insufficient evidence; absence alone does not prove permanent loss",
                AccountabilityVerdict::EvidenceConflict => "trusted facts conflict",
            },
            used,
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reports {
    pub properties: BTreeMap<String, R>,
    pub accountability: CheckReport<AccountabilityVerdict>,
}
pub fn check_all(e: &EvidenceSet, c: &ResearchContract, q: &QueryContext) -> Reports {
    let cs: Vec<(&str, Box<dyn PropertyChecker>)> = vec![
        ("G1", Box::new(SubjectRoleChecker)),
        ("G2", Box::new(ProvenanceChecker)),
        ("G3", Box::new(AuthorityBasisChecker)),
        ("G4", Box::new(CompleteMediationChecker)),
        ("G5", Box::new(GovernanceFreshnessChecker)),
        ("G6", Box::new(EffectBindingChecker)),
        ("O1", Box::new(AttributionClosureChecker)),
        ("O2", Box::new(AuthorityCorrespondenceChecker)),
        ("O3", Box::new(RevocationSafetyChecker)),
    ];
    Reports {
        properties: cs
            .into_iter()
            .map(|(name, ch)| (name.into(), ch.check(e, c, q)))
            .collect(),
        accountability: AccountabilityChecker.check(e, c, q),
    }
}
