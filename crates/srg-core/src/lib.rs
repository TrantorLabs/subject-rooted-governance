//! 主体根式治理的类型与证据语义。正常系统义务与可观察失败分开。
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

macro_rules! id {
    ($($name:ident),+) => {$ (
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);
        impl From<&str> for $name { fn from(v: &str) -> Self { Self(v.to_owned()) } }
        impl std::fmt::Display for $name { fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result { write!(f,"{}",self.0) } }
    )+};
}
id!(
    DomainId,
    ActorId,
    CredentialId,
    SessionId,
    RuntimeId,
    ClientId,
    RequestId,
    AdmissionId,
    EffectId,
    BasisId,
    RevocationId,
    EvidenceId,
    SourceId,
    ChainId
);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogicalPoint(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GovernanceVersion(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActorKind {
    Human,
    AIActor,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ActorRef {
    pub domain: DomainId,
    pub id: ActorId,
    pub kind: ActorKind,
}
impl ActorRef {
    pub fn ai(id: &str) -> Self {
        Self {
            domain: "research".into(),
            id: id.into(),
            kind: ActorKind::AIActor,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    Requester,
    Executor,
    Delegator,
    Authorizer,
}
pub type Roles = BTreeMap<Role, BTreeSet<ActorRef>>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRequirement {
    pub min: usize,
    pub max: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleTransition {
    CredentialRotation,
    SessionRenewal,
    ClientChange,
    RuntimeMigration,
    SubjectCreation,
    SubjectRetirement,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedActorFact {
    pub request_id: RequestId,
    pub actor: ActorRef,
    pub credentials: Vec<CredentialId>,
    pub session: Option<SessionId>,
    pub runtime: Option<RuntimeId>,
    pub roles: Roles,
    pub at: LogicalPoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDescriptor {
    pub resource: String,
    pub operation: String,
    pub recipient: String,
    pub amount: u64,
}
impl ActionDescriptor {
    pub fn transfer(to: &str, amount: u64) -> Self {
        Self {
            resource: "ledger".into(),
            operation: "transfer".into(),
            recipient: to.into(),
            amount,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub id: RequestId,
    pub chain: ChainId,
    pub subject: ActorRef,
    pub roles: Roles,
    pub action: ActionDescriptor,
    pub at: LogicalPoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityBasis {
    pub id: BasisId,
    pub subject: ActorRef,
    pub role: Role,
    pub resource: String,
    pub operation: String,
    pub recipients: BTreeSet<String>,
    pub max_amount: u64,
    pub issued_at: LogicalPoint,
    pub expires_at: Option<LogicalPoint>,
    pub delegation: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationTarget {
    Subject(ActorRef),
    Basis(BasisId),
    Delegation(String),
    Credential(CredentialId),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub id: RevocationId,
    pub target: RevocationTarget,
    pub resource: Option<String>,
    pub operation: Option<String>,
    pub effective_at: LogicalPoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reauthorization {
    pub revocation: RevocationId,
    pub at: LogicalPoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySnapshot {
    pub version: GovernanceVersion,
    pub at: LogicalPoint,
    pub bases: Vec<AuthorityBasis>,
    pub revocations: Vec<Revocation>,
    pub reauthorizations: Vec<Reauthorization>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsumptionPolicy {
    SingleUse,
    MaxUses(u32),
    Unlimited,
}
impl ConsumptionPolicy {
    pub fn limit(&self) -> Option<usize> {
        match self {
            Self::SingleUse => Some(1),
            Self::MaxUses(n) => Some(*n as usize),
            Self::Unlimited => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionDecision {
    pub id: AdmissionId,
    pub request_id: RequestId,
    pub chain: ChainId,
    pub subject: ActorRef,
    pub roles: Roles,
    pub action: ActionDescriptor,
    pub decision: Decision,
    pub actual_basis: Option<BasisId>,
    pub observed_version: GovernanceVersion,
    pub at: LogicalPoint,
    pub consumption: ConsumptionPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReceipt {
    pub id: EffectId,
    pub chain: ChainId,
    pub request_id: RequestId,
    pub action: ActionDescriptor,
    pub at: LogicalPoint,
    pub ledger_sequence: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectAttribution {
    pub effect_id: EffectId,
    pub subject: ActorRef,
    pub roles: Roles,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLink {
    pub effect_id: EffectId,
    pub admission_id: AdmissionId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityContext {
    Valid(BasisId),
    NoApplicableAuthority,
    Revoked(BasisId),
    Conflict(Vec<BasisId>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub effect_id: EffectId,
    pub subject: Option<ActorRef>,
    pub roles: Roles,
    pub authority: Option<AuthorityContext>,
    pub admission: Option<AdmissionId>,
    pub committed_at: Option<LogicalPoint>,
    pub corrects: Option<EvidenceId>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Availability {
    Available,
    TemporarilyUnavailable,
    PermanentlyLost,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStateFact {
    pub effect_id: EffectId,
    pub path: String,
    pub availability: Availability,
    pub at: LogicalPoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub id: EvidenceId,
    pub source: SourceId,
    pub fact: T,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSeal {
    pub source: SourceId,
    pub through: LogicalPoint,
    pub channels: BTreeSet<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceSet {
    pub identity: Vec<Envelope<VerifiedActorFact>>,
    pub requests: Vec<Envelope<ActionRequest>>,
    pub admissions: Vec<Envelope<AdmissionDecision>>,
    pub effects: Vec<Envelope<EffectReceipt>>,
    pub attributions: Vec<Envelope<EffectAttribution>>,
    pub links: Vec<Envelope<GovernanceLink>>,
    pub provenance: Vec<Envelope<ProvenanceRecord>>,
    pub snapshots: Vec<Envelope<AuthoritySnapshot>>,
    pub availability: Vec<Envelope<EvidenceStateFact>>,
    pub seals: Vec<ObservationSeal>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchContract {
    pub id: String,
    pub domain: DomainId,
    pub resources: BTreeSet<String>,
    pub role_schema: BTreeMap<Role, RoleRequirement>,
    pub sources: BTreeMap<String, SourceId>,
    pub commitment_window: u64,
    pub retention: u64,
    pub recovery_paths: BTreeSet<String>,
    pub max_clock: u64,
}
impl Default for ResearchContract {
    fn default() -> Self {
        let mut role_schema = BTreeMap::new();
        for r in [Role::Requester, Role::Executor] {
            role_schema.insert(r, RoleRequirement { min: 1, max: 1 });
        }
        Self {
            id: "ReferenceContractV1".into(),
            domain: "research".into(),
            resources: ["ledger".into()].into_iter().collect(),
            role_schema,
            sources: [
                ("identity", "identity-root"),
                ("requests", "request-recorder"),
                ("admissions", "admission-recorder"),
                ("effects", "resource-observer"),
                ("attributions", "resource-observer"),
                ("links", "resource-observer"),
                ("provenance", "provenance-store"),
                ("snapshots", "authority-root"),
                ("availability", "recovery-observer"),
                ("seal", "collector"),
            ]
            .into_iter()
            .map(|(a, b)| (a.into(), b.into()))
            .collect(),
            commitment_window: 2,
            retention: 100,
            recovery_paths: ["primary".into()].into_iter().collect(),
            max_clock: 200,
        }
    }
}
impl ResearchContract {
    pub fn accepts(&self, channel: &str, source: &SourceId) -> bool {
        self.sources.get(channel) == Some(source)
    }
    pub fn in_scope(&self, a: &ActionDescriptor) -> bool {
        self.resources.contains(&a.resource)
    }
    pub fn roles_complete(&self, roles: &Roles) -> bool {
        self.role_schema.iter().all(|(r, req)| {
            roles
                .get(r)
                .map_or(req.min == 0, |a| a.len() >= req.min && a.len() <= req.max)
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyVerdict {
    Satisfied,
    Violated,
    Unadjudicable,
    EvidenceConflict,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountabilityVerdict {
    Closed,
    Unadjudicable,
    ConfirmedRbh,
    EvidenceConflict,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOutcome<V> {
    NotApplicable { reason: String },
    Evaluated(V),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport<V> {
    pub outcome: CheckOutcome<V>,
    pub evidence_used: Vec<EvidenceId>,
    pub reasons: Vec<String>,
}
impl<V> CheckReport<V> {
    pub fn evaluated(v: V, reason: &str, ids: Vec<EvidenceId>) -> Self {
        Self {
            outcome: CheckOutcome::Evaluated(v),
            evidence_used: ids,
            reasons: vec![reason.into()],
        }
    }
    pub fn na(reason: &str) -> Self {
        Self {
            outcome: CheckOutcome::NotApplicable {
                reason: reason.into(),
            },
            evidence_used: vec![],
            reasons: vec![reason.into()],
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryContext {
    pub request_id: RequestId,
    pub now: LogicalPoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub point: LogicalPoint,
    pub kind: String,
    pub detail: serde_json::Value,
}
/// 只对声明的有限相容解释集作精确四值归约，不预先假设性质成立。
pub fn verdict_from_worlds(values: impl IntoIterator<Item = bool>) -> PropertyVerdict {
    let v: Vec<_> = values.into_iter().collect();
    if v.is_empty() {
        PropertyVerdict::EvidenceConflict
    } else if v.iter().all(|x| *x) {
        PropertyVerdict::Satisfied
    } else if v.iter().all(|x| !*x) {
        PropertyVerdict::Violated
    } else {
        PropertyVerdict::Unadjudicable
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn four_values() {
        assert_eq!(verdict_from_worlds([]), PropertyVerdict::EvidenceConflict);
        assert_eq!(verdict_from_worlds([true]), PropertyVerdict::Satisfied);
        assert_eq!(verdict_from_worlds([false]), PropertyVerdict::Violated);
        assert_eq!(
            verdict_from_worlds([true, false]),
            PropertyVerdict::Unadjudicable
        );
    }
    #[test]
    fn domain_separation() {
        let a = ActorRef::ai("A");
        let mut b = a.clone();
        b.domain = "another".into();
        assert_ne!(a, b);
    }
    #[test]
    fn consumption() {
        assert_eq!(ConsumptionPolicy::SingleUse.limit(), Some(1));
        assert_eq!(ConsumptionPolicy::Unlimited.limit(), None);
    }
}
