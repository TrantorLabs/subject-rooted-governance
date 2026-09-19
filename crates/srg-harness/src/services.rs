//! 被测路径：不依赖 checker；故障层可以构造真实错误执行。
use srg_core::*;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("final admission does not allow execution")]
    Denied,
    #[error("command does not match the admission")]
    Mismatch,
    #[error("admission consumption budget exhausted")]
    Consumed,
    #[error("insufficient balance or integer overflow")]
    Balance,
}
#[derive(Debug, Default)]
pub struct ControlledLedger {
    balances: BTreeMap<String, u64>,
    uses: BTreeMap<AdmissionId, usize>,
    idempotent: BTreeMap<(AdmissionId, String), EffectReceipt>,
    sequence: u64,
}
impl ControlledLedger {
    pub fn new() -> Self {
        Self {
            balances: [
                ("treasury".into(), 1_000_000),
                ("X".into(), 0),
                ("Y".into(), 0),
            ]
            .into_iter()
            .collect(),
            ..Self::default()
        }
    }
    pub fn balances(&self) -> BTreeMap<String, u64> {
        self.balances.clone()
    }
    pub fn execute(
        &mut self,
        a: &AdmissionDecision,
        command: ActionDescriptor,
        key: &str,
        at: LogicalPoint,
    ) -> Result<EffectReceipt, ResourceError> {
        if a.decision != Decision::Allow {
            return Err(ResourceError::Denied);
        }
        if a.action != command {
            return Err(ResourceError::Mismatch);
        }
        let id = (a.id.clone(), key.to_string());
        if let Some(old) = self.idempotent.get(&id) {
            return Ok(old.clone());
        }
        let used = *self.uses.get(&a.id).unwrap_or(&0);
        if a.consumption.limit().is_some_and(|n| used >= n) {
            return Err(ResourceError::Consumed);
        }
        let effect = self.apply(&a.chain, &a.request_id, command, at)?;
        self.uses.insert(a.id.clone(), used + 1);
        self.idempotent.insert(id, effect.clone());
        Ok(effect)
    }
    /// 只供故障注入。调用会真实修改研究账本，不是修改 checker 的输入答案。
    pub fn fault_execute(
        &mut self,
        chain: &ChainId,
        request: &RequestId,
        command: ActionDescriptor,
        at: LogicalPoint,
    ) -> Result<EffectReceipt, ResourceError> {
        self.apply(chain, request, command, at)
    }
    fn apply(
        &mut self,
        chain: &ChainId,
        request: &RequestId,
        command: ActionDescriptor,
        at: LogicalPoint,
    ) -> Result<EffectReceipt, ResourceError> {
        if command.resource != "ledger"
            || command.operation != "transfer"
            || command.amount == 0
            || command.recipient == "treasury"
        {
            return Err(ResourceError::Mismatch);
        }
        let from = *self.balances.get("treasury").unwrap_or(&0);
        let to = *self.balances.get(&command.recipient).unwrap_or(&0);
        let nf = from
            .checked_sub(command.amount)
            .ok_or(ResourceError::Balance)?;
        let nt = to
            .checked_add(command.amount)
            .ok_or(ResourceError::Balance)?;
        let seq = self.sequence.checked_add(1).ok_or(ResourceError::Balance)?;
        self.balances.insert("treasury".into(), nf);
        self.balances.insert(command.recipient.clone(), nt);
        self.sequence = seq;
        Ok(EffectReceipt {
            id: EffectId(format!("effect-{seq}")),
            chain: chain.clone(),
            request_id: request.clone(),
            action: command,
            at,
            ledger_sequence: seq,
        })
    }
}
pub fn roles(actor: &ActorRef) -> Roles {
    [Role::Requester, Role::Executor]
        .into_iter()
        .map(|r| (r, [actor.clone()].into_iter().collect()))
        .collect()
}
pub fn basis(id: &str, actor: &ActorRef) -> AuthorityBasis {
    AuthorityBasis {
        id: id.into(),
        subject: actor.clone(),
        role: Role::Requester,
        resource: "ledger".into(),
        operation: "transfer".into(),
        recipients: ["X".into()].into_iter().collect(),
        max_amount: 2000,
        issued_at: LogicalPoint(1),
        expires_at: None,
        delegation: None,
    }
}
/// SUT 的授权算法与审计器实现分开，便于相互校验。
pub fn decide(
    req: &ActionRequest,
    id: &VerifiedActorFact,
    s: &AuthoritySnapshot,
    c: &ResearchContract,
) -> AdmissionDecision {
    let at = LogicalPoint(5);
    let mut selected = None;
    if c.roles_complete(&req.roles) && req.subject == id.actor {
        for b in &s.bases {
            let mut eligible = b.subject == req.subject
                && b.resource == req.action.resource
                && b.operation == req.action.operation
                && b.recipients.contains(&req.action.recipient)
                && b.max_amount >= req.action.amount
                && b.issued_at <= at
                && b.expires_at.is_none_or(|x| at < x)
                && req
                    .roles
                    .get(&b.role)
                    .is_some_and(|xs| xs.contains(&req.subject));
            for r in &s.revocations {
                if r.effective_at > at
                    || s.reauthorizations
                        .iter()
                        .any(|x| x.revocation == r.id && x.at >= r.effective_at && x.at <= at)
                {
                    continue;
                }
                if r.resource
                    .as_ref()
                    .is_some_and(|x| x != &req.action.resource)
                    || r.operation
                        .as_ref()
                        .is_some_and(|x| x != &req.action.operation)
                {
                    continue;
                }
                let target = match &r.target {
                    RevocationTarget::Subject(a) => a == &req.subject,
                    RevocationTarget::Basis(bid) => bid == &b.id,
                    RevocationTarget::Delegation(d) => b.delegation.as_ref() == Some(d),
                    RevocationTarget::Credential(cid) => id.credentials.contains(cid),
                };
                if target {
                    eligible = false
                }
            }
            if eligible {
                selected = Some(b.id.clone());
                break;
            }
        }
    }
    AdmissionDecision {
        id: "admission-1".into(),
        request_id: req.id.clone(),
        chain: req.chain.clone(),
        subject: req.subject.clone(),
        roles: req.roles.clone(),
        action: req.action.clone(),
        decision: if selected.is_some() {
            Decision::Allow
        } else {
            Decision::Deny
        },
        actual_basis: selected,
        observed_version: s.version,
        at,
        consumption: ConsumptionPolicy::SingleUse,
    }
}
pub fn subject_suspend(a: &ActorRef) -> Revocation {
    Revocation {
        id: "revoke-1".into(),
        target: RevocationTarget::Subject(a.clone()),
        resource: Some("ledger".into()),
        operation: Some("transfer".into()),
        effective_at: LogicalPoint(3),
    }
}
pub fn seal(c: &ResearchContract, now: LogicalPoint) -> ObservationSeal {
    ObservationSeal {
        source: c.sources["seal"].clone(),
        through: now,
        channels: [
            "identity",
            "requests",
            "admissions",
            "effects",
            "attributions",
            "links",
            "provenance",
            "snapshots",
            "availability",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>(),
    }
}
