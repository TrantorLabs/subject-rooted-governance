//! SoulAuth 认证事实边界适配。输入必须来自调用者建立的可信传输边界。
//! 反序列化 JSON 本身不是认证；此 crate 不提供业务授权，也不假设存在公开 /fact 端点。
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use srg_core::*;
use thiserror::Error;
pub const REFERENCE_COMMIT: &str = "0830d1733b911558484006d61c463e8b90e9eab5";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    Password,
    Totp,
    BackupCode,
    ExternalIdentity,
    EmailLink,
    Ed25519Key,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoulAuthActorKind {
    Human,
    AiActor,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFact {
    pub actor_identity_id: String,
    pub actor_kind: SoulAuthActorKind,
    pub methods: Vec<AuthenticationMethod>,
    pub authenticated_at: i64,
    pub credential_refs: Vec<String>,
}
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("invalid authentication fact: {0}")]
    Invalid(String),
    #[error("transport error: {0}")]
    Transport(String),
}
/// 实现者须建立真实认证与传输信任；不能从任意调用方 JSON 伪造 verified 标记。
pub trait AuthenticatedFactTransport {
    fn obtain_fact(&mut self) -> Result<AuthenticationFact, AdapterError>;
}
pub struct SoulAuthIdentityProvider<T> {
    transport: T,
    domain: DomainId,
}
impl<T: AuthenticatedFactTransport> SoulAuthIdentityProvider<T> {
    pub fn new(transport: T, domain: DomainId) -> Self {
        Self { transport, domain }
    }
    pub fn authenticate(
        &mut self,
        request: RequestId,
        observed_at: LogicalPoint,
        now_unix: i64,
        max_age_seconds: i64,
    ) -> Result<VerifiedActorFact, AdapterError> {
        let f = self.transport.obtain_fact()?;
        if max_age_seconds < 0
            || f.authenticated_at > now_unix
            || now_unix.saturating_sub(f.authenticated_at) > max_age_seconds
        {
            return Err(AdapterError::Invalid(
                "authentication time outside the allowed window".into(),
            ));
        }
        if !f.actor_identity_id.starts_with("actor_identity:")
            || f.actor_identity_id.len() <= 15
            || f.methods.is_empty()
        {
            return Err(AdapterError::Invalid(
                "missing subject reference or authentication method".into(),
            ));
        }
        if f.actor_kind == SoulAuthActorKind::AiActor
            && (f.credential_refs.is_empty()
                || !f.methods.contains(&AuthenticationMethod::Ed25519Key))
        {
            return Err(AdapterError::Invalid(
                "AIActor fact carries no key-based authentication".into(),
            ));
        }
        let actor = ActorRef {
            domain: self.domain.clone(),
            id: ActorId(f.actor_identity_id),
            kind: match f.actor_kind {
                SoulAuthActorKind::Human => ActorKind::Human,
                SoulAuthActorKind::AiActor => ActorKind::AIActor,
            },
        };
        Ok(VerifiedActorFact {
            request_id: request,
            actor,
            credentials: f.credential_refs.into_iter().map(CredentialId).collect(),
            session: None,
            runtime: None,
            roles: Default::default(),
            at: observed_at,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Transport(AuthenticationFact);
    impl AuthenticatedFactTransport for Transport {
        fn obtain_fact(&mut self) -> Result<AuthenticationFact, AdapterError> {
            Ok(self.0.clone())
        }
    }
    fn fact() -> AuthenticationFact {
        AuthenticationFact {
            actor_identity_id: "actor_identity:alice".into(),
            actor_kind: SoulAuthActorKind::Human,
            methods: vec![AuthenticationMethod::ExternalIdentity],
            authenticated_at: 100,
            credential_refs: vec![],
        }
    }
    #[test]
    fn external_human_needs_no_fake_credential() {
        let mut p = SoulAuthIdentityProvider::new(Transport(fact()), "soulauth".into());
        let f = p
            .authenticate("r".into(), LogicalPoint(1), 101, 60)
            .unwrap();
        assert!(f.credentials.is_empty());
        assert!(f.roles.is_empty());
    }
    #[test]
    fn unix_is_not_logical_time() {
        let mut p = SoulAuthIdentityProvider::new(Transport(fact()), "soulauth".into());
        assert_eq!(
            p.authenticate("r".into(), LogicalPoint(7), 101, 60)
                .unwrap()
                .at,
            LogicalPoint(7)
        );
    }
    #[test]
    fn stale_fact_rejected() {
        let mut p = SoulAuthIdentityProvider::new(Transport(fact()), "soulauth".into());
        assert!(p
            .authenticate("r".into(), LogicalPoint(1), 200, 60)
            .is_err());
    }
    #[test]
    fn ai_requires_ed25519() {
        let mut f = fact();
        f.actor_kind = SoulAuthActorKind::AiActor;
        let mut p = SoulAuthIdentityProvider::new(Transport(f), "soulauth".into());
        assert!(p
            .authenticate("r".into(), LogicalPoint(1), 101, 60)
            .is_err());
    }
}
