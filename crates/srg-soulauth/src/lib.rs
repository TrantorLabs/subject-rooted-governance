//! SoulAuth 认证事实边界适配。输入必须来自调用者建立的可信传输边界。
//! 反序列化 JSON 本身不是认证；此 crate 不提供业务授权。
//!
//! SoulAuth 自 `GET /api/auth/introspect` 起把认证事实交给依赖方：出示令牌的那个
//! 会话是谁、什么类型、用哪些方法、何时、经由哪些本地凭证。这里定义那份响应的
//! 形状（[`IntrospectionResponse`]）并把它变成 [`VerifiedActorFact`]；真正去调用
//! 端点的 HTTP 传输在 `srg-live`，核心实验不依赖它。
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use srg_core::*;
use thiserror::Error;
/// 适配所针对的 SoulAuth 提交：`/api/auth/introspect` 与 `session.methods` /
/// `session.credential_refs` 首次出现的那一版。
pub const REFERENCE_COMMIT: &str = "1acef4935e2c13faadf378cd6bb4e60d96d9a163";
/// 认证事实所在的端点。持有者对自己的自省；不是 RFC 7662。
pub const INTROSPECTION_PATH: &str = "/api/auth/introspect";
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
/// `GET /api/auth/introspect` 的响应：事实 + 会话投影。事实不拥有令牌，响应里也没有令牌。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub authentication: AuthenticationFact,
    pub session: SessionProjection,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProjection {
    pub id: String,
    pub created_at: i64,
    pub expires_at: i64,
}
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("invalid authentication fact: {0}")]
    Invalid(String),
    #[error("transport error: {0}")]
    Transport(String),
}
/// 实现者须建立真实认证与传输信任；不能从任意调用方 JSON 伪造 verified 标记。
/// 交回的是 `/api/auth/introspect` 的整份响应：事实之外还有会话投影，会话是主体的
/// 外围对象（论文 §3.3），一并进入 [`VerifiedActorFact::session`]。
pub trait AuthenticatedFactTransport {
    fn obtain(&mut self) -> Result<IntrospectionResponse, AdapterError>;
}
pub struct SoulAuthIdentityProvider<T> {
    transport: T,
    domain: DomainId,
}
impl<T: AuthenticatedFactTransport> SoulAuthIdentityProvider<T> {
    pub fn new(transport: T, domain: DomainId) -> Self {
        Self { transport, domain }
    }
    /// 交还传输实现（例如为了取回它保留的原始响应作为证据）。
    pub fn into_transport(self) -> T {
        self.transport
    }
    pub fn authenticate(
        &mut self,
        request: RequestId,
        observed_at: LogicalPoint,
        now_unix: i64,
        max_age_seconds: i64,
    ) -> Result<VerifiedActorFact, AdapterError> {
        let r = self.transport.obtain()?;
        let f = r.authentication;
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
            session: Some(SessionId(r.session.id)),
            runtime: None,
            roles: Default::default(),
            at: observed_at,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// 与 SoulAuth `IntrospectionResponse`（routes/auth.rs）逐字段对应的样本；
    /// 结构变了这里先红，而不是等 live 跑到一半才发现解析不了。
    #[test]
    fn introspection_response_parses_and_flows_into_the_adapter() {
        let text = r#"{"authentication":{"actor_identity_id":"actor_identity:agent-1","actor_kind":"ai_actor","methods":["ed25519_key"],"authenticated_at":1700000000,"credential_refs":["ai_actor_credential:k1"]},"session":{"id":"s1","created_at":1700000000,"expires_at":1700086400}}"#;
        let r: IntrospectionResponse = serde_json::from_str(text).unwrap();
        assert_eq!(r.session.id, "s1");
        struct T(IntrospectionResponse);
        impl AuthenticatedFactTransport for T {
            fn obtain(&mut self) -> Result<IntrospectionResponse, AdapterError> {
                Ok(self.0.clone())
            }
        }
        let mut p = SoulAuthIdentityProvider::new(T(r), "soulauth".into());
        let f = p
            .authenticate("r".into(), LogicalPoint(1), 1700000010, 60)
            .unwrap();
        assert_eq!(f.actor.kind, ActorKind::AIActor);
        assert_eq!(f.actor.id.0, "actor_identity:agent-1");
        assert_eq!(
            f.credentials,
            vec![CredentialId("ai_actor_credential:k1".into())]
        );
        assert_eq!(f.session, Some(SessionId("s1".into())));
    }
    struct Transport(AuthenticationFact);
    impl AuthenticatedFactTransport for Transport {
        fn obtain(&mut self) -> Result<IntrospectionResponse, AdapterError> {
            Ok(IntrospectionResponse {
                authentication: self.0.clone(),
                session: SessionProjection {
                    id: "session-1".into(),
                    created_at: self.0.authenticated_at,
                    expires_at: self.0.authenticated_at + 3600,
                },
            })
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
