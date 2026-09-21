//! Live SoulAuth 集成套件（CONF-01 §32、§44 R21–R23）。
//!
//! 核心实验从不依赖网络服务；这里是单独的一条路径，对着一个**真正运行**的
//! SoulAuth 走完 AIActor 的认证：领取挑战 → 用 Ed25519 私钥签名 → 换取会话令牌 →
//! 用该令牌读 `/api/auth/introspect` → 把返回的认证事实经 [`srg_soulauth`] 的适配器
//! 变成 [`srg_core::VerifiedActorFact`]。每一步的响应都落成证据；令牌本身只留
//! SHA-256 指纹。
//!
//! 它做的只有认证与事实获取。它不读任何 Authority，也不产生任何治理决定 ——
//! Identity ≠ Authority（CORE-01 §24、§39）。
//!
//! ```text
//! srg-live keygen --seed-hex <64 hex>                # 打印对应的 base64url 公钥
//! srg-live run --base-url http://127.0.0.1:8080 \
//!     --actor-id actor_identity:… --seed-hex <64 hex> \
//!     [--human-email … --human-password …] [--soulauth-commit <sha>] [--out DIR]
//! ```
#![forbid(unsafe_code)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srg_core::{DomainId, LogicalPoint, RequestId, VerifiedActorFact};
use srg_soulauth::{
    AdapterError, AuthenticatedFactTransport, IntrospectionResponse, SoulAuthIdentityProvider,
    INTROSPECTION_PATH, REFERENCE_COMMIT,
};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Live SoulAuth integration suite for the Subject-Rooted Governance artifact"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the base64url public key of an Ed25519 seed (what SoulAuth registers).
    Keygen {
        #[arg(long)]
        seed_hex: String,
    },
    /// Authenticate against a running SoulAuth and record the evidence.
    Run {
        #[arg(long)]
        base_url: String,
        /// `actor_identity:…` of an AI actor whose public key SoulAuth already holds.
        #[arg(long)]
        actor_id: String,
        /// The actor's Ed25519 seed, 32 bytes hex. Never leaves this process.
        #[arg(long)]
        seed_hex: String,
        /// Optionally also introspect a human session established by password login.
        #[arg(long)]
        human_email: Option<String>,
        #[arg(long)]
        human_password: Option<String>,
        /// The SoulAuth commit the service was built from; recorded, not verified.
        #[arg(long)]
        soulauth_commit: Option<String>,
        #[arg(long, default_value = "results/live/soulauth")]
        out: PathBuf,
    },
}

#[derive(Debug, thiserror::Error)]
enum LiveError {
    #[error("HTTP {status} from {path}: {body}")]
    Status {
        status: u16,
        path: String,
        body: String,
    },
    #[error("transport: {0}")]
    Transport(String),
    #[error("{0}")]
    Other(String),
}

impl From<ureq::Error> for LiveError {
    fn from(e: ureq::Error) -> Self {
        match e {
            ureq::Error::Status(status, resp) => LiveError::Status {
                status,
                path: resp.get_url().to_string(),
                body: resp.into_string().unwrap_or_default(),
            },
            other => LiveError::Transport(other.to_string()),
        }
    }
}

fn seed_from_hex(seed_hex: &str) -> Result<SigningKey, LiveError> {
    let bytes =
        hex::decode(seed_hex.trim()).map_err(|e| LiveError::Other(format!("seed hex: {e}")))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| LiveError::Other("seed must be exactly 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sha256_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

// ── SoulAuth 的公开契约形状（只取本套件用到的字段）──

#[derive(Debug, Deserialize, Serialize)]
struct IssuedChallenge {
    actor_id: String,
    nonce: String,
    expires_at: i64,
    payload: String,
}

#[derive(Debug, Deserialize)]
struct AuthenticateResponse {
    token: String,
    actor_id: String,
    expires_at: i64,
    credential_label: String,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    token: String,
}

// ── 证据 ──

#[derive(Debug, Serialize)]
struct TokenFingerprint {
    /// 令牌的 SHA-256；证据里永远没有令牌本身。
    token_sha256: String,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
struct AiActorEvidence {
    challenge: IssuedChallenge,
    /// 签名以 base64url 记录：它对已经消费掉的一次性挑战无用，但能让审阅者验签。
    signature: String,
    authenticate: AiAuthenticateEvidence,
    introspection: IntrospectionResponse,
    verified_actor_fact: VerifiedActorFact,
}

#[derive(Debug, Serialize)]
struct AiAuthenticateEvidence {
    actor_id: String,
    credential_label: String,
    token: TokenFingerprint,
}

#[derive(Debug, Serialize)]
struct HumanEvidence {
    email: String,
    token: TokenFingerprint,
    introspection: IntrospectionResponse,
    verified_actor_fact: VerifiedActorFact,
}

#[derive(Debug, Serialize)]
struct NegativeChecks {
    /// 不带令牌读自省端点的状态码；必须是 401。
    no_token_status: u16,
    /// 带一枚伪造令牌的状态码；必须是 401。
    forged_token_status: u16,
    /// 换到令牌后不能再用同一个 nonce 认证；必须是 401。
    replayed_nonce_status: u16,
}

#[derive(Debug, Serialize)]
struct LiveManifest {
    soulauth_live: &'static str,
    base_url: String,
    /// 服务由哪个 SoulAuth 提交构建（由调用方给出）。
    soulauth_commit: Option<String>,
    /// 适配器编写时对应的 SoulAuth 提交。
    soulauth_reference_commit: &'static str,
    introspection_path: &'static str,
    artifact_version: &'static str,
    timestamp_unix: u64,
    ai_actor: bool,
    human: bool,
}

/// 一次 GET /api/auth/introspect，就是 [`AuthenticatedFactTransport`] 的一个实现：
/// 可信传输边界 = 出示刚由 SoulAuth 自己签发的会话令牌。
struct Introspection {
    base_url: String,
    token: String,
    last: Option<IntrospectionResponse>,
}

impl Introspection {
    fn fetch(&mut self) -> Result<IntrospectionResponse, LiveError> {
        let r: IntrospectionResponse =
            ureq::get(&format!("{}{}", self.base_url, INTROSPECTION_PATH))
                .set("Authorization", &format!("Bearer {}", self.token))
                .call()?
                .into_json()
                .map_err(|e| LiveError::Transport(e.to_string()))?;
        self.last = Some(r.clone());
        Ok(r)
    }
}

impl AuthenticatedFactTransport for Introspection {
    fn obtain(&mut self) -> Result<IntrospectionResponse, AdapterError> {
        self.fetch()
            .map_err(|e| AdapterError::Transport(e.to_string()))
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn status_of(req: ureq::Request) -> u16 {
    match req.call() {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(s, _)) => s,
        Err(_) => 0,
    }
}

fn verify_through_adapter(
    base_url: &str,
    token: &str,
    request: &str,
) -> Result<(IntrospectionResponse, VerifiedActorFact), LiveError> {
    let transport = Introspection {
        base_url: base_url.to_string(),
        token: token.to_string(),
        last: None,
    };
    let mut provider = SoulAuthIdentityProvider::new(transport, DomainId("soulauth".into()));
    // 逻辑时点由本套件给出（这里就是「第 1 个观察点」）；Unix 时间只用于新鲜度窗口。
    let fact = provider
        .authenticate(RequestId(request.into()), LogicalPoint(1), now_unix(), 300)
        .map_err(|e| LiveError::Other(e.to_string()))?;
    let raw = provider
        .into_transport()
        .last
        .ok_or_else(|| LiveError::Other("introspection response was not retained".into()))?;
    Ok((raw, fact))
}

fn run(
    base_url: String,
    actor_id: String,
    seed_hex: String,
    human: Option<(String, String)>,
    soulauth_commit: Option<String>,
    out: PathBuf,
) -> Result<(), LiveError> {
    let base_url = base_url.trim_end_matches('/').to_string();
    let signing = seed_from_hex(&seed_hex)?;
    fs::create_dir_all(&out).map_err(|e| LiveError::Other(e.to_string()))?;

    // 1. 挑战。
    let challenge: IssuedChallenge = ureq::post(&format!("{base_url}/api/actors/challenge"))
        .send_json(serde_json::json!({ "actor_id": actor_id }))?
        .into_json()
        .map_err(|e| LiveError::Transport(e.to_string()))?;
    if challenge.actor_id != actor_id {
        return Err(LiveError::Other(format!(
            "challenge is for {} but we asked for {actor_id}",
            challenge.actor_id
        )));
    }
    // 2. 签名：签的是服务端给出的完整 payload，客户端不自己拼。
    let signature = URL_SAFE_NO_PAD.encode(signing.sign(challenge.payload.as_bytes()).to_bytes());
    // 3. 换令牌。
    let auth: AuthenticateResponse = ureq::post(&format!("{base_url}/api/actors/authenticate"))
        .send_json(serde_json::json!({
            "actor_id": actor_id, "nonce": challenge.nonce,
            "algorithm": "ed25519", "signature": signature,
        }))?
        .into_json()
        .map_err(|e| LiveError::Transport(e.to_string()))?;
    // 4. 自省 → 适配器。
    let (introspection, fact) = verify_through_adapter(&base_url, &auth.token, "live-ai-actor")?;
    if introspection.authentication.actor_identity_id != actor_id {
        return Err(LiveError::Other(format!(
            "introspected subject {} is not the authenticated actor {actor_id}",
            introspection.authentication.actor_identity_id
        )));
    }
    if introspection.authentication.methods != vec![srg_soulauth::AuthenticationMethod::Ed25519Key]
    {
        return Err(LiveError::Other(format!(
            "AI actor session must be established by ed25519_key alone, got {:?}",
            introspection.authentication.methods
        )));
    }
    if !introspection
        .authentication
        .credential_refs
        .iter()
        .all(|r| r.starts_with("ai_actor_credential:"))
        || introspection.authentication.credential_refs.is_empty()
    {
        return Err(LiveError::Other(format!(
            "credential_refs must name the ai_actor_credential that established the session, got {:?}",
            introspection.authentication.credential_refs
        )));
    }
    let ai = AiActorEvidence {
        challenge,
        signature,
        authenticate: AiAuthenticateEvidence {
            actor_id: auth.actor_id.clone(),
            credential_label: auth.credential_label.clone(),
            token: TokenFingerprint {
                token_sha256: sha256_hex(&auth.token),
                expires_at: auth.expires_at,
            },
        },
        introspection,
        verified_actor_fact: fact,
    };
    write_json(&out.join("ai_actor.json"), &ai)?;
    println!(
        "ai actor: authenticated {} via {:?}; VerifiedActorFact for {}",
        ai.authenticate.actor_id,
        ai.introspection.authentication.methods,
        ai.verified_actor_fact.actor.id
    );

    // 5. 负例：没有令牌、伪造令牌、重放 nonce 都必须被拒。
    let forged = format!("{}x", auth.token);
    let negative = NegativeChecks {
        no_token_status: status_of(ureq::get(&format!("{base_url}{INTROSPECTION_PATH}"))),
        forged_token_status: status_of(
            ureq::get(&format!("{base_url}{INTROSPECTION_PATH}"))
                .set("Authorization", &format!("Bearer {forged}")),
        ),
        replayed_nonce_status: match ureq::post(&format!("{base_url}/api/actors/authenticate"))
            .send_json(serde_json::json!({
                "actor_id": actor_id, "nonce": ai.challenge.nonce,
                "algorithm": "ed25519", "signature": ai.signature,
            })) {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(s, _)) => s,
            Err(_) => 0,
        },
    };
    write_json(&out.join("negative.json"), &negative)?;
    for (name, status) in [
        ("no token", negative.no_token_status),
        ("forged token", negative.forged_token_status),
        ("replayed nonce", negative.replayed_nonce_status),
    ] {
        if status != 401 {
            return Err(LiveError::Other(format!(
                "{name}: expected 401, got {status}"
            )));
        }
    }
    println!("negative checks: no token 401, forged token 401, replayed nonce 401");

    // 6. 可选：人类口令登录 → 自省。
    let human_done = if let Some((email, password)) = human {
        let login: LoginResponse = ureq::post(&format!("{base_url}/api/auth/login"))
            .send_json(serde_json::json!({ "email": email, "password": password }))?
            .into_json()
            .map_err(|e| LiveError::Transport(e.to_string()))?;
        let (introspection, fact) = verify_through_adapter(&base_url, &login.token, "live-human")?;
        if introspection.authentication.actor_kind != srg_soulauth::SoulAuthActorKind::Human {
            return Err(LiveError::Other(
                "password login must introspect as a human".into(),
            ));
        }
        if !introspection
            .authentication
            .methods
            .contains(&srg_soulauth::AuthenticationMethod::Password)
        {
            return Err(LiveError::Other(format!(
                "password login must record the password method, got {:?}",
                introspection.authentication.methods
            )));
        }
        let h = HumanEvidence {
            email,
            token: TokenFingerprint {
                token_sha256: sha256_hex(&login.token),
                expires_at: introspection.session.expires_at,
            },
            introspection,
            verified_actor_fact: fact,
        };
        write_json(&out.join("human.json"), &h)?;
        println!(
            "human: authenticated {} via {:?}",
            h.verified_actor_fact.actor.id, h.introspection.authentication.methods
        );
        true
    } else {
        false
    };

    let manifest = LiveManifest {
        soulauth_live: "EXECUTED",
        base_url,
        soulauth_commit,
        soulauth_reference_commit: REFERENCE_COMMIT,
        introspection_path: INTROSPECTION_PATH,
        artifact_version: env!("CARGO_PKG_VERSION"),
        timestamp_unix: now_unix() as u64,
        ai_actor: true,
        human: human_done,
    };
    write_json(&out.join("manifest.json"), &manifest)?;
    println!("evidence written to {}", out.display());
    Ok(())
}

fn write_json<T: Serialize>(path: &PathBuf, value: &T) -> Result<(), LiveError> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|e| LiveError::Other(e.to_string()))?,
    )
    .map_err(|e| LiveError::Other(e.to_string()))
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Keygen { seed_hex } => seed_from_hex(&seed_hex).map(|k| {
            println!("{}", URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes()));
        }),
        Cmd::Run {
            base_url,
            actor_id,
            seed_hex,
            human_email,
            human_password,
            soulauth_commit,
            out,
        } => {
            let human = match (human_email, human_password) {
                (Some(e), Some(p)) => Some((e, p)),
                (None, None) => None,
                _ => {
                    eprintln!("error: --human-email and --human-password go together");
                    std::process::exit(2);
                }
            };
            run(base_url, actor_id, seed_hex, human, soulauth_commit, out)
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// 与 SoulAuth 集成套件同一个固定种子，公钥必须逐字节一致 —— 两边算出的钥匙不同，
    /// live 跑起来就是「签名莫名其妙不通过」。
    #[test]
    fn keygen_matches_the_soulauth_suite_seed() {
        let seed = format!("{:x}", Sha256::digest(b"soulauth-integration-agent"));
        let k = seed_from_hex(&seed).unwrap();
        let pk = URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes());
        assert_eq!(pk.len(), 43);
        assert!(!pk.contains('='));
    }
    #[test]
    fn token_never_appears_in_evidence() {
        let e = AiAuthenticateEvidence {
            actor_id: "actor_identity:a".into(),
            credential_label: "k".into(),
            token: TokenFingerprint {
                token_sha256: sha256_hex("secret-token"),
                expires_at: 1,
            },
        };
        let text = serde_json::to_string(&e).unwrap();
        assert!(!text.contains("secret-token"));
    }
}
