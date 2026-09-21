# Subject-Rooted Governance（主体根式治理）

**把长期 AIActor 当作持续主体来治理的可执行研究工件。**

本仓库是论文《持续主体性与责任黑洞：面向 AI 安全与治理的长期 AIActor 主体根式治理架构》（TRANTOR LABS，2026）的配套工件。论文问的是：当一个行动主体周围的一切——凭证、会话、客户端、运行环境——都在合法地变化时，什么必须继续指向*同一个主体*（角色、授权、限制、历史），做不到时会断在哪里。本工件把论文的六项结构条件（G1–G6）、三项目标性质（O1–O3）、四个命题（P1–P4）和责任黑洞判定，变成**能跑、能故意破坏、能被独立检查、能复现**的东西。

它是研究装置，不是产品：没有 IAM，没有策略语言，没有真实支付，不对 AI 对齐作任何断言。

[English](README.md)

## 工件回答什么

| 论文对象 | 落在哪里 | 怎样被检验 |
|---|---|---|
| G1 主体与角色解析 · G2 事件时来源保存 · G3 范围化授权依据 · G4 治理完全中介 · G5 治理状态新鲜度 · G6 准入—效果绑定 | `crates/srg-harness/src/checker.rs`，每个条件一个独立检查器 | 20 个场景，每个破坏一处真实结构（从不使用 `g1 = false` 这类开关） |
| O1 主体归因闭合 · O2 授权依据对应 · O3 撤销生效后执行安全 | 同一文件，三个只从证据重算的检查器 | 每个场景 × 4 种配置 |
| 责任黑洞（Closed / Unadjudicable / Confirmed-RBH / EvidenceConflict） | `AccountabilityChecker` | S16–S19，以及四种判定之间边界的单元测试 |
| P1 在线主体可区分性 · P2 历史归因可重建性 | `crates/srg-explorer`，有限世界碰撞搜索 | 弱观察出现碰撞，增强观察后碰撞消失 |
| P3 治理指向完整性 ⇏ 执行有效性 | S12（陈旧撤销）+ explorer 的 `StaleState` | G1 成立而 O3 违反 |
| P4 有界组合 | `crates/srg-harness/src/composition.rs` | P4(a) 对六个参考效果的回溯闭合；P4(b) 前瞻撤销安全，每条前提单独检查，完全中介是对参考资源的一次真实执行 |
| 形式核心模型与双世界观察模型 | `formal/*.tla` | SANY + TLC 已执行；逐故障反例矩阵与 Rust 搜索逐格对照 |
| SoulAuth 认证事实（上游身份） | `crates/srg-soulauth` + `crates/srg-live` | 对 `GET /api/auth/introspect` 的适配器，钉在一个 SoulAuth 提交；live 套件对着真正运行的 SoulAuth 完成 AIActor 认证并留证据 |

四值判定严格按论文 §3.8：**Satisfied**（所有与证据相容的执行都满足性质）、**Violated**（都违反）、**Unadjudicable**（相容执行之间结论不一致）、**EvidenceConflict**（没有任何执行与可信证据相容）。第五个标签 **N/A** 表示该性质没有适用对象——它从不被算作通过。

## 快速开始

Rust 1.82 及以上。不需要数据库、网络或外部身份服务。

```bash
cargo test --workspace --locked                 # 45 个测试：核心、检查器、场景、explorer、适配器、live 套件
cargo run --locked -p srg-harness -- run-all    # 20 场景 × 4 配置 → results/raw、traces、evidence
cargo run --locked -p srg-explorer -- all       # P1/P2 碰撞与 9 个变体的有界搜索
cargo run --locked -p srg-harness -- tables     # 从原始文件生成论文表格（从不静默重跑）
```

一条命令跑完全部，每一步的真实退出码记入 `results/validation/verification.json`：

```bash
bash scripts/reproduce.sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar bash scripts/reproduce.sh   # 另外执行 SANY/TLC
```

单项：

```bash
cargo run --locked -p srg-harness -- run S12                     # 单场景，打印其报告
cargo run --locked -p srg-harness -- run S12 --baseline B0
cargo run --locked -p srg-harness -- suite rbh                   # 四种问责判定
cargo run --locked -p srg-harness -- suite p4                    # 有界组合套件
cargo run --locked -p srg-harness -- audit results/raw/scenarios/B3/S12.json   # 重新检查归档记录
cargo run --locked -p srg-explorer -- p1                         # 或 p2 / core
```

`--out DIR` 切换输出目录。

## 钉定 commit 上的结果

完整参考配置（B3）。`SAT` / `VIOL` / `UNADJ` / `CONFLICT` 是四值判定，`RBH` 是 Confirmed-RBH。下表每一行都由 CI 从提交的源码逐字节重新生成，并与 `results/tables/scenario_matrix.csv` 比对。

| ID | 场景 | G1 | G2 | G3 | G4 | G5 | G6 | O1 | O2 | O3 | 问责 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S00 | 正常允许 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S01 | 凭证轮换 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S02 | 运行环境迁移 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S03 | 主体误认 | VIOL | SAT | SAT | SAT | SAT | VIOL | VIOL | VIOL | N/A | UNADJ |
| S04 | 多角色闭合 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S05 | 必需角色缺失 | VIOL | N/A | N/A | N/A | SAT | N/A | N/A | N/A | N/A | N/A |
| S06 | 越过提交边界才保存来源 | SAT | VIOL | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S07 | 历史重新绑定 | SAT | SAT | SAT | SAT | SAT | SAT | VIOL | SAT | N/A | UNADJ |
| S08 | 实际授权依据不匹配 | SAT | SAT | VIOL | SAT | SAT | SAT | SAT | VIOL | N/A | CLOSED |
| S09 | 独立授权撤销 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S10 | 治理旁路 | SAT | SAT | N/A | VIOL | N/A | N/A | SAT | VIOL | N/A | CLOSED |
| S11 | 拒绝后仍执行 | SAT | SAT | N/A | VIOL | SAT | N/A | SAT | VIOL | VIOL | CLOSED |
| S12 | 陈旧撤销状态 | SAT | SAT | SAT | SAT | VIOL | SAT | SAT | VIOL | VIOL | CLOSED |
| S13 | 合法重新授权 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S14 | 实际效果替换 | SAT | SAT | SAT | SAT | SAT | VIOL | SAT | VIOL | N/A | CLOSED |
| S15 | 单次准入重复消费 | SAT | SAT | SAT | SAT | SAT | VIOL | SAT | VIOL | N/A | CLOSED |
| S16 | 问责闭合 | SAT | SAT | SAT | SAT | SAT | SAT | SAT | SAT | N/A | CLOSED |
| S17 | 问责无法判定 | UNADJ | UNADJ | SAT | SAT | SAT | SAT | UNADJ | UNADJ | UNADJ | UNADJ |
| S18 | 已确认责任黑洞 | UNADJ | VIOL | SAT | SAT | SAT | SAT | UNADJ | UNADJ | UNADJ | RBH |
| S19 | 可信证据冲突 | CONFLICT | CONFLICT | CONFLICT | CONFLICT | CONFLICT | CONFLICT | CONFLICT | CONFLICT | CONFLICT | CONFLICT |

几行值得多看一眼：

- **S06 与 S18 是两种不同的失败。** 来源记录越过提交边界才持久化，破坏了 G2，但历史仍可恢复，问责照样闭合；唯一的事件时关系永久丢失、契约声明的全部恢复路径都被确认不可恢复，才是黑洞。G2 失败不自动等于 RBH。
- **S11 违反 G4 和 O3，问责却仍是 Closed。** 资源端在明确的 Deny 之后照样执行了；系统仍然完整记下了是谁干的。执行失效，归因没失效——这正是论文说的二者独立。
- **S12 是 P3 的见证。** 主体与撤销都正确指向 A（G1 成立），网关用了陈旧快照（G5 违反），效果发生了（O3 违反）。
- **S15 在动作内容完全相同的情况下违反 G6**：一次单次准入，两个独立的账本效果。只做内容绑定会放过它。
- **S16 通过更正而闭合**：第一条来源记录写错了主体，之后追加一条更正记录指回原记录，原记录保留。把原记录删掉，同一条更正就分不清是「追加更正」还是「静默覆盖」，检查器转为 Unadjudicable（`correction_closes_only_when_the_original_is_retained`）。
- **负例场景检出了自己的故障，既是测试通过，也是性质违反。** `expectation_matched` 与判定从不合并成一个 PASS。

配置：**B0** 把主体根落在凭证上（每个场景 G1 都失败，一次合法的多角色行动还被错误拒绝），**B1** 有稳定主体但不提交来源、治理状态陈旧，**B3** 是完整参考配置，**B2** 是换了标签的 B3——检查器一致性控制组，不是竞争对手。全部 80 行见 `results/tables/baseline_matrix.csv`。

有界搜索（`results/raw/explorer/core.json`）：未变异模型可达 9 个状态、无反例；8 个变异各可达 9–11 个状态，各自违反的性质列在 `results/formal/tlc_matrix.json`——TLC 与 Rust 搜索逐格一致（`tlc_matrix_agrees_with_bfs`）。P1 在弱观察下有 16 处碰撞，观察到可信主体后为 0；P2 为 8 处，观察到事件时绑定后为 0。

## 读证据

```text
results/
├── raw/scenarios/<配置>/<场景>.json     证据 + 轨迹 + 报告 + 预期 + 真值
├── evidence/<配置>/<场景>.json          单独的 EvidenceSet——检查器拿到的全部输入
├── traces/<配置>/<场景>.json            每个判定背后的事件链
├── raw/explorer/{core,p1,p2}.json      有界搜索与碰撞见证
├── raw/p4/                             组合实例与报告
├── tables/                             scenario_matrix、baseline_matrix、g_ablation_matrix、rbh_matrix、p4_matrix
├── formal/{status,tlc_matrix}.json     最近一次 SANY/TLC 执行
├── live/soulauth/                      最近一次 live SoulAuth 执行（天然不确定）
├── manifests/run_manifest.json         源码指纹、证据来源提交、Cargo.lock 哈希、工具链、契约与注册表标识
└── summary.json
```

检查器只收 `EvidenceSet + ResearchContract + QueryContext`。场景编号、注入的故障、预期结果和真值为了可审计而放在同一个原始文件里，但 `verdict_does_not_read_expected_or_truth` 把它们全部改写后断言报告不变；`srg-harness -- audit` 只从证据重新推导归档报告。

来源标识是信任契约，不是认证：`source` 不是契约为该渠道声明的来源的信封会被忽略（`unknown_source_cannot_claim_trust`）。缺席不是不存在的证明：只有当声明的收集器的 `ObservationSeal` 覆盖该渠道直到查询点，检查器才会得出「没有这样的准入」「没有这样的效果」。

## 形式模型

`formal/P2_Core.tla` 是单链治理核心（两个主体、一个请求、至多两个效果、八种故障变异）；`formal/P2_Observability.tla` 是 P1/P2 背后的双世界模型。`scripts/check-formal.sh` 用官方工具执行二者：SANY 解析两个模型，TLC 检查参考配置（全部不变式成立，9 个状态）、观察模型（两个见证存在、两个增强观察可分辨），以及每一个 `(故障, 性质)` 组合——`results/formal/tlc_matrix.json` 就是这样产生的。CI 下载钉定版本的 `tla2tools.jar`（v1.8.0，校验 SHA-256），重跑全部，提交的矩阵有差异就红。

Rust explorer 是同一状态空间上的确定性 BFS，不替代 TLA+；`docs/FORMAL_RUST_MAPPING.md` 把变量、迁移、性质一一对应。TLC 在这个模型上通过是有界证据，不是一般证明。

## 声称什么，不声称什么

声称，且可以从本仓库核对：

- G1–G6 各有可执行结构与至少一个独立故障见证；G4 覆盖旁路与拒绝后执行；G6 覆盖内容替换与准入重放。
- O1–O3 由从不读取故障、预期或真值的检查器重算。
- 四种问责判定各由一个不同场景复现，判定之间的边界（保留期届满、暂不可达、备用恢复路径、更正目标缺失）有单元测试。
- P1–P3 反例可由机器重现；P4(a)、P4(b) 在声明的参考契约内获得有界可执行支持。
- 核心证据是确定性的：同一 commit、同一 `Cargo.lock`、同样的字节（CI 把提交的结果与新跑一遍的结果做 diff）。

不声称：

- P4 的一般证明，或 G1–G6 在声明的有界模型之外的必要性 / 充分性。
- 任何生产、并发或分区容错验证；任何真实资金。
- 核心结果依赖 SoulAuth。不依赖：每一次核心运行都用确定性身份提供者（运行清单里 `identity_provider: deterministic`）。下面的 live 套件是关于上游边界的另一份证据，不是 P1–P4 的前提。
- 任何关于 AI 意识、意图或法律责任的结论。

场景是定向见证，不是流量样本；`results/` 里没有任何数字是安全概率。

## Live SoulAuth 集成

`crates/srg-live` 对着一个**真正运行**的 SoulAuth 端到端走完 AIActor 认证，再把结果交给适配器：

```text
POST /api/actors/challenge  →  用主体的 Ed25519 私钥签服务端给出的 payload
POST /api/actors/authenticate  →  会话令牌
GET  /api/auth/introspect（Bearer）  →  该令牌背后的认证事实
srg-soulauth::SoulAuthIdentityProvider  →  VerifiedActorFact
```

它同时检查事实端点拒绝无令牌、伪造令牌与重放的 nonce（都是 401），并可选地对一个人类口令会话做自省。证据落在 `results/live/soulauth/`：挑战、签名、自省响应、`VerifiedActorFact`、负例结果，以及记录服务由哪个 SoulAuth 提交构建的清单。令牌只留 SHA-256 指纹。

```bash
SOULAUTH_SRC=/path/to/SoulAuth bash scripts/live-soulauth.sh
```

脚本从那个检出启动 SurrealDB 与 SoulAuth，注册一个操作员和一个 AIActor（私钥从不离开脚本），运行 `srg-live`，然后收拾干净。适配器按 `srg_soulauth::REFERENCE_COMMIT`——引入 `/api/auth/introspect` 的 SoulAuth v0.4.0（`82ff8ae`）——编写；提交进仓库的证据就是对着同一个提交产生的。live 套件不在确定性核心之内：每次运行的 nonce、id、时间戳都不同，所以 CI 重新执行它但不做 diff。

适配器只做一件事：把认证事实变成 `VerifiedActorFact`。它不读任何授权，也不产生任何治理决定——身份不是授权。

## 仓库布局

```text
crates/srg-core        类型、参考契约、证据信封、四值归约——不做 I/O
crates/srg-harness     受控账本（SUT）、10 个检查器、20 场景 × 4 配置、表格、组合
crates/srg-explorer    有限世界、观察碰撞、带 8 种变异的有界 BFS
crates/srg-soulauth    SoulAuth 认证事实适配器（/api/auth/introspect），置于传输 trait 之后
crates/srg-live        live 套件：挑战 → Ed25519 签名 → 令牌 → 自省 → VerifiedActorFact
formal/                P2_Core.tla、P2_Observability.tla、逐故障 TLC 配置
scripts/               reproduce.sh、check-formal.sh、live-soulauth.sh
docs/                  三份冻结设计基线（CONF-01、CORE-01、EVAL-01）、形式↔Rust 映射、
                       复现说明，以及 ARTIFACT_DELTA.md——工件与论文正文仍有差别的每一处，分类记录
results/               上述已提交的证据
```

`docs/` 里的设计基线把这一代工件称为「v1.0」；软件发布号是 **0.1.1**。0.1.x 满足的就是那些基线的发布门槛。

## 复现与引用

请把 tag、commit 和归档校验值一起钉住；`main` 会往前走。运行清单记录了源码指纹（除 `results/` 外的全部受控文件）、`Cargo.lock` 哈希和工具链，因此任何一个结果文件都能对回产生它的那份源码。

```text
Subject-Rooted Governance v0.1.1, TRANTOR LABS, 2026.
https://github.com/TrantorLabs/subject-rooted-governance
```

[CITATION.cff](CITATION.cff) 以机器可读形式承载同样的元数据，供 GitHub 的 *Cite this repository* 使用。发布归档存入学术存档后补 DOI。

## 许可

Apache-2.0。见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。
