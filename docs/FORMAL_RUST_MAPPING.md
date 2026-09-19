# 形式模型与工程实现映射

## `P2_Core.tla` ↔ `srg-explorer::search`

| TLA+ 变量 / 迁移 | Rust explorer（`State` / `successors`） | 工程装置里的对应证据 |
|---|---|---|
| `stage` | `State.stage` 0..4 | 请求 → 准入 → 效果的逻辑顺序 |
| `revoked` / `Start` | `State.revoked`；"keep initial authority" / "subject-scoped revocation takes effect" | `AuthoritySnapshot.revocations` |
| `cached` / `Submit` | `State.cached_revoked`；"submit and resolve request" | `AdmissionDecision.observed_version` 与适用快照的差 |
| `resolved` | `State.resolved` | 请求主体与可信 `VerifiedActorFact` 的比较 |
| `allow` / `Admit` | `State.allow`；"final admission decision" | 最终 `Allow` / `Deny` |
| `effects` / `Execute` / `Replay` | `State.effects` 0..2；"resource executes and commits provenance" / "replay consumed admission" | 独立 `EffectId`、账本状态变化 |
| `saved` | `State.saved` | 事件时主体、角色、授权上下文的提交记录 |
| `op` | `State.actual_op` | 实际 `ActionDescriptor` |
| `afterRevoke` | `State.admitted_after_revoke` | 撤销生效后才进入最终准入 |
| `Bypass` | "bypass produces effect" 迁移 | 没有最终准入却有真实效果（S10） |
| `CONSTANT Fault` | `Mutation` | 场景里的真实结构破坏（S03、S06、S08、S10–S12、S14、S15） |
| `O1` / `O2` / `O3` | `properties()` 的 `O1_bounded` / `O2_bounded` / `O3_bounded` | 证据驱动的四值检查器 |

状态变量、初始值与迁移一一对应；`Fault` 的九个取值与 `Mutation` 的九个变体一一对应。

## 一致性是被执行的，不是被声明的

`scripts/check-formal.sh` 对每个 `(Fault, Oi)` 组合单独运行一次 TLC（TLC 遇到第一个反例即停，
所以不能一次跑三条性质来判断「违反了哪几条」），把结果写成 `results/formal/tlc_matrix.json`。
`srg-explorer` 的测试 `tlc_matrix_agrees_with_bfs` 把这张表与 BFS 的反例集合逐格比对；任一侧改动
而另一侧未跟上，测试即失败。CI 另外要求提交的矩阵与本次 TLC 执行一致。

首次执行 TLC 就抓到了一个模型缺陷（`docs/ARTIFACT_DELTA.md` D-04）：`Execute` 里一处运算优先级
错误使 `ProvenanceLoss` 配置下整条迁移不可用。这就是「TLC NOT_RUN 不等于通过」的意思。

## `P2_Observability.tla` ↔ `srg-explorer::collisions`

| TLA+ | Rust |
|---|---|
| `Worlds == [actor, prior, current]` | `worlds()`：8 个 `World` |
| `WeakOnline` / `StrongOnline`、`Decision` | `collisions(historical = false, strong)` 的观察函数与目标函数 |
| `WeakHistory` / `StrongHistory` | `collisions(historical = true, strong)` |
| `OnlineWitness`、`HistoryWitness`（弱观察存在碰撞） | 弱观察碰撞数 > 0（P1：16，P2：8） |
| `OnlineResolved`、`HistoryResolved`（增强观察无碰撞） | 增强观察碰撞数 = 0 |

## 范围

核心 TLA+ 只检验安全性质，没有活性证明；合法行为进展由工程正向场景与 `eligible_progress` 检查。
工程 harness 的对象更丰富（身份域、多角色、多条授权、证据缺失与封口），其场景数不能与 TLC 状态数
直接比较。TLC 反例说明该故障配置下存在违反，不表示运行程序发生了异常。
