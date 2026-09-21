# ARTIFACT_DELTA｜工件与论文正文（V2.7）之间的差额

`SRG-ARTIFACT-CONF-01` §46 规定：工件开发期间不改论文正文；发现的差额记在这里，按类别裁决。
只有 **Theory Ambiguity** 与 **Theory Bug** 才允许重新打开正文；其余由工件侧关闭，并在 v1.0 完成后
一次性回填论文第 7、8 章与 Artifact Availability。

类别：Implementation Bug ／ Artifact Gap ／ Evidence Gap ／ Theory Ambiguity ／ Theory Bug。
状态：CLOSED（工件已处理）／ OPEN（需正文裁决或回填）。

论文引用位置以 V2.7 章节号为准。

---

## D-01｜论文第 7、8 章描述的是旧 Python 原型，不是本工件

- **类别：** Evidence Gap（回填项）
- **正文：** §7.4.1「`shadow_model.py`」、§7.7「阶段记录」、§8.2.2「九类场景」、§8.4「72 个可达状态 … 174 / 72 / 92 / 122 / 104 / 90」、§8.5「0.778（7/9）… 1.000（9/9）」、§8.2.3「`authority_correspondence` … 原型授权关联检查」。
- **工件：** Rust 重写。20 个场景 × 4 配置；有限模型未变异 9 个状态，8 个故障变异各 9–11 个状态（`results/raw/explorer/core.json`）；不再有「安全率」。G1–G6 的删除见证不再用 `ENFORCE_G*` 开关（§7.2.3），而是破坏真实结构（CONF-01 §29、D08）。
- **状态：** OPEN — 回填第 7、8 章。可直接取用的数字与表：`results/tables/*.csv`、`results/raw/explorer/core.json`、`results/formal/tlc_matrix.json`、`results/raw/p4/report.json`。旧数字（72 状态、7/9 等）不得沿用（CONF-01 §39、EVAL-01 §33）。

## D-02｜正文写「尚未」的六项，工件已完成

- **类别：** Evidence Gap（回填项）
- **正文与工件对照：**

| 正文（V2.7） | 位置 | 工件状态 |
|---|---|---|
| 「当前核心模型 … 尚未完整表达一次准入被重复消费」 | §7.2.2、§6.7 末、§8.2.2、§8.6 | 已完成：`ConsumptionPolicy`、`ControlledLedger` 的幂等键与消费计数、S15 `Admission Replay`（G6 = Violated）、explorer/TLA+ 的 `Replay` 变异、测试 `normal_ledger_retry_is_idempotent` / `max_uses_consumption` |
| 「尚未将『明确 Deny 后资源仍产生 Effect』作为独立见证报告」 | §7.5 | 已完成：S11 `Denied But Executed`（G4 = Violated）、`DenyThenEffect` 变异、测试 `deny_effect_is_not_evidence_conflict` |
| 「授权上下文与责任黑洞判定尚未全部进入检查器」 | §7.5、§8.6 | 已完成：`AuthorityContext` 进入 `ProvenanceRecord`；`AccountabilityChecker` 四判定，S16–S19 各一 |
| 「核心 TLA+ 模型尚未展开完整多角色关系」 | §7.5 | 部分完成：多角色在工程装置（S04、`RoleRequirement` 基数、O1 多角色闭合）；TLA+ 核心仍是单主体模型。见 D-07 |
| 「官方 SANY/TLC 执行 … 尚未完成」 | §7.7、§8.4「而非官方 TLC 执行」 | 已完成：`scripts/check-formal.sh`，`results/formal/status.json`（tla2tools v1.8.0，SHA-256 已钉）。TLC 与 Rust BFS 的故障矩阵逐格一致（测试 `tlc_matrix_agrees_with_bfs`） |
| 「B2 与 B3 … 结构等价／检查器一致性控制组」 | §8.2.1 | 已完成并有测试守着：`equivalent_label_control` 断言 B2、B3 的证据与报告逐字节相同 |

- **状态：** OPEN — 回填时删除对应的「尚未」「后续需要」（CONF-01 §46 只允许删除真正完成的部分；D-07 那一条不能删）。

## D-03｜SoulAuth 集成的法位

- **类别：** Evidence Gap
- **正文：** §7.6「采用后续公开的 SoulAuth v0.3.0 … 尚未启动真实 SoulAuth 服务完成端到端认证」。
- **工件：** SoulAuth v0.3.0 的公开契约没有任何端点返回认证事实（它只在服务内部与 `login_success`
  审计 `details` 里）。SoulAuth 侧因此新增 `GET /api/auth/introspect`（会话行同时开始保存完整的
  `methods` / `credential_refs`），本工件新增 `srg-live`：对着真正运行的 SoulAuth 完成
  挑战 → Ed25519 签名 → 令牌 → 自省 → `VerifiedActorFact`，并检查无令牌 / 伪造令牌 / 重放 nonce
  都被拒。证据在 `results/live/soulauth/`；`srg_soulauth::REFERENCE_COMMIT` 钉住引入该端点的
  SoulAuth v0.4.0（`82ff8ae`），live 清单记录服务实际构建自哪个提交。
- **R21–R23：** R21 固定 SoulAuth 提交 ✓；R22 真正运行 SoulAuth 认证 ✓（AIActor 与人类口令两条）；
  R23 保存原始证据 ✓。正文回填时 §7.6 可改为「已对钉定的 SoulAuth 提交完成 live 集成」，
  并写明该端点自 SoulAuth 0.4.0 起可用。
- **状态：** CLOSED（回填正文时把「尚未」删去）。

## D-04｜形式模型的一个真实缺陷：`ProvenanceLoss` 使 `Execute` 不可用

- **类别：** Implementation Bug（形式层）
- **发现：** 首次用 TLC 执行 `P2_Core.tla` 时，`Fault = "ProvenanceLoss"` 配置只有 7 个状态、深度 4，从未到达 `stage = 4`，因此 O1 从未被违反——与 Rust BFS（O1 违反）不一致。原因是 `Execute` 中
  `saved' = (allow \/ Fault = "DenyThenEffect") /\ Fault # "ProvenanceLoss"` 的运算优先级：`=` 先于 `/\`，最后一个合取项在该故障下恒为 FALSE，整条迁移被禁用。
- **处理：** 加括号：`saved' = ((allow \/ …) /\ Fault # "ProvenanceLoss")`。修正后 ProvenanceLoss 违反 O1 且只违反 O1，与 BFS 一致。此后每个 `(故障, 性质)` 组合都由 TLC 单独执行并与 BFS 比对。
- **状态：** CLOSED。这也是「TLC 未执行时不得报告通过」这条规则的一个实证。

## D-05｜S06 与 S18、S16 与 S00 曾是同一份证据

- **类别：** Artifact Gap
- **发现：** 初版源码里 S06「提交边界后来源丢失」与 S18「已确认责任黑洞」构造完全相同（身份、归因、来源全部清空 + 永久丢失观察），S16「问责闭合」与 S00「正常允许」也完全相同。两个编号一份证据，等于少了两个见证。
- **处理：**
  - S06 改为 **越过提交边界才保存**：来源记录完整，但 `committed_at` 在 `effect.at + commitment_window` 之后。结果 G2 = Violated、O1 = Satisfied、问责 = Closed——直接见证正文 §4.5「保存失败不等于责任黑洞」与 §6.3「越界未保存 … 构成保存失败」。
  - S16 改为 **通过更正闭合**：第一条来源记录主体写错，第二条记录 `corrects` 指回第一条，原记录保留（§5.3「原始记录、更正来源和更正时间必须保留」）。检查器新增规则：更正记录所指的原记录不在可信集合中时，O1 与问责均为 Unadjudicable（分不清「追加更正」与「静默覆盖」）。
  - 新增测试 `every_scenario_has_distinct_evidence`：20 个场景两两证据不同。
- **状态：** CLOSED。场景注册表编号与 EVAL-01 §18 不变，S06 的名称改为「Provenance Committed After Boundary」。

## D-06｜SUT 的来源记录与可信身份事实矛盾时，问责判定是什么

- **类别：** Theory Ambiguity
- **情形：** S03（主体误认）与 S07（历史重新绑定）：来源记录完整地写着 B，可信身份事实与资源观察者写着 A。
- **工件当前裁决：** O1 = Violated（历史与独立可信事实不符）；问责 = **Unadjudicable**，不是 Closed，也不是 EvidenceConflict。理由：来源记录是被评价的对象（§6.1「不能由被测系统自己的日志单独决定自己是否正确」），不是与身份根同级的可信事实，因此不构成 $\mathcal K_{\mathcal C}(E)=\varnothing$；但检查器也不替 SUT 合成一条它从未提交的闭合关系，所以不是 Closed。
- **需要正文裁决的点：** §6.9 的 Closed 定义（「现有可信证据足以恢复 …」）在字面上可以读成「只要独立可信证据能恢复主体就 Closed」。若采此读法，S03/S07 应为 Closed，且 RBH 定义 §4.5 中的「漂移」一词需要说明它指的是不可恢复的漂移。建议正文明确：问责闭合要求 **系统提交的历史关系** 与可信事实一致地闭合，独立证据能重建真相属于「可更正」而非「已闭合」。
- **状态：** OPEN — 正文一句话即可关闭；工件行为不需要改。

## D-07｜TLA+ 核心模型仍是单主体、单请求、至多两个效果

- **类别：** Artifact Gap（已声明的有界范围）
- **说明：** `P2_Core.tla` 与 explorer 表达的是 §7.2.1 的最小实例；多角色、多授权、证据缺失只在工程装置中。CONF-01 §33 与 EVAL-01 §34 允许这一分工，但正文 §7.5 关于「尚未展开完整多角色关系」的句子对形式层仍然成立，回填时**不能**删。
- **状态：** OPEN（范围声明，不是缺陷）。

## D-08｜G4 与 G6 对「准入主体 ≠ 实际执行主体」的分工

- **类别：** Theory Ambiguity（轻）
- **情形：** S03 中 G6 也报 Violated：资源观察者记录的实际执行主体（A）与准入主体（B）不同。
- **工件裁决：** G6 的 $F(m)\equiv F(e)$ 中 $s(x)$ 是主体分量（§6.7 式 6.4），所以主体不一致属于 G6。G4 只管「有没有先行正向最终准入」。
- **状态：** CLOSED（与正文一致；记录在此是因为审阅者会问为什么 S03 同时亮 G1 和 G6）。

## D-09｜版本号

- **类别：** Artifact Gap（命名）
- **说明：** 三份设计基线把这一代工件叫「v1.0」并写「目标版本 v1.0.0」；软件首个公开发布号定为 **0.1.0**。基线文件保留原文，README 说明二者关系。
- **状态：** CLOSED。

---

## 回填清单（v0.1.0 发布后，论文一次性完成）

第 7 章：仓库 `TrantorLabs/subject-rooted-governance`、五个 crate 的分工、TLA+ 已执行（tla2tools v1.8.0）、SoulAuth live 集成（`/api/auth/introspect`，钉定提交）、release pin（tag / commit / 归档 SHA-256 / DOI）。

第 8 章：表 5 用 `results/tables/baseline_matrix.csv`；表 6 用 `results/formal/tlc_matrix.json` + `results/raw/explorer/core.json`（状态数 9 / 9–11，不再是 72 / 174…）；表 7 用 `results/tables/scenario_matrix.csv`（B3 那 20 行即 README 中的矩阵）；RBH 四判定用 `rbh_matrix.csv`；G6 消费用 S15；P4 用 `p4_matrix.csv`。删除 §8.2.3 与 §8.5 的 0.778 / 1.000 叙述。

Artifact Availability：repository、release、commit、SHA256、DOI。
