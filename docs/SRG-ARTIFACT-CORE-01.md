# SRG-ARTIFACT-CORE-01｜Rust 核心语义与不变量

## 工作区

`srg-core` 定义强类型引用、领域对象、参考契约、证据封装及四值语义；`srg-harness` 实现被测路径、独立检查器、定向场景和输出；`srg-explorer` 独立枚举有限世界和状态；`srg-soulauth` 适配经可信传输取得的上游身份事实。核心模块不依赖其他三个 crate。

## 对象边界

ActorRef 由 DomainId、ActorId 和 ActorKind 构成。CredentialId、SessionId、RuntimeId、RequestId、AdmissionId、EffectId、BasisId 使用不可互换的新类型。角色映射使用有序集合，重复同一个主体不被误计成两个授权者。请求、最终准入和实际效果分别保存。

AuthoritySnapshot 保存历史版本及撤销、重新授权；AdmissionDecision 记录 actual_basis 和 observed_version。撤销目标区分主体、单项授权、委托和凭证，主体目标包含身份域。独立授权仍有效时，单项撤销不扩大为永久全局禁令。

ActionDescriptor 表示资源、操作、收款对象和整数金额。身份与角色保留在独立事实中；执行链由 GovernanceLink 关联。效果来自内存账本已经完成的实际状态变化，不从允许记录直接复制一个“成功结果”。

## 正常执行与故障表示

正常 ControlledLedger 拒绝 Deny、内容不匹配和超量消费，使用 `&mut self` 将消费检查与状态变更放在同一临界调用中，整数运算使用 checked_add/checked_sub。同一准入和幂等键重复提交返回同一个 EffectId，不产生第二笔转账。

故障注入接口可以执行未准入、被拒绝、被替换或被重复消费的命令。观察类型允许表示这些违规事实，否则独立检查器将永远看不到需要检验的反例。正常执行不变量不应被误当作禁止构造负例的序列化限制。

## 证据边界

Envelope 携带 EvidenceId 和来源标识。ResearchContract 显式列出各类事实的认可来源。ObservationSeal 表明特定渠道在有限逻辑区间中的记录完整性；没有封口，检查器不得把“没看到”变成“不存在”。

ProvenanceRecord 保存事件时主体、角色、授权上下文和提交时点。允许缺字段，以表达真实的保存失败。EvidenceStateFact 记录契约声明恢复路径的暂不可达或永久丢失。ScenarioTruth 只用于最终实验评价，检查器接口不接收该类型。

## 判定

PropertyVerdict：Satisfied / Violated / Unadjudicable / EvidenceConflict。AccountabilityVerdict：Closed / Unadjudicable / ConfirmedRbh / EvidenceConflict。CheckOutcome 另包 NotApplicable，不把无适用对象算成确定通过。

有限相容世界归约保留论文的四种结果。工程检查器采用针对参考契约的保守证据规则；它不是通用无限世界求解器。只有完整性或永久丢失证据足够时，才报告涉及不存在或不可恢复的确定判断。

## 核心约束

主体不等于外围凭证；认证不产生授权；G4 不吞并 G6；授权必须是本次实际依据；查询不能用当前绑定覆盖过去；重复回执不等于重复效果；安全失败不等于可信事实冲突；检查器不读取故障、场景预期和隐藏真值。

## SoulAuth 的必要修正

公开的 AuthenticationFact 允许人类外部认证没有本地 credential_refs，并允许多个认证方法。因此本实现使用凭证列表而非强制单一凭证。authenticated_at 的 Unix 时间与实验 LogicalPoint 分离；角色、业务权限和运行实例不从认证事实中伪造。
