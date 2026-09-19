# SRG-ARTIFACT-CONF-01｜理论与研究实现一致性基线

目标仓库：`TrantorLabs/subject-rooted-governance`。设计代号 v1.0，软件发布号 0.1.0。性质：研究参考实现，不是生产级身份、支付或治理服务。本仓库全新编写，不包含旧 Python 实现或旧实验结果。

## 规范与证据

论文定义研究问题；本文件、CORE-01 和 EVAL-01 共同规定本次有限参考实现。实现不能通过更改判定含义让测试通过。设计批准不等于实验通过，实际构建和运行状态以 `results/validation`、`results/summary.json` 及交付 `VERIFICATION.md` 为准。

| 论文对象 | 实现位置 | 直接证据 |
|---|---|---|
| 持续主体与多角色 | srg-core / services / G1 | S01、S02、S03、S04、S05 |
| G2 事件时保存 | ProvenanceChecker | S06、S07、提交边界测试 |
| G3 实际授权依据 | AuthorityBasisChecker | S08、S09 |
| G4 完全中介 | CompleteMediationChecker | S10、S11、先允许后拒绝测试 |
| G5 状态与撤销 | GovernanceFreshnessChecker | S12、S13、在途例外测试 |
| G6 内容与次数 | EffectBindingChecker / ControlledLedger | S14、S15、幂等及 MaxUses 测试 |
| O1 历史归因 | AttributionClosureChecker | 多角色与来源查询 |
| O2 授权对应 | AuthorityCorrespondenceChecker | 独立检查组合 |
| O3 撤销安全 | RevocationSafetyChecker | 生效时点与封闭观察窗口 |
| RBH / AA | AccountabilityChecker | S16–S19 |
| OAL / P1 / P2 | srg-explorer | 有限世界观察碰撞 |
| P3 | S12 / explorer StaleState | 正确主体而执行失效 |
| P4 两个方向 | composition.rs | 原始前提、结论及有界组合报告 |

## 本次实现边界

参考契约使用一个研究域、一个内存账本、逻辑时间、明确角色基数和完整性封口证据。检查器信任的是研究收集器按契约标识的来源，不把来自任意网络的 JSON 或 `trusted=true` 当作密码学认证。来源标识是封闭实验的信任边界；把离线数据接到真实系统之前必须增加签名或可信传输校验。

TLA+ 与 Rust explorer 是对应的有限抽象，工程 harness 的对象更丰富；不宣称三者完全同构或已经完成一般性精化证明。形式模型只研究两个主体、一个请求链、最多两个效果及指定故障迁移。所有数字由当前程序产生，不能沿用旧稿的 72 个状态或 7/9。

SoulAuth crate 只实现已核对认证事实形状的边界适配与传输接口，不复制身份系统，不假设内部 AuthenticationFact 是一个公开 HTTP 端点。真实服务认证未运行时不得声称 live E2E 已完成。

## 实施纠偏

1. 安全性质的 `VIOLATED` 与负例测试的 `expectation_matched=true` 分开。
2. N/A、无法判定、证据冲突分开；证据缺失不自动等于不存在。
3. G3 评价准入实际使用的状态；G5 独立评价该状态当时是否新鲜和适用。
4. 归因失败不由隐藏 ScenarioTruth 直接决定，检查器只读声明证据。
5. G4 的执行链关联不等于 G6 的动作相等。
6. 单次批准重试返回同一物理效果；第二个效果使用不同 EffectId，才构成次数增加。
7. 保留期届满后的合法清理不自动构成 RBH；必须在保存义务内判断。
8. 程序遇到真正反例时记录具体轨迹；不把所有异常改成“超出范围”来维持结论。
