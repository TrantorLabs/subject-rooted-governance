# formal/

| 文件 | 内容 |
|---|---|
| `P2_Core.tla` | 单链治理核心：两个主体、一个请求、至多两个效果、八种故障变异（`CONSTANT Fault`）；不变式 `TypeOK`、`O1`、`O2`、`O3` |
| `P2_Core.cfg` | 参考配置 `Fault = "None"`：四条不变式都必须成立 |
| `P2_Core_<Fault>.cfg` | 八个故障配置，各带全部不变式，供人工用 TLC 查看反例轨迹 |
| `P2_Observability.tla` / `.cfg` | P1/P2 的双世界模型：弱观察存在碰撞（`OnlineWitness`、`HistoryWitness`），增强观察后可分辨（`OnlineResolved`、`HistoryResolved`） |

执行：`TLA2TOOLS_JAR=/path/to/tla2tools.jar ../scripts/check-formal.sh`。脚本对每个
`(Fault, Oi)` 组合单独跑 TLC（临时生成 `P2_Core_<Fault>_<Oi>.cfg`，跑完即删），产物在
`../results/formal/`。与 Rust 搜索的对应关系见 `../docs/FORMAL_RUST_MAPPING.md`。

手工看一条反例轨迹，例如陈旧撤销状态（P3）：

```bash
java -cp tla2tools.jar tlc2.TLC -workers 1 -config P2_Core_StaleState.cfg P2_Core.tla
```
