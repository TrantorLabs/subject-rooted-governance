# 复现与审计

1. `cargo test --workspace --locked`。
2. `bash scripts/reproduce.sh`：格式、测试、clippy、20 场景 × 4 配置、有限世界搜索、论文表格；
   每一步的退出码写进 `results/validation/verification.json`。设置 `TLA2TOOLS_JAR` 时再执行 SANY/TLC。
3. 原始证据在 `results/raw/scenarios/<配置>/<场景>.json`；`srg-harness -- audit <文件>` 只从其中的
   `evidence`、`contract`、`query` 重新计算判定并与归档的 `reports` 比较——`fault`、`expected`、`truth`
   都不参与。
4. `results/tables/` 由原始文件机械生成；`tables` 子命令没有原始结果时报错，不会静默重跑实验。
5. 核心证据是确定性的：同一 commit、同一 `Cargo.lock`，`results/raw`、`traces`、`evidence`、`tables`、
   `summary.json` 逐字节相同。CI 用 `git diff --exit-code` 守这一条。`manifests/run_manifest.json` 带
   时间戳与工具链版本，允许不同；`results/validation/` 与 `results/formal/*.log` 不入库。
6. 源码指纹（`run_manifest.json.source_sha256`）覆盖除 `results/`、`target/`、`.git/` 外的全部文件，
   结果文件不参与自己的指纹，避免循环。
7. 形式层：`TLA2TOOLS_JAR=/path/to/tla2tools.jar bash scripts/check-formal.sh`。CI 使用 tla2tools
   v1.8.0，SHA-256 `9d36716ffb5e49d1ba8fae4651eba59f3189887e12eb90e204a42d2e6e993fef`。负例配置的
   TLC 退出码 12（安全性质反例）是预期结果；其他非零退出码是工具或模型错误，脚本会终止而不是把它
   记成任何一种结论。

## 范围

参考信任模型是封闭研究收集器：来源标识是契约声明，不是抵御任意离线 JSON 伪造的证书系统。
Unix 认证时间与实验逻辑时间不混用。研究账本不能用于真实资金；适配器不等于已部署的 SoulAuth 服务。

发布时固定 tag、commit、源码归档 SHA-256 与 `Cargo.lock`。
