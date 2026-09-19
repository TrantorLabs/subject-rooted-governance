#!/usr/bin/env bash
# 一条命令重新生成全部证据：测试 → 20 场景 × 4 配置 → 有限世界搜索 → 论文表格 →
# （有 TLA+ 工具时）SANY/TLC。每一步的退出码都落到 results/validation/verification.json，
# 不存在「设计上应该通过」这种状态：文件里写的就是这台机器上真实发生的事。
#
#   bash scripts/reproduce.sh                       # 核心证据
#   TLA2TOOLS_JAR=… bash scripts/reproduce.sh       # 再加形式模型执行
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
mkdir -p results/validation
steps=""
failed=0
step() {   # $1=name  $2…=command
    local name="$1"; shift
    local start rc ms secs
    start="$(date +%s%N)"
    "$@" > "results/validation/$name.log" 2>&1; rc=$?
    ms=$(( ($(date +%s%N) - start) / 1000000 ))
    secs="$((ms / 1000)).$(printf '%03d' $((ms % 1000)))"
    [ "$rc" = 0 ] && status=PASSED || { status=FAILED; failed=1; }
    printf '  %-12s %s (rc=%s, %ss)\n' "$name" "$status" "$rc" "$secs"
    steps="$steps$(printf '    {"name": "%s", "status": "%s", "exit_code": %s, "seconds": %s},' "$name" "$status" "$rc" "$secs")"$'\n'
}
echo "reproducing subject-rooted-governance evidence"
step format     cargo fmt --all -- --check
step test       cargo test --workspace --locked
step clippy     cargo clippy --workspace --all-targets --locked -- -D warnings
step scenarios  cargo run --locked -p srg-harness -- run-all
step explorer   cargo run --locked -p srg-explorer -- all
step tables     cargo run --locked -p srg-harness -- tables
if [ -n "${TLA2TOOLS_JAR:-}" ]; then
    step formal scripts/check-formal.sh
else
    formal_note='"formal": "NOT_RUN_IN_THIS_INVOCATION (TLA2TOOLS_JAR unset); results/formal/ holds the last committed execution"'
fi
rustc_version="$(rustc --version 2>/dev/null || echo unknown)"
cat > results/validation/verification.json <<JSON
{
  "artifact_version": "$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')",
  "rustc": "$rustc_version",
  "generated_at_unix": $(date +%s),
  "steps": [
$(printf '%s' "$steps" | sed '$ s/,$//')
  ],
  ${formal_note:-\"formal\": \"executed in this invocation; see results/formal/status.json\"},
  "all_passed": $([ $failed = 0 ] && echo true || echo false),
  "soulauth_live": "NOT_RUN"
}
JSON
echo "verification record: results/validation/verification.json"
exit $failed
