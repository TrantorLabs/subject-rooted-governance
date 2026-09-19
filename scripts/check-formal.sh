#!/usr/bin/env bash
# 用官方 SANY / TLC 执行 formal/ 下的两个模型，并把结果落成机器可读文件。
#
#   TLA2TOOLS_JAR=/path/to/tla2tools.jar scripts/check-formal.sh
#
# 产物（都在 results/formal/）：
#   status.json        工具版本、jar 的 SHA-256、执行状态
#   tlc_matrix.json    每个故障配置 × {O1,O2,O3}：TLC 是否找到反例
#   *.log              每次 SANY / TLC 调用的完整输出
#
# TLC 遇到第一个被违反的不变式就停，所以「某个故障违反了哪几条性质」要按
# 性质逐条跑：每个 (Fault, Oi) 一次调用，退出码 12 = 找到安全性质反例，0 = 无反例。
# 其他退出码是工具或模型错误，不能被解释成任何一种结论。
set -euo pipefail
cd "$(dirname "$0")/.."
: "${TLA2TOOLS_JAR:?set TLA2TOOLS_JAR to a tla2tools.jar whose origin and SHA-256 you have checked}"
command -v java >/dev/null || { echo "java not found in PATH" >&2; exit 2; }
jar="$(realpath "$TLA2TOOLS_JAR")"
out="$(pwd)/results/formal"
mkdir -p "$out"
rm -f "$out"/*.log
JAVA_OPTS="-XX:+UseSerialGC -Xmx512m"
tlc() {   # $1=cfg $2=module $3=log → prints exit code
    local rc=0
    (cd formal && java $JAVA_OPTS -cp "$jar" tlc2.TLC -workers 1 -nowarning -noGenerateSpecTE -config "$1" "$2" > "$3" 2>&1) || rc=$?
    rm -rf formal/states formal/*_TTrace_*
    echo "$rc"
}
states_of() { grep -o '[0-9]* distinct states found' "$1" | head -1 | cut -d' ' -f1; }

(cd formal && java $JAVA_OPTS -cp "$jar" tla2sany.SANY P2_Core.tla > "$out/sany-core.log" 2>&1)
(cd formal && java $JAVA_OPTS -cp "$jar" tla2sany.SANY P2_Observability.tla > "$out/sany-observability.log" 2>&1)

# 参考配置：Fault = "None"，四条不变式都必须成立。
rc="$(tlc P2_Core.cfg P2_Core.tla "$out/tlc-core.log")"
[ "$rc" = 0 ] || { echo "reference configuration violated an invariant or failed (rc=$rc); see $out/tlc-core.log" >&2; exit 1; }
core_states="$(states_of "$out/tlc-core.log")"

# 双世界模型：两个 Witness（弱观察存在碰撞）与两个 Resolved（增强观察无碰撞）都必须成立。
rc="$(tlc P2_Observability.cfg P2_Observability.tla "$out/tlc-observability.log")"
[ "$rc" = 0 ] || { echo "observability model failed (rc=$rc); see $out/tlc-observability.log" >&2; exit 1; }
obs_states="$(states_of "$out/tlc-observability.log")"

# 故障矩阵。
faults="SubjectConfusion ProvenanceLoss AuthorityMismatch Bypass DenyThenEffect StaleState Substitution Replay"
matrix="{"
first=1
for f in $faults; do
    row=""
    for inv in O1 O2 O3; do
        cfg="P2_Core_${f}_${inv}.cfg"
        printf 'CONSTANT Fault = "%s"\nINIT Init\nNEXT Next\nINVARIANTS TypeOK %s\nCHECK_DEADLOCK FALSE\n' "$f" "$inv" > "formal/$cfg"
        rc="$(tlc "$cfg" P2_Core.tla "$out/tlc-${f}-${inv}.log")"
        rm -f "formal/$cfg"
        case "$rc" in
            0)  v=false ;;
            12) v=true ;;
            *)  echo "TLC failed for $f/$inv (rc=$rc); see $out/tlc-${f}-${inv}.log" >&2; exit 1 ;;
        esac
        row="$row\"$inv\": $v, "
    done
    # 故障配置下 TLC 在第一个反例处停下，它报告的状态数不是完整可达集，所以这里不记。
    # 完整的故障可达状态数由 srg-explorer 的 BFS 给出（results/raw/explorer/core.json）。
    [ $first = 1 ] || matrix="$matrix,"
    first=0
    matrix="$matrix\n  \"$f\": {${row%, }}"
done
matrix="$matrix\n}"
printf "$matrix\n" > "$out/tlc_matrix.json"

java_version="$(java -version 2>&1 | head -1 | tr -d '"')"
cat > "$out/status.json" <<JSON
{
  "sany": "executed",
  "tlc_reference": "executed",
  "tlc_observability": "executed",
  "tlc_fault_matrix": "executed",
  "tla2tools_sha256": "$(sha256sum "$jar" | cut -d' ' -f1)",
  "java": "$java_version",
  "core_reference_distinct_states": ${core_states:-null},
  "observability_distinct_states": ${obs_states:-null},
  "scope": "bounded reference model; a TLC pass is not a general proof"
}
JSON
echo "formal: reference $core_states states, observability $obs_states states; fault matrix written to $out/tlc_matrix.json"
