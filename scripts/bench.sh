#!/usr/bin/env bash
# bench.sh — httpgrep 性能验证（阶段四 V4 通道）。
#
# 用途：
#   1. 运行全部 Go 基准测试：go test -run '^$' -bench . -benchmem ./...
#   2. 对真实样本（默认 ~/Downloads/111.pcap）用 --stats --cpus 1 字面关键词连跑 3 次，
#      记录吞吐（--stats 的 throughput）、最大 RSS（/usr/bin/time -l）和用时；
#      再用 --cpus 4 跑一次；再用 -E '4904[0-9A-F]+' 跑一次（只记录，不参与判定）。
#   3. 输出摘要。单核吞吐任一次低于阈值（默认 100 MB/s，用来近似 x64 上的 50 MB/s）、
#      基准测试失败或 httpgrep 退出码不是 0/1 时，以非 0 退出。
#
# 前提：
#   - macOS（依赖 BSD 版 /usr/bin/time -l），已安装 Go 1.27；在仓库任意位置执行均可。
#   - 样本抓包含生产数据：httpgrep 的 stdout 一律丢到 /dev/null，stderr（仅统计计数）
#     和 time 的输出写到 $OUT_DIR 下，不打印原始内容，也不进仓库。
#
# 可用环境变量：
#   HTTPGREP_SAMPLE  样本路径，默认 ~/Downloads/111.pcap
#   KEYWORD          字面关键词，默认 490419C6117A0087747906
#   MIN_MBPS         单核吞吐下限（MB/s），默认 100
#   OUT_DIR          中间结果目录，默认 /tmp/httpgrep-verify/bench
#   SKIP_GOBENCH=1   跳过 go 基准测试（只跑样本）
#
# 用法：bash scripts/bench.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE="${HTTPGREP_SAMPLE:-$HOME/Downloads/111.pcap}"
KEYWORD="${KEYWORD:-490419C6117A0087747906}"
MIN_MBPS="${MIN_MBPS:-100}"
OUT_DIR="${OUT_DIR:-/tmp/httpgrep-verify/bench}"
BIN="$ROOT/dist/httpgrep"
FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }

mkdir -p "$OUT_DIR"
cd "$ROOT" || exit 2

echo "== build"
go build -o "$BIN" ./cmd/httpgrep || { echo "FAIL: go build"; exit 2; }

if [[ "${SKIP_GOBENCH:-0}" != 1 ]]; then
  echo "== go benchmarks (full log: $OUT_DIR/gobench.txt)"
  if go test -run '^$' -bench . -benchmem ./... > "$OUT_DIR/gobench.txt" 2>&1; then
    echo "go benchmarks: ok ($(grep -c '^Benchmark' "$OUT_DIR/gobench.txt") results)"
    # 只打印带 MB/s 的行：名称和吞吐
    awk '/^Benchmark/ { for (i = 1; i <= NF; i++) if ($i == "MB/s") printf "  %-40s %10s MB/s\n", $1, $(i-1) }' "$OUT_DIR/gobench.txt"
  else
    fail "go benchmarks failed, see $OUT_DIR/gobench.txt"
    grep -E '^(FAIL|---|panic)' "$OUT_DIR/gobench.txt" | head -20
  fi
fi

if [[ ! -r "$SAMPLE" ]]; then
  echo "FAIL: sample not readable: $SAMPLE (set HTTPGREP_SAMPLE)"
  exit 2
fi
echo "== sample: $(basename "$SAMPLE"), $(stat -f %z "$SAMPLE") bytes"

# run <tag> <httpgrep args...>：stdout 丢弃，stderr（--stats + time -l）写入 $OUT_DIR/<tag>.err；
# 打印 吞吐 / 用时 / 最大 RSS / 命中数，并把吞吐存进 LAST_MBPS。
LAST_MBPS=0
run() {
  local tag="$1"; shift
  local err="$OUT_DIR/$tag.err"
  /usr/bin/time -l "$BIN" "$@" "$SAMPLE" > /dev/null 2> "$err"
  local rc=$?
  if [[ $rc -ne 0 && $rc -ne 1 ]]; then
    fail "$tag: httpgrep exit code $rc, see $err"
  fi
  LAST_MBPS=$(awk '/^throughput:/ { print $2 }' "$err")
  local elapsed real rss matched
  elapsed=$(awk '/^elapsed:/ { print $2 }' "$err")
  real=$(awk '$2 == "real" { print $1 }' "$err")
  rss=$(awk '/maximum resident set size/ { printf "%.1f", $1 / 1048576 }' "$err")
  matched=$(awk '/^matched:/ { print $2 }' "$err")
  [[ -n "$LAST_MBPS" ]] || { fail "$tag: no throughput in --stats"; LAST_MBPS=0; }
  printf "  %-8s rc=%d throughput=%s MB/s elapsed=%s real=%ss maxRSS=%s MiB matched=%s\n" \
    "$tag" "$rc" "$LAST_MBPS" "$elapsed" "$real" "$rss" "$matched"
}

echo "== --cpus 1 literal x3 (threshold ${MIN_MBPS} MB/s)"
for i in 1 2 3; do
  run "cpus1-$i" --stats --cpus 1 "$KEYWORD"
  if awk -v t="$LAST_MBPS" -v m="$MIN_MBPS" 'BEGIN { exit !(t + 0 < m + 0) }'; then
    fail "cpus1-$i: ${LAST_MBPS} MB/s < ${MIN_MBPS} MB/s"
  fi
done

echo "== --cpus 4 literal x1"
run cpus4 --stats --cpus 4 "$KEYWORD"

echo "== -E '4904[0-9A-F]+' --cpus 1 (record only, not judged)"
run regex --stats --cpus 1 -E '4904[0-9A-F]+'

echo "== result"
if [[ $FAIL -ne 0 ]]; then echo "bench: FAIL"; exit 1; fi
echo "bench: PASS"
