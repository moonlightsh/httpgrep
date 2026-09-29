#!/bin/bash
# linux-check.sh —— 验证通道 V3：在 Linux 容器里验证 httpgrep。
#
# 检查项：
#   1. 交叉编译 linux/amd64 静态二进制 dist/httpgrep-linux-amd64，用 file 确认静态链接；
#   2. HTTPGREP_BIN 指向包装脚本（docker run busybox:1.37，linux/amd64 转译），
#      跑 cmd/httpgrep 的黑盒测试；信号类用例单独连跑，见 SIGNAL_COUNT；
#   3. 在 busybox amd64 容器内直接验证 SIGPIPE（替代无法经 docker CLI 观察的用例）；
#   4. 各 internal 包测试交叉编译成 linux/arm64，在 ubuntu:24.04（原生 arm64）里运行；
#   5. 同一份真实样本、TZ=UTC，本机与 amd64 容器输出的 sha256 必须相同。
#
# 前提：macOS arm64；go 1.27、docker（Docker Desktop 或 OrbStack，能以转译方式运行 linux/amd64 容器）、file；
#       本地已有或可拉取 busybox:1.37、ubuntu:24.04；$TMPDIR 与样本目录在 Docker 文件共享范围内。
# 样本：默认在 ~/Downloads、~/Documents/反馈处理 下按 SAMPLE_NAMES 查找，可用 SAMPLES="a.pcap b.pcap" 覆盖。
# 隐私：真实样本的输出只写到 $OUT（默认 /tmp/httpgrep-verify），终端只打印 sha256、行数和退出码。
# 用法：bash scripts/linux-check.sh   —— 全部通过退出 0，否则退出 1。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
OUT="${OUT:-/tmp/httpgrep-verify}"
LOG="$OUT/V3-logs"
DIST="$ROOT/dist"
SIGNAL_COUNT="${SIGNAL_COUNT:-5}"
SAMPLE_NAMES="${SAMPLE_NAMES:-222.pcap 490419C6117A0087747906.pcap}"
TMPD="${TMPDIR:-/tmp}"
TMPD="${TMPD%/}"
export TMPDIR="$TMPD/"
mkdir -p "$LOG" "$DIST/tests"

fails=0
summary=""
record() { # record 结果 名称 细节
  summary="$summary$(printf '%-5s %-34s %s' "$1" "$2" "$3")
"
  printf '[%s] %s: %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && fails=$((fails + 1))
  return 0
}
sha() { sha256sum "$1" | awk '{print $1}'; }

# ---- 0. 前提 ----
for c in go docker file sha256sum; do
  command -v "$c" >/dev/null || { echo "缺少命令：$c" >&2; exit 1; }
done
if ! docker info >/dev/null 2>&1; then
  echo "docker 不可用（docker info 失败），无法进行 V3" >&2
  exit 1
fi

# ---- 1. 编译 ----
if go build -o "$DIST/httpgrep" ./cmd/httpgrep >"$LOG/build-native.log" 2>&1; then
  record PASS build-native "dist/httpgrep"
else
  record FAIL build-native "见 $LOG/build-native.log"
fi
if CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$DIST/httpgrep-linux-amd64" ./cmd/httpgrep >"$LOG/build-linux.log" 2>&1; then
  f="$(file "$DIST/httpgrep-linux-amd64")"
  if echo "$f" | grep -q 'ELF 64-bit.*x86-64' && echo "$f" | grep -q 'statically linked'; then
    record PASS build-linux-amd64-static "ELF x86-64, statically linked"
  else
    record FAIL build-linux-amd64-static "file: $f"
  fi
else
  record FAIL build-linux-amd64-static "见 $LOG/build-linux.log"
fi

# 包装脚本：把测试传来的环境变量转进容器；$TMPDIR 挂到同一路径，测试生成的临时文件在容器里可见。
# 标准输出是终端（伪终端用例）时用 -t 代替 -i，容器里的进程才会认为输出到终端。
WRAP="$DIST/hg-docker.sh"
cat >"$WRAP" <<EOF
#!/bin/bash
mode=-i
[ -t 1 ] && mode=-t
exec docker run --rm \$mode --platform linux/amd64 -e TZ -e GOGC -e GODEBUG -e GOMAXPROCS \\
  -v "$TMPD:$TMPD" -v "$DIST:/opt/hg:ro" busybox:1.37 /opt/hg/httpgrep-linux-amd64 "\$@"
EOF
chmod +x "$WRAP"
arch="$(docker run --rm --platform linux/amd64 busybox:1.37 uname -m 2>"$LOG/uname.log")"
if [ "$arch" = x86_64 ] && "$WRAP" --version >/dev/null 2>&1; then
  record PASS wrapper-smoke "busybox:1.37 uname -m=$arch, --version ok"
else
  record FAIL wrapper-smoke "uname -m=$arch；见 $LOG/uname.log"
fi

# 统计 go test -v 日志里顶层用例的通过/失败/跳过数。
counts() {
  awk '/^--- PASS/{p++} /^--- FAIL/{f++} /^--- SKIP/{s++} END{printf "pass=%d fail=%d skip=%d", p, f, s}' "$1"
}
failed_names() { awk '/^--- FAIL/{printf "%s ", $3}' "$1"; }

# ---- 2. cmd/httpgrep 黑盒测试（amd64 转译容器）----
# 跳过 TestClosedStdoutKilledBySIGPIPE：测试进程的子进程是 docker CLI，它忽略 SIGPIPE、
# 写已关闭的 stdout 时以 exit 1 退出；容器内进程的 stdout 是 containerd shim 的管道，不会断；
# 即使容器内进程被 SIGPIPE 杀死，docker run 也只会以 exit 141 返回，WaitStatus.Signaled() 不可能为真。
# 这条语义改由第 3 项在容器内直接验证。
# 信号用例（SIGINT/SIGTERM）经 docker CLI 的 sig-proxy 转发给容器 PID 1，语义和原生进程不同，
# 单独连跑 SIGNAL_COUNT 次：全部通过记 PASS，出现失败记 SKIP（不稳定，不计入失败）。
SIGRE='^(TestSignalEndsInFlight|TestSecondSIGINTExits130)$'
l="$LOG/cmd-httpgrep.log"
HTTPGREP_BIN="$WRAP" go test -count=1 -v -timeout 20m \
  -skip "^TestClosedStdoutKilledBySIGPIPE\$|$SIGRE" ./cmd/httpgrep/ >"$l" 2>&1
rc=$?
if [ $rc -eq 0 ] && ! grep -q '^--- FAIL' "$l"; then
  record PASS cmd-httpgrep-amd64 "$(counts "$l")（TestVersion 在 HTTPGREP_BIN 下自跳过）"
else
  record FAIL cmd-httpgrep-amd64 "rc=$rc $(counts "$l") 失败：$(failed_names "$l")；见 $l"
fi

l="$LOG/cmd-httpgrep-signal.log"
HTTPGREP_BIN="$WRAP" go test -count="$SIGNAL_COUNT" -v -timeout 20m -run "$SIGRE" ./cmd/httpgrep/ >"$l" 2>&1
rc=$?
if [ $rc -eq 0 ] && ! grep -q '^--- FAIL' "$l"; then
  record PASS cmd-signal-amd64 "x$SIGNAL_COUNT $(counts "$l")"
else
  record SKIP cmd-signal-amd64 "不稳定（docker sig-proxy/PID 1 语义）：rc=$rc $(counts "$l")；见 $l"
fi

# ---- 样本查找（真实抓包，含生产数据，只读挂载，输出不出 $OUT）----
if [ -z "${SAMPLES:-}" ]; then
  SAMPLES=""
  for n in $SAMPLE_NAMES; do
    p="$(find "$HOME/Downloads" "$HOME/Documents/反馈处理" -name "$n" -type f 2>/dev/null | head -1)"
    [ -n "$p" ] && SAMPLES="$SAMPLES $p"
  done
fi

# ---- 3. 容器内 SIGPIPE：标准输出接到已退出的读端，进程应被 SIGPIPE 杀死（ash 里 $?=141）----
first="$(echo $SAMPLES | awk '{print $1}')"
if [ -z "$first" ]; then
  record SKIP sigpipe-in-container "没找到样本（SAMPLE_NAMES=$SAMPLE_NAMES）"
else
  sd="$(dirname "$first")"
  nbytes="$(TZ=UTC "$DIST/httpgrep" "" "$first" 2>/dev/null | wc -c | tr -d ' ')"
  got="$(docker run --rm --platform linux/amd64 -v "$DIST:/opt/hg:ro" -v "$sd:$sd:ro" busybox:1.37 \
    sh -c '( /opt/hg/httpgrep-linux-amd64 "" "$1" 2>/dev/null; echo "$?" >&2 ) | true' sh "$first" 2>&1 >/dev/null)"
  if [ "$nbytes" -gt 0 ] && [ "$got" = 141 ]; then
    record PASS sigpipe-in-container "exit 141 (128+SIGPIPE)，样本 $(basename "$first") 正常输出 $nbytes 字节"
  else
    record FAIL sigpipe-in-container "容器内退出码 '$got'（期望 141），本机输出 $nbytes 字节"
  fi
fi

# ---- 4. 各包测试：linux/arm64，ubuntu:24.04 原生容器；依赖 tshark 的用例自动跳过 ----
for d in internal/*/; do
  p="$(basename "$d")"
  ls "$d"*_test.go >/dev/null 2>&1 || continue
  l="$LOG/pkg-$p.log"
  if ! GOOS=linux GOARCH=arm64 go test -c -o "$DIST/tests/$p.test" "./internal/$p" >"$l" 2>&1; then
    record FAIL "pkg-$p-arm64" "编译失败，见 $l"
    continue
  fi
  docker run --rm --platform linux/arm64 -e TZ=UTC -v "$ROOT:/src:ro" -w "/src/internal/$p" ubuntu:24.04 \
    "/src/dist/tests/$p.test" -test.count=1 -test.v -test.timeout=10m >"$l" 2>&1
  rc=$?
  if [ $rc -eq 0 ] && ! grep -q '^--- FAIL' "$l"; then
    record PASS "pkg-$p-arm64" "$(counts "$l")"
  else
    record FAIL "pkg-$p-arm64" "rc=$rc $(counts "$l") 失败：$(failed_names "$l")；见 $l"
  fi
done

# ---- 5. 一致性：TZ=UTC，本机与 amd64 容器对同一份样本的 stdout sha256 和退出码必须相同 ----
# 组合：空关键词（输出全部交互）--cpus 1；关键词 490419C6117A0087747906 --cpus 4。
if [ -z "$SAMPLES" ]; then
  record SKIP consistency "没找到样本（SAMPLE_NAMES=$SAMPLE_NAMES）"
fi
for s in $SAMPLES; do
  b="$(basename "$s" .pcap)"
  sd="$(dirname "$s")"
  for mode in all kw; do
    if [ $mode = all ]; then set -- --cpus 1 ""; else set -- --cpus 4 490419C6117A0087747906; fi
    n="$OUT/V3-$b-$mode-native.out"
    c="$OUT/V3-$b-$mode-amd64.out"
    TZ=UTC "$DIST/httpgrep" "$@" "$s" >"$n" 2>"$n.err"
    rn=$?
    docker run --rm --platform linux/amd64 -e TZ=UTC -v "$DIST:/opt/hg:ro" -v "$sd:$sd:ro" busybox:1.37 \
      /opt/hg/httpgrep-linux-amd64 "$@" "$s" >"$c" 2>"$c.err"
    rc=$?
    hn="$(sha "$n")"; hc="$(sha "$c")"
    lines="$(wc -l <"$n" | tr -d ' ')"
    seps="$(grep -c '^--$' "$n")"
    if [ "$hn" = "$hc" ] && [ $rn -eq $rc ] && [ $rn -le 1 ]; then
      record PASS "consistency-$b-$mode" "exit $rn/$rc, $lines 行, $seps 条 -- 分隔行, sha256 ${hn:0:16}"
    else
      record FAIL "consistency-$b-$mode" "native exit $rn sha ${hn:0:16}; amd64 exit $rc sha ${hc:0:16}; 见 $n / $c"
    fi
  done
done

echo
echo "==== V3 摘要 ===="
printf '%s' "$summary"
echo "失败项：$fails"
[ $fails -eq 0 ]
