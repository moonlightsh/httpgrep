#!/usr/bin/env bash
# live-lo0.sh — 验证通道 V2：本机 lo0 实时抓包（计划第 8 节 V2）。
#
# 用途：在 127.0.0.1 的随机端口起一个 python3 标准库写的 HTTP 服务
# （/hit 响应带关键词、/nohit 不带、/chunked 分块响应带关键词、/slow 先睡 10 秒），
# 运行 `tcpdump -i lo0 -U -w - port P | httpgrep --timeout 3s 关键词`，
# 用 `curl -s -o /dev/null` 发请求，验证：
#   (a) 命中的块在响应完成后 1 秒内出现在 httpgrep 输出里；
#   (b) /slow 约 3 秒后输出 no-response(timeout)；
#   (c) 向 httpgrep 进程发一次 SIGINT 后，在途交互以 no-response(eof) 输出，
#       进程以 0 或 1 退出；另测一次向整个管道进程组发 SIGINT（计划原文写法）。
#
# 前提：macOS；当前用户在 access_bpf 组（不用 sudo 即可 tcpdump -i lo0）；
# 有 go（未设 HTTPGREP_BIN 时编译 dist/httpgrep）、python3、curl、perl。
# 不安装任何依赖。只产生本地合成流量，不读真实抓包。
#
# 用法：bash scripts/live-lo0.sh
# 环境变量：HTTPGREP_BIN 指定待测程序；V2_TCPDUMP_EXTRA 追加 tcpdump 参数（诊断用）；
# V2_OUT_DIR 指定产物目录
# （默认 /tmp/httpgrep-verify/v2-live，每次运行清空重建）。
# 退出码：全部通过 0；有检查项失败 1；环境不满足 2。

set -u
set -m # 开启作业控制：每条后台管道自成进程组，SIGINT 不被忽略，可按组发信号

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${V2_OUT_DIR:-/tmp/httpgrep-verify/v2-live}
KW=V2LIVEKW7Q
TIMEOUT_S=3
# 诊断用：给 tcpdump 追加的参数，例如 V2_TCPDUMP_EXTRA=--immediate-mode
TD_EXTRA=${V2_TCPDUMP_EXTRA:-}

rm -rf "$OUT" && mkdir -p "$OUT" || exit 2

PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null
  done
  for f in "$OUT"/*.tcpdump.pid; do
    [ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null
  done
  return 0
}
trap cleanup EXIT
trap 'exit 2' HUP TERM

now() { perl -MTime::HiRes=time -e 'printf "%.6f\n", time'; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", a-b}'; }
# in_range X LO HI：LO <= X <= HI 时返回 0
in_range() { awk -v x="$1" -v lo="$2" -v hi="$3" 'BEGIN{exit !(x>=lo && x<=hi)}'; }

FAILS=0
RESULTS=()
check() { # check 名称 结果(0=通过) 说明
  if [ "$2" -eq 0 ]; then RESULTS+=("PASS $1: $3")
  else RESULTS+=("FAIL $1: $3"); FAILS=$((FAILS+1)); fi
  echo "${RESULTS[${#RESULTS[@]}-1]}"
}

for c in tcpdump python3 curl perl; do
  command -v "$c" >/dev/null || { echo "缺少命令 $c" >&2; exit 2; }
done
if [ -n "${HTTPGREP_BIN:-}" ]; then
  BIN=$HTTPGREP_BIN
else
  BIN=$ROOT/dist/httpgrep
  (cd "$ROOT" && go build -o dist/httpgrep ./cmd/httpgrep) || { echo "编译失败" >&2; exit 2; }
fi
[ -x "$BIN" ] || { echo "找不到可执行文件 $BIN" >&2; exit 2; }

# ---- 本地 HTTP 服务（python3 标准库，HTTP/1.1，绑定 127.0.0.1:0 随机端口）----
cat > "$OUT/server.py" <<'PY'
import sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
KW = sys.argv[2].encode()
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def fixed(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/hit":
            self.fixed(b"hit ok " + KW + b"\n")
        elif p == "/nohit":
            self.fixed(b"nothing here\n")
        elif p == "/slow":
            time.sleep(10)
            self.fixed(b"slow done\n")
        elif p == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"part one\n", b"part two " + KW + b"\n", b"part three\n"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.flush()
                time.sleep(0.2)
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.fixed(b"404\n")
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
srv.daemon_threads = True
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY
python3 "$OUT/server.py" "$OUT/port" "$KW" &
PIDS+=($!)
for _ in $(seq 50); do [ -s "$OUT/port" ] && break; sleep 0.1; done
[ -s "$OUT/port" ] || { echo "HTTP 服务未启动" >&2; exit 2; }
PORT=$(cat "$OUT/port")
BASE="http://127.0.0.1:$PORT"
echo "服务端口: $PORT  产物目录: $OUT"

# ---- 输出块轮询：等 OUTFILE 里出现请求行含 "id=ID HTTP/" 的块 ----
# 结果写到 RESFILE：发现时刻（epoch 秒）<TAB>定位行；超时写 TIMEOUT。
cat > "$OUT/poll.py" <<'PY'
import sys, time
out, ident, maxsec, res = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
needle = "id=%s HTTP/" % ident
def find():
    try:
        data = open(out, "rb").read().decode("utf-8", "replace")
    except OSError:
        return None
    block = []
    for line in data.split("\n") + ["--"]:
        if line == "--":
            if any(needle in l for l in block[1:]):
                return block[0]
            block = []
        else:
            block.append(line)
    return None
deadline = time.time() + maxsec
while True:
    loc = find()
    if loc is not None:
        t = time.time()
        open(res, "w").write("%.6f\t%s\n" % (t, loc))
        break
    if time.time() > deadline:
        open(res, "w").write("TIMEOUT\n")
        break
    time.sleep(0.01)
PY
# start_poll ID MAXSEC TAG：后台启动轮询，pid 记入 POLL_PID
start_poll() {
  python3 "$OUT/poll.py" "$CUR_OUT" "$1" "$2" "$OUT/$3.poll" &
  POLL_PID=$!
  PIDS+=($POLL_PID)
  sleep 0.1 # 等 python 起来
}
poll_time()   { cut -f1 "$OUT/$1.poll"; }
poll_status() { cut -f2 "$OUT/$1.poll" | awk '{print $6}'; }
# block_count ID：当前输出里请求行含该 id 的块数
block_count() { grep -c "id=$1 HTTP/" "$CUR_OUT"; }

# ---- 启动 tcpdump | httpgrep 管道 ----
# start_pipeline TAG：设置 HG_PID、TD_PID、PGID、CUR_OUT
start_pipeline() {
  local tag=$1
  CUR_OUT=$OUT/$tag.out
  sh -c 'echo $$ > "$1"; exec tcpdump $4 -i lo0 -U -w - port "$2" 2>"$3"' sh \
      "$OUT/$tag.tcpdump.pid" "$PORT" "$OUT/$tag.tcpdump.err" "$TD_EXTRA" \
    | "$BIN" --timeout "${TIMEOUT_S}s" "$KW" >"$CUR_OUT" 2>"$OUT/$tag.err" &
  HG_PID=$!
  PIDS+=($HG_PID)
  local i
  for i in $(seq 100); do
    grep -q 'listening on' "$OUT/$tag.tcpdump.err" 2>/dev/null && break
    sleep 0.05
  done
  TD_PID=$(cat "$OUT/$tag.tcpdump.pid" 2>/dev/null)
  PIDS+=($TD_PID)
  PGID=$(ps -o pgid= -p "$HG_PID" | tr -d ' ')
  if ! grep -q 'listening on' "$OUT/$tag.tcpdump.err" 2>/dev/null; then
    echo "tcpdump 未开始抓包（lo0 权限？），见 $OUT/$tag.tcpdump.err" >&2
    exit 2
  fi
  sleep 0.3
}
# wait_exit SECS：轮询 httpgrep 是否已退出（ps 查不到或成了僵尸），设置 T_EXIT；
# 超过 SECS 仍未退出则 kill -9。之后结束 tcpdump，再 wait 取退出码 HG_RC。
# 不能直接用 wait 计时：bash 3.2 对管道中的 pid 会等整条管道（含 tcpdump）结束。
wait_exit() {
  local deadline st
  deadline=$(awk -v t="$(now)" -v s="$1" 'BEGIN{printf "%.6f", t+s}')
  while :; do
    st=$(ps -o stat= -p "$HG_PID" 2>/dev/null | tr -d ' ')
    case "$st" in ''|Z*) T_EXIT=$(now); break ;; esac
    if ! in_range "$(now)" 0 "$deadline"; then
      T_EXIT=$(now); kill -9 "$HG_PID" 2>/dev/null; break
    fi
    sleep 0.02
  done
  # 记下 httpgrep 退出后 1 秒内 tcpdump 是否也已退出（TD_GONE=0 表示已退出）
  TD_GONE=1
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    st=$(ps -o stat= -p "$TD_PID" 2>/dev/null | tr -d ' ')
    case "$st" in ''|Z*) TD_GONE=0; break ;; esac
    sleep 0.1
  done
  kill -TERM "$TD_PID" 2>/dev/null
  wait "$HG_PID"; HG_RC=$?
}

# ---- (a) 命中块在响应完成后 1 秒内输出 ----
# check_fast 名称 路径 ID
check_fast() {
  local name=$1 path=$2 id=$3 t_done d st
  start_poll "$id" 5 "$id"
  curl -s -o /dev/null -m 10 "$BASE$path?id=$id"
  t_done=$(now)
  wait "$POLL_PID"
  if grep -q TIMEOUT "$OUT/$id.poll"; then
    check "$name" 1 "响应完成后 5 秒内未出现块"
    return
  fi
  d=$(sub "$(poll_time "$id")" "$t_done"); st=$(poll_status "$id")
  [ "$st" = complete ] && in_range "$d" -1 1.0
  check "$name" $? "curl 结束到块出现 ${d}s（上限 1.0s），状态 $st"
}

echo "== 阶段 1：SIGINT 只发给 httpgrep 进程 =="
start_pipeline p1
check_fast "a1 /hit 块延迟" /hit a1
check_fast "a2 /chunked 块延迟" /chunked a2
curl -s -o /dev/null -m 10 "$BASE/nohit?id=n1"

# ---- (b) /slow 约 3 秒后 no-response(timeout) ----
start_poll b1 10 b1
T_REQ=$(now)
curl -s -o /dev/null -m 15 "$BASE/slow?k=$KW&id=b1" &
PIDS+=($!)
wait "$POLL_PID"
if grep -q TIMEOUT "$OUT/b1.poll"; then
  check "b /slow 超时" 1 "请求后 10 秒内未出现块"
else
  D=$(sub "$(poll_time b1)" "$T_REQ"); ST=$(poll_status b1)
  [ "$ST" = "no-response(timeout)" ] && in_range "$D" 2.8 4.5
  check "b /slow 超时" $? "请求发出到块出现 ${D}s（期望 2.8~4.5s：3s 超时 + tcpdump 非 immediate 模式约 0.5s 投递延迟 + 200ms 空闲检查粒度），状态 $ST"
fi

# ---- (c1) 在途交互 + SIGINT 发给 httpgrep ----
curl -s -o /dev/null -m 15 "$BASE/slow?k=$KW&id=c1" &
PIDS+=($!)
sleep 1
T_SIG=$(now)
kill -INT "$HG_PID"
wait_exit 10
E=$(sub "$T_EXIT" "$T_SIG")
python3 "$OUT/poll.py" "$CUR_OUT" c1 0 "$OUT/c1.poll"
ST=$(poll_status c1)
[ "$ST" = "no-response(eof)" ]
check "c1 在途交互状态" $? "状态 ${ST:-无块}"
[ "$HG_RC" -eq 0 ] || [ "$HG_RC" -eq 1 ]
check "c1 退出码" $? "退出码 ${HG_RC}（有命中应为 0），SIGINT 到退出 ${E}s"
in_range "$E" 0 2.5
check "c1 退出耗时" $? "SIGINT 到退出 ${E}s（排空最多 1s，上限 2.5s）"
N=$(block_count n1); [ "$N" -eq 0 ]
check "对照 /nohit 不输出" $? "块数 $N"
BAD=""
for id in a1 a2 b1 c1; do [ "$(block_count $id)" -eq 1 ] || BAD="$BAD $id"; done
[ -z "$BAD" ]
check "阶段 1 每个命中交互恰好一块" $? "异常:${BAD:-无}；总块数 $(grep -c -- '^--$' "$CUR_OUT") 个分隔行"
[ ! -s "$OUT/p1.err" ]
check "阶段 1 stderr 为空" $? "$(wc -c <"$OUT/p1.err" | tr -d ' ') 字节"
kill -9 "$TD_PID" 2>/dev/null

# ---- (c2) 计划原文写法：SIGINT 发给整个管道进程组（tcpdump 和 httpgrep）----
echo "== 阶段 2：SIGINT 发给管道进程组 =="
start_pipeline p2
check_fast "a3 /hit 块延迟（阶段 2）" /hit a3
curl -s -o /dev/null -m 15 "$BASE/slow?k=$KW&id=c2" &
PIDS+=($!)
sleep 1
MYPG=$(ps -o pgid= -p $$ | tr -d ' ')
T_SIG=$(now)
if [ -n "$PGID" ] && [ "$PGID" != "$MYPG" ]; then
  kill -INT -- "-$PGID"
else
  echo "警告：管道未独立成进程组，改为分别向 tcpdump 和 httpgrep 发 SIGINT" >&2
  kill -INT "$TD_PID" "$HG_PID"
fi
wait_exit 10
E=$(sub "$T_EXIT" "$T_SIG")
python3 "$OUT/poll.py" "$CUR_OUT" c2 0 "$OUT/c2.poll"
ST=$(poll_status c2)
[ "$ST" = "no-response(eof)" ]
check "c2 在途交互状态（进程组）" $? "状态 ${ST:-无块}"
[ "$HG_RC" -eq 0 ] || [ "$HG_RC" -eq 1 ]
check "c2 退出码（进程组）" $? "退出码 ${HG_RC}，SIGINT 到退出 ${E}s"
in_range "$E" 0 2.5
check "c2 退出耗时（进程组）" $? "SIGINT 到退出 ${E}s（上限 2.5s）"
check "c2 tcpdump 已退出" "$TD_GONE" "httpgrep 退出后 1 秒内 tcpdump 是否退出"

echo
echo "== 摘要 =="
printf '%s\n' "${RESULTS[@]}"
echo "失败 $FAILS 项，共 ${#RESULTS[@]} 项；产物目录 $OUT"
[ "$FAILS" -eq 0 ]
