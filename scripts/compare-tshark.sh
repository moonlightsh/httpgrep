#!/usr/bin/env bash
# compare-tshark.sh —— 阶段四 V1：用真实抓包验证 httpgrep，并和 tshark 交叉核对。
#
# 用途：
#   1. 关键词检查：490419C6117A0087747906 在同名抓包里至少命中一次；34095128 在所有样本里都不命中。
#   2. 空关键词输出全部交互，和 tshark 核对 complete / no-response / no-request 三组计数，
#      差异按连接分类，并用 tools/samplecheck 判断能否归入已知的 tshark 口径差异（E1–E4，定义见
#      tools/samplecheck/main.go 的 explain）；有解释不了的差异就判失败。
#   3. 记录每个文件的 --stats、/usr/bin/time -l 的最大 RSS 和用时。
#   4. 111.pcap 上比较 --cpus 4 和 --cpus 1 的输出块集合（sha256）。
#   5. 出错路径：空文件、非 pcap、pcapng、不支持的链路类型。
#
# 前提：
#   - macOS，已装 go、tshark（Wireshark 4.x）、capinfos、tcpdump，/usr/bin/time 支持 -l。
#   - 样本在 ~/Downloads 和 ~/Documents/反馈处理 下（含生产数据，不进仓库）。
#     可用 SAMPLE_DIRS 覆盖搜索目录（空格分隔）。
#   - 输出全部写到 $OUT（默认 /tmp/httpgrep-verify/V1），终端只打印计数和状态，
#     不打印抓包里的 IP、URL、头部或 body。
#
# 用法：bash scripts/compare-tshark.sh
# 退出码：全部通过为 0；有检查失败为 1；缺少工具或必需样本为 2。
set -u
export LC_ALL=C

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-/tmp/httpgrep-verify/V1}
SAMPLE_DIRS=${SAMPLE_DIRS:-"$HOME/Downloads $HOME/Documents/反馈处理"}
BIN=$ROOT/dist/httpgrep
SC=$ROOT/dist/samplecheck
mkdir -p "$OUT"
SUMMARY=$OUT/summary.txt
: > "$SUMMARY"
FAILS=0

say() { echo "$*" | tee -a "$SUMMARY"; }
pass() { say "PASS $*"; }
fail() { say "FAIL $*"; FAILS=$((FAILS + 1)); }

for t in go tshark capinfos tcpdump; do
	command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }
done

(cd "$ROOT" && go build -o dist/httpgrep ./cmd/httpgrep && go build -o dist/samplecheck ./tools/samplecheck) || {
	echo "build failed" >&2
	exit 2
}

# ---- 找样本 ----
SAMPLES=$OUT/samples.txt
# shellcheck disable=SC2086
find $SAMPLE_DIRS -name '*.pcap' -size +100k 2>/dev/null | sort > "$SAMPLES"
say "samples: $(wc -l < "$SAMPLES" | tr -d ' ') files (*.pcap > 100k)"

# sample NAME：按文件名（不含 .pcap）找样本路径，找不到输出空串。
sample() { grep "/$1\.pcap\$" "$SAMPLES" | head -1; }

MISSING=0
for n in 111 222 34095128 490419C6117A0087747906; do
	[ -n "$(sample "$n")" ] || { fail "required sample $n.pcap not found"; MISSING=1; }
done
SLL2=$(sample 1112)
[ -n "$SLL2" ] || SLL2=$(sample 3)
[ -n "$SLL2" ] || { fail "no SLL2 sample (1112.pcap or 3.pcap)"; MISSING=1; }
HIK=$(grep '/HIK_PCAPdroid[^/]*\.pcap$' "$SAMPLES" | head -1)
[ -n "$HIK" ] || { fail "HIK_PCAPdroid sample not found"; MISSING=1; }
[ "$MISSING" = 0 ] || exit 2

# base PATH：文件名去掉 .pcap，作为输出文件名的前缀。
base() { b=$(basename "$1" .pcap); echo "$b" | cut -c1-40; }

# 链路类型只取 capinfos 的 encapsulation 一行。
while IFS= read -r f <&3; do
	enc=$(capinfos -E "$f" 2>/dev/null | awk -F': *' '/encapsulation/{print $2}')
	say "linktype $(base "$f"): $enc"
done 3< "$SAMPLES"
if tcpdump -r "$HIK" -c 1 2>&1 >/dev/null | grep -q 'link-type RAW'; then
	pass "HIK_PCAPdroid link type is RAW (101), expected to be supported"
else
	say "INFO HIK_PCAPdroid link type is not RAW; httpgrep must either read it or reject it with exit 2"
fi

# ---- 出错路径 ----
# expect_err NAME FILE PATTERN：httpgrep 读 FILE 应以 2 退出，stderr 含 PATTERN。
expect_err() {
	"$BIN" x "$2" > /dev/null 2> "$OUT/err-$1.txt"
	rc=$?
	if [ "$rc" = 2 ] && grep -q "^httpgrep: .*$3" "$OUT/err-$1.txt"; then
		pass "error path $1: exit 2, '$(head -1 "$OUT/err-$1.txt")'"
	else
		fail "error path $1: exit $rc, stderr '$(head -1 "$OUT/err-$1.txt")' (want exit 2 and /$3/)"
	fi
}
# shellcheck disable=SC2086
E3000=$(find $SAMPLE_DIRS -name '3000.pcap' 2>/dev/null | head -1)
if [ -n "$E3000" ]; then
	expect_err 3000.pcap "$E3000" 'empty input'
else
	say "SKIP error path 3000.pcap: file not found"
fi
head -c 4096 /dev/urandom > "$OUT/random.bin"
expect_err random "$OUT/random.bin" 'not a pcap'
# 合成的 pcap：链路类型 147（USER0），一个 4 字节的包；pcapng：只有 SHB 魔数。
printf 'd4c3b2a1020004000000000000000000ffff000093000000000000000000000004000000040000000102030400' | xxd -r -p > "$OUT/linktype147.pcap"
expect_err linktype147 "$OUT/linktype147.pcap" 'unsupported link type'
printf '0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c000000' | xxd -r -p > "$OUT/magic.pcapng"
expect_err pcapng "$OUT/magic.pcapng" 'pcapng'

# ---- 关键词 ----
F490=$(sample 490419C6117A0087747906)
"$BIN" 490419C6117A0087747906 "$F490" > "$OUT/kw-490419.txt" 2> "$OUT/kw-490419.err"
rc=$?
n=$("$SC" locators "$OUT/kw-490419.txt" | awk -F= '/^blocks=/{split($2,a," "); print a[1]}')
if [ "$rc" = 0 ] && [ "$n" -ge 1 ]; then
	pass "keyword 490419C6117A0087747906 in its own file: exit 0, $n matching blocks"
else
	fail "keyword 490419C6117A0087747906 in its own file: exit $rc, $n matching blocks (want exit 0, >=1)"
fi
nz=0
while IFS= read -r f <&3; do
	b=$(base "$f")
	"$BIN" 34095128 "$f" > "$OUT/kw-34095128-$b.txt" 2> "$OUT/kw-34095128-$b.err"
	rc=$?
	sz=$(wc -c < "$OUT/kw-34095128-$b.txt" | tr -d ' ')
	if [ "$rc" != 1 ] || [ "$sz" != 0 ]; then
		fail "keyword 34095128 in $b: exit $rc, $sz bytes of output (want exit 1, empty)"
		nz=$((nz + 1))
	fi
done 3< "$SAMPLES"
[ "$nz" = 0 ] && pass "keyword 34095128: no hits in all $(wc -l < "$SAMPLES" | tr -d ' ') samples (exit 1, empty output)"

# ---- 空关键词：统计、资源和 tshark 核对 ----
# stat KEY FILE：取 --stats 里某一项的值。
stat() { awk -F': ' -v k="$1" '$1==k{print $2; exit}' "$2"; }

# run_hg BASE FILE [选项...]：空关键词跑一遍，stdout 到 o-BASE.txt，stderr（--stats 和 time -l）到 s-BASE.txt。
run_hg() {
	b=$1 f=$2
	shift 2
	/usr/bin/time -l "$BIN" --stats "$@" '' "$f" > "$OUT/o-$b.txt" 2> "$OUT/s-$b.txt"
	echo $? > "$OUT/rc-$b.txt"
}

# server_ports BASE FILE：按 conv,tcp 找服务端口（出现在 >=10% 的连接里的端口，最多 3 个）。
server_ports() {
	tshark -r "$2" -q -z conv,tcp > "$OUT/conv-$1.txt" 2> /dev/null
	awk '$2=="<->"{n++; split($1,a,":"); split($3,c,":"); p[a[length(a)]]++; p[c[length(c)]]++}
		END{for (k in p) if (p[k]*10 >= n && p[k] >= 2) print p[k], k}' "$OUT/conv-$1.txt" |
		sort -rn | head -3 | awk '{print $2}' | tr '\n' ' '
}

FIELDS="-e frame.number -e frame.time_epoch -e tcp.stream -e ip.src -e ipv6.src -e tcp.srcport -e ip.dst -e ipv6.dst -e tcp.dstport -e http.request -e http.response -e http.response_in -e http.request_in"
ANOM='tcp.flags.syn==1 || tcp.analysis.retransmission || tcp.analysis.out_of_order || tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment'

TABLE=$OUT/table.txt
printf '%-40s %8s %8s %6s %8s %9s %9s %9s %9s\n' file exch complete no-req no-resp incompl ts-compl ts-no-rsp ts-no-req > "$TABLE"
while IFS= read -r f <&3; do
	b=$(base "$f")
	run_hg "$b" "$f"
	rc=$(cat "$OUT/rc-$b.txt")
	s=$OUT/s-$b.txt
	if [ "$rc" = 2 ]; then
		if grep -q 'unsupported link type' "$s"; then
			pass "$b: unsupported link type rejected with exit 2 ($(head -1 "$s"))"
		else
			fail "$b: exit 2: $(head -1 "$s")"
		fi
		continue
	fi
	ex=$(stat exchanges "$s")
	rss=$(awk '/maximum resident set size/{printf "%.1f MiB", $1/1048576}' "$s")
	real=$(awk '/ real /{print $1 "s"}' "$s")
	say "stats $b: packets=$(stat packets "$s") bytes=$(stat bytes "$s") elapsed=$(stat elapsed "$s") throughput=$(stat throughput "$s") connections=$(stat connections "$s") mid-stream=$(stat 'mid-stream connections' "$s") exchanges=$ex gaps=$(stat gaps "$s") desyncs=$(stat desyncs "$s") orphans=$(stat 'orphan messages' "$s") maxrss=$rss real=$real"
	# 退出码：有交互时 0，没有时 1。
	want=1
	[ "${ex:-0}" -gt 0 ] && want=0
	[ "$rc" = "$want" ] || fail "$b: empty pattern exit $rc, want $want (exchanges=$ex)"
	# --stats 自洽：块数 = exchanges = matched；各状态个数和块的状态词一致。
	"$SC" locators "$OUT/o-$b.txt" > "$OUT/loc-$b.txt"
	blocks=$(awk -F'[= ]' '/^blocks=/{print $2}' "$OUT/loc-$b.txt")
	bad=$(awk -F'[= ]' '/^blocks=/{print $4}' "$OUT/loc-$b.txt")
	# cnt STR：状态词里含 STR 的块数（按字面子串，complete 按整词）。
	cnt() { awk -v s="$1" '$1=="status" && (s=="complete" ? $2==s : index($2, s) > 0) {n+=$3} END{print n+0}' "$OUT/loc-$b.txt"; }
	ok=1
	[ "$blocks" = "$ex" ] && [ "$(stat matched "$s")" = "$ex" ] && [ "$bad" = 0 ] || ok=0
	[ "$(cnt complete)" = "$(stat complete "$s")" ] || ok=0
	[ "$(cnt no-request)" = "$(stat no-request "$s")" ] || ok=0
	[ "$(cnt incomplete)" = "$(stat incomplete "$s")" ] || ok=0
	for r in timeout closed eof; do
		[ "$(cnt "no-response($r)")" = "$(stat "no-response($r)" "$s")" ] || ok=0
	done
	if [ "$ok" = 1 ]; then
		pass "$b: --stats consistent with output ($blocks blocks, $(tr '\n' ' ' < "$OUT/loc-$b.txt" | sed 's/blocks=[0-9]* bad_start=0 //'))"
	else
		fail "$b: --stats inconsistent with output: blocks=$blocks bad_start=$bad stats exchanges=$ex (see $OUT/loc-$b.txt, $s)"
	fi
	# tshark：-d 把服务端口当 HTTP 解析，-2 两遍解析才有 http.response_in。
	ports=$(server_ports "$b" "$f")
	dargs=""
	for p in $ports; do dargs="$dargs -d tcp.port==$p,http"; done
	# shellcheck disable=SC2086
	tshark -r "$f" -2 $dargs -Y http -T fields -E separator=/t -E occurrence=a -E aggregator=, $FIELDS \
		> "$OUT/tf-$b.tsv" 2> "$OUT/tf-$b.err" &
	tshark -r "$f" -Y "$ANOM" -T fields -e tcp.stream -e tcp.flags.syn -e tcp.analysis.retransmission \
		-e tcp.analysis.out_of_order -e tcp.analysis.lost_segment -e tcp.analysis.ack_lost_segment \
		> "$OUT/an-$b.tsv" 2> /dev/null &
	wait
	"$SC" compare "$OUT/o-$b.txt" "$OUT/tf-$b.tsv" "$OUT/an-$b.tsv" > "$OUT/cmp-$b.txt"
	crc=$?
	hgl=$(grep '^httpgrep ' "$OUT/cmp-$b.txt")
	tsl=$(grep '^tshark ' "$OUT/cmp-$b.txt")
	v() { echo "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2}'; }
	printf '%-40s %8s %8s %6s %8s %9s %9s %9s %9s\n' "$b" "$ex" "$(v "$hgl" complete)" "$(v "$hgl" no-request)" \
		"$(v "$hgl" no-response)" "$(v "$hgl" incomplete-only)" "$(v "$tsl" complete)" "$(v "$tsl" no-response)" \
		"$(v "$tsl" no-request)" >> "$TABLE"
	say "tshark $b: ports=[${ports% }] $(grep '^diff ' "$OUT/cmp-$b.txt" | sed 's/^diff *//')"
	grep '^category ' "$OUT/cmp-$b.txt" | sed "s/^/  $b /" | tee -a "$SUMMARY"
	if [ "$crc" = 0 ]; then
		pass "$b: every per-connection difference vs tshark is explained ($(grep '^differing' "$OUT/cmp-$b.txt"))"
	else
		fail "$b: unexplained differences vs tshark ($(grep '^differing' "$OUT/cmp-$b.txt")); examples in $OUT/cmp-$b.txt"
	fi
done 3< "$SAMPLES"
cat "$TABLE" | tee -a "$SUMMARY"

# ---- 111.pcap：--cpus 4 与 --cpus 1 的块集合 ----
F111=$(sample 111)
run_hg 111-cpus1 "$F111" --cpus 1
run_hg 111-cpus4 "$F111" --cpus 4
for c in 1 4; do
	s=$OUT/s-111-cpus$c.txt
	say "stats 111 --cpus $c: exit=$(cat "$OUT/rc-111-cpus$c.txt") elapsed=$(stat elapsed "$s") throughput=$(stat throughput "$s") exchanges=$(stat exchanges "$s") maxrss=$(awk '/maximum resident set size/{printf "%.1f MiB", $1/1048576}' "$s") real=$(awk '/ real /{print $1 "s"}' "$s")"
done
"$SC" blocks "$OUT/o-111-cpus1.txt" "$OUT/o-111-cpus4.txt" > "$OUT/blocks-111.txt"
brc=$?
# 另按题面做一遍：整份输出排序后的 sha256（只作记录，块内多行排序后也应相同）。
s1=$(sort "$OUT/o-111-cpus1.txt" | shasum -a 256 | cut -c1-64)
s4=$(sort "$OUT/o-111-cpus4.txt" | shasum -a 256 | cut -c1-64)
if [ "$brc" = 0 ] && [ "$s1" = "$s4" ]; then
	pass "111 --cpus 4 vs --cpus 1: same block set ($(head -1 "$OUT/blocks-111.txt")); sorted-lines sha256 $s1"
else
	fail "111 --cpus 4 vs --cpus 1: $(head -1 "$OUT/blocks-111.txt"); sorted-lines sha256 cpus1=$s1 cpus4=$s4"
fi
if cmp -s "$OUT/o-111-cpus1.txt" "$OUT/o-111-cpus4.txt"; then
	say "INFO 111 --cpus 4 output is byte-identical to --cpus 1"
else
	say "INFO 111 --cpus 4 output order differs from --cpus 1 (allowed)"
fi

echo
if [ "$FAILS" = 0 ]; then
	say "RESULT PASS (details in $OUT)"
	exit 0
fi
say "RESULT FAIL: $FAILS check(s) failed (details in $OUT)"
exit 1
