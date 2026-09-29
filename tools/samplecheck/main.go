// Command samplecheck 是 scripts/compare-tshark.sh 的辅助程序，只在验证阶段使用。
//
// 它读取 httpgrep 的输出文件和 tshark 导出的字段文件，按连接比较交互计数；
// 或者比较两份 httpgrep 输出的块集合。为了不泄露抓包里的生产数据，
// 它只打印计数、tcp.stream 编号、客户端端口、时间、状态和 sha256，
// 从不打印 IP、URL、头部或 body。
//
// 用法：
//
//	samplecheck compare HTTPGREP_OUT TSHARK_TSV ANOMALY_TSV
//	    # 退出码 0 表示每条连接的差异都能归入已知的 tshark 口径差异（见 explain）
//	samplecheck blocks OUT_A OUT_B                # 退出码 0 表示块集合相同
//	samplecheck locators HTTPGREP_OUT             # 统计各状态的块数
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	var code int
	switch os.Args[1] {
	case "compare":
		if len(os.Args) != 5 {
			usage()
		}
		code = compare(os.Args[2], os.Args[3], os.Args[4])
	case "blocks":
		if len(os.Args) != 4 {
			usage()
		}
		code = blocks(os.Args[2], os.Args[3])
	case "locators":
		code = locators(os.Args[2])
	default:
		usage()
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: samplecheck compare HG_OUT TSHARK_TSV ANOMALY_TSV | blocks A B | locators HG_OUT")
	os.Exit(2)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "samplecheck:", err)
	os.Exit(2)
}

// locatorRe 匹配每块的第一行（定位行）：日期 时间 客户端 -> 服务端 状态 [耗时]。
var locatorRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (\S+) -> (\S+) (\S+)( [0-9.]+ms)?$`)

// block 是一个输出块的摘要，不保留内容本身。
type block struct {
	time, client, server, status string
	sum                          string
}

// readBlocks 逐行读取 httpgrep 输出并切块。只有后面紧跟定位行的 "--" 才算分隔行，
// 这样 body 里恰好是 "--" 的行不会被误切。fn 对每块调用一次。
func readBlocks(path string, fn func(b block)) (bad int) {
	f, err := os.Open(path)
	if err != nil {
		die(err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	var cur *block
	h := sha256.New()
	pendingSep := false
	finish := func() {
		if cur != nil {
			cur.sum = hex.EncodeToString(h.Sum(nil))
			fn(*cur)
		}
		h.Reset()
		cur = nil
	}
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			trim := strings.TrimSuffix(string(line), "\n")
			isLoc := locatorRe.MatchString(trim)
			if cur == nil || (pendingSep && isLoc) {
				if cur == nil && !isLoc {
					bad++ // 文件开头不是定位行
				}
				finish()
				m := locatorRe.FindStringSubmatch(trim)
				cur = &block{}
				if m != nil {
					cur.time, cur.client, cur.server, cur.status = m[1], m[2], m[3], m[4]
				}
				pendingSep = false
				h.Write(line)
				continue
			}
			if pendingSep {
				h.Write([]byte("--\n"))
				pendingSep = false
			}
			if trim == "--" {
				pendingSep = true
				continue
			}
			h.Write(line)
		}
		if err != nil {
			break
		}
	}
	if pendingSep {
		h.Write([]byte("--\n"))
	}
	finish()
	return bad
}

// blocks 比较两份输出的块集合（多重集合），块的顺序不限。
func blocks(a, b string) int {
	count := func(path string) (map[string]int, int, int) {
		m := map[string]int{}
		n := 0
		bad := readBlocks(path, func(bl block) { m[bl.sum]++; n++ })
		return m, n, bad
	}
	ma, na, ba := count(a)
	mb, nb, bb := count(b)
	onlyA, onlyB := 0, 0
	for k, v := range ma {
		if d := v - mb[k]; d > 0 {
			onlyA += d
		}
	}
	for k, v := range mb {
		if d := v - ma[k]; d > 0 {
			onlyB += d
		}
	}
	setHash := func(m map[string]int) string {
		keys := make([]string, 0, len(m))
		for k, v := range m {
			for i := 0; i < v; i++ {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		s := sha256.Sum256([]byte(strings.Join(keys, "\n")))
		return hex.EncodeToString(s[:])
	}
	fmt.Printf("blocks_a=%d blocks_b=%d only_a=%d only_b=%d bad_start_a=%d bad_start_b=%d\n", na, nb, onlyA, onlyB, ba, bb)
	fmt.Printf("set_sha256_a=%s\nset_sha256_b=%s\n", setHash(ma), setHash(mb))
	if onlyA != 0 || onlyB != 0 || ba != 0 || bb != 0 {
		return 1
	}
	return 0
}

// locators 按状态统计块数。
func locators(path string) int {
	st := map[string]int{}
	n := 0
	bad := readBlocks(path, func(bl block) { st[bl.status]++; n++ })
	keys := make([]string, 0, len(st))
	for k := range st {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("blocks=%d bad_start=%d\n", n, bad)
	for _, k := range keys {
		fmt.Printf("status %s %d\n", k, st[k])
	}
	return 0
}

// conn 汇总一条连接（按无序四元组）上两边的计数。
type conn struct {
	hgC, hgN, hgR, hgI int // complete / no-response / 含 no-request / 仅 incomplete
	hgRI               int // no-request,incomplete（hgR 的子集）
	hgStatus           map[string]int
	tsC, tsN, tsR      int
	streams            map[int]bool
	clientPort         string
	firstHG            string
	firstFrame         int
	firstTS            float64
}

// endpoint 把 "1.2.3.4:80" 或 "[::1]:80" 拆成 ip 和端口。
func endpoint(s string) (string, string) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, ""
	}
	return strings.Trim(s[:i], "[]"), s[i+1:]
}

func key(ip1, p1, ip2, p2 string) string {
	a, b := ip1+"|"+p1, ip2+"|"+p2
	if a > b {
		a, b = b, a
	}
	return a + "#" + b
}

func countTrue(s string) int {
	n := 0
	for _, v := range strings.Split(s, ",") {
		if v == "True" || v == "1" {
			n++
		}
	}
	return n
}

func countItems(s string) int {
	if s == "" {
		return 0
	}
	return len(strings.Split(s, ","))
}

func first(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		return s[:i]
	}
	return s
}

func compare(hgPath, tsPath, anPath string) int {
	syn, anom := readAnomalies(anPath)
	conns := map[string]*conn{}
	get := func(k string) *conn {
		c := conns[k]
		if c == nil {
			c = &conn{hgStatus: map[string]int{}, streams: map[int]bool{}}
			conns[k] = c
		}
		return c
	}
	var hgC, hgN, hgR, hgI, blocksN int
	bad := readBlocks(hgPath, func(b block) {
		blocksN++
		cip, cp := endpoint(b.client)
		sip, sp := endpoint(b.server)
		c := get(key(cip, cp, sip, sp))
		c.clientPort = cp
		if c.firstHG == "" {
			c.firstHG = b.time
		}
		c.hgStatus[b.status]++
		switch {
		case b.status == "complete":
			c.hgC++
			hgC++
		case strings.Contains(b.status, "no-request"):
			c.hgR++
			if strings.Contains(b.status, "incomplete") {
				c.hgRI++
			}
			hgR++
		case strings.Contains(b.status, "no-response"):
			c.hgN++
			hgN++
		default: // 仅 incomplete：请求在，响应没收完
			c.hgI++
			hgI++
		}
	})
	f, err := os.Open(tsPath)
	if err != nil {
		die(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var tsC, tsN, tsR int
	for sc.Scan() {
		fl := strings.Split(sc.Text(), "\t")
		if len(fl) < 13 {
			continue
		}
		nReq, nResp := countTrue(fl[9]), countTrue(fl[10])
		if nReq == 0 && nResp == 0 {
			continue // 续传帧等，不是消息
		}
		src, dst := first(fl[3]), first(fl[6])
		if src == "" {
			src, dst = first(fl[4]), first(fl[7])
		}
		sp, dp := first(fl[5]), first(fl[8])
		c := get(key(src, sp, dst, dp))
		if st, err := strconv.Atoi(first(fl[2])); err == nil {
			c.streams[st] = true
		}
		if c.firstFrame == 0 {
			c.firstFrame, _ = strconv.Atoi(fl[0])
			c.firstTS, _ = strconv.ParseFloat(fl[1], 64)
		}
		if c.clientPort == "" {
			if nReq > 0 {
				c.clientPort = sp
			} else {
				c.clientPort = dp
			}
		}
		ri, qi := countItems(fl[11]), countItems(fl[12])
		if ri > nReq {
			ri = nReq
		}
		if qi > nResp {
			qi = nResp
		}
		c.tsC += ri
		c.tsN += nReq - ri
		c.tsR += nResp - qi
		tsC += ri
		tsN += nReq - ri
		tsR += nResp - qi
	}
	if err := sc.Err(); err != nil {
		die(err)
	}
	fmt.Printf("httpgrep blocks=%d bad_start=%d complete=%d no-response=%d no-request=%d incomplete-only=%d\n", blocksN, bad, hgC, hgN, hgR, hgI)
	fmt.Printf("tshark   complete=%d no-response=%d no-request=%d\n", tsC, tsN, tsR)
	fmt.Printf("diff     complete=%+d no-response=%+d (with incomplete-only: %+d) no-request=%+d\n", hgC-tsC, hgN-tsN, hgN+hgI-tsN, hgR-tsR)
	unexplained := report(conns, syn, anom)
	fmt.Printf("raw_equal=%v unexplained_connections=%d\n", hgC == tsC && hgN+hgI == tsN && hgR == tsR, unexplained)
	if unexplained == 0 && bad == 0 {
		return 0
	}
	return 1
}

func sign(n int) string {
	switch {
	case n > 0:
		return "+"
	case n < 0:
		return "-"
	}
	return "="
}

func minStream(c *conn) int {
	m := 1 << 30
	for s := range c.streams {
		if s < m {
			m = s
		}
	}
	return m
}

func streamList(c *conn) string {
	var s []int
	for k := range c.streams {
		s = append(s, k)
	}
	sort.Ints(s)
	var out []string
	for _, v := range s {
		out = append(out, strconv.Itoa(v))
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

func statusList(m map[string]int) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", k, m[k])
	}
	return b.String()
}

func tsTime(t float64) string {
	if t == 0 {
		return "-"
	}
	sec := int64(t)
	return time.Unix(sec, int64((t-float64(sec))*1e9)).Format("2006-01-02 15:04:05.000")
}

// readAnomalies 读 tshark 导出的 "tcp.stream \t tcp.flags.syn \t 重传 \t 乱序 \t 丢段 \t 确认了未抓到的段"，
// 返回看到过 SYN 的流，以及 tshark 自己报告了重传、乱序或丢段的流。
func readAnomalies(path string) (syn, anom map[int]bool) {
	syn, anom = map[int]bool{}, map[int]bool{}
	f, err := os.Open(path)
	if err != nil {
		die(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Split(sc.Text(), "\t")
		st, err := strconv.Atoi(first(fl[0]))
		if err != nil {
			continue
		}
		if len(fl) > 1 && (first(fl[1]) == "True" || first(fl[1]) == "1") {
			syn[st] = true
		}
		for _, v := range fl[2:] {
			if v != "" {
				anom[st] = true
			}
		}
	}
	return syn, anom
}

// explain 判断一条连接上的差异能否归入已知的 tshark 口径差异：
//
//	E1 响应只收到一部分（httpgrep 标 incomplete）：tshark 等不到完整的 PDU，不输出这条消息。
//	   所以 no-request,incomplete 在 tshark 里可以不存在；incomplete（有请求）对应 tshark 的无响应请求。
//	E2 tshark 重组失败：连接上有 tshark 自己报告的重传/乱序/丢段，httpgrep 配成 complete，
//	   tshark 却把请求算成没有响应。
//	E3 开始抓包前已建立的连接（没有 SYN）：tshark 把开头截断的数据当成上一条消息的续传，
//	   后面真正的请求被吞掉，响应在 tshark 里就成了缺请求。
//	E4 开始抓包前已建立、且 tshark 报告了重传/乱序/丢段的连接：开头那个完整的缺请求响应
//	   因为乱序没被 tshark 重组出来（打开 tcp.reassemble_out_of_order 后 tshark 也能看到）。
//
// 返回说明标签；有无法解释的部分时标签以 UNEXPLAINED 开头。
func explain(c *conn, syn, anom map[int]bool) string {
	dC, dN, dR := c.hgC-c.tsC, c.hgN+c.hgI-c.tsN, c.hgR-c.tsR
	var why []string
	if dR > 0 && dR <= c.hgRI {
		dR = 0
		why = append(why, "E1")
	}
	hasAnom, midStream := false, len(c.streams) == 0
	for s := range c.streams {
		if anom[s] {
			hasAnom = true
		}
		if !syn[s] {
			midStream = true
		}
	}
	if dC > 0 && dN <= 0 && dR <= 0 && dC == -(dN+dR) {
		ok := true
		if dN < 0 {
			ok = ok && hasAnom
			why = append(why, "E2")
		}
		if dR < 0 {
			ok = ok && midStream
			why = append(why, "E3")
		}
		if ok {
			return strings.Join(why, "+")
		}
		return "UNEXPLAINED(" + strings.Join(why, "+") + " preconditions not met)"
	}
	if dC == 0 && dN == 0 && dR > 0 && hasAnom && midStream {
		return strings.Join(append(why, "E4"), "+")
	}
	if dC == 0 && dN == 0 && dR == 0 {
		return strings.Join(why, "+")
	}
	return "UNEXPLAINED"
}

// report 按差异的正负组合和解释标签给连接分类，每类最多举 5 个例子；返回无法解释的连接数。
func report(conns map[string]*conn, syn, anom map[int]bool) int {
	type cat struct {
		n, dC, dN, dR int
		ex            []*conn
	}
	cats := map[string]*cat{}
	total, unexplained := 0, 0
	for _, c := range conns {
		dC, dN, dR := c.hgC-c.tsC, c.hgN+c.hgI-c.tsN, c.hgR-c.tsR
		if dC == 0 && dN == 0 && dR == 0 {
			continue
		}
		total++
		why := explain(c, syn, anom)
		if strings.HasPrefix(why, "UNEXPLAINED") {
			unexplained++
		}
		sig := "complete" + sign(dC) + " no-response" + sign(dN) + " no-request" + sign(dR) + " => " + why
		if len(c.streams) == 0 {
			sig += " (no tshark http)"
		}
		k := cats[sig]
		if k == nil {
			k = &cat{}
			cats[sig] = k
		}
		k.n++
		k.dC += dC
		k.dN += dN
		k.dR += dR
		k.ex = append(k.ex, c)
	}
	sigs := make([]string, 0, len(cats))
	for s := range cats {
		sigs = append(sigs, s)
	}
	sort.Slice(sigs, func(i, j int) bool {
		if cats[sigs[i]].n != cats[sigs[j]].n {
			return cats[sigs[i]].n > cats[sigs[j]].n
		}
		return sigs[i] < sigs[j]
	})
	fmt.Printf("differing connections=%d unexplained=%d categories=%d\n", total, unexplained, len(cats))
	for _, s := range sigs {
		k := cats[s]
		fmt.Printf("category [%s] connections=%d sum_diff complete=%+d no-response=%+d no-request=%+d\n", s, k.n, k.dC, k.dN, k.dR)
		sort.Slice(k.ex, func(i, j int) bool {
			if a, b := minStream(k.ex[i]), minStream(k.ex[j]); a != b {
				return a < b
			}
			return k.ex[i].clientPort < k.ex[j].clientPort
		})
		for i, c := range k.ex {
			if i == 5 {
				break
			}
			fmt.Printf("  example streams=%s cport=%s hg_first=%s ts_first_frame=%d ts_first=%s hg{%s} ts{complete=%d no-response=%d no-request=%d}\n",
				streamList(c), c.clientPort, c.firstHG, c.firstFrame, tsTime(c.firstTS), statusList(c.hgStatus), c.tsC, c.tsN, c.tsR)
		}
	}
	return unexplained
}
