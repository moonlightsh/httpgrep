package pcapgen_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// tshark 返回 tshark 的路径，不存在时跳过测试。
func tshark(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark 未安装")
	}
	return p
}

// writePcap 在临时目录生成一个 pcap 文件，gen 负责写记录。
func writePcap(t *testing.T, name string, link pcap.LinkType, gen func(w *pcapgen.Writer)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgen.NewWriter(f, link)
	gen(w)
	return path
}

// tsharkFields 以 -T fields 运行 tshark，按行返回字段值。
func tsharkFields(t *testing.T, path string, extra []string, fields ...string) [][]string {
	t.Helper()
	args := []string{"-r", path, "-T", "fields"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	args = append(args, extra...)
	cmd := exec.Command(tshark(t), args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark 执行失败: %v\n%s", err, errb.String())
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows
}

// tsharkOut 运行 tshark 并返回全部标准输出。
func tsharkOut(t *testing.T, path string, args ...string) string {
	t.Helper()
	cmd := exec.Command(tshark(t), append([]string{"-r", path}, args...)...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark 执行失败: %v\n%s", err, errb.String())
	}
	return out.String()
}

// isHexLine 判断一行是否是纯十六进制（偶数个字符，只含 0-9a-f）。
func isHexLine(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// 行为 1：生成的 pcap 能被 tshark 读出，包数、时间戳、地址、端口、
// 序号、确认号和标志位都和写入的一致。
func TestRecordTCPFields(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:12345")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 123456000)
	t1 := t0.Add(1500 * time.Millisecond)
	t2 := t0.Add(2 * time.Second)
	// 192.168.1.1→192.168.1.2 的头部按 16 位字求和会产生进位，
	// 用来覆盖校验和的进位折叠（python 独立算出 0xb77c）。
	carrySrc := netip.MustParseAddrPort("192.168.1.1:1")
	carryDst := netip.MustParseAddrPort("192.168.1.2:2")

	path := writePcap(t, "basic.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		syn := pcapgen.TCP(client, server, 1000, 0, decode.SYN, nil)
		if err := w.Record(t0, pcapgen.Frame(pcap.LinkEthernet, syn), 0); err != nil {
			t.Fatal(err)
		}
		data := pcapgen.TCP(client, server, 1001, 2001, decode.ACK|decode.PSH, []byte("hello"))
		if err := w.Record(t1, pcapgen.Frame(pcap.LinkEthernet, data), 0); err != nil {
			t.Fatal(err)
		}
		carry := pcapgen.TCP(carrySrc, carryDst, 7, 0, decode.SYN, nil)
		if err := w.Record(t2, pcapgen.Frame(pcap.LinkEthernet, carry), 0); err != nil {
			t.Fatal(err)
		}
	})

	rows := tsharkFields(t, path, []string{"-o", "ip.check_checksum:TRUE"},
		"frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
		"tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.len", "ip.checksum", "ip.checksum.status")
	if len(rows) != 3 {
		t.Fatalf("包数 = %d，想要 3", len(rows))
	}
	// 期望值逐字段手写：时间戳只核对到微秒（pcap 的精度）。
	wantTime := []string{"1700000000.123456", "1700000001.623456", "1700000002.123456"}
	want := [][]string{
		{"10.0.0.1", "10.0.0.2", "12345", "80", "1000", "0", "0x0002", "0", "0x26ce", "1"},
		{"10.0.0.1", "10.0.0.2", "12345", "80", "1001", "2001", "0x0018", "5", "0x26c9", "1"},
		{"192.168.1.1", "192.168.1.2", "1", "2", "7", "0", "0x0002", "0", "0xb77c", "1"},
	}
	for i, row := range rows {
		if !strings.HasPrefix(row[0], wantTime[i]) {
			t.Errorf("第 %d 个包时间戳 = %q，想要前缀 %q", i+1, row[0], wantTime[i])
		}
		for j, wv := range want[i] {
			if got := row[j+1]; got != wv {
				t.Errorf("第 %d 个包字段 %d = %q，想要 %q", i+1, j, got, wv)
			}
		}
	}
}

// 行为 2：各种链路层类型和 IPv6 下 tshark 都能解码出 TCP。
func TestFrameLinkTypes(t *testing.T) {
	c4 := netip.MustParseAddrPort("10.0.0.1:12345")
	s4 := netip.MustParseAddrPort("10.0.0.2:80")
	c6 := netip.MustParseAddrPort("[2001:db8::1]:12345")
	s6 := netip.MustParseAddrPort("[2001:db8::2]:80")
	ts := time.Unix(1700000000, 0)

	cases := []struct {
		name string
		link pcap.LinkType
		ip   []byte
		src  string
	}{
		{"ethernet", pcap.LinkEthernet, pcapgen.TCP(c4, s4, 1, 0, decode.SYN, nil), "10.0.0.1"},
		{"sll", pcap.LinkLinuxSLL, pcapgen.TCP(c4, s4, 1, 0, decode.SYN, nil), "10.0.0.1"},
		{"sll2", pcap.LinkLinuxSLL2, pcapgen.TCP(c4, s4, 1, 0, decode.SYN, nil), "10.0.0.1"},
		{"null", pcap.LinkNull, pcapgen.TCP(c4, s4, 1, 0, decode.SYN, nil), "10.0.0.1"},
		{"loop", pcap.LinkLoop, pcapgen.TCP(c4, s4, 1, 0, decode.SYN, nil), "10.0.0.1"},
		{"raw", pcap.LinkRaw, pcapgen.TCP(c4, s4, 1, 0, decode.SYN, nil), "10.0.0.1"},
		{"ipv6", pcap.LinkEthernet, pcapgen.TCP(c6, s6, 1, 0, decode.SYN, nil), "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePcap(t, tc.name+".pcap", tc.link, func(w *pcapgen.Writer) {
				if err := w.Record(ts, pcapgen.Frame(tc.link, tc.ip), 0); err != nil {
					t.Fatal(err)
				}
			})
			rows := tsharkFields(t, path, nil, "ip.src", "ipv6.src", "tcp.srcport", "tcp.flags")
			if len(rows) != 1 {
				t.Fatalf("包数 = %d，想要 1；文件 %s", len(rows), path)
			}
			row := rows[0]
			gotSrc := row[0]
			if gotSrc == "" {
				gotSrc = row[1] // IPv6 时 ip.src 为空，取 ipv6.src
			}
			if gotSrc != tc.src {
				t.Errorf("源地址 = %q，想要 %q", gotSrc, tc.src)
			}
			if row[2] != "12345" || row[3] != "0x0002" {
				t.Errorf("端口/标志 = %q/%q，想要 12345/0x0002", row[2], row[3])
			}
		})
	}
}

// IPv6 包在各链路层下的协议字段：EtherType 0x86dd，Null/Loop 为 AF_INET6（30）。
// decode 按这些字段分发，所以不能只靠 tshark 按版本号猜。
func TestFrameIPv6Protocol(t *testing.T) {
	c6 := netip.MustParseAddrPort("[2001:db8::1]:12345")
	s6 := netip.MustParseAddrPort("[2001:db8::2]:80")
	ts := time.Unix(1700000000, 0)
	cases := []struct {
		name  string
		link  pcap.LinkType
		field string
		want  string
	}{
		{"ethernet", pcap.LinkEthernet, "eth.type", "0x86dd"},
		{"sll", pcap.LinkLinuxSLL, "sll.etype", "0x86dd"},
		{"sll2", pcap.LinkLinuxSLL2, "sll.etype", "0x86dd"},
		{"null", pcap.LinkNull, "null.family", "30"},
		{"loop", pcap.LinkLoop, "null.family", "30"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePcap(t, tc.name+"6.pcap", tc.link, func(w *pcapgen.Writer) {
				ip := pcapgen.TCP(c6, s6, 1, 0, decode.SYN, nil)
				if err := w.Record(ts, pcapgen.Frame(tc.link, ip), 0); err != nil {
					t.Fatal(err)
				}
			})
			rows := tsharkFields(t, path, nil, tc.field, "ipv6.src", "tcp.srcport")
			if len(rows) != 1 {
				t.Fatalf("包数 = %d，想要 1", len(rows))
			}
			want := []string{tc.want, "2001:db8::1", "12345"}
			if !reflect.DeepEqual(rows[0], want) {
				t.Errorf("%s/ipv6.src/tcp.srcport = %v，想要 %v", tc.field, rows[0], want)
			}
		})
	}
}

// 行为 3：握手后 ClientSend 3000 字节切成 1460、1460、80 三段，
// 序号连续，tshark follow 流还原的字节和写入的相同。
func TestConnHandshakeSend(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50000")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)

	path := writePcap(t, "conn.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, client, server)
		c.Handshake(t0)
		payload := make([]byte, 3000)
		for i := range payload {
			payload[i] = byte('A' + i%26)
		}
		c.ClientSend(t0.Add(10*time.Millisecond), payload)
		c.ServerAck(t0.Add(20 * time.Millisecond))
	})

	// 数据段按写入顺序核对序号连续性。
	rows := tsharkFields(t, path, nil, "tcp.flags", "tcp.len", "tcp.seq_raw", "tcp.ack_raw")
	var dataLens []int
	var seqs []uint64
	for _, row := range rows {
		lens := row[1]
		if lens == "0" {
			continue
		}
		n, err := strconv.Atoi(strings.ReplaceAll(lens, ",", ""))
		if err != nil {
			t.Fatalf("tcp.len 字段 %q 无法解析: %v", lens, err)
		}
		dataLens = append(dataLens, n)
		seq, _ := strconv.ParseUint(strings.Split(row[2], ",")[0], 10, 64)
		seqs = append(seqs, seq)
	}
	wantLens := []int{1460, 1460, 80}
	if !reflect.DeepEqual(dataLens, wantLens) {
		t.Fatalf("分段长度 = %v，想要 %v", dataLens, wantLens)
	}
	// ISN 是 1001 的话三段序号是 1001、2461、3921；这里直接验证连续性：
	// 每段序号等于前一段序号加前一段长度。
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+uint64(dataLens[i-1]) {
			t.Errorf("第 %d 段序号 = %d，想要 %d", i, seqs[i], seqs[i-1]+uint64(dataLens[i-1]))
		}
	}

	// tshark follow 流还原客户端方向的字节。raw 模式下：客户端方向的行
	// 顶格写十六进制，服务端方向的行以制表符开头；表头（====、标题、
	// Follow: 等）都不是纯十六进制，按格式精确区分。
	out := tsharkOut(t, path, "-q", "-z", "follow,tcp,raw,0")
	var follow [][]byte
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "\t"):
			continue // 服务端方向
		case !isHexLine(line):
			continue // 表头或空行
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			t.Fatalf("follow 行 %q 不是十六进制: %v", line, err)
		}
		follow = append(follow, b)
	}
	var got []byte
	for _, b := range follow {
		got = append(got, b...)
	}
	want := make([]byte, 3000)
	for i := range want {
		want[i] = byte('A' + i%26)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("follow 还原 %d 字节，和写入的 %d 字节不同", len(got), len(want))
	}
}

// 行为 4：SkipClient 跳过 100 字节后，下一段序号比原来多 100，
// tshark 会标出 tcp.analysis.lost_segment。
func TestConnSkipClient(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50001")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)

	var seqNoSkip, seqSkip string
	path := writePcap(t, "skip.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, client, server)
		c.Handshake(t0)
		c.ClientSend(t0.Add(10*time.Millisecond), []byte("before"))
		seqNoSkip = fmt.Sprint(c.ClientISN + 1 + 6) // 跳过前下一段的序号

		c.SkipClient(100)
		c.ClientSend(t0.Add(20*time.Millisecond), []byte("after"))
		seqSkip = fmt.Sprint(c.ClientISN + 1 + 6 + 100)
	})

	rows := tsharkFields(t, path, nil, "tcp.seq_raw", "tcp.len", "tcp.analysis.lost_segment")
	if len(rows) != 5 {
		t.Fatalf("包数 = %d，想要 5（握手 3 个 + 数据 2 个）", len(rows))
	}
	// 找到带 lost_segment 的段。
	var lost []string
	for _, row := range rows {
		if strings.Contains(row[2], "1") && row[1] != "0" {
			lost = append(lost, row[0])
		}
	}
	if len(lost) == 0 {
		t.Fatalf("没有包被标出 tcp.analysis.lost_segment；字段输出 %q", rows)
	}
	if got := lost[len(lost)-1]; got != seqSkip {
		t.Errorf("丢失段之后的第一段序号 = %s，想要 %s", got, seqSkip)
	}
	if seqNoSkip == seqSkip {
		t.Fatal("对照值相同，测试无意义")
	}
}

// SLL2 头部字段按 LINKTYPE_LINUX_SLL2 的布局写出：
// 协议 0-1、保留 2-3、接口索引 4-7、ARPHRD 8-9、包类型 10、地址长度 11、地址 12-19。
func TestFrameSLL2Layout(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:12345")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	ts := time.Unix(1700000000, 0)
	path := writePcap(t, "sll2layout.pcap", pcap.LinkLinuxSLL2, func(w *pcapgen.Writer) {
		if err := w.Record(ts, pcapgen.Frame(pcap.LinkLinuxSLL2,
			pcapgen.TCP(client, server, 1, 0, decode.SYN, nil)), 0); err != nil {
			t.Fatal(err)
		}
	})
	out := tsharkOut(t, path, "-V")
	for _, want := range []string{
		"Interface index: 1",
		"Link-layer address type: Ethernet (1)",
		"Link-layer address length: 6",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tshark 输出缺少 %q", want)
		}
	}
	if strings.Contains(out, "Interface index: 16777216") {
		t.Errorf("接口索引被写成 16777216（ARPHRD 落到了 4-7 字节）")
	}
}

// ISN 可以在 NewConn 之后设置（包括接近 2^32 的值），
// 握手和数据段的序号都要从 ISN+1 起步；发送数据时确认号自动维护。
func TestConnCustomISN(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50002")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)
	path := writePcap(t, "isn.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, client, server)
		c.ClientISN = 0xFFFFFF00 // 接近回绕点
		c.ServerISN = 9000
		c.Handshake(t0)
		c.ClientSend(t0.Add(10*time.Millisecond), []byte("GET / HTTP/1.1\r\n\r\n")) // 18 字节
		c.ServerSend(t0.Add(20*time.Millisecond), []byte("ok"))                     // 2 字节
		c.ClientSend(t0.Add(30*time.Millisecond), []byte("again"))                  // 5 字节
	})
	rows := tsharkFields(t, path, nil, "tcp.srcport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags")
	if len(rows) != 6 {
		t.Fatalf("包数 = %d，想要 6（3 握手 + 3 数据）", len(rows))
	}
	// 期望值全部手写：客户端 ISN 0xFFFFFF00，服务端 ISN 9000。
	want := [][]string{
		// src, seq, ack, len, flags
		{"50002", "4294967040", "0", "0", "0x0002"},     // SYN
		{"80", "9000", "4294967041", "0", "0x0012"},     // SYN-ACK
		{"50002", "4294967041", "9001", "0", "0x0010"},  // ACK
		{"50002", "4294967041", "9001", "18", "0x0018"}, // 请求数据
		{"80", "9001", "4294967059", "2", "0x0018"},     // 响应数据，ack 确认 18 字节请求
		{"50002", "4294967059", "9003", "5", "0x0018"},  // 后续数据，ack 确认响应
	}
	for i, w := range want {
		got := []string{rows[i][0], rows[i][1], rows[i][2], rows[i][3], rows[i][4]}
		for j := range w {
			if got[j] != w[j] {
				t.Errorf("第 %d 个包字段 %d = %q，想要 %q", i+1, j, got[j], w[j])
			}
		}
	}
}

// 行为 3 的补充：数据段绝对序号紧接握手之后（ISN+1 = 1001、2461、3921），
// 并核对 ack。
func TestConnSendAbsoluteSeq(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50000")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)
	path := writePcap(t, "abs.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, client, server)
		c.Handshake(t0)
		c.ClientSend(t0.Add(10*time.Millisecond), make([]byte, 3000))
	})
	rows := tsharkFields(t, path, nil, "tcp.len", "tcp.seq_raw", "tcp.ack_raw")
	var seqs []uint64
	var acks []string
	for _, row := range rows {
		if row[0] == "0" {
			continue
		}
		seq, _ := strconv.ParseUint(row[1], 10, 64)
		seqs = append(seqs, seq)
		acks = append(acks, row[2])
	}
	wantSeqs := []uint64{1001, 2461, 3921} // ISN+1，每段加前段长度
	if !reflect.DeepEqual(seqs, wantSeqs) {
		t.Errorf("数据段序号 = %v，想要 %v", seqs, wantSeqs)
	}
	for _, ack := range acks {
		if ack != "2001" { // 服务端 ISN+1
			t.Errorf("数据段 ack = %q，想要 2001", ack)
		}
	}
}

// FIN 和 RST 的标志位正确，FIN 消耗一个序号，FIN 之后数据段序号继续推进；
// 纯 ACK、FIN、RST 的确认号都取对端已发送的位置。
func TestConnFinRstSeq(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50003")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)
	path := writePcap(t, "finrst.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, client, server)
		c.Handshake(t0)
		c.ClientSend(t0.Add(10*time.Millisecond), []byte("abc")) // 3 字节，序号到 1004
		c.ServerAck(t0.Add(11 * time.Millisecond))
		c.ServerSend(t0.Add(12*time.Millisecond), []byte("xy")) // 2 字节，服务端到 2003
		c.ClientAck(t0.Add(13 * time.Millisecond))
		c.ClientFin(t0.Add(20 * time.Millisecond)) // 占用 1004，之后 1005
		c.ClientSend(t0.Add(30*time.Millisecond), []byte("d"))
		c.ClientRst(t0.Add(40 * time.Millisecond))
	})
	// 期望值手写：客户端 ISN=1000，服务端 ISN=2000。
	want := [][]string{
		// flags, seq, ack
		{"0x0002", "1000", "0"},    // SYN
		{"0x0012", "2000", "1001"}, // SYN-ACK
		{"0x0010", "1001", "2001"}, // ACK
		{"0x0018", "1001", "2001"}, // 数据 abc
		{"0x0010", "2001", "1004"}, // ServerAck 确认 abc
		{"0x0018", "2001", "1004"}, // 数据 xy
		{"0x0010", "1004", "2003"}, // ClientAck 确认 xy
		{"0x0011", "1004", "2003"}, // ClientFin
		{"0x0018", "1005", "2003"}, // 数据 d
		{"0x0014", "1006", "2003"}, // RST
	}
	rows := tsharkFields(t, path, nil, "tcp.flags", "tcp.seq_raw", "tcp.ack_raw")
	if len(rows) != len(want) {
		t.Fatalf("包数 = %d，想要 %d", len(rows), len(want))
	}
	for i, row := range rows {
		if !reflect.DeepEqual(row, want[i]) {
			t.Errorf("第 %d 个包 flags/seq/ack = %v，想要 %v", i+1, row, want[i])
		}
	}
}

// SkipServer 和 ServerFin 推进服务端序号：之后的服务端数据段序号、
// 客户端 ACK 的确认号都跟着前进。
func TestConnServerSkipFin(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50004")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)
	cases := []struct {
		name string
		gen  func(c *pcapgen.Conn, ts time.Time)
		want [][]string // 握手之后各包的 flags、seq、ack，手写，ISN 1000/2000
	}{
		{
			name: "skip-server",
			gen: func(c *pcapgen.Conn, ts time.Time) {
				c.SkipServer(50) // 服务端 2001 → 2051
				c.ServerSend(ts, []byte("ok"))
				c.ClientAck(ts)
			},
			want: [][]string{
				{"0x0018", "2051", "1001"}, // 数据 ok
				{"0x0010", "1001", "2053"}, // ClientAck 确认 ok
			},
		},
		{
			name: "server-fin",
			gen: func(c *pcapgen.Conn, ts time.Time) {
				c.ServerFin(ts) // 占用 2001，之后 2002
				c.ClientAck(ts)
				c.ServerSend(ts, []byte("z"))
			},
			want: [][]string{
				{"0x0011", "2001", "1001"}, // ServerFin
				{"0x0010", "1001", "2002"}, // ClientAck 确认 FIN
				{"0x0018", "2002", "1001"}, // 数据 z
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePcap(t, tc.name+".pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, client, server)
				c.Handshake(t0)
				tc.gen(c, t0.Add(10*time.Millisecond))
			})
			rows := tsharkFields(t, path, nil, "tcp.flags", "tcp.seq_raw", "tcp.ack_raw")
			if len(rows) != 3+len(tc.want) {
				t.Fatalf("包数 = %d，想要 %d", len(rows), 3+len(tc.want))
			}
			for i, w := range tc.want {
				if got := rows[3+i]; !reflect.DeepEqual(got, w) {
					t.Errorf("握手后第 %d 个包 flags/seq/ack = %v，想要 %v", i+1, got, w)
				}
			}
		})
	}
}

// ClientSend 按 Conn.MSS 切段；MSS 不大于 0 时按默认 1460 切。
func TestConnMSS(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:50005")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 0)
	cases := []struct {
		name string
		mss  int
		n    int
		want []string // 数据段的 seq_raw 和 tcp.len，手写
	}{
		{"mss-500", 500, 1200, []string{"1001:500", "1501:500", "2001:200"}},
		{"mss-0", 0, 3000, []string{"1001:1460", "2461:1460", "3921:80"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePcap(t, tc.name+".pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, client, server)
				c.MSS = tc.mss
				c.Handshake(t0)
				c.ClientSend(t0.Add(10*time.Millisecond), make([]byte, tc.n))
			})
			var got []string
			for _, row := range tsharkFields(t, path, nil, "tcp.seq_raw", "tcp.len") {
				if row[1] != "0" {
					got = append(got, row[0]+":"+row[1])
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("数据段 seq:len = %v，想要 %v", got, tc.want)
			}
		})
	}
}
