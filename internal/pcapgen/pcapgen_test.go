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

// 行为 1：生成的 pcap 能被 tshark 读出，包数、时间戳、地址、端口、
// 序号、确认号和标志位都和写入的一致。
func TestRecordTCPFields(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.1:12345")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	t0 := time.Unix(1700000000, 123456000)
	t1 := t0.Add(1500 * time.Millisecond)

	path := writePcap(t, "basic.pcap", pcap.LinkEthernet, func(w *pcapgen.Writer) {
		syn := pcapgen.TCP(client, server, 1000, 0, decode.SYN, nil)
		if err := w.Record(t0, pcapgen.Frame(pcap.LinkEthernet, syn), 0); err != nil {
			t.Fatal(err)
		}
		data := pcapgen.TCP(client, server, 1001, 2001, decode.ACK|decode.PSH, []byte("hello"))
		if err := w.Record(t1, pcapgen.Frame(pcap.LinkEthernet, data), 0); err != nil {
			t.Fatal(err)
		}
	})

	rows := tsharkFields(t, path, nil,
		"frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
		"tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.len")
	if len(rows) != 2 {
		t.Fatalf("包数 = %d，想要 2", len(rows))
	}
	// 期望值逐字段手写：时间戳只核对到微秒（pcap 的精度）。
	wantTime := []string{"1700000000.123456", "1700000001.623456"}
	want := [][]string{
		{"10.0.0.1", "10.0.0.2", "12345", "80", "1000", "0", "0x0002", "0"},
		{"10.0.0.1", "10.0.0.2", "12345", "80", "1001", "2001", "0x0018", "5"},
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
		n := 0
		for _, ch := range lens {
			if ch != ',' {
				n = n*10 + int(ch-'0')
			}
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

	// tshark follow 流还原客户端方向的字节。
	cmd := exec.Command(tshark(t), "-r", path, "-q", "-z", "follow,tcp,raw,0")
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark follow 失败: %v\n%s", err, errb.String())
	}
	var follow [][]byte
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "\t"))
		if len(line) == 0 || strings.ContainsAny(line[:1], "Cc=\t") {
			continue
		}
		// follow 输出里客户端方向的行不带前缀，服务端方向带制表符；
		// 这里只收集十六进制行。
		if b, err := hex.DecodeString(line); err == nil {
			follow = append(follow, b)
		}
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
	for i, row := range rows {
		if strings.Contains(row[2], "1") && row[1] != "0" {
			lost = append(lost, row[0])
			_ = i
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
