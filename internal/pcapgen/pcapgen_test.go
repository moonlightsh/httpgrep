package pcapgen_test

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
