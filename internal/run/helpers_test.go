package run_test

import (
	"bytes"
	"net/netip"
	"os"
	"testing"
	"time"

	"httpgrep/internal/cli"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// loc 是测试固定使用的时区。run 不接收时区参数，输出按 time.Local 渲染，
// 所以 TestMain 把 time.Local 固定成它。
var loc = time.FixedZone("T", 8*3600)

// t0 渲染成 2026-09-28 15:30:12.345。
var t0 = time.Date(2026, 9, 28, 15, 30, 12, 345_000_000, loc)

var (
	cli1 = netip.MustParseAddrPort("10.0.0.1:52814")
	cli2 = netip.MustParseAddrPort("10.0.0.1:52815")
	srv  = netip.MustParseAddrPort("10.0.0.2:80")
)

func TestMain(m *testing.M) {
	time.Local = loc
	os.Exit(m.Run())
}

// ms 返回 t0 之后 n 毫秒的时间。
func ms(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Millisecond))) }

// opts 按命令行参数解析选项。
func opts(t *testing.T, args ...string) cli.Options {
	t.Helper()
	o, err := cli.Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// capture 用 build 生成一份以太网抓包。
func capture(t *testing.T, build func(w *pcapgen.Writer)) []byte {
	t.Helper()
	var b bytes.Buffer
	w := pcapgen.NewWriter(&b, pcap.LinkEthernet)
	build(w)
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// check 比较写出的文本。
func check(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("output mismatch\n--- got ---\n%s\n--- want ---\n%s\n--- got %q\n--- want %q", got, want, got, want)
	}
}
