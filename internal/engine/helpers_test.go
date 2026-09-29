package engine_test

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// loc 是测试固定使用的时区，定位行按它渲染。
var loc = time.FixedZone("T", 8*3600)

// t0 是测试抓包的基准时间，渲染成 2026-09-28 15:30:12.345。
var t0 = time.Date(2026, 9, 28, 15, 30, 12, 345_000_000, loc)

var (
	cli1 = netip.MustParseAddrPort("10.0.0.1:52814")
	cli2 = netip.MustParseAddrPort("10.0.0.1:52815")
	srv  = netip.MustParseAddrPort("10.0.0.2:80")
)

// ms 返回 t0 之后 n 毫秒的时间。
func ms(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Millisecond))) }

// matcher 编译字面关键词。
func matcher(t *testing.T, patterns ...string) *match.Matcher {
	t.Helper()
	m, err := match.Compile(patterns, false)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// replay 用 build 生成抓包，经 pcap.Reader 和 decode.Decode 逐个喂给引擎：
// 每个包之后用它的时间戳调用 Advance，最后以最后一个包的时间调用 Finish。
// Emit 收到的块交给非 TTY 的 output.Writer 渲染，返回渲染出的文本和统计。
// cfg 里为零的 Timeout、MaxMemory、MaxMessage 取命令行的默认值。
func replay(t *testing.T, cfg engine.Config, build func(w *pcapgen.Writer)) (string, engine.Stats) {
	t.Helper()
	var capture bytes.Buffer
	w := pcapgen.NewWriter(&capture, pcap.LinkEthernet)
	build(w)
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	ow := output.NewWriter(&out, output.Options{Location: loc})
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxMemory == 0 {
		cfg.MaxMemory = 256 << 20
	}
	if cfg.MaxMessage == 0 {
		cfg.MaxMessage = 8 << 20
	}
	cfg.Emit = func(b *output.Block) {
		if err := ow.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	e := engine.New(cfg)

	r, err := pcap.NewReader(&capture)
	if err != nil {
		t.Fatal(err)
	}
	var seg decode.Segment
	var last time.Time
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if decode.Decode(r.LinkType(), p.Data, p.OrigLen, &seg) != decode.OK {
			t.Fatalf("packet at %v does not decode", p.Timestamp)
		}
		e.Segment(&seg, p.Timestamp)
		e.Advance(p.Timestamp)
		last = p.Timestamp
	}
	e.Finish(last)
	return out.String(), e.Stats()
}

// check 比较渲染出的文本。
func check(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("output mismatch\n--- got ---\n%s\n--- want ---\n%s\n--- got %q\n--- want %q", got, want, got, want)
	}
}
