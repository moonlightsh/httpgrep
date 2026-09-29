package run_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"httpgrep/internal/pcapgen"
	"httpgrep/internal/run"
)

// 普通文件输入：读完整份抓包，命中的交互整块写到 Stdout，matched 为真。
func TestRunFileOutputsMatchedExchange(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n"))
		c2 := pcapgen.NewConn(w, cli2, srv)
		c2.Handshake(ms(20))
		c2.ClientSend(ms(21), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c2.ServerSend(ms(22), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	var out bytes.Buffer
	matched, _, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "TOKEN-42")})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("matched = false, want true")
	}
	check(t, out.String(), "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 12.0ms\n"+
		"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n")
}

// 输入远大于一批（256 KiB）和整个批次池：包跨批次、批次复用之后，
// 每个交互的数据都不能串。400 个交互共约 1.7 MB，命中其中 4 个。
func TestRunLargeInputAcrossBatches(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		for i := range 400 {
			body := fmt.Sprintf("row-%03d:", i) + strings.Repeat("a", 3992)
			c.ClientSend(ms(float64(i*10)), fmt.Appendf(nil, "GET /%d HTTP/1.1\r\n\r\n", i))
			c.ServerSend(ms(float64(i*10+1)), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n"+body))
		}
	})
	var out bytes.Buffer
	matched, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "-E", "row-.07:")})
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("a", 3992)
	block := func(ts, i, row string) string {
		return "2026-09-28 " + ts + " 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n" +
			"GET /" + i + " HTTP/1.1\r\n\r\n" +
			"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\nrow-" + row + ":" + pad + "\n"
	}
	check(t, out.String(), block("15:30:12.415", "7", "007")+"--\n"+
		block("15:30:13.415", "107", "107")+"--\n"+
		block("15:30:14.415", "207", "207")+"--\n"+
		block("15:30:15.415", "307", "307"))
	if !matched || st.Exchanges != 400 || st.Matched != 4 {
		t.Fatalf("matched %v, stats %+v", matched, st)
	}
}

// 时钟不倒退：抓包里时间戳变小的包，按已经到达的最大时间戳交给引擎。
// 连接 2 的包排在连接 1 之后，时间戳却早 2 秒，它的交互按 15:30:15.347 计，耗时 0。
func TestRunClockNeverGoesBack(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(2999))
		c.ClientSend(ms(3000), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(3002), []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT"))
		c2 := pcapgen.NewConn(w, cli2, srv)
		c2.Handshake(ms(999))
		c2.ClientSend(ms(1000), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c2.ServerSend(ms(1005), []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT"))
	})
	var out bytes.Buffer
	_, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "HIT")})
	if err != nil {
		t.Fatal(err)
	}
	check(t, out.String(), "2026-09-28 15:30:15.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /a HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT\n--\n"+
		"2026-09-28 15:30:15.347 10.0.0.1:52815 -> 10.0.0.2:80 complete 0.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT\n")
	if st.Complete != 2 {
		t.Fatalf("stats %+v", st)
	}
}
