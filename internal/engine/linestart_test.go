package engine_test

import (
	"testing"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 失步前的字节不以换行结尾时，下一个段开头的起始行照样能重新对齐（http1 把每个段的开头当作行首候选）。

// E2-2 的真实形态：半路连接的第一个包是 JSON body 的结尾，没有换行。
// 之后两个交互照常配对，残余字节计入 Orphans。
func TestMidStreamBodyTailWithoutNewline(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.ServerSend(ms(0), []byte(`"end":1}`))
		c.ClientSend(ms(10), []byte("GET /1 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-1"))
		c.ClientSend(ms(20), []byte("GET /2 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(22), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2"))
	})
	check(t, out, "2026-09-28 15:30:12.355 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /1 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-1\n"+
		"--\n"+
		"2026-09-28 15:30:12.365 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /2 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2\n")
	if st.Exchanges != 2 || st.Complete != 2 || st.Orphans != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// E2-7 的真实形态：同 TestResponseHeadGapDesync，但失步期间的 body 是 "r1"，不以换行结尾。
// 下一个响应在新的段开头，要能重新对齐，不被吞进 /a 的 Unparsed。/a 的响应最后一个包是 ms4 抓到的，耗时 4.0ms。
func TestResponseDesyncTailWithoutNewline(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\n"))
		c.SkipServer(len("Content-Length: 2\r\n"))
		c.ServerSend(ms(4), []byte("X-Id: TOKEN-1\r\n\r\nr1"))
		c.ClientAck(ms(5))
		c.ServerSend(ms(6), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 4.0ms\n"+
		"GET /a HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\n"+
		"[gap: 19 bytes missing]\n"+
		"X-Id: TOKEN-1\r\n\r\nr1\n"+
		"--\n"+
		"2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 5.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2\n")
	if st.Incomplete != 1 || st.Complete != 1 || st.Desyncs != 1 {
		t.Fatalf("stats: %+v", st)
	}
}
