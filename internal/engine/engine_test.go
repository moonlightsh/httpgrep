package engine_test

import (
	"testing"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 请求 GET，响应 200 带 Content-Length，关键词只在响应 body 里：输出一块 complete。
// 定位行时间是请求第一个包的时间；耗时是响应最后一个包减请求最后一个包（17ms-5ms）。
func TestExchangeComplete(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n"))
		c.ClientSend(ms(5), []byte("Host: x\r\n\r\n"))
		c.ServerSend(ms(10), []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"))
		c.ServerSend(ms(17), []byte("id=TOKEN-42\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 12.0ms\n"+
		"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n")
	if st.Exchanges != 1 || st.Matched != 1 || st.Complete != 1 || st.Connections != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 没有命中时不输出，但交互照样计数。
func TestExchangeNoMatch(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
		c.ServerSend(ms(10), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	})
	check(t, out, "")
	if st.Exchanges != 1 || st.Matched != 0 {
		t.Fatalf("Exchanges %d Matched %d, want 1 0", st.Exchanges, st.Matched)
	}
}

// 关键词只在请求头里，也要输出。
func TestExchangeMatchInRequestHead(t *testing.T) {
	out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nX-Id: TOKEN-42\r\n\r\n"))
		c.ServerSend(ms(3), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /a HTTP/1.1\r\nX-Id: TOKEN-42\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
}
