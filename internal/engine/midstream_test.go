package engine_test

import (
	"testing"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 没看到 SYN 的连接，第一个包是客户端的请求：按内容判定发请求行的一方是客户端，交互照常输出。
func TestMidStreamRequestFirst(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
		c.ServerSend(ms(4), []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nTOKEN-42"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 4.0ms\n"+
		"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nTOKEN-42\n")
	if st.Connections != 1 || st.MidStream != 1 || st.Exchanges != 1 || st.Complete != 1 || st.Orphans != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 没看到 SYN，第一个包是某个响应 body 的中间部分：这些字节丢弃，计入 Orphans，
// 即使里面有关键词也不输出。之后的请求和响应照常配对。
func TestMidStreamResponseBodyFirst(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.ServerSend(ms(0), []byte("tail of an earlier body TOKEN-0\nmore\n"))
		c.ClientSend(ms(10), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-1"))
	})
	check(t, out, "2026-09-28 15:30:12.355 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-1\n")
	if st.MidStream != 1 || st.Exchanges != 1 || st.Complete != 1 || st.Orphans != 1 || st.Desyncs != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 没看到 SYN，第一个完整的消息是响应，它的请求没抓到：输出一块 no-request，
// 定位行时间用响应第一个包的时间，没有耗时。之后的交互照常配对。
func TestMidStreamResponseFirst(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.ServerSend(ms(0), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"))
		c.ServerSend(ms(1), []byte("TOKEN-0"))
		c.ClientSend(ms(10), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-request\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-0\n"+
		"--\n"+
		"2026-09-28 15:30:12.355 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.MidStream != 1 || st.Exchanges != 2 || st.NoRequest != 1 || st.Complete != 1 || st.Orphans != 0 {
		t.Fatalf("stats: %+v", st)
	}
}
