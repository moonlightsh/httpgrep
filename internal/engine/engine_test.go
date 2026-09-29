package engine_test

import (
	"bytes"
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

// 同一连接上的 3 个 keep-alive 交互，只有第 2 个命中，就只输出第 2 个。
func TestKeepAliveOnlyMatchedOutput(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /1 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"))
		c.ClientSend(ms(100), []byte("GET /2 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(102), []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nTOKEN-42"))
		c.ClientSend(ms(200), []byte("GET /3 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(203), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nthree"))
	})
	check(t, out, "2026-09-28 15:30:12.445 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /2 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nTOKEN-42\n")
	if st.Exchanges != 3 || st.Matched != 1 || st.Complete != 3 {
		t.Fatalf("stats: %+v", st)
	}
}

// 管道化：连发两个请求之后才依次收到两个响应，两块的请求和响应要配对正确。
func TestPipelinedPairing(t *testing.T) {
	out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /first HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1), []byte("GET /second HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(10), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-1"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 10.0ms\n"+
		"GET /first HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-1\n"+
		"--\n"+
		"2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 11.0ms\n"+
		"GET /second HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2\n")
}

// chunked 响应：关键词拆在两个 chunk 里也命中，输出保留 chunk 长度行。
// 关键词只出现在 chunk 长度行里（a3f 即 2623 字节的数据，数据里没有 a3f）不算命中。
func TestChunkedMatch(t *testing.T) {
	t.Run("split across chunks", func(t *testing.T) {
		out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
			c.ServerSend(ms(4), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nTOK\r\n"))
			c.ServerSend(ms(6), []byte("5\r\nEN-42\r\n0\r\n\r\n"))
		})
		check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 6.0ms\n"+
			"GET /a HTTP/1.1\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nTOK\r\n5\r\nEN-42\r\n0\r\n\r\n")
	})
	t.Run("only in chunk size line", func(t *testing.T) {
		out, st := replay(t, engine.Config{Matcher: matcher(t, "a3f")}, func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
			c.ServerSend(ms(4), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na3f\r\n"))
			c.ServerSend(ms(5), bytes.Repeat([]byte("x"), 0xa3f))
			c.ServerSend(ms(6), []byte("\r\n0\r\n\r\n"))
		})
		check(t, out, "")
		if st.Exchanges != 1 || st.Complete != 1 {
			t.Fatalf("stats: %+v", st)
		}
	})
}

// 关键词拆在两个 TCP 段里也命中。
func TestMatchSplitAcrossSegments(t *testing.T) {
	out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("POST /a HTTP/1.1\r\nContent-Length: 12\r\n\r\nid=TOK"))
		c.ClientSend(ms(2), []byte("EN-42\n"))
		c.ServerSend(ms(3), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+
		"POST /a HTTP/1.1\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
}

// 100 Continue 之后再 200：输出一块，依次是请求、100 响应、200 响应。
func TestContinueThenFinal(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("PUT /a HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 8\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 100 Continue\r\n\r\n"))
		c.ClientSend(ms(2), []byte("TOKEN-42"))
		c.ServerSend(ms(9), []byte("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 7.0ms\n"+
		"PUT /a HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 8\r\n\r\nTOKEN-42\n"+
		"HTTP/1.1 100 Continue\r\n\r\n"+
		"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	if st.Exchanges != 1 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}
