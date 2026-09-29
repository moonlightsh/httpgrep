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

// HEAD 请求的响应带 Content-Length: 1000 但没有 body；下一个交互照常解析。
func TestHeadResponseHasNoBody(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("HEAD /a HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 200 OK\r\nX-Id: TOKEN-1\r\nContent-Length: 1000\r\n\r\n"))
		c.ClientSend(ms(10), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+
		"HEAD /a HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nX-Id: TOKEN-1\r\nContent-Length: 1000\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:12.355 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2\n")
	if st.Complete != 2 {
		t.Fatalf("stats: %+v", st)
	}
}

// 两条连接交错传输：后开始但先结束的交互先输出。
func TestInterleavedConnsOutputInFinishOrder(t *testing.T) {
	out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		a := pcapgen.NewConn(w, cli1, srv)
		b := pcapgen.NewConn(w, cli2, srv)
		a.Handshake(ms(-2))
		b.Handshake(ms(-1))
		a.ClientSend(ms(0), []byte("GET /slow HTTP/1.1\r\n\r\n"))
		b.ClientSend(ms(1), []byte("GET /fast HTTP/1.1\r\n\r\n"))
		a.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN"))
		b.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-B"))
		a.ServerSend(ms(20), []byte("-SLOW"))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52815 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /fast HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-B\n"+
		"--\n"+
		"2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 20.0ms\n"+
		"GET /slow HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN-SLOW\n")
}

// 二进制 body 输出占位行：body 含 NUL 且关键词在 body 里时带 matched；
// 带 Content-Encoding 时行里写上编码。
func TestBinaryBodyPlaceholder(t *testing.T) {
	cases := []struct {
		name, keyword, req, res, want string
	}{
		{
			name:    "NUL, match in body",
			keyword: "TOKEN",
			req:     "GET /a HTTP/1.1\r\n\r\n",
			res:     "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 9\r\n\r\nab\x00TOKEN\n",
			want: "GET /a HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 9\r\n\r\n" +
				"[binary body omitted: application/octet-stream, 9 B, matched]\n",
		},
		{
			name:    "NUL, match in head only",
			keyword: "TOKEN",
			req:     "GET /TOKEN HTTP/1.1\r\n\r\n",
			res:     "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na\x00b",
			want: "GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" +
				"[binary body omitted: 3 B]\n",
		},
		{
			name:    "NUL, match in head and body",
			keyword: "TOKEN",
			req:     "GET /TOKEN HTTP/1.1\r\n\r\n",
			res:     "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n\x00TOKEN\x01",
			want: "GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n" +
				"[binary body omitted: 7 B, matched]\n",
		},
		{
			name:    "gzip",
			keyword: "TOKEN",
			req:     "GET /TOKEN HTTP/1.1\r\n\r\n",
			res:     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello",
			want: "GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\n" +
				"[binary body omitted: gzip, application/json, 5 B]\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := replay(t, engine.Config{Matcher: matcher(t, tc.keyword)}, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte(tc.req))
				c.ServerSend(ms(1), []byte(tc.res))
			})
			check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+tc.want)
		})
	}
}

// 读到关闭为止的响应：服务端 FIN 之后是 complete，耗时算到 FIN 那个包。
func TestReadUntilCloseResponse(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.0\r\n\r\n"))
		c.ServerSend(ms(2), []byte("HTTP/1.0 200 OK\r\n\r\nTOKEN"))
		c.ServerSend(ms(3), []byte("-42\n"))
		c.ServerFin(ms(5))
		c.ClientFin(ms(6))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 5.0ms\n"+
		"GET /a HTTP/1.0\r\n\r\n"+
		"HTTP/1.0 200 OK\r\n\r\nTOKEN-42\n")
	if st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 服务端 FIN 或 RST 之后，在途交互随之结束：没收到响应的是 no-response(closed)，
// 响应收到一半的是 incomplete。同一四元组上出现新连接时，旧连接按同样规则处理。
func TestConnectionClosed(t *testing.T) {
	cases := []struct {
		name               string
		build              func(w *pcapgen.Writer)
		want               string
		closed, incomplete int64 // Stats.NoResponseClosed、Stats.Incomplete
	}{
		{
			name: "server FIN before responses",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("GET /TOKEN-A HTTP/1.1\r\n\r\n"))
				c.ServerFin(ms(5))
				c.ClientSend(ms(6), []byte("GET /TOKEN-B HTTP/1.1\r\n\r\n"))
				c.ClientFin(ms(7))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"GET /TOKEN-A HTTP/1.1\r\n\r\n" +
				"--\n" +
				"2026-09-28 15:30:12.351 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"GET /TOKEN-B HTTP/1.1\r\n\r\n",
			closed: 2, incomplete: 0,
		},
		{
			// 请求 body 发到一半时服务端 FIN：等请求发完再以 no-response(closed) 结束。
			name: "server FIN in the middle of a request",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcde"))
				c.ServerFin(ms(2))
				c.ClientSend(ms(3), []byte("fghij"))
				c.ClientFin(ms(4))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcdefghij\n",
			closed: 1, incomplete: 0,
		},
		{
			// 服务端提前回完响应，请求没发完连接就断了：incomplete。
			name: "RST after early response, request unfinished",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcde"))
				c.ServerSend(ms(2), []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"))
				c.ClientRst(ms(3))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 2.0ms\n" +
				"POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcde\n" +
				"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n",
			closed: 0, incomplete: 1,
		},
		{
			name: "RST before response",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
				c.ClientRst(ms(3))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n",
			closed: 1, incomplete: 0,
		},
		{
			name: "RST in the middle of a response",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN"))
				c.ClientRst(ms(8))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 2.0ms\n" +
				"GET /a HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN\n",
			closed: 0, incomplete: 1,
		},
		{
			name: "RST after 100 Continue",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("PUT /TOKEN HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))
				c.ServerSend(ms(1), []byte("HTTP/1.1 100 Continue\r\n\r\n"))
				c.ClientRst(ms(4))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"PUT /TOKEN HTTP/1.1\r\nContent-Length: 0\r\n\r\n" +
				"HTTP/1.1 100 Continue\r\n\r\n",
			closed: 1, incomplete: 0,
		},
		{
			name: "replaced before response",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("GET /TOKEN-OLD HTTP/1.1\r\n\r\n"))
				n := pcapgen.NewConn(w, cli1, srv)
				n.ClientISN, n.ServerISN = 5000000, 6000000
				n.Handshake(ms(10))
				n.ClientSend(ms(11), []byte("GET /TOKEN-NEW HTTP/1.1\r\n\r\n"))
				n.ServerSend(ms(12), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"GET /TOKEN-OLD HTTP/1.1\r\n\r\n" +
				"--\n" +
				"2026-09-28 15:30:12.356 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n" +
				"GET /TOKEN-NEW HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 204 No Content\r\n\r\n",
			closed: 1, incomplete: 0,
		},
		{
			name: "replaced in the middle of a response",
			build: func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nTOKEN\r\n"))
				n := pcapgen.NewConn(w, cli1, srv)
				n.ClientISN, n.ServerISN = 5000000, 6000000
				n.Handshake(ms(10))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 3.0ms\n" +
				"GET /a HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nTOKEN\r\n",
			closed: 0, incomplete: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, tc.build)
			check(t, out, tc.want)
			if st.NoResponseClosed != tc.closed || st.Incomplete != tc.incomplete {
				t.Fatalf("NoResponseClosed %d Incomplete %d, want %d %d", st.NoResponseClosed, st.Incomplete, tc.closed, tc.incomplete)
			}
		})
	}
}

// 只有客户端发了 FIN，之后服务端才回响应：complete。
func TestClientFinThenResponse(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c.ClientFin(ms(1))
		c.ServerSend(ms(4), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		c.ServerFin(ms(5))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 4.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\n")
	if st.Complete != 1 || st.NoResponseClosed != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 101 升级、CONNECT 加 200 之后，连接不再按 HTTP 解析：即使出现关键词也不再输出。
// 带 Upgrade 头的请求得到 400 时继续按 HTTP 解析，下一个请求照常配对。
func TestUpgrade(t *testing.T) {
	// 隧道里看起来像 HTTP 的数据，里面有关键词。
	tunnelData := func(c *pcapgen.Conn) {
		c.ClientSend(ms(20), []byte("GET /TOKEN-IN-TUNNEL HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(21), []byte("HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nTOKEN-IN-TUNNEL"))
	}
	cases := []struct {
		name      string
		build     func(c *pcapgen.Conn)
		want      string
		exchanges int64
	}{
		{
			name: "101 switching protocols",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN\r\n\r\n"))
				c.ServerSend(ms(2), []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"))
				tunnelData(c)
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n" +
				"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN\r\n\r\n" +
				"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
			exchanges: 1,
		},
		{
			name: "CONNECT 200",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("CONNECT TOKEN.example:443 HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(3), []byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				tunnelData(c)
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n" +
				"CONNECT TOKEN.example:443 HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 Connection Established\r\n\r\n",
			exchanges: 1,
		},
		{
			name: "400, next request sent after it",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
				c.ServerSend(ms(2), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
				c.ClientSend(ms(10), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(11), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			},
			want: "2026-09-28 15:30:12.355 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 204 No Content\r\n\r\n",
			exchanges: 2,
		},
		{
			name: "400, next request sent before it",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
				c.ClientSend(ms(1), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(2), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
				c.ServerSend(ms(4), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			},
			want: "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 204 No Content\r\n\r\n",
			exchanges: 2,
		},
		{
			// 400 和下一个请求的响应在同一个段里：下一个请求要在 204 开始之前排进队列。
			name: "400 and next response in one segment",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
				c.ClientSend(ms(1), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(2), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"+
					"HTTP/1.1 204 No Content\r\n\r\n"))
			},
			want: "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 204 No Content\r\n\r\n",
			exchanges: 2,
		},
		{
			// h2c 升级被拒（普通 200），后面管道化的两个请求按序配对。
			name: "h2c refused, pipelined requests after it",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET / HTTP/1.1\r\nUpgrade: h2c\r\n\r\n"))
				c.ClientSend(ms(1), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
				c.ClientSend(ms(2), []byte("GET /TOKEN-3 HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1"+
					"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbody-2"))
				c.ServerSend(ms(4), []byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbody-3"))
			},
			want: "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n" +
				"GET /TOKEN-2 HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbody-2\n" +
				"--\n" +
				"2026-09-28 15:30:12.347 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n" +
				"GET /TOKEN-3 HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbody-3\n",
			exchanges: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				tc.build(c)
			})
			check(t, out, tc.want)
			if st.Exchanges != tc.exchanges || st.Complete != tc.exchanges {
				t.Fatalf("Exchanges %d Complete %d, want %d", st.Exchanges, st.Complete, tc.exchanges)
			}
		})
	}
}

// Finish 时：只有请求没有响应的是 no-response(eof)，响应收到一半的是 incomplete。
func TestFinishEndsInFlight(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		a := pcapgen.NewConn(w, cli1, srv)
		a.Handshake(ms(-1))
		a.ClientSend(ms(0), []byte("GET /TOKEN-A HTTP/1.1\r\n\r\n"))
		b := pcapgen.NewConn(w, cli2, srv)
		b.Handshake(ms(1))
		b.ClientSend(ms(2), []byte("GET /b HTTP/1.1\r\n\r\n"))
		b.ServerSend(ms(6), []byte("HTTP/1.1 200 OK\r\n\r\nTOKEN-B"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n"+
		"GET /TOKEN-A HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:12.347 10.0.0.1:52815 -> 10.0.0.2:80 incomplete 4.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\n\r\nTOKEN-B\n")
	if st.NoResponseEOF != 1 || st.Incomplete != 1 || st.Complete != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 没有 body 的消息即使带 Content-Encoding 也不输出占位行：占位行替换的是 body。
func TestContentEncodingWithoutBody(t *testing.T) {
	cases := []struct{ name, req, res string }{
		{
			name: "HEAD",
			req:  "HEAD /TOKEN HTTP/1.1\r\n\r\n",
			res:  "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1000\r\n\r\n",
		},
		{
			name: "304",
			req:  "GET /TOKEN HTTP/1.1\r\n\r\n",
			res:  "HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\n\r\n",
		},
		{
			name: "Content-Length 0",
			req:  "GET /TOKEN HTTP/1.1\r\n\r\n",
			res:  "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte(tc.req))
				c.ServerSend(ms(1), []byte(tc.res))
			})
			check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+tc.req+tc.res)
		})
	}
}

// 请求 body 还没发完，服务端就回了最终响应（上传时提前回 413、401 很常见）：
// 等请求发完再结束交互，输出完整的请求。响应在请求发完之前就收完，耗时记 0。
func TestResponseBeforeRequestEnds(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcde"))
		c.ServerSend(ms(2), []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"))
		c.ClientSend(ms(5), []byte("fghij"))
		c.ClientSend(ms(6), []byte("GET /next HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(7), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nTOKEN"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 0.0ms\n"+
		"POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcdefghij\n"+
		"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:12.351 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+
		"GET /next HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nTOKEN\n")
	if st.Complete != 2 {
		t.Fatalf("stats: %+v", st)
	}
}

// 请求和响应交错到达时各自按行匹配：请求 body 里跨段的关键词不会被响应打断，
// 响应 body 是否命中也不受请求影响。
func TestInterleavedDirectionsMatch(t *testing.T) {
	t.Run("keyword split around early response", func(t *testing.T) {
		out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), []byte("POST /a HTTP/1.1\r\nContent-Length: 8\r\n\r\nTOK"))
			c.ServerSend(ms(1), []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"))
			c.ClientSend(ms(2), []byte("EN-42"))
		})
		check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 0.0ms\n"+
			"POST /a HTTP/1.1\r\nContent-Length: 8\r\n\r\nTOKEN-42\n"+
			"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
	})
	t.Run("keyword split in binary response body", func(t *testing.T) {
		// 响应的二进制 body 里关键词被请求的字节隔开：占位行要带 matched。
		out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), []byte("POST /a HTTP/1.1\r\nContent-Length: 4\r\n\r\nab"))
			c.ServerSend(ms(1), []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 6\r\n\r\n\x00TOK"))
			c.ClientSend(ms(2), []byte("cd"))
			c.ServerSend(ms(3), []byte("EN"))
		})
		check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+
			"POST /a HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd\n"+
			"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 6\r\n\r\n"+
			"[binary body omitted: 6 B, matched]\n")
	})
}

// Upgrade 请求还没得到最终响应时连接就关闭（或一方 FIN）：请求解析器缓存着的、
// 之后管道化的请求不能丢，要按 HTTP 回放。
func TestUpgradeHeldBytesOnClose(t *testing.T) {
	cases := []struct {
		name  string
		build func(c *pcapgen.Conn)
		want  string
	}{
		{
			// 客户端 FIN 时先不关闭请求解析器，等 400 之后回放完再关。
			name: "client FIN before refusal",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
				c.ClientSend(ms(1), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
				c.ClientFin(ms(2))
				c.ServerSend(ms(3), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
				c.ServerSend(ms(4), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			},
			want: "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n" +
				"HTTP/1.1 204 No Content\r\n\r\n",
		},
		{
			// 输入结束时还没有决定：回放缓存的请求，两个都没有响应。
			name: "finish before decision",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN\r\n\r\n"))
				c.ClientSend(ms(1), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
			},
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n" +
				"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN\r\n\r\n" +
				"--\n" +
				"2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n",
		},
		{
			// RST 时还没有决定：同样先回放，再以 no-response(closed) 结束。
			name: "RST before decision",
			build: func(c *pcapgen.Conn) {
				c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
				c.ClientSend(ms(1), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
				c.ClientRst(ms(2))
			},
			want: "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				tc.build(c)
			})
			check(t, out, tc.want)
		})
	}
}

// 服务端 FIN 时 Upgrade 请求还没有决定：立即回放缓存的请求，它们以 no-response(closed) 结束，
// 不等到输入结束。另一条连接之后才结束的交互排在它们后面输出。
func TestUpgradeHeldBytesOnServerFin(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		a := pcapgen.NewConn(w, cli1, srv)
		a.Handshake(ms(-1))
		a.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
		a.ClientSend(ms(1), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\nGET /TOKEN-2 HTTP/1.1\r\n"))
		a.ServerFin(ms(2))
		a.ClientSend(ms(3), []byte("\r\n"))
		b := pcapgen.NewConn(w, cli2, srv)
		b.Handshake(ms(4))
		b.ClientSend(ms(5), []byte("GET /TOKEN-B HTTP/1.1\r\n\r\n"))
		b.ServerSend(ms(6), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n"+
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n"+
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:12.350 10.0.0.1:52815 -> 10.0.0.2:80 complete 1.0ms\n"+
		"GET /TOKEN-B HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.NoResponseClosed != 3 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// Upgrade 被拒后回放出一个没发完的请求，它的响应提前到达，然后 RST：
// 请求最后一个包的时间是它缓存时的时间（ms1），不是回放发生时的时间（ms2）。
func TestUpgradeReplayedRequestTiming(t *testing.T) {
	out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
		c.ClientSend(ms(1), []byte("POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"))
		c.ServerSend(ms(2), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		c.ServerSend(ms(5), []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"))
		c.ClientRst(ms(6))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 4.0ms\n"+
		"POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc\n"+
		"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
}
