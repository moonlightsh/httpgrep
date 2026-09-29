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
