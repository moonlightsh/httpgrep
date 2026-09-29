package engine_test

import (
	"bytes"
	"testing"

	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 客户端请求 body（Content-Length）里有缺口：输出缺口标记，状态 incomplete，
// 缺口两边照常匹配；缺口处断行，关键词不会跨过缺口拼起来。
// 服务端在 ms2 的纯 ACK 越过了没抓到的 5 字节，缺口在这时认定，缓存的后半段随之交付，
// 请求在 ms2 发完；响应在 ms5 收完，耗时 3.0ms。
func TestRequestBodyGap(t *testing.T) {
	build := func(before, after string) func(w *pcapgen.Writer) {
		return func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), []byte("POST /a HTTP/1.1\r\nContent-Length: 20\r\n\r\n"+before))
			c.SkipClient(5)
			c.ClientSend(ms(1), []byte(after))
			c.ServerAck(ms(2))
			c.ServerSend(ms(5), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
		}
	}
	t.Run("match after gap", func(t *testing.T) {
		out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, build("abcde", "TOKEN-42ab"))
		check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 3.0ms\n"+
			"POST /a HTTP/1.1\r\nContent-Length: 20\r\n\r\nabcde\n"+
			"[gap: 5 bytes missing]\n"+
			"TOKEN-42ab\n"+
			"HTTP/1.1 204 No Content\r\n\r\n")
		if st.Incomplete != 1 || st.Complete != 0 || st.Gaps != 1 || st.GapBytes != 5 || st.Desyncs != 0 {
			t.Fatalf("stats: %+v", st)
		}
	})
	t.Run("keyword split by gap", func(t *testing.T) {
		out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, build("abTOK", "EN-42abcde"))
		check(t, out, "")
		if st.Exchanges != 1 || st.Matched != 0 || st.Incomplete != 1 {
			t.Fatalf("stats: %+v", st)
		}
	})
}

// 客户端请求头里有缺口：请求方向失步。已经看到请求行的请求把缺口到下一个请求行之间的
// 字节以 Unparsed 收下（照样参与匹配），状态 incomplete；下一个请求正常。
// 缺口在 ms2 服务端的纯 ACK 越过时认定，/a 的请求最后一个包按 ms2 算，耗时 5-2=3.0ms；
// /b 在 ms3 发出，耗时 6-3=3.0ms。
func TestRequestHeadGapDesync(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nHost: x\r\n"))
		c.SkipClient(len("X-Pad: 1234\r\n"))
		c.ClientSend(ms(1), []byte("X-Tok: TOKEN-1\r\n\r\n"))
		c.ServerAck(ms(2))
		c.ClientSend(ms(3), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(5), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nr1"))
		c.ServerSend(ms(6), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 3.0ms\n"+
		"GET /a HTTP/1.1\r\nHost: x\r\n"+
		"[gap: 13 bytes missing]\n"+
		"X-Tok: TOKEN-1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nr1\n"+
		"--\n"+
		"2026-09-28 15:30:12.348 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2\n")
	if st.Incomplete != 1 || st.Complete != 1 || st.Gaps != 1 || st.GapBytes != 13 || st.Desyncs != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 服务端响应头里有缺口：响应方向失步。Unparsed 字节归入正在解析的响应（队首请求的），
// 这个交互 incomplete，重新对齐（看到下一个状态行）时结束；下一个响应和下一个请求配对。
// 缺口在 ms5 客户端的纯 ACK 越过时认定，/a 的响应最后一个包按 ms5 算。
func TestResponseHeadGapDesync(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\n"))
		c.SkipServer(len("Content-Length: 2\r\n"))
		c.ServerSend(ms(4), []byte("X-Id: TOKEN-1\r\n\r\nr\n"))
		c.ClientAck(ms(5))
		c.ServerSend(ms(6), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 5.0ms\n"+
		"GET /a HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\n"+
		"[gap: 19 bytes missing]\n"+
		"X-Id: TOKEN-1\r\n\r\nr\n"+
		"--\n"+
		"2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 5.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-2\n")
	if st.Incomplete != 1 || st.Complete != 1 || st.Desyncs != 1 || st.Gaps != 1 || st.GapBytes != 19 {
		t.Fatalf("stats: %+v", st)
	}
}

// 服务端丢了一整个响应（缺口正好落在两个响应之间）：缺口作为 Orphan 归入队首请求的响应，
// 这个交互 incomplete，响应一个字节都没抓到，不输出耗时；下一个响应和下一个请求配对，不错位。
// 缺口在 ms4 客户端的纯 ACK 越过时认定，缓存的第二个响应随之交付，/TOKEN-b 耗时 4-1=3.0ms。
func TestWholeResponseLost(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-a HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1), []byte("GET /TOKEN-b HTTP/1.1\r\n\r\n"))
		c.SkipServer(len("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nbody--1"))
		c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nbody--2"))
		c.ClientAck(ms(4))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete\n"+
		"GET /TOKEN-a HTTP/1.1\r\n\r\n"+
		"[gap: 45 bytes missing]\n"+
		"--\n"+
		"2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /TOKEN-b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nbody--2\n")
	if st.Incomplete != 1 || st.Complete != 1 || st.Orphans != 0 || st.Gaps != 1 || st.GapBytes != 45 {
		t.Fatalf("stats: %+v", st)
	}
}

// tlsRecord 返回一段像 TLS 记录的二进制字节，中间夹着关键词。
func tlsRecord(n int) []byte {
	b := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00}
	for i := range n {
		b = append(b, byte(i*7+3))
	}
	return append(b, "TOKEN-42"...)
}

// 客户端方向的 Orphan 消息只计数、丢弃：一条 TLS 连接不产生交互，也不输出任何块，
// 即使字节里含关键词。服务端方向同样找不到状态行，队列为空，Orphan 也丢弃。
// 两个方向各失步一次，各开始一条 Orphan 消息（找不到起始行，一直不结束）。
func TestTLSConnectionOrphans(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN-42")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), tlsRecord(300))
		c.ServerSend(ms(1), tlsRecord(3000))
		c.ClientSend(ms(2), tlsRecord(500))
		c.ServerSend(ms(3), tlsRecord(800))
		c.ClientFin(ms(4))
		c.ServerFin(ms(5))
	})
	check(t, out, "")
	if st.Exchanges != 0 || st.Orphans != 2 || st.Desyncs != 2 {
		t.Fatalf("stats: %+v", st)
	}
}

// 非 HTTP 连接的数据只扫描、不缓存：内存计量不随它的数据量增长。
// 作为对照，同样大小的 HTTP 响应 body 会被缓存，计量随之增长。
// 只比较两种规模的差值，不依赖连接和交互的固定开销。
func TestNonHTTPNotBuffered(t *testing.T) {
	tls := func(n int) func(w *pcapgen.Writer) {
		return func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), tlsRecord(200))
			for i := range n {
				c.ServerSend(ms(float64(1+i)), tlsRecord(1400))
			}
		}
	}
	httpRes := func(n int) func(w *pcapgen.Writer) {
		return func(w *pcapgen.Writer) {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Handshake(ms(-1))
			c.ClientSend(ms(0), []byte("GET / HTTP/1.1\r\n\r\n"))
			c.ServerSend(ms(1), []byte("HTTP/1.1 200 OK\r\n\r\n"))
			for i := range n {
				c.ServerSend(ms(float64(2+i)), bytes.Repeat([]byte("x"), 1000))
			}
		}
	}
	cfg := engine.Config{Matcher: matcher(t, "TOKEN-42")}
	_, small := replay(t, cfg, tls(1))
	_, large := replay(t, cfg, tls(100))
	if small.PeakBuffered != large.PeakBuffered {
		t.Fatalf("TLS PeakBuffered grows with data: %d -> %d", small.PeakBuffered, large.PeakBuffered)
	}
	_, small = replay(t, cfg, httpRes(1))
	_, large = replay(t, cfg, httpRes(100))
	if d := large.PeakBuffered - small.PeakBuffered; d != 99*1000 {
		t.Fatalf("HTTP PeakBuffered grows by %d, want %d", d, 99*1000)
	}
}

// ACK 校验：响应所在包的 ACK 表明服务端当时还没收到队首请求 R 的第一个字节，
// 这个响应不属于 R，按缺请求的交互输出（定位行时间是响应第一个包的时间，没有耗时），
// R 继续等自己的响应。
func TestAckCheckNoRequest(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-r HTTP/1.1\r\n\r\n"))
		stray := []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-x")
		c.Raw(ms(1), false, c.ServerISN+1, c.ClientISN+1, decode.ACK|decode.PSH, stray)
		c.SkipServer(len(stray))
		c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-request\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-x\n"+
		"--\n"+
		"2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /TOKEN-r HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\n")
	if st.Exchanges != 2 || st.NoRequest != 1 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 缺请求的交互也可以先有 1xx：最终响应归入同一个交互，不去配队列里的请求。
func TestNoRequestWithInterim(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-r HTTP/1.1\r\n\r\n"))
		stray := []byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-x")
		c.Raw(ms(1), false, c.ServerISN+1, c.ClientISN+1, decode.ACK|decode.PSH, stray)
		c.SkipServer(len(stray))
		c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-request\n"+
		"HTTP/1.1 100 Continue\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-x\n"+
		"--\n"+
		"2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /TOKEN-r HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\n")
	if st.Exchanges != 2 || st.NoRequest != 1 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 缺请求的交互只收到 1xx 连接就断了：没有最终响应，状态是 no-request,no-response(closed)。
func TestNoRequestInterimThenReset(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ServerSend(ms(1), []byte("HTTP/1.1 100 TOKEN\r\n\r\n"))
		c.ClientRst(ms(2))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 no-request,no-response(closed)\n"+
		"HTTP/1.1 100 TOKEN\r\n\r\n")
	if st.Exchanges != 1 || st.NoRequest != 1 || st.NoResponseClosed != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// Orphan 消息也做 ACK 校验：服务端在收到请求之前发出的非 HTTP 字节不归入这个请求的响应，
// 丢弃并计入 Orphans；请求照常等自己的响应。
func TestAckCheckOrphan(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-r HTTP/1.1\r\n\r\n"))
		junk := []byte("garbage TOKEN-x\r\n")
		c.Raw(ms(1), false, c.ServerISN+1, c.ClientISN+1, decode.ACK|decode.PSH, junk)
		c.SkipServer(len(junk))
		c.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /TOKEN-r HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\n")
	if st.Exchanges != 1 || st.Orphans != 1 || st.Complete != 1 || st.Desyncs != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 客户端丢了一整个请求（缺口正好落在两个请求之间）：连请求行都没抓到，缺口作为 Orphan 丢弃、计数。
// 它的响应到达时，ACK 表明服务端还没收到下一个请求，不和下一个请求配对，按缺请求输出。
// 缺口在 ms2 服务端响应的 ACK 越过时认定。
func TestWholeRequestLost(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.SkipClient(len("GET /lost HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-a"))
		c.ClientSend(ms(5), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(7), []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-b"))
	})
	check(t, out, "2026-09-28 15:30:12.347 10.0.0.1:52814 -> 10.0.0.2:80 no-request\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-a\n"+
		"--\n"+
		"2026-09-28 15:30:12.350 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nTOKEN-b\n")
	if st.Exchanges != 2 || st.NoRequest != 1 || st.Complete != 1 || st.Orphans != 1 || st.Desyncs != 1 || st.GapBytes != 22 {
		t.Fatalf("stats: %+v", st)
	}
}
