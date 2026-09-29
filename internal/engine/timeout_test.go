package engine_test

import (
	"net/netip"
	"strings"
	"testing"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 请求发完后一直没有响应：Advance 到 +29.9 秒时不输出，到 +30 秒时输出 no-response(timeout)。
func TestTimeoutNoResponse(t *testing.T) {
	snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN HTTP/1.1\r\n"))
		c.ClientSend(ms(5), []byte("Host: x\r\n\r\n"))
	}, ms(30004.9), ms(30005))
	want := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN HTTP/1.1\r\nHost: x\r\n\r\n"
	check(t, snaps[0], "")
	check(t, snaps[1], want)
	check(t, out, want)
	if st.NoResponseTimeout != 1 || st.NoResponseEOF != 0 || st.Exchanges != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 响应收到一部分之后没了下文：从最后一次收到数据（响应的第二个包，+2s）起 30 秒，状态 incomplete。
// 耗时算到最后一次收到响应数据。
func TestTimeoutPartialResponse(t *testing.T) {
	snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1000), []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"))
		c.ServerSend(ms(2000), []byte("TOKEN"))
	}, ms(31999.9), ms(32000))
	want := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 2000.0ms\n" +
		"GET /a HTTP/1.1\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN\n"
	check(t, snaps[0], "")
	check(t, snaps[1], want)
	check(t, out, want)
	if st.Incomplete != 1 || st.NoResponseTimeout != 0 || st.Complete != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 管道化的 R1（t=0）和 R2（t=1）都没有得到响应：R1 在 t=30 超时；
// R2 从 t=30 轮到队首时才开始计时，t=59.9 时还没超时，t=60 超时。
func TestTimeoutPipelinedStartsAtHead(t *testing.T) {
	snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
	}, ms(29999.9), ms(30000), ms(31000), ms(59999.9), ms(60000))
	r1 := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n"
	r2 := "--\n" +
		"2026-09-28 15:30:13.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"
	for i, want := range []string{"", r1, r1, r1, r1 + r2} {
		check(t, snaps[i], want)
	}
	check(t, out, r1+r2)
	if st.NoResponseTimeout != 2 {
		t.Fatalf("stats: %+v", st)
	}
}

// 一次 Advance 跨过多个到期时间：R2 的计时从 R1 的到期时间（t=30）起算，不从调用 Advance 的时刻起算。
func TestTimeoutPipelinedSingleAdvance(t *testing.T) {
	snaps, _, _ := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
	}, ms(60000))
	check(t, snaps[0], "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:13.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n")
}

// 迟到响应：R1 在 t=30 超时，它的响应 t=35 才到。不输出第二块，Late 加 1，也不缓存它的数据；
// 之后的 R2 和它自己的响应配对。
// 缓存峰值是 R2 的请求加响应：25 + 40 = 65 字节，迟到响应的 5041 字节不计入。
func TestLateResponse(t *testing.T) {
	late := "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + strings.Repeat("TOKEN-LATE", 500)
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(35000), []byte(late))
		c.ClientSend(ms(40000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(40003), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:52.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok\n")
	if st.Late != 1 || st.Exchanges != 2 || st.NoRequest != 0 || st.Complete != 1 || st.PeakBuffered != 65 {
		t.Fatalf("stats: %+v", st)
	}
}

// 响应收到一半时超时，剩下的部分超时之后才到，中间还有缺口，缺口认定时下一个请求 R2 已经在排队：
// 这些字节和缺口留给占位，不挂到 R2 上，算一次 Late（响应的一部分迟到也是迟到响应）。
// R2 在 t=34 排到占位后面，和它自己的响应配对。
// 缺口在 "ab" 之前，"ab" 进乱序缓存，t=37 乱序超时才认定缺口。
func TestLateRestOfResponseWithGap(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1000), []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN"))
		c.ClientSend(ms(34000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
		c.SkipServer(3)
		c.ServerSend(ms(35000), []byte("ab"))
		c.ServerAck(ms(38000))
		c.ServerSend(ms(40003), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 1000.0ms\n"+
		"GET /a HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN\n"+
		"--\n"+
		"2026-09-28 15:30:46.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 6003.0ms\n"+
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.Late != 1 || st.Incomplete != 1 || st.Complete != 1 || st.Gaps != 1 || st.GapBytes != 3 {
		t.Fatalf("stats: %+v", st)
	}
}

// 带 Upgrade 头的请求超时：先按被拒处理（Resume），缓存在它后面的请求照常排队，
// 从 Upgrade 请求到期（t=30）起计时，t=60 以 no-response(timeout) 结束，而不是等到输入结束。
func TestTimeoutUpgradeResumesHeld(t *testing.T) {
	snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
		c.ClientSend(ms(1000), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
	}, ms(59999.9), ms(60000))
	want := "2026-09-28 15:30:13.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN HTTP/1.1\r\n\r\n"
	check(t, snaps[0], "")
	check(t, snaps[1], want)
	check(t, out, want)
	if st.NoResponseTimeout != 2 || st.NoResponseEOF != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// Upgrade 请求超时之后，它的 400 才迟到：占位收下 400，不再回放一次；
// 缓存在它后面的请求已经在超时时回放，和随后的 204 配对。耗时从它最后一个缓存段（t=1）算起。
func TestTimeoutUpgradeLateRefusal(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN-U\r\n\r\n"))
		c.ClientSend(ms(1000), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(35000), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		c.ServerSend(ms(36000), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN-U\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:13.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 35000.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.Late != 1 || st.Complete != 1 || st.NoResponseTimeout != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 迟到的 400 属于已经超时的 Upgrade 请求，不能当成对正在发送的下一个 Upgrade 请求的决定：
// 第二个 Upgrade 请求照常等自己的 101，101 之后隧道里像请求的字节不再解析、不输出。
func TestTimeoutUpgradeLateRefusalNotForNext(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN-U\r\n\r\n"))
		c.ClientSend(ms(32000), []byte("GET /chat2 HTTP/1.1\r\nUpgrade: websocket\r\n"))
		c.ServerSend(ms(35000), []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		c.ClientSend(ms(36000), []byte("\r\n"))
		c.ClientSend(ms(37000), []byte("GET /TOKEN-IN-TUNNEL HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(38000), []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nX-Id: TOKEN-U\r\n\r\n")
	if st.Late != 1 || st.Exchanges != 2 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 一次 Advance 里到期的交互按到期时间的先后输出，不按开始时间：
// A 在 t=0 开始、t=5 还收到请求的后半，t=35 到期；B 在 t=1 开始，t=31 到期；C 在 t=2 开始，t=32 到期。
func TestTimeoutOrderByDeadline(t *testing.T) {
	cli3 := netip.MustParseAddrPort("10.0.0.1:52816")
	snaps, _, _ := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		a := pcapgen.NewConn(w, cli1, srv)
		a.Handshake(ms(-1))
		a.ClientSend(ms(0), []byte("GET /TOKEN-A HTTP/1.1\r\n"))
		b := pcapgen.NewConn(w, cli2, srv)
		b.Handshake(ms(500))
		b.ClientSend(ms(1000), []byte("GET /TOKEN-B HTTP/1.1\r\n\r\n"))
		c := pcapgen.NewConn(w, cli3, srv)
		c.Handshake(ms(1500))
		c.ClientSend(ms(2000), []byte("GET /TOKEN-C HTTP/1.1\r\n\r\n"))
		a.ClientSend(ms(5000), []byte("\r\n"))
	}, ms(40000))
	check(t, snaps[0], "2026-09-28 15:30:13.345 10.0.0.1:52815 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /TOKEN-B HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:14.345 10.0.0.1:52816 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /TOKEN-C HTTP/1.1\r\n\r\n"+
		"--\n"+
		"2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n"+
		"GET /TOKEN-A HTTP/1.1\r\n\r\n")
}

// 空闲 60 秒（2 倍交互超时）的连接被释放：A、B 在 t=60 释放后，同时存在的连接数随之减少，
// 之后 C 打开时只有 2 条连接（PeakConns 为 2，不释放的话是 3）。
// 之后 A 的四元组上的新数据按半路连接处理：新建连接、按内容判定角色，交互照常输出。
// A 的请求已经在 t=30 超时输出，释放时占位直接回收，不再以 no-response(closed) 输出。
func TestIdleConnectionReleased(t *testing.T) {
	cli3 := netip.MustParseAddrPort("10.0.0.1:52816")
	snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		a := pcapgen.NewConn(w, cli1, srv)
		a.Handshake(ms(-1))
		a.ClientSend(ms(0), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\n"))
		b := pcapgen.NewConn(w, cli2, srv)
		b.Handshake(ms(0))
		a.ClientSend(ms(61000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
		a.ServerSend(ms(61003), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
		c := pcapgen.NewConn(w, cli3, srv)
		c.Handshake(ms(62000))
	}, ms(30000), ms(59999.9), ms(60000))
	first := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n"
	check(t, snaps[0], first)
	check(t, snaps[2], first)
	check(t, out, first+
		"--\n"+
		"2026-09-28 15:31:13.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.Connections != 4 || st.MidStream != 1 || st.PeakConns != 2 || st.NoResponseClosed != 0 || st.NoResponseTimeout != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 缺请求的交互（不在队列里）也会超时：响应收到一半的是 no-request,incomplete，
// 只收到 1xx 的是 no-request,no-response(timeout)。剩下的部分或最终响应迟到时计入 Late，
// 不另起一个缺请求的交互；之后的请求和它自己的响应配对。
func TestTimeoutNoRequest(t *testing.T) {
	cases := []struct {
		name, first, late, status string
	}{
		{
			name:   "partial response",
			first:  "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nTOKEN",
			late:   "abcde",
			status: "no-request,incomplete",
		},
		{
			name:   "interim only",
			first:  "HTTP/1.1 100 Continue\r\nX-Id: TOKEN\r\n\r\n",
			late:   "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			status: "no-request,no-response(timeout)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ServerSend(ms(0), []byte(tc.first))
				c.ServerSend(ms(35000), []byte(tc.late))
				c.ClientSend(ms(40000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
				c.ServerSend(ms(40003), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			}, ms(29999.9), ms(30000))
			first := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 " + tc.status + "\n" + tc.first
			if tc.name == "partial response" {
				first += "\n"
			}
			check(t, snaps[0], "")
			check(t, snaps[1], first)
			check(t, out, first+
				"--\n"+
				"2026-09-28 15:30:52.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 3.0ms\n"+
				"GET /TOKEN-2 HTTP/1.1\r\n\r\n"+
				"HTTP/1.1 204 No Content\r\n\r\n")
			if st.Late != 1 || st.NoRequest != 1 || st.Exchanges != 2 || st.Complete != 1 {
				t.Fatalf("stats: %+v", st)
			}
		})
	}
}

// 请求发到一半时超时：incomplete,no-response(timeout)。请求剩下的字节超时之后才到，
// 由占位收下，不缓存、不输出；它的响应迟到，计入 Late；之后的请求排在占位后面，和自己的响应配对。
// 缓存峰值是第二个交互的 25 + 27 = 52 字节：剩下的 "fghij" 不计入（计入的话是 57）。
func TestTimeoutPartialRequest(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcde"))
		c.ClientSend(ms(35000), []byte("fghij"))
		c.ClientSend(ms(36000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(37000), []byte("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"))
		c.ServerSend(ms(37100), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete,no-response(timeout)\n"+
		"POST /TOKEN HTTP/1.1\r\nContent-Length: 10\r\n\r\nabcde\n"+
		"--\n"+
		"2026-09-28 15:30:48.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1100.0ms\n"+
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.Late != 1 || st.Incomplete != 1 || st.NoResponseTimeout != 1 || st.Complete != 1 || st.PeakBuffered != 52 {
		t.Fatalf("stats: %+v", st)
	}
}

// 请求没发完就超时，Upgrade 头或 body 的剩余部分超时之后才到：超时时就按被拒记下决定，
// 请求发完后解析器直接继续解析，不缓存后面的请求；后面管道化的请求照常排队，输入结束时 no-response(eof)。
func TestTimeoutUnfinishedUpgradeRequest(t *testing.T) {
	cases := []struct {
		name, first, rest string
	}{
		{
			// 超时时还没看到 Upgrade 头，引擎还不知道它是 Upgrade 请求。
			name:  "upgrade header after timeout",
			first: "GET /chat HTTP/1.1\r\n",
			rest:  "Upgrade: websocket\r\n\r\n",
		},
		{
			name:  "body after timeout",
			first: "POST /chat HTTP/1.1\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\nab",
			rest:  "cd",
		},
	}
	ends := []struct {
		name string
		end  func(c *pcapgen.Conn)
		why  string
	}{
		{"finish", func(*pcapgen.Conn) {}, "no-response(eof)"},
		{"server FIN", func(c *pcapgen.Conn) { c.ServerFin(ms(37000)) }, "no-response(closed)"},
	}
	for _, tc := range cases {
		for _, end := range ends {
			t.Run(tc.name+"/"+end.name, func(t *testing.T) {
				out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
					c := pcapgen.NewConn(w, cli1, srv)
					c.Handshake(ms(-1))
					c.ClientSend(ms(0), []byte(tc.first))
					c.ClientSend(ms(35000), []byte(tc.rest))
					c.ClientSend(ms(36000), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
					end.end(c)
				})
				check(t, out, "2026-09-28 15:30:48.345 10.0.0.1:52814 -> 10.0.0.2:80 "+end.why+"\n"+
					"GET /TOKEN HTTP/1.1\r\n\r\n")
				if st.Exchanges != 2 || st.NoResponseTimeout != 1 {
					t.Fatalf("stats: %+v", st)
				}
			})
		}
	}
}

// 占位上迟到的 1xx 之后还有迟到的最终响应：100 不结束占位，200 也归占位，
// 下一个请求和它自己的 204 配对，不错位。
func TestLateInterimResponse(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(35000), []byte("HTTP/1.1 100 Continue\r\n\r\n"))
		c.ClientSend(ms(36000), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(37000), []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		c.ServerSend(ms(37001), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:48.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1001.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	if st.Late != 1 || st.Complete != 1 || st.NoResponseTimeout != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 空闲释放不是连接关闭：管道化的 R1、R2、R3 都没有响应，R1 在 t=30、R2 在 t=60 超时；
// 最后一个包在 t=2，连接在 t=62 空闲释放，这时 R3 还没到自己的超时（t=90），
// 但同样是等不到数据而结束，标为 no-response(timeout)，不是 closed。
func TestIdleReleaseEndsAsTimeout(t *testing.T) {
	snaps, out, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN-1 HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(1000), []byte("GET /TOKEN-2 HTTP/1.1\r\n\r\n"))
		c.ClientSend(ms(2000), []byte("GET /TOKEN-3 HTTP/1.1\r\n\r\n"))
	}, ms(60000), ms(61900), ms(62000))
	r12 := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN-1 HTTP/1.1\r\n\r\n" +
		"--\n" +
		"2026-09-28 15:30:13.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN-2 HTTP/1.1\r\n\r\n"
	r3 := "--\n" +
		"2026-09-28 15:30:14.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
		"GET /TOKEN-3 HTTP/1.1\r\n\r\n"
	check(t, snaps[0], r12)
	check(t, snaps[1], r12)
	check(t, snaps[2], r12+r3)
	check(t, out, r12+r3)
	if st.NoResponseTimeout != 3 || st.NoResponseClosed != 0 {
		t.Fatalf("stats: %+v", st)
	}
}
