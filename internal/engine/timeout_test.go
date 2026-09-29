package engine_test

import (
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
