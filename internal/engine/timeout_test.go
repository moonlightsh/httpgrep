package engine_test

import (
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
