package engine_test

import (
	"testing"

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
