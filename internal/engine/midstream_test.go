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
