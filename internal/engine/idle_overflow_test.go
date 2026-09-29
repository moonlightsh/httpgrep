package engine_test

import (
	"testing"
	"time"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 超时大到两倍会溢出时，连接空闲释放的时长取最大值，不会变成负数、每个包都重建连接。
func TestHugeTimeoutIdleNoOverflow(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), Timeout: 1500000 * time.Hour}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(0))
		c.ClientSend(ms(1), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(2), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")
	if st.Connections != 1 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}
