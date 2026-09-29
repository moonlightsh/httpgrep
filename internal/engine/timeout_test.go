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
