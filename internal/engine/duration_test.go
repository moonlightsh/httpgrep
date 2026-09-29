package engine_test

import (
	"testing"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// 响应 body 里有 5 字节没抓到，也没有 ACK 越过：后半段进乱序缓存，等 2 秒乱序超时才认定缺口、
// 交付。耗时按响应最后一个数据包被抓到的时间（ms2）算，是 2.0ms，不是认定缺口的时刻。
// 之后只有另一条连接的包推着时钟走。
func TestDurationUsesCaptureTimeOfBufferedBytes(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab"))
		c.SkipServer(5)
		c.ServerSend(ms(2), []byte("fgh"))
		d := pcapgen.NewConn(w, cli2, srv)
		d.Handshake(ms(1000))
		d.ClientAck(ms(2500))
		d.ClientAck(ms(5000))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 2.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab\n"+
		"[gap: 5 bytes missing]\n"+
		"fgh\n")
	if st.Incomplete != 1 || st.Gaps != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 请求 body 的后半段乱序缓存、2 秒后才认定缺口：请求发完的时间按后半段被抓到的时间（ms1）算。
// 响应在认定缺口之后（ms2600）才来，耗时 2599.0ms。
func TestDurationRequestBufferedBytes(t *testing.T) {
	out, _ := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("POST /TOKEN HTTP/1.1\r\nContent-Length: 6\r\n\r\na"))
		c.SkipClient(2)
		c.ClientSend(ms(1), []byte("def"))
		d := pcapgen.NewConn(w, cli2, srv)
		d.Handshake(ms(1000))
		d.ClientAck(ms(2500))
		c.ServerSend(ms(2600), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 2599.0ms\n"+
		"POST /TOKEN HTTP/1.1\r\nContent-Length: 6\r\n\r\na\n"+
		"[gap: 2 bytes missing]\n"+
		"def\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
}
