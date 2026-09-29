package tcp_test

import (
	"testing"
)

// 第 1 条：三次握手后双向发数据。
func TestHandshakeThenData(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.feed(at(1),
		c2s(1001, 5001, pshAck, "GET / HTTP/1.1\r\n\r\n"), // 18 字节
		s2c(5001, 1019, pshAck, "HTTP/1.1 200 OK\r\n"),
	)
	h.expect(
		"open A=10.0.0.1:40000 B=10.0.0.2:80 known=true",
		`data 0 off=0 "GET / HTTP/1.1\r\n\r\n" ack=0`,
		`data 1 off=0 "HTTP/1.1 200 OK\r\n" ack=18`,
	)
}
