package tcp_test

import (
	"testing"

	"httpgrep/internal/decode"
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
	if n := h.a.Len(); n != 1 {
		t.Fatalf("Len() = %d, want 1", n)
	}
}

// 第 2 条：第一个包是 SYN-ACK。
func TestFirstPacketSynAck(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.feed(at(0),
		s2c(sISN, cISN+1, synAck, ""),
		c2s(cISN+1, sISN+1, pshAck, "GET"),
		s2c(sISN+1, cISN+4, pshAck, "HTTP"),
	)
	h.expect(
		"open A=10.0.0.1:40000 B=10.0.0.2:80 known=true",
		`data 0 off=0 "GET" ack=0`,
		`data 1 off=0 "HTTP" ack=3`,
	)
}

// 第 3 条：第一个包是普通数据包。
func TestFirstPacketData(t *testing.T) {
	tests := []struct {
		name  string
		first pkt
		want  []string
	}{
		{
			name:  "server data with ack",
			first: s2c(70000, 90000, pshAck, "HTTP"),
			want: []string{
				"open A=10.0.0.2:80 B=10.0.0.1:40000 known=false",
				`data 0 off=0 "HTTP" ack=0`,
				// 客户端方向的起点是 90000，客户端的 Ack 70004 换算成 4。
				`data 1 off=0 "GET" ack=4`,
			},
		},
		{
			name:  "data without ack flag",
			first: pkt{src: srv, dst: cli, seq: 70000, payload: "HTTP"},
			want: []string{
				"open A=10.0.0.2:80 B=10.0.0.1:40000 known=false",
				`data 0 off=0 "HTTP" ack=-1`,
				`data 1 off=0 "GET" ack=4`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.feed(at(0), tt.first, c2s(90000, 70004, pshAck, "GET"))
			h.expect(tt.want...)
		})
	}
}

// 第 4 条：表里没有的连接，不带负载的 ACK、FIN、RST 不建连接。
func TestNoConnForBarePackets(t *testing.T) {
	tests := []struct {
		name string
		p    pkt
	}{
		{"ack", c2s(1, 2, ack, "")},
		{"fin", c2s(1, 2, finAck, "")},
		{"fin without ack", c2s(1, 0, decode.FIN, "")},
		{"rst", c2s(1, 0, rst, "")},
		{"rst ack", c2s(1, 2, rstAck, "")},
		{"rst with payload", c2s(1, 2, rstAck, "x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.add(tt.p, at(0))
			h.expect()
			if n := h.a.Len(); n != 0 {
				t.Fatalf("Len() = %d, want 0", n)
			}
		})
	}
}
