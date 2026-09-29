package tcp_test

import (
	"testing"

	"httpgrep/internal/decode"
)

// 第 12 条：FIN 按序号生效，两个方向都 Fin 后 Closed(CloseFin)。
func TestFin(t *testing.T) {
	tests := []struct {
		name    string
		ps      []pkt
		advance int // 大于 0 时，喂完后 Advance 到这个毫秒数
		want    []string
	}{
		{
			name: "in order",
			ps: []pkt{
				c2s(1001, 5001, pshAck|decode.FIN, "abcd"),
				s2c(5001, 1006, finAck, ""),
				c2s(1006, 5002, ack, ""),
			},
			want: []string{`data 0 off=0 "abcd" ack=0`, "fin 0", "fin 1", "closed fin"},
		},
		{
			name: "fin before data",
			ps: []pkt{
				c2s(1005, 5001, finAck, ""),
				c2s(1001, 5001, pshAck, "abcd"),
			},
			want: []string{`data 0 off=0 "abcd" ack=0`, "fin 0"},
		},
		{
			name: "fin with buffered data before hole filled",
			ps: []pkt{
				c2s(1003, 5001, pshAck|decode.FIN, "cd"),
				c2s(1001, 5001, pshAck, "ab"),
			},
			want: []string{`data 0 off=0 "ab" ack=0`, `data 0 off=2 "cd" ack=0`, "fin 0"},
		},
		{
			name: "hole before fin acked by peer",
			ps: []pkt{
				c2s(1005, 5001, finAck, ""),
				s2c(5001, 1006, ack, ""),
			},
			want: []string{"gap 0 off=0 n=4", "fin 0"},
		},
		{
			name: "hole before fin times out",
			ps: []pkt{
				c2s(1005, 5001, finAck, ""),
			},
			advance: 2001,
			want:    []string{"gap 0 off=0 n=4", "fin 0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
			h.feed(at(1), tt.ps...)
			if tt.advance > 0 {
				h.a.Advance(at(tt.advance))
			}
			h.expect(tt.want...)
		})
	}
}
