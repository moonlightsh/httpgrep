package tcp_test

import (
	"testing"
)

// 第 8 条：对端 ACK 越过没抓到的数据时立即认定缺口。
func TestGapByPeerAck(t *testing.T) {
	tests := []struct {
		name  string
		early []pkt // side 0 丢了 [0,4) 之后到达的段
		ack   pkt   // side 1 发出的确认
		want  []string
	}{
		{
			name:  "ack past hole with buffered data",
			early: []pkt{c2s(1005, 5001, pshAck, "efgh")},
			ack:   s2c(5001, 1009, ack, ""),
			want:  []string{"gap 0 off=0 n=4", `data 0 off=4 "efgh" ack=0`},
		},
		{
			name: "ack past next without buffered data",
			ack:  s2c(5001, 1005, ack, ""),
			want: []string{"gap 0 off=0 n=4"},
		},
		{
			name:  "ack carried by data packet",
			early: []pkt{c2s(1005, 5001, pshAck, "efgh")},
			ack:   s2c(5001, 1009, pshAck, "HTTP"),
			want:  []string{"gap 0 off=0 n=4", `data 0 off=4 "efgh" ack=0`, `data 1 off=0 "HTTP" ack=8`},
		},
		{
			name:  "two holes",
			early: []pkt{c2s(1005, 5001, pshAck, "ef"), c2s(1009, 5001, pshAck, "ij")},
			ack:   s2c(5001, 1011, ack, ""),
			want:  []string{"gap 0 off=0 n=4", `data 0 off=4 "ef" ack=0`, "gap 0 off=6 n=2", `data 0 off=8 "ij" ack=0`},
		},
		{
			name:  "ack stops before buffered data",
			early: []pkt{c2s(1009, 5001, pshAck, "ij")},
			ack:   s2c(5001, 1005, ack, ""),
			want:  []string{"gap 0 off=0 n=4"},
		},
		{
			name:  "ack not past next",
			early: []pkt{c2s(1005, 5001, pshAck, "efgh")},
			ack:   s2c(5001, 1001, ack, ""),
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
			h.feed(at(1), tt.early...)
			h.expect()
			h.add(tt.ack, at(2))
			h.expect(tt.want...)
		})
	}
}

// 第 9 条：乱序超时。空洞一直没补上，最早的缓存段到达 2 秒后认定缺口。
func TestReorderTimeout(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	h.add(c2s(1005, 5001, pshAck, "efgh"), at(1000)) // 空洞 [0,4)
	h.add(c2s(1011, 5001, pshAck, "kl"), at(1500))   // 空洞 [8,10)
	h.expect()

	h.a.Advance(at(2900)) // 最早的段到达后 1.9 秒
	h.expect()
	h.a.Advance(at(3000)) // 到达后 2 秒
	h.expect("gap 0 off=0 n=4", `data 0 off=4 "efgh" ack=0`)
	h.a.Advance(at(3400))
	h.expect()
	h.a.Advance(at(3500)) // 第二段到达后 2 秒
	h.expect("gap 0 off=8 n=2", `data 0 off=10 "kl" ack=0`)
}
