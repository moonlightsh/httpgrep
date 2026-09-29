package tcp_test

import (
	"testing"
)

// 第 5 条：重传已经交付过的数据时没有回调，部分重叠时只交付新的部分。
func TestRetransmission(t *testing.T) {
	tests := []struct {
		name string
		p    pkt
		want []string
	}{
		{"full retransmit", c2s(1001, 5001, pshAck, "abcd"), nil},
		{"prefix retransmit", c2s(1001, 5001, pshAck, "ab"), nil},
		{"inner retransmit", c2s(1002, 5001, pshAck, "bc"), nil},
		{"partial overlap", c2s(1003, 5001, pshAck, "cdef"), []string{`data 0 off=4 "ef" ack=0`}},
		{"superset", c2s(1001, 5001, pshAck, "abcdefg"), []string{`data 0 off=4 "efg" ack=0`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.add(c2s(1001, 5001, pshAck, "abcd"), at(1))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true", `data 0 off=0 "abcd" ack=0`)
			h.add(tt.p, at(2))
			h.expect(tt.want...)
		})
	}
}
