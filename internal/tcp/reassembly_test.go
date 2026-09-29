package tcp_test

import (
	"fmt"
	"strings"
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

// 第 6 条：后面的段先到时先缓存，前面的段到了再按偏移顺序交付。
func TestOutOfOrder(t *testing.T) {
	tests := []struct {
		name  string
		early []pkt // 先到的后续段，到达时没有回调
		want  []string
	}{
		{
			name:  "one segment",
			early: []pkt{c2s(1005, 5001, pshAck, "efgh")},
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "efgh" ack=0`},
		},
		{
			name:  "two segments reversed",
			early: []pkt{c2s(1009, 5001, pshAck, "ij"), c2s(1005, 5001, pshAck, "efgh")},
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "efgh" ack=0`, `data 0 off=8 "ij" ack=0`},
		},
		{
			name:  "hole remains",
			early: []pkt{c2s(1010, 5001, pshAck, "jk"), c2s(1005, 5001, pshAck, "efgh")},
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "efgh" ack=0`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
			h.feed(at(1), tt.early...)
			h.expect()
			h.add(c2s(1001, 5001, pshAck, "abcd"), at(2))
			h.expect(tt.want...)
		})
	}
}

// 第 7 条：缓存里的段互相重叠时，重叠部分以先到的为准。
func TestOverlapFirstWins(t *testing.T) {
	tests := []struct {
		name  string
		early []pkt
		fill  pkt // 最后到达、补上开头空洞的段
		want  []string
	}{
		{
			name:  "same range",
			early: []pkt{c2s(1005, 5001, pshAck, "EFGH"), c2s(1005, 5001, pshAck, "xxxx")},
			fill:  c2s(1001, 5001, pshAck, "abcd"),
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "EFGH" ack=0`},
		},
		{
			name:  "later overlaps tail",
			early: []pkt{c2s(1005, 5001, pshAck, "EFGH"), c2s(1007, 5001, pshAck, "xxIJ")},
			fill:  c2s(1001, 5001, pshAck, "abcd"),
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "EFGH" ack=0`, `data 0 off=8 "IJ" ack=0`},
		},
		{
			name:  "later overlaps head",
			early: []pkt{c2s(1007, 5001, pshAck, "GHIJ"), c2s(1005, 5001, pshAck, "EFxx")},
			fill:  c2s(1001, 5001, pshAck, "abcd"),
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "EF" ack=0`, `data 0 off=6 "GHIJ" ack=0`},
		},
		{
			name:  "later covers earlier",
			early: []pkt{c2s(1007, 5001, pshAck, "GH"), c2s(1005, 5001, pshAck, "efxxij")},
			fill:  c2s(1001, 5001, pshAck, "abcd"),
			want: []string{
				`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "ef" ack=0`,
				`data 0 off=6 "GH" ack=0`, `data 0 off=8 "ij" ack=0`,
			},
		},
		{
			name:  "in-order segment overlaps buffer",
			early: []pkt{c2s(1005, 5001, pshAck, "EFGH")},
			fill:  c2s(1001, 5001, pshAck, "abcdxxxxij"),
			want:  []string{`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "EFGH" ack=0`, `data 0 off=8 "ij" ack=0`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
			h.feed(at(1), tt.early...)
			h.expect()
			h.add(tt.fill, at(2))
			h.expect(tt.want...)
		})
	}
}

// 第 14 条：序号回绕。ISN 为 0xFFFFFF00 时，跨过 2³² 的偏移仍然连续。
func TestSequenceWrap(t *testing.T) {
	h := newHarness(t, defaultConfig())
	const isn uint32 = 0xFFFFFF00
	h.feed(at(0),
		c2s(isn, 0, syn, ""),
		s2c(sISN, isn+1, synAck, ""),
		c2s(isn+1, sISN+1, ack, ""),
	)
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	first := strings.Repeat("a", 254)                   // 序号 0xFFFFFF01 到 0xFFFFFFFE
	h.add(c2s(0x00000000, sISN+1, pshAck, "yz"), at(1)) // 偏移 255，回绕后第一个序号，先到
	h.add(c2s(0xFFFFFF01, sISN+1, pshAck, first), at(1))
	h.add(c2s(0xFFFFFFFF, sISN+1, pshAck, "x"), at(1))  // 偏移 254，最后一个回绕前的序号
	h.add(s2c(sISN+1, 0x00000002, pshAck, "OK"), at(1)) // 0xFFFFFF01+257 回绕后是 2
	h.expect(
		fmt.Sprintf("data 0 off=0 %q ack=0", first),
		`data 0 off=254 "x" ack=0`,
		`data 0 off=255 "yz" ack=0`,
		`data 1 off=0 "OK" ack=257`,
	)
}
