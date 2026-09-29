package tcp_test

import (
	"fmt"
	"strings"
	"testing"

	"httpgrep/internal/decode"
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

// 第 15 条：保活探测（序号等于下一个期望序号减 1，负载 0 或 1 字节）没有回调。
func TestKeepAlive(t *testing.T) {
	tests := []struct {
		name string
		p    pkt
	}{
		{"client empty", c2s(1004, 5003, ack, "")},
		{"client one byte", c2s(1004, 5003, ack, "\x00")},
		{"server empty", s2c(5002, 1005, ack, "")},
		{"server one byte", s2c(5002, 1005, ack, "Z")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.feed(at(1), c2s(1001, 5001, pshAck, "abcd"), s2c(5001, 1005, pshAck, "OK"))
			h.expect(
				"open A=10.0.0.1:40000 B=10.0.0.2:80 known=true",
				`data 0 off=0 "abcd" ack=0`,
				`data 1 off=0 "OK" ack=4`,
			)
			h.add(tt.p, at(2))
			h.expect()
		})
	}
}

// 第 18 条：peerAck 是对端流的偏移，服务端包的 Ack = 客户端 ISN+1+N 时为 N。
func TestPeerAck(t *testing.T) {
	tests := []struct {
		name string
		p    pkt
		want string
	}{
		{"acks nothing", s2c(5001, cISN+1, pshAck, "OK"), `data 1 off=0 "OK" ack=0`},
		{"acks 3 bytes", s2c(5001, cISN+1+3, pshAck, "OK"), `data 1 off=0 "OK" ack=3`},
		{"acks 10 bytes", s2c(5001, cISN+1+10, pshAck, "OK"), `data 1 off=0 "OK" ack=10`},
		{"no ack flag", s2c(5001, cISN+1+10, decode.PSH, "OK"), `data 1 off=0 "OK" ack=-1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.add(c2s(1001, 5001, pshAck, "0123456789"), at(1))
			h.log = nil
			h.add(tt.p, at(2))
			h.expect(tt.want)
		})
	}
}

// 第 15 条：某方向还没发过数据（next=0）时的保活探测，seq=ISN、负载 1 字节。
// 序号比偏移 0 小 1，不能被当成远处的乱序数据缓存。
func TestKeepAliveBeforeData(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	h.add(c2s(cISN, sISN+1, ack, "\x00"), at(1))
	h.add(s2c(sISN, cISN+1, ack, "Z"), at(1))
	h.expect()
	if got := h.a.BufferedBytes(); got != 0 {
		t.Fatalf("BufferedBytes() = %d, want 0", got)
	}
	h.a.Flush(at(2))
	h.expect("closed eof")
}

// 第 5 条：按第 3 条从中途开始抓包后，收到起点之前的重传，只交付起点之后的部分。
func TestRetransmissionBeforeStart(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.add(c2s(2000, 7000, pshAck, "ab"), at(0)) // 起点 seq=2000
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=false", `data 0 off=0 "ab" ack=0`)
	h.add(c2s(1998, 7000, pshAck, "abcdef"), at(1)) // 覆盖偏移 [-2,4)
	h.expect(`data 0 off=2 "ef" ack=0`)
	h.add(c2s(1990, 7000, pshAck, "old"), at(1)) // 完全在起点之前
	h.expect()
	if got := h.a.BufferedBytes(); got != 0 {
		t.Fatalf("BufferedBytes() = %d, want 0", got)
	}
	h.a.Flush(at(2))
	h.expect("closed eof")
}

// 第 14 条：单方向流偏移超过 2³¹ 和 2³² 后仍然连续。每轮服务端先用裸 ACK
// 越过 1.5 GiB（0x60000000）没抓到的客户端数据，客户端再从那个位置发 "hi"。
// 只用 Gap，不分配大块内存。
func TestLongStreamOffset(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	rounds := []struct {
		seq      uint32 // 1001 + 本轮起点偏移 + 0x60000000，按 2³² 取模
		gap, off string
	}{
		{0x600003E9, "gap 0 off=0 n=1610612736", `data 0 off=1610612736 "hi" ack=0`},
		{0xC00003EB, "gap 0 off=1610612738 n=1610612736", `data 0 off=3221225474 "hi" ack=0`},
		{0x200003ED, "gap 0 off=3221225476 n=1610612736", `data 0 off=4831838212 "hi" ack=0`},
		{0x800003EF, "gap 0 off=4831838214 n=1610612736", `data 0 off=6442450950 "hi" ack=0`},
	}
	for i, r := range rounds {
		h.add(s2c(sISN+1, r.seq, ack, ""), at(i+1))
		h.expect(r.gap)
		h.add(c2s(r.seq, sISN+1, pshAck, "hi"), at(i+1))
		h.expect(r.off)
	}
	// 客户端流长 6442450952 = 0x180000008，确认序号 1001+0x180000008 取模为 0x800003F1。
	h.add(s2c(sISN+1, 0x800003F1, pshAck, "OK"), at(5))
	h.expect(`data 1 off=0 "OK" ack=6442450952`)
	if got := h.a.BufferedBytes(); got != 0 {
		t.Fatalf("BufferedBytes() = %d, want 0", got)
	}
}
