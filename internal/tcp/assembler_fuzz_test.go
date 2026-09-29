package tcp_test

import (
	"net/netip"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/tcp"
)

// fuzzConn 检查一条连接收到的回调是否合法。
type fuzzConn struct {
	t      *testing.T
	info   tcp.ConnInfo
	next   [2]int64 // 下一个应交付的偏移
	delta  [2]byte  // 负载字节与偏移低 8 位之差，见 seqByte
	known  [2]bool
	fin    [2]bool
	closed bool
	live   *int
}

func (c *fuzzConn) check(side tcp.Side, off, n int64, what string) {
	c.t.Helper()
	if c.closed {
		c.t.Fatalf("%s after Closed", what)
	}
	if side > 1 {
		c.t.Fatalf("%s: bad side %d", what, side)
	}
	if n <= 0 {
		c.t.Fatalf("%s side %d off=%d: empty (n=%d)", what, side, off, n)
	}
	if off != c.next[side] {
		c.t.Fatalf("%s side %d: off=%d, want %d (non-monotonic or overlapping)", what, side, off, c.next[side])
	}
	c.next[side] = off + n
}

func (c *fuzzConn) Data(side tcp.Side, off int64, b []byte, peerAck int64, ts time.Time) {
	c.check(side, off, int64(len(b)), "Data")
	if peerAck < -1 {
		c.t.Fatalf("Data side %d off=%d: peerAck %d < -1", side, off, peerAck)
	}
	// 生成的负载字节等于所在序号的低 8 位，所以字节与偏移之差在一个方向上恒定。
	for i, x := range b {
		d := x - byte(off+int64(i))
		if !c.known[side] {
			c.known[side], c.delta[side] = true, d
		} else if d != c.delta[side] {
			c.t.Fatalf("Data side %d off=%d: byte %d does not match its sequence number", side, off, i)
		}
	}
}

func (c *fuzzConn) Gap(side tcp.Side, off, n int64, ts time.Time) { c.check(side, off, n, "Gap") }

func (c *fuzzConn) Fin(side tcp.Side, ts time.Time) {
	if c.closed || c.fin[side] {
		c.t.Fatalf("Fin side %d twice or after Closed", side)
	}
	c.fin[side] = true
}

func (c *fuzzConn) Reset(ts time.Time) {
	if c.closed {
		c.t.Fatal("Reset after Closed")
	}
}

func (c *fuzzConn) Closed(reason tcp.CloseReason, ts time.Time) {
	if c.closed {
		c.t.Fatal("Closed twice")
	}
	c.closed = true
	*c.live--
}

// seqByte 是序号 seq 处的负载字节：重传和重叠的段内容一致。
func seqByte(seq uint32) byte { return byte(seq) }

var fuzzHosts = []netip.AddrPort{
	netip.MustParseAddrPort("10.0.0.1:40000"),
	netip.MustParseAddrPort("10.0.0.1:40001"),
	netip.MustParseAddrPort("10.0.0.2:80"),
}

// FuzzAssembler 用种子字节生成段序列交给 Assembler：交付的偏移单调、不重叠、连续，
// 内容与序号一致；BufferedBytes 不为负，不超过每方向上限之和；Flush 之后为 0，连接全部关闭。
func FuzzAssembler(f *testing.F) {
	f.Add([]byte{0x02, 0, 0, 0, 0x12, 0, 0, 0, 0x18, 10, 5, 0, 0x18, 0x80, 20, 0})
	f.Add([]byte{0x18, 1, 30, 0, 0x18, 0x40, 30, 0, 0x18, 0xc0, 30, 3, 0x11, 0, 0, 0})
	f.Add([]byte{0x02, 0xff, 0xff, 0xff, 0x04, 0, 0, 0, 0x18, 0, 60, 0x80})
	f.Add([]byte("\x18\x7f\x40\x00\x18\x81\x40\x10\x19\x00\x00\x20\x18\x00\x10\xff"))
	f.Fuzz(func(t *testing.T, in []byte) {
		const maxReorder = 256
		live := 0
		var conns []*fuzzConn
		a := tcp.NewAssembler(tcp.Config{
			ReorderTimeout:  2 * time.Second,
			MaxReorderBytes: maxReorder,
			IdleTimeout:     10 * time.Second,
		}, func(ci tcp.ConnInfo) tcp.Handler {
			c := &fuzzConn{t: t, info: ci, live: &live}
			conns = append(conns, c)
			live++
			return c
		})
		now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		var cursor [3][3]uint32 // 每对端点各自的序号游标
		payload := make([]byte, 0, 256)
		for len(in) >= 4 {
			op, x, y, z := in[0], in[1], in[2], in[3]
			in = in[4:]
			si, di := int(z>>4)%3, int(z>>6)%3
			if si == di {
				di = (di + 1) % 3
			}
			src, dst := fuzzHosts[si], fuzzHosts[di]
			switch {
			case op == 0xff:
				a.Advance(now.Add(time.Duration(x) * 100 * time.Millisecond))
				now = now.Add(time.Duration(x) * 100 * time.Millisecond)
				continue
			case op == 0xfe:
				a.Release(tcp.Key{A: src, B: dst}, now)
				continue
			}
			// 序号：大多是游标附近的小步，x 高位置位时跳 2³¹ 左右。
			seq := cursor[si][di]
			switch x >> 6 {
			case 0, 1:
				seq += uint32(x & 0x7f)
			case 2:
				seq -= uint32(x & 0x3f)
			case 3:
				seq += 1<<31 - 32 + uint32(x&0x3f)
			}
			n := int(y) % 97
			payload = payload[:0]
			for i := range n {
				payload = append(payload, seqByte(seq+uint32(i)))
			}
			missing := 0
			if z&0x08 != 0 {
				missing = int(z&0x07) * 7
			}
			ack := cursor[di][si] + uint32(z&0x07)
			if y&0x80 != 0 {
				ack -= 1 << 30
			}
			seg := decode.Segment{Src: src, Dst: dst, Seq: seq, Ack: ack, Flags: decode.Flags(op & 0x3f),
				Payload: payload, Missing: missing}
			if op&0x40 != 0 {
				now = now.Add(time.Duration(y) * 50 * time.Millisecond)
			}
			a.Add(&seg, now)
			if op&0x80 != 0 {
				a.Advance(now)
			}
			cursor[si][di] = seq + uint32(n+missing)
			if b := a.BufferedBytes(); b < 0 || b > int64(2*maxReorder*max(a.Len(), 1)) {
				t.Fatalf("BufferedBytes %d with %d conns", b, a.Len())
			}
			if a.Len() != live {
				t.Fatalf("Len %d, live handlers %d", a.Len(), live)
			}
		}
		a.Flush(now)
		if b := a.BufferedBytes(); b != 0 {
			t.Fatalf("BufferedBytes after Flush = %d", b)
		}
		if a.Len() != 0 || live != 0 {
			t.Fatalf("after Flush: Len %d, live %d", a.Len(), live)
		}
		for _, c := range conns {
			if !c.closed {
				t.Fatal("connection not closed after Flush")
			}
		}
	})
}
