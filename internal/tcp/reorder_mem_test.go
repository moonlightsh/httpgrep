package tcp_test

import (
	"net/netip"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/tcp"
)

// 乱序缓存按“负载字节 + 每段 128 字节”计量：只记缺口、没有负载的段（被 snaplen
// 截到只剩头部）也计入，受 MaxReorderBytes 限制。
func TestReorderGapChunksCounted(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxReorderBytes = 300
	h := newHarness(t, cfg)
	h.handshake(at(0))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	trunc := func(seq uint32) pkt {
		return pkt{src: cli, dst: srv, seq: seq, ack: 5001, flags: ack, missing: 1}
	}
	h.add(trunc(1003), at(1)) // [2,3) 没抓到
	if got := h.a.BufferedBytes(); got != 128 {
		t.Fatalf("BufferedBytes = %d, want 128", got)
	}
	h.add(trunc(1005), at(1)) // [4,5)
	if got := h.a.BufferedBytes(); got != 256 {
		t.Fatalf("BufferedBytes = %d, want 256", got)
	}
	h.expect()
	h.add(trunc(1007), at(1)) // [6,7)：384 超过 300，认定最前面的空洞
	h.expect("gap 0 off=0 n=2", "gap 0 off=2 n=1")
	if got := h.a.BufferedBytes(); got != 256 {
		t.Fatalf("BufferedBytes = %d, want 256", got)
	}
}

// 相接的缺口段合并成一段：只计一次固定开销，交付时是一个缺口。
func TestReorderAdjacentGapChunksMerge(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	for _, seq := range []uint32{1003, 1005, 1007} {
		h.add(pkt{src: cli, dst: srv, seq: seq, ack: 5001, flags: ack, missing: 2}, at(1))
	}
	if got := h.a.BufferedBytes(); got != 128 {
		t.Fatalf("BufferedBytes = %d, want 128", got)
	}
	h.add(c2s(1001, 5001, pshAck, "ab"), at(2))
	h.expect(`data 0 off=0 "ab" ack=0`, "gap 0 off=2 n=6")
}

// 源地址和目的地址相同的自连接也算一条连接。
func TestSelfConnCounted(t *testing.T) {
	self := netip.MustParseAddrPort("10.0.0.9:7")
	a := tcp.NewAssembler(defaultConfig(), func(tcp.ConnInfo) tcp.Handler { return &tsRec{} })
	a.Add(&decode.Segment{Src: self, Dst: self, Seq: 1, Flags: syn}, at(0))
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 1, Flags: syn}, at(0))
	if got := a.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	a.Flush(at(1))
	if got := a.Len(); got != 0 {
		t.Fatalf("Len after Flush = %d, want 0", got)
	}
}

// tsRec 丢弃全部事件。
type tsRec struct{}

func (*tsRec) Data(tcp.Side, int64, []byte, int64, time.Time) {}
func (*tsRec) Gap(tcp.Side, int64, int64, time.Time)          {}
func (*tsRec) Fin(tcp.Side, time.Time)                        {}
func (*tsRec) Reset(time.Time)                                {}
func (*tsRec) Closed(tcp.CloseReason, time.Time)              {}

// peerRec 记下 Data 的 peerAck 和 Fin。
type peerRec struct {
	acks []int64
	fins []tcp.Side
}

func (r *peerRec) Data(_ tcp.Side, _ int64, _ []byte, peerAck int64, _ time.Time) {
	r.acks = append(r.acks, peerAck)
}
func (r *peerRec) Gap(tcp.Side, int64, int64, time.Time) {}
func (r *peerRec) Fin(s tcp.Side, _ time.Time)           { r.fins = append(r.fins, s) }
func (r *peerRec) Reset(time.Time)                       {}
func (r *peerRec) Closed(tcp.CloseReason, time.Time)     {}

// 序号落后 2³¹ 左右的 FIN：FIN 的偏移不小于已交付的位置，确认它的 peerAck 不会小于 -1。
func TestStaleFinOffset(t *testing.T) {
	r := &peerRec{}
	a := tcp.NewAssembler(defaultConfig(), func(tcp.ConnInfo) tcp.Handler { return r })
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 1000, Flags: syn}, at(0))
	a.Add(&decode.Segment{Src: srv, Dst: cli, Seq: 5000, Ack: 1001, Flags: synAck}, at(0))
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 1001, Ack: 5001, Flags: pshAck, Payload: []byte("abcd")}, at(1))
	// 序号比 next 落后 2³¹-8 的 FIN
	stale := uint32(1005)
	stale -= 1<<31 - 8
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: stale, Ack: 5001, Flags: finAck}, at(2))
	// 服务端发数据，确认号指向客户端流里很远的位置
	a.Add(&decode.Segment{Src: srv, Dst: cli, Seq: 5001, Ack: 1005 + 100, Flags: pshAck, Payload: []byte("x")}, at(3))
	for _, pa := range r.acks {
		if pa < -1 {
			t.Fatalf("peerAck %d < -1 (acks %v)", pa, r.acks)
		}
	}
}
