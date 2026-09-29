package tcp_test

import (
	"net/netip"
	"slices"
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

// tsRec 记下每次 Data 的偏移和时间。
type tsRec struct {
	off []int64
	ts  []time.Time
}

func (r *tsRec) Data(_ tcp.Side, off int64, _ []byte, _ int64, ts time.Time) {
	r.off, r.ts = append(r.off, off), append(r.ts, ts)
}
func (r *tsRec) Gap(tcp.Side, int64, int64, time.Time) {}
func (r *tsRec) Fin(tcp.Side, time.Time)               {}
func (r *tsRec) Reset(time.Time)                       {}
func (r *tsRec) Closed(tcp.CloseReason, time.Time)     {}

// 乱序缓存里的段交付时，Data 的 ts 是这段到达（被抓到）的时间，不是放行它的那个时刻。
func TestReorderDataKeepsArrivalTime(t *testing.T) {
	r := &tsRec{}
	a := tcp.NewAssembler(defaultConfig(), func(tcp.ConnInfo) tcp.Handler { return r })
	add := func(seq uint32, p string, ts time.Time) {
		a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: seq, Ack: 1, Flags: pshAck, Payload: []byte(p)}, ts)
	}
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 100, Flags: syn}, at(0))
	add(105, "efgh", at(10))
	add(109, "ij", at(20))
	add(101, "abcd", at(30)) // 补上空洞
	a.Advance(at(40))
	add(120, "zz", at(50))
	a.Advance(at(3000)) // 乱序超时放行 "zz"
	wantOff := []int64{0, 4, 8, 19}
	wantTS := []time.Time{at(30), at(10), at(20), at(50)}
	if len(r.off) != 4 {
		t.Fatalf("Data offsets %v, want %v", r.off, wantOff)
	}
	for i := range wantOff {
		if r.off[i] != wantOff[i] || !r.ts[i].Equal(wantTS[i]) {
			t.Fatalf("Data %d: off=%d ts=%v, want off=%d ts=%v", i, r.off[i], r.ts[i], wantOff[i], wantTS[i])
		}
	}
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

// 序号落后 2³¹ 左右的 FIN：FIN 的偏移不小于已交付的位置，确认到它之后的 peerAck 封顶到这个位置。
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
	// 客户端数据的 peerAck 是服务端流的 0；服务端数据确认到客户端流的 104，封顶到 FIN 的偏移 4
	// （FIN 的偏移不早于已交付的位置）。客户端方向的 FIN 在它到达时就生效。
	if !slices.Equal(r.acks, []int64{0, 4}) || !slices.Equal(r.fins, []tcp.Side{0}) {
		t.Fatalf("acks %v fins %v, want [0 4] [0]", r.acks, r.fins)
	}
}

// 先到的段 A 交付之后，它的到达记录过时了，但缓存里还有后到的段 B。超时扫描要跳过 A 的记录，
// 按 B 的到达时间判断：不跳过的话会拿 A 的时间当作已超时，skipTo 到 A 的偏移又推进不了，死循环。
func TestReorderExpireSkipsDeliveredArrival(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
	h.add(c2s(1005, 5001, pshAck, "efgh"), at(1))  // A：[4,8)
	h.add(c2s(1021, 5001, pshAck, "uv"), at(1500)) // B：[20,22)
	h.add(c2s(1001, 5001, pshAck, "abcd"), at(1600))
	h.expect(`data 0 off=0 "abcd" ack=0`, `data 0 off=4 "efgh" ack=0`)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.a.Advance(at(2100)) // A 到达已满 2 秒，B 还没有
		h.a.Advance(at(3500)) // B 到达满 2 秒
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Advance does not return")
	}
	h.expect("gap 0 off=8 n=12", `data 0 off=20 "uv" ack=0`)
}
