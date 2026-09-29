package tcp_test

import (
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/tcp"
)

// nopHandler 丢弃所有事件。
type nopHandler struct{}

func (nopHandler) Data(tcp.Side, int64, []byte, int64, time.Time) {}
func (nopHandler) Gap(tcp.Side, int64, int64, time.Time)          {}
func (nopHandler) Fin(tcp.Side, time.Time)                        {}
func (nopHandler) Reset(time.Time)                                {}
func (nopHandler) Closed(tcp.CloseReason, time.Time)              {}

// BenchmarkInOrder 是按序大流量：一条连接上客户端连续发 1KB 的段，
// 服务端每隔一个段回一个 ACK。
func BenchmarkInOrder(b *testing.B) {
	const size = 1024
	a := tcp.NewAssembler(defaultConfig(), func(tcp.ConnInfo) tcp.Handler { return nopHandler{} })
	payload := make([]byte, size)
	data := &decode.Segment{Src: cli, Dst: srv, Seq: cISN + 1, Ack: sISN + 1, Flags: pshAck, Payload: payload}
	acks := &decode.Segment{Src: srv, Dst: cli, Seq: sISN + 1, Flags: ack}
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: cISN, Flags: syn}, t0)
	a.Add(&decode.Segment{Src: srv, Dst: cli, Seq: sISN, Ack: cISN + 1, Flags: synAck}, t0)
	ts := t0
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		ts = ts.Add(time.Microsecond)
		a.Add(data, ts)
		data.Seq += size
		if i%2 == 1 {
			acks.Ack = data.Seq
			a.Add(acks, ts)
		}
		if i%1000 == 0 {
			a.Advance(ts)
		}
	}
}

// BenchmarkReordered 每两个段交换一次顺序，测乱序缓存的开销。
func BenchmarkReordered(b *testing.B) {
	const size = 1024
	a := tcp.NewAssembler(defaultConfig(), func(tcp.ConnInfo) tcp.Handler { return nopHandler{} })
	payload := make([]byte, size)
	seg := &decode.Segment{Src: cli, Dst: srv, Ack: sISN + 1, Flags: pshAck, Payload: payload}
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: cISN, Flags: syn}, t0)
	seq := cISN + 1
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if i%2 == 0 {
			seg.Seq = seq + size // 后一个段先到
		} else {
			seg.Seq = seq
			seq += 2 * size
		}
		a.Add(seg, t0)
	}
}
