package tcp_test

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/tcp"
)

var (
	cli = netip.MustParseAddrPort("10.0.0.1:40000")
	srv = netip.MustParseAddrPort("10.0.0.2:80")
	t0  = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
)

// at 返回 t0 之后 ms 毫秒的时刻。
func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// rec 把收到的事件记成字符串，所有连接共用一个事件列表，便于断言先后顺序。
type rec struct {
	log *[]string
}

func (r rec) add(format string, args ...any) { *r.log = append(*r.log, fmt.Sprintf(format, args...)) }

func (r rec) Data(side tcp.Side, off int64, b []byte, peerAck int64, ts time.Time) {
	r.add("data %d off=%d %q ack=%d", side, off, b, peerAck)
}
func (r rec) Gap(side tcp.Side, off, n int64, ts time.Time) { r.add("gap %d off=%d n=%d", side, off, n) }
func (r rec) Fin(side tcp.Side, ts time.Time)               { r.add("fin %d", side) }
func (r rec) Reset(ts time.Time)                            { r.add("reset") }
func (r rec) Closed(reason tcp.CloseReason, ts time.Time) {
	r.add("closed %s", [...]string{"fin", "reset", "idle", "replaced", "eof", "evicted"}[reason])
}

// harness 包装 Assembler 和事件记录。
type harness struct {
	t   *testing.T
	a   *tcp.Assembler
	log []string
}

func defaultConfig() tcp.Config {
	return tcp.Config{ReorderTimeout: 2 * time.Second, MaxReorderBytes: 1 << 20, IdleTimeout: 60 * time.Second}
}

func newHarness(t *testing.T, cfg tcp.Config) *harness {
	h := &harness{t: t}
	h.a = tcp.NewAssembler(cfg, func(ci tcp.ConnInfo) tcp.Handler {
		h.log = append(h.log, fmt.Sprintf("open A=%s B=%s known=%v", ci.Key.A, ci.Key.B, ci.RolesKnown))
		return rec{&h.log}
	})
	return h
}

// pkt 描述一个要喂给 Assembler 的段。
type pkt struct {
	src, dst netip.AddrPort
	seq, ack uint32
	flags    decode.Flags
	payload  string
	missing  int
}

// c2s 构造客户端发往服务端的段，s2c 反之。
func c2s(seq, ack uint32, flags decode.Flags, payload string) pkt {
	return pkt{src: cli, dst: srv, seq: seq, ack: ack, flags: flags, payload: payload}
}

func s2c(seq, ack uint32, flags decode.Flags, payload string) pkt {
	return pkt{src: srv, dst: cli, seq: seq, ack: ack, flags: flags, payload: payload}
}

func (h *harness) add(p pkt, ts time.Time) {
	h.t.Helper()
	seg := &decode.Segment{Src: p.src, Dst: p.dst, Seq: p.seq, Ack: p.ack, Flags: p.flags, Missing: p.missing}
	if p.payload != "" {
		seg.Payload = []byte(p.payload)
	}
	h.a.Add(seg, ts)
}

// feed 依次喂入多个段，时间戳都是 ts。
func (h *harness) feed(ts time.Time, ps ...pkt) {
	h.t.Helper()
	for _, p := range ps {
		h.add(p, ts)
	}
}

// expect 断言自上次 expect 以来收到的事件序列，然后清空记录。
func (h *harness) expect(want ...string) {
	h.t.Helper()
	got := h.log
	h.log = nil
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		h.t.Fatalf("events mismatch\ngot:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

const (
	syn    = decode.SYN
	synAck = decode.SYN | decode.ACK
	ack    = decode.ACK
	pshAck = decode.PSH | decode.ACK
	finAck = decode.FIN | decode.ACK
	rst    = decode.RST
	rstAck = decode.RST | decode.ACK
)

// 握手用的 ISN：客户端 1000，服务端 5000。数据偏移 0 对应序号 ISN+1。
const (
	cISN uint32 = 1000
	sISN uint32 = 5000
)

// handshake 喂入三次握手。
func (h *harness) handshake(ts time.Time) {
	h.t.Helper()
	h.feed(ts,
		c2s(cISN, 0, syn, ""),
		s2c(sISN, cISN+1, synAck, ""),
		c2s(cISN+1, sISN+1, ack, ""),
	)
}
