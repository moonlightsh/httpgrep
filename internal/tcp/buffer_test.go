package tcp_test

import (
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/tcp"
)

// 第 20 条：BufferedBytes 等于乱序缓存里的字节数，交付后减少。
func TestBufferedBytes(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	check := func(want int64) {
		t.Helper()
		if got := h.a.BufferedBytes(); got != want {
			t.Fatalf("BufferedBytes() = %d, want %d", got, want)
		}
	}
	check(0)
	h.add(c2s(1005, 5001, pshAck, "efgh"), at(1))
	check(4)
	h.add(c2s(1011, 5001, pshAck, "kl"), at(1))
	check(6)
	h.add(c2s(1007, 5001, pshAck, "ghij"), at(1)) // 只有 "ij" 是新的
	check(8)
	h.add(s2c(5003, 1001, pshAck, "CDE"), at(1)) // 另一方向
	check(11)
	h.add(c2s(1001, 5001, pshAck, "abcd"), at(2)) // 交付 efghijkl
	check(3)
	h.add(c2s(1011, 5001, pshAck, "kl"), at(2)) // 重传不进缓存
	check(3)
	h.a.Release(tcp.Key{A: cli, B: srv}, at(3)) // 释放时丢弃缓存
	check(0)
}

// capture 保存 Data 收到的切片本身，用来检查是否拷贝。
type capture struct{ data [][]byte }

func (c *capture) Data(_ tcp.Side, _ int64, b []byte, _ int64, _ time.Time) {
	c.data = append(c.data, b)
}
func (c *capture) Gap(tcp.Side, int64, int64, time.Time) {}
func (c *capture) Fin(tcp.Side, time.Time)               {}
func (c *capture) Reset(time.Time)                       {}
func (c *capture) Closed(tcp.CloseReason, time.Time)     {}

// 第 20 条：按序段直接把 Payload 传给 Data；乱序段缓存时拷贝负载。
func TestPayloadCopy(t *testing.T) {
	c := &capture{}
	a := tcp.NewAssembler(defaultConfig(), func(tcp.ConnInfo) tcp.Handler { return c })
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 100, Flags: syn}, at(0))
	late := []byte("efgh")
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 105, Ack: 1, Flags: pshAck, Payload: late}, at(0))
	for i := range late {
		late[i] = 'x' // 调用方复用缓冲区
	}
	first := []byte("abcd")
	a.Add(&decode.Segment{Src: cli, Dst: srv, Seq: 101, Ack: 1, Flags: pshAck, Payload: first}, at(1))
	if len(c.data) != 2 {
		t.Fatalf("got %d Data calls, want 2", len(c.data))
	}
	if &c.data[0][0] != &first[0] {
		t.Error("in-order payload was copied")
	}
	if got := string(c.data[1]); got != "efgh" {
		t.Errorf("buffered payload = %q, want %q", got, "efgh")
	}
}
