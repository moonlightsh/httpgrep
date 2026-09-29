package tcp_test

import (
	"net/netip"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/tcp"
)

// 第 12 条：FIN 按序号生效，两个方向都 Fin 后 Closed(CloseFin)。
func TestFin(t *testing.T) {
	tests := []struct {
		name    string
		ps      []pkt
		advance int // 大于 0 时，喂完后 Advance 到这个毫秒数
		want    []string
	}{
		{
			name: "in order",
			ps: []pkt{
				c2s(1001, 5001, pshAck|decode.FIN, "abcd"),
				s2c(5001, 1006, finAck, ""),
				c2s(1006, 5002, ack, ""),
			},
			want: []string{`data 0 off=0 "abcd" ack=0`, "fin 0", "fin 1", "closed fin"},
		},
		{
			name: "fin before data",
			ps: []pkt{
				c2s(1005, 5001, finAck, ""),
				c2s(1001, 5001, pshAck, "abcd"),
			},
			want: []string{`data 0 off=0 "abcd" ack=0`, "fin 0"},
		},
		{
			name: "fin with buffered data before hole filled",
			ps: []pkt{
				c2s(1003, 5001, pshAck|decode.FIN, "cd"),
				c2s(1001, 5001, pshAck, "ab"),
			},
			want: []string{`data 0 off=0 "ab" ack=0`, `data 0 off=2 "cd" ack=0`, "fin 0"},
		},
		{
			name: "hole before fin acked by peer",
			ps: []pkt{
				c2s(1005, 5001, finAck, ""),
				s2c(5001, 1006, ack, ""),
			},
			want: []string{"gap 0 off=0 n=4", "fin 0"},
		},
		{
			name: "hole before fin times out",
			ps: []pkt{
				c2s(1005, 5001, finAck, ""),
			},
			advance: 2001,
			want:    []string{"gap 0 off=0 n=4", "fin 0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
			h.feed(at(1), tt.ps...)
			if tt.advance > 0 {
				h.a.Advance(at(tt.advance))
			}
			h.expect(tt.want...)
		})
	}
}

// 第 13 条：RST 先按缺口规则交付缓存数据，再 Reset、Closed(CloseReset)。
func TestReset(t *testing.T) {
	tests := []struct {
		name string
		ps   []pkt
		want []string
	}{
		{
			name: "no buffered data",
			ps:   []pkt{c2s(1001, 5001, pshAck, "ab"), s2c(5001, 1003, rstAck, "")},
			want: []string{`data 0 off=0 "ab" ack=0`, "reset", "closed reset"},
		},
		{
			name: "buffered data in both directions",
			ps: []pkt{
				c2s(1005, 5001, pshAck, "ef"),
				s2c(5003, 1001, pshAck, "CD"),
				c2s(1001, 0, rst, ""),
			},
			want: []string{
				"gap 0 off=0 n=4", `data 0 off=4 "ef" ack=0`,
				"gap 1 off=0 n=2", `data 1 off=2 "CD" ack=0`,
				"reset", "closed reset",
			},
		},
		{
			name: "sequence out of window",
			ps:   []pkt{s2c(123456, 0, rst, "")},
			want: []string{"reset", "closed reset"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, defaultConfig())
			h.handshake(at(0))
			h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")
			h.feed(at(1), tt.ps...)
			h.expect(tt.want...)
			if n := h.a.Len(); n != 0 {
				t.Fatalf("Len() = %d, want 0", n)
			}
		})
	}
}

// 第 17 条：空闲超过 IdleTimeout 的连接先认定空洞，再 Closed(CloseIdle)。
func TestIdle(t *testing.T) {
	cfg := defaultConfig()
	cfg.ReorderTimeout = time.Hour // 让空洞留到空闲释放时
	h := newHarness(t, cfg)
	h.handshake(at(0))
	h.add(c2s(1005, 5001, pshAck, "ef"), at(1000))
	h.add(s2c(5001, 1001, ack, ""), at(30000)) // 最后一个包
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")

	h.a.Advance(at(89900))
	h.expect()
	h.a.Advance(at(90000))
	h.expect("gap 0 off=0 n=4", `data 0 off=4 "ef" ack=0`, "closed idle")
	if n := h.a.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
}

// 第 17 条：空闲释放时，FIN 之前的空洞认定为缺口后 FIN 生效。
func TestIdlePendingFin(t *testing.T) {
	cfg := defaultConfig()
	cfg.ReorderTimeout = time.Hour
	h := newHarness(t, cfg)
	h.handshake(at(0))
	h.add(c2s(1005, 5001, finAck, ""), at(0))
	h.a.Advance(at(60000))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true", "gap 0 off=0 n=4", "fin 0", "closed idle")
}

// 第 17 条：Flush 对所有连接做同样的处理，从最久没收到包的连接开始。
func TestFlush(t *testing.T) {
	other := netip.MustParseAddrPort("10.0.0.3:50000")
	h := newHarness(t, defaultConfig())
	h.add(pkt{src: other, dst: srv, seq: 100, ack: 200, flags: pshAck, payload: "a"}, at(0))
	h.add(pkt{src: other, dst: srv, seq: 103, ack: 200, flags: pshAck, payload: "d"}, at(1))
	h.add(c2s(1001, 5001, pshAck, "x"), at(2))
	h.add(c2s(1005, 5001, pshAck, "y"), at(3))
	h.log = nil
	h.a.Flush(at(4))
	h.expect(
		"gap 0 off=1 n=2", `data 0 off=3 "d" ack=0`, "closed eof",
		"gap 0 off=1 n=3", `data 0 off=4 "y" ack=0`, "closed eof",
	)
	if n := h.a.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}
}

// 第 19 条：Release 之后回调 Closed(CloseEvicted)，之后的包当新连接处理。
func TestRelease(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.add(c2s(1005, 5001, pshAck, "ef"), at(1))
	h.expect("open A=10.0.0.1:40000 B=10.0.0.2:80 known=true")

	k := tcp.Key{A: cli, B: srv}
	if !h.a.Release(k, at(2)) {
		t.Fatal("Release() = false, want true")
	}
	h.expect("closed evicted")
	if h.a.Release(k, at(2)) {
		t.Fatal("second Release() = true, want false")
	}
	if n := h.a.Len(); n != 0 {
		t.Fatalf("Len() = %d, want 0", n)
	}

	h.add(s2c(5001, 1007, ack, ""), at(3)) // 第 4 条：裸 ACK 不建连接
	h.expect()
	h.add(s2c(5001, 1007, pshAck, "HTTP"), at(4)) // 第 3 条：数据包建连接
	h.expect("open A=10.0.0.2:80 B=10.0.0.1:40000 known=false", `data 0 off=0 "HTTP" ack=0`)
}

// 第 19 条：Release 也接受反向的 Key。
func TestReleaseReversedKey(t *testing.T) {
	h := newHarness(t, defaultConfig())
	h.handshake(at(0))
	h.log = nil
	if !h.a.Release(tcp.Key{A: srv, B: cli}, at(1)) {
		t.Fatal("Release() = false, want true")
	}
	h.expect("closed evicted")
}

// 第 19 条：LeastRecent 返回最后一个包时间最早的连接。
func TestLeastRecent(t *testing.T) {
	c2 := netip.MustParseAddrPort("10.0.0.3:50000")
	c3 := netip.MustParseAddrPort("10.0.0.4:50000")
	h := newHarness(t, defaultConfig())
	if _, ok := h.a.LeastRecent(); ok {
		t.Fatal("LeastRecent() on empty table: ok = true")
	}
	h.add(pkt{src: cli, dst: srv, seq: 1, ack: 1, flags: pshAck, payload: "a"}, at(0))
	h.add(pkt{src: c2, dst: srv, seq: 1, ack: 1, flags: pshAck, payload: "a"}, at(1))
	h.add(pkt{src: c3, dst: srv, seq: 1, ack: 1, flags: pshAck, payload: "a"}, at(2))
	h.add(pkt{src: srv, dst: cli, seq: 1, ack: 2, flags: ack}, at(3)) // cli 那条连接又收到包

	want := []tcp.Key{{A: c2, B: srv}, {A: c3, B: srv}, {A: cli, B: srv}}
	for i, w := range want {
		k, ok := h.a.LeastRecent()
		if !ok || k != w {
			t.Fatalf("step %d: LeastRecent() = %v, %v; want %v, true", i, k, ok, w)
		}
		h.a.Release(k, at(4))
	}
	if _, ok := h.a.LeastRecent(); ok {
		t.Fatal("LeastRecent() after releasing all: ok = true")
	}
}
