package engine_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// MaxMessage 为 4 KiB，响应一共 10 KiB（42 字节的头部加 10198 字节 body）：
// 只缓存和匹配前 4096 字节，输出末尾是截断标记，Truncated 加 1，状态仍是 complete。
// 关键词只出现在 4096 字节之后，或者跨在第 4096 字节上时，不算命中。
func TestMaxMessageTruncates(t *testing.T) {
	const head = "HTTP/1.1 200 OK\r\nContent-Length: 10198\r\n\r\n" // 42 字节
	// body 在 off 处放关键词，其余是 'a'，一共 10198 字节。
	body := func(off int) string {
		return strings.Repeat("a", off) + "TOKEN" + strings.Repeat("a", 10198-off-5)
	}
	cases := []struct {
		name string
		off  int // 关键词在 body 里的偏移
		want string
	}{
		{
			name: "keyword within first 4 KiB",
			off:  0,
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n" +
				"GET / HTTP/1.1\r\nHost: x\r\n\r\n" +
				head + "TOKEN" + strings.Repeat("a", 4096-42-5) + "\n" +
				"[truncated: 6144 bytes over --max-message]\n",
		},
		// 响应按 1460 字节切段，第 4096 字节落在第三段（线上 [2920, 4380)）。关键词从线上
		// 第 42+2876=2918 字节开始，跨在第二、三段之间，整个在 4096 字节以内：照样命中，
		// 截断不会把第三段里限额以内的部分和前面拆成两行。
		{
			name: "keyword across segments before the limit",
			off:  2876,
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n" +
				"GET / HTTP/1.1\r\nHost: x\r\n\r\n" +
				head + strings.Repeat("a", 2876) + "TOKEN" + strings.Repeat("a", 4096-42-2876-5) + "\n" +
				"[truncated: 6144 bytes over --max-message]\n",
		},
		// 关键词从线上第 42+4051=4093 字节开始，只有 "TOK" 在 4096 字节以内。
		{name: "keyword across the limit", off: 4051},
		{name: "keyword after 4 KiB", off: 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMessage: 4096}, func(w *pcapgen.Writer) {
				c := pcapgen.NewConn(w, cli1, srv)
				c.Handshake(ms(-1))
				c.ClientSend(ms(0), []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
				c.ServerSend(ms(2), []byte(head+body(tc.off)))
			})
			check(t, out, tc.want)
			if st.Truncated != 1 || st.Exchanges != 1 || st.Complete != 1 {
				t.Fatalf("stats: %+v", st)
			}
		})
	}
}

// 截断之后的缺口：没抓到的字节同样超出了 MaxMessage，并入截断标记，不再单独输出缺口标记；
// 交互因为缺口标为不完整。body 的第 5000–5999 字节没抓到（线上 [5042, 6042)）。
func TestMaxMessageGapAfterTruncation(t *testing.T) {
	const head = "HTTP/1.1 200 OK\r\nContent-Length: 10198\r\n\r\n"
	body := strings.Repeat("a", 10198)
	out, st := replay(t, engine.Config{Matcher: matcher(t, "GET"), MaxMessage: 4096}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		c.ServerSend(ms(2), []byte(head+body[:5000]))
		c.SkipServer(1000)
		c.ServerSend(ms(3), []byte(body[6000:]))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 3.0ms\n"+
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n"+
		head+strings.Repeat("a", 4096-42)+"\n"+
		"[truncated: 6144 bytes over --max-message]\n")
	if st.Truncated != 1 || st.Gaps != 1 || st.GapBytes != 1000 || st.Incomplete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 内存计量：缓存的消息字节、乱序缓存、每条连接 1 KiB、每个在途交互 512 字节。
// 响应是 150 字节（40 字节头部加 110 字节 body），后 50 字节先到、进乱序缓存，
// 前 100 字节补上后整个响应交付，交互结束。之后再开一条连接。
func TestMemoryAccounting(t *testing.T) {
	res := "HTTP/1.1 200 OK\r\nContent-Length: 110\r\n\r\n" + strings.Repeat("b", 110)
	var got []int64
	replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(0)) // 3 个包
		c.ClientSend(ms(1), []byte("GET / HTTP/1.1\r\n\r\n"))
		c.SkipServer(100)
		c.ServerSend(ms(2), []byte(res[100:]))
		c.SkipServer(-150)
		c.ServerSend(ms(3), []byte(res[:100]))
		c.SkipServer(50)
		pcapgen.NewConn(w, cli2, srv).Handshake(ms(4)) // 3 个包
	}, func(e *engine.Engine, _ time.Time) { got = append(got, e.Memory()) })
	want := []int64{
		1024, 1024, 1024, // 握手：一条连接
		1024 + 512 + 18,      // 请求 18 字节在途
		1024 + 512 + 18 + 50, // 乱序缓存 50 字节
		1024,                 // 响应收完，交互结束
		2048, 2048, 2048,     // 第二条连接
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Memory after each packet = %v, want %v", got, want)
	}
}

// 101 升级之后连接不再按 HTTP 解析，也不再缓存：隧道里两个方向各 100 KB 的数据
// 不计入内存计量，计量只剩这条连接的固定开销。
func TestTunnelNotBuffered(t *testing.T) {
	var got []int64
	replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(0))
		c.ClientSend(ms(1), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"))
		c.ServerSend(ms(2), []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"))
		for i := range 100 {
			c.ClientSend(ms(float64(3+i)), []byte(strings.Repeat("c", 1000)))
			c.ServerSend(ms(float64(3+i)), []byte(strings.Repeat("s", 1000)))
		}
	}, func(e *engine.Engine, _ time.Time) { got = append(got, e.Memory()) })
	// 握手 3 个包、请求 1 个、101 响应 1 个，之后是 200 个隧道包。
	if len(got) != 205 {
		t.Fatalf("%d packets", len(got))
	}
	for i, m := range got[4:] {
		if m != 1024 {
			t.Fatalf("Memory after packet %d = %d, want 1024", 4+i, m)
		}
	}
}

// 超过内存上限时，从开始时间最早的在途交互起丢弃，直到不超限。
// A（t=0，请求命中）和 B（t=1）两个在途交互，B 的响应收到第三个包时计量是
// 2048（两条连接）+ 1024（两个交互）+ 23 + 19（两个请求）+ 4380（B 的响应）= 7494，
// 超过 7000：丢弃 A，减去 512 + 23，得 6959，不再超限。
// A 已经命中也不输出，它在队列里留占位：它的响应之后才到，不缓存、不输出，也不算迟到响应。
// B 照常收完、输出。
func TestEvictOldestInFlight(t *testing.T) {
	bBody := "TOKEN" + strings.Repeat("x", 4995)
	var mem []int64
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 7000}, func(w *pcapgen.Writer) {
		a := pcapgen.NewConn(w, cli1, srv)
		b := pcapgen.NewConn(w, cli2, srv)
		a.Handshake(ms(-1))
		b.Handshake(ms(-1))
		a.ClientSend(ms(0), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		b.ClientSend(ms(1), []byte("GET /b HTTP/1.1\r\n\r\n"))
		b.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"+bBody)) // 1460×3 + 661
		a.ServerSend(ms(3), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nTOKEN"))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	check(t, out, "2026-09-28 15:30:12.346 10.0.0.1:52815 -> 10.0.0.2:80 complete 1.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"+bBody+"\n")
	// 两次握手 6 个包，两个请求，B 的响应 4 个包，A 的响应 1 个包。
	want := []int64{1024, 1024, 1024, 2048, 2048, 2048,
		2048 + 512 + 23, 2048 + 1024 + 42,
		3114 + 1460, 3114 + 2920, 6959, 2048, 2048}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
	if st.Evicted != 1 || st.EvictedMatched != 1 || st.Exchanges != 2 || st.Matched != 1 ||
		st.Complete != 1 || st.Late != 0 || st.NoResponseEOF != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// Upgrade 请求 U 的头部收到一半时因内存上限被丢弃（计量和 TestEvictOldestInFlight 相同：
// 3114 - 23 + 40 + 1460×3 = 7511，丢弃 U 减去 552，得 6959）。U 的请求随后发完，
// 请求解析器照常缓存它后面管道化的请求 R2，等对 U 的决定。连接被 RST 时要先回放缓存，
// R2 以 no-response(closed) 结束并输出，不能随请求解析器关闭而丢掉。
func TestEvictedUpgradeRequestKeepsHeld(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 7000}, func(w *pcapgen.Writer) {
		u := pcapgen.NewConn(w, cli1, srv)
		b := pcapgen.NewConn(w, cli2, srv)
		u.Handshake(ms(-1))
		b.Handshake(ms(-1))
		u.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n"))
		b.ClientSend(ms(1), []byte("GET /b HTTP/1.1\r\n\r\n"))
		b.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"+strings.Repeat("x", 5000)))
		u.ClientSend(ms(4), []byte("\r\nGET /TOKEN HTTP/1.1\r\n\r\n"))
		u.ClientRst(ms(5))
	})
	check(t, out, "2026-09-28 15:30:12.349 10.0.0.1:52814 -> 10.0.0.2:80 no-response(closed)\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n")
	if st.Evicted != 1 || st.EvictedMatched != 0 || st.Exchanges != 3 || st.NoResponseClosed != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 在途交互都丢完了仍然超限：释放最久没有收到包的连接，直到不超限。上限 2600。
// C1、C2 握手后，C1 又发了一个 ACK，最久没有包的是 C2。C3 的 SYN 使计量到 3072，
// 没有在途交互可丢，释放 C2，回到 2048。C2 的四元组上随后来的请求按半路连接新建
// （3072 + 512 + 23）：先丢弃这个交互（已命中，不输出），仍超限，再释放此时最久没有包的 C1。
// C3 不受影响，它的交互照常输出。
func TestEvictLeastRecentConnection(t *testing.T) {
	cli3 := netip.MustParseAddrPort("10.0.0.1:52816")
	var mem []int64
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 2600}, func(w *pcapgen.Writer) {
		c1 := pcapgen.NewConn(w, cli1, srv)
		c2 := pcapgen.NewConn(w, cli2, srv)
		c3 := pcapgen.NewConn(w, cli3, srv)
		c1.Handshake(ms(0))
		c2.Handshake(ms(1))
		c1.ClientAck(ms(2))
		c3.Handshake(ms(3))
		c2.ClientSend(ms(4), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c3.ClientSend(ms(5), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c3.ServerSend(ms(6), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	check(t, out, "2026-09-28 15:30:12.350 10.0.0.1:52816 -> 10.0.0.2:80 complete 1.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	want := []int64{1024, 1024, 1024, 2048, 2048, 2048, 2048,
		2048, 2048, 2048, // C3 握手：SYN 之后释放了 C2
		2048, // C2 四元组上的请求：丢弃交互，释放 C1
		2048 + 512 + 23, 2048}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
	if st.Connections != 4 || st.MidStream != 1 || st.Evicted != 1 || st.EvictedMatched != 1 ||
		st.Exchanges != 2 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// Warn 按抓包时钟最多每 10 秒调用一次，报告距上一次告警以来的累计数；Finish 时补报剩下的。
// 上限 1600：一条连接（1024）上同时只放得下一个在途请求（512 + 19 或 23 字节），
// 每来一个管道化的请求就丢弃前一个。丢弃发生在 t=0（R0，命中）、1（R1）、5（R2，命中）、
// 12（R3）、13（R4）。t=0 立即告警；t=1、5 的累计到 t=10 的 Advance 时告警；
// t=12、13 的累计不到 10 秒，Finish 时补报。R5 留到最后，以 eof 结束。
func TestEvictWarnRateLimited(t *testing.T) {
	var warns []string
	var counts []int
	cfg := engine.Config{
		Matcher:   matcher(t, "TOKEN"),
		MaxMemory: 1600,
		Warn:      func(msg string) { warns = append(warns, msg) },
	}
	_, out, st := replayHook(t, cfg, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-600))
		for _, r := range []struct {
			at   float64
			path string
		}{{-500, "/TOKEN"}, {0, "/r1"}, {1000, "/TOKEN"}, {5000, "/r3"}, {12000, "/r4"}, {13000, "/TOKEN"}} {
			c.ClientSend(ms(r.at), []byte("GET "+r.path+" HTTP/1.1\r\n\r\n"))
		}
	}, func(*engine.Engine, time.Time) { counts = append(counts, len(warns)) }, ms(9999.9), ms(10000))
	check(t, out, "2026-09-28 15:30:25.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n")
	// 握手 3 个包，之后每个请求一个包。
	if want := []int{0, 0, 0, 0, 1, 1, 1, 2, 2}; !slices.Equal(counts, want) {
		t.Fatalf("warnings after each packet = %v, want %v", counts, want)
	}
	want := []string{
		"dropped 1 in-flight exchanges (1 matched) to stay under --max-memory",
		"dropped 2 in-flight exchanges (1 matched) to stay under --max-memory",
		"dropped 2 in-flight exchanges (0 matched) to stay under --max-memory",
	}
	if !slices.Equal(warns, want) {
		t.Fatalf("warnings = %q, want %q", warns, want)
	}
	if st.Evicted != 5 || st.EvictedMatched != 2 || st.NoResponseEOF != 1 {
		t.Fatalf("stats: %+v", st)
	}
}
