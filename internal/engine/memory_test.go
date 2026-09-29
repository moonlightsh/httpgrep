package engine_test

import (
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/engine"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
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
// 超过 7400：丢弃 A，减去 512 + 23、加上占位的 384，得 7343，不再超限。
// A 已经命中也不输出，它在队列里留占位：它的响应之后才到，不缓存、不输出，也不算迟到响应，
// 占位随即回收。B 照常收完、输出。
func TestEvictOldestInFlight(t *testing.T) {
	bBody := "TOKEN" + strings.Repeat("x", 4995)
	var mem []int64
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 7400}, func(w *pcapgen.Writer) {
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
		3114 + 1460, 3114 + 2920, 7343, 2048 + 384, 2048}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
	if st.Evicted != 1 || st.EvictedMatched != 1 || st.Exchanges != 2 || st.Matched != 1 ||
		st.Complete != 1 || st.Late != 0 || st.NoResponseEOF != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// Upgrade 请求 U 的头部收到一半时因内存上限被丢弃（计量和 TestEvictOldestInFlight 相同：
// 3114 - 23 + 40 + 1460×3 = 7511，超过 7400，丢弃 U 减去 552、加上占位的 384，得 7343）。U 的请求随后发完，
// 请求解析器照常缓存它后面管道化的请求 R2，等对 U 的决定。连接被 RST 时要先回放缓存，
// R2 以 no-response(closed) 结束并输出，不能随请求解析器关闭而丢掉。
func TestEvictedUpgradeRequestKeepsHeld(t *testing.T) {
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 7400}, func(w *pcapgen.Writer) {
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

// 在途交互都丢完了仍然超限：释放最久没有收到包的连接，直到不超限。上限 3000。
// C1、C2 握手后，C1 又发了一个 ACK，最久没有包的是 C2。C3 的 SYN 使计量到 3072，
// 没有在途交互可丢，释放 C2，回到 2048。C2 的四元组上随后来的请求按半路连接新建
// （3072 + 512 + 23）：先丢弃这个交互（已命中，不输出，留下 384 字节的占位），得 3456，
// 仍超限，再释放此时最久没有包的 C1，得 2432。C3 不受影响，它的交互照常输出。
func TestEvictLeastRecentConnection(t *testing.T) {
	cli3 := netip.MustParseAddrPort("10.0.0.1:52816")
	var mem []int64
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 3000}, func(w *pcapgen.Writer) {
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
		2048 + 384, // C2 四元组上的请求：丢弃交互，释放 C1
		2048 + 384 + 512 + 23, 2048 + 384}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
	if st.Connections != 4 || st.MidStream != 1 || st.Evicted != 1 || st.EvictedMatched != 1 ||
		st.Exchanges != 2 || st.Complete != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// Warn 按抓包时钟最多每 10 秒调用一次，报告距上一次告警以来的累计数；Finish 时补报剩下的。
// 上限 2000：一条连接（1024）上同时只放得下一个在途请求（512 + 20 或 23 字节）和一个占位（384），
// 每来一个管道化的请求就丢弃前一个；被丢弃的请求的响应紧接着到达，占位随即回收。
// 丢弃发生在 t=0（R0，命中）、1（R1）、5（R2，命中）、12（R3）、13（R4）。t=0 立即告警；
// t=1、5 的累计到 t=10 的 Advance 时告警；t=12、13 的累计不到 10 秒，Finish 时补报。
// R5 留到最后，以 eof 结束。
func TestEvictWarnRateLimited(t *testing.T) {
	var warns []string
	var counts []int
	cfg := engine.Config{
		Matcher:   matcher(t, "TOKEN"),
		MaxMemory: 2000,
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
			if r.at >= 0 {
				// 前一个请求刚被丢弃，它的响应到达。
				c.ServerSend(ms(r.at), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
			}
		}
	}, func(*engine.Engine, time.Time) { counts = append(counts, len(warns)) }, ms(9999.9), ms(10000))
	check(t, out, "2026-09-28 15:30:25.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n")
	// 握手 3 个包，R0 一个包，之后每个请求和前一个请求的响应各一个包。
	if want := []int{0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2}; !slices.Equal(counts, want) {
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
	if st.Evicted != 5 || st.EvictedMatched != 2 || st.NoResponseEOF != 1 || st.Late != 0 || st.Connections != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 上限 64 KiB，100 个大请求并发：10 条连接上各有 10 个管道化的 POST（body 4000 字节），
// 按 1460 字节一段在 10 条连接之间轮流发送，每个包一个时间戳。100 个请求的固定开销
// 就超过了上限，要一直丢弃才能不超限。每个包之后（引擎在每个 Segment 之后执行上限）
// 计量都不超过上限，比计划要求的“上限加一个包的大小”更严。
//
// PeakBuffered 的手算：第一阶段 10 条连接都在（10240），至少有一个在途交互（512），
// 包处理完时计量不超过 65536，一个包最多带来 1460 字节，所以缓存的峰值不超过
// 65536 + 1460 - 10240 - 512 = 56244。第一阶段以 RST 结束全部连接。第二阶段只有一条
// 新连接和一个 70000 字节的请求：第 43 段之后是 1024 + 512 + 43×1460 = 64316，不超限；
// 第 44 段把缓存推到 44×1460 = 64240，计量 65776 超限，这个交互被丢弃。峰值就是 64240。
func TestMemoryLimitUnderLoad(t *testing.T) {
	const limit = 64 << 10
	var mem []int64
	var sizes []int
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "NEEDLE"), MaxMemory: limit, MaxMessage: limit}, func(w *pcapgen.Writer) {
		tick := 0
		next := func() time.Time { tick++; return t0.Add(time.Duration(tick) * time.Microsecond) }
		send := func(c *pcapgen.Conn, b []byte) {
			c.ClientSend(next(), b)
			sizes = append(sizes, len(b))
		}
		var conns []*pcapgen.Conn
		var streams [][]byte
		for i := range 10 {
			c := pcapgen.NewConn(w, netip.AddrPortFrom(cli1.Addr(), uint16(20000+i)), srv)
			c.Handshake(next())
			sizes = append(sizes, 0, 0, 0)
			var s []byte
			for j := range 10 {
				s = append(s, "POST /up"+string(rune('0'+i))+string(rune('0'+j))+" HTTP/1.1\r\nContent-Length: 4000\r\n\r\n"...)
				s = append(s, strings.Repeat("a", 4000)...)
			}
			conns, streams = append(conns, c), append(streams, s)
		}
		for more := true; more; {
			more = false
			for i, c := range conns {
				if n := min(len(streams[i]), 1460); n > 0 {
					send(c, streams[i][:n])
					streams[i] = streams[i][n:]
					more = true
				}
			}
		}
		for _, c := range conns {
			c.ClientRst(next())
			sizes = append(sizes, 0)
		}
		big := pcapgen.NewConn(w, netip.MustParseAddrPort("10.0.0.3:40000"), srv)
		big.Handshake(next())
		sizes = append(sizes, 0, 0, 0)
		head := "POST /big HTTP/1.1\r\nContent-Length: 69953\r\n\r\n" // 47 字节，一共 70000 字节
		body := []byte(head + strings.Repeat("b", 70000-len(head)))
		for len(body) > 0 {
			n := min(len(body), 1460)
			send(big, body[:n])
			body = body[n:]
		}
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	check(t, out, "")
	if len(mem) != len(sizes) {
		t.Fatalf("%d packets, %d sizes", len(mem), len(sizes))
	}
	for i, m := range mem {
		if m > limit {
			t.Fatalf("Memory after packet %d = %d, over %d", i, m, limit)
		}
	}
	// 第一阶段 10×3 + 10×10×4047/1460 取整（每条连接 28 段）+ 10 个 RST，第二阶段的握手之后是 1024。
	if i := 30 + 10*28 + 10 + 3 - 1; mem[i] != 1024 {
		t.Fatalf("Memory after the second handshake = %d, want 1024", mem[i])
	}
	if st.PeakBuffered != 64240 || st.Evicted < 1 || st.Exchanges != 101 {
		t.Fatalf("stats: %+v", st)
	}
}

// 回收的交互留着缓存和扫描器以便复用，但不计入内存计量，所以要有上限：
// 1000 个交互同时在途、各缓存 30 KB，全部结束之后，引擎留着的内存不超过 6 MB
// （上限 64 MB 时回收的缓存和扫描器行缓存的总量不超过它的 1/16，即 4 MB，
// 另加不超过 256 个交互对象）。不设上限时会留着全部 30 MB。
// 正则模式下扫描器要缓存没写完的行，body 里没有换行时，每个响应方向的扫描器都缓存了
// 约 30 KB，这部分同样要算进上限：不算的话 256 个回收的交互要多留约 7.5 MB。
func TestFreeListBounded(t *testing.T) {
	for _, regex := range []bool{false, true} {
		t.Run("regex="+strconv.FormatBool(regex), func(t *testing.T) { freeListBounded(t, regexMatcher(t, regex)) })
	}
}

// regexMatcher 返回关键词 NEEDLE 的匹配器：regex 为真时按 -E 编译成 NEE+DLE，扫描器走缓存行的路径。
func regexMatcher(t *testing.T, regex bool) *match.Matcher {
	t.Helper()
	if !regex {
		return matcher(t, "NEEDLE")
	}
	m, err := match.Compile([]string{"NEE+DLE"}, true)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func freeListBounded(t *testing.T, m *match.Matcher) {
	const n = 1000
	body := strings.Repeat("z", 30000)
	pkts, _ := decodeAll(t, func(w *pcapgen.Writer) {
		conns := make([]*pcapgen.Conn, n)
		for i := range conns {
			conns[i] = pcapgen.NewConn(w, netip.AddrPortFrom(netip.MustParseAddr("10.2.0.1"), uint16(10000+i)), srv)
			conns[i].Handshake(ms(0))
			conns[i].ClientSend(ms(1), []byte("GET / HTTP/1.1\r\n\r\n"))
			conns[i].ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 30000\r\n\r\n"+body[:29000]))
		}
		for _, c := range conns {
			c.ServerSend(ms(3), []byte(body[29000:]))
		}
	})
	e := engine.New(engine.Config{
		Matcher: m, Timeout: 30 * time.Second,
		MaxMemory: 64 << 20, MaxMessage: 8 << 20,
		Emit: func(*output.Block) {},
	})
	for i := range pkts {
		e.Segment(&pkts[i].seg, pkts[i].ts)
		e.Advance(pkts[i].ts)
	}
	e.Finish(pkts[len(pkts)-1].ts)
	if st := e.Stats(); st.Complete != n || st.PeakInFlight != n {
		t.Fatalf("stats: %+v", st)
	}
	// 引擎留着的内存：引擎还活着时的堆，减去引擎被回收之后的堆。
	pkts = nil
	var alive, gone runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&alive)
	runtime.KeepAlive(e)
	e = nil
	runtime.GC()
	runtime.ReadMemStats(&gone)
	retained := int64(alive.HeapAlloc) - int64(gone.HeapAlloc)
	t.Logf("retained %d bytes", retained)
	if retained > 6<<20 {
		t.Fatalf("engine retains %d bytes after all exchanges ended", retained)
	}
}

// 超时或被丢弃的交互留在队列里当占位，它的缓存已经不计入内存计量，也要真的释放：
// 1000 个交互各缓存了约 30 KB 的响应后超时，连接都还在，占位等着迟到的响应。
// 此时计量是每条连接 1024 加每个占位 384，引擎留着的内存不超过 10 MB；
// 占位留着缓存的话要多 30 MB。
// 正则模式下占位的扫描器还缓存着没写完的行（每个约 29 KB），也要释放。
func TestPlaceholderReleasesBuffer(t *testing.T) {
	for _, regex := range []bool{false, true} {
		t.Run("regex="+strconv.FormatBool(regex), func(t *testing.T) { placeholderReleasesBuffer(t, regexMatcher(t, regex)) })
	}
}

func placeholderReleasesBuffer(t *testing.T, m *match.Matcher) {
	const n = 1000
	body := strings.Repeat("z", 29000)
	pkts, _ := decodeAll(t, func(w *pcapgen.Writer) {
		for i := range n {
			c := pcapgen.NewConn(w, netip.AddrPortFrom(netip.MustParseAddr("10.2.0.1"), uint16(10000+i)), srv)
			c.Handshake(ms(0))
			c.ClientSend(ms(1), []byte("GET / HTTP/1.1\r\n\r\n"))
			c.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 30000\r\n\r\n"+body))
		}
	})
	e := engine.New(engine.Config{
		Matcher: m, Timeout: 30 * time.Second,
		MaxMemory: 64 << 20, MaxMessage: 8 << 20,
		Emit: func(*output.Block) {},
	})
	for i := range pkts {
		e.Segment(&pkts[i].seg, pkts[i].ts)
		e.Advance(pkts[i].ts)
	}
	e.Advance(ms(40000))
	if st := e.Stats(); st.Incomplete != n || st.PeakInFlight != n || e.Memory() != n*(1024+384) {
		t.Fatalf("stats: %+v, Memory %d", st, e.Memory())
	}
	pkts = nil
	var alive, gone runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&alive)
	runtime.KeepAlive(e)
	e = nil
	runtime.GC()
	runtime.ReadMemStats(&gone)
	retained := int64(alive.HeapAlloc) - int64(gone.HeapAlloc)
	t.Logf("retained %d bytes", retained)
	if retained > 10<<20 {
		t.Fatalf("engine retains %d bytes with %d placeholders", retained, n)
	}
}

// 丢弃 Upgrade 请求时回放出的请求照常计入，仍然超限时同样被丢弃，不会等到连接释放时
// 再以 no-response(closed) 输出。上限 2600。C1 的 Upgrade 请求 U 后面跟着管道化的
// GET /TOKEN（缓存着等决定）；C2 的 SYN 使计量到 2048 + 512 + 44 = 2604，超限：
// 丢弃 U（得 2048 + 384），回放出 GET /TOKEN（再加 512 + 23，得 2967），仍超限，
// 丢弃它（已命中，不输出，得 2816），仍超限，释放最久没有包的 C1。
func TestEvictedUpgradeReplayEvicted(t *testing.T) {
	cli3 := netip.MustParseAddrPort("10.0.0.1:52816")
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 2600}, func(w *pcapgen.Writer) {
		c1 := pcapgen.NewConn(w, cli1, srv)
		c1.Handshake(ms(0))
		c1.ClientSend(ms(1), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\nGET /TOKEN HTTP/1.1\r\n\r\n"))
		pcapgen.NewConn(w, cli2, srv).Handshake(ms(2))
		pcapgen.NewConn(w, cli3, srv).Handshake(ms(3))
	})
	check(t, out, "")
	if st.Exchanges != 2 || st.Evicted != 2 || st.EvictedMatched != 1 || st.NoResponseClosed != 0 || st.NoResponseEOF != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 单个交互喂入超过 64 KiB 的方向，回收时不留扫描器（和超过 64 KiB 的缓存一样），
// 即使份额还放得下：上限 1 GiB（份额 64 MB），20 个交互各有 1 MiB 没有换行的响应 body，
// 正则模式下每个响应方向的扫描器都缓存了 1 MiB。全部结束后引擎留着的内存不超过 4 MB；
// 留着扫描器的话要多 20 MB。
func TestFreeListDropsLargeScanners(t *testing.T) {
	body := strings.Repeat("z", 1<<20)
	pkts, _ := decodeAll(t, func(w *pcapgen.Writer) {
		// 20 个交互同时在途：先给每条连接发响应的前一半，再逐个发完。
		conns := make([]*pcapgen.Conn, 20)
		for i := range conns {
			conns[i] = pcapgen.NewConn(w, netip.AddrPortFrom(netip.MustParseAddr("10.2.0.1"), uint16(10000+i)), srv)
			conns[i].Handshake(ms(0))
			conns[i].ClientSend(ms(1), []byte("GET / HTTP/1.1\r\n\r\n"))
			conns[i].ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n"+body[:1<<19]))
		}
		for _, c := range conns {
			c.ServerSend(ms(3), []byte(body[1<<19:]))
		}
	})
	e := engine.New(engine.Config{
		Matcher: regexMatcher(t, true), Timeout: 30 * time.Second,
		MaxMemory: 1 << 30, MaxMessage: 8 << 20,
		Emit: func(*output.Block) {},
	})
	for i := range pkts {
		e.Segment(&pkts[i].seg, pkts[i].ts)
		e.Advance(pkts[i].ts)
	}
	e.Finish(pkts[len(pkts)-1].ts)
	if st := e.Stats(); st.Complete != 20 || st.PeakInFlight != 20 || st.Evicted != 0 {
		t.Fatalf("stats: %+v", st)
	}
	pkts = nil
	var alive, gone runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&alive)
	runtime.KeepAlive(e)
	e = nil
	runtime.GC()
	runtime.ReadMemStats(&gone)
	retained := int64(alive.HeapAlloc) - int64(gone.HeapAlloc)
	t.Logf("retained %d bytes", retained)
	if retained > 4<<20 {
		t.Fatalf("engine retains %d bytes after all exchanges ended", retained)
	}
}

// 缺请求的交互同样按开始时间参与丢弃：半路连接（没有握手）上先收到一个没有请求的大响应，
// body 里有关键词。上限 3000：第二个包之后计量是 1024 + 512 + 2920 = 4456，超限，
// 丢弃这个交互（已命中，不输出），剩下 1024 加占位的 384，连接本身不释放；
// 剩下的响应由占位收下，收完时占位回收。
// 之后同一连接上的请求和响应照常配对输出。
func TestEvictNoRequestExchange(t *testing.T) {
	var mem []int64
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 3000}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.ServerSend(ms(0), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\nTOKEN"+strings.Repeat("x", 4995)))
		c.ClientSend(ms(10), []byte("GET /TOKEN HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(11), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	check(t, out, "2026-09-28 15:30:12.355 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n"+
		"GET /TOKEN HTTP/1.1\r\n\r\n"+
		"HTTP/1.1 204 No Content\r\n\r\n")
	// 响应 5042 字节分 4 段（1460×3 + 662），之后是请求和 204。
	want := []int64{1024 + 512 + 1460, 1024 + 384, 1024 + 384, 1024, 1024 + 512 + 23, 1024}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
	if st.Connections != 1 || st.MidStream != 1 || st.Evicted != 1 || st.EvictedMatched != 1 ||
		st.Exchanges != 2 || st.Complete != 1 || st.NoRequest != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// 占位按每个 384 字节计入内存计量：服务端一直不回响应、客户端隔一会儿就发一个请求时，
// 超时留下的占位只增不减，计量随之增长，超过上限后和别的内存一样被回收。上限 2400，
// 每个请求 19 字节。R1（t=0）、R2（t=31）、R3（t=62）依次超时，各留一个占位：t=92.5 时
// （客户端的一个纯 ACK）是 1024 + 3×384 = 2176。R4（t=93）使计量到 2176 + 531 = 2707，超限：
// 丢弃 R4 后还有 2560，没有在途交互可丢，释放这条连接，回到 0。
func TestPlaceholdersCounted(t *testing.T) {
	var mem []int64
	out, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 2400}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		for _, at := range []float64{0, 31000, 62000} {
			c.ClientSend(ms(at), []byte("GET /r HTTP/1.1\r\n\r\n"))
		}
		c.ClientAck(ms(92500))
		c.ClientSend(ms(93000), []byte("GET /r HTTP/1.1\r\n\r\n"))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	check(t, out, "")
	want := []int64{1024, 1024, 1024,
		1024 + 531,         // R1
		1024 + 384 + 531,   // R2，R1 已超时
		1024 + 2*384 + 531, // R3
		1024 + 3*384,       // ACK，R3 已超时
		0,                  // R4：丢弃 R4，释放连接
	}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
	if st.NoResponseTimeout != 3 || st.Evicted != 1 || st.Connections != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 因内存上限丢弃的 Upgrade 请求像超时的一样按被拒处理：它后面管道化的请求马上照常解析、
// 从丢弃时起计时，不等到连接关闭或输入结束。
//   - 头部收到一半时被丢弃（上限 7400）：计量同 TestEvictedUpgradeRequestKeepsHeld，t=2 时丢弃 U；
//     t=4 请求发完，GET /TOKEN 随即开始，t=30.004 超时输出。
//   - 请求发完、后面的 GET /TOKEN 已经缓存着时被丢弃（上限 8000）：U 带 1000 字节的 X-Pad，1043 字节。
//     B 的响应第三个包之后计量是 2048 + (512+1043) + (512+19) + 4380 = 8514，超限，丢弃 U，
//     得 8514 - 1555 + 384 = 7343；回放出 GET /TOKEN（512 + 23），得 7878，不再超限。
//     GET /TOKEN 从 t=2 起计时，t=30.002 超时输出；定位行时间是它所在包的时间 t=0。
func TestEvictedUpgradeGivesUpDecision(t *testing.T) {
	pad := "X-Pad: " + strings.Repeat("p", 991) + "\r\n" // 1000 字节
	cases := []struct {
		name  string
		limit int64
		u     func(u *pcapgen.Conn) // U 在 t=0 发出的请求
		rest  func(u *pcapgen.Conn) // B 的响应之后 U 再发的
		tick  time.Time
		want  string
	}{
		{
			name:  "evicted while head in progress",
			limit: 7400,
			u: func(u *pcapgen.Conn) {
				u.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n"))
			},
			rest: func(u *pcapgen.Conn) {
				u.ClientSend(ms(4), []byte("\r\nGET /TOKEN HTTP/1.1\r\n\r\n"))
			},
			tick: ms(30004),
			want: "2026-09-28 15:30:12.349 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n",
		},
		{
			name:  "evicted while holding",
			limit: 8000,
			rest:  func(*pcapgen.Conn) {},
			u: func(u *pcapgen.Conn) {
				u.ClientSend(ms(0), []byte("GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n"+pad+"\r\nGET /TOKEN HTTP/1.1\r\n\r\n"))
			},
			tick: ms(30002),
			want: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" +
				"GET /TOKEN HTTP/1.1\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snaps, _, st := replayTicks(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: tc.limit}, func(w *pcapgen.Writer) {
				u := pcapgen.NewConn(w, cli1, srv)
				b := pcapgen.NewConn(w, cli2, srv)
				u.Handshake(ms(-1))
				b.Handshake(ms(-1))
				tc.u(u)
				b.ClientSend(ms(1), []byte("GET /b HTTP/1.1\r\n\r\n"))
				b.ServerSend(ms(2), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"+strings.Repeat("x", 5000)))
				tc.rest(u)
			}, tc.tick)
			check(t, snaps[0], tc.want)
			if st.Evicted != 1 || st.Exchanges != 3 || st.NoResponseTimeout != 1 || st.NoResponseEOF != 0 {
				t.Fatalf("stats: %+v", st)
			}
		})
	}
}
