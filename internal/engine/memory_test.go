package engine_test

import (
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
