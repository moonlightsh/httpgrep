package engine_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/pcapgen"
)

// truncServer 写一个服务端数据包，只抓到 payload 的前 keep 字节（snaplen 截断），
// seq 是这个包的序号。调用方随后用 SkipServer 推进 pcapgen 的序号。
func truncServer(w *pcapgen.Writer, ts time.Time, seq, ack uint32, payload []byte, keep int) {
	frame := pcapgen.Frame(w.Link(), pcapgen.TCP(srv, cli1, seq, ack, decode.ACK, payload))
	cut := len(frame) - len(payload) + keep
	_ = w.Record(ts, frame[:cut], len(frame))
}

// 响应 body 里连续三个包都只抓到头部：相邻的缺口合并成一个缺口标记。
func TestGapPiecesMerged(t *testing.T) {
	const req = "GET /TOKEN HTTP/1.1\r\n\r\n" // 23 字节
	const head = "HTTP/1.1 200 OK\r\nContent-Length: 310\r\n\r\n"
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte(req))
		c.ServerSend(ms(1), []byte(head))
		seq := uint32(2001 + len(head))
		for i := range 3 {
			truncServer(w, ms(2), seq+uint32(100*i), 1001+uint32(len(req)), make([]byte, 100), 0)
		}
		c.SkipServer(300)
		c.ServerSend(ms(3), []byte("0123456789"))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 3.0ms\n"+
		req+head+
		"[gap: 300 bytes missing]\n"+
		"0123456789\n")
	if st.Gaps != 3 || st.GapBytes != 300 {
		t.Fatalf("stats: %+v", st)
	}
}

// 每个缺口标记按 64 字节计入 --max-message：body 的每个包只抓到 1 字节时，数据和缺口
// 交替出现，片段不能合并。头部 40 字节，每个包计 1 + 64，4 个包之后正好 300；
// 第 5 个包起截断，剩下 6 个包的 60 字节并入截断标记。
func TestGapPiecesCountTowardMaxMessage(t *testing.T) {
	const req = "GET /TOKEN HTTP/1.1\r\n\r\n"
	const head = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" // 40 字节
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMessage: 300}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte(req))
		c.ServerSend(ms(1), []byte(head))
		seq := uint32(2001 + len(head))
		for i := range 10 {
			truncServer(w, ms(2), seq+uint32(10*i), 1001+uint32(len(req)), []byte("bbbbbbbbbb"), 1)
		}
		c.SkipServer(100)
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 2.0ms\n"+
		req+head+
		strings.Repeat("b\n[gap: 9 bytes missing]\n", 4)+
		"[truncated: 60 bytes over --max-message]\n")
	if st.Truncated != 1 || st.Gaps != 10 {
		t.Fatalf("stats: %+v", st)
	}
}

// 新的缺口标记放不进 --max-message 时改为截断：头部 40 字节加 body 200 字节之后是 240，
// 缺口标记计 64 会到 304，超过 300，这 10 字节并入截断标记，后面的 20 字节也并进去，一共 30。
func TestGapMarkerOverMaxMessageTruncates(t *testing.T) {
	const req = "GET /TOKEN HTTP/1.1\r\n\r\n"
	const head = "HTTP/1.1 200 OK\r\nContent-Length: 230\r\n\r\n" // 40 字节
	out, st := replay(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMessage: 300}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte(req))
		c.ServerSend(ms(1), []byte(head+strings.Repeat("a", 200)))
		truncServer(w, ms(2), uint32(2001+240), 1001+uint32(len(req)), []byte("bbbbbbbbbb"), 0)
		c.SkipServer(10)
		c.ServerSend(ms(3), []byte(strings.Repeat("c", 20)))
	})
	check(t, out, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 incomplete 3.0ms\n"+
		req+head+strings.Repeat("a", 200)+"\n"+
		"[truncated: 30 bytes over --max-message]\n")
	if st.Truncated != 1 || st.Gaps != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// 1xx 中间响应的消息和片段计入内存：一个请求（38 字节）后面跟 40 个 100 Continue
// （每个 25 字节，同一个包里）。连接 2048，在途交互 1024，缓存 38 + 1000 字节；
// 交互的前 2 条消息、前 4 个片段含在 1024 里，其余每条消息 128、每个片段 64：
// 41 条消息计 39×128 = 4992，41 个片段计 37×64 = 2368，合计 11470。
func TestInterimMessagesCountedInMemory(t *testing.T) {
	var mem []int64
	replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(0))
		c.ClientSend(ms(1), []byte("POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\n"))
		c.ServerSend(ms(2), []byte(strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 40)))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	want := []int64{2048, 2048, 2048, 2048 + 1024 + 38, 11470}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
}

// 解析器里没收完的头部行计入内存：请求行（16 字节）已缓存在交互里，
// "X: " 加 1000 字节还没换行，留在解析器的行缓存里（1003）。
func TestPartialHeadLineCountedInMemory(t *testing.T) {
	var mem []int64
	replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(0))
		c.ClientSend(ms(1), []byte("GET / HTTP/1.1\r\nX: "+strings.Repeat("a", 1000)))
		c.ClientSend(ms(2), []byte("\r\n\r\n"))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	want := []int64{2048, 2048, 2048, 2048 + 1024 + 16 + 1003, 2048 + 1024 + 1023}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
}

// 上限 20000：每条连接各有一个没收完的 8000 字节头部行，第三条连接到来时超限，
// 先丢弃最早的在途交互，仍超限就释放最久没有包的连接，解析器的行缓存随之释放。
func TestPartialHeadLinesBoundedByMaxMemory(t *testing.T) {
	var peak int64
	_, st := replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN"), MaxMemory: 20000}, func(w *pcapgen.Writer) {
		for i := range 5 {
			c := pcapgen.NewConn(w, cli1, srv)
			c.Client = netip.AddrPortFrom(cli1.Addr(), uint16(52814+i))
			c.Handshake(ms(float64(i)))
			c.ClientSend(ms(float64(i)), []byte("GET / HTTP/1.1\r\nX: "+strings.Repeat("a", 8000)))
		}
	}, func(e *engine.Engine, _ time.Time) { peak = max(peak, e.Memory()) })
	if peak > 20000 || st.Evicted == 0 {
		t.Fatalf("peak Memory %d, stats %+v", peak, st)
	}
}

// 没看到握手的半路连接，定角色之前每个方向多一个解析器，另计 1024 字节；
// 定了角色之后只剩连接的 2048。
func TestMidStreamProbesCountedInMemory(t *testing.T) {
	var mem []int64
	replayEach(t, engine.Config{Matcher: matcher(t, "TOKEN")}, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.ClientSend(ms(0), []byte("zz"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	}, func(e *engine.Engine, _ time.Time) { mem = append(mem, e.Memory()) })
	want := []int64{2048 + 1024, 2048}
	if !slices.Equal(mem, want) {
		t.Fatalf("Memory after each packet = %v, want %v", mem, want)
	}
}
