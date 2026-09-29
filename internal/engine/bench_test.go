package engine_test

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// packet 是解码好的一个段和它的抓包时间；Payload 已拷贝，可以反复喂。
type packet struct {
	seg decode.Segment
	ts  time.Time
}

// decodeAll 用 build 生成抓包，经 pcap.Reader 和 decode.Decode 解码成段的序列。
func decodeAll(tb testing.TB, build func(w *pcapgen.Writer)) (pkts []packet, payload int64) {
	tb.Helper()
	var capture bytes.Buffer
	w := pcapgen.NewWriter(&capture, pcap.LinkEthernet)
	build(w)
	if err := w.Err(); err != nil {
		tb.Fatal(err)
	}
	r, err := pcap.NewReader(&capture)
	if err != nil {
		tb.Fatal(err)
	}
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return pkts, payload
		}
		if err != nil {
			tb.Fatal(err)
		}
		var seg decode.Segment
		if decode.Decode(r.LinkType(), p.Data, p.OrigLen, &seg) != decode.OK {
			tb.Fatal("packet does not decode")
		}
		seg.Payload = bytes.Clone(seg.Payload)
		payload += int64(len(seg.Payload))
		pkts = append(pkts, packet{seg, p.Timestamp})
	}
}

// keepAlive 在一条连接上生成 n 个 keep-alive 交互，响应 body 是 size 字节，不含关键词。
func keepAlive(n, size int) func(w *pcapgen.Writer) {
	body := bytes.Repeat([]byte("abcdefghij"), size/10)
	res := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"), body...)
	return func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(0))
		for i := range n {
			c.ClientSend(ms(float64(2*i+1)), []byte("GET /item HTTP/1.1\r\nHost: x\r\n\r\n"))
			c.ServerSend(ms(float64(2*i+2)), res)
		}
	}
}

var benchMatcher = func() *match.Matcher {
	m, err := match.Compile([]string{"NEEDLE"}, false)
	if err != nil {
		panic(err)
	}
	return m
}()

func newBenchEngine(emitted *int) *engine.Engine {
	return engine.New(engine.Config{
		Matcher:    benchMatcher,
		Timeout:    30 * time.Second,
		MaxMemory:  256 << 20,
		MaxMessage: 8 << 20,
		Emit:       func(*output.Block) { *emitted++ },
	})
}

// 同一连接上反复出现的交互复用交互对象、缓存和扫描器：
// 预热之后，引擎自身每个交互不分配内存。
// 剩下的分配来自 http1 把头部取值转成字符串（Head.Target、Head.ContentType），
// 每条消息至多一次，不随包数增长。
func TestSteadyStateAllocs(t *testing.T) {
	const warm, runs = 50, 200
	pkts, _ := decodeAll(t, keepAlive(warm+runs+1, 4000))
	var emitted int
	e := newBenchEngine(&emitted)
	// 握手 3 个包，之后每个交互 2 + ceil(响应长度/1460) 个包。
	perExchange := (len(pkts) - 3) / (warm + runs + 1)
	i := 0
	feed := func(n int) {
		for range n {
			p := &pkts[i]
			e.Segment(&p.seg, p.ts)
			e.Advance(p.ts)
			i++
		}
	}
	feed(3 + warm*perExchange)
	allocs := testing.AllocsPerRun(runs-1, func() { feed(perExchange) })
	if allocs > 2 {
		t.Fatalf("allocs per exchange = %v, want <= 2 (Head.Target, Head.ContentType)", allocs)
	}
	if st := e.Stats(); st.Complete < warm+runs-1 || emitted != 0 {
		t.Fatalf("Complete %d emitted %d", st.Complete, emitted)
	}
}

// BenchmarkKeepAlive 测引擎处理 keep-alive 交互的吞吐（从 Segment 算起，不含 pcap 读取和解码）。
func BenchmarkKeepAlive(b *testing.B) {
	const n = 1000
	pkts, payload := decodeAll(b, keepAlive(n, 16000))
	b.SetBytes(payload)
	b.ReportAllocs()
	for b.Loop() {
		var emitted int
		e := engine.New(engine.Config{
			Matcher:    benchMatcher,
			Timeout:    30 * time.Second,
			MaxMemory:  256 << 20,
			MaxMessage: 8 << 20,
			Emit:       func(*output.Block) { emitted++ },
		})
		for i := range pkts {
			p := &pkts[i]
			e.Segment(&p.seg, p.ts)
			e.Advance(p.ts)
		}
		e.Finish(pkts[len(pkts)-1].ts)
		if e.Stats().Complete != n {
			b.Fatalf("Complete %d", e.Stats().Complete)
		}
	}
}
