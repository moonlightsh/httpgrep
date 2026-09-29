package engine_test

import (
	"bytes"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

var fuzzRequests = []string{
	"GET /needle HTTP/1.1\r\nHost: a\r\n\r\n",
	"POST /p HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello needle",
	"PUT /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nneedle\r\n0\r\n\r\n",
	"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
	"CONNECT a:443 HTTP/1.1\r\n\r\n",
	"HEAD / HTTP/1.1\r\n\r\n",
	"GET /1 HTTP/1.1\r\n\r\nGET /2 HTTP/1.1\r\n\r\nGET /3 HTTP/1.1\r\n\r\n",
	"POST /big HTTP/1.1\r\nContent-Length: 3000\r\n\r\n" + strings.Repeat("x", 2990) + "needle",
	"garbage without request line\n",
}

var fuzzResponses = []string{
	"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nneedle",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
	"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello",
	"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
	"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nclose delimited needle",
	"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\n\x1f\x8b\x08\x00",
	"HTTP/1.1 400 Bad\r\nContent-Length: 0\r\n\r\n",
	"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n" + strings.Repeat("y", 5000),
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfff\r\n" + strings.Repeat("z", 100),
}

// genCapture 按种子生成若干条交错的连接，返回按写出顺序排列的记录。
func genCapture(in []byte, t0 time.Time) []pcap.Packet {
	var buf bytes.Buffer
	w := pcapgen.NewWriter(&buf, pcap.LinkEthernet)
	server := netip.MustParseAddrPort("10.0.0.2:80")
	conns := make([]*pcapgen.Conn, 4)
	now := t0
	for i := range conns {
		cli := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(50000+i))
		if i == 3 {
			cli = netip.MustParseAddrPort("[fd00::1]:50003")
			conns[i] = pcapgen.NewConn(w, cli, netip.MustParseAddrPort("[fd00::2]:80"))
		} else {
			conns[i] = pcapgen.NewConn(w, cli, server)
		}
		conns[i].ClientISN = 0xfffff000 + uint32(i)*977 // 靠近回绕
		conns[i].MSS = 1460
	}
	for len(in) >= 3 {
		op, a, b := in[0], in[1], in[2]
		in = in[3:]
		c := conns[int(a)%len(conns)]
		switch op % 12 {
		case 0:
			c.Handshake(now)
		case 1:
			c.ClientSend(now, []byte(fuzzRequests[int(b)%len(fuzzRequests)]))
		case 2:
			c.ServerSend(now, []byte(fuzzResponses[int(b)%len(fuzzResponses)]))
		case 3:
			c.SkipClient(int(b))
		case 4:
			c.SkipServer(int(b) * 7)
		case 5:
			c.ClientFin(now)
		case 6:
			c.ServerFin(now)
		case 7:
			c.ClientRst(now)
		case 8:
			now = now.Add(time.Duration(b) * 20 * time.Millisecond)
		case 9:
			c.MSS = 1 + int(b)*6
		case 10:
			c.ClientAck(now)
			c.ServerAck(now)
		case 11:
			flags := decode.Flags(b & 0x3f)
			c.Raw(now, a&1 == 0, uint32(b)<<24|uint32(a), uint32(a)<<20, flags, []byte(fuzzRequests[int(b)%len(fuzzRequests)]))
		}
	}
	r, err := pcap.NewReader(&buf)
	if err != nil {
		panic(err)
	}
	var recs []pcap.Packet
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		p.Data = append([]byte(nil), p.Data...)
		recs = append(recs, p)
	}
	return recs
}

// FuzzEngine 用种子驱动 pcapgen 生成交错的抓包，再按扰动字节做乱序、丢段、重复、
// 截断和时间戳倒退，经 pcap.Reader、decode.Decode 交给 Engine：不 panic；
// 每个包之后内存计量不超过 MaxMemory；Finish 之后计量回到 0，没有在途交互。
func FuzzEngine(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 2, 0, 0, 5, 0, 0, 6, 0, 0}, []byte{0})
	f.Add([]byte{0, 1, 0, 1, 1, 6, 2, 1, 7, 0, 2, 0, 1, 2, 3, 2, 2, 3, 8, 0, 200, 5, 1, 0}, []byte{0, 0, 0x21, 0, 0x42})
	f.Add([]byte{9, 0, 3, 1, 0, 7, 2, 0, 7, 3, 0, 40, 1, 0, 1, 2, 0, 0, 8, 0, 255, 8, 0, 255}, []byte{0x10, 0x31, 0x02})
	f.Add([]byte{0, 0, 0, 1, 0, 3, 2, 0, 2, 1, 0, 0, 11, 0, 5, 1, 0, 4, 2, 0, 3}, []byte{0x63, 0x84, 0})
	f.Add([]byte{0, 2, 0, 1, 2, 8, 2, 2, 8, 0, 3, 0, 1, 3, 1, 2, 3, 0}, []byte{0x05, 0x16, 0x27, 0x38})
	f.Fuzz(func(t *testing.T, gen, perturb []byte) {
		t0 := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		recs := genCapture(gen, t0)
		// 扰动：低 3 位选动作，高位是参数。
		var out []pcap.Packet
		for i := 0; i < len(recs); i++ {
			p := recs[i]
			var k byte
			if len(perturb) > 0 {
				k = perturb[i%len(perturb)]
			}
			switch k & 7 {
			case 1: // 丢段
				continue
			case 2: // 和后面第 n 个交换
				if j := i + 1 + int(k>>3)%4; j < len(recs) {
					recs[i], recs[j] = recs[j], recs[i]
					p = recs[i]
				}
			case 3: // 重复
				out = append(out, p)
			case 4: // snaplen 截断
				n := min(len(p.Data), 14+int(k>>3)*4)
				p.OrigLen = max(p.OrigLen, len(p.Data))
				p.Data = p.Data[:n]
			case 5: // 时间戳倒退
				p.Timestamp = p.Timestamp.Add(-time.Duration(k>>3) * time.Second)
			case 6: // 时间跳到很远以后
				p.Timestamp = p.Timestamp.Add(time.Duration(k>>3) * time.Minute)
			}
			out = append(out, p)
		}
		var capture bytes.Buffer
		w := pcapgen.NewWriter(&capture, pcap.LinkEthernet)
		for _, p := range out {
			_ = w.Record(p.Timestamp, p.Data, p.OrigLen)
		}

		m, err := match.Compile([]string{"needle"}, false)
		if err != nil {
			t.Fatal(err)
		}
		ow := output.NewWriter(io.Discard, output.Options{})
		const maxMem = 24 << 10
		e := engine.New(engine.Config{
			Matcher:    m,
			Timeout:    time.Second,
			MaxMemory:  maxMem,
			MaxMessage: 4 << 10,
			Emit: func(b *output.Block) {
				if err := ow.Write(b); err != nil {
					t.Fatal(err)
				}
			},
		})
		r, err := pcap.NewReader(&capture)
		if err != nil {
			t.Fatal(err)
		}
		var seg decode.Segment
		var clock time.Time
		for {
			p, err := r.Next()
			if err != nil {
				break
			}
			if p.Timestamp.After(clock) {
				clock = p.Timestamp
			}
			if decode.Decode(r.LinkType(), p.Data, p.OrigLen, &seg) != decode.OK {
				continue
			}
			e.Segment(&seg, clock)
			if got := e.Memory(); got > maxMem {
				t.Fatalf("Memory %d > MaxMemory %d after Segment", got, maxMem)
			}
			e.Advance(clock)
			if got := e.Memory(); got < 0 || got > maxMem {
				t.Fatalf("Memory %d out of [0, %d] after Advance", got, maxMem)
			}
		}
		e.Finish(clock)
		if got := e.Memory(); got != 0 {
			t.Fatalf("Memory after Finish = %d, want 0", got)
		}
		st := e.Stats()
		if st.Exchanges < st.Matched || st.Evicted < st.EvictedMatched {
			t.Fatalf("inconsistent stats %+v", st)
		}
	})
}
