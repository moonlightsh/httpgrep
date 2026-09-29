package engine_test

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"httpgrep/internal/engine"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// record 是一条 pcap 记录：抓包时间和链路层帧。
type record struct {
	ts    time.Time
	frame []byte
}

// records 用 build 生成抓包并读回全部记录。
func records(t *testing.T, build func(w *pcapgen.Writer)) []record {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgen.NewWriter(&buf, pcap.LinkEthernet)
	build(w)
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}
	r, err := pcap.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var out []record
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, record{p.Timestamp, bytes.Clone(p.Data)})
	}
}

// 同样内容的两份抓包，一份每个包都完整按序，另一份把某些段重传一次（紧跟着重传，
// 以及过一会儿再重传），还把同一时刻发出的相邻两段顺序颠倒：两份的输出逐字节相同。
func TestRetransmitAndReorderSameOutput(t *testing.T) {
	build := func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.MSS = 16
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("POST /a HTTP/1.1\r\nContent-Length: 30\r\n\r\nid=TOKEN-42&pad=aaaaaaaaaaaaaa"))
		c.ServerSend(ms(4), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nTOK\r\n5\r\nEN-43\r\n0\r\n\r\n"))
		c.ClientSend(ms(10), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(13), []byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nnothing to see here\n"))
		c.ClientFin(ms(20))
		c.ServerFin(ms(21))
	}
	clean := records(t, build)
	// 挑出几段来改：同一时刻相邻两段颠倒，两个段各重传一次。
	messy := func(w *pcapgen.Writer) {
		for i := 0; i < len(clean); i++ {
			r := clean[i]
			switch {
			case i == 5 || i == 10:
				// 和下一段颠倒；两段时间相同，时间戳照原样。
				n := clean[i+1]
				if !n.ts.Equal(r.ts) {
					t.Fatalf("records %d and %d differ in time", i, i+1)
				}
				_ = w.Record(r.ts, n.frame, 0)
				_ = w.Record(r.ts, r.frame, 0)
				i++
				continue
			case i == 4 || i == 14:
				// 紧跟着重传一次。
				_ = w.Record(r.ts, r.frame, 0)
			}
			_ = w.Record(r.ts, r.frame, 0)
			if i == 8 {
				// 过一会儿再重传更早的一段（和下一段同一时刻，时间不倒退）。
				_ = w.Record(clean[i+1].ts, clean[3].frame, 0)
			}
		}
	}
	// 颠倒不增减记录，重传共 3 次：messy 要比 clean 多 3 条记录，否则上面的下标已经对不上样本。
	if n := len(records(t, messy)); n != len(clean)+3 {
		t.Fatalf("messy has %d records, want %d", n, len(clean)+3)
	}
	cfg := engine.Config{Matcher: matcher(t, "TOKEN")}
	want, _ := replay(t, cfg, build)
	check(t, want, "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 4.0ms\n"+
		"POST /a HTTP/1.1\r\nContent-Length: 30\r\n\r\nid=TOKEN-42&pad=aaaaaaaaaaaaaa\n"+
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nTOK\r\n5\r\nEN-43\r\n0\r\n\r\n")
	got, st := replay(t, cfg, messy)
	check(t, got, want)
	if st.Exchanges != 2 || st.Complete != 2 || st.Gaps != 0 {
		t.Fatalf("stats: %+v", st)
	}
}
