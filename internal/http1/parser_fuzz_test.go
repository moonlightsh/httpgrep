package http1_test

import (
	"testing"
	"time"

	"httpgrep/internal/http1"
)

// orderSink 检查一条流上的事件顺序：Begin、若干 Raw/Head/Body/Gap、End，
// 消息之间只允许 Desync；Orphan 消息没有 Head 和 Body；Begin 的偏移递增。
type orderSink struct {
	t       *testing.T
	open    bool
	orphan  bool
	head    bool
	lastOff int64
	raw     int64 // Raw 字节数
	body    int64 // Body 字节数
	fed     *int64
}

func (s *orderSink) need(what string) {
	s.t.Helper()
	if !s.open {
		s.t.Fatalf("%s outside a message", what)
	}
}

func (s *orderSink) Begin(b http1.Begin) {
	if s.open {
		s.t.Fatalf("Begin at %d while a message is open", b.Off)
	}
	if b.Off < s.lastOff || b.Off < 0 || b.Off >= *s.fed+1 {
		s.t.Fatalf("Begin.Off %d out of order (last %d, fed %d)", b.Off, s.lastOff, *s.fed)
	}
	s.lastOff = b.Off
	s.open, s.orphan, s.head = true, b.Orphan, false
}

func (s *orderSink) Raw(sec http1.Section, b []byte) {
	s.need("Raw")
	if len(b) == 0 {
		s.t.Fatal("empty Raw")
	}
	if s.orphan && sec != http1.SecUnparsed {
		s.t.Fatalf("orphan message got Raw section %d", sec)
	}
	s.raw += int64(len(b))
	if s.raw > *s.fed {
		s.t.Fatalf("Raw bytes %d exceed fed bytes %d", s.raw, *s.fed)
	}
}

func (s *orderSink) Head(h *http1.Head) {
	s.need("Head")
	if s.orphan || s.head {
		s.t.Fatalf("Head on orphan=%v or twice=%v", s.orphan, s.head)
	}
	s.head = true
}

func (s *orderSink) Body(b []byte) {
	s.need("Body")
	if !s.head {
		s.t.Fatal("Body before Head")
	}
	s.body += int64(len(b))
	if s.body > s.raw {
		s.t.Fatalf("Body bytes %d exceed Raw bytes %d", s.body, s.raw)
	}
}

func (s *orderSink) Gap(sec http1.Section, n int64) {
	s.need("Gap")
	if n <= 0 {
		s.t.Fatalf("Gap n=%d", n)
	}
}

func (s *orderSink) End(complete bool, ts time.Time) {
	s.need("End")
	if complete && (s.orphan || !s.head) {
		s.t.Fatalf("complete End on orphan=%v head=%v", s.orphan, s.head)
	}
	s.open = false
}

func (s *orderSink) Desync(off int64) {}

var fuzzMethods = []string{"", "GET", "HEAD", "CONNECT"}

// FuzzParser 把任意字节流按 cuts 切分后喂给请求或响应解析器，其间插入缺口、
// Resume 和 Tunnel：不 panic，事件顺序合法，Close 之后没有打开的消息。
func FuzzParser(f *testing.F) {
	req := "GET / HTTP/1.1\r\nHost: a\r\n\r\nPOST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello" +
		"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX: y\r\n\r\n"
	res := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nHTTP/1.0 200 OK\r\n\r\nrest"
	up := "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\nGET /next HTTP/1.1\r\n\r\n"
	f.Add(uint8(0), []byte(req), []byte{5, 17, 3, 200, 1})
	f.Add(uint8(1), []byte(res), []byte{1, 1, 1, 1, 90})
	f.Add(uint8(2), []byte(req), []byte{0x80 | 10, 20})
	f.Add(uint8(0), []byte(up), []byte{0x40, 10, 0x41, 80})
	f.Add(uint8(0), []byte(up), []byte{0x60, 10, 0x61, 80})
	f.Add(uint8(3), []byte("garbage\nHTTP/1.1 404 x\r\n\r\n"), []byte{3, 3})
	f.Add(uint8(4), []byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nab"), []byte{0x80 | 60, 4})
	f.Fuzz(func(t *testing.T, mode uint8, data, cuts []byte) {
		var fed int64
		s := &orderSink{t: t, fed: &fed}
		kind := http1.Kind(mode & 1)
		opt := http1.Options{Resync: mode&2 != 0}
		if kind == http1.Response {
			m := fuzzMethods[int(mode>>2)%len(fuzzMethods)]
			opt.Method = func() string { return m }
		}
		p := http1.NewParser(kind, s, opt)
		ts := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
		var off int64
		for i := 0; len(data) > 0; i++ {
			c := byte(len(data))
			if len(cuts) > 0 {
				c = cuts[i%len(cuts)]
				if i >= 4*len(cuts) {
					c = byte(len(data)) // cuts 用完几轮后把剩下的一次喂完，保证终止
				}
			}
			ts = ts.Add(time.Millisecond)
			switch c >> 5 {
			case 4, 5: // 缺口：跳过若干字节
				n := min(int(c&0x3f)+1, len(data))
				fed += int64(n)
				p.Gap(off, int64(n), ts)
				off += int64(n)
				data = data[n:]
				continue
			case 2:
				p.Resume()
			case 3:
				p.Tunnel()
			}
			n := min(max(int(c&0x1f), 1), len(data))
			if c>>5 == 7 {
				n = min(int(c)*8, len(data))
			}
			fed += int64(n)
			p.Feed(off, data[:n], -1, ts)
			off += int64(n)
			data = data[n:]
		}
		p.Close(mode&0x80 != 0, ts)
		if s.open {
			t.Fatal("message still open after Close")
		}
		// Close 之后不再产生事件。
		p.Feed(off, []byte("GET / HTTP/1.1\r\n\r\n"), -1, ts)
		p.Resume()
		if s.open {
			t.Fatal("event after Close")
		}
	})
}
