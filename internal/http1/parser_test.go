package http1_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/http1"
)

var t0 = time.Unix(1000, 0).UTC()

// rec 记录 Sink 事件。相邻的数据事件会合并：Raw 并入前面同一 Section 的 Raw
// （中间只隔着 Body 时也并入），Body 并入前面的 Body（中间只隔着 Raw(SecBody) 时也并入）。
// 这样无论怎么切分喂入，同一段流得到的记录都相同。
type rec struct {
	ev     []string
	begins []http1.Begin
	ends   []time.Time
	heads  []http1.Head
}

var secName = map[http1.Section]string{
	http1.SecHead: "head", http1.SecBody: "body",
	http1.SecTrailer: "trailer", http1.SecUnparsed: "unparsed",
}

func (r *rec) mergeInto(prefix string, skip string, b []byte) bool {
	for j := len(r.ev) - 1; j >= 0; j-- {
		e := r.ev[j]
		if strings.HasPrefix(e, prefix) {
			r.ev[j] = e + string(b)
			return true
		}
		if skip == "" || !strings.HasPrefix(e, skip) {
			return false
		}
	}
	return false
}

func (r *rec) Begin(b http1.Begin) {
	r.begins = append(r.begins, b)
	s := fmt.Sprintf("begin off=%d", b.Off)
	if b.Orphan {
		s += " orphan"
	}
	r.ev = append(r.ev, s)
}

func (r *rec) Raw(sec http1.Section, b []byte) {
	p := "raw " + secName[sec] + " "
	skip := ""
	if sec == http1.SecBody {
		skip = "body "
	}
	if !r.mergeInto(p, skip, b) {
		r.ev = append(r.ev, p+string(b))
	}
}

func (r *rec) Head(h *http1.Head) {
	r.heads = append(r.heads, *h)
	var s string
	if h.Method != "" {
		s = fmt.Sprintf("head %s %s %s", h.Method, h.Target, h.Proto)
	} else {
		s = fmt.Sprintf("head %d %s", h.Status, h.Proto)
	}
	if h.ContentType != "" {
		s += " ct=" + h.ContentType
	}
	if h.ContentEncoding != "" {
		s += " ce=" + h.ContentEncoding
	}
	if h.Upgrade {
		s += " upgrade"
	}
	if h.Tunnel {
		s += " tunnel"
	}
	r.ev = append(r.ev, s)
}

func (r *rec) Body(b []byte) {
	if !r.mergeInto("body ", "raw body ", b) {
		r.ev = append(r.ev, "body "+string(b))
	}
}

func (r *rec) Gap(sec http1.Section, n int64) {
	r.ev = append(r.ev, fmt.Sprintf("gap %s %d", secName[sec], n))
}

func (r *rec) End(complete bool, ts time.Time) {
	r.ends = append(r.ends, ts)
	r.ev = append(r.ev, fmt.Sprintf("end %v", complete))
}

func (r *rec) Desync(off int64) {
	r.ev = append(r.ev, fmt.Sprintf("desync %d", off))
}

// step 是喂给解析器的一个动作：数据、缺口或关闭。
type step struct {
	data  string
	gap   int64
	close string // "fin" 或 "rst"
	ack   int64
	ts    time.Time
}

func data(s string) step          { return step{data: s, ack: -1} }
func gap(n int64) step            { return step{gap: n} }
func closeFin() step              { return step{close: "fin"} }
func closeRst() step              { return step{close: "rst"} }
func (s step) at(sec int) step    { s.ts = t0.Add(time.Duration(sec) * time.Second); return s }
func (s step) acked(a int64) step { s.ack = a; return s }

// run 依次执行 steps。chunk > 0 时把每段数据按 chunk 字节切开喂入。
func run(kind http1.Kind, opt http1.Options, chunk int, steps ...step) *rec {
	r := &rec{}
	p := http1.NewParser(kind, r, opt)
	var off int64
	for _, s := range steps {
		ts := s.ts
		if ts.IsZero() {
			ts = t0
		}
		switch {
		case s.close != "":
			p.Close(s.close == "fin", ts)
		case s.gap > 0:
			p.Gap(off, s.gap, ts)
			off += s.gap
		default:
			b := []byte(s.data)
			n := chunk
			if n <= 0 {
				n = len(b)
			}
			for len(b) > 0 {
				k := min(n, len(b))
				// 每次喂入一份独立的拷贝，喂完后涂掉，检查解析器没有保留传入的切片。
				piece := append([]byte(nil), b[:k]...)
				p.Feed(off, piece, s.ack, ts)
				for i := range piece {
					piece[i] = '#'
				}
				off += int64(k)
				b = b[k:]
			}
		}
	}
	return r
}

func checkEvents(t *testing.T, got *rec, want []string) {
	t.Helper()
	if strings.Join(got.ev, "\n") != strings.Join(want, "\n") {
		t.Errorf("events:\n  got:  %q\n  want: %q", got.ev, want)
	}
}

// checkAllChunkings 用整段、逐字节和几种切分方式喂入，事件都应等于 want。
func checkAllChunkings(t *testing.T, kind http1.Kind, opt http1.Options, want []string, steps ...step) {
	t.Helper()
	for _, c := range []int{0, 1, 2, 3, 7} {
		got := run(kind, opt, c, steps...)
		if strings.Join(got.ev, "\n") != strings.Join(want, "\n") {
			t.Errorf("chunk=%d events:\n  got:  %q\n  want: %q", c, got.ev, want)
		}
	}
}

func TestContentLengthRequest(t *testing.T) {
	req := "POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"
	want := []string{
		"begin off=0",
		"raw head POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n",
		"head POST /submit HTTP/1.1",
		"raw body hello",
		"body hello",
		"end true",
	}
	checkAllChunkings(t, http1.Request, http1.Options{}, want, data(req))
}

// nonOrphanBegins 返回非 Orphan 的 Begin。
func nonOrphanBegins(r *rec) []http1.Begin {
	var out []http1.Begin
	for _, b := range r.begins {
		if !b.Orphan {
			out = append(out, b)
		}
	}
	return out
}

func TestStartLine(t *testing.T) {
	tests := []struct {
		name  string
		kind  http1.Kind
		in    string
		valid bool
		head  string // 合法时 Head 事件的记录
	}{
		{"get crlf", http1.Request, "GET / HTTP/1.1\r\n\r\n", true, "head GET / HTTP/1.1"},
		{"get lf", http1.Request, "GET /a?b=c HTTP/1.0\n\n", true, "head GET /a?b=c HTTP/1.0"},
		{"dash method", http1.Request, "M-SEARCH * HTTP/1.1\r\n\r\n", true, "head M-SEARCH * HTTP/1.1"},
		{"20 letter method", http1.Request, "ABCDEFGHIJKLMNOPQRST / HTTP/1.1\r\n\r\n", true, "head ABCDEFGHIJKLMNOPQRST / HTTP/1.1"},
		{"21 letter method", http1.Request, "ABCDEFGHIJKLMNOPQRSTU / HTTP/1.1\r\n\r\n", false, ""},
		{"lowercase method", http1.Request, "get / HTTP/1.1\r\n\r\n", false, ""},
		{"digit in method", http1.Request, "GET2 / HTTP/1.1\r\n\r\n", false, ""},
		{"http2", http1.Request, "GET / HTTP/2.0\r\n\r\n", false, ""},
		{"http1.2", http1.Request, "GET / HTTP/1.2\r\n\r\n", false, ""},
		{"no proto", http1.Request, "GET /\r\n\r\n", false, ""},
		{"empty target", http1.Request, "GET  HTTP/1.1\r\n\r\n", false, ""},
		{"space in target", http1.Request, "GET /a b HTTP/1.1\r\n\r\n", false, ""},
		{"trailing space", http1.Request, "GET / HTTP/1.1 \r\n\r\n", false, ""},
		{"status reason", http1.Response, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, "head 200 HTTP/1.1"},
		{"status no reason", http1.Response, "HTTP/1.0 404\nContent-Length: 0\n\n", true, "head 404 HTTP/1.0"},
		{"status empty reason", http1.Response, "HTTP/1.1 204 \r\n\r\n", true, "head 204 HTTP/1.1"},
		{"status long reason", http1.Response, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n", true, "head 500 HTTP/1.1"},
		{"status 2 digits", http1.Response, "HTTP/1.1 20 OK\r\n\r\n", false, ""},
		{"status 4 digits", http1.Response, "HTTP/1.1 2000\r\n\r\n", false, ""},
		{"status no space", http1.Response, "HTTP/1.1 200OK\r\n\r\n", false, ""},
		{"status http2", http1.Response, "HTTP/2 200 OK\r\n\r\n", false, ""},
		{"status letters", http1.Response, "HTTP/1.1 2x0 OK\r\n\r\n", false, ""},
		{"request on response side", http1.Response, "GET / HTTP/1.1\r\n\r\n", false, ""},
		{"response on request side", http1.Request, "HTTP/1.1 200 OK\r\n\r\n", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range []int{0, 1} {
				r := run(tt.kind, http1.Options{}, c, data(tt.in))
				bs := nonOrphanBegins(r)
				if !tt.valid {
					if len(bs) != 0 {
						t.Fatalf("chunk=%d: invalid start line began a message: %q", c, r.ev)
					}
					continue
				}
				if len(bs) != 1 || bs[0].Off != 0 {
					t.Fatalf("chunk=%d: begins = %+v, events %q", c, bs, r.ev)
				}
				if len(r.ev) < 3 || r.ev[2] != tt.head {
					t.Fatalf("chunk=%d: events %q, want head %q", c, r.ev, tt.head)
				}
			}
		})
	}
}

// Begin 只在起始行完整之后才出现。
func TestBeginAfterCompleteStartLine(t *testing.T) {
	r := &rec{}
	p := http1.NewParser(http1.Request, r, http1.Options{})
	p.Feed(0, []byte("GET / HTTP/1.1"), 7, t0)
	if len(r.ev) != 0 {
		t.Fatalf("events before line end: %q", r.ev)
	}
	p.Feed(14, []byte("\r\n\r\n"), 9, t0.Add(time.Second))
	if len(r.begins) != 1 {
		t.Fatalf("begins = %+v", r.begins)
	}
	// Begin 的时间和 peerAck 取起始行第一个字节所在的包。
	want := http1.Begin{Off: 0, TS: t0, PeerAck: 7}
	if r.begins[0] != want {
		t.Errorf("begin = %+v, want %+v", r.begins[0], want)
	}
}

func TestSkipBlankLinesBeforeStartLine(t *testing.T) {
	want := []string{
		"begin off=3",
		"raw head GET / HTTP/1.1\r\n\r\n",
		"head GET / HTTP/1.1",
		"end true",
	}
	checkAllChunkings(t, http1.Request, http1.Options{}, want, data("\r\n\nGET / HTTP/1.1\r\n\r\n"))
}

func TestChunked(t *testing.T) {
	tests := []struct {
		name string
		kind http1.Kind
		in   string
		want []string
	}{
		{
			"request with extension and trailer", http1.Request,
			"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 1\r\n\r\n",
			[]string{
				"begin off=0",
				"raw head POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
				"head POST / HTTP/1.1",
				"raw body 5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\n",
				"body hello world",
				"raw trailer X-Sum: 1\r\n\r\n",
				"end true",
			},
		},
		{
			"response hex size empty trailer lf", http1.Response,
			"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\na\n0123456789\n0\n\n",
			[]string{
				"begin off=0",
				"raw head HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n",
				"head 200 HTTP/1.1",
				"raw body a\n0123456789\n0\n",
				"body 0123456789",
				"raw trailer \n",
				"end true",
			},
		},
		{
			"uppercase hex and leading zeros", http1.Response,
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00B\r\nhello world\r\n000\r\n\r\n",
			[]string{
				"begin off=0",
				"raw head HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
				"head 200 HTTP/1.1",
				"raw body 00B\r\nhello world\r\n000\r\n",
				"body hello world",
				"raw trailer \r\n",
				"end true",
			},
		},
		{
			"chunked wins over content-length", http1.Request,
			"POST / HTTP/1.1\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
			[]string{
				"begin off=0",
				"raw head POST / HTTP/1.1\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n",
				"head POST / HTTP/1.1",
				"raw body 2\r\nhi\r\n0\r\n",
				"body hi",
				"raw trailer \r\n",
				"end true",
			},
		},
		{
			"coding list ending in chunked", http1.Request,
			"POST / HTTP/1.1\r\ntransfer-encoding: gzip, Chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
			[]string{
				"begin off=0",
				"raw head POST / HTTP/1.1\r\ntransfer-encoding: gzip, Chunked\r\n\r\n",
				"head POST / HTTP/1.1",
				"raw body 1\r\nx\r\n0\r\n",
				"body x",
				"raw trailer \r\n",
				"end true",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkAllChunkings(t, tt.kind, http1.Options{}, tt.want, data(tt.in))
		})
	}
}

// methodFn 返回一个固定方法的 Options.Method，并统计调用次数。
func methodFn(m string, calls *int) func() string {
	return func() string {
		*calls++
		return m
	}
}

func TestBodyLength(t *testing.T) {
	const next = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	tests := []struct {
		name   string
		kind   http1.Kind
		method string // Options.Method 的返回值
		in     string
		want   []string
	}{
		{
			"request content-length 0", http1.Request, "",
			"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "head POST / HTTP/1.1", "end true"},
		},
		{
			"request without length has no body", http1.Request, "",
			"POST / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n",
			[]string{
				"begin off=0", "raw head POST / HTTP/1.1\r\n\r\n", "head POST / HTTP/1.1", "end true",
				"begin off=19", "raw head GET / HTTP/1.1\r\n\r\n", "head GET / HTTP/1.1", "end true",
			},
		},
		{
			"response 204 ignores content-length", http1.Response, "GET",
			"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
			[]string{"begin off=0", "raw head HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "head 204 HTTP/1.1", "end true"},
		},
		{
			"response 304 ignores chunked", http1.Response, "GET",
			"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
			[]string{"begin off=0", "raw head HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", "head 304 HTTP/1.1", "end true"},
		},
		{
			"response to HEAD", http1.Response, "HEAD",
			"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + next,
			[]string{
				"begin off=0", "raw head HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", "head 200 HTTP/1.1", "end true",
				"begin off=40", "raw head " + next, "head 200 HTTP/1.1", "end true",
			},
		},
		{
			"unknown method is GET", http1.Response, "",
			"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", "head 200 HTTP/1.1", "raw body abc", "body abc", "end true"},
		},
		{
			"response without length reads to close", http1.Response, "GET",
			"HTTP/1.1 200 OK\r\n\r\nabc" + next,
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\n\r\n", "head 200 HTTP/1.1", "raw body abc" + next, "body abc" + next},
		},
		{
			"response non-chunked coding reads to close", http1.Response, "GET",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 3\r\n\r\nabcdef",
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 3\r\n\r\n", "head 200 HTTP/1.1", "raw body abcdef", "body abcdef"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			opt := http1.Options{}
			if tt.kind == http1.Response {
				opt.Method = methodFn(tt.method, &calls)
			}
			checkAllChunkings(t, tt.kind, opt, tt.want, data(tt.in))
		})
	}
}

// 没有设置 Options.Method 时，响应按 GET 处理。
func TestNilMethodIsGET(t *testing.T) {
	want := []string{"begin off=0", "raw head HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n", "head 200 HTTP/1.1", "raw body x", "body x", "end true"}
	checkAllChunkings(t, http1.Response, http1.Options{}, want, data("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"))
}

func TestInformationalResponses(t *testing.T) {
	in := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	want := []string{
		"begin off=0", "raw head HTTP/1.1 100 Continue\r\n\r\n", "head 100 HTTP/1.1", "end true",
		"begin off=25", "raw head HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n", "head 103 HTTP/1.1", "end true",
		"begin off=69", "raw head HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "head 200 HTTP/1.1", "raw body ok", "body ok", "end true",
	}
	var calls int
	checkAllChunkings(t, http1.Response, http1.Options{Method: methodFn("POST", &calls)}, want, data(in))
	// 5 种切分各喂一遍，每遍只有 200 响应会问方法。
	if calls != 5 {
		t.Errorf("Method called %d times, want 5 (once per run, only for the final response)", calls)
	}
}

func TestTunnelResponse(t *testing.T) {
	after := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n\x81\x05hello"
	tests := []struct {
		name, method, in string
		want             []string
	}{
		{
			"101 switching protocols", "GET",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
			[]string{"begin off=0", "raw head HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", "head 101 HTTP/1.1 tunnel", "end true"},
		},
		{
			"connect 200", "CONNECT",
			"HTTP/1.1 200 Connection Established\r\n\r\n",
			[]string{"begin off=0", "raw head HTTP/1.1 200 Connection Established\r\n\r\n", "head 200 HTTP/1.1 tunnel", "end true"},
		},
		{
			"connect 200 ignores content-length", "CONNECT",
			"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "head 200 HTTP/1.1 tunnel", "end true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			opt := http1.Options{Method: methodFn(tt.method, &calls)}
			checkAllChunkings(t, http1.Response, opt, tt.want, data(tt.in), data(after), gap(10), data(after), closeRst())
		})
	}
}

// CONNECT 的非 2xx 响应不是隧道，后面照常解析。
func TestConnectRejected(t *testing.T) {
	in := "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 2\r\n\r\nnoHTTP/1.1 200 OK\r\n\r\n"
	want := []string{
		"begin off=0", "raw head HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 2\r\n\r\n", "head 407 HTTP/1.1",
		"raw body no", "body no", "end true",
		"begin off=67", "raw head HTTP/1.1 200 OK\r\n\r\n", "head 200 HTTP/1.1 tunnel", "end true",
	}
	var calls int
	checkAllChunkings(t, http1.Response, http1.Options{Method: methodFn("CONNECT", &calls)}, want, data(in))
}

func TestClose(t *testing.T) {
	const toClose = "HTTP/1.1 200 OK\r\n\r\nabc"
	toCloseEv := []string{"begin off=0", "raw head HTTP/1.1 200 OK\r\n\r\n", "head 200 HTTP/1.1", "raw body abc", "body abc"}
	tests := []struct {
		name  string
		kind  http1.Kind
		in    string
		close step
		want  []string // 在 in 的事件之后，由 Close 产生的事件
		pre   []string // in 的事件
	}{
		{"read-to-close body fin", http1.Response, toClose, closeFin(), []string{"end true"}, toCloseEv},
		{"read-to-close body rst", http1.Response, toClose, closeRst(), []string{"end false"}, toCloseEv},
		{
			"content-length body cut", http1.Response, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab", closeFin(),
			[]string{"end false"},
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "head 200 HTTP/1.1", "raw body ab", "body ab"},
		},
		{
			"head cut", http1.Request, "GET / HTTP/1.1\r\nHost: a\r\nAcc", closeFin(),
			[]string{"end false"},
			[]string{"begin off=0", "raw head GET / HTTP/1.1\r\nHost: a\r\nAcc"},
		},
		{
			"chunked cut", http1.Request, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab", closeFin(),
			[]string{"end false"},
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "head POST / HTTP/1.1", "raw body 3\r\nab", "body ab"},
		},
		{
			"trailer cut", http1.Request, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: 1\r\n", closeRst(),
			[]string{"end false"},
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "head POST / HTTP/1.1", "raw body 0\r\n", "raw trailer X: 1\r\n"},
		},
		{
			"between messages", http1.Request, "GET / HTTP/1.1\r\n\r\n", closeFin(),
			nil,
			[]string{"begin off=0", "raw head GET / HTTP/1.1\r\n\r\n", "head GET / HTTP/1.1", "end true"},
		},
		{"partial start line", http1.Request, "GET / HT", closeFin(), nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := append(append([]string(nil), tt.pre...), tt.want...)
			// Close 之后再喂数据，不再产生事件。
			checkAllChunkings(t, tt.kind, http1.Options{}, want,
				data(tt.in), tt.close.at(5), data("GET / HTTP/1.1\r\n\r\n"), gap(3), closeFin())
			r := run(tt.kind, http1.Options{}, 0, data(tt.in), tt.close.at(5))
			if tt.want != nil {
				if len(r.ends) != 1 || !r.ends[len(r.ends)-1].Equal(t0.Add(5*time.Second)) {
					t.Errorf("end times = %v, want the close time", r.ends)
				}
			}
		})
	}
}
