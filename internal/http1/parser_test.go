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
	call  string // "resume" 或 "tunnel"
	ack   int64
	ts    time.Time
}

func data(s string) step          { return step{data: s, ack: -1} }
func gap(n int64) step            { return step{gap: n} }
func closeFin() step              { return step{close: "fin"} }
func closeRst() step              { return step{close: "rst"} }
func resume() step                { return step{call: "resume"} }
func tunnel() step                { return step{call: "tunnel"} }
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
		case s.call == "resume":
			p.Resume()
		case s.call == "tunnel":
			p.Tunnel()
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

func TestGapInBody(t *testing.T) {
	const clHead = "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"
	const chHead = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
	tests := []struct {
		name  string
		kind  http1.Kind
		steps []step
		want  []string
	}{
		{
			"content-length", http1.Request,
			[]step{data(clHead + "ab"), gap(5), data("cde")},
			[]string{"begin off=0", "raw head " + clHead, "head POST / HTTP/1.1",
				"raw body ab", "body ab", "gap body 5", "raw body cde", "body cde", "end true"},
		},
		{
			"gap completes content-length", http1.Request,
			[]step{data(clHead + "abcde"), gap(5).at(3), data("GET / HTTP/1.1\r\n\r\n")},
			[]string{"begin off=0", "raw head " + clHead, "head POST / HTTP/1.1",
				"raw body abcde", "body abcde", "gap body 5", "end true",
				"begin off=49", "raw head GET / HTTP/1.1\r\n\r\n", "head GET / HTTP/1.1", "end true"},
		},
		{
			"chunk data", http1.Request,
			[]step{data(chHead + "5\r\nhe"), gap(2), data("o\r\n0\r\n\r\n")},
			[]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 5\r\nhe", "body he", "gap body 2", "raw body o\r\n0\r\n", "body o", "raw trailer \r\n", "end true"},
		},
		{
			"gap ends chunk data", http1.Request,
			[]step{data(chHead + "5\r\nhel"), gap(2), data("\r\n0\r\n\r\n")},
			[]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 5\r\nhel", "body hel", "gap body 2", "raw body \r\n0\r\n", "raw trailer \r\n", "end true"},
		},
		{
			"read-to-close body", http1.Response,
			[]step{data("HTTP/1.1 200 OK\r\n\r\nab"), gap(4), data("cd"), closeFin()},
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\n\r\n", "head 200 HTTP/1.1",
				"raw body ab", "body ab", "gap body 4", "raw body cd", "body cd", "end true"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkAllChunkings(t, tt.kind, http1.Options{}, tt.want, tt.steps...)
		})
	}
	// 缺口补齐 Content-Length 时，End 的时间是缺口的时间。
	r := run(http1.Request, http1.Options{}, 0, data(clHead+"abcde"), gap(5).at(3))
	if len(r.ends) != 1 || !r.ends[0].Equal(t0.Add(3*time.Second)) {
		t.Errorf("end times = %v, want gap time", r.ends)
	}
}

func TestDesync(t *testing.T) {
	const next = "GET /2 HTTP/1.1\r\n\r\n"
	const chHead = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" // 47 字节
	nextEv := func(off int) []string {
		return []string{fmt.Sprintf("begin off=%d", off), "raw head " + next, "head GET /2 HTTP/1.1", "end true"}
	}
	tests := []struct {
		name  string
		kind  http1.Kind
		steps []step
		want  []string
	}{
		{
			"gap in head", http1.Request,
			[]step{data("GET / HTTP/1.1\r\nHo"), gap(3), data("t: a\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head GET / HTTP/1.1\r\nHo", "desync 18", "gap unparsed 3",
				"raw unparsed t: a\r\n\r\n", "end false"}, nextEv(29)...),
		},
		{
			"gap in start line", http1.Request,
			[]step{data("GET / HT"), gap(2), data("1.1\r\n\r\n" + next)},
			append([]string{"desync 8", "begin off=0 orphan", "raw unparsed GET / HT", "gap unparsed 2",
				"raw unparsed 1.1\r\n\r\n", "end false"}, nextEv(17)...),
		},
		{
			"gap between messages", http1.Request,
			[]step{data("GET / HTTP/1.1\r\n\r\n"), gap(30), data(next)},
			append([]string{"begin off=0", "raw head GET / HTTP/1.1\r\n\r\n", "head GET / HTTP/1.1", "end true",
				"desync 18", "begin off=18 orphan", "gap unparsed 30", "end false"}, nextEv(48)...),
		},
		{
			"gap past content-length end", http1.Request,
			[]step{data("POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\na"), gap(10), data(next)},
			append([]string{"begin off=0", "raw head POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\n", "head POST / HTTP/1.1",
				"raw body a", "body a", "desync 39", "gap unparsed 10", "end false"}, nextEv(49)...),
		},
		{
			"gap past chunk data end", http1.Request,
			[]step{data(chHead + "2\r\na"), gap(4), data("0\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 2\r\na", "body a", "desync 51", "gap unparsed 4", "raw unparsed 0\r\n\r\n", "end false"}, nextEv(60)...),
		},
		{
			"gap in chunk size line", http1.Request,
			[]step{data(chHead + "5"), gap(2), data("\r\nhello\r\n0\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 5", "desync 48", "gap unparsed 2", "raw unparsed \r\nhello\r\n0\r\n\r\n", "end false"}, nextEv(64)...),
		},
		{
			"gap at chunk data crlf", http1.Request,
			[]step{data(chHead + "1\r\nx"), gap(2), data("0\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 1\r\nx", "body x", "desync 51", "gap unparsed 2", "raw unparsed 0\r\n\r\n", "end false"}, nextEv(58)...),
		},
		{
			"gap in trailer", http1.Request,
			[]step{data(chHead + "0\r\nX: 1"), gap(1), data("\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 0\r\n", "raw trailer X: 1", "desync 54", "gap unparsed 1", "raw unparsed \r\n\r\n", "end false"}, nextEv(59)...),
		},
		{
			"bad request line", http1.Request,
			[]step{data("GET / HTTP/2.0\r\nHost: a\r\n\r\n" + next)},
			append([]string{"desync 0", "begin off=0 orphan", "raw unparsed GET / HTTP/2.0\r\nHost: a\r\n\r\n", "end false"}, nextEv(27)...),
		},
		{
			"bad status line", http1.Response,
			[]step{data("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 2 OK\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")},
			[]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "head 200 HTTP/1.1", "end true",
				"desync 38", "begin off=38 orphan", "raw unparsed HTTP/1.1 2 OK\r\n\r\n", "end false",
				"begin off=55", "raw head HTTP/1.1 204 No Content\r\n\r\n", "head 204 HTTP/1.1", "end true"},
		},
		{
			"header without colon", http1.Request,
			[]step{data("GET / HTTP/1.1\r\nBadHeader\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head GET / HTTP/1.1\r\n", "desync 16",
				"raw unparsed BadHeader\r\n\r\n", "end false"}, nextEv(29)...),
		},
		{
			"content-length not a number", http1.Request,
			[]step{data("POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head POST / HTTP/1.1\r\n", "desync 17",
				"raw unparsed Content-Length: 1x\r\n\r\n", "end false"}, nextEv(39)...),
		},
		{
			"content-length empty", http1.Request,
			[]step{data("POST / HTTP/1.1\r\nContent-Length: \r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head POST / HTTP/1.1\r\n", "desync 17",
				"raw unparsed Content-Length: \r\n\r\n", "end false"}, nextEv(37)...),
		},
		{
			"content-length negative", http1.Request,
			[]step{data("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head POST / HTTP/1.1\r\n", "desync 17",
				"raw unparsed Content-Length: -1\r\n\r\n", "end false"}, nextEv(39)...),
		},
		{
			"request transfer-encoding not chunked", http1.Request,
			[]step{data("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
				"desync 44", "end false"}, nextEv(44)...),
		},
		{
			"bad chunk size", http1.Request,
			[]step{data(chHead + "zz\r\nhello\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"desync 47", "raw unparsed zz\r\nhello\r\n", "end false"}, nextEv(58)...),
		},
		{
			"empty chunk size", http1.Request,
			[]step{data(chHead + "\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"desync 47", "raw unparsed \r\n", "end false"}, nextEv(49)...),
		},
		{
			"chunk data not followed by crlf", http1.Request,
			[]step{data(chHead + "1\r\nxy\r\n0\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 1\r\nx", "body x", "desync 51", "raw unparsed y\r\n0\r\n\r\n", "end false"}, nextEv(59)...),
		},
		{
			"trailer without colon", http1.Request,
			[]step{data(chHead + "0\r\nbad\r\n\r\n" + next)},
			append([]string{"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
				"raw body 0\r\n", "desync 50", "raw unparsed bad\r\n\r\n", "end false"}, nextEv(57)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkAllChunkings(t, tt.kind, http1.Options{}, tt.want, tt.steps...)
		})
	}
}

func TestDesyncLimits(t *testing.T) {
	const next = "GET /2 HTTP/1.1\r\n\r\n"
	const chHead = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
	line := "X: " + strings.Repeat("a", 3997) + "\r\n" // 4002 字节
	// 起始行 16 字节 + 16 行 = 64048 字节，加空行不到 64 KiB，可以接受。
	okHead := "GET / HTTP/1.1\r\n" + strings.Repeat(line, 16) + "\r\n"
	// 17 行时超过 64 KiB，在第 17 行（偏移 64048）处失步。
	bigHead := "GET / HTTP/1.1\r\n" + strings.Repeat(line, 17) + "\r\n"
	// 长度行正好 4096 字节（含 CRLF）可以接受，4097 字节时失步。
	okSize := "5;" + strings.Repeat("e", 4092) + "\r\n"
	bigSize := "5;" + strings.Repeat("e", 4093) + "\r\n"
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"head at limit", okHead + next, []string{
			"begin off=0", "raw head " + okHead, "head GET / HTTP/1.1", "end true",
			"begin off=64050", "raw head " + next, "head GET /2 HTTP/1.1", "end true"}},
		{"head over limit", bigHead + next, []string{
			"begin off=0", "raw head GET / HTTP/1.1\r\n" + strings.Repeat(line, 16), "desync 64048",
			"raw unparsed " + line + "\r\n", "end false",
			"begin off=68052", "raw head " + next, "head GET /2 HTTP/1.1", "end true"}},
		{"chunk size line at limit", chHead + okSize + "hello\r\n0\r\n\r\n" + next, []string{
			"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1",
			"raw body " + okSize + "hello\r\n0\r\n", "body hello", "raw trailer \r\n", "end true",
			"begin off=4155", "raw head " + next, "head GET /2 HTTP/1.1", "end true"}},
		{"chunk size line over limit", chHead + bigSize + "hello\r\n0\r\n\r\n" + next, []string{
			"begin off=0", "raw head " + chHead, "head POST / HTTP/1.1", "desync 47",
			"raw unparsed " + bigSize + "hello\r\n0\r\n\r\n", "end false",
			"begin off=4156", "raw head " + next, "head GET /2 HTTP/1.1", "end true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range []int{0, 1, 1460} {
				got := run(http1.Request, http1.Options{}, c, data(tt.in))
				if strings.Join(got.ev, "\n") != strings.Join(tt.want, "\n") {
					t.Errorf("chunk=%d events:\n  got:  %.300q\n  want: %.300q", c, got.ev, tt.want)
				}
			}
		})
	}
}

func TestScan(t *testing.T) {
	t.Run("start line only at line start or after gap", func(t *testing.T) {
		want := []string{
			"begin off=0", "raw head GET / HTTP/1.1\r\n", "desync 16",
			"raw unparsed bad\r\nx GET /no HTTP/1.1\r\ngarbage", "gap unparsed 3", "end false",
			"begin off=51", "raw head GET /2 HTTP/1.1\r\n\r\n", "head GET /2 HTTP/1.1", "end true",
		}
		// 已经失步时再遇到缺口，不再报告 Desync。
		checkAllChunkings(t, http1.Request, http1.Options{}, want,
			data("GET / HTTP/1.1\r\nbad\r\nx GET /no HTTP/1.1\r\ngarbage"), gap(3), data("GET /2 HTTP/1.1\r\n\r\n"))
	})
	t.Run("response side looks for status lines", func(t *testing.T) {
		const ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		want := []string{
			"begin off=0", "raw head HTTP/1.1 200 OK\r\n", "desync 17",
			"raw unparsed nocolon\r\nGET / HTTP/1.1\r\n xHTTP/1.1 200 OK\r\n", "end false",
			"begin off=61", "raw head " + ok, "head 200 HTTP/1.1", "end true",
		}
		checkAllChunkings(t, http1.Response, http1.Options{}, want,
			data("HTTP/1.1 200 OK\r\nnocolon\r\nGET / HTTP/1.1\r\n xHTTP/1.1 200 OK\r\n"+ok))
	})
}

// Orphan 消息的 Begin 取第一个字节（或缺口）的偏移、时间和 peerAck；缺口没有 peerAck，为 -1。
func TestOrphanBegin(t *testing.T) {
	const ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" // 38 字节
	r := run(http1.Response, http1.Options{}, 0, data(ok).acked(5).at(1), data("junk\r\n").acked(77).at(2))
	want := []http1.Begin{
		{Off: 0, TS: t0.Add(time.Second), PeerAck: 5},
		{Off: 38, TS: t0.Add(2 * time.Second), PeerAck: 77, Orphan: true},
	}
	if len(r.begins) != 2 || r.begins[0] != want[0] || r.begins[1] != want[1] {
		t.Errorf("bytes: begins = %+v, want %+v", r.begins, want)
	}
	r = run(http1.Response, http1.Options{}, 0, data(ok).acked(5).at(1), gap(10).at(3))
	want[1] = http1.Begin{Off: 38, TS: t0.Add(3 * time.Second), PeerAck: -1, Orphan: true}
	if len(r.begins) != 2 || r.begins[0] != want[0] || r.begins[1] != want[1] {
		t.Errorf("gap: begins = %+v, want %+v", r.begins, want)
	}
}

func TestResync(t *testing.T) {
	const ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	okEv := func(off int) []string {
		return []string{fmt.Sprintf("begin off=%d", off), "raw head HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
			"head 200 HTTP/1.1", "raw body ok", "body ok", "end true"}
	}
	resync := http1.Options{Resync: true}
	tests := []struct {
		name  string
		kind  http1.Kind
		steps []step
		want  []string
	}{
		{
			"middle of a response body", http1.Response,
			[]step{data("dy of previous\r\nmore\r\n" + ok)},
			append([]string{"begin off=0 orphan", "raw unparsed dy of previous\r\nmore\r\n", "end false"}, okEv(22)...),
		},
		{
			"first byte is a status line", http1.Response,
			[]step{data(ok)},
			okEv(0),
		},
		{
			"first byte is a request line", http1.Request,
			[]step{data("GET / HTTP/1.1\r\n\r\n")},
			[]string{"begin off=0", "raw head GET / HTTP/1.1\r\n\r\n", "head GET / HTTP/1.1", "end true"},
		},
		{
			"starts with a gap", http1.Response,
			[]step{gap(100), data(ok)},
			append([]string{"begin off=0 orphan", "gap unparsed 100", "end false"}, okEv(100)...),
		},
		{
			"non-http stream", http1.Request,
			[]step{data("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\n\x00GET"), closeFin()},
			[]string{"begin off=0 orphan", "raw unparsed \x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\n\x00GET", "end false"},
		},
		{"nothing fed", http1.Request, []step{closeFin()}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkAllChunkings(t, tt.kind, resync, tt.want, tt.steps...)
		})
	}
}

func TestScanLongLine(t *testing.T) {
	const next = "GET /2 HTTP/1.1\r\n\r\n"
	nextEv := func(off int) []string {
		return []string{fmt.Sprintf("begin off=%d", off), "raw head " + next, "head GET /2 HTTP/1.1", "end true"}
	}
	// 请求行长度是 k+16 字节（含 CRLF）。
	reqLine := func(k int) string { return "GET /" + strings.Repeat("a", k) + " HTTP/1.1\r\n" }
	ok, long := reqLine(8176), reqLine(8177) // 8192 和 8193 字节
	tests := []struct {
		name   string
		resync bool
		in     string
		want   []string
	}{
		{"8 KiB line is a candidate", true, ok + "\r\n",
			[]string{"begin off=0", "raw head " + ok + "\r\n", "head GET /" + strings.Repeat("a", 8176) + " HTTP/1.1", "end true"}},
		{"longer line is not a candidate", true, long + "\r\n" + next,
			append([]string{"begin off=0 orphan", "raw unparsed " + long + "\r\n", "end false"}, nextEv(8195)...)},
		{"limit applies only while scanning", false, long + "\r\n",
			[]string{"begin off=0", "raw head " + long + "\r\n", "head GET /" + strings.Repeat("a", 8177) + " HTTP/1.1", "end true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range []int{0, 1, 1460} {
				got := run(http1.Request, http1.Options{Resync: tt.resync}, c, data(tt.in))
				if strings.Join(got.ev, "\n") != strings.Join(tt.want, "\n") {
					t.Errorf("chunk=%d events:\n  got:  %.200q\n  want: %.200q", c, got.ev, tt.want)
				}
			}
		})
	}
}

func TestUpgradeFlag(t *testing.T) {
	tests := []struct{ in, head string }{
		{"GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nupgrade: websocket\r\n\r\n", "head GET /ws HTTP/1.1 upgrade"},
		{"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "head CONNECT example.com:443 HTTP/1.1 upgrade"},
		{"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n", "head GET / HTTP/1.1"},
	}
	for _, tt := range tests {
		r := run(http1.Request, http1.Options{}, 0, data(tt.in))
		if len(r.ev) < 3 || r.ev[2] != tt.head {
			t.Errorf("%q: events %q, want %q", tt.in, r.ev, tt.head)
		}
	}
	// 响应里的 Upgrade 头不影响 Head.Upgrade。
	r := run(http1.Response, http1.Options{}, 0, data("HTTP/1.1 426 Upgrade Required\r\nUpgrade: h2c\r\nContent-Length: 0\r\n\r\n"))
	if len(r.heads) != 1 || r.heads[0].Upgrade || r.heads[0].Tunnel {
		t.Errorf("response heads = %+v", r.heads)
	}
}

func TestUpgradeHold(t *testing.T) {
	const up = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n" // 40 字节
	const next = "GET /2 HTTP/1.1\r\n\r\n"                      // 19 字节
	upEv := []string{"begin off=0", "raw head " + up, "head GET /ws HTTP/1.1 upgrade", "end true"}
	nextEv := func(off int) []string {
		return []string{fmt.Sprintf("begin off=%d", off), "raw head " + next, "head GET /2 HTTP/1.1", "end true"}
	}
	cat := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	// 缓存超过 64 KiB 的请求：头部 42 字节，body 70000 字节，
	// 只缓存得下 body 的前 65494 字节，其余 4506 字节丢弃。
	const bigHead = "POST / HTTP/1.1\r\nContent-Length: 70000\r\n\r\n"
	bigBody := strings.Repeat("b", 65494)
	tests := []struct {
		name  string
		steps []step
		want  []string
	}{
		{"held until resume", []step{data(up + next), data(next)}, upEv},
		{"resume parses held bytes", []step{data(up + next), data("GET /2 "), resume(), data("HTTP/1.1\r\n\r\n"), data(next)},
			cat(upEv, nextEv(40), nextEv(59), nextEv(78))},
		{"tunnel drops everything", []step{data(up + next), tunnel(), data(next), gap(5), resume(), data(next), closeRst()}, upEv},
		{"gap while held is replayed", []step{data(up + "GET /2 HT"), gap(4), data(next), resume()},
			cat(upEv, []string{"desync 49", "begin off=40 orphan", "raw unparsed GET /2 HT", "gap unparsed 4", "end false"}, nextEv(53))},
		{"overflow becomes a gap", []step{data(up), data(bigHead + bigBody + strings.Repeat("c", 4506)), resume(), data(next)},
			cat(upEv, []string{"begin off=40", "raw head " + bigHead, "head POST / HTTP/1.1",
				"raw body " + bigBody, "body " + bigBody, "gap body 4506", "end true"}, nextEv(40+42+70000))},
		{"resume before request ends", []step{data(up[:30]), resume(), data(up[30:] + next)}, cat(upEv, nextEv(40))},
		{"tunnel before request ends", []step{data(up[:30]), tunnel(), data(up[30:] + next), resume(), data(next)}, upEv},
		{"close while held", []step{data(up + next), closeFin(), resume()}, upEv},
		{"resume when not held is a no-op", []step{resume(), data(next), resume(), data(next)}, cat(nextEv(0), nextEv(19))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range []int{0, 1, 1460} {
				got := run(http1.Request, http1.Options{}, c, tt.steps...)
				if strings.Join(got.ev, "\n") != strings.Join(tt.want, "\n") {
					t.Errorf("chunk=%d events:\n  got:  %.400q\n  want: %.400q", c, got.ev, tt.want)
				}
			}
		})
	}
}

// 缓存的字节在 Resume 时仍带着原来所在包的时间和 peerAck。
func TestUpgradeHoldKeepsPacketMeta(t *testing.T) {
	const up = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"
	r := run(http1.Request, http1.Options{}, 0, data(up), data("\r\nGET /2 HTTP/1.1\r\n").acked(9).at(4), data("\r\n").at(6), resume())
	want := http1.Begin{Off: 42, TS: t0.Add(4 * time.Second), PeerAck: 9}
	if len(r.begins) != 2 || r.begins[1] != want {
		t.Fatalf("begins = %+v, want second %+v", r.begins, want)
	}
	if len(r.ends) != 2 || !r.ends[1].Equal(t0.Add(6*time.Second)) {
		t.Errorf("ends = %v", r.ends)
	}
}

// 响应解析器的 Resume 和 Tunnel 不起作用。
func TestResumeTunnelIgnoredOnResponse(t *testing.T) {
	const ok = "HTTP/1.1 204 No Content\r\n\r\n"
	want := []string{"begin off=0", "raw head " + ok, "head 204 HTTP/1.1", "end true",
		"begin off=27", "raw head " + ok, "head 204 HTTP/1.1", "end true"}
	checkAllChunkings(t, http1.Response, http1.Options{}, want, data(ok), tunnel(), resume(), data(ok))
}

func TestHeaderNamesAndDuplicates(t *testing.T) {
	const next = "GET /2 HTTP/1.1\r\n\r\n"
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"mixed case content-length", "POST / HTTP/1.1\r\ncOnTeNt-LeNgTh: 2\r\n\r\nhi",
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\ncOnTeNt-LeNgTh: 2\r\n\r\n", "head POST / HTTP/1.1", "raw body hi", "body hi", "end true"}},
		{"upper case transfer-encoding", "POST / HTTP/1.1\r\nTRANSFER-ENCODING: CHUNKED\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\nTRANSFER-ENCODING: CHUNKED\r\n\r\n", "head POST / HTTP/1.1",
				"raw body 2\r\nhi\r\n0\r\n", "body hi", "raw trailer \r\n", "end true"}},
		{"duplicate content-length same value", "POST / HTTP/1.1\r\nContent-Length: 2\r\ncontent-length:2 \r\n\r\nhi",
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\nContent-Length: 2\r\ncontent-length:2 \r\n\r\n", "head POST / HTTP/1.1",
				"raw body hi", "body hi", "end true"}},
		{"duplicate content-length different value", "POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nhi\r\n" + next,
			[]string{"begin off=0", "raw head POST / HTTP/1.1\r\nContent-Length: 2\r\n", "desync 36",
				"raw unparsed Content-Length: 3\r\n\r\nhi\r\n", "end false",
				"begin off=61", "raw head " + next, "head GET /2 HTTP/1.1", "end true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkAllChunkings(t, http1.Request, http1.Options{}, tt.want, data(tt.in))
		})
	}
}

func TestHeadFields(t *testing.T) {
	in := "HTTP/1.1 200 OK\r\n" +
		"content-type:  text/html; charset=utf-8 \r\n" +
		"Content-Type: application/json\r\n" +
		"CONTENT-ENCODING:\tgzip\r\n" +
		"Content-Encoding: br\r\n" +
		"Content-Length: 0\r\n\r\n"
	r := run(http1.Response, http1.Options{}, 1, data(in))
	want := http1.Head{Status: 200, Proto: "HTTP/1.1", ContentType: "text/html; charset=utf-8", ContentEncoding: "gzip"}
	if len(r.heads) != 1 || r.heads[0] != want {
		t.Errorf("heads = %+v, want %+v", r.heads, want)
	}
	r = run(http1.Request, http1.Options{}, 0, data("PUT /x HTTP/1.0\r\nContent-Type: text/plain\r\n\r\n"))
	wantReq := http1.Head{Method: "PUT", Target: "/x", Proto: "HTTP/1.0", ContentType: "text/plain"}
	if len(r.heads) != 1 || r.heads[0] != wantReq {
		t.Errorf("heads = %+v, want %+v", r.heads, wantReq)
	}
}
