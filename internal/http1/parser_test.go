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
