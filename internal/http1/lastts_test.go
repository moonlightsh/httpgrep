package http1_test

import (
	"testing"
	"time"

	"httpgrep/internal/http1"
)

// tsSink 在每个 Raw 事件里记下解析器的 LastTS，头部和 body 分开记。
type tsSink struct {
	p          *http1.Parser
	head, body []time.Time
}

func (s *tsSink) Begin(http1.Begin) {}
func (s *tsSink) Raw(sec http1.Section, b []byte) {
	if sec == http1.SecBody {
		s.body = append(s.body, s.p.LastTS())
	} else {
		s.head = append(s.head, s.p.LastTS())
	}
}
func (s *tsSink) Head(*http1.Head)         {}
func (s *tsSink) Body([]byte)              {}
func (s *tsSink) Gap(http1.Section, int64) {}
func (s *tsSink) End(bool, time.Time)      {}
func (s *tsSink) Desync(int64)             {}

// Resume 回放缓存时，LastTS 是正在交付的字节所在缓存段的时间，不是最后收到的包的时间。
func TestLastTSDuringResume(t *testing.T) {
	const up = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"   // 40 字节
	const req = "POST /2 HTTP/1.1\r\nContent-Length: 5\r\n\r\nab" // 41 字节
	s := &tsSink{}
	p := http1.NewParser(http1.Request, s, http1.Options{})
	s.p = p
	if !p.LastTS().IsZero() {
		t.Fatalf("LastTS before any Feed = %v, want zero", p.LastTS())
	}
	p.Feed(0, []byte(up), -1, t0)
	p.Feed(40, []byte(req), -1, t0.Add(4*time.Second))
	p.Feed(81, []byte("cd"), -1, t0.Add(6*time.Second))
	if got, want := p.LastTS(), t0.Add(6*time.Second); !got.Equal(want) {
		t.Fatalf("LastTS while held = %v, want %v", got, want)
	}
	s.head, s.body = nil, nil
	p.Resume()
	// 请求头和第一段 body "ab" 在 4s 的段里，"cd" 在 6s 的段里。
	at4, at6 := t0.Add(4*time.Second), t0.Add(6*time.Second)
	if len(s.head) == 0 {
		t.Fatal("no head raw events")
	}
	for _, ts := range s.head {
		if !ts.Equal(at4) {
			t.Fatalf("head raw events at %v, want all %v", s.head, at4)
		}
	}
	if len(s.body) != 2 || !s.body[0].Equal(at4) || !s.body[1].Equal(at6) {
		t.Fatalf("body raw events at %v, want [%v %v]", s.body, at4, at6)
	}
}
