package http1_test

import (
	"strconv"
	"testing"
	"time"

	"httpgrep/internal/http1"
)

// nopSink 丢弃所有事件，只统计 body 字节数和 Body 调用里的最大一次长度。
type nopSink struct {
	body, maxBody int
	ends          int
}

func (s *nopSink) Begin(http1.Begin)         {}
func (s *nopSink) Raw(http1.Section, []byte) {}
func (s *nopSink) Head(*http1.Head)          {}
func (s *nopSink) Gap(http1.Section, int64)  {}
func (s *nopSink) End(bool, time.Time)       { s.ends++ }
func (s *nopSink) Desync(int64)              {}
func (s *nopSink) Body(b []byte) {
	s.body += len(b)
	s.maxBody = max(s.maxBody, len(b))
}

// clStream 返回一个带 size 字节 Content-Length body 的响应。
func clStream(size int) []byte {
	b := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
		strconv.Itoa(size) + "\r\n\r\n")
	for i := range size {
		b = append(b, byte('a'+i%26))
	}
	return b
}

// Content-Length body 的数据按传入的切片整段交付，不拆成小段，也不分配内存。
func TestContentLengthBodyZeroCopy(t *testing.T) {
	// AllocsPerRun 先预热一次再测 runs 次，每次喂 1 MiB，body 声明得足够大，都落在 body 里。
	const runs = 20
	head := []byte("HTTP/1.1 200 OK\r\nContent-Length: 22020096\r\n\r\n") // 21 MiB
	chunk := clStream(1 << 20)[len(clStream(0)):]
	s := &nopSink{}
	p := http1.NewParser(http1.Response, s, http1.Options{})
	p.Feed(0, head, -1, t0)
	off := int64(len(head))
	allocs := testing.AllocsPerRun(runs, func() {
		for i := 0; i < len(chunk); i += 1460 {
			end := min(i+1460, len(chunk))
			p.Feed(off, chunk[i:end], -1, t0)
			off += int64(end - i)
		}
	})
	if allocs != 0 {
		t.Errorf("allocs while feeding body = %v, want 0", allocs)
	}
	if s.body != 21<<20 || s.maxBody != 1460 || s.ends != 1 {
		t.Errorf("body=%d maxBody=%d ends=%d, want 22020096, 1460, 1", s.body, s.maxBody, s.ends)
	}
}

// 1 MiB 的 Content-Length body 按 1460 字节分片喂入，目标 1 GB/s 以上。
func BenchmarkContentLengthBody(b *testing.B) {
	msg := clStream(1 << 20)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		s := &nopSink{}
		p := http1.NewParser(http1.Response, s, http1.Options{})
		for off := 0; off < len(msg); off += 1460 {
			end := min(off+1460, len(msg))
			p.Feed(int64(off), msg[off:end], -1, t0)
		}
	}
}

// 小请求的吞吐：每个请求一个包，看头部解析的开销。
func BenchmarkSmallRequests(b *testing.B) {
	req := []byte("GET /api/v1/items?id=12345 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench/1.0\r\n" +
		"Accept: */*\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"id\":12345}\n")
	s := &nopSink{}
	p := http1.NewParser(http1.Request, s, http1.Options{})
	b.SetBytes(int64(len(req)))
	b.ReportAllocs()
	var off int64
	for b.Loop() {
		p.Feed(off, req, -1, t0)
		off += int64(len(req))
	}
}

// 非 HTTP 的连接（比如 TLS）一直处于扫描状态：伪随机字节按 1460 字节分片喂入。
func BenchmarkScanBinary(b *testing.B) {
	buf := make([]byte, 1<<20)
	x := uint32(2463534242)
	for i := range buf {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		buf[i] = byte(x)
	}
	s := &nopSink{}
	p := http1.NewParser(http1.Request, s, http1.Options{Resync: true})
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	var off int64
	for b.Loop() {
		for i := 0; i < len(buf); i += 1460 {
			end := min(i+1460, len(buf))
			p.Feed(off, buf[i:end], -1, t0)
			off += int64(end - i)
		}
	}
}
