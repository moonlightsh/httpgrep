package http1

import (
	"bytes"
	"time"
)

// 解析状态。
type state uint8

const (
	stStart  state = iota // 等起始行（两条消息之间）
	stHead                // 读头部行
	stBodyCL              // 读 Content-Length body
)

const maxHead = 64 << 10 // 起始行加头部的上限

// Parser 解析一个方向的 HTTP/1.x 字节流。
type Parser struct {
	kind Kind
	sink Sink
	opt  Options

	st state

	// 当前行跨越多次 Feed 时，已收到的部分缓存在 lb 里。
	// lnOff、lnTS、lnAck 是当前行第一个字节的偏移、所在包的时间和 peerAck。
	lb    []byte
	lnOff int64
	lnTS  time.Time
	lnAck int64

	open bool // 有正在解析的消息（已 Begin 未 End）

	// 当前消息的头部。
	h       Head
	headLen int   // 已收到的起始行和头部字节数
	hasCL   bool  // 出现过 Content-Length
	cl      int64 // Content-Length 的值
	rem     int64 // body 还剩多少字节
}

// NewParser 创建一个解析器。
func NewParser(kind Kind, sink Sink, opt Options) *Parser {
	return &Parser{kind: kind, sink: sink, opt: opt}
}

// Feed 按序喂入从流偏移 off 开始的字节 b。b 只在调用期间使用，不保留。
func (p *Parser) Feed(off int64, b []byte, peerAck int64, ts time.Time) {
	for len(b) > 0 {
		n := p.step(off, b, peerAck, ts)
		off += int64(n)
		b = b[n:]
	}
}

// step 处理 b 开头的一部分字节，返回消耗的字节数。
// 不消耗字节时必须改变状态，保证 Feed 的循环能推进。
func (p *Parser) step(off int64, b []byte, ack int64, ts time.Time) int {
	switch p.st {
	case stStart:
		line, n, _ := p.line(off, b, ack, ts, maxHead)
		if line == nil {
			return n
		}
		if validStart(p.kind, line) {
			p.begin(line)
		}
		p.lb = p.lb[:0]
		return n

	case stHead:
		line, n, _ := p.line(off, b, ack, ts, maxHead-p.headLen)
		if line == nil {
			return n
		}
		p.headLine(line, ts)
		p.lb = p.lb[:0]
		return n

	case stBodyCL:
		k := len(b)
		if int64(k) > p.rem {
			k = int(p.rem)
		}
		p.sink.Raw(SecBody, b[:k])
		p.sink.Body(b[:k])
		p.rem -= int64(k)
		if p.rem == 0 {
			p.end(true, ts)
		}
		return k
	}
	return len(b)
}

// line 从 b 开头取一行（含 '\n'）。返回完整的一行（没取到时为 nil）、
// 消耗的字节数，以及这一行是否已经收满 limit 字节还没有换行。
// 行跨越多次 Feed 时，开头部分缓存在 p.lb 里，完整的行也从 p.lb 返回；
// 调用方处理完完整的一行后要清空 p.lb。
func (p *Parser) line(off int64, b []byte, ack int64, ts time.Time, limit int) (line []byte, n int, over bool) {
	if len(p.lb) == 0 {
		p.lnOff, p.lnTS, p.lnAck = off, ts, ack
	}
	room := limit - len(p.lb)
	if room <= 0 {
		return nil, 0, true
	}
	k := min(room, len(b))
	if i := bytes.IndexByte(b[:k], '\n'); i >= 0 {
		if len(p.lb) == 0 {
			return b[:i+1], i + 1, false
		}
		p.lb = append(p.lb, b[:i+1]...)
		return p.lb, i + 1, false
	}
	p.lb = append(p.lb, b[:k]...)
	return nil, k, len(p.lb) >= limit
}

// Gap 表示 [off, off+n) 这段没抓到。
func (p *Parser) Gap(off, n int64, ts time.Time) {}

// Close 在流结束时调用。fin 为真表示正常 FIN，为假表示 RST 或输入结束。
func (p *Parser) Close(fin bool, ts time.Time) {}

// Resume 把 Upgrade 请求之后缓存的字节按 HTTP 解析。只对请求解析器有效。
func (p *Parser) Resume() {}

// Tunnel 丢弃 Upgrade 请求之后缓存的字节，此后不再产生事件。只对请求解析器有效。
func (p *Parser) Tunnel() {}
