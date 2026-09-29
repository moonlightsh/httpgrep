package http1

import (
	"bytes"
	"time"
)

// 解析状态。
type state uint8

const (
	stStart     state = iota // 等起始行（两条消息之间）
	stHead                   // 读头部行
	stBodyCL                 // 读 Content-Length body
	stChunkSize              // 读 chunk 长度行
	stChunkData              // 读 chunk 数据
	stChunkEnd               // 读 chunk 数据后面的 CRLF
	stTrailer                // 读 trailer
	stBodyClose              // 读到关闭为止的 body
	stScan                   // 失步：在行首找起始行
	stDead                   // 隧道或已关闭：不再产生任何事件
)

const (
	maxHead      = 64 << 10 // 起始行加头部的上限
	maxTrailer   = 64 << 10 // trailer 的上限
	maxChunkLine = 4 << 10  // chunk 长度行的上限
	maxScanLine  = 8 << 10  // 扫描时起始行候选的上限
	probeLen     = 24       // 扫描时先看行首这么多字节，明显不是起始行就不缓存
)

// Parser 解析一个方向的 HTTP/1.x 字节流。
type Parser struct {
	kind Kind
	sink Sink
	opt  Options

	st  state
	bol bool // 扫描状态下，下一个字节在行首

	// 当前行跨越多次 Feed 时，已收到的部分缓存在 lb 里。
	// lnOff、lnTS、lnAck 是当前行第一个字节的偏移、所在包的时间和 peerAck。
	lb    []byte
	lnOff int64
	lnTS  time.Time
	lnAck int64

	open bool // 有正在解析的消息（已 Begin 未 End），包括 Orphan 消息

	// 当前消息的头部。
	h       Head
	headLen int   // 已收到的起始行和头部字节数
	hasCL   bool  // 出现过 Content-Length
	cl      int64 // Content-Length 的值
	hasTE   bool  // 出现过 Transfer-Encoding
	chunked bool  // 最后一个 Transfer-Encoding 的最后一项是 chunked
	rem     int64 // Content-Length body 或当前 chunk 数据还剩多少字节
	trlLen  int   // 已收到的 trailer 字节数
}

// NewParser 创建一个解析器。
func NewParser(kind Kind, sink Sink, opt Options) *Parser {
	p := &Parser{kind: kind, sink: sink, opt: opt}
	if opt.Resync {
		// 流的第一个字节算作行首。
		p.st, p.bol = stScan, true
	}
	return p
}

// Feed 按序喂入从流偏移 off 开始的字节 b。b 只在调用期间使用，不保留。
func (p *Parser) Feed(off int64, b []byte, peerAck int64, ts time.Time) {
	for len(b) > 0 && p.st != stDead {
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
		line, n, over := p.line(off, b, ack, ts, maxHead)
		if line == nil {
			// 行还没收完：开头已经不可能是起始行时立即失步，不再缓存。
			if over || !startPrefix(p.kind, p.lb, true) {
				p.desync(p.lnOff)
				p.unparsedLine()
				p.bol = false
			}
			return n
		}
		switch {
		case len(trimEOL(line)) == 0: // 起始行之前的空行跳过
		case validStart(p.kind, line):
			p.begin(line)
		default:
			p.desync(p.lnOff)
			p.unparsed(line, p.lnOff, p.lnTS, p.lnAck)
			p.bol = true
		}
		p.lb = p.lb[:0]
		return n

	case stHead:
		line, n, over := p.line(off, b, ack, ts, maxHead-p.headLen)
		if line == nil {
			if over {
				p.desync(p.lnOff)
				p.unparsedLine()
				p.bol = false
			}
			return n
		}
		if !p.headLine(line, ts) {
			p.desyncAtLine(line)
		}
		p.lb = p.lb[:0]
		return n

	case stBodyCL, stChunkData:
		// 大段数据直接切片交付，不逐字节处理。
		k := len(b)
		if int64(k) > p.rem {
			k = int(p.rem)
		}
		p.sink.Raw(SecBody, b[:k])
		p.sink.Body(b[:k])
		p.rem -= int64(k)
		if p.rem == 0 {
			p.dataDone(ts)
		}
		return k

	case stBodyClose:
		p.sink.Raw(SecBody, b)
		p.sink.Body(b)
		return len(b)

	case stChunkSize:
		line, n, over := p.line(off, b, ack, ts, maxChunkLine)
		if line == nil {
			if over {
				p.desync(p.lnOff)
				p.unparsedLine()
				p.bol = false
			}
			return n
		}
		size, ok := parseChunkSize(trimEOL(line))
		switch {
		case !ok:
			p.desyncAtLine(line)
		case size == 0:
			p.sink.Raw(SecBody, line)
			p.trlLen = 0
			p.st = stTrailer
		default:
			p.sink.Raw(SecBody, line)
			p.rem = size
			p.st = stChunkData
		}
		p.lb = p.lb[:0]
		return n

	case stChunkEnd:
		// chunk 数据后面只能是 "\r\n" 或 "\n"：按上限 2 字节的一行来读。
		line, n, over := p.line(off, b, ack, ts, 2)
		if line == nil {
			if over {
				p.desync(p.lnOff)
				p.unparsedLine()
				p.bol = false
			}
			return n
		}
		if len(trimEOL(line)) != 0 {
			p.desyncAtLine(line)
		} else {
			p.sink.Raw(SecBody, line)
			p.st = stChunkSize
		}
		p.lb = p.lb[:0]
		return n

	case stTrailer:
		line, n, over := p.line(off, b, ack, ts, maxTrailer-p.trlLen)
		if line == nil {
			if over {
				p.desync(p.lnOff)
				p.unparsedLine()
				p.bol = false
			}
			return n
		}
		s := trimEOL(line)
		switch {
		case len(s) == 0:
			p.sink.Raw(SecTrailer, line)
			p.end(true, ts)
		case bytes.IndexByte(s, ':') <= 0:
			p.desyncAtLine(line)
		default:
			p.trlLen += len(line)
			p.sink.Raw(SecTrailer, line)
		}
		p.lb = p.lb[:0]
		return n

	case stScan:
		return p.scan(off, b, ack, ts)
	}
	return len(b)
}

// dataDone 在 Content-Length body 或一个 chunk 的数据收完时调用。
func (p *Parser) dataDone(ts time.Time) {
	if p.st == stBodyCL {
		p.end(true, ts)
	} else {
		p.st = stChunkEnd
	}
}

// scan 处理扫描状态下的字节：只在行首找合法的起始行，其余字节作为 SecUnparsed 交付。
func (p *Parser) scan(off int64, b []byte, ack int64, ts time.Time) int {
	if !p.bol {
		// 不在行首：直接跳到下一个换行。
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.unparsed(b, off, ts, ack)
			return len(b)
		}
		p.unparsed(b[:i+1], off, ts, ack)
		p.bol = true
		return i + 1
	}
	if len(p.lb) == 0 && !startPrefix(p.kind, b, false) {
		// 行首几个字节就不像起始行：这一行不缓存，按普通字节交付。
		p.bol = false
		return 0
	}
	line, n, over := p.line(off, b, ack, ts, maxScanLine)
	if line == nil {
		if over || !startPrefix(p.kind, p.lb, false) {
			p.unparsedLine()
			p.bol = false
		}
		return n
	}
	if validStart(p.kind, line) {
		if p.open {
			p.sink.End(false, p.lnTS)
			p.open = false
		}
		p.begin(line)
	} else {
		p.unparsed(line, p.lnOff, p.lnTS, p.lnAck)
	}
	p.lb = p.lb[:0]
	return n
}

// desync 在 off 处失步，进入扫描状态。
func (p *Parser) desync(off int64) {
	p.sink.Desync(off)
	p.st = stScan
}

// desyncAtLine 在一个完整但不合法的行处失步：这一行作为 SecUnparsed 交付，
// 从下一行的行首开始扫描。
func (p *Parser) desyncAtLine(line []byte) {
	p.desync(p.lnOff)
	p.unparsed(line, p.lnOff, p.lnTS, p.lnAck)
	p.bol = true
}

// unparsed 以 SecUnparsed 交付失步期间的字节；没有正在解析的消息时先开始一条 Orphan 消息。
func (p *Parser) unparsed(b []byte, off int64, ts time.Time, ack int64) {
	if len(b) == 0 {
		return
	}
	p.orphan(off, ts, ack)
	p.sink.Raw(SecUnparsed, b)
}

// unparsedLine 把缓存的半行作为 SecUnparsed 交付并清空。
func (p *Parser) unparsedLine() {
	p.unparsed(p.lb, p.lnOff, p.lnTS, p.lnAck)
	p.lb = p.lb[:0]
}

// orphan 在没有正在解析的消息时开始一条 Orphan 消息。
func (p *Parser) orphan(off int64, ts time.Time, ack int64) {
	if !p.open {
		p.sink.Begin(Begin{Off: off, TS: ts, PeerAck: ack, Orphan: true})
		p.open = true
	}
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
func (p *Parser) Gap(off, n int64, ts time.Time) {
	if n <= 0 {
		return
	}
	switch p.st {
	case stDead:
		return
	case stBodyCL, stChunkData:
		if n <= p.rem {
			// 缺口落在长度已知的数据里：不影响解析。
			p.sink.Gap(SecBody, n)
			p.rem -= n
			if p.rem == 0 {
				p.dataDone(ts)
			}
			return
		}
	case stBodyClose:
		p.sink.Gap(SecBody, n)
		return
	}
	if p.st != stScan {
		// 其余位置的缺口都会失步。已经收到的半行照原来的 Section 交付；
		// 两条消息之间的半行没有所属消息，下面归入 Orphan 消息。
		if p.open && len(p.lb) > 0 {
			p.sink.Raw(p.lineSection(), p.lb)
			p.lb = p.lb[:0]
		}
		p.desync(off)
	}
	p.unparsedLine()
	p.orphan(off, ts, -1)
	p.sink.Gap(SecUnparsed, n)
	p.bol = true
}

// Close 在流结束时调用。fin 为真表示正常 FIN，为假表示 RST 或输入结束。
func (p *Parser) Close(fin bool, ts time.Time) {
	switch p.st {
	case stDead:
		return
	case stStart:
		// 还没有构成起始行的半行不属于任何消息，丢弃。
	case stScan:
		p.unparsedLine()
	default:
		// 没收完的一行照样交付，保证 Raw 拼起来是原文。
		if len(p.lb) > 0 {
			p.sink.Raw(p.lineSection(), p.lb)
		}
	}
	if p.open {
		p.sink.End(fin && p.st == stBodyClose, ts)
		p.open = false
	}
	p.lb = p.lb[:0]
	p.st = stDead
}

// lineSection 返回当前状态下正在读的行所属的 Section。
func (p *Parser) lineSection() Section {
	switch p.st {
	case stChunkSize, stChunkEnd:
		return SecBody
	case stTrailer:
		return SecTrailer
	}
	return SecHead
}

// Resume 把 Upgrade 请求之后缓存的字节按 HTTP 解析。只对请求解析器有效。
func (p *Parser) Resume() {}

// Tunnel 丢弃 Upgrade 请求之后缓存的字节，此后不再产生事件。只对请求解析器有效。
func (p *Parser) Tunnel() {}
