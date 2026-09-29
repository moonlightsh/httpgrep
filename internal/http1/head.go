package http1

import (
	"bytes"
	"time"
)

// begin 在收到合法的起始行后开始一条新消息。
func (p *Parser) begin(line []byte) {
	p.sink.Begin(Begin{Off: p.lnOff, TS: p.lnTS, PeerAck: p.lnAck})
	p.open = true
	p.h = Head{}
	p.hasCL, p.cl = false, 0
	parseStart(p.kind, trimEOL(line), &p.h)
	p.sink.Raw(SecHead, line)
	p.headLen = len(line)
	p.st = stHead
}

// headLine 处理一行头部（含行尾）。
func (p *Parser) headLine(line []byte, ts time.Time) {
	p.headLen += len(line)
	s := trimEOL(line)
	if len(s) == 0 {
		p.sink.Raw(SecHead, line)
		p.finishHead(ts)
		return
	}
	i := bytes.IndexByte(s, ':')
	name, val := s[:i], trimSpace(s[i+1:])
	if eqFold(name, "content-length") {
		p.hasCL = true
		p.cl, _ = parseCL(val)
	}
	p.sink.Raw(SecHead, line)
}

// finishHead 在头部结束的空行之后决定 body 的长度。
func (p *Parser) finishHead(ts time.Time) {
	p.sink.Head(&p.h)
	if p.hasCL && p.cl > 0 {
		p.rem = p.cl
		p.st = stBodyCL
		return
	}
	p.end(true, ts)
}

// end 结束当前消息。
func (p *Parser) end(complete bool, ts time.Time) {
	p.sink.End(complete, ts)
	p.open = false
	p.st = stStart
}

// validStart 判断 line（含行尾）是不是合法的起始行。
func validStart(kind Kind, line []byte) bool {
	return len(trimEOL(line)) > 0
}

// parseStart 把合法的起始行（不含行尾）解析进 h。
func parseStart(kind Kind, s []byte, h *Head) {
	if kind == Request {
		i := bytes.IndexByte(s, ' ')
		j := bytes.LastIndexByte(s, ' ')
		h.Method = string(s[:i])
		h.Target = string(s[i+1 : j])
		h.Proto = string(s[j+1:])
	}
}

// parseCL 解析 Content-Length 的值：只允许十进制数字。
func parseCL(s []byte) (int64, bool) {
	var v int64
	for _, c := range s {
		v = v*10 + int64(c-'0')
	}
	return v, true
}

// trimEOL 去掉行尾的 "\n" 或 "\r\n"。
func trimEOL(s []byte) []byte {
	if n := len(s); n > 0 && s[n-1] == '\n' {
		s = s[:n-1]
		if n := len(s); n > 0 && s[n-1] == '\r' {
			s = s[:n-1]
		}
	}
	return s
}

// trimSpace 去掉首尾的空格和制表符。
func trimSpace(s []byte) []byte {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// eqFold 判断 b 与小写 ASCII 字符串 lower 是否不区分大小写相等。
func eqFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := range len(b) {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
