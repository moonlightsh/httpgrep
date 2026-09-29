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
	p.hasTE, p.chunked = false, false
	p.hasCT, p.hasCE = false, false
	p.dec = undecided
	parseStart(p.kind, trimEOL(line), &p.h)
	p.sink.Raw(SecHead, line)
	p.headLen = len(line)
	p.st = stHead
}

// headLine 处理一行头部（含行尾），格式不合法时返回 false。
func (p *Parser) headLine(line []byte, ts time.Time) bool {
	s := trimEOL(line)
	if len(s) == 0 {
		p.headLen += len(line)
		p.sink.Raw(SecHead, line)
		p.finishHead(p.lnOff+int64(len(line)), ts)
		return true
	}
	i := bytes.IndexByte(s, ':')
	if i <= 0 {
		return false
	}
	name, val := s[:i], trimSpace(s[i+1:])
	switch {
	case eqFold(name, "content-length"):
		v, ok := parseCL(val)
		if !ok || p.hasCL && v != p.cl {
			return false
		}
		p.hasCL, p.cl = true, v
	case eqFold(name, "transfer-encoding"):
		p.hasTE = true
		last := val
		if k := bytes.LastIndexByte(val, ','); k >= 0 {
			last = trimSpace(val[k+1:])
		}
		p.chunked = eqFold(last, "chunked")
	case eqFold(name, "content-type"):
		if !p.hasCT {
			p.hasCT, p.h.ContentType = true, string(val)
		}
	case eqFold(name, "content-encoding"):
		if !p.hasCE {
			p.hasCE, p.h.ContentEncoding = true, string(val)
		}
	case p.kind == Request && eqFold(name, "upgrade"):
		p.h.Upgrade = true
	}
	p.headLen += len(line)
	p.sink.Raw(SecHead, line)
	return true
}

// finishHead 在头部结束的空行之后决定 body 的长度。end 是空行之后的流偏移。
func (p *Parser) finishHead(end int64, ts time.Time) {
	if p.kind == Request && p.hasTE && !p.chunked {
		// 请求的 body 长度无法确定。
		p.desync(end)
		p.bol = true
		p.tunnelAfterDesync()
		return
	}
	next := p.bodyState()
	p.sink.Head(&p.h)
	if next == stStart {
		p.end(true, ts)
		if p.h.Tunnel {
			p.st = stDead
		}
		return
	}
	p.st = next
}

// bodyState 返回头部之后的状态；没有 body 时返回 stStart。
func (p *Parser) bodyState() state {
	if p.kind == Response {
		st := p.h.Status
		if st == 101 {
			p.h.Tunnel = true
			return stStart
		}
		if st < 200 {
			return stStart
		}
		// 每个非 1xx 响应都问一次对应请求的方法。
		m := ""
		if p.opt.Method != nil {
			m = p.opt.Method()
		}
		if m == "CONNECT" && st < 300 {
			p.h.Tunnel = true
			return stStart
		}
		if m == "HEAD" || st == 204 || st == 304 {
			return stStart
		}
		if p.hasTE {
			if p.chunked {
				return stChunkSize
			}
			return stBodyClose
		}
		if p.hasCL {
			return p.clState()
		}
		return stBodyClose
	}
	if p.hasTE && p.chunked {
		return stChunkSize
	}
	if p.hasCL {
		return p.clState()
	}
	return stStart
}

func (p *Parser) clState() state {
	if p.cl == 0 {
		return stStart
	}
	p.rem = p.cl
	return stBodyCL
}

// end 结束当前消息，按调用方的决定和 Head.Upgrade 选择之后的状态。
func (p *Parser) end(complete bool, ts time.Time) {
	p.sink.End(complete, ts)
	p.open = false
	switch {
	case p.dec == decTunnel:
		p.st = stDead
	case p.kind == Request && p.h.Upgrade && p.dec != decResume:
		p.st = stHold
		p.dropHold()
	default:
		p.st = stStart
	}
	p.dec = undecided
}

// validStart 判断 line（含行尾）是不是合法的起始行。
//
//	请求行：方法 SP 目标 SP HTTP/1.0|HTTP/1.1，方法是 1 到 20 个大写字母或 '-'，目标非空且不含空格。
//	状态行：HTTP/1.0|HTTP/1.1 SP 三位数字，后面直接换行或跟 SP 原因短语。
func validStart(kind Kind, line []byte) bool {
	s := trimEOL(line)
	if kind == Request {
		i := methodLen(s)
		if i == 0 || i >= len(s) || s[i] != ' ' {
			return false
		}
		j := bytes.LastIndexByte(s, ' ')
		return j > i+1 && bytes.IndexByte(s[i+1:j], ' ') < 0 && isProto(s[j+1:])
	}
	if len(s) < 12 || !isProto(s[:8]) || s[8] != ' ' {
		return false
	}
	for _, c := range s[9:12] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) == 12 || s[12] == ' '
}

// startPrefix 判断还没收完的一行 s 的开头是否还可能是合法的起始行，
// 只看换行之前的前 probeLen 个字节。blank 为真时，一个单独的 '\r' 也算（可能是空行）。
func startPrefix(kind Kind, s []byte, blank bool) bool {
	if i := bytes.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > probeLen {
		s = s[:probeLen]
	}
	if len(s) == 0 || blank && len(s) == 1 && s[0] == '\r' {
		return true
	}
	if kind == Request {
		i := methodLen(s)
		switch {
		case i == 0 && len(s) > 0:
			return false
		case i == len(s):
			return true
		}
		return s[i] == ' ' && (i+1 == len(s) || s[i+1] != ' ')
	}
	const pat = "HTTP/1.x ddd"
	for j, c := range s {
		if j >= len(pat) {
			// 三位状态码之后是原因短语前的空格，或者行尾 CRLF 的 '\r'（没有原因短语）。
			return c == ' ' || c == '\r' && j == len(s)-1
		}
		switch pat[j] {
		case 'x':
			if c != '0' && c != '1' {
				return false
			}
		case 'd':
			if c < '0' || c > '9' {
				return false
			}
		default:
			if c != pat[j] {
				return false
			}
		}
	}
	return true
}

// methodLen 返回 s 开头由大写字母和 '-' 组成的方法名长度；超过 20 个时返回 0。
func methodLen(s []byte) int {
	i := 0
	for i < len(s) && (('A' <= s[i] && s[i] <= 'Z') || s[i] == '-') {
		i++
		if i > 20 {
			return 0
		}
	}
	return i
}

func isProto(s []byte) bool {
	return string(s) == "HTTP/1.1" || string(s) == "HTTP/1.0"
}

// proto 返回协议版本的常量字符串，避免分配。
func proto(s []byte) string {
	if string(s) == "HTTP/1.0" {
		return "HTTP/1.0"
	}
	return "HTTP/1.1"
}

// parseStart 把合法的起始行（不含行尾）解析进 h。
func parseStart(kind Kind, s []byte, h *Head) {
	if kind == Request {
		i := bytes.IndexByte(s, ' ')
		j := bytes.LastIndexByte(s, ' ')
		h.Method = method(s[:i])
		h.Target = string(s[i+1 : j])
		h.Proto = proto(s[j+1:])
		h.Upgrade = h.Method == "CONNECT"
		return
	}
	h.Proto = proto(s[:8])
	h.Status = int(s[9]-'0')*100 + int(s[10]-'0')*10 + int(s[11]-'0')
}

// method 返回方法名字符串；常见方法用常量，避免分配。
func method(s []byte) string {
	switch string(s) {
	case "GET":
		return "GET"
	case "POST":
		return "POST"
	case "HEAD":
		return "HEAD"
	case "PUT":
		return "PUT"
	case "DELETE":
		return "DELETE"
	case "OPTIONS":
		return "OPTIONS"
	case "PATCH":
		return "PATCH"
	case "CONNECT":
		return "CONNECT"
	}
	return string(s)
}

// parseCL 解析 Content-Length 的值：1 到 18 位十进制数字。
func parseCL(s []byte) (int64, bool) {
	if len(s) == 0 || len(s) > 18 {
		return 0, false
	}
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int64(c-'0')
	}
	return v, true
}

// parseChunkSize 解析 chunk 长度行（不含行尾）：十六进制数字，后面可以跟 ";扩展"。
func parseChunkSize(s []byte) (int64, bool) {
	if k := bytes.IndexByte(s, ';'); k >= 0 {
		s = s[:k]
	}
	s = trimSpace(s)
	if len(s) == 0 {
		return 0, false
	}
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	if len(s) > 15 { // 超过 int64 能放下的范围
		return 0, false
	}
	var v int64
	for _, c := range s {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c -= 'a' - 10
		case 'A' <= c && c <= 'F':
			c -= 'A' - 10
		default:
			return 0, false
		}
		v = v<<4 | int64(c)
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
