package engine

import (
	"time"

	"httpgrep/internal/http1"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
)

// 请求方法里引擎关心的几种，响应解析器要据此判断有没有 body。
const (
	methodOther uint8 = iota
	methodHead
	methodConnect
)

// 喂给扫描器的内容分类。切换分类或切换消息时先 Break，免得两段拼成一行。
const (
	feedNone uint8 = iota
	feedHead
	feedBody
	feedTrailer
	feedUnparsed
)

// piece 是缓存里的一段：[lo, hi) 是 exchange.buf 里的字节。
type piece struct {
	msg    int // 所属消息在 exchange.msgs 里的下标
	kind   output.PieceKind
	lo, hi int
	n      int64
	inBody bool
}

// message 是交互里的一条消息：请求、1xx 响应或最终响应。
type message struct {
	interim     bool // 1xx 中间响应（不含 101）
	binary      bool
	ct, ce      string
	bodySize    int64
	bodyMatched bool
	bodyAlt     bool // body 开始时主扫描器已命中，改用 alt 判断 body 是否命中
}

// exchange 是一个交互：一个请求和它的响应（含 1xx）。
type exchange struct {
	start   time.Time // 定位行的时间：请求第一个包，缺请求时用响应的
	reqLast time.Time // 请求最后一个包
	resLast time.Time // 响应最后一个包

	hasReq     bool
	hasRes     bool // 收到过响应（含 1xx）
	reqDone    bool // 请求已结束
	incomplete bool
	noResp     string // 无响应的原因
	method     uint8
	upgrade    bool // 请求是 CONNECT 或带 Upgrade 头

	reqMsg, resMsg int // 正在接收的请求、响应消息的下标

	sc  *match.Scanner // 整个交互的扫描器
	alt *match.Scanner // 主扫描器已命中后，只用来判断某个 body 是否命中

	fedMsg int
	fedSec uint8

	buf    []byte
	pieces []piece
	msgs   []message
}

// maxKeepBuf 是交互复用时保留的缓存容量上限，超过就释放。
const maxKeepBuf = 64 << 10

// 无响应的原因，即 output.Status.NoResponse 的取值。
const (
	noRespTimeout = "timeout"
	noRespClosed  = "closed"
	noRespEOF     = "eof"
)

// status 返回交互结束时的状态。
func (x *exchange) status() output.Status {
	return output.Status{Incomplete: x.incomplete, NoResponse: x.noResp}
}

// reset 清空交互以便复用。
func (x *exchange) reset() {
	*x = exchange{
		sc:     x.sc,
		alt:    x.alt,
		buf:    x.buf[:0],
		pieces: x.pieces[:0],
		msgs:   x.msgs[:0],
		fedMsg: -1,
	}
	if cap(x.buf) > maxKeepBuf {
		x.buf = nil
	}
	x.sc.Reset()
	x.alt.Reset()
}

// addMessage 追加一条消息，返回下标。
func (x *exchange) addMessage() int {
	x.msgs = append(x.msgs, message{})
	return len(x.msgs) - 1
}

// raw 缓存消息 mi 的一段线上字节，并按分类喂给扫描器。
func (x *exchange) raw(mi int, sec http1.Section, b []byte) {
	kind := pieceKind(sec)
	lo := len(x.buf)
	x.buf = append(x.buf, b...)
	if n := len(x.pieces); n > 0 {
		p := &x.pieces[n-1]
		if p.msg == mi && p.kind == kind && p.hi == lo {
			p.hi = len(x.buf)
			goto feed
		}
	}
	x.pieces = append(x.pieces, piece{msg: mi, kind: kind, lo: lo, hi: len(x.buf)})
feed:
	switch sec {
	case http1.SecHead:
		x.feed(mi, feedHead, b)
	case http1.SecTrailer:
		x.feed(mi, feedTrailer, b)
	case http1.SecUnparsed:
		x.feed(mi, feedUnparsed, b)
	}
}

// head 记下头部里输出要用的信息。
func (x *exchange) head(mi int, h *http1.Head) {
	m := &x.msgs[mi]
	m.ct, m.ce = h.ContentType, h.ContentEncoding
	if h.ContentEncoding != "" {
		m.binary = true
	}
}

// body 喂入消息 mi 去掉 chunked 编码后的 body，顺带判断是不是二进制。
func (x *exchange) body(mi int, b []byte) {
	m := &x.msgs[mi]
	m.bodySize += int64(len(b))
	if !m.binary && hasControl(b) {
		m.binary = true
	}
	x.feed(mi, feedBody, b)
}

// feed 把 b 喂给扫描器。消息或分类变化时先结束当前行。
// body 开始时主扫描器已经命中的，改用 alt 扫描器判断这个 body 是否命中。
func (x *exchange) feed(mi int, sec uint8, b []byte) {
	if x.fedMsg != mi || x.fedSec != sec {
		x.lineBreak()
		x.fedMsg, x.fedSec = mi, sec
		if m := &x.msgs[mi]; sec == feedBody && !m.bodyAlt && x.sc.Matched() {
			m.bodyAlt = true
			x.alt.Reset()
		}
	}
	if sec != feedBody {
		x.sc.Write(b)
		return
	}
	m := &x.msgs[mi]
	if m.bodyAlt {
		if !m.bodyMatched {
			x.alt.Write(b)
			m.bodyMatched = x.alt.Matched()
		}
		return
	}
	x.sc.Write(b)
	m.bodyMatched = x.sc.Matched()
}

// lineBreak 结束扫描器的当前行；正在喂 body 时顺带更新 body 是否命中。
func (x *exchange) lineBreak() {
	if x.fedSec == feedBody {
		m := &x.msgs[x.fedMsg]
		if m.bodyAlt {
			if !m.bodyMatched {
				x.alt.Break()
				m.bodyMatched = x.alt.Matched()
			}
			return
		}
		x.sc.Break()
		m.bodyMatched = x.sc.Matched()
		return
	}
	x.sc.Break()
}

// hasControl 判断 b 里有没有 \t \r \n 以外的 C0 控制字符或 DEL。
func hasControl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' || c == 0x7f {
			return true
		}
	}
	return false
}

func pieceKind(sec http1.Section) output.PieceKind {
	switch sec {
	case http1.SecBody:
		return output.PieceBody
	case http1.SecTrailer:
		return output.PieceTrailer
	case http1.SecUnparsed:
		return output.PieceUnparsed
	}
	return output.PieceHead
}
