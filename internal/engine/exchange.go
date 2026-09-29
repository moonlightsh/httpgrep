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
	dir         uint8 // dirReq 或 dirRes
	interim     bool  // 1xx 中间响应（不含 101）
	binary      bool
	ct, ce      string
	bodySize    int64
	bodyMatched bool
	bodyAlt     bool // body 开始时这个方向的主扫描器已命中，改用 alt 判断 body 是否命中
}

// 消息所在的方向，也是 exchange.dirs 的下标。
const (
	dirReq = 0
	dirRes = 1
)

// scanDir 是一个方向的匹配状态。请求和响应的字节可能交错到达
// （比如服务端提前回响应时请求 body 还在发），两个方向各自按行续接，互不打断。
// 同一方向上的消息（1xx 和最终响应）依次到达，共用一份状态。
type scanDir struct {
	sc  *match.Scanner // 这个方向的全部内容
	alt *match.Scanner // sc 已命中后，只用来判断某个 body 是否命中

	fedMsg int // 上一次喂入的消息下标，-1 表示还没喂过
	fedSec uint8
}

// exchange 是一个交互：一个请求和它的响应（含 1xx）。
type exchange struct {
	c *conn // 所属连接

	start   time.Time // 定位行的时间：请求第一个包，缺请求时用响应的
	reqLast time.Time // 请求最后一个包
	resLast time.Time // 响应最后一个包

	reqOff int64 // 请求第一个字节的流偏移，用于 ACK 校验

	// 超时计时。last 是最后一次收到属于它的数据的时间（开始计时的时刻也算）；
	// key 和 hpos 由 timers 维护，hpos 为 0 表示不在计时。
	last time.Time
	key  time.Time
	hpos int

	hasReq     bool
	noReq      bool // 缺请求：响应配不上任何请求
	hasRes     bool // 收到过最终响应（或没收完、还不知道是不是 1xx 的响应）
	resOrphan  bool // 响应是失步后归入的 Orphan 消息，没有状态行，不输出耗时
	reqDone    bool // 请求已结束
	resDone    bool // 最终响应已结束
	incomplete bool
	noResp     string // 无响应的原因
	method     uint8
	upgrade    bool // 请求是 CONNECT 或带 Upgrade 头
	decided    bool // 已经就 Upgrade 请求调用过 Resume 或 Tunnel

	reqMsg, resMsg int // 正在接收的请求、响应消息的下标

	dirs [2]scanDir // 按方向的匹配状态，下标是 dirReq、dirRes

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

// touch 记下 ts 收到了属于这个交互的数据。
func (x *exchange) touch(ts time.Time) {
	if ts.After(x.last) {
		x.last = ts
	}
}

// status 返回交互结束时的状态。
func (x *exchange) status() output.Status {
	return output.Status{NoRequest: x.noReq, Incomplete: x.incomplete, NoResponse: x.noResp}
}

// reset 清空交互以便复用。
func (x *exchange) reset() {
	*x = exchange{
		dirs:   x.dirs,
		buf:    x.buf[:0],
		pieces: x.pieces[:0],
		msgs:   x.msgs[:0],
	}
	if cap(x.buf) > maxKeepBuf {
		x.buf = nil
	}
	for i := range x.dirs {
		d := &x.dirs[i]
		d.sc.Reset()
		d.alt.Reset()
		d.fedMsg, d.fedSec = -1, feedNone
	}
}

// matched 报告交互是否命中。alt 只在 sc 已命中后使用，不用看。
func (x *exchange) matched() bool {
	return x.dirs[dirReq].sc.Matched() || x.dirs[dirRes].sc.Matched()
}

// addMessage 在方向 dir 上追加一条消息，返回下标。
func (x *exchange) addMessage(dir uint8) int {
	x.msgs = append(x.msgs, message{dir: dir})
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

// gap 在消息 mi 里记下 n 字节没抓到：输出缺口标记，交互不完整，
// 这个方向在缺口处断行，缺口两边的内容不会拼成一行去匹配。
// 带 Content-Encoding 的 body 里有缺口时也算二进制（解码后的大小不可知）。
func (x *exchange) gap(mi int, sec http1.Section, n int64) {
	m := &x.msgs[mi]
	inBody := sec == http1.SecBody
	if inBody && m.ce != "" {
		m.binary = true
	}
	lo := len(x.buf)
	x.pieces = append(x.pieces, piece{msg: mi, kind: output.PieceGap, lo: lo, hi: lo, n: n, inBody: inBody})
	x.incomplete = true
	x.lineBreak(m.dir)
}

// head 记下头部里输出要用的信息。
func (x *exchange) head(mi int, h *http1.Head) {
	m := &x.msgs[mi]
	m.ct, m.ce = h.ContentType, h.ContentEncoding
}

// body 喂入消息 mi 去掉 chunked 编码后的 body，顺带判断是不是二进制。
// 带 Content-Encoding 的消息解码后真的有 body 字节时才算二进制：HEAD 的响应、304、
// Content-Length: 0 和 chunked 的空 body（只有 "0\r\n\r\n"）原样输出，不加占位行。
// 这几种都不会调用 body（http1 不交付空的 Body），所以判断放在这里、而不是在收到
// Raw(SecBody) 时，就足够区分。body 里有缺口时也算二进制，由缺口处理负责标记。
func (x *exchange) body(mi int, b []byte) {
	m := &x.msgs[mi]
	m.bodySize += int64(len(b))
	if !m.binary && (m.ce != "" || hasControl(b)) {
		m.binary = true
	}
	x.feed(mi, feedBody, b)
}

// feed 把消息 mi 的 b 喂给它所在方向的扫描器。同一方向上消息或分类变化时先结束当前行。
// 交互已经命中后只剩“这个 body 是否命中”要判断：body 开始时已经命中的，
// 改用 alt 扫描器判断；body 以外的内容不再扫描。
func (x *exchange) feed(mi int, sec uint8, b []byte) {
	m := &x.msgs[mi]
	d := &x.dirs[m.dir]
	if d.fedMsg != mi || d.fedSec != sec {
		x.lineBreak(m.dir)
		d.fedMsg, d.fedSec = mi, sec
		if sec == feedBody && !m.bodyAlt && x.matched() {
			m.bodyAlt = true
			d.alt.Reset()
		}
	}
	if sec != feedBody {
		if !x.matched() {
			d.sc.Write(b)
		}
		return
	}
	if m.bodyAlt {
		if !m.bodyMatched {
			d.alt.Write(b)
			m.bodyMatched = d.alt.Matched()
		}
		return
	}
	d.sc.Write(b)
	m.bodyMatched = d.sc.Matched()
}

// lineBreak 结束方向 dir 的当前行；正在喂 body 时顺带更新 body 是否命中。
func (x *exchange) lineBreak(dir uint8) {
	d := &x.dirs[dir]
	if d.fedSec != feedBody {
		d.sc.Break()
		return
	}
	m := &x.msgs[d.fedMsg]
	if m.bodyAlt {
		if !m.bodyMatched {
			d.alt.Break()
			m.bodyMatched = d.alt.Matched()
		}
		return
	}
	d.sc.Break()
	m.bodyMatched = d.sc.Matched()
}

// breakAll 结束两个方向的当前行，交互结束时调用。
func (x *exchange) breakAll() {
	x.lineBreak(dirReq)
	x.lineBreak(dirRes)
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
