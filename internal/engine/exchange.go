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

	// 超过 MaxMessage 的截断。size 是已经缓存的线上字节数；trunc 是截断标记在
	// exchange.pieces 里的下标加 1，0 表示还没截断；bodyRoom 是紧接着的 Body
	// 里还能喂入的字节数（http1 先交付 Raw(SecBody)，紧跟着交付同样字节的 Body）。
	size     int64
	trunc    int
	bodyRoom int
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

	// prev、next 把在途交互按开始时间串成链表（见 Engine.oldest），超过内存上限时从最早的丢起。
	prev, next *exchange
	tracked    bool

	// ghost 表示交互已经超时结束（或因内存上限被丢弃）、留在原位置当占位，保证后面的响应配对正确。
	// 它之后的请求字节和迟到响应只由解析器解析长度，不缓存、不匹配、不输出。
	ghost bool
	late  bool // 已经为它计过一次 Late
	// evicted 表示占位是因内存上限丢弃的交互留下的：之后到达的是它自己的数据，不是迟到响应。
	evicted bool
	// lateInterim 表示占位上正在收的迟到响应是 1xx（不含 101），之后还有最终响应。
	lateInterim bool

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
// 缺口不调用 touch：缺口说明那段数据没抓到（或 ACK 表明已送达），不是收到了数据，
// 不给交互续命。缺口通常紧挨着真正收到的数据，那些数据照常续命。
func (x *exchange) touch(ts time.Time) {
	if ts.After(x.last) {
		x.last = ts
	}
}

// bury 把已经结束的交互变成占位：丢掉缓存（已经不计入缓存计量），只留配对要用的状态。
func (x *exchange) bury() {
	x.ghost = true
	x.buf, x.pieces, x.msgs = x.buf[:0], x.pieces[:0], x.msgs[:0]
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

// raw 缓存消息 mi 的一段线上字节，并按分类喂给扫描器，返回缓存的字节数。
// 消息缓存到 limit 字节为止（limit 不大于 0 时不限），超出的部分不缓存、不匹配，
// 只在输出里记一个截断标记。
func (x *exchange) raw(mi int, sec http1.Section, b []byte, limit int64) int {
	m := &x.msgs[mi]
	var over int64
	if limit > 0 && m.size+int64(len(b)) > limit {
		keep := int(max(limit-m.size, 0))
		over = int64(len(b) - keep)
		b = b[:keep]
	}
	m.size += int64(len(b))
	m.bodyRoom = len(b)
	if len(b) > 0 {
		x.cache(mi, sec, b)
	}
	if over > 0 {
		// 先缓存和喂入限额以内的部分，截断标记排在它后面。
		x.truncate(mi, over)
	}
	return len(b)
}

// cache 缓存消息 mi 的一段线上字节并按分类喂给扫描器。
func (x *exchange) cache(mi int, sec http1.Section, b []byte) {
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

// truncate 记下消息 mi 有 n 字节超过了 MaxMessage、没有缓存。第一次截断时在消息末尾
// 放一个截断标记并计入 Truncated；之后超出的字节都累加到这个标记上。
// 截断之后这条消息不会再有别的片段，标记就是它的最后一段。
func (x *exchange) truncate(mi int, n int64) {
	m := &x.msgs[mi]
	if m.trunc == 0 {
		lo := len(x.buf)
		x.pieces = append(x.pieces, piece{msg: mi, kind: output.PieceTruncated, lo: lo, hi: lo})
		m.trunc = len(x.pieces)
		x.c.e.stats.Truncated++
		// 这里不断行：限额以内的 body 字节随后才由 Body 喂入，要和前面的内容接成一行。
		// 截断之后这条消息不再喂入，消息结束时照常断行。
	}
	x.pieces[m.trunc-1].n += n
}

// gap 在消息 mi 里记下 n 字节没抓到：输出缺口标记，交互不完整，
// 这个方向在缺口处断行，缺口两边的内容不会拼成一行去匹配。
// 带 Content-Encoding 的 body 里有缺口时也算二进制（解码后的大小不可知）。
func (x *exchange) gap(mi int, sec http1.Section, n int64) {
	m := &x.msgs[mi]
	x.incomplete = true
	if m.trunc != 0 {
		// 截断之后没抓到的字节同样超出了 MaxMessage，并入截断标记，不单独输出缺口。
		x.truncate(mi, n)
		return
	}
	inBody := sec == http1.SecBody
	if inBody && m.ce != "" {
		m.binary = true
	}
	lo := len(x.buf)
	x.pieces = append(x.pieces, piece{msg: mi, kind: output.PieceGap, lo: lo, hi: lo, n: n, inBody: inBody})
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
// 超过 MaxMessage 的部分不喂，也不计入 body 大小和二进制判断。
func (x *exchange) body(mi int, b []byte) {
	m := &x.msgs[mi]
	n := min(len(b), m.bodyRoom)
	m.bodyRoom -= n
	if b = b[:n]; n == 0 {
		return
	}
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
