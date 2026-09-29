// Package engine 把重组后的字节流解析成 HTTP 交互：配对请求和响应、
// 管理交互的生命周期、按关键词匹配，命中的交互结束时整块输出。
package engine

import (
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
	"httpgrep/internal/tcp"
)

// Config 是引擎的参数。
type Config struct {
	Matcher    *match.Matcher
	Timeout    time.Duration
	MaxMemory  int64
	MaxMessage int64
	Emit       func(b *output.Block) // 命中的交互结束时调用；b 只在回调期间有效
	Warn       func(msg string)      // 内存上限告警，引擎自己限频
}

// Engine 处理一个分片的全部连接。不是并发安全的。
type Engine struct {
	cfg   Config
	asm   *tcp.Assembler
	stats Stats

	free     []*exchange // 回收的交互，连同缓存和扫描器一起复用，见 recycle
	freeBuf  int64       // free 里的交互留着的内存估计之和，见 recycle
	timers   timers      // 正在计时的在途交互，按到期时间排序
	inFlight int
	buffered int64 // 在途交互缓存的消息字节数

	// oldest、newest 是按开始时间排序的在途交互链表的两端，超过内存上限时从 oldest 丢起。
	oldest, newest *exchange

	// 内存告警：dropped、droppedMatched 是距上一次告警以来丢弃的交互数和其中已命中的；
	// warnedAt 是上一次告警的抓包时间，warned 表示告警过。
	dropped, droppedMatched int64
	warnedAt                time.Time
	warned                  bool

	// 输出块和它引用的切片，每次输出复用。
	block  output.Block
	msgs   []output.Message
	pieces []output.Piece
	starts []int
}

// reorderTimeout 是乱序数据最多等待的时间。
const reorderTimeout = 2 * time.Second

// New 创建引擎。
func New(cfg Config) *Engine {
	e := &Engine{cfg: cfg}
	e.asm = tcp.NewAssembler(tcp.Config{
		ReorderTimeout:  reorderTimeout,
		MaxReorderBytes: cfg.MaxMessage,
		IdleTimeout:     2 * cfg.Timeout,
	}, e.open)
	return e
}

// open 是 tcp.Assembler 新建连接时的回调。
func (e *Engine) open(info tcp.ConnInfo) tcp.Handler {
	e.stats.Connections++
	if !info.RolesKnown {
		e.stats.MidStream++
	}
	if n := e.asm.Len() + 1; n > e.stats.PeakConns {
		e.stats.PeakConns = n
	}
	return e.newConn(info)
}

// Segment 处理一个 TCP 段。ts 是抓包时间，单调不减。
// 先结束到 ts 为止已经超时的交互：调用方没有在两个包之间调用 Advance 时，
// 这个段的数据也不会让已经超时的交互续命。
func (e *Engine) Segment(seg *decode.Segment, ts time.Time) {
	e.expire(ts)
	e.asm.Add(seg, ts)
	e.enforce(ts)
}

// Advance 推进时钟，只处理到期的定时器。now 单调不减。
func (e *Engine) Advance(now time.Time) {
	e.expire(now)
	e.asm.Advance(now)
	e.enforce(now)
}

// expire 按到期时间的先后结束到 now 为止超时的交互。
// 堆里的 key 不随每个包更新（见 timers），堆顶到期时先按 last 核对真正的到期时间。
func (e *Engine) expire(now time.Time) {
	for len(e.timers) > 0 {
		x := e.timers[0]
		if x.key.After(now) {
			return
		}
		if at := x.last.Add(e.cfg.Timeout); at.After(x.key) {
			x.key = at
			e.timers.fixTop()
			continue
		}
		e.timers.remove(x)
		x.c.timeout(x, x.key)
	}
}

// arm 从 at 起给交互 x 计时：at 之前收到的数据不再算数。
func (e *Engine) arm(x *exchange, at time.Time) {
	if at.After(x.last) {
		x.last = at
	}
	e.timers.push(x, x.last.Add(e.cfg.Timeout))
}

// Finish 在输入结束时调用：在途交互都以 eof 结束。
func (e *Engine) Finish(now time.Time) {
	e.asm.Flush(now)
	if e.dropped > 0 {
		e.warn(now)
	}
}

// newExchange 为连接 c 取一个空的交互。
func (e *Engine) newExchange(c *conn) *exchange {
	var x *exchange
	if n := len(e.free); n > 0 {
		x = e.free[n-1]
		e.free[n-1] = nil
		e.free = e.free[:n-1]
		e.freeBuf -= x.keep
	} else {
		x = &exchange{}
	}
	x.reset(e.cfg.Matcher)
	x.c = c
	e.stats.Exchanges++
	e.inFlight++
	if e.inFlight > e.stats.PeakInFlight {
		e.stats.PeakInFlight = e.inFlight
	}
	return x
}

// finish 结束交互：计入统计，命中的输出，然后回收。
func (e *Engine) finish(c *conn, x *exchange) {
	e.end(c, x)
	e.recycle(x)
}

// end 结束交互但不回收：停止计时，计入统计，命中的输出，缓存不再计入。
// 超时的交互之后还要留在队列里当占位，由调用方决定何时回收。
func (e *Engine) end(c *conn, x *exchange) {
	e.timers.remove(x)
	e.untrack(x)
	x.breakAll()
	st := x.status()
	switch {
	case st == output.Status{}:
		e.stats.Complete++
	default:
		if st.NoRequest {
			e.stats.NoRequest++
		}
		if st.Incomplete {
			e.stats.Incomplete++
		}
		switch st.NoResponse {
		case noRespTimeout:
			e.stats.NoResponseTimeout++
		case noRespClosed:
			e.stats.NoResponseClosed++
		case noRespEOF:
			e.stats.NoResponseEOF++
		}
	}
	if x.matched() {
		e.stats.Matched++
		e.emit(c, x, st)
	}
	e.inFlight--
	e.buffered -= int64(len(x.buf))
}

// addBuffered 记下在途交互新缓存的 n 字节，更新峰值。
// 只计消息字节；乱序缓存和固定开销在内存上限（E4）里计入。
func (e *Engine) addBuffered(n int) {
	e.buffered += int64(n)
	if e.buffered > e.stats.PeakBuffered {
		e.stats.PeakBuffered = e.buffered
	}
}

// emit 把交互组装成输出块交给 Emit。
func (e *Engine) emit(c *conn, x *exchange, st output.Status) {
	b := &e.block
	b.Time = x.start
	b.Client, b.Server = c.cliAddr, c.srvAddr
	b.Status = st
	b.HasDuration = x.hasReq && x.hasRes && !x.resOrphan
	b.Duration = 0
	if b.HasDuration {
		// 服务端在请求发完之前就回完了响应时，耗时记 0，不输出负数。
		b.Duration = max(x.resLast.Sub(x.reqLast), 0)
	}
	// 片段按到达顺序缓存，两个方向可能交错：按消息分组后再切给各条消息。
	e.pieces, e.starts = e.pieces[:0], e.starts[:0]
	for mi := range x.msgs {
		e.starts = append(e.starts, len(e.pieces))
		for _, p := range x.pieces {
			if p.msg == mi {
				e.pieces = append(e.pieces, output.Piece{Kind: p.kind, Data: x.buf[p.lo:p.hi], N: p.n, InBody: p.inBody})
			}
		}
	}
	e.msgs = e.msgs[:0]
	for mi := range x.msgs {
		m := &x.msgs[mi]
		end := len(e.pieces)
		if mi+1 < len(x.msgs) {
			end = e.starts[mi+1]
		}
		e.msgs = append(e.msgs, output.Message{
			Pieces:          e.pieces[e.starts[mi]:end],
			Binary:          m.binary,
			ContentType:     m.ct,
			ContentEncoding: m.ce,
			BodySize:        m.bodySize,
			BodyMatched:     m.bodyMatched,
		})
	}
	b.Messages = e.msgs
	e.cfg.Emit(b)
	// 不让复用的块继续引用交互的缓存。
	clear(e.pieces)
	b.Messages = nil
}

// Stats 返回引擎填写的统计。
func (e *Engine) Stats() Stats { return e.stats }
