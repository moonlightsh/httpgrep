package engine

import (
	"net/netip"
	"time"

	"httpgrep/internal/http1"
	"httpgrep/internal/tcp"
)

// conn 是一条连接：两个方向的解析器，以及按请求顺序排队、还没结束的交互。
// 它实现 tcp.Handler。
type conn struct {
	e *Engine

	// 角色。E1 只处理看到握手的连接（known 为真，client 是 side 0）；
	// 角色未知的半路连接在 known 为假时按内容判定。
	known            bool
	client           tcp.Side
	cliAddr, srvAddr netip.AddrPort

	req, res *http1.Parser // 客户端方向的请求解析器、服务端方向的响应解析器
	rq       reqSink
	rs       resSink

	queue []*exchange // 按请求顺序排队、还没结束的交互；队首是正在等（或正在收）响应的

	srvClosed bool // 服务端方向已结束（FIN），之后的请求不会再有响应

	now time.Time // 当前回调所属包的时间
}

// reqSink 接收请求解析器的事件。cur 为 nil 时丢弃事件。
type reqSink struct {
	c   *conn
	cur *exchange
}

// resSink 接收响应解析器的事件。cur 为 nil 时丢弃事件。
type resSink struct {
	c   *conn
	cur *exchange
}

// newConn 为新连接创建 Handler。
func (e *Engine) newConn(info tcp.ConnInfo) *conn {
	c := &conn{e: e}
	c.rq.c, c.rs.c = c, c
	if info.RolesKnown {
		c.known = true
		c.client = 0
		c.cliAddr, c.srvAddr = info.Key.A, info.Key.B
		c.req = http1.NewParser(http1.Request, &c.rq, http1.Options{})
		c.res = http1.NewParser(http1.Response, &c.rs, http1.Options{Method: c.method})
	}
	return c
}

// method 告诉响应解析器对应请求的方法。
func (c *conn) method() string {
	if x := c.rs.cur; x != nil {
		switch x.method {
		case methodHead:
			return "HEAD"
		case methodConnect:
			return "CONNECT"
		}
	}
	return ""
}

// Data 实现 tcp.Handler。
func (c *conn) Data(side tcp.Side, off int64, b []byte, peerAck int64, ts time.Time) {
	if !c.known {
		return
	}
	c.now = ts
	if side == c.client {
		c.req.Feed(off, b, peerAck, ts)
	} else {
		c.res.Feed(off, b, peerAck, ts)
	}
}

// Gap 实现 tcp.Handler。
func (c *conn) Gap(side tcp.Side, off, n int64, ts time.Time) {
	if !c.known {
		return
	}
	c.now = ts
	if side == c.client {
		c.req.Gap(off, n, ts)
	} else {
		c.res.Gap(off, n, ts)
	}
}

// Fin 实现 tcp.Handler：这个方向的流按序结束。
// 服务端 FIN 时，读到关闭为止的响应算收完。
func (c *conn) Fin(side tcp.Side, ts time.Time) {
	if !c.known {
		return
	}
	c.now = ts
	if side == c.client {
		// 只有客户端 FIN 时照常等服务端，它还可能回响应。
		c.req.Close(true, ts)
		return
	}
	c.res.Close(true, ts)
	c.srvClosed = true
	// 请求已经发完的交互不会再有响应；还在发的，等请求结束时再结束。
	c.closeQueue(noRespClosed, false)
}

// Reset 实现 tcp.Handler：RST 立即结束所有在途交互。
func (c *conn) Reset(ts time.Time) {
	c.close(noRespClosed, ts)
}

// Closed 实现 tcp.Handler：连接已经从连接表移除，结束剩下的在途交互。
func (c *conn) Closed(reason tcp.CloseReason, ts time.Time) {
	why := noRespClosed
	if reason == tcp.CloseEOF {
		why = noRespEOF
	}
	c.close(why, ts)
}

// close 结束两个方向的解析和所有在途交互：没收完的消息标为不完整，
// 没收到响应的标为无响应，原因是 why。
func (c *conn) close(why string, ts time.Time) {
	if !c.known {
		return
	}
	c.now = ts
	c.req.Close(false, ts)
	c.res.Close(false, ts)
	c.srvClosed = true
	c.closeQueue(why, true)
}

// closeQueue 以无响应结束队列里的交互。all 为假时只结束请求已经发完的。
func (c *conn) closeQueue(why string, all bool) {
	for i := 0; i < len(c.queue); {
		x := c.queue[i]
		if !all && !x.reqDone {
			i++
			continue
		}
		x.noResp = why
		c.finish(x)
	}
}

// finish 结束交互 x：移出队列，命中的输出，然后回收。
func (c *conn) finish(x *exchange) {
	for i, q := range c.queue {
		if q == x {
			copy(c.queue[i:], c.queue[i+1:])
			c.queue[len(c.queue)-1] = nil
			c.queue = c.queue[:len(c.queue)-1]
			break
		}
	}
	if c.rq.cur == x {
		c.rq.cur = nil
	}
	if c.rs.cur == x {
		c.rs.cur = nil
	}
	c.e.finish(c, x)
}

// Begin 实现 http1.Sink：开始一个新的交互，排到队尾。
func (s *reqSink) Begin(b http1.Begin) {
	if b.Orphan {
		s.cur = nil
		return
	}
	c := s.c
	x := c.e.newExchange()
	x.hasReq = true
	x.start = b.TS
	x.reqMsg = x.addMessage()
	c.queue = append(c.queue, x)
	s.cur = x
}

func (s *reqSink) Raw(sec http1.Section, b []byte) {
	if x := s.cur; x != nil {
		x.reqLast = s.c.now
		x.raw(x.reqMsg, sec, b)
	}
}

func (s *reqSink) Head(h *http1.Head) {
	x := s.cur
	if x == nil {
		return
	}
	x.head(x.reqMsg, h)
	switch h.Method {
	case "HEAD":
		x.method = methodHead
	case "CONNECT":
		x.method = methodConnect
	}
	x.upgrade = h.Upgrade
}

func (s *reqSink) Body(b []byte) {
	if x := s.cur; x != nil {
		x.body(x.reqMsg, b)
	}
}

func (s *reqSink) Gap(sec http1.Section, n int64) {}

func (s *reqSink) End(complete bool, ts time.Time) {
	x := s.cur
	if x == nil {
		return
	}
	s.cur = nil
	x.reqDone = true
	if complete {
		x.reqLast = ts
	} else {
		x.incomplete = true
	}
	x.lineBreak()
	if s.c.srvClosed {
		// 服务端已经关闭，这个请求不会再有响应。
		x.noResp = noRespClosed
		s.c.finish(x)
	}
}

func (s *reqSink) Desync(off int64) {}

// Begin 实现 http1.Sink：响应按顺序归入队首的交互。
func (s *resSink) Begin(b http1.Begin) {
	c := s.c
	if b.Orphan || len(c.queue) == 0 {
		s.cur = nil
		return
	}
	x := c.queue[0]
	x.hasRes = true
	x.resMsg = x.addMessage()
	s.cur = x
}

func (s *resSink) Raw(sec http1.Section, b []byte) {
	if x := s.cur; x != nil {
		x.resLast = s.c.now
		x.raw(x.resMsg, sec, b)
	}
}

func (s *resSink) Head(h *http1.Head) {
	if x := s.cur; x != nil {
		x.head(x.resMsg, h)
		// 1xx 中间响应（101 除外）归入所属交互，之后还有最终响应。
		x.msgs[x.resMsg].interim = h.Status >= 100 && h.Status < 200 && h.Status != 101
	}
}

func (s *resSink) Body(b []byte) {
	if x := s.cur; x != nil {
		x.body(x.resMsg, b)
	}
}

func (s *resSink) Gap(sec http1.Section, n int64) {}

func (s *resSink) End(complete bool, ts time.Time) {
	x := s.cur
	if x == nil {
		return
	}
	s.cur = nil
	if complete {
		x.resLast = ts
	} else {
		// 没收完的响应，耗时算到最后一次收到响应数据。
		x.incomplete = true
	}
	x.lineBreak()
	if complete && x.msgs[x.resMsg].interim {
		return // 等最终响应
	}
	s.c.finish(x)
}

func (s *resSink) Desync(off int64) {}
