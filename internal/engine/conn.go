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

// Fin 实现 tcp.Handler。
func (c *conn) Fin(side tcp.Side, ts time.Time) {}

// Reset 实现 tcp.Handler。
func (c *conn) Reset(ts time.Time) {}

// Closed 实现 tcp.Handler。
func (c *conn) Closed(reason tcp.CloseReason, ts time.Time) {}

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
	x.reqDone, x.reqLast = true, ts
	if !complete {
		x.incomplete = true
	}
	x.lineBreak()
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
	x.resLast = ts
	if !complete {
		x.incomplete = true
	}
	x.lineBreak()
	s.c.finish(x)
}

func (s *resSink) Desync(off int64) {}
