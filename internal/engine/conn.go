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

	// held 表示请求解析器正缓存着 Upgrade 请求之后的字节，等 Resume 或 Tunnel。
	// 这时不能直接关闭请求解析器，否则缓存里管道化的请求会被静默丢掉。
	held bool
	// cliFin 表示客户端 FIN 时请求解析器正在缓存，关闭推迟到 Resume 或 Tunnel 之后；
	// cliFinTS 是 FIN 的时间。
	cliFin   bool
	cliFinTS time.Time

	now time.Time // 当前回调所属包的时间。请求的时间不用它，取 req.LastTS()：回放缓存时 now 不是那些字节的时间
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
		if c.held {
			// Upgrade 请求还在等决定：缓存里可能有管道化的请求，关闭推迟到决定之后。
			c.cliFin, c.cliFinTS = true, ts
			return
		}
		c.req.Close(true, ts)
		return
	}
	c.res.Close(true, ts)
	// 等决定的 Upgrade 请求不会再有响应：缓存的请求现在就回放，先照常排队，
	// 下面和它一起以无响应结束，不拖到输入结束。
	c.resumeAllHeld()
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
	c.resumeAllHeld()
	c.req.Close(false, ts)
	c.res.Close(false, ts)
	c.srvClosed = true
	c.closeQueue(why, true)
}

// closeQueue 结束队列里的交互：没收到最终响应的标为无响应，原因是 why。
// all 为假时只结束请求已经发完的。all 为真时调用方已经关闭了请求解析器，
// 没发完的请求都已经以 End(false) 结束并标为不完整。
func (c *conn) closeQueue(why string, all bool) {
	for i := 0; i < len(c.queue); {
		x := c.queue[i]
		if !all && !x.reqDone {
			i++
			continue
		}
		if !x.hasRes {
			x.noResp = why
		}
		c.finish(x)
	}
}

// resumeHeld 把请求解析器缓存的、Upgrade 请求之后的字节按 HTTP 回放，
// 然后补上推迟的客户端 FIN。Upgrade 请求得到普通响应、要关闭连接或超时之前调用。
// 回放出的请求可能又是 Upgrade 请求而重新开始缓存，此时 held 仍为真。
func (c *conn) resumeHeld() {
	c.held = false
	c.req.Resume()
	c.closePendingFin()
}

// resumeAllHeld 在关闭连接前回放请求解析器缓存的全部字节：
// Upgrade 请求再也等不到决定，按被拒处理，缓存的请求照常排队。
func (c *conn) resumeAllHeld() {
	for c.held {
		c.resumeHeld()
	}
}

// closePendingFin 在请求解析器不再缓存时补调推迟的客户端 FIN。
func (c *conn) closePendingFin() {
	if c.cliFin && !c.held {
		c.cliFin = false
		c.req.Close(true, c.cliFinTS)
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
	x.start, x.reqLast = b.TS, b.TS
	x.reqMsg = x.addMessage(dirReq)
	c.queue = append(c.queue, x)
	s.cur = x
}

func (s *reqSink) Raw(sec http1.Section, b []byte) {
	if x := s.cur; x != nil {
		// 回放 Upgrade 请求之后缓存的字节时，LastTS 是这些字节所在缓存段的时间。
		x.reqLast = s.c.req.LastTS()
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
		// 请求解析器在 Upgrade 请求正常结束、还没有决定时开始缓存后面的字节。
		s.c.held = x.upgrade && !x.decided
	} else {
		x.incomplete = true
	}
	x.lineBreak(dirReq)
	switch {
	case x.resDone:
		// 服务端在请求发完之前就回了最终响应，现在请求也发完了。
		s.c.finish(x)
	case s.c.srvClosed:
		// 服务端已经关闭，这个请求不会再有响应。
		if !x.hasRes {
			x.noResp = noRespClosed
		}
		s.c.finish(x)
	}
}

func (s *reqSink) Desync(off int64) {}

// Begin 实现 http1.Sink：响应按顺序归入第一个还没收完最终响应的交互。
// 通常就是队首；队首的请求还没发完、响应却已收完时，它还留在队列里。
func (s *resSink) Begin(b http1.Begin) {
	s.cur = nil
	if b.Orphan {
		return
	}
	var x *exchange
	for _, q := range s.c.queue {
		if !q.resDone {
			x = q
			break
		}
	}
	if x == nil {
		return
	}
	x.hasRes = true
	x.resMsg = x.addMessage(dirRes)
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
		// 对 Upgrade 请求的决定要立即交给请求解析器：同一个段里可能紧跟着
		// 下一个响应，它要配给 Upgrade 请求之后缓存着的请求。两个方向的解析器
		// 互相独立，请求解析器回放时只改动队列和 rq，不碰响应解析器和 rs.cur。
		// 放在 Head 而不是 End：响应没有 body 时两者之间没有别的字节，没有区别；
		// 只有 Upgrade 请求的响应带 body，或者读到关闭为止时，body 期间到达的
		// 请求字节放在 Head 里回放会及时解析，放在 End 里要等响应收完。
		c := s.c
		switch {
		case h.Tunnel:
			// 101 或 CONNECT 的 2xx：此后连接不再按 HTTP 解析，也不再缓存。
			// 响应解析器自己已经停下。
			x.decided = true
			c.held = false
			c.req.Tunnel()
			c.closePendingFin()
		case x.upgrade && !x.msgs[x.resMsg].interim:
			// Upgrade 请求得到普通的最终响应：请求方向继续按 HTTP 解析。
			// 请求还没发完时 Resume 只记下决定，没有可回放的。
			x.decided = true
			c.resumeHeld()
		}
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
	x.lineBreak(dirRes)
	if complete && x.msgs[x.resMsg].interim {
		// 等最终响应；只有 1xx 的交互不算有响应，不输出耗时。
		x.hasRes = false
		return
	}
	x.resDone = true
	if !x.reqDone {
		// 请求还没发完：等它发完再结束，免得丢掉请求剩下的字节。
		return
	}
	s.c.finish(x)
}

func (s *resSink) Desync(off int64) {}
