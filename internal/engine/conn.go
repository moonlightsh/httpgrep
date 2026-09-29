package engine

import (
	"bytes"
	"net/netip"
	"time"

	"httpgrep/internal/http1"
	"httpgrep/internal/tcp"
)

// conn 是一条连接：两个方向的解析器，以及按请求顺序排队、还没结束的交互。
// 它实现 tcp.Handler。
type conn struct {
	e *Engine

	// 角色。看到握手的连接一开始就知道（client 是 side 0）；没看到握手的半路连接
	// 在 known 为假时按内容判定，见 probe。
	known            bool
	client           tcp.Side
	cliAddr, srvAddr netip.AddrPort
	key              tcp.Key

	// probes 只在角色未知时使用：每个方向各有一个请求解析器和一个响应解析器，
	// 下标是 [side][http1.Request 或 http1.Response]。
	probes *[2][2]probe
	// orphanOff 是角色未知时每个解析器最近一条 Orphan 消息的起始偏移，下标同 probes，-1 表示没有。
	// 同一方向的两个解析器都在同一偏移开始 Orphan 消息，这些字节才确实不属于任何消息，只计一次；
	// 只有一个解析器认为是 Orphan 的（比如请求解析器看到状态行）不计。
	orphanOff [2][2]int64
	// finSide 记下角色未知时已经按序结束的方向，定角色时据此设置 srvClosed。
	finSide [2]bool

	req, res *http1.Parser // 客户端方向的请求解析器、服务端方向的响应解析器
	rq       reqSink
	rs       resSink

	queue []*exchange // 按请求顺序排队、还没结束的交互；队首是正在等（或正在收）响应的
	// noReq 是收完 1xx、还在等最终响应的缺请求交互。它不在队列里，最终响应先归它。
	noReq *exchange

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

// probe 是角色未知时挂在一个方向上的一个解析器和它的 Sink。
// 定角色之前只看 Begin：Orphan 消息计数后丢弃，第一个非 Orphan 的 Begin 决定角色。
// 定角色之后，留下的解析器的事件原样转给 rq 或 rs，丢弃的解析器的事件忽略。
type probe struct {
	c    *conn
	side tcp.Side
	kind http1.Kind
	p    *http1.Parser
}

// newConn 为新连接创建 Handler。
func (e *Engine) newConn(info tcp.ConnInfo) *conn {
	c := &conn{e: e, key: info.Key}
	c.rq.c, c.rs.c = c, c
	if info.RolesKnown {
		c.known = true
		c.client = 0
		c.cliAddr, c.srvAddr = info.Key.A, info.Key.B
		c.req = http1.NewParser(http1.Request, &c.rq, http1.Options{})
		c.res = http1.NewParser(http1.Response, &c.rs, http1.Options{Method: c.method})
		return c
	}
	c.probes = new([2][2]probe)
	c.orphanOff = [2][2]int64{{-1, -1}, {-1, -1}}
	for side := range c.probes {
		for kind := range c.probes[side] {
			pr := &c.probes[side][kind]
			pr.c, pr.side, pr.kind = c, tcp.Side(side), http1.Kind(kind)
			opt := http1.Options{Resync: true}
			if pr.kind == http1.Response {
				opt.Method = c.method
			}
			pr.p = http1.NewParser(pr.kind, pr, opt)
		}
	}
	return c
}

// decide 按 pr 产生的第一个非 Orphan 的 Begin 确定角色：发请求行的一方是客户端，
// 发状态行的一方是服务端。留下两个方向上对应的解析器，丢弃另外两个。
func (c *conn) decide(pr *probe) {
	c.client = pr.side
	if pr.kind == http1.Response {
		c.client = 1 - pr.side
	}
	srv := 1 - c.client
	c.req = c.probes[c.client][http1.Request].p
	c.res = c.probes[srv][http1.Response].p
	c.cliAddr, c.srvAddr = c.key.A, c.key.B
	if c.client == 1 {
		c.cliAddr, c.srvAddr = c.key.B, c.key.A
	}
	c.srvClosed = c.finSide[srv]
	c.known = true
}

// chosen 报告 pr 是否是定角色后留下的解析器。
func (pr *probe) chosen() bool {
	c := pr.c
	return c.known && (pr.p == c.req || pr.p == c.res)
}

// Begin 实现 http1.Sink。
func (pr *probe) Begin(b http1.Begin) {
	c := pr.c
	if !c.known {
		if b.Orphan {
			c.orphanOff[pr.side][pr.kind] = b.Off
			if c.orphanOff[pr.side][1-pr.kind] == b.Off {
				c.e.stats.Orphans++
			}
			return
		}
		c.decide(pr)
	}
	if !pr.chosen() {
		return
	}
	if pr.kind == http1.Request {
		c.rq.Begin(b)
	} else {
		c.rs.Begin(b)
	}
}

// sink 返回定角色后 pr 的事件要转给的 Sink；定角色之前或 pr 被丢弃时返回 nil。
// 定角色之前的消息都是 Orphan，它们的事件丢弃。
func (pr *probe) sink() http1.Sink {
	if !pr.chosen() {
		return nil
	}
	if pr.kind == http1.Request {
		return &pr.c.rq
	}
	return &pr.c.rs
}

func (pr *probe) Raw(sec http1.Section, b []byte) {
	if s := pr.sink(); s != nil {
		s.Raw(sec, b)
	}
}

func (pr *probe) Head(h *http1.Head) {
	if s := pr.sink(); s != nil {
		s.Head(h)
	}
}

func (pr *probe) Body(b []byte) {
	if s := pr.sink(); s != nil {
		s.Body(b)
	}
}

func (pr *probe) Gap(sec http1.Section, n int64) {
	if s := pr.sink(); s != nil {
		s.Gap(sec, n)
	}
}

func (pr *probe) End(complete bool, ts time.Time) {
	if s := pr.sink(); s != nil {
		s.End(complete, ts)
	}
}

// Desync 实现 http1.Sink。定角色之前两个解析器都从失步状态开始，不算失步。
func (pr *probe) Desync(off int64) {
	if s := pr.sink(); s != nil {
		s.Desync(off)
	}
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
	c.now = ts
	if !c.known {
		c.probeFeed(side, off, b, peerAck, ts)
		return
	}
	if side == c.client {
		c.req.Feed(off, b, peerAck, ts)
	} else {
		c.res.Feed(off, b, peerAck, ts)
	}
}

// probeFeed 在角色未知时把字节喂给这个方向的两个解析器。
// 角色要按字节流里先出现的起始行判定，所以按行交替喂入：每一行先喂请求解析器，
// 再喂响应解析器。起始行的 Begin 只在收到这一行的 '\n' 时产生，一行之内不会有两个解析器
// 先后定角色。定了角色之后，剩下的字节整段交给这个方向上留下的解析器：
// 它就是刚刚定角色的那个解析器（喂过这一行），或者两个解析器都喂过这一行。
func (c *conn) probeFeed(side tcp.Side, off int64, b []byte, peerAck int64, ts time.Time) {
	ps := &c.probes[side]
	for len(b) > 0 && !c.known {
		n := len(b)
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			n = i + 1
		}
		ps[http1.Request].p.Feed(off, b[:n], peerAck, ts)
		if !c.known {
			ps[http1.Response].p.Feed(off, b[:n], peerAck, ts)
		}
		off += int64(n)
		b = b[n:]
	}
	if !c.known {
		return
	}
	c.probes = nil
	if len(b) == 0 {
		return
	}
	if side == c.client {
		c.req.Feed(off, b, peerAck, ts)
	} else {
		c.res.Feed(off, b, peerAck, ts)
	}
}

// Gap 实现 tcp.Handler。
func (c *conn) Gap(side tcp.Side, off, n int64, ts time.Time) {
	c.e.stats.Gaps++
	c.e.stats.GapBytes += n
	c.now = ts
	if !c.known {
		// 定角色之前的消息都是 Orphan，缺口不会让某个解析器产生非 Orphan 的 Begin。
		c.probes[side][http1.Request].p.Gap(off, n, ts)
		c.probes[side][http1.Response].p.Gap(off, n, ts)
		return
	}
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
		// 定角色之前，这个方向的两个解析器都只有 Orphan 消息，结束它们不产生交互。
		c.finSide[side] = true
		c.probes[side][http1.Request].p.Close(true, ts)
		c.probes[side][http1.Response].p.Close(true, ts)
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
	if x := c.noReq; x != nil {
		// 只收到 1xx 的缺请求交互不会再有最终响应。
		c.noReq = nil
		x.noResp = why
		c.finish(x)
	}
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
	if c.noReq == x {
		c.noReq = nil
	}
	c.e.finish(c, x)
}

// Begin 实现 http1.Sink：开始一个新的交互，排到队尾。
// 客户端方向的 Orphan 消息（连请求行都没抓到）丢弃，只计数。
func (s *reqSink) Begin(b http1.Begin) {
	if b.Orphan {
		s.c.e.stats.Orphans++
		s.cur = nil
		return
	}
	c := s.c
	x := c.e.newExchange()
	x.hasReq = true
	x.start, x.reqLast = b.TS, b.TS
	x.reqOff = b.Off
	x.reqMsg = x.addMessage(dirReq)
	c.queue = append(c.queue, x)
	s.cur = x
}

func (s *reqSink) Raw(sec http1.Section, b []byte) {
	if x := s.cur; x != nil {
		// 回放 Upgrade 请求之后缓存的字节时，LastTS 是这些字节所在缓存段的时间。
		x.reqLast = s.c.req.LastTS()
		x.raw(x.reqMsg, sec, b)
		s.c.e.addBuffered(len(b))
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

func (s *reqSink) Gap(sec http1.Section, n int64) {
	if x := s.cur; x != nil {
		x.gap(x.reqMsg, sec, n)
	}
}

func (s *reqSink) End(complete bool, ts time.Time) {
	x := s.cur
	if x == nil {
		return
	}
	s.cur = nil
	x.reqDone = true
	if complete {
		x.reqLast = ts
		if x.upgrade && !x.decided {
			if s.c.srvClosed {
				// 服务端已经关闭，决定不会再来：现在就按被拒处理。解析器还没结束这条消息，
				// Resume 只记下决定，随后直接继续解析，不缓存后面的字节。
				x.decided = true
				s.c.req.Resume()
			} else {
				// 请求解析器在 Upgrade 请求正常结束、还没有决定时开始缓存后面的字节。
				s.c.held = true
			}
		}
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

func (s *reqSink) Desync(off int64) { s.c.e.stats.Desyncs++ }

// Begin 实现 http1.Sink：响应按顺序归入第一个还没收完最终响应的交互。
// 通常就是队首；队首的请求还没发完、响应却已收完时，它还留在队列里。
// 失步后没有正在解析的响应时，Orphan 消息（缺口和 Unparsed 字节）同样归入这个交互的响应，
// 交互标为不完整，重新对齐时结束。
//
// ACK 校验：响应第一个字节所在包的 PeerAck 不大于请求的起始偏移，说明服务端当时还没收到
// 这个请求，响应不属于它。这样的响应，以及没有请求可配的响应，作为缺请求的交互单独结束，
// 不进队列；Orphan 消息没有状态行，不成交互，直接丢弃。PeerAck 为 -1（不知道）时不校验。
func (s *resSink) Begin(b http1.Begin) {
	s.cur = nil
	c := s.c
	x := s.target(b.PeerAck)
	if x == nil {
		if b.Orphan {
			c.e.stats.Orphans++
			return
		}
		x = c.e.newExchange()
		x.noReq, x.reqDone = true, true
		x.start = b.TS
	}
	s.open(x, b.Orphan)
}

// target 找响应要归入的交互：先是收完 1xx、在等最终响应的缺请求交互，
// 再是第一个还没收完最终响应的交互（要通过 ACK 校验）。都没有时返回 nil。
func (s *resSink) target(peerAck int64) *exchange {
	c := s.c
	if x := c.noReq; x != nil {
		c.noReq = nil
		return x
	}
	for _, q := range c.queue {
		if !q.resDone {
			if peerAck >= 0 && peerAck <= q.reqOff {
				return nil
			}
			return q
		}
	}
	return nil
}

// open 在交互 x 上开始一条响应消息。orphan 表示它是失步后没有状态行的字节。
func (s *resSink) open(x *exchange, orphan bool) {
	x.hasRes = true
	x.resOrphan = orphan
	if orphan {
		x.incomplete = true
	}
	x.resMsg = x.addMessage(dirRes)
	s.cur = x
}

func (s *resSink) Raw(sec http1.Section, b []byte) {
	if x := s.cur; x != nil {
		x.resLast = s.c.now
		x.raw(x.resMsg, sec, b)
		s.c.e.addBuffered(len(b))
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
			// 推迟的客户端 FIN 不用再补：Tunnel 之后请求解析器已经停下，Close 不会产生事件。
			c.cliFin = false
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

// Gap 实现 http1.Sink。cur 为 nil 时解析器里还开着一条被丢弃的 Orphan 消息
// （ACK 校验不通过、没有交互可归，或者是半路连接定角色之前的残余字节），解析器不会为
// 这个缺口再 Begin。缺口里可能正是队首请求的响应，按 Orphan 的规则（缺口没有 PeerAck，
// 不做 ACK 校验）归入它，此后的 Unparsed 字节也记在这条消息上，重新对齐时由 End(false) 结束。
func (s *resSink) Gap(sec http1.Section, n int64) {
	x := s.cur
	if x == nil {
		if x = s.target(-1); x == nil {
			return
		}
		s.open(x, true)
	}
	x.gap(x.resMsg, sec, n)
}

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
		if x.noReq {
			s.c.noReq = x
		}
		return
	}
	x.resDone = true
	if !x.reqDone {
		// 请求还没发完：等它发完再结束，免得丢掉请求剩下的字节。
		return
	}
	s.c.finish(x)
}

func (s *resSink) Desync(off int64) { s.c.e.stats.Desyncs++ }
