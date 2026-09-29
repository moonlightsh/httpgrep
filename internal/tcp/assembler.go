package tcp

import (
	"time"

	"httpgrep/internal/decode"
)

// Assembler 维护连接表并做 TCP 重组。不是并发安全的。
type Assembler struct {
	cfg   Config
	open  func(ConnInfo) Handler
	conns map[Key]*conn // 两个方向的四元组都指向同一条连接
	lru   lru

	buffered int64 // 所有连接乱序缓存的字节数

	scanned time.Time // 上次扫描全部连接的时间
}

// scanInterval 是 Advance 扫描全部连接的最小间隔（抓包时间）。
const scanInterval = 100 * time.Millisecond

// NewAssembler 创建重组器。open 在新建连接时调用，返回这条连接的 Handler。
func NewAssembler(cfg Config, open func(ConnInfo) Handler) *Assembler {
	return &Assembler{cfg: cfg, open: open, conns: make(map[Key]*conn)}
}

// Add 处理一个 TCP 段。ts 是抓包时间，单调不减。
func (a *Assembler) Add(seg *decode.Segment, ts time.Time) {
	c := a.conns[Key{seg.Src, seg.Dst}]
	if c != nil && seg.Flags&(decode.SYN|decode.ACK) == decode.SYN {
		if c.synSeen && seg.Src == c.key.A && seg.Seq == c.isn {
			// SYN 重传。
			c.last = ts
			a.lru.touch(c)
			return
		}
		// 同一四元组上的新连接。
		a.flushHoles(c, ts)
		a.close(c, CloseReplaced, ts)
		c = nil
	}
	if c == nil {
		c = a.create(seg, ts)
		if c == nil {
			return
		}
	}
	c.last = ts
	a.lru.touch(c)
	if seg.Flags&decode.RST != 0 {
		// RST 立即生效，不检查序号是否在窗口内。
		a.flushHoles(c, ts)
		c.h.Reset(ts)
		a.close(c, CloseReset, ts)
		return
	}
	a.segment(c, c.side(seg.Src), seg, ts)
	a.settle(c, ts)
}

// segment 把一个段应用到连接的 side 方向。
func (a *Assembler) segment(c *conn, s Side, seg *decode.Segment, ts time.Time) {
	d, peer := &c.d[s], &c.d[1-s]
	if seg.Flags&decode.SYN != 0 {
		if s == 1 && !d.started {
			d.start(seg.Seq + 1)
		}
		return
	}
	if !d.started {
		d.start(seg.Seq)
	}
	hasAck := seg.Flags&decode.ACK != 0
	peerAck := peerAckOf(peer, seg.Ack, hasAck)
	if peerAck > peer.next {
		// 对端的数据已经送达，只是没抓到。
		a.skipTo(c, 1-s, peerAck, ts)
	}
	off := d.offset(seg.Seq)
	if seg.Flags&decode.FIN != 0 && !d.finSeen {
		d.finSeen = true
		d.finOff = off + int64(len(seg.Payload)) + int64(max(seg.Missing, 0))
		d.finTs = ts
	}
	if len(seg.Payload) == 0 && seg.Missing <= 0 {
		return
	}
	if off > d.next {
		a.buffer(d, off, seg.Payload, int64(max(seg.Missing, 0)), seg.Ack, hasAck, ts)
		a.limitReorder(c, s, ts)
		return
	}
	a.deliver(c, s, off, seg.Payload, peerAck, ts)
	if seg.Missing > 0 {
		// 截断的字节紧跟在负载之后，按缺口交付。
		a.skipTo(c, s, off+int64(len(seg.Payload))+int64(seg.Missing), ts)
	}
}

// settle 回调已经生效的 FIN；两个方向都结束后关闭连接。
func (a *Assembler) settle(c *conn, ts time.Time) {
	if a.fins(c, ts) {
		a.close(c, CloseFin, ts)
	}
}

// fins 回调已经生效、还没回调过的 FIN。两个方向都已结束时返回 true。
func (a *Assembler) fins(c *conn, ts time.Time) bool {
	for s := range Side(2) {
		d := &c.d[s]
		if d.finSeen && !d.finDone && d.next >= d.finOff {
			d.finDone = true
			c.h.Fin(s, ts)
		}
	}
	return c.d[0].finDone && c.d[1].finDone
}

// close 把连接移出连接表，再回调 Closed。
func (a *Assembler) close(c *conn, reason CloseReason, ts time.Time) {
	delete(a.conns, c.key)
	delete(a.conns, Key{c.key.B, c.key.A})
	a.lru.remove(c)
	for s := range c.d {
		a.buffered -= c.d[s].bufLen
		c.d[s].buf, c.d[s].bufLen = nil, 0
	}
	c.h.Closed(reason, ts)
}

// deliver 交付从 off 开始、off <= next 的负载，已交付的前缀跳过。
// 负载和缓存重叠的部分以缓存（先到的）为准；负载直接切片交付，不拷贝。
func (a *Assembler) deliver(c *conn, s Side, off int64, b []byte, peerAck int64, ts time.Time) {
	d := &c.d[s]
	end := off + int64(len(b))
	for d.next < end {
		stop := end
		if len(d.buf) > 0 && d.buf[0].off < stop {
			stop = max(d.buf[0].off, d.next)
		}
		if stop > d.next {
			c.h.Data(s, d.next, b[d.next-off:stop-off], peerAck, ts)
			d.next = stop
		}
		a.drain(c, s, ts)
	}
}

// create 为表里没有的四元组新建连接。不该建连接的段返回 nil。
func (a *Assembler) create(seg *decode.Segment, ts time.Time) *conn {
	info := ConnInfo{Start: ts}
	c := &conn{}
	switch {
	case seg.Flags&decode.RST != 0:
		// RST 即使带负载也不建连接，建了也会立即释放。
		return nil
	case seg.Flags&(decode.SYN|decode.ACK) == decode.SYN:
		info.Key = Key{seg.Src, seg.Dst}
		info.RolesKnown = true
		c.synSeen, c.isn = true, seg.Seq
		c.d[0].start(seg.Seq + 1)
	case seg.Flags&(decode.SYN|decode.ACK) == decode.SYN|decode.ACK:
		// 没看到 SYN：SYN-ACK 的目的方是客户端。
		info.Key = Key{seg.Dst, seg.Src}
		info.RolesKnown = true
		c.d[0].start(seg.Ack)
		c.d[1].start(seg.Seq + 1)
	case len(seg.Payload) > 0 || seg.Missing > 0:
		// 开始抓包前已建立的连接：源地址当作 side 0，另一方向的起点取 Ack。
		info.Key = Key{seg.Src, seg.Dst}
		c.d[0].start(seg.Seq)
		if seg.Flags&decode.ACK != 0 {
			c.d[1].start(seg.Ack)
		}
	default:
		return nil
	}
	c.key = info.Key
	c.h = a.open(info)
	a.conns[info.Key] = c
	a.conns[Key{info.Key.B, info.Key.A}] = c
	a.lru.pushNewest(c)
	return c
}

// Advance 处理乱序超时和空闲释放。now 单调不减。
func (a *Assembler) Advance(now time.Time) {
	if !a.scanned.IsZero() && now.Sub(a.scanned) < scanInterval {
		return
	}
	a.scanned = now
	for c := a.lru.oldest; c != nil; {
		next := c.newer // 回调里可能关闭 c
		if now.Sub(c.last) >= a.cfg.IdleTimeout {
			a.flushHoles(c, now)
			a.close(c, CloseIdle, now)
			c = next
			continue
		}
		a.expireReorder(c, 0, now)
		a.expireReorder(c, 1, now)
		a.settle(c, now)
		c = next
	}
}

// Flush 在输入结束时调用：先把每条连接的空洞都认定为缺口，再依次 Closed(CloseEOF)。
func (a *Assembler) Flush(now time.Time) {
	for a.lru.oldest != nil {
		c := a.lru.oldest
		a.flushHoles(c, now)
		a.close(c, CloseEOF, now)
	}
}

// Release 主动释放连接（内存超限时用），回调 Closed(CloseEvicted)。连接不存在时返回 false。
// k 的两个方向都可以。乱序缓存直接丢弃，不再交付。
func (a *Assembler) Release(k Key, now time.Time) bool {
	c := a.conns[k]
	if c == nil {
		return false
	}
	a.close(c, CloseEvicted, now)
	return true
}

// BufferedBytes 返回乱序缓存里的字节数。
func (a *Assembler) BufferedBytes() int64 { return 0 }

// Len 返回当前的连接数。
func (a *Assembler) Len() int { return len(a.conns) / 2 }

// LeastRecent 返回最久没有收到包的连接。
func (a *Assembler) LeastRecent() (Key, bool) {
	if a.lru.oldest == nil {
		return Key{}, false
	}
	return a.lru.oldest.key, true
}
