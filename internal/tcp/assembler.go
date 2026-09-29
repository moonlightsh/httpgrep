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
}

// NewAssembler 创建重组器。open 在新建连接时调用，返回这条连接的 Handler。
func NewAssembler(cfg Config, open func(ConnInfo) Handler) *Assembler {
	return &Assembler{cfg: cfg, open: open, conns: make(map[Key]*conn)}
}

// Add 处理一个 TCP 段。ts 是抓包时间，单调不减。
func (a *Assembler) Add(seg *decode.Segment, ts time.Time) {
	c := a.conns[Key{seg.Src, seg.Dst}]
	if c == nil {
		c = a.create(seg, ts)
		if c == nil {
			return
		}
	}
	c.last = ts
	s := c.side(seg.Src)
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
	peerAck := int64(-1)
	if seg.Flags&decode.ACK != 0 && peer.started {
		peerAck = peer.offset(seg.Ack)
	}
	if len(seg.Payload) == 0 {
		return
	}
	off := d.offset(seg.Seq)
	if off == d.next {
		c.h.Data(s, off, seg.Payload, peerAck, ts)
		d.next += int64(len(seg.Payload))
	}
}

// create 为表里没有的四元组新建连接。不该建连接的段返回 nil。
func (a *Assembler) create(seg *decode.Segment, ts time.Time) *conn {
	info := ConnInfo{Start: ts}
	c := &conn{}
	switch {
	case seg.Flags&(decode.SYN|decode.ACK) == decode.SYN:
		info.Key = Key{seg.Src, seg.Dst}
		info.RolesKnown = true
		c.d[0].start(seg.Seq + 1)
	default:
		return nil
	}
	c.key = info.Key
	c.h = a.open(info)
	a.conns[info.Key] = c
	a.conns[Key{info.Key.B, info.Key.A}] = c
	return c
}

// Advance 处理乱序超时和空闲释放。now 单调不减。
func (a *Assembler) Advance(now time.Time) {}

// Flush 在输入结束时调用：先把每条连接的空洞都认定为缺口，再依次 Closed(CloseEOF)。
func (a *Assembler) Flush(now time.Time) {}

// Release 主动释放连接，回调 Closed(CloseEvicted)。连接不存在时返回 false。
func (a *Assembler) Release(k Key, now time.Time) bool { return false }

// BufferedBytes 返回乱序缓存里的字节数。
func (a *Assembler) BufferedBytes() int64 { return 0 }

// Len 返回当前的连接数。
func (a *Assembler) Len() int { return 0 }

// LeastRecent 返回最久没有收到包的连接。
func (a *Assembler) LeastRecent() (Key, bool) { return Key{}, false }
