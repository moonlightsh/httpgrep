package tcp

import (
	"net/netip"
	"time"
)

// dir 是连接一个方向的重组状态。
type dir struct {
	started bool   // 已知这个方向的起始序号
	base    uint32 // 偏移 0 对应的序号
	next    int64  // 下一个期望交付的偏移
	buf     []chunk
	bufLen  int64     // buf 的计量：负载字节加每段的固定开销，见 chunk.cost
	arr     *arrivals // 缓存段按到达先后的记录，第一次缓存时才分配，见 oldest

	finSeen bool
	finDone bool      // 已回调 Fin
	finOff  int64     // FIN 的偏移，即这个方向流的长度
	finTs   time.Time // FIN 到达的时间
}

// limit 把要跳到的偏移限制在 FIN 之前。
func (d *dir) limit(off int64) int64 {
	if d.finSeen {
		return min(off, d.finOff)
	}
	return off
}

// start 以 seq 作为偏移 0 的序号。
func (d *dir) start(seq uint32) {
	d.started = true
	d.base = seq
	d.next = 0
}

// offset 把序号换算成流偏移。以 next 为参照展开 32 位回绕，
// 所以只要序号离 next 不超过 2³¹，跨过 2³² 仍然连续。
func (d *dir) offset(seq uint32) int64 {
	return d.next + int64(int32(seq-d.base-uint32(d.next)))
}

// conn 是连接表里的一条连接。
type conn struct {
	key  Key
	h    Handler
	d    [2]dir
	last time.Time // 最后一个包的时间

	synSeen bool   // 看到过 side 0 发的 SYN
	isn     uint32 // 这个 SYN 的序号

	// 按最后一个包的时间排成双向链表，older 一侧是更早的连接。
	older, newer *conn
}

// side 返回从 src 发出的段属于哪个方向。
func (c *conn) side(src netip.AddrPort) Side {
	if src == c.key.A {
		return 0
	}
	return 1
}

// lru 是按最后一个包的时间排序的连接链表，oldest 最早。
type lru struct {
	oldest, newest *conn
}

// pushNewest 把 c 放到链表末尾。c 不能已经在链表里。
func (l *lru) pushNewest(c *conn) {
	c.older, c.newer = l.newest, nil
	if l.newest != nil {
		l.newest.newer = c
	} else {
		l.oldest = c
	}
	l.newest = c
}

// remove 把 c 从链表里摘掉。
func (l *lru) remove(c *conn) {
	if c.older != nil {
		c.older.newer = c.newer
	} else {
		l.oldest = c.newer
	}
	if c.newer != nil {
		c.newer.older = c.older
	} else {
		l.newest = c.older
	}
	c.older, c.newer = nil, nil
}

// touch 把 c 移到链表末尾。
func (l *lru) touch(c *conn) {
	if l.newest == c {
		return
	}
	l.remove(c)
	l.pushNewest(c)
}
