package engine

import "time"

// 计入内存上限的固定开销。
const (
	connOverhead     = 1024 // 每条连接
	exchangeOverhead = 512  // 每个在途交互
)

// Memory 返回当前的内存计量值：在途交互缓存的消息字节、乱序缓存、
// 每条连接和每个在途交互的固定开销。内存上限按它判断。
func (e *Engine) Memory() int64 {
	return e.buffered + e.asm.BufferedBytes() +
		int64(e.asm.Len())*connOverhead + int64(e.inFlight)*exchangeOverhead
}

// enforce 在超过内存上限时丢弃在途交互，从开始时间最早的起，直到不超限；
// 在途交互都丢完了仍然超限，就释放最久没有收到包的连接。
// 在 Assembler 的回调之外调用（回调里不能调用 Release），所以计量最多超出上限一个包的量。
func (e *Engine) enforce(now time.Time) {
	limit := e.cfg.MaxMemory
	if limit <= 0 || e.Memory() <= limit {
		return
	}
	for e.oldest != nil && e.Memory() > limit {
		x := e.oldest
		x.c.evict(x, now)
	}
}

// track 把刚开始的交互 x 按开始时间插入在途链表。交互大体按开始时间先后创建，
// 从尾部往前找插入位置，通常一步就到。开始时间相同的排在后面。
func (e *Engine) track(x *exchange) {
	p := e.newest
	for p != nil && p.start.After(x.start) {
		p = p.prev
	}
	x.prev = p
	if p == nil {
		x.next = e.oldest
		e.oldest = x
	} else {
		x.next = p.next
		p.next = x
	}
	if x.next == nil {
		e.newest = x
	} else {
		x.next.prev = x
	}
	x.tracked = true
}

// untrack 把 x 移出在途链表。x 不在链表里时什么都不做。
func (e *Engine) untrack(x *exchange) {
	if !x.tracked {
		return
	}
	if x.prev == nil {
		e.oldest = x.next
	} else {
		x.prev.next = x.next
	}
	if x.next == nil {
		e.newest = x.prev
	} else {
		x.next.prev = x.prev
	}
	x.prev, x.next, x.tracked = nil, nil, false
}

// evict 因内存上限丢弃在途交互 x：即使已经命中也不输出，只计数。
// 它像超时的交互一样留在原位置当占位，之后的数据只解析长度、不缓存。
func (c *conn) evict(x *exchange, now time.Time) {
	e := c.e
	c.now = now
	e.timers.remove(x)
	e.untrack(x)
	e.stats.Evicted++
	if x.matched() {
		e.stats.EvictedMatched++
	}
	e.inFlight--
	e.buffered -= int64(len(x.buf))
	x.evicted = true
	x.bury()
	// 排在它后面的请求轮到队首，从现在起计时。
	c.rearm(now)
}
