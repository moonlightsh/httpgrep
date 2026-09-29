package engine

import (
	"strconv"
	"time"
)

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

// 回收的交互不计入内存计量，所以限量：最多留 maxFree 个；它们留着的内存
// （缓存、片段的容量和扫描器的行缓存，见 exchange.retained）之和不超过 MaxMemory 的
// 1/freeBufShare（MaxMemory 不大于 0 表示不限）。单个交互超过 maxKeepBuf 的缓存或
// 扫描器不留；放不进份额的交互只留对象，其余交给 GC。
// 峰值过后，多出来的交互、缓存和扫描器不会一直留着。
const (
	maxFree      = 256
	freeBufShare = 16
)

// recycle 回收已经结束、不再被连接引用的交互 x。
func (e *Engine) recycle(x *exchange) {
	if len(e.free) >= maxFree {
		return
	}
	x.shed(false)
	n := x.retained()
	if e.cfg.MaxMemory > 0 && e.freeBuf+n > e.cfg.MaxMemory/freeBufShare {
		x.shed(true)
		n = 0
	}
	x.keep = n
	e.freeBuf += n
	e.free = append(e.free, x)
}

// enforce 在超过内存上限时丢弃在途交互，从开始时间最早的起，直到不超限；
// 在途交互都丢完了仍然超限，就释放最久没有收到包的连接。
// 在 Assembler 的回调之外调用（回调里不能调用 Release），所以计量最多超出上限一个包的量。
// 之后如果有没报告过的丢弃，并且距上一次告警已满 10 秒（抓包时钟），调用 Warn。
// 只释放连接、没有丢弃交互时不告警：告警说的是丢了多少交互。
func (e *Engine) enforce(now time.Time) {
	limit := e.cfg.MaxMemory
	if limit > 0 && e.Memory() > limit {
		e.shrink(limit, now)
	}
	if e.dropped > 0 && (!e.warned || !now.Before(e.warnedAt.Add(warnInterval))) {
		e.warn(now)
	}
}

// warnInterval 是内存告警的最小间隔，按抓包时钟。
const warnInterval = 10 * time.Second

// warn 报告距上一次告警以来丢弃的交互数，然后清零。
func (e *Engine) warn(now time.Time) {
	if e.cfg.Warn != nil {
		msg := "dropped " + strconv.FormatInt(e.dropped, 10) + " in-flight exchanges (" +
			strconv.FormatInt(e.droppedMatched, 10) + " matched) to stay under --max-memory"
		e.cfg.Warn(msg)
	}
	e.dropped, e.droppedMatched = 0, 0
	e.warnedAt, e.warned = now, true
}

// shrink 把计量降到 limit 以内，见 enforce。
func (e *Engine) shrink(limit int64, now time.Time) {
	for e.oldest != nil && e.Memory() > limit {
		x := e.oldest
		x.c.evict(x, now)
	}
	for e.Memory() > limit {
		k, ok := e.asm.LeastRecent()
		if !ok {
			return
		}
		// Closed(CloseEvicted) 结束这条连接：队列里只剩占位（在途交互上面已经丢完），
		// 回收即可。关闭前回放的 Upgrade 缓存可能又产生交互，它们随即以无响应结束。
		e.asm.Release(k, now)
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
	e.dropped++
	if x.matched() {
		e.stats.EvictedMatched++
		e.droppedMatched++
	}
	e.inFlight--
	e.buffered -= int64(len(x.buf))
	x.evicted = true
	x.bury()
	// 排在它后面的请求轮到队首，从现在起计时。
	c.rearm(now)
}
