package engine

import "time"

// 计入内存上限的固定开销，按 64 位下实测的堆占用标定（留了余量）。
const (
	// connOverhead 是每条连接：engine.conn、tcp.conn、连接表里两个方向的条目和两个解析器。
	// 实测约 1.55 KiB；连接不断新建、释放（比如 SYN 洪水）时连接表只增不缩，约 2 KiB。
	connOverhead = 2048
	// probeOverhead 是半路连接定角色之前多出来的：另外两个解析器和 probe 数组，实测约 0.9 KiB。
	probeOverhead = 1024
	// exchangeOverhead 是每个在途交互：交互对象、四个扫描器，以及前 freeMessages 条消息和
	// 前 freePieces 个片段，实测约 1 KiB。
	exchangeOverhead = 1024
	// 超出的消息（比如一连串 1xx）和片段（比如数据和缺口交替）每个另计。
	freeMessages    = 2
	freePieces      = 4
	messageOverhead = 128
	pieceOverhead   = 64
	// ghostOverhead 是每个占位的固定开销：占位只剩交互对象（64 位下 352 字节）和队列里的
	// 一个指针，缓存和扫描器都已释放（见 exchange.bury）。
	ghostOverhead = 384
)

// Memory 返回当前的内存计量值：在途交互缓存的消息字节和超出的消息、片段，乱序缓存
// （含每段的固定开销），解析器内部的缓存（没收完的行、Upgrade 请求之后缓存的字节），
// 每条连接、每个定角色之前的半路连接、每个在途交互和每个占位的固定开销。内存上限按它判断。
//
// 已知的漏计：正则模式（以及含 \r 的字面关键词）下，扫描器缓存着没写完的行，最多 8 MiB，
// body 里没有换行时它和缓存的 body 差不多大，实际内存最多约为计量值的两倍。
// 字面关键词走快速路径，不缓存行。match 没有导出行缓存的大小，引擎无法区分这两种情况。
func (e *Engine) Memory() int64 {
	return e.buffered + e.extra + e.parsers + e.asm.BufferedBytes() +
		int64(e.asm.Len())*connOverhead + int64(e.probing)*probeOverhead +
		int64(e.inFlight)*exchangeOverhead + int64(e.ghosts)*ghostOverhead
}

// bury 把已经结束的交互 x 变成占位，计入占位数。
func (e *Engine) bury(x *exchange) {
	x.bury()
	e.ghosts++
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

// enforce 在超过内存上限时丢弃在途交互，从最早开始的起（见 track），直到不超限；
// 在途交互都丢完了仍然超限，就释放最久没有收到包的连接。
// 在 Assembler 的回调之外调用（回调里不能调用 Release），所以计量最多超出上限一个包的量。
func (e *Engine) enforce(now time.Time) {
	limit := e.cfg.MaxMemory
	if limit > 0 && e.Memory() > limit {
		e.shrink(limit, now)
	}
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

// track 把刚开始的交互 x 排到在途链表的末尾，O(1)。
// 链表按引擎看到交互开始的先后排列，大体就是开始时间的先后。例外是 Upgrade 请求被拒后
// 回放出的请求：它的开始时间（定位行时间）是缓存段的时间，更早，但它排在回放时刻。
// 不按开始时间插入：回放可能一次放出几千个请求，每个都要往前越过全部在途交互。
func (e *Engine) track(x *exchange) {
	x.prev, x.next = e.newest, nil
	if e.newest == nil {
		e.oldest = x
	} else {
		e.newest.next = x
	}
	e.newest = x
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
	x.uncharge()
	x.evicted = true
	e.bury(x)
	// 和超时一样，还在等决定的 Upgrade 请求按被拒处理，缓存在它后面的请求回放出来。
	// 回放出的交互照常计入，上限由调用方（shrink）继续执行。
	c.giveUp(x)
	// 排在它后面的请求轮到队首，从现在起计时。
	c.rearm(now)
	c.syncParsers()
}
