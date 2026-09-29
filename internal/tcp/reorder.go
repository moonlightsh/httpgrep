package tcp

import (
	"sort"
	"time"
)

// chunk 是乱序缓存里的一段 [off, off+n)。data 为 nil 时这段是因截断而没抓到的字节，
// 交付时认定为缺口。缓存按偏移排序，互不重叠。
type chunk struct {
	off    int64
	n      int64
	data   []byte // 负载的拷贝，len(data) == n
	ack    uint32 // 所在段的 Ack，交付时再换算成 peerAck
	hasAck bool
	ts     time.Time // 到达时间
}

func (k *chunk) end() int64 { return k.off + k.n }

// chunkOverhead 是每段乱序缓存在负载之外计入的固定开销：chunk 本身（64 位下 72 字节）、
// 切片扩容留的余量和负载拷贝的分配取整。只记缺口、没有负载的段同样计入。
const chunkOverhead = 128

// cost 是 k 计入乱序缓存计量的字节数。
func (k *chunk) cost() int64 { return int64(len(k.data)) + chunkOverhead }

// arrival 是按到达先后排队的一段 [off, end)，用来找最早到达、还没交付的缓存段，
// 不用每次扫描全部缓存。段交付后对应的记录过时（end <= next），在队首时顺带丢掉。
type arrival struct {
	off, end int64
	ts       time.Time
}

// buffer 把 [off, off+len(b)+missing) 中缓存里还没有的部分放进乱序缓存：
// 负载部分拷贝，截断的 missing 部分记为缺口段。重叠部分以先到的为准。
func (a *Assembler) buffer(d *dir, off int64, b []byte, missing int64, ack uint32, hasAck bool, ts time.Time) {
	dataEnd := off + int64(len(b))
	cur, end := off, dataEnd+missing
	// 第一个结束在 cur 之后的段。常见情况是追加到末尾，不用查找。
	i := len(d.buf)
	if i > 0 && d.buf[i-1].end() > cur {
		i = sort.Search(len(d.buf), func(j int) bool { return d.buf[j].end() > cur })
	}
	for cur < end {
		if i < len(d.buf) && d.buf[i].off <= cur {
			cur = max(cur, d.buf[i].end())
			i++
			continue
		}
		stop := end
		if i < len(d.buf) && d.buf[i].off < end {
			stop = d.buf[i].off
		}
		if cur < dataEnd {
			ds := min(stop, dataEnd)
			a.insert(d, i, chunk{off: cur, n: ds - cur, data: append([]byte(nil), b[cur-off:ds-off]...), ack: ack, hasAck: hasAck, ts: ts})
			i++
			cur = ds
		}
		if cur < stop {
			if i > 0 && d.buf[i-1].data == nil && d.buf[i-1].end() == cur {
				// 和前面相接的缺口段合并，只计一次固定开销；合并后的段保留较早的到达时间，
				// 到达记录也只留原来那一条。
				d.buf[i-1].n += stop - cur
			} else {
				a.insert(d, i, chunk{off: cur, n: stop - cur, ack: ack, hasAck: hasAck, ts: ts})
				i++
			}
			cur = stop
		}
	}
}

// insert 把 k 插到缓存的第 i 个位置。
func (a *Assembler) insert(d *dir, i int, k chunk) {
	if i == len(d.buf) {
		d.buf = append(d.buf, k)
	} else {
		d.buf = append(d.buf, chunk{})
		copy(d.buf[i+1:], d.buf[i:])
		d.buf[i] = k
	}
	d.bufLen += k.cost()
	a.buffered += k.cost()
	d.arrive(k.off, k.end(), k.ts)
}

// arrivals 是一个方向的到达记录队列，q[head:] 有效。放在指针后面：多数连接没有乱序缓存，
// 不让每个 dir 都多带这些字段（连接表的全表扫描对 conn 的大小敏感）。
type arrivals struct {
	q    []arrival
	head int
}

// arrive 记下 [off, end) 在 ts 到达。每个缓存段正好一条没过时的记录；过时的记录
// 超过缓存段数的两倍时整体清理一次，队列长度和缓存段数成正比，摊还 O(1)。
func (d *dir) arrive(off, end int64, ts time.Time) {
	if d.arr == nil {
		d.arr = &arrivals{}
	}
	a := d.arr
	if len(a.q)-a.head > 2*len(d.buf)+32 {
		live := a.q[:0]
		for _, r := range a.q[a.head:] {
			if r.end > d.next {
				live = append(live, r)
			}
		}
		clear(a.q[len(live):])
		a.q, a.head = live, 0
	}
	a.q = append(a.q, arrival{off: off, end: end, ts: ts})
}

// oldest 返回最早到达、还没交付的缓存段的记录，缓存为空时返回 false。
func (d *dir) oldest() (arrival, bool) {
	a := d.arr
	if a == nil {
		return arrival{}, false
	}
	if len(d.buf) == 0 {
		a.q, a.head = a.q[:0], 0
		return arrival{}, false
	}
	for a.head < len(a.q) && a.q[a.head].end <= d.next {
		a.head++
	}
	if a.head > len(a.q)/2 {
		// 过时的记录占了一半以上时压缩，队列长度不超过缓存段数的两倍左右。
		n := copy(a.q, a.q[a.head:])
		a.q, a.head = a.q[:n], 0
	}
	if a.head == len(a.q) {
		return arrival{}, false
	}
	return a.q[a.head], true
}

// clearBuf 丢弃这个方向的乱序缓存。
func (d *dir) clearBuf() {
	d.buf, d.bufLen, d.arr = nil, 0, nil
}

// limitReorder 在 side 方向乱序缓存超过 MaxReorderBytes 时，
// 从最前面的空洞起逐个认定缺口，直到不超限。
func (a *Assembler) limitReorder(c *conn, s Side, ts time.Time) {
	d := &c.d[s]
	for d.bufLen > a.cfg.MaxReorderBytes && len(d.buf) > 0 {
		a.skipTo(c, s, d.buf[0].off, ts)
	}
}

// drain 交付 side 方向缓存里已经和 next 相接的段。
func (a *Assembler) drain(c *conn, s Side, ts time.Time) {
	d, peer := &c.d[s], &c.d[1-s]
	for len(d.buf) > 0 && d.buf[0].off <= d.next {
		k := d.buf[0]
		d.buf[0] = chunk{}
		d.buf = d.buf[1:]
		d.bufLen -= k.cost()
		a.buffered -= k.cost()
		if k.end() <= d.next {
			continue
		}
		if k.data == nil {
			c.h.Gap(s, d.next, k.end()-d.next, ts)
		} else {
			// 缓存的数据按它到达的时间交付，不是放行它的那个时刻。
			c.h.Data(s, d.next, k.data[d.next-k.off:], peerAckOf(peer, k.ack, k.hasAck), k.ts)
		}
		d.next = k.end()
	}
}

// peerAckOf 把 Ack 换算成对端流的偏移，不知道时返回 -1。
func peerAckOf(peer *dir, ack uint32, hasAck bool) int64 {
	if !hasAck || !peer.started {
		return -1
	}
	if off := peer.offset(ack); off >= 0 {
		// 确认 FIN 的那个序号不算流里的字节。FIN 的偏移不早于已交付的位置（见 segment），
		// 所以结果不为负。
		return peer.limit(off)
	}
	return -1
}

// skipTo 把 side 方向 next 到 limit 之间没抓到的部分认定为缺口，
// 并交付其间以及紧接其后的缓存数据。
func (a *Assembler) skipTo(c *conn, s Side, limit int64, ts time.Time) {
	d := &c.d[s]
	for d.next < limit {
		stop := limit
		if len(d.buf) > 0 && d.buf[0].off < stop {
			stop = d.buf[0].off
		}
		if stop > d.next {
			c.h.Gap(s, d.next, stop-d.next, ts)
			d.next = stop
		}
		a.drain(c, s, ts)
	}
}

// expireReorder 处理 side 方向的乱序超时：最早到达的缓存段等满 ReorderTimeout
// 仍没补上时，把它之前的空洞认定为缺口。
func (a *Assembler) expireReorder(c *conn, s Side, now time.Time) {
	d := &c.d[s]
	if len(d.buf) == 0 && !d.finSeen {
		return // 常见情况：没有乱序缓存，也没有等待中的 FIN
	}
	for {
		k, ok := d.oldest()
		if !ok {
			break
		}
		if now.Sub(k.ts) < a.cfg.ReorderTimeout {
			return
		}
		a.skipTo(c, s, k.off, now)
	}
	// FIN 之前的空洞也按 FIN 到达的时间计时。
	if d.finSeen && d.next < d.finOff && now.Sub(d.finTs) >= a.cfg.ReorderTimeout {
		a.skipTo(c, s, d.finOff, now)
	}
}

// flushHoles 把两个方向的空洞（包括 FIN 之前的）都认定为缺口，
// 交付全部缓存数据，再回调因此生效的 FIN。
func (a *Assembler) flushHoles(c *conn, ts time.Time) {
	for s := range Side(2) {
		d := &c.d[s]
		if n := len(d.buf); n > 0 {
			a.skipTo(c, s, d.buf[n-1].end(), ts)
		}
		if d.finSeen {
			a.skipTo(c, s, d.finOff, ts)
		}
	}
	a.fins(c, ts)
}
