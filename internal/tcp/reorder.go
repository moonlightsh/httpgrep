package tcp

import "time"

// chunk 是乱序缓存里的一段数据。缓存按偏移排序。
type chunk struct {
	off    int64
	data   []byte // 负载的拷贝
	ack    uint32 // 所在段的 Ack，交付时再换算成 peerAck
	hasAck bool
	ts     time.Time // 到达时间
}

func (k *chunk) end() int64 { return k.off + int64(len(k.data)) }

// buffer 把 [off, off+len(b)) 中缓存里还没有的部分拷进乱序缓存。
// 缓存里的段互不重叠，重叠部分以先到的为准。
func (a *Assembler) buffer(d *dir, off int64, b []byte, ack uint32, hasAck bool, ts time.Time) {
	cur, end := off, off+int64(len(b))
	i := 0
	for i < len(d.buf) && d.buf[i].end() <= cur {
		i++
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
		k := chunk{off: cur, data: append([]byte(nil), b[cur-off:stop-off]...), ack: ack, hasAck: hasAck, ts: ts}
		d.buf = append(d.buf, chunk{})
		copy(d.buf[i+1:], d.buf[i:])
		d.buf[i] = k
		d.bufLen += int64(len(k.data))
		a.buffered += int64(len(k.data))
		i++
		cur = stop
	}
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
		d.bufLen -= int64(len(k.data))
		a.buffered -= int64(len(k.data))
		if k.end() <= d.next {
			continue
		}
		c.h.Data(s, d.next, k.data[d.next-k.off:], peerAckOf(peer, k.ack, k.hasAck), ts)
		d.next = k.end()
	}
}

// peerAckOf 把 Ack 换算成对端流的偏移，不知道时返回 -1。
func peerAckOf(peer *dir, ack uint32, hasAck bool) int64 {
	if !hasAck || !peer.started {
		return -1
	}
	if off := peer.offset(ack); off >= 0 {
		return off
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
	for len(d.buf) > 0 {
		oldest := 0
		for i := range d.buf {
			if d.buf[i].ts.Before(d.buf[oldest].ts) {
				oldest = i
			}
		}
		if now.Sub(d.buf[oldest].ts) < a.cfg.ReorderTimeout {
			return
		}
		a.skipTo(c, s, d.buf[oldest].off, now)
	}
}
