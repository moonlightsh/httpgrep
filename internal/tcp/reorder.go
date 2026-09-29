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

// buffer 把 [off, off+len(b)) 拷进乱序缓存。
func (a *Assembler) buffer(d *dir, off int64, b []byte, ack uint32, hasAck bool, ts time.Time) {
	k := chunk{off: off, data: append([]byte(nil), b...), ack: ack, hasAck: hasAck, ts: ts}
	i := len(d.buf)
	for i > 0 && d.buf[i-1].off > off {
		i--
	}
	d.buf = append(d.buf, chunk{})
	copy(d.buf[i+1:], d.buf[i:])
	d.buf[i] = k
}

// drain 交付 side 方向缓存里已经和 next 相接的段。
func (a *Assembler) drain(c *conn, s Side, ts time.Time) {
	d, peer := &c.d[s], &c.d[1-s]
	for len(d.buf) > 0 && d.buf[0].off <= d.next {
		k := d.buf[0]
		d.buf[0] = chunk{}
		d.buf = d.buf[1:]
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
