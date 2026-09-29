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
}

// side 返回从 src 发出的段属于哪个方向。
func (c *conn) side(src netip.AddrPort) Side {
	if src == c.key.A {
		return 0
	}
	return 1
}
