// Package tcp 维护连接表，把 TCP 段按序号重组成两个方向的字节流，并认定缺口。
package tcp

import (
	"net/netip"
	"time"
)

// Side 表示连接的方向：0 是发起方（看到 SYN 时就是客户端），1 是另一方。
type Side uint8

// Key 标识一条连接，A 是 side 0 的地址。
type Key struct{ A, B netip.AddrPort }

// ConnInfo 是新建连接时交给 open 的信息。
type ConnInfo struct {
	Key        Key
	RolesKnown bool // 看到了 SYN 或 SYN-ACK，side 0 确定是客户端
	Start      time.Time
}

// CloseReason 是连接结束的原因。
type CloseReason uint8

const (
	CloseFin      CloseReason = iota // 两个方向的 FIN 都已按序生效
	CloseReset                       // 收到 RST
	CloseIdle                        // 空闲超过 IdleTimeout
	CloseReplaced                    // 同一四元组上出现了新连接
	CloseEOF                         // 调用了 Flush
	CloseEvicted                     // 调用了 Release
)

// Handler 接收一条连接的事件。回调里不得调用 Assembler 的方法。
type Handler interface {
	// Data 按序交付 side 方向的字节。off 是 b 在该方向流里的偏移，从 0 开始。
	// b 只在回调期间有效。peerAck 是这个包确认到的对端流偏移
	// （即对端流下一个期望的偏移），不知道时为 -1。ts 是 b 所在段的抓包时间：乱序缓存里的
	// 数据是它到达的时间，可能早于放行它的那个包（或 Advance 的时刻）。
	Data(side Side, off int64, b []byte, peerAck int64, ts time.Time)
	// Gap 表示 side 方向 [off, off+n) 这段没抓到。
	Gap(side Side, off, n int64, ts time.Time)
	// Fin 在 side 方向 FIN 之前的字节全部交付或认定为缺口之后调用。
	Fin(side Side, ts time.Time)
	// Reset 在收到 RST 时调用。调用前，两个方向缓存的乱序数据先按缺口规则交付。
	Reset(ts time.Time)
	// Closed 是最后一个回调，此时连接已经从表里移除。
	Closed(reason CloseReason, ts time.Time)
}

// Config 是重组器的参数。
type Config struct {
	ReorderTimeout  time.Duration // 乱序数据最多等多久，取 2s
	MaxReorderBytes int64         // 单方向乱序缓存的上限（口径见 BufferedBytes），取 --max-message
	IdleTimeout     time.Duration // 空闲多久释放连接，取 2 倍 --timeout
}
