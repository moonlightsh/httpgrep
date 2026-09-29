// Package decode 把一个链路层帧解码成 TCP 段（链路层 → IPv4/IPv6 → TCP）。
package decode

import "net/netip"

// Flags 是 TCP 头里的标志位，取值与 TCP 头第 13 字节的位一致。
type Flags uint8

const (
	FIN Flags = 1 << iota // 0x01
	SYN                   // 0x02
	RST                   // 0x04
	PSH                   // 0x08
	ACK                   // 0x10
	URG                   // 0x20
)

// Segment 是解码出的一个 TCP 段。
type Segment struct {
	Src, Dst netip.AddrPort // IPv4 地址是 4 字节形式（Is4() 为真），不是 IPv4-mapped
	Seq, Ack uint32
	Flags    Flags
	// Payload 是抓到的 TCP 负载，引用原始帧数据，不拷贝。
	// 长度按 IP 头里的长度字段截取，不含以太网填充字节。
	Payload []byte
	// Missing 是因 snaplen 截断而没抓到的负载字节数，这些字节紧跟在 Payload 之后。
	Missing int
}

// Result 是 Decode 的结果分类。
type Result uint8

const (
	OK        Result = iota // 解出了 TCP 段
	NotTCP                  // 不是 IP 或不是 TCP（ARP、UDP、ICMP 等）
	Fragment                // IP 分片（IPv4 MF 或片偏移非 0，IPv6 分片头），不重组
	Malformed               // 头部不完整或长度字段不合理
)
