// Package pcap 读取 tcpdump 写出的 pcap 数据流（不支持 pcapng）。
package pcap

import "time"

// LinkType 是 pcap 文件头里的链路层类型（LINKTYPE_* 取值）。
type LinkType uint32

const (
	LinkNull      LinkType = 0   // BSD/macOS 回环：4 字节协议族，抓包机字节序
	LinkEthernet  LinkType = 1   // 以太网，可带 VLAN 标签
	LinkRaw       LinkType = 101 // 直接是 IP 包；有的文件写成 12 或 14，含义相同
	LinkLoop      LinkType = 108 // OpenBSD 回环：4 字节协议族，网络字节序
	LinkLinuxSLL  LinkType = 113 // Linux cooked v1（老版本 tcpdump -i any）
	LinkLinuxSLL2 LinkType = 276 // Linux cooked v2（新版本 tcpdump -i any）
)

// Packet 是一条 pcap 记录。
//
// Data 引用 Reader 的内部缓冲区，只在下一次调用 Reader.Next 之前有效；
// 需要保留时由调用方自行拷贝。
type Packet struct {
	Timestamp time.Time
	Data      []byte // 抓到的字节，len(Data) 即 caplen
	OrigLen   int    // 线上原始长度；大于 len(Data) 表示被 snaplen 截断
}
