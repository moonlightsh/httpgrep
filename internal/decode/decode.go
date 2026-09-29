package decode

import (
	"encoding/binary"
	"net/netip"

	"httpgrep/internal/pcap"
)

// Supported 判断这种链路层类型能否解码。
func Supported(link pcap.LinkType) bool {
	switch link {
	case pcap.LinkNull, pcap.LinkEthernet, 12, 14,
		pcap.LinkRaw, pcap.LinkLoop, pcap.LinkLinuxSLL, pcap.LinkLinuxSLL2:
		return true
	}
	return false
}

// Decode 把 data（抓到的字节）按链路层类型 link 解码到 seg。
// origLen 是线上原始长度。seg.Payload 引用 data，不拷贝。
// link 不在 Supported 支持之列时返回 NotTCP。
// IP 版本以首字节高 4 位为权威：链路层协议号（EtherType、BSD 协议族）
// 只用来区分“是否 IP”，不校验它与版本位一致。
func Decode(link pcap.LinkType, data []byte, origLen int, seg *Segment) Result {
	ip, res := stripLink(link, data)
	if res != OK {
		return res
	}
	// origLen 是整帧长度，去掉链路层头后才是线上 IP 包长度
	return decodeIP(ip, origLen-(len(data)-len(ip)), seg)
}

// stripLink 去掉链路层头，返回 IP 包。
func stripLink(link pcap.LinkType, data []byte) ([]byte, Result) {
	switch link {
	case pcap.LinkEthernet:
		return stripEthernet(data)
	case pcap.LinkNull, pcap.LinkLoop:
		return stripNullLoop(link, data)
	case 12, 14, pcap.LinkRaw: // 12/14 是旧写法的 RAW IP
		return data, OK
	case pcap.LinkLinuxSLL:
		if len(data) < 16 {
			return nil, Malformed
		}
		// SLL 协议号在偏移 14
		if et := binary.BigEndian.Uint16(data[14:16]); et != ethTypeIPv4 && et != ethTypeIPv6 {
			return nil, NotTCP
		}
		return data[16:], OK
	case pcap.LinkLinuxSLL2:
		if len(data) < 20 {
			return nil, Malformed
		}
		// SLL2 协议号在偏移 0
		if et := binary.BigEndian.Uint16(data[0:2]); et != ethTypeIPv4 && et != ethTypeIPv6 {
			return nil, NotTCP
		}
		return data[20:], OK
	}
	return nil, NotTCP
}

// 链路层头里出现的协议号取值。
const (
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
	ethTypeVLAN = 0x8100
	ethTypeQinQ = 0x88A8
	afInet      = 2  // BSD 协议族：IPv4
	afInet6     = 24 // BSD 协议族：IPv6
	afInet6Alt1 = 28 // 部分系统（如 Haiku/旧 Darwin）的 IPv6 取值
	afInet6Alt2 = 30 // 部分系统的 IPv6 取值
)

// IPv6 扩展头类型取值。
const (
	extHopByHop  = 0  // 逐跳选项
	extRouting   = 43 // 路由
	extFragment  = 44 // 分片
	extDestOpts  = 60 // 目的选项
	ipv6HeaderLn = 40 // IPv6 基本头长度
)

// stripEthernet 去掉以太网头，跳过 VLAN（802.1Q）和 QinQ 标签。
const ethHeaderLen = 14

func stripEthernet(data []byte) ([]byte, Result) {
	if len(data) < ethHeaderLen {
		return nil, Malformed
	}
	off := 12 // EtherType 在帧头里的偏移
	for {
		if len(data) < off+2 {
			return nil, Malformed
		}
		switch binary.BigEndian.Uint16(data[off : off+2]) {
		case ethTypeVLAN, ethTypeQinQ:
			off += 4
		case ethTypeIPv4, ethTypeIPv6:
			return data[off+2:], OK
		default:
			return nil, NotTCP
		}
	}
}

// stripNullLoop 去掉 NULL/LOOP 头（4 字节协议族）。
// NULL 的抓包机字节序不确定，大端小端都认；LOOP 只按大端。
func stripNullLoop(link pcap.LinkType, data []byte) ([]byte, Result) {
	if len(data) < 4 {
		return nil, Malformed
	}
	fam := binary.BigEndian.Uint32(data[:4])
	if !isIPFamily(fam) && link == pcap.LinkNull {
		fam = binary.LittleEndian.Uint32(data[:4])
	}
	if !isIPFamily(fam) {
		return nil, NotTCP
	}
	return data[4:], OK
}

func isIPFamily(fam uint32) bool {
	return fam == afInet || fam == afInet6 || fam == afInet6Alt1 || fam == afInet6Alt2
}

// decodeIP 解码 IP 包，按首字节高 4 位区分 IPv4 和 IPv6。
func decodeIP(ip []byte, origLen int, seg *Segment) Result {
	if len(ip) < 1 {
		return Malformed
	}
	switch ip[0] >> 4 {
	case 4:
		return decodeIPv4(ip, origLen, seg)
	case 6:
		return decodeIPv6(ip, origLen, seg)
	}
	return NotTCP
}

const protoTCP = 6 // TCP 协议号

// decodeIPv4 解码 IPv4 包。
func decodeIPv4(ip []byte, origLen int, seg *Segment) Result {
	if len(ip) < 20 {
		return Malformed
	}
	hl := int(ip[0]&0x0F) * 4
	if hl < 20 || len(ip) < hl {
		return Malformed
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total != 0 && total < hl {
		return Malformed
	}
	if binary.BigEndian.Uint16(ip[6:8])&0x3FFF != 0 {
		return Fragment // MF 位或片偏移非 0
	}
	if ip[9] != protoTCP {
		return NotTCP
	}
	if total == 0 {
		// 网卡 TSO 抓包：总长度字段为 0，用线上长度推算
		total = origLen
		if total < hl {
			return Malformed
		}
	}
	return decodeTCP(ip, true, hl, total, seg)
}

// decodeIPv6 解码 IPv6 包，跳过逐跳选项、路由、目的选项扩展头。
func decodeIPv6(ip []byte, origLen int, seg *Segment) Result {
	if len(ip) < ipv6HeaderLn {
		return Malformed
	}
	hl := ipv6HeaderLn
	next := ip[6]
	for next == extHopByHop || next == extRouting || next == extDestOpts {
		if len(ip) < hl+2 {
			return Malformed
		}
		next = ip[hl]
		hl += 8 + int(ip[hl+1])*8
		if len(ip) < hl {
			return Malformed
		}
	}
	if next == extFragment {
		return Fragment // 分片头，不重组
	}
	if next != protoTCP {
		return NotTCP
	}
	plen := int(binary.BigEndian.Uint16(ip[4:6]))
	// Payload Length 字段已包含扩展头：报文总长 = 40 + plen
	total := ipv6HeaderLn + plen
	if plen == 0 {
		// 网卡 TSO 抓包：负载长度为 0，用线上长度推算
		total = origLen
	}
	if total < hl {
		return Malformed
	}
	return decodeTCP(ip, false, hl, total, seg)
}

// addrPortFrom4 用 4 字节 IPv4 地址和端口拼 AddrPort，不分配内存。
func addrPortFrom4(addr, port []byte) netip.AddrPort {
	var a [4]byte
	copy(a[:], addr)
	return netip.AddrPortFrom(netip.AddrFrom4(a), binary.BigEndian.Uint16(port))
}

// addrPortFrom16 用 16 字节 IPv6 地址和端口拼 AddrPort。
func addrPortFrom16(addr, port []byte) netip.AddrPort {
	var a [16]byte
	copy(a[:], addr)
	return netip.AddrPortFrom(netip.AddrFrom16(a), binary.BigEndian.Uint16(port))
}

// decodeTCP 从 ip[hl:] 解码 TCP 头；total 是 IP 报文总长。
// 返回的 Payload 引用 ip 内部，被 snaplen 截断时 Missing 记缺失字节数。
func decodeTCP(ip []byte, v4 bool, hl, total int, seg *Segment) Result {
	if total < hl || len(ip) < hl+20 {
		return Malformed
	}
	tcp := ip[hl:]
	off := int(tcp[12]>>4) * 4
	if off < 20 || len(tcp) < off || total-hl < off {
		return Malformed
	}
	if v4 {
		seg.Src = addrPortFrom4(ip[12:16], tcp[0:2])
		seg.Dst = addrPortFrom4(ip[16:20], tcp[2:4])
	} else {
		seg.Src = addrPortFrom16(ip[8:24], tcp[0:2])
		seg.Dst = addrPortFrom16(ip[24:40], tcp[2:4])
	}
	seg.Seq = binary.BigEndian.Uint32(tcp[4:8])
	seg.Ack = binary.BigEndian.Uint32(tcp[8:12])
	seg.Flags = Flags(tcp[13])
	tcpEnd := min(total-hl, len(tcp))
	seg.Payload = tcp[off:tcpEnd]
	seg.Missing = 0
	if total-hl > len(tcp) { // snaplen 截断
		seg.Missing = total - hl - len(tcp)
	}
	return OK
}
