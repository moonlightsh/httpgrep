package decode_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"httpgrep/internal/decode"
	"httpgrep/internal/pcap"
)

// ---- 测试数据构造辅助 ----

// tcpSegment 拼一个 TCP 段：20 字节固定头 + 可选的选项 + 负载。
func tcpSegment(sport, dport uint16, seq, ack uint32, flags byte, opts, payload []byte) []byte {
	b := make([]byte, 20+len(opts)+len(payload))
	b[0], b[1] = byte(sport>>8), byte(sport)
	b[2], b[3] = byte(dport>>8), byte(dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = byte((20 + len(opts)) / 4 << 4)
	b[13] = flags
	copy(b[20:], opts)
	copy(b[20+len(opts):], payload)
	return b
}

// ipv4Packet 拼一个 IPv4 包：可选的 IP 选项 + 上层（通常是 TCP 段）。
func ipv4Packet(src, dst [4]byte, flagsFrag uint16, opts, upper []byte) []byte {
	b := make([]byte, 20+len(opts)+len(upper))
	b[0] = byte(0x40 | (20+len(opts))/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b))) // 总长度
	b[8] = 64                                          // TTL
	b[9] = 6                                           // TCP
	binary.BigEndian.PutUint16(b[6:8], flagsFrag)
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	copy(b[20:], opts)
	copy(b[20+len(opts):], upper)
	return b
}

// ethernet 拼一个以太网帧。
func ethernet(et uint16, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	binary.BigEndian.PutUint16(b[12:14], et)
	copy(b[14:], payload)
	return b
}

func addr4(a, b, c, d byte) [4]byte { return [4]byte{a, b, c, d} }

// ---- Supported ----

func TestSupported(t *testing.T) {
	for _, lt := range []pcap.LinkType{
		pcap.LinkNull, pcap.LinkEthernet, 12, 14,
		pcap.LinkRaw, pcap.LinkLoop, pcap.LinkLinuxSLL, pcap.LinkLinuxSLL2,
	} {
		if !decode.Supported(lt) {
			t.Errorf("Supported(%d) = false, want true", lt)
		}
	}
	for _, lt := range []pcap.LinkType{6 /* PPP */, 9, 100, 105, 1130, 2760} {
		if decode.Supported(lt) {
			t.Errorf("Supported(%d) = true, want false", lt)
		}
	}
}

// ---- 行为 1：以太网 + IPv4 + TCP ----

func TestEthernetIPv4TCP(t *testing.T) {
	tcp := tcpSegment(1234, 80, 0x11223344, 0x55667788, 0x18, nil, []byte("hello"))
	frame := ethernet(0x0800, ipv4Packet(addr4(10, 1, 2, 3), addr4(192, 168, 100, 200), 0x4000, nil, tcp))

	var seg decode.Segment
	got := decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg)
	if got != decode.OK {
		t.Fatalf("Decode = %v, want OK", got)
	}
	if want := mustAddrPort(t, "10.1.2.3:1234"); seg.Src != want {
		t.Errorf("Src = %v, want %v", seg.Src, want)
	}
	if want := mustAddrPort(t, "192.168.100.200:80"); seg.Dst != want {
		t.Errorf("Dst = %v, want %v", seg.Dst, want)
	}
	if !seg.Src.Addr().Is4() || seg.Src.Addr().Is4In6() {
		t.Errorf("Src.Addr() 应是 4 字节 IPv4 形式，Is4=%v Is4In6=%v", seg.Src.Addr().Is4(), seg.Src.Addr().Is4In6())
	}
	if seg.Seq != 0x11223344 {
		t.Errorf("Seq = %#x, want %#x", seg.Seq, 0x11223344)
	}
	if seg.Ack != 0x55667788 {
		t.Errorf("Ack = %#x, want %#x", seg.Ack, 0x55667788)
	}
	if seg.Flags != decode.PSH|decode.ACK {
		t.Errorf("Flags = %#x, want %#x", seg.Flags, decode.PSH|decode.ACK)
	}
	if string(seg.Payload) != "hello" {
		t.Errorf("Payload = %q, want %q", seg.Payload, "hello")
	}
	if seg.Missing != 0 {
		t.Errorf("Missing = %d, want 0", seg.Missing)
	}
}

func mustAddrPort(t *testing.T, s string) (ap netip.AddrPort) {
	t.Helper()
	if err := ap.UnmarshalText([]byte(s)); err != nil {
		t.Fatalf("bad addrport %q: %v", s, err)
	}
	return ap
}

// ---- 行为 2：以太网填充与 IPv4 总长度截取 ----

func TestEthernetPadding(t *testing.T) {
	// 最小以太网帧负载 46 字节；TCP 段只有 25 字节，其余是填充。
	tcp := tcpSegment(1, 2, 1, 1, 0x10, nil, []byte("hi"))              // 22 字节
	ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp) // 42 字节
	frame := ethernet(0x0800, ip)
	for len(frame) < 60 {
		frame = append(frame, 0) // 以太网填充字节
	}
	if len(frame) != 60 {
		t.Fatalf("测试帧长 %d，应为 60", len(frame))
	}
	var seg decode.Segment
	if got := decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg); got != decode.OK {
		t.Fatalf("Decode = %v, want OK", got)
	}
	if string(seg.Payload) != "hi" {
		t.Errorf("Payload = %q, want %q（填充字节不能算进 Payload）", seg.Payload, "hi")
	}
}

// ---- 行为 3：VLAN 与 QinQ ----

func TestVLANQinQ(t *testing.T) {
	tcp := tcpSegment(80, 443, 7, 8, 0x02, nil, nil)
	ip := ipv4Packet(addr4(1, 2, 3, 4), addr4(5, 6, 7, 8), 0, nil, tcp)

	// 802.1Q：TPID 0x8100 + TCI 2 字节
	vlan := make([]byte, 4)
	binary.BigEndian.PutUint16(vlan[0:2], 0x8100)
	binary.BigEndian.PutUint16(vlan[2:4], 100) // VLAN 100
	// QinQ：外层 0x88A8 + 内层 0x8100
	qinqOuter := make([]byte, 4)
	binary.BigEndian.PutUint16(qinqOuter[0:2], 0x88A8)
	binary.BigEndian.PutUint16(qinqOuter[2:4], 200)

	tests := []struct {
		name string
		tags []byte
	}{
		{"802.1Q", vlan},
		{"QinQ", append(append([]byte{}, qinqOuter...), vlan...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := make([]byte, 0, 14+len(tt.tags)+len(ip))
			dmac := []byte{0, 0, 0, 0, 0, 1}
			smac := []byte{0, 0, 0, 0, 0, 2}
			innerET := make([]byte, 2)
			binary.BigEndian.PutUint16(innerET, 0x0800)
			frame = append(frame, dmac...)
			frame = append(frame, smac...)
			// 先写 tags，再写内层 ethertype，最后 IP
			frame = append(frame, tt.tags...)
			frame = append(frame, innerET...)
			frame = append(frame, ip...)

			var seg decode.Segment
			if got := decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg); got != decode.OK {
				t.Fatalf("Decode = %v, want OK", got)
			}
			if seg.Src.Port() != 80 || seg.Dst.Port() != 443 {
				t.Errorf("ports = %v -> %v, want 80 -> 443", seg.Src.Port(), seg.Dst.Port())
			}
		})
	}
}

// ---- 行为 4：SLL 与 SLL2 ----

func TestSLL(t *testing.T) {
	tcp := tcpSegment(22, 80, 1, 2, 0x18, nil, []byte("x"))
	ip := ipv4Packet(addr4(10, 0, 0, 1), addr4(10, 0, 0, 2), 0, nil, tcp)

	// SLL：16 字节头，协议号在偏移 14
	sll := make([]byte, 16, 16+len(ip))
	binary.BigEndian.PutUint16(sll[14:16], 0x0800)
	sll = append(sll, ip...)

	var seg decode.Segment
	if got := decode.Decode(pcap.LinkLinuxSLL, sll, len(sll), &seg); got != decode.OK {
		t.Fatalf("SLL Decode = %v, want OK", got)
	}
	if string(seg.Payload) != "x" || seg.Src.Port() != 22 {
		t.Errorf("SLL payload=%q sport=%d", seg.Payload, seg.Src.Port())
	}

	// SLL2：20 字节头，协议号在偏移 0
	sll2 := make([]byte, 20, 20+len(ip))
	binary.BigEndian.PutUint16(sll2[0:2], 0x0800)
	sll2 = append(sll2, ip...)

	seg = decode.Segment{}
	if got := decode.Decode(pcap.LinkLinuxSLL2, sll2, len(sll2), &seg); got != decode.OK {
		t.Fatalf("SLL2 Decode = %v, want OK", got)
	}
	if string(seg.Payload) != "x" || seg.Src.Port() != 22 {
		t.Errorf("SLL2 payload=%q sport=%d", seg.Payload, seg.Src.Port())
	}

	// SLL 协议号不是 IP 时返回 NotTCP
	arpSLL := make([]byte, 16, 20)
	binary.BigEndian.PutUint16(arpSLL[14:16], 0x0806)
	arpSLL = append(arpSLL, 0, 0, 0, 0)
	if got := decode.Decode(pcap.LinkLinuxSLL, arpSLL, len(arpSLL), &seg); got != decode.NotTCP {
		t.Errorf("SLL ARP Decode = %v, want NotTCP", got)
	}
}

// ---- 行为 5：NULL 与 LOOP ----

func TestNullLoop(t *testing.T) {
	tcp := tcpSegment(1, 2, 3, 4, 0x10, nil, []byte("ab"))
	ip4 := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
	ip6 := ipv6Packet(tcp)

	famBE := func(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
	famLE := func(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

	tests := []struct {
		name  string
		link  pcap.LinkType
		fam   []byte
		ip    []byte
		want  decode.Result
		sport uint16
	}{
		// NULL：大端、小端都认；2=IPv4，24/28/30=IPv6
		{"null/v4/be", pcap.LinkNull, famBE(2), ip4, decode.OK, 1},
		{"null/v4/le", pcap.LinkNull, famLE(2), ip4, decode.OK, 1},
		{"null/v6-24/be", pcap.LinkNull, famBE(24), ip6, decode.OK, 1},
		{"null/v6-24/le", pcap.LinkNull, famLE(24), ip6, decode.OK, 1},
		{"null/v6-28/be", pcap.LinkNull, famBE(28), ip6, decode.OK, 1},
		{"null/v6-30/le", pcap.LinkNull, famLE(30), ip6, decode.OK, 1},
		// LOOP：只按大端
		{"loop/v4/be", pcap.LinkLoop, famBE(2), ip4, decode.OK, 1},
		{"loop/v6/be", pcap.LinkLoop, famBE(24), ip6, decode.OK, 1},
		// 不是 IP 协议族
		{"null/af-unix", pcap.LinkNull, famBE(1), ip4, decode.NotTCP, 0},
		{"null/af-unix/le", pcap.LinkNull, famLE(1), ip4, decode.NotTCP, 0},
		// LOOP 只按大端读：小端字节序的家族号读不出来
		{"loop/v4/le", pcap.LinkLoop, famLE(2), ip4, decode.NotTCP, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := append(append([]byte{}, tt.fam...), tt.ip...)
			var seg decode.Segment
			got := decode.Decode(tt.link, frame, len(frame), &seg)
			if got != tt.want {
				t.Fatalf("Decode = %v, want %v", got, tt.want)
			}
			if tt.want == decode.OK && seg.Src.Port() != tt.sport {
				t.Errorf("sport = %d, want %d", seg.Src.Port(), tt.sport)
			}
		})
	}
}

// ipv6Packet 拼一个 IPv6 包（无扩展头）。
func ipv6Packet(upper []byte) []byte {
	b := make([]byte, 40+len(upper))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(upper)))
	b[6] = 6                                                                           // TCP
	copy(b[8:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1})  // src
	copy(b[24:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2}) // dst
	copy(b[40:], upper)
	return b
}

// ---- 行为 6：RAW IP ----

func TestRawIP(t *testing.T) {
	tcp := tcpSegment(1, 2, 3, 4, 0x10, nil, []byte("raw"))
	ip4 := ipv4Packet(addr4(9, 9, 9, 9), addr4(8, 8, 8, 8), 0, nil, tcp)
	ip6 := ipv6Packet(tcpSegment(3, 4, 5, 6, 0x10, nil, []byte("v6")))

	for _, lt := range []pcap.LinkType{101, 12, 14} {
		var seg decode.Segment
		if got := decode.Decode(lt, ip4, len(ip4), &seg); got != decode.OK {
			t.Errorf("RAW(%d) v4 Decode = %v, want OK", lt, got)
			continue
		}
		if string(seg.Payload) != "raw" {
			t.Errorf("RAW(%d) payload = %q", lt, seg.Payload)
		}
	}
	var seg decode.Segment
	if got := decode.Decode(pcap.LinkRaw, ip6, len(ip6), &seg); got != decode.OK {
		t.Fatalf("RAW v6 Decode = %v, want OK", got)
	}
	if string(seg.Payload) != "v6" {
		t.Errorf("RAW v6 payload = %q", seg.Payload)
	}
}

// ---- 行为 7：IP 选项与 TCP 选项 ----

func TestOptions(t *testing.T) {
	// IP 选项 4 字节（IHL=6），TCP 选项 4 字节（数据偏移=6）
	ipOpts := []byte{0x01, 0x01, 0x01, 0x01} // NOP
	tcpOpts := []byte{0x01, 0x01, 0x01, 0x01}
	tcp := tcpSegment(1000, 2000, 9, 10, 0x18, tcpOpts, []byte("data!"))
	ip := ipv4Packet(addr4(1, 2, 3, 4), addr4(5, 6, 7, 8), 0, ipOpts, tcp)
	frame := ethernet(0x0800, ip)

	var seg decode.Segment
	if got := decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg); got != decode.OK {
		t.Fatalf("Decode = %v, want OK", got)
	}
	if seg.Src.Port() != 1000 || seg.Dst.Port() != 2000 {
		t.Errorf("ports = %d -> %d, want 1000 -> 2000", seg.Src.Port(), seg.Dst.Port())
	}
	if string(seg.Payload) != "data!" {
		t.Errorf("Payload = %q, want %q", seg.Payload, "data!")
	}
}

// ---- 行为 8：IPv6 扩展头 ----

// ipv6ExtPacket 拼带一个扩展头的 IPv6 包。hdrlenUnits 是扩展头 Hdr Ext Len
// 字段的取值（不含前 8 字节的单位数），upper 紧跟在扩展头之后。
func ipv6ExtPacket(next byte, hdrlenUnits int, upper []byte) []byte {
	extTotal := 8 + hdrlenUnits*8
	b := make([]byte, 40+extTotal+len(upper))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(extTotal+len(upper)))
	b[6] = next
	b[40] = 6 // 扩展头的下一个头是 TCP
	b[41] = byte(hdrlenUnits)
	copy(b[8:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1})
	copy(b[24:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2})
	copy(b[40+extTotal:], upper)
	return b
}

func TestIPv6ExtHeaders(t *testing.T) {
	tcp := tcpSegment(1, 2, 3, 4, 0x10, nil, []byte("ext"))

	// 逐跳（0）、路由（43）、目的选项（60）各 16 字节（Hdrlen=1），都能跳过
	for _, tc := range []struct {
		name string
		next byte
	}{
		{"hopopt", 0}, {"routing", 43}, {"dstopt", 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := ipv6ExtPacket(tc.next, 1, tcp)
			var seg decode.Segment
			if got := decode.Decode(pcap.LinkRaw, frame, len(frame), &seg); got != decode.OK {
				t.Fatalf("Decode = %v, want OK", got)
			}
			if string(seg.Payload) != "ext" {
				t.Errorf("Payload = %q, want %q", seg.Payload, "ext")
			}
			if seg.Missing != 0 {
				t.Errorf("Missing = %d, want 0（扩展头不能重复计入负载长度）", seg.Missing)
			}
		})
	}

	// 扩展头之后跟着链路层尾部字节时，尾部不能算进 Payload
	trailer := append(ipv6ExtPacket(43, 1, tcp), make([]byte, 16)...)
	var seg decode.Segment
	if got := decode.Decode(pcap.LinkRaw, trailer, len(trailer), &seg); got != decode.OK {
		t.Fatalf("trailer Decode = %v, want OK", got)
	}
	if string(seg.Payload) != "ext" {
		t.Errorf("trailer Payload = %q, want %q", seg.Payload, "ext")
	}
	if seg.Missing != 0 {
		t.Errorf("trailer Missing = %d, want 0", seg.Missing)
	}

	// 带 TSO（负载长度 0）的 IPv6 加扩展头
	tsoFrame := ipv6ExtPacket(0, 1, tcpSegment(5, 6, 7, 8, 0x18, nil, []byte("v6tso")))
	binary.BigEndian.PutUint16(tsoFrame[4:6], 0)
	seg = decode.Segment{}
	if got := decode.Decode(pcap.LinkRaw, tsoFrame, len(tsoFrame), &seg); got != decode.OK {
		t.Fatalf("v6 TSO+ext Decode = %v, want OK", got)
	}
	if string(seg.Payload) != "v6tso" {
		t.Errorf("v6 TSO+ext Payload = %q, want %q", seg.Payload, "v6tso")
	}
	if seg.Missing != 0 {
		t.Errorf("v6 TSO+ext Missing = %d, want 0", seg.Missing)
	}

	// 分片头（44）返回 Fragment
	frag := ipv6ExtPacket(44, 1, tcp)
	seg = decode.Segment{}
	if got := decode.Decode(pcap.LinkRaw, frag, len(frag), &seg); got != decode.Fragment {
		t.Errorf("分片头 Decode = %v, want Fragment", got)
	}
}

// ---- 行为 9：IPv4 分片 ----

func TestIPv4Fragment(t *testing.T) {
	tcp := tcpSegment(1, 2, 3, 4, 0x10, nil, []byte("frag"))

	tests := []struct {
		name      string
		flagsFrag uint16
		want      decode.Result
	}{
		{"MF", 0x2000, decode.Fragment},     // MF 位置 1
		{"offset", 0x0001, decode.Fragment}, // 片偏移非 0（8 字节）
		{"DF-only", 0x4000, decode.OK},      // 只设 DF 不算分片
		{"none", 0x0000, decode.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), tt.flagsFrag, nil, tcp)
			var seg decode.Segment
			if got := decode.Decode(pcap.LinkRaw, ip, len(ip), &seg); got != tt.want {
				t.Errorf("Decode = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---- 行为 10：snaplen 截断 ----

func TestSnaplenTruncation(t *testing.T) {
	// 100 字节 TCP 负载，只抓到 30 字节
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	tcp := tcpSegment(1, 2, 3, 4, 0x18, nil, payload)
	ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
	full := len(ip) // 20 + 20 + 100 = 140

	captured := ip[:full-70] // 少 70 字节：只剩 30 字节负载
	var seg decode.Segment
	if got := decode.Decode(pcap.LinkRaw, captured, full, &seg); got != decode.OK {
		t.Fatalf("Decode = %v, want OK", got)
	}
	if len(seg.Payload) != 30 {
		t.Errorf("抓到负载 %d 字节, want 30", len(seg.Payload))
	}
	if seg.Missing != 70 {
		t.Errorf("Missing = %d, want 70", seg.Missing)
	}
}

// ---- 行为 11：总长度 0（TSO）与 IPv6 负载长度 0 ----

func TestZeroLengthTSO(t *testing.T) {
	// IPv4 总长度 0：用 origLen 推算。origLen 是整帧长度（链路层头含在内时
	// 需先扣除），这里用 RAW，直接就是 IP 包长。
	payload := []byte("tso payload here")
	tcp := tcpSegment(1, 2, 3, 4, 0x18, nil, payload)
	ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
	binary.BigEndian.PutUint16(ip[2:4], 0) // 网卡 TSO 抓包：总长度为 0

	var seg decode.Segment
	if got := decode.Decode(pcap.LinkRaw, ip, len(ip), &seg); got != decode.OK {
		t.Fatalf("v4 TSO Decode = %v, want OK", got)
	}
	if string(seg.Payload) != string(payload) {
		t.Errorf("v4 TSO payload = %q, want %q", seg.Payload, payload)
	}

	// IPv6 负载长度 0
	ip6 := ipv6Packet(tcpSegment(5, 6, 7, 8, 0x18, nil, payload))
	binary.BigEndian.PutUint16(ip6[4:6], 0)

	seg = decode.Segment{}
	if got := decode.Decode(pcap.LinkRaw, ip6, len(ip6), &seg); got != decode.OK {
		t.Fatalf("v6 TSO Decode = %v, want OK", got)
	}
	if string(seg.Payload) != string(payload) {
		t.Errorf("v6 TSO payload = %q, want %q", seg.Payload, payload)
	}
}

// ---- 行为 12：Malformed 与 NotTCP ----

func udpPacket(src, dst [4]byte) []byte {
	b := make([]byte, 20+8)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 28)
	b[9] = 17 // UDP
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	return b
}

func icmpPacket(src, dst [4]byte) []byte {
	b := make([]byte, 20+8)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 28)
	b[9] = 1 // ICMP
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	return b
}

func TestNotTCP(t *testing.T) {
	a, b := addr4(1, 1, 1, 1), addr4(2, 2, 2, 2)
	var seg decode.Segment

	// ARP 以太网帧
	arp := ethernet(0x0806, make([]byte, 28))
	if got := decode.Decode(pcap.LinkEthernet, arp, len(arp), &seg); got != decode.NotTCP {
		t.Errorf("ARP Decode = %v, want NotTCP", got)
	}
	// UDP、ICMP（RAW IP）
	for name, pkt := range map[string][]byte{
		"udp":  udpPacket(a, b),
		"icmp": icmpPacket(a, b),
	} {
		if got := decode.Decode(pcap.LinkRaw, pkt, len(pkt), &seg); got != decode.NotTCP {
			t.Errorf("%s Decode = %v, want NotTCP", name, got)
		}
	}
}

func TestMalformed(t *testing.T) {
	tcp := tcpSegment(1, 2, 3, 4, 0x10, nil, []byte("hi"))
	var seg decode.Segment

	tests := []struct {
		name string
		// 构造帧并返回帧和 origLen
		build func() ([]byte, int)
	}{
		{"以太网头不完整", func() ([]byte, int) {
			f := ethernet(0x0800, tcp)[:10]
			return f, len(f)
		}},
		{"IP 头不完整", func() ([]byte, int) {
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
			return ethernet(0x0800, ip[:19]), 14 + 19
		}},
		{"TCP 头不完整", func() ([]byte, int) {
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
			return ethernet(0x0800, ip[:20+15]), 14 + 35
		}},
		{"总长度比 IP 头短", func() ([]byte, int) {
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
			binary.BigEndian.PutUint16(ip[2:4], 12) // < 20
			return ethernet(0x0800, ip), 14 + len(ip)
		}},
		{"总长度比 TCP 头短", func() ([]byte, int) {
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
			binary.BigEndian.PutUint16(ip[2:4], 30) // 20 IP + 10 TCP，TCP 头都不够
			return ethernet(0x0800, ip), 14 + len(ip)
		}},
		{"IHL 太小", func() ([]byte, int) {
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, tcp)
			ip[0] = 0x43 // IHL=3
			return ethernet(0x0800, ip), 14 + len(ip)
		}},
		{"TCP 数据偏移太小", func() ([]byte, int) {
			t := tcpSegment(1, 2, 3, 4, 0x10, nil, []byte("hi"))
			t[12] = 0x30 // 数据偏移 3
			ip := ipv4Packet(addr4(1, 1, 1, 1), addr4(2, 2, 2, 2), 0, nil, t)
			return ethernet(0x0800, ip), 14 + len(ip)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, origLen := tt.build()
			if got := decode.Decode(pcap.LinkEthernet, frame, origLen, &seg); got != decode.Malformed {
				t.Errorf("Decode = %v, want Malformed", got)
			}
		})
	}
}

// ---- 行为 13：零分配与基准测试 ----

func TestAllocsPerRun(t *testing.T) {
	tcp := tcpSegment(1234, 80, 1, 2, 0x18, nil, make([]byte, 512))
	ip := ipv4Packet(addr4(10, 1, 2, 3), addr4(10, 1, 2, 4), 0, nil, tcp)
	frame := ethernet(0x0800, ip)
	var seg decode.Segment
	decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg) // 预热

	n := testing.AllocsPerRun(100, func() {
		decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg)
	})
	if n != 0 {
		t.Errorf("Decode 分配 %v 次/调用, want 0", n)
	}
}

func BenchmarkDecodeEthernet(b *testing.B) {
	tcp := tcpSegment(1234, 80, 1, 2, 0x18, nil, make([]byte, 1024))
	ip := ipv4Packet(addr4(10, 1, 2, 3), addr4(10, 1, 2, 4), 0, nil, tcp)
	frame := ethernet(0x0800, ip)
	var seg decode.Segment
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decode.Decode(pcap.LinkEthernet, frame, len(frame), &seg)
	}
}

func BenchmarkDecodeIPv6(b *testing.B) {
	ip6 := ipv6Packet(tcpSegment(1234, 80, 1, 2, 0x18, nil, make([]byte, 1024)))
	var seg decode.Segment
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decode.Decode(pcap.LinkRaw, ip6, len(ip6), &seg)
	}
}
