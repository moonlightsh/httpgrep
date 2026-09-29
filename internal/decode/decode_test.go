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
