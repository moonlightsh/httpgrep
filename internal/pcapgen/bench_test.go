package pcapgen_test

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// BenchmarkTCP 单独测 TCP/IP 包构造。
func BenchmarkTCP(b *testing.B) {
	src := netip.MustParseAddrPort("10.0.0.1:12345")
	dst := netip.MustParseAddrPort("10.0.0.2:80")
	payload := make([]byte, 1460)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = pcapgen.TCP(src, dst, uint32(i), 1, decode.ACK|decode.PSH, payload)
	}
}

// BenchmarkTCPFrame 构造加链路头。
func BenchmarkTCPFrame(b *testing.B) {
	src := netip.MustParseAddrPort("10.0.0.1:12345")
	dst := netip.MustParseAddrPort("10.0.0.2:80")
	payload := make([]byte, 1460)
	ip := pcapgen.TCP(src, dst, 1, 1, decode.ACK|decode.PSH, payload)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = pcapgen.Frame(pcap.LinkEthernet, ip)
	}
}

// BenchmarkConnSend 模拟整条连接的握手加大流量发送，写到内存缓冲。
func BenchmarkConnSend(b *testing.B) {
	client := netip.MustParseAddrPort("10.0.0.1:50000")
	server := netip.MustParseAddrPort("10.0.0.2:80")
	payload := make([]byte, 8192)
	t0 := time.Unix(1700000000, 0)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := pcapgen.NewWriter(&buf, pcap.LinkEthernet)
		c := pcapgen.NewConn(w, client, server)
		c.Handshake(t0)
		c.ClientSend(t0, payload)
	}
}

// sink 防止编译器把赋值优化掉。
var sink []byte
