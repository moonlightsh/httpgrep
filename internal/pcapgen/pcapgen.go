// Package pcapgen 生成测试用的 pcap 抓包，供各包的测试使用。
// 它不是产品接缝，本身不依赖 tcp、http1 或 engine。
package pcapgen

import (
	"encoding/binary"
	"io"
	"net/netip"
	"strconv"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/pcap"
)

// snaplen 是写出的 pcap 文件头的抓包长度。
const snaplen = 262144

// Writer 按 pcap 格式写记录。NewWriter 先写文件头。
type Writer struct {
	w    io.Writer
	link pcap.LinkType
	err  error // 文件头或上一条记录的写入错误
}

// NewWriter 写出 pcap 文件头（snaplen 262144，微秒精度，小端）。
func NewWriter(w io.Writer, link pcap.LinkType) *Writer {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // 魔数（小端）
	hdr[4] = 2                                         // 主版本
	hdr[5] = 4                                         // 次版本
	// hdr[8:] sigfigs、hdr[16:] 时区偏移都保持 0
	binary.LittleEndian.PutUint32(hdr[12:], snaplen)
	binary.LittleEndian.PutUint32(hdr[20:], uint32(link))
	if _, err := w.Write(hdr[:]); err != nil {
		// 写文件头失败时保留错误，Record 首次调用时返回。
		return &Writer{w: w, link: link, err: err}
	}
	return &Writer{w: w, link: link}
}

// Record 写一条 pcap 记录。origLen 为 0 时取 len(frame)。
func (w *Writer) Record(ts time.Time, frame []byte, origLen int) error {
	if w.err != nil {
		return w.err
	}
	if origLen == 0 {
		origLen = len(frame)
	}
	usec := ts.Nanosecond() / 1000
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:], uint32(usec))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(origLen))
	if _, err := w.w.Write(hdr[:]); err != nil {
		w.err = err
		return err
	}
	if _, err := w.w.Write(frame); err != nil {
		w.err = err
		return err
	}
	return nil
}

// Link 返回文件头里的链路层类型。
func (w *Writer) Link() pcap.LinkType { return w.link }

// Err 返回文件头或记录写出时遇到的第一个错误。
// Conn 的各方法不返回错误，需要可靠写出的调用方在最后检查一次。
func (w *Writer) Err() error { return w.err }

// ipv4HeaderLen 和 tcpHeaderLen 是构造时使用的固定头长。
const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20
)

// TCP 构造一个完整的 IP 包。IPv4 带正确的头部校验和，TCP 校验和填 0。
// payload 超出 IP 长度字段能表示的范围时 panic（测试工具尽早暴露错误用法）。
func TCP(src, dst netip.AddrPort, seq, ack uint32, flags decode.Flags, payload []byte) []byte {
	if src.Addr().Is4() && dst.Addr().Is4() {
		return tcpIPv4(src, dst, seq, ack, flags, payload)
	}
	return tcpIPv6(src, dst, seq, ack, flags, payload)
}

func tcpIPv4(src, dst netip.AddrPort, seq, ack uint32, flags decode.Flags, payload []byte) []byte {
	total := ipv4HeaderLen + tcpHeaderLen + len(payload)
	if total > 0xffff {
		panic("pcapgen: IPv4 packet too long: " + strconv.Itoa(total))
	}
	b := make([]byte, ipv4HeaderLen+tcpHeaderLen+len(payload))

	b[0] = 0x45 // 版本 4，IHL 5
	b[1] = 0    // DSCP
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[4:], 0) // 标识
	binary.BigEndian.PutUint16(b[6:], 0x4000)
	b[8] = 64 // TTL
	b[9] = 6  // TCP
	srcIP := src.Addr().As4()
	dstIP := dst.Addr().As4()
	copy(b[12:], srcIP[:])
	copy(b[16:], dstIP[:])

	// 头部校验和：按 16 位字求和、折叠进位、取反，大端写入。
	var sum uint32
	for i := 0; i < ipv4HeaderLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:], ^uint16(sum))

	writeTCP(b[ipv4HeaderLen:], src, dst, seq, ack, flags, payload)
	return b
}

func tcpIPv6(src, dst netip.AddrPort, seq, ack uint32, flags decode.Flags, payload []byte) []byte {
	if n := tcpHeaderLen + len(payload); n > 0xffff {
		panic("pcapgen: IPv6 payload too long: " + strconv.Itoa(n))
	}
	b := make([]byte, 40+tcpHeaderLen+len(payload))
	b[0] = 0x60 // 版本 6，流量类别 0
	binary.BigEndian.PutUint16(b[4:], uint16(tcpHeaderLen+len(payload)))
	b[6] = 6 // TCP
	srcIP := src.Addr().As16()
	dstIP := dst.Addr().As16()
	copy(b[8:], srcIP[:])
	copy(b[24:], dstIP[:])
	writeTCP(b[40:], src, dst, seq, ack, flags, payload)
	return b
}

func writeTCP(b []byte, src, dst netip.AddrPort, seq, ack uint32, flags decode.Flags, payload []byte) {
	b[0] = uint8(src.Port() >> 8)
	b[1] = uint8(src.Port())
	b[2] = uint8(dst.Port() >> 8)
	b[3] = uint8(dst.Port())
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12] = 0x50 // 数据偏移 5
	b[13] = uint8(flags)
	binary.BigEndian.PutUint16(b[14:], 64240) // 窗口
	binary.BigEndian.PutUint16(b[16:], 0)     // 校验和，按约定填 0
	binary.BigEndian.PutUint16(b[18:], 0)     // 紧急指针
	copy(b[tcpHeaderLen:], payload)
}

// Frame 按链路层类型给 IP 包加链路头：Ethernet（MAC 全 0）、SLL、SLL2、Null、Loop、Raw。
func Frame(link pcap.LinkType, ip []byte) []byte {
	switch link {
	case pcap.LinkEthernet:
		b := make([]byte, 14+len(ip))
		b[12], b[13] = 0x08, 0x00 // EtherType：IPv4
		if len(ip) >= 1 && ip[0]>>4 == 6 {
			b[12], b[13] = 0x86, 0xdd
		}
		copy(b[14:], ip)
		return b
	case pcap.LinkLinuxSLL:
		b := make([]byte, 16+len(ip))
		binary.BigEndian.PutUint16(b[0:], 0) // 包类型
		binary.BigEndian.PutUint16(b[2:], 1) // ARPHRD_ETHER
		binary.BigEndian.PutUint16(b[4:], 6) // 地址长度
		binary.BigEndian.PutUint16(b[14:], etherType(ip))
		copy(b[16:], ip)
		return b
	case pcap.LinkLinuxSLL2:
		b := make([]byte, 20+len(ip))
		binary.BigEndian.PutUint16(b[0:], etherType(ip)) // 协议类型
		// b[2:4] 保留；接口索引 4-7 写 1
		binary.BigEndian.PutUint32(b[4:], 1)
		binary.BigEndian.PutUint16(b[8:], 1) // ARPHRD_ETHER
		b[10] = 0                            // 包类型：主机收到
		b[11] = 6                            // 链路层地址长度
		copy(b[20:], ip)
		return b
	case pcap.LinkNull:
		b := make([]byte, 4+len(ip))
		binary.LittleEndian.PutUint32(b[:4], 2) // AF_INET
		if len(ip) >= 1 && ip[0]>>4 == 6 {
			binary.LittleEndian.PutUint32(b[:4], 30) // AF_INET6
		}
		copy(b[4:], ip)
		return b
	case pcap.LinkLoop:
		b := make([]byte, 4+len(ip))
		binary.BigEndian.PutUint32(b[:4], 2)
		if len(ip) >= 1 && ip[0]>>4 == 6 {
			binary.BigEndian.PutUint32(b[:4], 30)
		}
		copy(b[4:], ip)
		return b
	case pcap.LinkRaw:
		return ip
	}
	panic("pcapgen: unsupported link type " + strconv.Itoa(int(link)))
}

// etherType 按 IP 版本返回 EtherType：IPv6 为 0x86dd，否则为 0x0800。
func etherType(ip []byte) uint16 {
	if len(ip) >= 1 && ip[0]>>4 == 6 {
		return 0x86dd
	}
	return 0x0800
}

// Conn 模拟一条连接，自动维护双方的序号和确认号。
type Conn struct {
	Client, Server       netip.AddrPort
	ClientISN, ServerISN uint32
	MSS                  int // 发送时按它切段，默认 1460

	w             *Writer
	clientSeq     uint32 // 下一段要用的序号
	serverSeq     uint32
	clientSent    uint32 // 已发送的最后一个字节的下一个位置（SYN/FIN 计入）
	serverSent    uint32
	clientStarted bool // 首次发送前用当前 ISN 初始化序号
	serverStarted bool
}

// NewConn 创建一条连接，序号从 ISN+1 起步。
// ClientISN/ServerISN 可在 NewConn 之后、Handshake 或首次发送之前修改。
func NewConn(w *Writer, client, server netip.AddrPort) *Conn {
	return &Conn{
		Client:    client,
		Server:    server,
		ClientISN: 1000,
		ServerISN: 2000,
		MSS:       1460,
		w:         w,
	}
}

// startClient 在首次使用客户端序号前，按当前 ISN 初始化。
func (c *Conn) startClient() {
	if !c.clientStarted {
		c.clientStarted = true
		c.clientSeq = c.ClientISN + 1
		c.clientSent = c.ClientISN + 1
	}
}

// startServer 在首次使用服务端序号前，按当前 ISN 初始化。
func (c *Conn) startServer() {
	if !c.serverStarted {
		c.serverStarted = true
		c.serverSeq = c.ServerISN + 1
		c.serverSent = c.ServerISN + 1
	}
}

// mss 返回生效的 MSS。
func (c *Conn) mss() int {
	if c.MSS > 0 {
		return c.MSS
	}
	return 1460
}

// write 从 from 端发出一个段。
func (c *Conn) write(ts time.Time, fromClient bool, seq, ack uint32, flags decode.Flags, payload []byte) {
	if c.w.err != nil {
		return
	}
	var pkt []byte
	if fromClient {
		pkt = TCP(c.Client, c.Server, seq, ack, flags, payload)
	} else {
		pkt = TCP(c.Server, c.Client, seq, ack, flags, payload)
	}
	_ = c.w.Record(ts, Frame(c.w.link, pkt), 0)
}

// Handshake 写出 SYN、SYN-ACK、ACK 三步。
func (c *Conn) Handshake(ts time.Time) {
	c.startClient()
	c.startServer()
	c.write(ts, true, c.ClientISN, 0, decode.SYN, nil)
	c.write(ts, false, c.ServerISN, c.ClientISN+1, decode.SYN|decode.ACK, nil)
	c.write(ts, true, c.ClientISN+1, c.ServerISN+1, decode.ACK, nil)
}

// ClientSend 从客户端发送数据，带 ACK|PSH，按 MSS 切段。
// 确认号自动取服务端已发送的位置。
func (c *Conn) ClientSend(ts time.Time, b []byte) {
	c.startClient()
	c.startServer()
	mss := c.mss()
	for len(b) > 0 {
		n := mss
		if n > len(b) {
			n = len(b)
		}
		c.write(ts, true, c.clientSeq, c.serverSent, decode.ACK|decode.PSH, b[:n])
		c.clientSeq += uint32(n)
		c.clientSent = c.clientSeq
		b = b[n:]
	}
}

// ServerSend 从服务端发送数据，带 ACK|PSH，按 MSS 切段。
// 确认号自动取客户端已发送的位置。
func (c *Conn) ServerSend(ts time.Time, b []byte) {
	c.startServer()
	c.startClient()
	mss := c.mss()
	for len(b) > 0 {
		n := mss
		if n > len(b) {
			n = len(b)
		}
		c.write(ts, false, c.serverSeq, c.clientSent, decode.ACK|decode.PSH, b[:n])
		c.serverSeq += uint32(n)
		c.serverSent = c.serverSeq
		b = b[n:]
	}
}

// ClientAck 写一个从客户端发出的纯 ACK，确认到服务端当前的序号。
func (c *Conn) ClientAck(ts time.Time) {
	c.startClient()
	c.startServer()
	c.write(ts, true, c.clientSeq, c.serverSent, decode.ACK, nil)
}

// ServerAck 写一个从服务端发出的纯 ACK。
func (c *Conn) ServerAck(ts time.Time) {
	c.startServer()
	c.startClient()
	c.write(ts, false, c.serverSeq, c.clientSent, decode.ACK, nil)
}

// SkipClient 只推进客户端序号，不写包，用来模拟丢包。
func (c *Conn) SkipClient(n int) {
	c.startClient()
	c.clientSeq += uint32(n)
	c.clientSent = c.clientSeq
}

// SkipServer 只推进服务端序号。
func (c *Conn) SkipServer(n int) {
	c.startServer()
	c.serverSeq += uint32(n)
	c.serverSent = c.serverSeq
}

// ClientFin 从客户端发 FIN。
func (c *Conn) ClientFin(ts time.Time) {
	c.startClient()
	c.startServer()
	c.write(ts, true, c.clientSeq, c.serverSent, decode.FIN|decode.ACK, nil)
	c.clientSeq++
	c.clientSent = c.clientSeq
}

// ServerFin 从服务端发 FIN。
func (c *Conn) ServerFin(ts time.Time) {
	c.startServer()
	c.startClient()
	c.write(ts, false, c.serverSeq, c.clientSent, decode.FIN|decode.ACK, nil)
	c.serverSeq++
	c.serverSent = c.serverSeq
}

// ClientRst 从客户端发 RST。
func (c *Conn) ClientRst(ts time.Time) {
	c.startClient()
	c.startServer()
	c.write(ts, true, c.clientSeq, c.serverSent, decode.RST|decode.ACK, nil)
}

// Raw 写一个任意的段，用来构造重传、乱序、重叠等场景。
func (c *Conn) Raw(ts time.Time, fromClient bool, seq, ack uint32, flags decode.Flags, payload []byte) {
	c.write(ts, fromClient, seq, ack, flags, payload)
}
