// Package http1 增量解析单个方向的 HTTP/1.x 字节流：切分消息、去掉 chunked 编码，
// 缺口或格式错误导致失步后，在后续数据里找下一个起始行重新对齐。
package http1

import "time"

// Kind 是解析器所解析的消息类型。
type Kind uint8

const (
	Request Kind = iota
	Response
)

// Section 表示一段线上字节在消息里的位置。
type Section uint8

const (
	SecHead     Section = iota // 起始行、头部和结尾的空行
	SecBody                    // body 的线上字节：chunk 长度行、数据、CRLF 和最后的 "0\r\n"
	SecTrailer                 // trailer 头和最后的 CRLF
	SecUnparsed                // 失步后到重新对齐之前的原始字节
)

// Head 是解析出的起始行和关心的头部。
type Head struct {
	Method, Target  string // 请求用
	Status          int    // 响应用
	Proto           string // "HTTP/1.0" 或 "HTTP/1.1"
	ContentType     string // 第一个值，去掉首尾空白；没有时为空
	ContentEncoding string
	Upgrade         bool // 请求：方法是 CONNECT，或带 Upgrade 头
	Tunnel          bool // 响应：101，或 CONNECT 的 2xx；此后这个方向不再解析
}

// Begin 描述一条消息的开始。
type Begin struct {
	Off     int64     // 起始行第一个字节的流偏移
	TS      time.Time // 这个字节所在包的时间
	PeerAck int64     // 这个字节所在包的 peerAck，原样透传
	Orphan  bool      // 失步时没有正在解析的消息，后面只会有 SecUnparsed
}

// Sink 接收解析事件。所有 []byte 参数只在回调期间有效。
type Sink interface {
	Begin(b Begin)
	Raw(sec Section, b []byte) // 当前消息的线上字节，按顺序拼起来就是原文
	Head(h *Head)              // 头部解析完成；h 只在回调期间有效
	Body(b []byte)             // 去掉 chunked 编码后的 body 字节
	Gap(sec Section, n int64)  // 当前消息里有 n 字节没抓到
	End(complete bool, ts time.Time)
	Desync(off int64) // 在 off 处失步，用于统计
}

// Options 是解析器的选项。
type Options struct {
	Resync bool // 从失步状态开始：没看到连接开头时用
	// Method 只给响应解析器用：解析完一个非 1xx 响应的头部时调用，
	// 返回对应请求的方法；不知道时返回空串，按 GET 处理。
	Method func() string
}
