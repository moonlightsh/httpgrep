// Package output 把交互的输出块渲染成字节并写出。
package output

import (
	"io"
	"net/netip"
	"strconv"
	"time"
)

// Status 是交互的异常状态。
type Status struct {
	NoRequest  bool
	Incomplete bool
	NoResponse string // ""、"timeout"、"closed"、"eof"
}

// PieceKind 是输出片段的类型。
type PieceKind uint8

const (
	PieceHead PieceKind = iota // 起始行和头部
	PieceBody                  // body 的线上字节（chunk 长度行也在内）
	PieceTrailer
	PieceUnparsed
	PieceGap       // N 字节没抓到；InBody 表示缺口在 body 里
	PieceTruncated // 超过 --max-message 的 N 字节没有缓存
)

// Piece 是消息里的一段字节。
type Piece struct {
	Kind   PieceKind
	Data   []byte
	N      int64
	InBody bool
}

// Message 是一个请求、一个 1xx 响应或一个最终响应。
type Message struct {
	Pieces          []Piece
	Binary          bool
	ContentType     string
	ContentEncoding string
	BodySize        int64 // 抓到的解码后 body 字节数
	BodyMatched     bool
}

// Block 是一次交互的输出块。
type Block struct {
	Time           time.Time
	Client, Server netip.AddrPort
	Status         Status
	Duration       time.Duration
	HasDuration    bool
	Messages       []Message // 依次是请求（如果有）、1xx、最终响应
}

// Options 配置 Writer 的行为。
type Options struct {
	TTY       bool
	Location  *time.Location             // 为 nil 时用 time.Local
	Highlight func(line []byte) [][2]int // 只在 TTY 模式下使用，可以为 nil
}

// Writer 把 Block 渲染后写给底层 writer。
type Writer struct {
	w    io.Writer
	opt  Options
	buf  []byte
	prev bool // 之前是否已经写过块
}

// NewWriter 创建一个 Writer。
func NewWriter(w io.Writer, opt Options) *Writer {
	return &Writer{w: w, opt: opt}
}

// Write 先把整块渲染到内部缓冲区，再一次性写给 w。
func (w *Writer) Write(b *Block) error {
	w.buf = w.buf[:0]
	if w.prev {
		w.buf = append(w.buf, "--\n"...)
	}
	w.prev = true
	w.writeLocationLine(b)
	for i := range b.Messages {
		w.writeMessage(&b.Messages[i])
	}
	_, err := w.w.Write(w.buf)
	return err
}

func (w *Writer) writeMessage(m *Message) {
	for i := range m.Pieces {
		p := &m.Pieces[i]
		switch p.Kind {
		case PieceGap, PieceTruncated:
			if len(w.buf) > 0 && w.buf[len(w.buf)-1] != '\n' {
				w.buf = append(w.buf, '\n')
			}
			if p.Kind == PieceGap {
				w.buf = append(w.buf, "[gap: "...)
				w.buf = strconv.AppendInt(w.buf, p.N, 10)
				w.buf = append(w.buf, " bytes missing]\n"...)
			} else {
				w.buf = append(w.buf, "[truncated: "...)
				w.buf = strconv.AppendInt(w.buf, p.N, 10)
				w.buf = append(w.buf, " bytes over --max-message]\n"...)
			}
		default:
			w.buf = append(w.buf, p.Data...)
		}
	}
	if n := len(w.buf); n > 0 && w.buf[n-1] != '\n' {
		w.buf = append(w.buf, '\n')
	}
}

// writeLocationLine 写定位行。
func (w *Writer) writeLocationLine(b *Block) {
	loc := w.opt.Location
	if loc == nil {
		loc = time.Local
	}
	ts := b.Time.In(loc)
	w.buf = ts.AppendFormat(w.buf, "2006-01-02 15:04:05.000 ")
	w.buf = appendAddr(w.buf, b.Client)
	w.buf = append(w.buf, " -> "...)
	w.buf = appendAddr(w.buf, b.Server)
	// 状态词
	var words [3]string
	n := 0
	if b.Status.NoRequest {
		words[n] = "no-request"
		n++
	}
	if b.Status.Incomplete {
		words[n] = "incomplete"
		n++
	}
	if b.Status.NoResponse != "" {
		words[n] = "no-response(" + b.Status.NoResponse + ")"
		n++
	}
	w.buf = append(w.buf, ' ')
	if n == 0 {
		w.buf = append(w.buf, "complete"...)
	} else {
		for i := 0; i < n; i++ {
			if i > 0 {
				w.buf = append(w.buf, ',')
			}
			w.buf = append(w.buf, words[i]...)
		}
	}
	if b.HasDuration {
		w.buf = append(w.buf, ' ')
		w.buf = strconv.AppendFloat(w.buf, float64(b.Duration)/1e6, 'f', 1, 64)
		w.buf = append(w.buf, "ms"...)
	}
	w.buf = append(w.buf, '\n')
}

// appendAddr 追加 "地址:端口"，IPv6 加方括号。
func appendAddr(buf []byte, a netip.AddrPort) []byte {
	return a.AppendTo(buf)
}
