// Package output 把交互的输出块渲染成字节并写出。
package output

import (
	"bytes"
	"io"
	"net/netip"
	"strconv"
	"time"
	"unicode/utf8"
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
	TTY      bool
	Location *time.Location // 为 nil 时用 time.Local
	// Highlight 只在 TTY 模式下使用，可以为 nil。返回的区间应按起点排序、互不重叠；
	// 否则重叠部分并入前一个区间，乱序区间跳过，不会 panic。
	Highlight func(line []byte) [][2]int
}

// Writer 把 Block 渲染后写给底层 writer。
type Writer struct {
	w    io.Writer
	opt  Options
	buf  []byte
	prev bool   // 之前是否已经写过块
	line []byte // TTY 模式下暂存还没写完的行
}

// NewWriter 创建一个 Writer。
func NewWriter(w io.Writer, opt Options) *Writer {
	return &Writer{w: w, opt: opt}
}

// Write 先把整块渲染到内部缓冲区，再一次性写给 w。
func (w *Writer) Write(b *Block) error {
	w.buf = w.buf[:0]
	if w.prev {
		if w.opt.TTY {
			w.buf = append(w.buf, "\x1b[36m--\x1b[m\n"...)
		} else {
			w.buf = append(w.buf, "--\n"...)
		}
	}
	w.prev = true
	w.writeLocationLine(b)
	for i := range b.Messages {
		w.writeMessage(&b.Messages[i])
		// 消息结束时，暂存的行即使没有换行也要写出并补换行
		if w.opt.TTY && len(w.line) > 0 {
			w.flushLine(false)
			w.buf = append(w.buf, '\n')
		}
	}
	_, err := w.w.Write(w.buf)
	return err
}

func (w *Writer) writeMessage(m *Message) {
	if m.Binary {
		w.writeBinaryMessage(m)
		return
	}
	for i := range m.Pieces {
		w.writePiece(&m.Pieces[i])
	}
	if n := len(w.buf); n > 0 && w.buf[n-1] != '\n' {
		w.buf = append(w.buf, '\n')
	}
}

// writePiece 写一个 Piece：数据原样追加，标记类 Piece 写成标记行。
func (w *Writer) writePiece(p *Piece) {
	switch p.Kind {
	case PieceGap, PieceTruncated:
		if len(w.line) > 0 {
			// 标记行必须自己占一行，先把暂存的行写出（flushLine 已带换行）
			w.flushLine(true)
		} else if len(w.buf) > 0 && w.buf[len(w.buf)-1] != '\n' {
			w.buf = append(w.buf, '\n')
		}
		if w.opt.TTY {
			w.buf = append(w.buf, "\x1b[33m"...)
		}
		if p.Kind == PieceGap {
			w.buf = append(w.buf, "[gap: "...)
			w.buf = strconv.AppendInt(w.buf, p.N, 10)
			w.buf = append(w.buf, " bytes missing]"...)
		} else {
			w.buf = append(w.buf, "[truncated: "...)
			w.buf = strconv.AppendInt(w.buf, p.N, 10)
			w.buf = append(w.buf, " bytes over --max-message]"...)
		}
		if w.opt.TTY {
			w.buf = append(w.buf, "\x1b[m"...)
		}
		w.buf = append(w.buf, '\n')
	default:
		if w.opt.TTY {
			w.appendHighlighted(p.Data)
		} else {
			w.buf = append(w.buf, p.Data...)
		}
	}
}

// appendHighlighted 把内容转义后追加，按行调用 Highlight，命中区间用红色包住。
// 一行可能跨多个 Piece：行缓冲在 Writer 里暂存，遇到换行或块结束时才写出。
func (w *Writer) appendHighlighted(data []byte) {
	for len(data) > 0 {
		// 找下一个换行
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			w.line = append(w.line, data...)
			return
		}
		w.line = append(w.line, data[:i]...)
		data = data[i+1:]
		w.flushLine(true)
	}
}

// flushLine 把暂存的行写出。有换行时行尾的 \r 不转义不参与高亮。
// Highlight 收到的是去掉 \n 和行尾 \r 的原始字节；命中区间按原始偏移给出，
// 输出时按区间分段转义并插入颜色码，不需要偏移映射。
func (w *Writer) flushLine(newline bool) {
	line := w.line
	tail := ""
	// 行尾的 \r 原样输出，但不传给 Highlight（newline 为假时表示消息末尾，规则一致）
	if len(line) > 0 && line[len(line)-1] == '\r' {
		tail = "\r"
		line = line[:len(line)-1]
	}
	var ranges [][2]int
	if w.opt.Highlight != nil {
		ranges = w.opt.Highlight(line)
	}
	// 按区间顺序分段写：区间外原样转义，区间内先写起始码，转义后写结束码。
	// 区间应按起点排序、互不重叠；越界的部分夹到行内，与已写部分重叠的部分并入
	// 前一个区间，完全落在已写部分之前的区间跳过。
	// 区间边界切在多字节序列中间时，两边各自按孤立字节处理，结果可能与整行转义不同。
	prev := 0
	for _, r := range ranges {
		lo, hi := r[0], r[1]
		if lo < 0 {
			lo = 0
		}
		if hi > len(line) {
			hi = len(line)
		}
		if lo < prev {
			lo = prev
		}
		if lo >= hi {
			continue
		}
		w.buf = appendEscapedTo(w.buf, line[prev:lo])
		w.buf = append(w.buf, "\x1b[01;31m"...)
		w.buf = appendEscapedTo(w.buf, line[lo:hi])
		w.buf = append(w.buf, "\x1b[m"...)
		prev = hi
	}
	w.buf = appendEscapedTo(w.buf, line[prev:])
	if tail != "" {
		w.buf = append(w.buf, tail...)
	}
	if newline {
		w.buf = append(w.buf, '\n')
	}
	w.line = w.line[:0]
}

// \t、\r、\n 以外的 C0 字符和 DEL；合法 UTF-8 编码的 C1 字符（C2 80–C2 9F，
// 两字节都转义）；以及不成 UTF-8 序列的单个 0x80–0x9F 字节。其他字节原样。
func appendEscapedTo(buf, data []byte) []byte {
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c < 0x20 && c != '\t' && c != '\r' && c != '\n', c == 0x7f:
			buf = appendHex(buf, c)
			i++
		case c == 0xc2 && i+1 < len(data) && data[i+1] >= 0x80 && data[i+1] <= 0x9f:
			// 合法 UTF-8 的 C1 字符，两个字节都转义
			buf = appendHex(buf, c)
			buf = appendHex(buf, data[i+1])
			i += 2
		case c >= 0x80 && c <= 0x9f:
			// 不成 UTF-8 序列的单字节（前面不是能和它组成序列的引导字节）
			buf = appendHex(buf, c)
			i++
		case c >= 0xc2:
			// 可能是合法 UTF-8 序列的引导字节，用 utf8 判断；
			// DecodeRune 同时拒绝过长编码和代理区编码
			_, size := utf8.DecodeRune(data[i:])
			if size > 1 {
				buf = append(buf, data[i:i+size]...)
				i += size
			} else {
				buf = append(buf, c)
				i++
			}
		default:
			buf = append(buf, c)
			i++
		}
	}
	return buf
}

// appendHex 追加小写十六进制形式的 \xNN。
func appendHex(buf []byte, c byte) []byte {
	const hexdigits = "0123456789abcdef"
	return append(buf, '\\', 'x', hexdigits[c>>4], hexdigits[c&0xf])
}

// writeLocationLine 写定位行。
func (w *Writer) writeLocationLine(b *Block) {
	if w.opt.TTY {
		// 定位行整体用紫色包住（不含末尾换行）
		w.buf = append(w.buf, "\x1b[35m"...)
	}
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
	if w.opt.TTY {
		w.buf = append(w.buf, "\x1b[m"...)
	}
	w.buf = append(w.buf, '\n')
}

// writeBinaryMessage 写二进制 body 的消息：从第一个 body 类 Piece 起的连续一段
// 换成一行占位，其余 Piece 原样输出。
func (w *Writer) writeBinaryMessage(m *Message) {
	i := 0
	for ; i < len(m.Pieces); i++ {
		if isBodyPiece(&m.Pieces[i]) {
			break
		}
		w.writePiece(&m.Pieces[i])
	}
	// 占位行
	if len(w.line) > 0 {
		// TTY 模式下先把暂存的行写出
		w.flushLine(true)
	} else if len(w.buf) > 0 && w.buf[len(w.buf)-1] != '\n' {
		w.buf = append(w.buf, '\n')
	}
	if w.opt.TTY {
		w.buf = append(w.buf, "\x1b[33m"...)
	}
	w.buf = append(w.buf, "[binary body omitted: "...)
	if m.ContentEncoding != "" {
		w.buf = append(w.buf, m.ContentEncoding...)
		if m.ContentType != "" {
			w.buf = append(w.buf, ", "...)
		}
	}
	if m.ContentType != "" {
		w.buf = append(w.buf, m.ContentType...)
		w.buf = append(w.buf, ", "...)
	} else if m.ContentEncoding != "" {
		w.buf = append(w.buf, ", "...)
	}
	w.buf = appendSize(w.buf, m.BodySize)
	if m.BodyMatched {
		w.buf = append(w.buf, ", matched"...)
	}
	w.buf = append(w.buf, "]"...)
	if w.opt.TTY {
		w.buf = append(w.buf, "\x1b[m"...)
	}
	w.buf = append(w.buf, '\n')
	// body 之后的部分
	for ; i < len(m.Pieces); i++ {
		if !isBodyPiece(&m.Pieces[i]) {
			break
		}
	}
	for ; i < len(m.Pieces); i++ {
		w.writePiece(&m.Pieces[i])
	}
	if n := len(w.buf); n > 0 && w.buf[n-1] != '\n' {
		w.buf = append(w.buf, '\n')
	}
}

// isBodyPiece 判断 Piece 是否属于 body 段。
func isBodyPiece(p *Piece) bool {
	return p.Kind == PieceBody || (p.Kind == PieceGap && p.InBody)
}

// appendSize 按人的习惯追加大小：小于 1024 写 N B，小于 1 MiB 写 %.1f KB，否则 %.1f MB。
func appendSize(buf []byte, n int64) []byte {
	switch {
	case n < 1024:
		buf = strconv.AppendInt(buf, n, 10)
		return append(buf, " B"...)
	case n < 1024*1024:
		buf = strconv.AppendFloat(buf, float64(n)/1024, 'f', 1, 64)
		return append(buf, " KB"...)
	default:
		buf = strconv.AppendFloat(buf, float64(n)/(1024*1024), 'f', 1, 64)
		return append(buf, " MB"...)
	}
}
func appendAddr(buf []byte, a netip.AddrPort) []byte {
	return a.AppendTo(buf)
}
