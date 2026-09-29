package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// 读 pcap 流时的错误。
var (
	ErrEmpty   = errors.New("empty input")
	ErrPcapNG  = errors.New("pcapng is not supported; capture with tcpdump -w")
	ErrNotPcap = errors.New("input is not a pcap stream; pipe it from tcpdump -U -w -")
	ErrCorrupt = errors.New("corrupt pcap record")
)

const (
	fileHeaderLen = 24
	recHeaderLen  = 16
	// maxCaplen 是单条记录允许的最大 caplen，超过视为损坏数据。
	maxCaplen = 16 << 20
	// nanosPerMicro 是纳秒与微秒的换算系数。
	nanosPerMicro = 1000
)

// Reader 顺序读取 pcap 流里的记录。
type Reader struct {
	r     *bufio.Reader
	bo    binary.ByteOrder // 文件头之后的记录头也用同一字节序
	nanos bool             // 时间戳是纳秒精度
	link  LinkType
	buf   [recHeaderLen]byte
	data  []byte // 复用的记录数据缓冲区
}

// NewReader 读取并校验 24 字节的 pcap 文件头。
// 底层 reader 报的非 EOF 错误原样返回，不归入 ErrEmpty/ErrPcapNG/ErrNotPcap。
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	var hdr [fileHeaderLen]byte
	n, err := io.ReadFull(br, hdr[:])
	if err != nil {
		if err == io.EOF {
			return nil, ErrEmpty
		}
		if err != io.ErrUnexpectedEOF {
			return nil, err
		}
		// 只有 4 字节且是 pcapng 的 magic 时也能识别。
		if n >= 4 && binary.BigEndian.Uint32(hdr[0:4]) == 0x0a0d0d0a {
			return nil, ErrPcapNG
		}
		return nil, ErrNotPcap
	}
	switch binary.BigEndian.Uint32(hdr[0:4]) {
	case 0xa1b2c3d4:
		return newReader(br, binary.BigEndian, false, hdr)
	case 0xd4c3b2a1:
		return newReader(br, binary.LittleEndian, false, hdr)
	case 0xa1b23c4d:
		return newReader(br, binary.BigEndian, true, hdr)
	case 0x4d3cb2a1:
		return newReader(br, binary.LittleEndian, true, hdr)
	case 0x0a0d0d0a:
		return nil, ErrPcapNG
	default:
		return nil, ErrNotPcap
	}
}

// newReader 按已识别的 magic 解析文件头的其余字段。
func newReader(br *bufio.Reader, bo binary.ByteOrder, nanos bool, hdr [fileHeaderLen]byte) (*Reader, error) {
	return &Reader{
		r:     br,
		bo:    bo,
		nanos: nanos,
		link:  LinkType(bo.Uint32(hdr[20:24])),
	}, nil
}

// LinkType 返回文件头 network 字段的低 16 位。
func (r *Reader) LinkType() LinkType {
	return r.link & 0xffff
}

// Next 返回下一条记录。正常结束，或者最后一条记录不完整时，返回 io.EOF。
//
// 返回 ErrCorrupt 或底层 reader 的 I/O 错误以后，流的位置已经不可信，
// 调用方应停止读取，不要再调用 Next。
//
// Timestamp 由 time.Unix 生成，带本地时区；比较时间请用 Time.Equal，不要用 ==。
func (r *Reader) Next() (Packet, error) {
	if _, err := io.ReadFull(r.r, r.buf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Packet{}, io.EOF
		}
		return Packet{}, err
	}
	caplen := int(r.bo.Uint32(r.buf[8:12]))
	if uint32(caplen) > maxCaplen {
		return Packet{}, ErrCorrupt
	}
	origlen := int(r.bo.Uint32(r.buf[12:16]))
	if origlen < caplen {
		origlen = caplen
	}
	if cap(r.data) < caplen {
		r.data = make([]byte, caplen)
	}
	data := r.data[:caplen]
	if _, err := io.ReadFull(r.r, data); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Packet{}, io.EOF
		}
		return Packet{}, err
	}
	sec := r.bo.Uint32(r.buf[0:4])
	frac := r.bo.Uint32(r.buf[4:8])
	ts := time.Unix(int64(sec), 0)
	if r.nanos {
		ts = ts.Add(time.Duration(frac) * time.Nanosecond)
	} else {
		ts = ts.Add(time.Duration(frac) * time.Microsecond)
	}
	return Packet{Timestamp: ts, Data: data, OrigLen: origlen}, nil
}
