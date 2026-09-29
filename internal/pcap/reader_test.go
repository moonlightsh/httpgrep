package pcap_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
	"time"

	"httpgrep/internal/pcap"
)

// fileHeader 构造 24 字节的 pcap 文件头。
func fileHeader(bo binary.ByteOrder, magic, network uint32) []byte {
	b := make([]byte, 24)
	bo.PutUint32(b[0:4], magic)
	bo.PutUint16(b[4:6], 2) // version_major
	bo.PutUint16(b[6:8], 4) // version_minor
	bo.PutUint32(b[8:12], 0)
	bo.PutUint32(b[12:16], 0)
	bo.PutUint32(b[16:20], 262144) // snaplen
	bo.PutUint32(b[20:24], network)
	return b
}

// recBlock 构造一条完整的 pcap 记录（头 + 数据）。
func recBlock(bo binary.ByteOrder, sec, frac uint32, data []byte, origlen uint32) []byte {
	b := make([]byte, 16+len(data))
	bo.PutUint32(b[0:4], sec)
	bo.PutUint32(b[4:8], frac)
	bo.PutUint32(b[8:12], uint32(len(data)))
	bo.PutUint32(b[12:16], origlen)
	copy(b[16:], data)
	return b
}

type badInputCase struct {
	name string
	in   []byte
	want error
}

// badInputCases 是 NewReader 应当拒绝的输入。
func badInputCases() []badInputCase {
	return []badInputCase{
		{"empty", nil, pcap.ErrEmpty},
		{"one byte", []byte{0xa1}, pcap.ErrNotPcap},
		{"23 bytes", bytes.Repeat([]byte{0}, 23), pcap.ErrNotPcap},
		{"unknown magic", append([]byte{0xde, 0xad, 0xbe, 0xef}, bytes.Repeat([]byte{0}, 20)...), pcap.ErrNotPcap},
		{"pcapng magic", append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, bytes.Repeat([]byte{0x1a}, 20)...), pcap.ErrPcapNG},
		{"pcapng only 4 bytes", []byte{0x0a, 0x0d, 0x0d, 0x0a}, pcap.ErrPcapNG},
	}
}

func TestNewReaderRejectsBadInput(t *testing.T) {
	checkBadInput(t, func(r io.Reader) io.Reader { return r })
}

// checkBadInput 用 wrap 包装输入后跑一遍 badInputCases。
func checkBadInput(t *testing.T, wrap func(io.Reader) io.Reader) {
	for _, tt := range badInputCases() {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pcap.NewReader(wrap(bytes.NewReader(tt.in)))
			if err == nil {
				t.Fatalf("NewReader(%q) = nil error, want %v", tt.name, tt.want)
			}
			if err != tt.want {
				t.Fatalf("NewReader(%q) error = %v, want %v", tt.name, err, tt.want)
			}
		})
	}
}

type recordCase struct {
	name  string
	in    []byte
	link  pcap.LinkType
	wants []pcap.Packet
}

// recordCases 覆盖 4 种 magic。手算：3 秒 + 123456 微秒 = 3.123456000 秒。
func recordCases() []recordCase {
	le := binary.LittleEndian
	be := binary.BigEndian
	var usecBE []byte
	usecBE = append(usecBE, fileHeader(be, 0xa1b2c3d4, 1)...)
	usecBE = append(usecBE, recBlock(be, 3, 123456, []byte("GET / HTTP"), 10)...)
	usecBE = append(usecBE, recBlock(be, 4, 0, []byte{0xde}, 1)...)

	var nsecLE []byte
	nsecLE = append(nsecLE, fileHeader(le, 0xa1b23c4d, 113)...)
	nsecLE = append(nsecLE, recBlock(le, 5, 987654321, []byte("abc"), 99)...)

	var usecLE []byte
	usecLE = append(usecLE, fileHeader(le, 0xa1b2c3d4, 101)...)
	usecLE = append(usecLE, recBlock(le, 9, 1, []byte("xyz"), 3)...)

	var nsecBE []byte
	nsecBE = append(nsecBE, fileHeader(be, 0xa1b23c4d, 0)...)
	nsecBE = append(nsecBE, recBlock(be, 7, 42, []byte("q"), 1)...)

	return []recordCase{
		{
			name: "usec big endian",
			in:   usecBE,
			link: pcap.LinkEthernet,
			wants: []pcap.Packet{
				{Timestamp: time.Unix(3, 123456000), Data: []byte("GET / HTTP"), OrigLen: 10},
				{Timestamp: time.Unix(4, 0), Data: []byte{0xde}, OrigLen: 1},
			},
		},
		{
			name: "nsec little endian",
			in:   nsecLE,
			link: pcap.LinkLinuxSLL,
			wants: []pcap.Packet{
				{Timestamp: time.Unix(5, 987654321), Data: []byte("abc"), OrigLen: 99},
			},
		},
		{
			name: "usec little endian",
			in:   usecLE,
			link: pcap.LinkRaw,
			wants: []pcap.Packet{
				{Timestamp: time.Unix(9, 1000), Data: []byte("xyz"), OrigLen: 3},
			},
		},
		{
			name: "nsec big endian",
			in:   nsecBE,
			link: pcap.LinkNull,
			wants: []pcap.Packet{
				{Timestamp: time.Unix(7, 42), Data: []byte("q"), OrigLen: 1},
			},
		},
	}
}

func TestNextReadsRecords(t *testing.T) {
	checkRecords(t, func(r io.Reader) io.Reader { return r })
}

// checkRecords 用 wrap 包装输入后跑一遍 recordCases。
func checkRecords(t *testing.T, wrap func(io.Reader) io.Reader) {
	for _, tt := range recordCases() {
		t.Run(tt.name, func(t *testing.T) {
			r, err := pcap.NewReader(wrap(bytes.NewReader(tt.in)))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			if got := r.LinkType(); got != tt.link {
				t.Fatalf("LinkType() = %v, want %v", got, tt.link)
			}
			for i, want := range tt.wants {
				got, err := r.Next()
				if err != nil {
					t.Fatalf("第 %d 条: %v", i, err)
				}
				if !got.Timestamp.Equal(want.Timestamp) {
					t.Errorf("第 %d 条时间戳 = %v, want %v", i, got.Timestamp, want.Timestamp)
				}
				if !bytes.Equal(got.Data, want.Data) {
					t.Errorf("第 %d 条数据 = %q, want %q", i, got.Data, want.Data)
				}
				if got.OrigLen != want.OrigLen {
					t.Errorf("第 %d 条 OrigLen = %d, want %d", i, got.OrigLen, want.OrigLen)
				}
			}
			if _, err := r.Next(); err != io.EOF {
				t.Errorf("结束后 Next() = %v, want io.EOF", err)
			}
		})
	}
}

// 底层 reader 每次只给 1 个字节时，所有用例的结果不变。
func TestNextWithOneByteReader(t *testing.T) {
	t.Run("bad input", func(t *testing.T) { checkBadInput(t, iotest.OneByteReader) })
	t.Run("records", func(t *testing.T) { checkRecords(t, iotest.OneByteReader) })
	t.Run("truncated tail", func(t *testing.T) { checkTruncatedTail(t, iotest.OneByteReader) })
}

// network 字段高 16 位带有其他信息时，LinkType 只取低 16 位：0x02a50071 → 113。
func TestLinkTypeLow16Bits(t *testing.T) {
	r, err := pcap.NewReader(bytes.NewReader(fileHeader(binary.BigEndian, 0xa1b2c3d4, 0x02a50071)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if got := r.LinkType(); got != pcap.LinkLinuxSLL {
		t.Fatalf("LinkType() = %d, want 113", got)
	}
}

// errBoom 模拟底层 reader 的 I/O 故障（比如 stdin 读失败）。
var errBoom = errors.New("boom")

// 读文件头时底层 reader 报的非 EOF 错误要原样透出，不能归成 ErrNotPcap 等格式错误。
func TestNewReaderPassesThroughIOError(t *testing.T) {
	le := binary.LittleEndian
	tests := []struct {
		name   string
		prefix []byte
	}{
		{"no bytes", nil},
		{"10 bytes of header", fileHeader(le, 0xa1b2c3d4, 1)[:10]},
		{"pcapng magic then error", []byte{0x0a, 0x0d, 0x0d, 0x0a}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := io.MultiReader(bytes.NewReader(tt.prefix), iotest.ErrReader(errBoom))
			_, err := pcap.NewReader(in)
			if !errors.Is(err, errBoom) {
				t.Fatalf("NewReader error = %v, want %v", err, errBoom)
			}
		})
	}
}
