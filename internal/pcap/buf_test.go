package pcap_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"httpgrep/internal/pcap"
)

// loopReader 无限重放同一段记录字节，模拟持续到来的 pcap 流。
// 只重放记录部分；文件头由调用方用 io.MultiReader 放在最前面，只出现一次。
type loopReader struct {
	data []byte
	off  int
}

func (l *loopReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := copy(p[n:], l.data[l.off:])
		n += c
		l.off = (l.off + c) % len(l.data)
	}
	return n, nil
}

// endlessStream 返回“文件头一次 + 记录无限循环”的流。
func endlessStream(header, records []byte) io.Reader {
	return io.MultiReader(bytes.NewReader(header), &loopReader{data: records})
}

// mixedRecords 构造一批长短不一的小端微秒记录，最长 1500 字节。
func mixedRecords() []byte {
	le := binary.LittleEndian
	var in []byte
	for i, n := range []int{100, 60, 1500, 40, 1024, 1} {
		in = append(in, recBlock(le, uint32(i), 0, bytes.Repeat([]byte{byte('a' + i)}, n), uint32(n))...)
	}
	return in
}

// 连续调用 Next 时 Data 复用内部缓冲区，稳定状态下每条记录 0 次分配。
func TestNextZeroAllocSteadyState(t *testing.T) {
	r, err := pcap.NewReader(endlessStream(fileHeader(binary.LittleEndian, 0xa1b2c3d4, 1), mixedRecords()))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	for i := 0; i < 6; i++ { // 预热一整轮，让缓冲区扩到最长记录
		if _, err := r.Next(); err != nil {
			t.Fatalf("预热 Next: %v", err)
		}
	}
	allocs := testing.AllocsPerRun(3000, func() {
		if _, err := r.Next(); err != nil {
			t.Fatalf("Next: %v", err)
		}
	})
	if allocs != 0 {
		t.Fatalf("稳定状态每条记录分配 %v 次, want 0", allocs)
	}
}

// 后一条记录不比前一条长时，Data 与前一条共用同一块底层内存。
func TestNextDataReusesBuffer(t *testing.T) {
	le := binary.LittleEndian
	in := fileHeader(le, 0xa1b2c3d4, 1)
	in = append(in, recBlock(le, 1, 0, []byte("abcdefgh"), 8)...)
	in = append(in, recBlock(le, 2, 0, []byte("xyz"), 3)...)
	r, err := pcap.NewReader(bytes.NewReader(in))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	first, err := r.Next()
	if err != nil {
		t.Fatalf("第一条: %v", err)
	}
	second, err := r.Next()
	if err != nil {
		t.Fatalf("第二条: %v", err)
	}
	if &first.Data[0] != &second.Data[0] {
		t.Fatalf("两条记录的 Data 不共用缓冲区")
	}
	if string(second.Data) != "xyz" || string(first.Data[:3]) != "xyz" {
		t.Fatalf("second = %q, first[:3] = %q, want \"xyz\", \"xyz\"", second.Data, first.Data[:3])
	}
}

// sizeRecorder 记录底层 Read 收到的最大 len(p)，用来观察缓冲区大小。
type sizeRecorder struct {
	r   io.Reader
	max int
}

func (s *sizeRecorder) Read(p []byte) (int, error) {
	if len(p) > s.max {
		s.max = len(p)
	}
	return s.r.Read(p)
}

// Reader 用 1 MiB 的缓冲区读底层数据：每次向底层要 1 MiB（1048576 字节）。
func TestReaderUsesOneMiBBuffer(t *testing.T) {
	le := binary.LittleEndian
	in := fileHeader(le, 0xa1b2c3d4, 1)
	in = append(in, recBlock(le, 1, 0, []byte("abc"), 3)...)
	rec := &sizeRecorder{r: bytes.NewReader(in)}
	r, err := pcap.NewReader(rec)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := r.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if rec.max != 1048576 {
		t.Fatalf("底层 Read 的最大 len(p) = %d, want 1048576", rec.max)
	}
}

// BenchmarkNext 测持续流上逐条读 1 KiB 记录的吞吐，每条记录 16+1024 字节。
func BenchmarkNext(b *testing.B) {
	le := binary.LittleEndian
	payload := bytes.Repeat([]byte{0xab}, 1024)
	var records []byte
	for i := 0; i < 40; i++ { // 40 条一批循环重放
		records = append(records, recBlock(le, uint32(i), 0, payload, 1024)...)
	}
	r, err := pcap.NewReader(endlessStream(fileHeader(le, 0xa1b2c3d4, 1), records))
	if err != nil {
		b.Fatalf("NewReader: %v", err)
	}
	if _, err := r.Next(); err != nil { // 先分配好数据缓冲区
		b.Fatalf("Next: %v", err)
	}
	b.SetBytes(16 + 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := r.Next()
		if err != nil {
			b.Fatalf("Next: %v", err)
		}
		if len(p.Data) != 1024 {
			b.Fatalf("len(Data) = %d, want 1024", len(p.Data))
		}
	}
}
