package pcap_test

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"httpgrep/internal/pcap"
)

func heapAlloc() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

// 单条大记录（8 MiB）读完之后，Reader 不一直留着那么大的缓冲区：
// 之后只读小记录时，Reader 留着的内存不超过 1 MiB（bufio 的缓冲区在读文件头时就已分配）。
func TestBigRecordBufferReleased(t *testing.T) {
	le := binary.LittleEndian
	var in bytes.Buffer
	in.Write(fileHeader(le, 0xa1b2c3d4, 1))
	big := make([]byte, 8<<20)
	in.Write(recBlock(le, 1, 0, big, uint32(len(big))))
	for i := range 100 {
		in.Write(recBlock(le, uint32(2+i), 0, []byte("small"), 5))
	}
	r, err := pcap.NewReader(bytes.NewReader(in.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	before := heapAlloc()
	for range 101 {
		if _, err := r.Next(); err != nil {
			t.Fatal(err)
		}
	}
	grown := heapAlloc() - before
	runtime.KeepAlive(r)
	if grown > 1<<20 {
		t.Fatalf("Reader retains %d bytes after a big record", grown)
	}
}
