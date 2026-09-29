package pcap_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"httpgrep/internal/pcap"
)

// FuzzReader 把任意字节流交给 NewReader 和 Next：不 panic，不无限循环，
// 每条记录的 Data 不超过剩余输入，OrigLen 不小于 len(Data)。
func FuzzReader(f *testing.F) {
	le := func(magic uint32, link uint32) []byte {
		h := make([]byte, 24)
		binary.LittleEndian.PutUint32(h[0:], magic)
		binary.LittleEndian.PutUint32(h[20:], link)
		return h
	}
	rec := func(caplen, origlen uint32, data []byte) []byte {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h[8:], caplen)
		binary.LittleEndian.PutUint32(h[12:], origlen)
		return append(h, data...)
	}
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x0d, 0x0d, 0x0a})
	f.Add(le(0xa1b2c3d4, 1))
	f.Add(append(le(0xa1b2c3d4, 1), rec(4, 4, []byte("abcd"))...))
	f.Add(append(le(0xa1b23c4d, 276), rec(0, 0, nil)...))
	f.Add(append(le(0xa1b2c3d4, 0), rec(0xffffffff, 1, nil)...))
	f.Add(append(le(0xa1b2c3d4, 101), rec(10, 3, []byte("short"))...))
	f.Fuzz(func(t *testing.T, in []byte) {
		r, err := pcap.NewReader(bytes.NewReader(in))
		if err != nil {
			if r != nil {
				t.Fatal("NewReader returned both reader and error")
			}
			return
		}
		_ = r.LinkType()
		rest := len(in) - 24
		// 每条记录至少消耗 16 字节记录头，Next 次数有上界。
		for i := 0; ; i++ {
			if i > rest/16+1 {
				t.Fatalf("Next did not terminate after %d records on %d bytes", i, len(in))
			}
			p, err := r.Next()
			if err != nil {
				if err != io.EOF && err != pcap.ErrCorrupt {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			rest -= 16 + len(p.Data)
			if rest < 0 {
				t.Fatalf("record data beyond input: rest=%d", rest)
			}
			if p.OrigLen < len(p.Data) {
				t.Fatalf("OrigLen %d < caplen %d", p.OrigLen, len(p.Data))
			}
		}
	})
}
