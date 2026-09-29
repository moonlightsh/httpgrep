package pcap_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"httpgrep/internal/pcap"
)

// 最后一条记录的头或数据不完整时，前面完整的记录照常返回，之后是 io.EOF。
func TestNextTruncatedTail(t *testing.T) {
	checkTruncatedTail(t, func(r io.Reader) io.Reader { return r })
}

// checkTruncatedTail 用 wrap 包装输入后检查末尾截断的各种长度。
func checkTruncatedTail(t *testing.T, wrap func(io.Reader) io.Reader) {
	le := binary.LittleEndian
	full := recBlock(le, 1, 0, []byte("first"), 5)
	truncated := recBlock(le, 2, 0, []byte("second-half-cut"), 14)
	for _, n := range []int{0, 5, 15, 23} { // 0：正常结束；5/15：记录头不完整；23：头完整、数据只有 7 字节
		t.Run(fmt.Sprintf("tail %d bytes", n), func(t *testing.T) {
			in := append([]byte{}, fileHeader(le, 0xa1b2c3d4, 1)...)
			in = append(in, full...)
			in = append(in, truncated[:n]...)
			r, err := pcap.NewReader(wrap(bytes.NewReader(in)))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			got, err := r.Next()
			if err != nil || string(got.Data) != "first" {
				t.Fatalf("第一条 = (%q, %v), want (\"first\", nil)", got.Data, err)
			}
			if _, err := r.Next(); err != io.EOF {
				t.Fatalf("第二条 err = %v, want io.EOF", err)
			}
		})
	}
}

// caplen 超过 16 MiB 返回 ErrCorrupt；origlen 小于 caplen 时取 caplen。
func TestNextCaplenAndOriglen(t *testing.T) {
	le := binary.LittleEndian
	t.Run("caplen over limit", func(t *testing.T) {
		in := append([]byte{}, fileHeader(le, 0xa1b2c3d4, 1)...)
		hdr := make([]byte, 16)
		le.PutUint32(hdr[8:12], uint32(16<<20+1)) // caplen
		le.PutUint32(hdr[12:16], 16<<20+1)        // origlen
		in = append(in, hdr...)
		r, err := pcap.NewReader(bytes.NewReader(in))
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		if _, err := r.Next(); err != pcap.ErrCorrupt {
			t.Fatalf("Next() err = %v, want ErrCorrupt", err)
		}
	})
	t.Run("origlen clamped to caplen", func(t *testing.T) {
		in := append([]byte{}, fileHeader(le, 0xa1b2c3d4, 1)...)
		in = append(in, recBlock(le, 3, 0, []byte("12345"), 2)...) // origlen=2 < caplen=5
		r, err := pcap.NewReader(bytes.NewReader(in))
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		got, err := r.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if got.OrigLen != 5 || len(got.Data) != 5 {
			t.Fatalf("OrigLen = %d, len(Data) = %d, want 5, 5", got.OrigLen, len(got.Data))
		}
	})
}

// caplen 恰好 16 MiB（16777216 字节）时不算超限，记录正常返回。
func TestNextCaplenAtLimit(t *testing.T) {
	le := binary.LittleEndian
	in := append([]byte{}, fileHeader(le, 0xa1b2c3d4, 1)...)
	in = append(in, recBlock(le, 1, 0, make([]byte, 16777216), 16777216)...)
	r, err := pcap.NewReader(bytes.NewReader(in))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(got.Data) != 16777216 || got.OrigLen != 16777216 {
		t.Fatalf("len(Data) = %d, OrigLen = %d, want 16777216, 16777216", len(got.Data), got.OrigLen)
	}
}
