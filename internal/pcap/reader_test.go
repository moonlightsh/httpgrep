package pcap_test

import (
	"bytes"
	"encoding/binary"
	"testing"

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

func TestNewReaderRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, pcap.ErrEmpty},
		{"one byte", []byte{0xa1}, pcap.ErrNotPcap},
		{"23 bytes", bytes.Repeat([]byte{0}, 23), pcap.ErrNotPcap},
		{"unknown magic", append([]byte{0xde, 0xad, 0xbe, 0xef}, bytes.Repeat([]byte{0}, 20)...), pcap.ErrNotPcap},
		{"pcapng magic", append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, bytes.Repeat([]byte{0x1a}, 20)...), pcap.ErrPcapNG},
		{"pcapng only 4 bytes", []byte{0x0a, 0x0d, 0x0d, 0x0a}, pcap.ErrPcapNG},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pcap.NewReader(bytes.NewReader(tt.in))
			if err == nil {
				t.Fatalf("NewReader(%q) = nil error, want %v", tt.name, tt.want)
			}
			if err != tt.want {
				t.Fatalf("NewReader(%q) error = %v, want %v", tt.name, err, tt.want)
			}
		})
	}
}
