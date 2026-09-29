package decode_test

import (
	"testing"
	"unsafe"

	"httpgrep/internal/decode"
	"httpgrep/internal/pcap"
)

// fuzzLinks 是 fuzz 时轮流尝试的链路层类型，含两个不支持的。
var fuzzLinks = []pcap.LinkType{
	pcap.LinkNull, pcap.LinkEthernet, 12, 14, pcap.LinkRaw, pcap.LinkLoop,
	pcap.LinkLinuxSLL, pcap.LinkLinuxSLL2, 9, 0xffff,
}

// FuzzDecode 把任意帧按各种链路层类型解码：不 panic；OK 时 Payload 落在帧内，
// Missing 不为负。origLen 取 pcap.Reader 能给出的范围：不小于 len(data)，不超过 32 位。
func FuzzDecode(f *testing.F) {
	eth := func(et uint16, ip []byte) []byte {
		b := make([]byte, 14, 14+len(ip))
		b[12], b[13] = byte(et>>8), byte(et)
		return append(b, ip...)
	}
	v4 := []byte{0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
		0x30, 0x39, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0}
	v6 := make([]byte, 60)
	v6[0], v6[6] = 0x60, 6
	v6[5] = 20
	v6[52] = 0x50
	v6ext := make([]byte, 68)
	v6ext[0], v6ext[6] = 0x60, 0 // 逐跳选项
	v6ext[40], v6ext[41] = 6, 0
	v6ext[60] = 0x50
	f.Add(uint16(1), eth(0x0800, v4), uint32(0))
	f.Add(uint16(1), eth(0x8100, append([]byte{0, 1, 0x08, 0}, v4...)), uint32(0))
	f.Add(uint16(101), v4, uint32(1500))
	f.Add(uint16(101), v6, uint32(0))
	f.Add(uint16(101), v6ext, uint32(0))
	f.Add(uint16(0), append([]byte{2, 0, 0, 0}, v4...), uint32(0))
	f.Add(uint16(113), append(make([]byte, 14), append([]byte{0x08, 0}, v4...)...), uint32(0))
	f.Add(uint16(276), append([]byte{0x86, 0xdd}, append(make([]byte, 18), v6...)...), uint32(0))
	tso := append([]byte(nil), v4...)
	tso[2], tso[3] = 0, 0
	f.Add(uint16(101), tso, uint32(9000))
	f.Fuzz(func(t *testing.T, sel uint16, data []byte, orig uint32) {
		origLen := max(int(orig), len(data))
		links := fuzzLinks
		if int(sel) < 0x8000 {
			links = []pcap.LinkType{fuzzLinks[int(sel)%len(fuzzLinks)]}
		}
		lo := uintptr(unsafe.Pointer(unsafe.SliceData(data)))
		hi := lo + uintptr(len(data))
		for _, link := range links {
			var seg decode.Segment
			res := decode.Decode(link, data, origLen, &seg)
			if res != decode.OK {
				continue
			}
			if !decode.Supported(link) {
				t.Fatalf("link %d unsupported but decoded", link)
			}
			if seg.Missing < 0 {
				t.Fatalf("negative Missing %d", seg.Missing)
			}
			if n := len(seg.Payload); n > 0 {
				p := uintptr(unsafe.Pointer(unsafe.SliceData(seg.Payload)))
				if p < lo || p+uintptr(n) > hi {
					t.Fatalf("payload [%#x,+%d) outside frame [%#x,%#x)", p, n, lo, hi)
				}
			}
			if len(seg.Payload)+seg.Missing > origLen {
				t.Fatalf("payload %d + missing %d > origLen %d", len(seg.Payload), seg.Missing, origLen)
			}
		}
	})
}
