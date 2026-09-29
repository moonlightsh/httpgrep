package match_test

import (
	"fmt"
	"strings"
	"testing"

	"httpgrep/internal/match"
)

// genJSON 生成不含关键词命中的 JSON 文本。
func genJSON(n int) []byte {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "{\"id\":%d,\"name\":\"device-%d\",\"ch\":%d,\"ok\":true,\"ts\":\"2026-09-28T15:30:12.%03dZ\"}\n", i, i, i%16, i%1000)
	}
	return []byte(b.String())
}

// 4 KiB 分块写入不含命中的 JSON 文本，目标 1 GB/s 以上。
// 逐块扫一次即可（跳过续接的行首边界）
func BenchmarkScanFast4K(b *testing.B) {
	m, err := match.Compile([]string{"490419C6", "miss-me"}, false)
	if err != nil {
		b.Fatal(err)
	}
	chunk := genJSON(4096)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	s := m.NewScanner()
	for i := 0; i < b.N; i++ {
		s.Write(chunk)
		if s.Matched() {
			b.Fatal("unexpected match")
		}
	}
}
