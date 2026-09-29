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

// 正则模式 4 KiB 分块，行缓存路径。
func BenchmarkScanRegex4K(b *testing.B) {
	m, err := match.Compile([]string{`"sn":"\d+"`, `(?i)error`}, true)
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
	}
}

// Highlight 基准。
func BenchmarkHighlight(b *testing.B) {
	m, _ := match.Compile([]string{"device", "true"}, false)
	line := []byte(`{"id":123,"name":"device-45","ok":true,"ts":"2026-09-28T15:30:12.345Z"}`)
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Highlight(line)
	}
}

// 快速路径整块扫描的稳态分配（含块边界候选更新）。
func BenchmarkFastTailUpdate(b *testing.B) {
	m, _ := match.Compile([]string{"keyword"}, false)
	s := m.NewScanner()
	chunk := []byte("some line without keyword\n") // 每块以 \n 结束
	s.Write(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Write(chunk)
		s.Break()
	}
}
