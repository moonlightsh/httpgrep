package match_test

import (
	"testing"

	"httpgrep/internal/match"
)

// 字面匹配：区分大小写，任一关键词命中即命中。
func TestLiteralCaseSensitive(t *testing.T) {
	m, err := match.Compile([]string{"Device"}, false)
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewScanner()
	s.Write([]byte("POST /api/Device/bind HTTP/1.1\n"))
	if !s.Matched() {
		t.Fatal("want match for exact case")
	}

	m2, _ := match.Compile([]string{"device"}, false)
	s2 := m2.NewScanner()
	s2.Write([]byte("POST /api/device/bind HTTP/1.1\n"))
	if !s2.Matched() {
		t.Fatal("device is lowercase in the line, should match")
	}

	m3, _ := match.Compile([]string{"DEVICE"}, false)
	s3 := m3.NewScanner()
	s3.Write([]byte("POST /api/Device/bind HTTP/1.1\n"))
	if s3.Matched() {
		t.Fatal("want no match for different case")
	}
}

// 多个关键词中任意一个命中就算命中。
func TestAnyPatternMatches(t *testing.T) {
	m, _ := match.Compile([]string{"zzz", "sn"}, false)
	s := m.NewScanner()
	s.Write([]byte(`{"sn":"4904"}` + "\n"))
	if !s.Matched() {
		t.Fatal("second pattern should match")
	}
}

// 空关键词匹配任何行，包括空行。
func TestEmptyPatternMatchesEverything(t *testing.T) {
	m, err := match.Compile([]string{""}, false)
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewScanner()
	s.Write([]byte("\n"))
	if !s.Matched() {
		t.Fatal("empty pattern should match empty line")
	}
}

// 跨多次 Write 的命中也能找到；跨行、跨 Break 的不算。
func TestMatchAcrossWritesNotLines(t *testing.T) {
	m, _ := match.Compile([]string{"490419C6"}, false)
	s := m.NewScanner()
	s.Write([]byte(`{"sn":"4904`))
	s.Write([]byte(`19C6117A"}` + "\n"))
	if !s.Matched() {
		t.Fatal("match spanning two Write calls should be found")
	}

	// 跨行不算：同一行内没有完整关键词。
	m2, _ := match.Compile([]string{"490419C6"}, false)
	s2 := m2.NewScanner()
	s2.Write([]byte("4904\n19C6\n"))
	if s2.Matched() {
		t.Fatal("match must not span lines")
	}

	// 跨 Break 不算：Break 等同于行结束。
	m3, _ := match.Compile([]string{"490419C6"}, false)
	s3 := m3.NewScanner()
	s3.Write([]byte("4904"))
	s3.Break()
	s3.Write([]byte("19C6\n"))
	if s3.Matched() {
		t.Fatal("match must not span Break")
	}
}

// Reset 后可以重新扫描。
func TestScannerReset(t *testing.T) {
	m, _ := match.Compile([]string{"hit"}, false)
	s := m.NewScanner()
	s.Write([]byte("a hit b\n"))
	if !s.Matched() {
		t.Fatal("expected match")
	}
	s.Reset()
	if s.Matched() {
		t.Fatal("after Reset, matched should be false")
	}
	s.Write([]byte("no such thing\n"))
	s.Break()
	if s.Matched() {
		t.Fatal("should not match after reset on clean data")
	}
	// Reset 后未完成的行缓冲也清空：跨 Reset 拼接不算命中。
	s.Reset()
	s.Write([]byte("hi"))
	s.Reset()
	s.Write([]byte("t here\n"))
	if s.Matched() {
		t.Fatal("partial line buffer must be cleared by Reset")
	}
}

// 行尾的 \r 不算行内容。
func TestTrailingCRNotPartOfLine(t *testing.T) {
	// 关键词 abc\r 不命中 abc\r\n（行内容是 abc）。
	m, err := match.Compile([]string{"abc\r"}, false)
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewScanner()
	s.Write([]byte("abc\r\n"))
	if s.Matched() {
		t.Fatal("abc\\r should not match line abc (trailing CR stripped)")
	}
}
