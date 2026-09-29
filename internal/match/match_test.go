package match_test

import (
	"reflect"
	"strings"
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

// 命中之后 Write 直接返回，不再处理后续数据。
func TestEarlyReturnAfterMatch(t *testing.T) {
	m, _ := match.Compile([]string{"first"}, false)
	s := m.NewScanner()
	s.Write([]byte("first line\n"))
	if !s.Matched() {
		t.Fatal("expected match")
	}
	// 命中后再写入任何数据都不改变状态、不出错。
	s.Write([]byte("more data without newline"))
	s.Break()
	s.Write([]byte("tail"))
	if !s.Matched() {
		t.Fatal("Matched must stay true")
	}
}

// 正则按行匹配，^、$ 锚定行首行尾，支持 (?i)，多个正则合并编译。
func TestRegexLineMatching(t *testing.T) {
	m, err := match.Compile([]string{`^POST\s`, `(?i)content-type:\s*application/json`}, true)
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewScanner()
	s.Write([]byte("post /x HTTP/1.1\r\n"))
	if s.Matched() {
		t.Fatal("lowercase post should not match ^POST\\s")
	}
	s.Write([]byte("Content-Type: application/json\r\n"))
	if !s.Matched() {
		t.Fatal("(?i) pattern should match case-insensitively")
	}

	// $ 锚定行尾。
	m2, _ := match.Compile([]string{`json$`}, true)
	s2 := m2.NewScanner()
	s2.Write([]byte("Content-Type: application/json\r\n"))
	if !s2.Matched() {
		t.Fatal("$ should anchor at end of line with CR stripped")
	}
	s2r := m2.NewScanner()
	s2r.Write([]byte("jsonx\n"))
	if s2r.Matched() {
		t.Fatal("jsonx should not match json$")
	}
}

// 正则不合法时，Compile 的错误里包含这个关键词。
func TestRegexCompileErrorContainsPattern(t *testing.T) {
	_, err := match.Compile([]string{`ok`, `(unclosed`}, true)
	if err == nil {
		t.Fatal("expected compile error")
	}
	if !strings.Contains(err.Error(), "(unclosed") {
		t.Fatalf("error should mention the bad pattern, got: %v", err)
	}
}

// 正则模式下空关键词同样匹配所有行。
func TestEmptyRegexPatternMatchesEverything(t *testing.T) {
	m, err := match.Compile([]string{""}, true)
	if err != nil {
		t.Fatal(err)
	}
	s := m.NewScanner()
	s.Write([]byte("\n"))
	if !s.Matched() {
		t.Fatal("empty regex should match empty line")
	}
}

// Highlight 返回一行里所有命中的 [起, 止) 区间，按起点排序、互不重叠。
func TestHighlightLiteral(t *testing.T) {
	m, _ := match.Compile([]string{"ab"}, false)
	got := m.Highlight([]byte("abxabxab"))
	want := [][2]int{{0, 2}, {3, 5}, {6, 8}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	// 空关键词：整行都是命中区间。
	m2, _ := match.Compile([]string{""}, false)
	got2 := m2.Highlight([]byte("abc"))
	want2 := [][2]int{{0, 3}}
	if !reflect.DeepEqual(got2, want2) {
		t.Fatalf("empty pattern: got %v want %v", got2, want2)
	}

	// 重叠的区间合并：关键词 ab 和 bc 在 abc 里重叠。
	m3, _ := match.Compile([]string{"ab", "bc"}, false)
	got3 := m3.Highlight([]byte("abc"))
	want3 := [][2]int{{0, 3}}
	if !reflect.DeepEqual(got3, want3) {
		t.Fatalf("overlapping: got %v want %v", got3, want3)
	}
}

// 正则模式用 FindAllIndex，丢弃长度为 0 的区间。
func TestHighlightRegex(t *testing.T) {
	m, _ := match.Compile([]string{`\d+`, `x*`}, true)
	got := m.Highlight([]byte("a12b345c"))
	// \d+ 命中 12 和 345；x* 命中空区间（丢弃）以及非重叠的空串。
	want := [][2]int{{1, 3}, {4, 7}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	// 空正则关键词：整行。
	m2, _ := match.Compile([]string{""}, true)
	got2 := m2.Highlight([]byte("abc"))
	want2 := [][2]int{{0, 3}}
	if !reflect.DeepEqual(got2, want2) {
		t.Fatalf("empty regex: got %v want %v", got2, want2)
	}
}

// 正则 c$ 命中 abc\r\n（\r 去掉后 c 在行尾）。
func TestTrailingCRRegex(t *testing.T) {
	m, _ := match.Compile([]string{`c$`}, true)
	s := m.NewScanner()
	s.Write([]byte("abc\r\n"))
	if !s.Matched() {
		t.Fatal("c$ should match abc with trailing CR stripped")
	}
}

// 正则模式缓存没写完的行，上限 8 MiB，超出的部分不参与匹配。
func TestRegexLineBufferCap(t *testing.T) {
	const miB = 1 << 20
	m, _ := match.Compile([]string{"near-start"}, true)
	s := m.NewScanner()
	head := make([]byte, 100)
	copy(head, []byte("near-start"))
	s.Write(head)
	s.Write(make([]byte, 9*miB)) // 远超 8 MiB
	s.Break()
	if !s.Matched() {
		t.Fatal("keyword within first 8 MiB should match")
	}

	m2, _ := match.Compile([]string{"past-the-cap"}, true)
	s2 := m2.NewScanner()
	s2.Write(make([]byte, 8*miB+1024)) // 先填满并溢出
	s2.Write([]byte("past-the-cap"))   // 溢出之后的部分不参与匹配
	s2.Break()
	if s2.Matched() {
		t.Fatal("keyword past the 8 MiB cap must not match")
	}
}
