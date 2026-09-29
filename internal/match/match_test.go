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
