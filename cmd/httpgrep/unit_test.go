package main

import (
	"runtime/debug"
	"testing"
)

// Go 运行时的软内存上限是 --max-memory 的 1.5 倍，很小的值也不能截断成 0
// （SetMemoryLimit(0) 会让 GC 一直运行）。
func TestMemoryLimit(t *testing.T) {
	for _, tc := range []struct{ in, want int64 }{
		{1, 1},
		{3, 4},
		{1025, 1537},
		{256 << 20, 384 << 20},
	} {
		if got := memoryLimit(tc.in); got != tc.want {
			t.Errorf("memoryLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// 构建时工作区有未提交的改动（vcs.modified=true）时，revision 后面加 -dirty。
func TestVersionFrom(t *testing.T) {
	for _, tc := range []struct {
		settings []debug.BuildSetting
		want     string
	}{
		{nil, "httpgrep dev\n"},
		{[]debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.modified", Value: "false"}}, "httpgrep dev (revision abc123)\n"},
		{[]debug.BuildSetting{{Key: "vcs.modified", Value: "true"}, {Key: "vcs.revision", Value: "abc123"}}, "httpgrep dev (revision abc123-dirty)\n"},
		{[]debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}, "httpgrep dev\n"},
	} {
		if got := versionFrom(tc.settings); got != tc.want {
			t.Errorf("versionFrom(%v) = %q, want %q", tc.settings, got, tc.want)
		}
	}
}
