package cli_test

import (
	"testing"
	"time"

	"httpgrep/internal/cli"
)

// 第 1 条：默认值。
func TestParseDefaults(t *testing.T) {
	opts, err := cli.Parse([]string{"keyword", "capture.pcap"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", opts.Timeout)
	}
	if opts.MaxMemory != 256<<20 {
		t.Errorf("MaxMemory = %d, want %d", opts.MaxMemory, 256<<20)
	}
	if opts.MaxMessage != 8<<20 {
		t.Errorf("MaxMessage = %d, want %d", opts.MaxMessage, 8<<20)
	}
	if opts.CPUs != 1 {
		t.Errorf("CPUs = %d, want 1", opts.CPUs)
	}
	if opts.Regex {
		t.Errorf("Regex 默认应为 false")
	}
	if opts.Stats || opts.Help || opts.Version {
		t.Errorf("Stats/Help/Version 默认应为 false")
	}
}

// 第 2 条：不带 -e 时第一个非选项参数是关键词，第二个是文件。
func TestParsePositionalPatternAndFile(t *testing.T) {
	opts, err := cli.Parse([]string{"keyword", "capture.pcap"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(opts.Patterns) != 1 || opts.Patterns[0] != "keyword" {
		t.Errorf("Patterns = %v, want [keyword]", opts.Patterns)
	}
	if opts.File != "capture.pcap" {
		t.Errorf("File = %q, want capture.pcap", opts.File)
	}

	// 只有关键词时从标准输入读。
	opts, err = cli.Parse([]string{"keyword"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.File != "" {
		t.Errorf("File = %q, want \"\"", opts.File)
	}
}

// 第 2 条：文件参数最多一个。
func TestParseTooManyFiles(t *testing.T) {
	_, err := cli.Parse([]string{"keyword", "a.pcap", "b.pcap"})
	if err == nil || err.Error() != "only one input file is supported" {
		t.Fatalf("err = %v, want only one input file is supported", err)
	}
	_, err = cli.Parse([]string{"-e", "keyword", "a.pcap", "b.pcap"})
	if err == nil || err.Error() != "only one input file is supported" {
		t.Fatalf("with -e: err = %v, want only one input file is supported", err)
	}
}

// 第 2 条：带 -e 时非选项参数都是文件。
func TestParseFileWithE(t *testing.T) {
	opts, err := cli.Parse([]string{"-e", "keyword", "a.pcap"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.File != "a.pcap" {
		t.Errorf("File = %q, want a.pcap", opts.File)
	}
	if len(opts.Patterns) != 1 || opts.Patterns[0] != "keyword" {
		t.Errorf("Patterns = %v, want [keyword]", opts.Patterns)
	}
}

// 第 2 条：没有关键词时报错。
func TestParseNoPattern(t *testing.T) {
	_, err := cli.Parse(nil)
	if err == nil || err.Error() != "no pattern given" {
		t.Fatalf("err = %v, want no pattern given", err)
	}
}

// 第 3 条：-- 之后的参数一律不当选项；单独的 - 是文件参数。
func TestParseDashDashAndDash(t *testing.T) {
	opts, err := cli.Parse([]string{"kw", "--", "--timeout"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.File != "--timeout" {
		t.Errorf("File = %q, want --timeout", opts.File)
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("Timeout 被修改为 %v", opts.Timeout)
	}

	opts, err = cli.Parse([]string{"kw", "-"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.File != "-" {
		t.Errorf("File = %q, want -", opts.File)
	}
}

// 第 3 条：选项和非选项参数任意交错。
func TestParseInterleaved(t *testing.T) {
	opts, err := cli.Parse([]string{"kw", "--stats", "a.pcap", "--cpus", "4"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(opts.Patterns) != 1 || opts.Patterns[0] != "kw" {
		t.Errorf("Patterns = %v", opts.Patterns)
	}
	if !opts.Stats {
		t.Error("Stats 应为 true")
	}
	if opts.File != "a.pcap" {
		t.Errorf("File = %q, want a.pcap", opts.File)
	}
	if opts.CPUs != 4 {
		t.Errorf("CPUs = %d, want 4", opts.CPUs)
	}
}

// 第 4 条：长短选项的各种写法。
func TestParseOptionForms(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want cli.Options
	}{
		{"long= form", []string{"--timeout=5s", "kw"}, cli.Options{Timeout: 5 * time.Second}},
		{"long space form", []string{"--timeout", "5s", "kw"}, cli.Options{Timeout: 5 * time.Second}},
		{"short space form", []string{"-e", "kw"}, cli.Options{Patterns: []string{"kw"}}},
		{"short glued form", []string{"-ekw"}, cli.Options{Patterns: []string{"kw"}}},
		{"short combined", []string{"-Ee", "kw"}, cli.Options{Regex: true, Patterns: []string{"kw"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := cli.Parse(c.args)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if c.want.Timeout != 0 && got.Timeout != c.want.Timeout {
				t.Errorf("Timeout = %v, want %v", got.Timeout, c.want.Timeout)
			}
			if got.Regex != c.want.Regex {
				t.Errorf("Regex = %v, want %v", got.Regex, c.want.Regex)
			}
			if c.want.Patterns != nil && len(got.Patterns) != len(c.want.Patterns) {
				t.Fatalf("Patterns = %v, want %v", got.Patterns, c.want.Patterns)
			}
			for i := range got.Patterns {
				if c.want.Patterns != nil && got.Patterns[i] != c.want.Patterns[i] {
					t.Errorf("Patterns[%d] = %q, want %q", i, got.Patterns[i], c.want.Patterns[i])
				}
			}
		})
	}
}

// 第 5 条：大小解析。
func TestParseSizes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"100", 100},
		{"512K", 524288},
		{"512k", 524288},
		{"1M", 1 << 20},
		{"1m", 1 << 20},
		{"2G", 2 << 30},
	}
	for _, c := range cases {
		opts, err := cli.Parse([]string{"--max-memory=" + c.in, "--max-message=1", "kw"})
		if err != nil {
			t.Fatalf("--max-memory %s: %v", c.in, err)
		}
		if opts.MaxMemory != c.want {
			t.Errorf("--max-memory %s = %d, want %d", c.in, opts.MaxMemory, c.want)
		}
	}
	for _, bad := range []string{"0", "-5", "abc", "", "1Q", "1Kx"} {
		_, err := cli.Parse([]string{"--max-memory=" + bad, "kw"})
		if err == nil {
			t.Errorf("--max-memory %q 应报错", bad)
		}
	}
	// MaxMessage 大于 MaxMemory 时报错。
	_, err := cli.Parse([]string{"--max-memory=1M", "--max-message=2M", "kw"})
	if err == nil {
		t.Error("max-message > max-memory 应报错")
	}
	// 负数形式会被当成选项串处理，必须报错而不是被当成文件。
	_, err = cli.Parse([]string{"--max-memory", "-5", "kw"})
	if err == nil {
		t.Error("--max-memory -5 应报错")
	}
}

// 第 6 条：时长与 CPU 数。
func TestParseDurationAndCPUs(t *testing.T) {
	opts, err := cli.Parse([]string{"--timeout", "2m", "--cpus", "8", "kw"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.Timeout != 2*time.Minute {
		t.Errorf("Timeout = %v, want 2m", opts.Timeout)
	}
	if opts.CPUs != 8 {
		t.Errorf("CPUs = %d, want 8", opts.CPUs)
	}
	for _, bad := range []string{"0s", "-1s", "abc", "0"} {
		_, err := cli.Parse([]string{"--timeout=" + bad, "kw"})
		if err == nil {
			t.Errorf("--timeout %q 应报错", bad)
		}
	}
	for _, bad := range []string{"0", "-1", "x"} {
		_, err := cli.Parse([]string{"--cpus=" + bad, "kw"})
		if err == nil {
			t.Errorf("--cpus %q 应报错", bad)
		}
	}
}

// 第 7 条：关键词里的换行拆成多个。
func TestParseSplitLines(t *testing.T) {
	opts, err := cli.Parse([]string{"-e", "a\nb"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(opts.Patterns) != 2 || opts.Patterns[0] != "a" || opts.Patterns[1] != "b" {
		t.Errorf("Patterns = %v, want [a b]", opts.Patterns)
	}
	// 位置参数形式同样拆分；首尾空段也应产生。
	opts, err = cli.Parse([]string{"x\ny\n", "f.pcap"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(opts.Patterns) != 3 || opts.Patterns[0] != "x" || opts.Patterns[1] != "y" || opts.Patterns[2] != "" {
		t.Errorf("Patterns = %v, want [x y ]", opts.Patterns)
	}
	if opts.File != "f.pcap" {
		t.Errorf("File = %q", opts.File)
	}
}
