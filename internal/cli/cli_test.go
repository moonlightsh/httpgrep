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
