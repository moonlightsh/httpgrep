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
