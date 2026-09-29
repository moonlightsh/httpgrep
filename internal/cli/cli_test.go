package cli_test

import (
	"strings"
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

// 第 2 条：-e 可以写多次，关键词按出现顺序累积。
func TestParseMultipleE(t *testing.T) {
	opts, err := cli.Parse([]string{"-e", "a", "-e", "b"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(opts.Patterns) != 2 || opts.Patterns[0] != "a" || opts.Patterns[1] != "b" {
		t.Errorf("Patterns = %v, want [a b]", opts.Patterns)
	}

	opts, err = cli.Parse([]string{"-e", "a\nb", "-ec"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(opts.Patterns) != 3 || opts.Patterns[0] != "a" || opts.Patterns[1] != "b" || opts.Patterns[2] != "c" {
		t.Errorf("Patterns = %v, want [a b c]", opts.Patterns)
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
		name     string
		args     []string
		timeout  time.Duration
		patterns []string
		regex    bool
	}{
		{"long= form", []string{"--timeout=5s", "kw"}, 5 * time.Second, []string{"kw"}, false},
		{"long space form", []string{"--timeout", "5s", "kw"}, 5 * time.Second, []string{"kw"}, false},
		{"short space form", []string{"-e", "kw"}, 30 * time.Second, []string{"kw"}, false},
		{"short glued form", []string{"-ekw"}, 30 * time.Second, []string{"kw"}, false},
		{"short combined", []string{"-Ee", "kw"}, 30 * time.Second, []string{"kw"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := cli.Parse(c.args)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Timeout != c.timeout {
				t.Errorf("Timeout = %v, want %v", got.Timeout, c.timeout)
			}
			if got.Regex != c.regex {
				t.Errorf("Regex = %v, want %v", got.Regex, c.regex)
			}
			if len(got.Patterns) != len(c.patterns) {
				t.Fatalf("Patterns = %v, want %v", got.Patterns, c.patterns)
			}
			for i := range got.Patterns {
				if got.Patterns[i] != c.patterns[i] {
					t.Errorf("Patterns[%d] = %q, want %q", i, got.Patterns[i], c.patterns[i])
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
		{"2g", 2 << 30},
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
	// 溢出与 ParseInt 越界都必须报错；前导 + 不算纯数字。
	for _, bad := range []string{"0", "-5", "abc", "", "1Q", "1Kx", "+5", "8589934592G", "9223372036854775807K", "99999999999999999999"} {
		_, err := cli.Parse([]string{"--max-memory=" + bad, "kw"})
		if err == nil {
			t.Errorf("--max-memory %q 应报错", bad)
			continue
		}
		// 错误消息带选项名和原始输入。
		want := "invalid size for --max-memory: " + bad
		if err.Error() != want {
			t.Errorf("err = %q, want %q", err.Error(), want)
		}
	}
	// MaxMessage 大于 MaxMemory 时报错；相等则合法。
	_, err := cli.Parse([]string{"--max-memory=1M", "--max-message=2M", "kw"})
	if err == nil {
		t.Error("max-message > max-memory 应报错")
	}
	opts, err := cli.Parse([]string{"--max-memory=1M", "--max-message=1M", "kw"})
	if err != nil {
		t.Fatalf("max-message == max-memory 应合法: %v", err)
	}
	if opts.MaxMessage != 1<<20 {
		t.Errorf("MaxMessage = %d, want %d", opts.MaxMessage, int64(1<<20))
	}
	// 选项值是负数时直接作为选项值取走，同样报错而不是被当成文件。
	_, err = cli.Parse([]string{"--max-memory", "-5", "kw"})
	if err == nil {
		t.Error("--max-memory -5 应报错")
	}
}

// 第 5 条：--max-message 单独走同一套大小解析。
func TestParseMaxMessageSizes(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"100", 100},
		{"512K", 524288},
		{"1M", 1 << 20},
		{"2G", 2 << 30},
		{"2g", 2 << 30},
	}
	for _, c := range cases {
		opts, err := cli.Parse([]string{"--max-memory=8G", "--max-message=" + c.in, "kw"})
		if err != nil {
			t.Fatalf("--max-message %s: %v", c.in, err)
		}
		if opts.MaxMessage != c.want {
			t.Errorf("--max-message %s = %d, want %d", c.in, opts.MaxMessage, c.want)
		}
	}
	for _, bad := range []string{"0", "-5", "abc", "", "1Q", "1Kx", "+5", "8589934592G", "99999999999999999999"} {
		_, err := cli.Parse([]string{"--max-message=" + bad, "kw"})
		if err == nil {
			t.Errorf("--max-message %q 应报错", bad)
			continue
		}
		want := "invalid size for --max-message: " + bad
		if err.Error() != want {
			t.Errorf("err = %q, want %q", err.Error(), want)
		}
	}
	// 空格形式同样支持。
	opts, err := cli.Parse([]string{"--max-message", "512K", "kw"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.MaxMessage != 524288 {
		t.Errorf("MaxMessage = %d, want 524288", opts.MaxMessage)
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
	for _, bad := range []string{"0", "-1", "x", "+5", "+4", "1.5"} {
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

// 第 8 条：--help / --version 不要求关键词。
func TestParseHelpVersion(t *testing.T) {
	opts, err := cli.Parse([]string{"--help"})
	if err != nil {
		t.Fatalf("Parse --help: %v", err)
	}
	if !opts.Help {
		t.Error("Help 应为 true")
	}
	opts, err = cli.Parse([]string{"--version"})
	if err != nil {
		t.Fatalf("Parse --version: %v", err)
	}
	if !opts.Version {
		t.Error("Version 应为 true")
	}
	// 没有关键词但带了 help 时也不报错；其他格式错误照常检查。
	if _, err := cli.Parse([]string{"--help", "--foo"}); err == nil {
		t.Error("未知选项仍应报错")
	}
	if _, err := cli.Parse([]string{"--version", "--foo"}); err == nil {
		t.Error("--version 下未知选项仍应报错")
	}
	// help 不豁免位置参数个数限制：第一个是关键词，第二个是文件，第三个多余。
	_, err = cli.Parse([]string{"--help", "a.pcap", "b.pcap", "c.pcap"})
	if err == nil || err.Error() != "only one input file is supported" {
		t.Fatalf("err = %v, want only one input file is supported", err)
	}
	// 不提供 -h。
	if _, err := cli.Parse([]string{"-h"}); err == nil {
		t.Error("-h 不应存在")
	}
}

// 第 9 条：未知选项与缺少选项值。
func TestParseErrors(t *testing.T) {
	_, err := cli.Parse([]string{"--foo", "kw"})
	if err == nil || err.Error() != "unknown option: --foo" {
		t.Fatalf("err = %v, want unknown option: --foo", err)
	}
	_, err = cli.Parse([]string{"-x", "kw"})
	if err == nil || err.Error() != "unknown option: -x" {
		t.Fatalf("err = %v, want unknown option: -x", err)
	}
	// 长选项形式只有 --timeout 等，--e/--E 未定义，应报未知选项。
	_, err = cli.Parse([]string{"--e", "kw"})
	if err == nil || err.Error() != "unknown option: --e" {
		t.Fatalf("err = %v, want unknown option: --e", err)
	}
	_, err = cli.Parse([]string{"--E", "kw"})
	if err == nil || err.Error() != "unknown option: --E" {
		t.Fatalf("err = %v, want unknown option: --E", err)
	}
	_, err = cli.Parse([]string{"--timeout"})
	if err == nil || err.Error() != "option requires an argument: --timeout" {
		t.Fatalf("err = %v, want option requires an argument: --timeout", err)
	}
	_, err = cli.Parse([]string{"-e"})
	if err == nil || err.Error() != "option requires an argument: -e" {
		t.Fatalf("err = %v, want option requires an argument: -e", err)
	}
}

// Usage 覆盖设计文档第 2 节的全部选项。
func TestUsageCoversOptions(t *testing.T) {
	for _, opt := range []string{"-e", "-E", "--timeout", "--max-memory", "--max-message", "--cpus", "--stats", "--help", "--version"} {
		if !strings.Contains(cli.Usage, opt) {
			t.Errorf("Usage 缺少 %s", opt)
		}
	}
}

// 第 9 条：每个取值选项缺少选项值时，报错都指向该选项本身。
func TestParseMissingOptionValue(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"kw", "--timeout"}, "option requires an argument: --timeout"},
		{[]string{"kw", "--max-memory"}, "option requires an argument: --max-memory"},
		{[]string{"kw", "--max-message"}, "option requires an argument: --max-message"},
		{[]string{"kw", "--cpus"}, "option requires an argument: --cpus"},
		{[]string{"kw", "-e"}, "option requires an argument: -e"},
	}
	for _, c := range cases {
		_, err := cli.Parse(c.args)
		if err == nil || err.Error() != c.want {
			t.Errorf("Parse(%q) err = %v, want %q", c.args, err, c.want)
		}
	}
}

// 开关类长选项不接受 =值 形式。
func TestParseFlagRejectsValue(t *testing.T) {
	cases := []struct {
		arg  string
		want string
	}{
		{"--stats=x", "option --stats does not take an argument"},
		{"--help=x", "option --help does not take an argument"},
		{"--version=x", "option --version does not take an argument"},
	}
	for _, c := range cases {
		_, err := cli.Parse([]string{c.arg, "kw"})
		if err == nil || err.Error() != c.want {
			t.Errorf("Parse(%q) err = %v, want %q", c.arg, err, c.want)
		}
	}
}

// 非 ASCII 短选项的报错消息按完整字符输出，不出现乱码。
func TestParseUnknownNonASCIIShortOption(t *testing.T) {
	_, err := cli.Parse([]string{"-é", "kw"})
	if err == nil || err.Error() != "unknown option: -é" {
		t.Fatalf("err = %v, want unknown option: -é", err)
	}
}
