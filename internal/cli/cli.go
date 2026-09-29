// Package cli 解析 httpgrep 的命令行参数。
package cli

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Usage 是英文帮助文本，覆盖设计文档第 2 节的全部选项。
const Usage = `Usage: httpgrep [OPTION]... PATTERN [FILE]
       httpgrep [OPTION]... -e PATTERN [-e PATTERN]... [FILE]

Search HTTP conversations in a pcap capture for PATTERN and print the
matching requests and responses. With no FILE, or when FILE is -, read
standard input.

Options:
  -e PATTERN        Pattern to search for; may be given multiple times,
                    an exchange matches if any pattern matches
  -E                Interpret all patterns as regular expressions
  --timeout DUR     Exchange timeout: end an unfinished exchange after
                    DUR without new data (default 30s); at most 8760h
  --max-memory SIZE Approximate limit for buffered data (default 256M):
                    request and response data, out-of-order segments,
                    partial header lines, bytes held after an Upgrade
                    request, and per-connection/per-exchange overhead.
                    When it is exceeded, the oldest unfinished
                    exchanges are dropped, then the least recently
                    active connections. Not counted: -E line buffers
                    (up to 8M per scanner, only for very long lines).
                    The process uses more memory than this; the Go
                    runtime soft limit is set to 1.5 times this value
  --max-message SIZE
                    Limit for a single request or response; bytes over
                    it are not buffered (default 8M). It cannot exceed
                    --max-memory divided by --cpus; the default is
                    lowered to that when it is smaller
  --cpus N          Number of CPUs to use, 1 to 1024 (default 1). With
                    N > 1, connections are split among N workers, each
                    limited to 1/N of --max-memory; output is ordered
                    by exchange end only within a worker, so blocks
                    from different workers may be interleaved
  --stats           Print statistics to stderr before exiting
  --help            Show this help and exit
  --version         Show version information and exit

SIZE accepts K, M, G suffixes (powers of 1024). DUR is a Go duration
such as 30s or 2m. Options may appear before or after PATTERN and FILE;
arguments after -- are never treated as options.

Live search:
  tcpdump -i lo -U --immediate-mode -w - port 7010 | httpgrep PATTERN
Without --immediate-mode, tcpdump may hold packets for up to about 1s
before writing them, so matches are printed that much later.

Exit status is 0 if an exchange matched, 1 if none matched, 2 on error.
`

// Options 是 Parse 的结果。
type Options struct {
	Patterns   []string // 已经按换行拆开
	Regex      bool
	File       string // 空串或 "-" 表示标准输入
	Timeout    time.Duration
	MaxMemory  int64
	MaxMessage int64
	CPUs       int
	Stats      bool
	Help       bool
	Version    bool
}

// errBadArg 是参数解析错误，消息用英文。
type errBadArg struct {
	msg string
}

func (e *errBadArg) Error() string { return e.msg }

// Parse 解析命令行参数（args 不含程序名）。
func Parse(args []string) (Options, error) {
	opts := Options{
		Timeout:    30 * time.Second,
		MaxMemory:  256 << 20,
		MaxMessage: 8 << 20,
		CPUs:       1,
	}
	hasE, msgSet := false, false
	var positional []string
	// 第 i 位待处理；一个参数可能既当选项又带值，也可能合并多个短选项。
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			// -- 之后的参数一律不当选项
			positional = append(positional, args[i+1:]...)
			goto done
		case len(arg) > 2 && arg[0] == '-' && arg[1] == '-':
			name, val, hasVal := cut(arg[2:], "=")
			var err error
			switch name {
			case "timeout":
				if !hasVal {
					i, val, err = takeArg(args, i, "--timeout")
					if err != nil {
						return opts, err
					}
				}
				opts.Timeout, err = parseDuration("--timeout", val)
				if err != nil {
					return opts, err
				}
				if opts.Timeout > maxTimeout {
					return opts, &errBadArg{"invalid duration for --timeout: " + val + " (at most 8760h)"}
				}
			case "max-memory":
				if !hasVal {
					i, val, err = takeArg(args, i, "--max-memory")
					if err != nil {
						return opts, err
					}
				}
				opts.MaxMemory, err = parseSize("--max-memory", val)
				if err != nil {
					return opts, err
				}
			case "max-message":
				if !hasVal {
					i, val, err = takeArg(args, i, "--max-message")
					if err != nil {
						return opts, err
					}
				}
				opts.MaxMessage, err = parseSize("--max-message", val)
				if err != nil {
					return opts, err
				}
				msgSet = true
			case "cpus":
				if !hasVal {
					i, val, err = takeArg(args, i, "--cpus")
					if err != nil {
						return opts, err
					}
				}
				opts.CPUs, err = parseCPUs(val)
				if err != nil {
					return opts, err
				}
			case "stats":
				if hasVal {
					return opts, &errBadArg{"option --stats does not take an argument"}
				}
				opts.Stats = true
			case "help":
				if hasVal {
					return opts, &errBadArg{"option --help does not take an argument"}
				}
				opts.Help = true
			case "version":
				if hasVal {
					return opts, &errBadArg{"option --version does not take an argument"}
				}
				opts.Version = true
			default:
				return opts, &errBadArg{"unknown option: --" + name}
			}
		case len(arg) >= 2 && arg[0] == '-':
			// 短选项串，可合并，取值时剩余部分或下一个参数充当选项值。
			for j := 1; j < len(arg); j++ {
				c := arg[j]
				var err error
				switch c {
				case 'e':
					rest := arg[j+1:]
					if rest == "" {
						i, rest, err = takeArg(args, i, "-e")
						if err != nil {
							return opts, err
						}
					}
					opts.Patterns = append(opts.Patterns, splitLines(rest)...)
					hasE = true
					j = len(arg) // 选项值之后的字符不再当选项
				case 'E':
					opts.Regex = true
				default:
					r, _ := utf8.DecodeRuneInString(arg[j:])
					return opts, &errBadArg{"unknown option: -" + string(r)}
				}
			}
		default:
			positional = append(positional, arg)
		}
	}
done:
	if !hasE {
		if len(positional) > 0 {
			opts.Patterns = splitLines(positional[0])
			positional = positional[1:]
		}
	}
	if len(positional) > 1 {
		return opts, &errBadArg{"only one input file is supported"}
	}
	if len(positional) == 1 {
		opts.File = positional[0]
	}
	if !opts.Help && !opts.Version && len(opts.Patterns) == 0 {
		return opts, &errBadArg{"no pattern given"}
	}
	// 每个分片的内存上限是 MaxMemory/CPUs。单条消息超过它时，本该截断的消息会整笔
	// 因内存上限丢弃，所以 MaxMessage 不能超过它；没给 --max-message 时默认值随之下调。
	share := opts.MaxMemory / int64(opts.CPUs)
	if !msgSet {
		opts.MaxMessage = min(opts.MaxMessage, share)
	}
	if opts.MaxMessage > opts.MaxMemory {
		return opts, &errBadArg{"--max-message cannot exceed --max-memory"}
	}
	if opts.MaxMessage > share {
		return opts, &errBadArg{"--max-message cannot exceed --max-memory divided by --cpus (" +
			strconv.FormatInt(share, 10) + " bytes per worker with --cpus " + strconv.Itoa(opts.CPUs) + ")"}
	}
	return opts, nil
}

// maxTimeout 是 --timeout 的上限（一年）。连接空闲释放用两倍超时，再大会溢出。
const maxTimeout = 8760 * time.Hour

// takeArg 取选项值：优先用下一个参数。
func takeArg(args []string, i int, name string) (int, string, error) {
	if i+1 >= len(args) {
		return i, "", &errBadArg{"option requires an argument: " + name}
	}
	return i + 1, args[i+1], nil
}

// cut 按 s 里第一个 sep 切开。
func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// splitLines 按换行符把一个关键词拆成多个。
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// parseSize 解析大小：纯数字是字节，可带 K/M/G 后缀（1024 进位）。
func parseSize(name, orig string) (int64, error) {
	s := orig
	if s == "" {
		return 0, &errBadArg{"invalid size for " + name + ": " + orig}
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'k', 'K':
		mult, s = 1024, s[:len(s)-1]
	case 'm', 'M':
		mult, s = 1<<20, s[:len(s)-1]
	case 'g', 'G':
		mult, s = 1<<30, s[:len(s)-1]
	}
	if !isDigits(s) {
		return 0, &errBadArg{"invalid size for " + name + ": " + orig}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<63-1)/mult {
		return 0, &errBadArg{"invalid size for " + name + ": " + orig}
	}
	return n * mult, nil
}

// isDigits 报告 s 非空且全是 ASCII 数字。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseInt 解析不小于 1 的纯数字整数。
func parseInt(name, s string) (int, error) {
	if !isDigits(s) {
		return 0, &errBadArg{"invalid value for " + name + ": " + s}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, &errBadArg{"invalid value for " + name + ": " + s}
	}
	return n, nil
}

// maxCPUs 是 --cpus 的上限。太大时 Go 运行时起不了那么多线程（--cpus 100000 直接
// thread exhaustion），--max-memory 平均分给各分片后每个分片的上限也几乎为 0。
const maxCPUs = 1024

// parseCPUs 解析 --cpus：1 到 maxCPUs 的纯数字整数。
func parseCPUs(s string) (int, error) {
	if !isDigits(s) || strings.Trim(s, "0") == "" { // 不是正整数
		return parseInt("--cpus", s)
	}
	if n, err := strconv.Atoi(s); err == nil && n <= maxCPUs {
		return n, nil
	}
	return 0, &errBadArg{"invalid value for --cpus: " + s + " (at most " + strconv.Itoa(maxCPUs) + ")"}
}

// parseDuration 解析必须大于 0 的时长。
func parseDuration(name, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, &errBadArg{"invalid duration for " + name + ": " + s}
	}
	return d, nil
}
