// Package cli 解析 httpgrep 的命令行参数。
package cli

import "time"

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

// Error 是参数解析错误，消息用英文。
type Error struct {
	msg string
}

func (e *Error) Error() string { return e.msg }

// Parse 解析命令行参数（args 不含程序名）。
func Parse(args []string) (Options, error) {
	opts := Options{
		Timeout:    30 * time.Second,
		MaxMemory:  256 << 20,
		MaxMessage: 8 << 20,
		CPUs:       1,
	}
	hasE := false
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-e":
			if i+1 >= len(args) {
				return opts, &Error{"option requires an argument: -e"}
			}
			i++
			opts.Patterns = append(opts.Patterns, splitLines(args[i])...)
			hasE = true
		default:
			positional = append(positional, arg)
		}
	}

	if !hasE {
		if len(positional) > 0 {
			opts.Patterns = splitLines(positional[0])
			positional = positional[1:]
		}
	}
	if len(positional) > 1 {
		return opts, &Error{"only one input file is supported"}
	}
	if len(positional) == 1 {
		opts.File = positional[0]
	}
	if len(opts.Patterns) == 0 {
		return opts, &Error{"no pattern given"}
	}
	return opts, nil
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
