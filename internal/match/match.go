// Package match 按 grep 的方式逐行匹配关键词。
package match

import (
	"bytes"
	"strconv"
)

// Matcher 是编译好的关键词集合，可以派生多个 Scanner。
type Matcher struct {
	patterns [][]byte // 字面关键词；空串表示匹配所有行
}

// Compile 编译关键词。patterns 已经按换行拆好；regex 为真时按 RE2 解释。
func Compile(patterns []string, regex bool) (*Matcher, error) {
	if regex {
		return nil, &CompileError{Pattern: "", Err: "regex not supported yet"}
	}
	m := &Matcher{patterns: make([][]byte, len(patterns))}
	for i, p := range patterns {
		m.patterns[i] = []byte(p)
	}
	return m, nil
}

// CompileError 表示某个关键词编译失败。
type CompileError struct {
	Pattern string
	Err     string
}

func (e *CompileError) Error() string {
	return "match: invalid pattern " + strconv.Quote(e.Pattern) + ": " + e.Err
}

// NewScanner 创建一个新的扫描器。
func (m *Matcher) NewScanner() *Scanner {
	return &Scanner{m: m}
}

// Scanner 流式扫描文本，按 \n 分行，没写完的行留到下一次。
type Scanner struct {
	m       *Matcher
	matched bool
	buf     []byte // 没写完的行
}

// Write 流式写入，按 \n 分行，没写完的行留到下一次。
func (s *Scanner) Write(b []byte) {
	if s.matched {
		return
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			s.buf = append(s.buf, b...)
			return
		}
		s.processLine(append(s.buf, b[:i]...))
		s.buf = s.buf[:0]
		b = b[i+1:]
	}
}

// Break 结束当前行，效果等同于写入一个 \n。
func (s *Scanner) Break() {
	if s.matched {
		return
	}
	s.processLine(s.buf)
	s.buf = s.buf[:0]
}

// Matched 报告是否已有命中。
func (s *Scanner) Matched() bool { return s.matched }

// Reset 重置扫描器，可复用。
func (s *Scanner) Reset() {
	s.matched = false
	s.buf = s.buf[:0]
}

// processLine 处理一行完整的行（不含 \n）。行尾的 \r 由调用方去掉。
func (s *Scanner) processLine(line []byte) {
	for _, p := range s.m.patterns {
		if len(p) == 0 {
			s.matched = true
		} else if bytes.Contains(line, p) {
			s.matched = true
		}
	}
}
