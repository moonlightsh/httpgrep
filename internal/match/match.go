// Package match 按 grep 的方式逐行匹配关键词。
package match

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Matcher 是编译好的关键词集合，可以派生多个 Scanner。
type Matcher struct {
	patterns [][]byte       // 字面关键词；空串表示匹配所有行
	re       *regexp.Regexp // 正则模式：合并编译后的行匹配
	anyEmpty bool           // 某个关键词是空串（匹配所有行）
}

// Compile 编译关键词。patterns 已经按换行拆好；regex 为真时按 RE2 解释。
// 多个正则合并成 (?:a)|(?:b) 编译；正则不合法时返回的错误里包含该关键词。
func Compile(patterns []string, regex bool) (*Matcher, error) {
	m := &Matcher{}
	if regex {
		var parts []string
		for _, p := range patterns {
			if p == "" {
				m.anyEmpty = true
				continue // 空正则匹配一切，无需合并
			}
			if _, err := regexp.Compile(p); err != nil {
				return nil, &CompileError{Pattern: p, Err: err.Error()}
			}
			parts = append(parts, "(?:"+p+")")
		}
		if len(parts) > 0 {
			// 逐行匹配：每行单独传入，^、$ 自然锚定行首行尾。
			re, err := regexp.Compile(strings.Join(parts, "|"))
			if err != nil {
				return nil, &CompileError{Pattern: parts[0], Err: err.Error()}
			}
			m.re = re
		}
		return m, nil
	}
	for _, p := range patterns {
		if p == "" {
			m.anyEmpty = true
			continue
		}
		m.patterns = append(m.patterns, []byte(p))
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

// Highlight 返回一行里所有命中的 [起, 止) 区间，按起点排序、互不重叠。
// line 不含 \n；行尾的 \r 由调用方去掉。
func (m *Matcher) Highlight(line []byte) [][2]int {
	if m.anyEmpty {
		if len(line) == 0 {
			return nil
		}
		return [][2]int{{0, len(line)}}
	}
	if m.re != nil {
		var out [][2]int
		for _, loc := range m.re.FindAllIndex(line, -1) {
			if loc[1] > loc[0] {
				out = append(out, [2]int{loc[0], loc[1]})
			}
		}
		return out
	}
	// 字面匹配：找所有关键词的所有出现位置，重叠的合并。
	var ranges [][2]int
	for _, p := range m.patterns {
		for i := 0; i+len(p) <= len(line); {
			j := bytes.Index(line[i:], p)
			if j < 0 {
				break
			}
			ranges = append(ranges, [2]int{i + j, i + j + len(p)})
			i += j + 1
		}
	}
	sort.Slice(ranges, func(a, b int) bool { return ranges[a][0] < ranges[b][0] })
	var out [][2]int
	for _, r := range ranges {
		if n := len(out); n > 0 && r[0] < out[n-1][1] {
			// 重叠：延长或跳过。
			if r[1] > out[n-1][1] {
				out[n-1][1] = r[1]
			}
			continue
		}
		out = append(out, r)
	}
	return out
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

// processLine 处理一行完整的行（不含 \n）。行尾的 \r 不算行内容，先去掉。
func (s *Scanner) processLine(line []byte) {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if s.m.anyEmpty {
		s.matched = true
		return
	}
	if s.m.re != nil {
		if s.m.re.Match(line) {
			s.matched = true
		}
		return
	}
	for _, p := range s.m.patterns {
		if len(p) == 0 {
			s.matched = true
		} else if bytes.Contains(line, p) {
			s.matched = true
		}
	}
}
