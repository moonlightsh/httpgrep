// Package match 按 grep 的方式逐行匹配关键词。
package match

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 正则模式下没写完的行的缓存上限，超出的部分不参与匹配。
const regexBufCap = 8 << 20

// Matcher 是编译好的关键词集合，可以派生多个 Scanner。
type Matcher struct {
	patterns [][]byte       // 字面关键词（不含空串）
	re       *regexp.Regexp // 正则模式：合并编译后的行匹配
	anyEmpty bool           // 某个关键词是空串（匹配所有行）
	fast     bool           // 字面模式且关键词都不含 \r：走快速路径
	maxLen   int            // 最长关键词的长度（快速路径用）
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
	m.fast = true
	for _, p := range patterns {
		if p == "" {
			m.anyEmpty = true
			continue
		}
		if strings.ContainsRune(p, '\r') {
			m.fast = false // 关键词含 \r 时必须按行处理
		}
		if len(p) > m.maxLen {
			m.maxLen = len(p)
		}
		m.patterns = append(m.patterns, []byte(p))
	}
	if m.anyEmpty || len(m.patterns) == 0 {
		m.fast = false
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

// Scanner 流式扫描文本，按 \n 分行后逐行匹配。
type Scanner struct {
	m        *Matcher
	matched  bool
	buf      []byte // 没写完的行（慢路径/正则模式）
	fastTail []byte // 快速路径：上一块末尾的候选字节，供跨块命中拼接
	sb       []byte // 快速路径：块边界检查的复用缓冲
}

// Write 流式写入，按 \n 分行，没写完的行留到下一次。
func (s *Scanner) Write(b []byte) {
	if s.matched {
		return
	}
	if s.m.fast {
		s.fastScan(b)
		return
	}
	if !s.m.anyEmpty && s.m.re == nil && len(s.m.patterns) == 0 {
		return // 没有关键词，永远不命中
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			s.holdLine(b)
			return
		}
		if len(s.buf) == 0 {
			// 不拷贝，直接处理；正则模式下按上限截断。
			line := b[:i]
			if s.m.re != nil && len(line) > regexBufCap {
				line = line[:regexBufCap]
			}
			s.processLine(line)
		} else {
			s.buf = append(s.buf, b[:i]...)
			if s.m.re != nil && len(s.buf) > regexBufCap {
					s.buf = s.buf[:regexBufCap]
			}
			s.processLine(s.buf)
			s.buf = s.buf[:0]
		}
		b = b[i+1:]
	}
}

// holdLine 缓存没写完的行。正则模式下缓存上限是 regexBufCap，
// 超出后新到的字节不参与匹配。
func (s *Scanner) holdLine(b []byte) {
	if s.m.re != nil && len(s.buf) >= regexBufCap {
		return // 已到上限，超出的部分不参与匹配
	}
	s.buf = append(s.buf, b...)
	if s.m.re != nil && len(s.buf) > regexBufCap {
		s.buf = s.buf[:regexBufCap]
	}
}

// fastScan 快速路径：对整块数据直接扫描，不按行切分。
// 关键词都不含 \r 和 \n（换行已拆），不会跨行误报；跨块的命中
// 通过携带块尾 len(最长关键词)-1 个字节来补齐。
func (s *Scanner) fastScan(b []byte) {
	n := s.m.maxLen - 1
	if n > 0 && len(s.fastTail) > 0 {
		// 只检查块边界：上一块尾部 + 本块开头 n 个字节。
		m := n
		if len(b) < m {
			m = len(b)
		}
		s.sb = append(s.sb[:0], s.fastTail...)
		s.sb = append(s.sb, b[:m]...)
		for _, p := range s.m.patterns {
			if bytes.Contains(s.sb, p) {
				s.matched = true
				return
			}
		}
	}
	for _, p := range s.m.patterns {
		if bytes.Contains(b, p) {
			s.matched = true
			return
		}
	}
	if n <= 0 {
		return
	}
	// 更新块尾候选字节。
	if len(b) >= n {
		s.fastTail = append(s.fastTail[:0], b[len(b)-n:]...)
	} else {
		s.fastTail = append(s.fastTail, b...)
		if len(s.fastTail) > n {
			copy(s.fastTail, s.fastTail[len(s.fastTail)-n:])
			s.fastTail = s.fastTail[:n]
		}
	}
}

// Break 结束当前行，效果等同于写入一个 \n。
func (s *Scanner) Break() {
	if s.matched {
		return
	}
	if s.m.fast {
		s.fastTail = nil // 跨 Break 的候选作废
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
	s.fastTail = nil
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
		if bytes.Contains(line, p) {
			s.matched = true
			return
		}
	}
}
