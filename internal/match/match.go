// Package match 按 grep 的方式逐行匹配关键词。
package match

import (
	"bytes"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// 没写完的行的缓存上限（正则和含 \r 的字面关键词共用），超出的部分不参与匹配。
// 副作用：超长行按截断点作为行尾，正则的 $ 会锚定在第 8 MiB 处而非真正的行尾。
const lineBufCap = 8 << 20

// Matcher 是编译好的关键词集合，可以派生多个 Scanner。
type Matcher struct {
	patterns [][]byte       // 字面关键词（不含空串）
	re       *regexp.Regexp // 正则模式：合并编译后的行匹配
	hl       *regexp.Regexp // 正则模式：re 的 leftmost-longest 版本，只给 Highlight 用
	anyEmpty bool           // 某个关键词是空串（匹配所有行）
	fast     bool           // 字面模式且关键词都不含 \r：走快速路径
	maxLen   int            // 最长关键词的长度（快速路径用）
}

// Compile 编译关键词。patterns 已经按换行拆好；regex 为真时按 RE2 解释。
// 多个正则合并成 (?:a)|(?:b) 编译；正则不合法时返回的错误里包含该关键词。
// 关键词里有空串时匹配任何一行：Break 等同于写入 \n，所以即使没写入任何数据，
// 调用 Break 之后 Matched 也为真。
func Compile(patterns []string, regex bool) (*Matcher, error) {
	for _, p := range patterns {
		if strings.ContainsRune(p, '\n') {
			return nil, &CompileError{Pattern: p, Err: "pattern contains newline"}
		}
	}
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
			joined := strings.Join(parts, "|")
			re, err := regexp.Compile(joined)
			if err != nil {
				return nil, &CompileError{Pattern: joined, Err: err.Error()}
			}
			m.re = re
			// Highlight 用 leftmost-longest，与 grep --color 一致：否则排在前面、
			// 能匹配空串或较短串的分支会遮住后面分支的命中（如 x*|\d+ 作用于 a12b）。
			// 命中判断仍用 re：是否命中与匹配语义无关，leftmost-first 更快。
			hl := regexp.MustCompile(joined) // 刚刚编译成功过，不会 panic
			hl.Longest()
			m.hl = hl
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
// 正则模式按 leftmost-longest 取区间，丢弃长度为 0 的区间。
func (m *Matcher) Highlight(line []byte) [][2]int {
	if m.hl != nil {
		var out [][2]int
		for _, loc := range m.hl.FindAllIndex(line, -1) {
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
	slices.SortFunc(ranges, func(a, b [2]int) int { return a[0] - b[0] })
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
// 必须通过 Matcher.NewScanner 创建，零值不可用（调用方法会 panic）。
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
	if s.m.anyEmpty {
		// 空关键词匹配任何一行：行内容用不上，不缓存，遇到 \n 即命中。
		if bytes.IndexByte(b, '\n') >= 0 {
			s.matched = true
		}
		return
	}
	if s.m.re == nil && len(s.m.patterns) == 0 {
		return // 没有关键词，永远不命中
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			s.appendCapped(b)
			return
		}
		if len(s.buf) == 0 {
			// 不拷贝，直接处理；正则模式下按上限截断。
			line := b[:i]
			if len(line) > lineBufCap {
				line = line[:lineBufCap]
			}
			s.processLine(line)
		} else {
			s.appendCapped(b[:i])
			s.processLine(s.buf)
			s.buf = s.buf[:0]
		}
		b = b[i+1:]
	}
}

// appendCapped 把 b 追加到没写完的行的缓存，上限 lineBufCap：
// 只追加上限内的部分，超出的字节不参与匹配，既不拷贝也不为它们扩容。
func (s *Scanner) appendCapped(b []byte) {
	if room := lineBufCap - len(s.buf); len(b) > room {
		b = b[:room]
	}
	s.buf = append(s.buf, b...)
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
		s.fastTail = s.fastTail[:0] // 跨 Break 的候选作废，保留容量
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
	s.fastTail = s.fastTail[:0]
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
