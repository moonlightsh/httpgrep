// Package run 是 httpgrep 的读入循环：从 pcap 读包、解码，按抓包时钟推进引擎，
// 把命中的交互写到输出；--cpus N 时按连接把包分给 N 个分片引擎。
package run

import (
	"io"
	"sync"
	"time"

	"httpgrep/internal/cli"
	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
)

// Config 是 Run 的参数。
type Config struct {
	Input  io.Reader
	Pipe   bool            // 输入不是普通文件；为真时启用真实时间兜底
	Stop   <-chan struct{} // 第一次收到信号时关闭
	Stdout io.Writer
	Stderr io.Writer // 告警写到这里
	TTY    bool
	Opts   cli.Options
}

// sink 是所有分片共用的输出，带互斥锁。
type sink struct {
	mu      sync.Mutex
	w       *output.Writer
	stderr  io.Writer
	matched bool
	err     error // 第一次写出失败的错误，之后不再写
}

// emit 是引擎的 Emit 回调。
func (s *sink) emit(b *output.Block) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	if err := s.w.Write(b); err != nil {
		s.err = err
		return
	}
	s.matched = true
}

// warn 是引擎的 Warn 回调，一条告警写一行。
func (s *sink) warn(msg string) {
	if s.stderr == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	io.WriteString(s.stderr, "httpgrep: "+msg+"\n")
}

// failed 返回写出失败的错误。
func (s *sink) failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Run 处理整个输入。matched 为真表示至少输出了一块。
func Run(cfg Config) (matched bool, st engine.Stats, err error) {
	o := cfg.Opts
	m, err := match.Compile(o.Patterns, o.Regex)
	if err != nil {
		return false, st, err
	}
	oo := output.Options{TTY: cfg.TTY}
	if cfg.TTY {
		oo.Highlight = m.Highlight
	}
	out := &sink{w: output.NewWriter(cfg.Stdout, oo), stderr: cfg.Stderr}

	rd := startReader(cfg.Input, 1)
	defer close(rd.done)
	h := <-rd.hdr
	if h.err != nil {
		return false, st, h.err
	}

	ecfg := engine.Config{
		Matcher:    m,
		Timeout:    o.Timeout,
		MaxMemory:  o.MaxMemory,
		MaxMessage: o.MaxMessage,
		Emit:       out.emit,
		Warn:       out.warn,
	}
	var d dispatcher = &single{e: engine.New(ecfg), free: rd.free}

	var (
		clock time.Time // 抓包时钟：所有包时间戳的最大值
		seg   decode.Segment
	)
	for b := range rd.out {
		for _, r := range b.recs {
			if r.ts.After(clock) {
				clock = r.ts
			}
			// 引擎要求时间单调不减：时间戳变小的包按当前时钟处理
			if decode.Decode(h.link, b.buf[r.off:r.off+r.n], r.origLen, &seg) == decode.OK {
				d.segment(b, &seg, clock)
			}
		}
		end := b.err
		d.flush(b, clock)
		if end != nil {
			break
		}
	}
	st = d.finish(clock)
	return out.matched, st, out.failed()
}
