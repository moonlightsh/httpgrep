// Package run 是 httpgrep 的读入循环：从 pcap 读包、解码，按抓包时钟推进引擎，
// 把命中的交互写到输出；--cpus N 时按连接把包分给 N 个分片引擎。
package run

import (
	"fmt"
	"io"
	"sync"
	"time"

	"httpgrep/internal/cli"
	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
	"httpgrep/internal/match"
	"httpgrep/internal/output"
	"httpgrep/internal/pcap"
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

	n := max(o.CPUs, 1)
	rd := startReader(cfg.Input, n)
	defer close(rd.done)
	// Stop 关闭后最多再读 stopGrace，或者读到输入结束为止；读取协程卡在阻塞的 read 上时不等它。
	stop := cfg.Stop
	var grace <-chan time.Time
	onStop := func() {
		stop = nil
		t := time.NewTimer(stopGrace)
		grace = t.C
	}
	var h header
	for waiting := true; waiting; {
		select {
		case h = <-rd.hdr:
			waiting = false
		case <-stop:
			onStop()
		case <-grace: // 文件头都没等到：当作没有任何包
			return false, st, nil
		}
	}
	if h.err != nil {
		return false, st, h.err
	}
	if !decode.Supported(h.link) {
		return false, st, fmt.Errorf("unsupported link type %d", h.link)
	}

	ecfg := engine.Config{
		Matcher:    m,
		Timeout:    o.Timeout,
		MaxMemory:  o.MaxMemory,
		MaxMessage: o.MaxMessage,
		Emit:       out.emit,
		Warn:       out.warn,
	}
	var d dispatcher
	if n > 1 {
		d = newMulti(n, ecfg, rd.free)
	} else {
		d = &single{e: engine.New(ecfg), free: rd.free}
	}

	l := loop{link: h.link, d: d}
	var tick <-chan time.Time
	if cfg.Pipe {
		t := time.NewTicker(idleCheck)
		defer t.Stop()
		tick = t.C
	}
	for done := false; !done; {
		select {
		case b := <-rd.out:
			done = l.batch(b)
		case <-tick:
			l.idle()
		case <-stop:
			onStop()
		case <-grace:
			done = true
		}
	}
	st = d.finish(l.clock)
	if err := out.failed(); err != nil {
		return out.matched, st, err
	}
	// 读到一半出错：已经读到的交互照常结束和输出，再报错
	return out.matched, st, l.readErr
}

const (
	// stopGrace 是 Stop 关闭后最多再读的时间。
	stopGrace = time.Second
	// 管道输入的真实时间兜底：每 idleCheck 检查一次，超过 idleAfter 没有新包时，
	// 时钟从最后一个包起按真实经过的时间往前推。
	idleCheck = 200 * time.Millisecond
	idleAfter = time.Second
)

// loop 是主循环的状态。
type loop struct {
	link    pcap.LinkType
	d       dispatcher
	seg     decode.Segment
	clock   time.Time // 抓包时钟：所有包时间戳的最大值，管道输入时还会按真实时间往前推
	lastTS  time.Time // 所有包时间戳的最大值
	lastRcv time.Time // 收到最近一批包的真实时间；零值表示还没收到包
	readErr error     // 读记录时的错误（不含 io.EOF）
}

// batch 处理一批包，返回输入是否已经结束。
func (l *loop) batch(b *batch) (end bool) {
	for _, r := range b.recs {
		if r.ts.After(l.lastTS) {
			l.lastTS = r.ts
		}
		if r.ts.After(l.clock) {
			l.clock = r.ts
		}
		// 引擎要求时间单调不减：时间戳变小的包按当前时钟处理
		if decode.Decode(l.link, b.buf[r.off:r.off+r.n], r.origLen, &l.seg) == decode.OK {
			l.d.segment(b, &l.seg, l.clock)
		}
	}
	if len(b.recs) > 0 {
		l.lastRcv = time.Now()
	}
	end = b.err != nil
	if end && b.err != io.EOF {
		l.readErr = b.err
	}
	l.d.flush(b, l.clock)
	return end
}

// idle 是管道输入的定时检查。
func (l *loop) idle() {
	if l.lastRcv.IsZero() {
		return
	}
	since := time.Since(l.lastRcv)
	if since <= idleAfter {
		return
	}
	if c := l.lastTS.Add(since); c.After(l.clock) {
		l.clock = c
	}
	l.d.advance(l.clock)
}
