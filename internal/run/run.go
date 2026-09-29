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
	err     error         // 第一次写出失败的错误，之后不再写
	fail    chan struct{} // 写出失败时关闭，通知主循环停下

	// 内存告警由 sink 统一限频，不用引擎自己的 Warn（它按引擎各自限频、各自计数，
	// --cpus N 时会有 N 路告警）。dropped、droppedMatched 是距上一次告警以来各分片丢弃的
	// 交互数之和和其中已命中的；warnedAt 是上一次告警的抓包时间，warned 表示告警过。
	dropped, droppedMatched int64
	warnedAt                time.Time
	warned                  bool
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
		close(s.fail)
		return
	}
	s.matched = true
}

// warnInterval 是内存告警的最小间隔，按抓包时钟。
const warnInterval = 10 * time.Second

// drop 累计分片报来的 n 个因内存上限丢弃的交互（其中 m 个已命中），now 是这时的抓包时钟。
// 有累计数，并且从没告警过或者距上一次告警已满 10 秒时，写一行告警。
// 分片按批报告（见 dispatcher.flush），同一批包里各分片的丢弃合成一行。
func (s *sink) drop(n, m int64, now time.Time) {
	if n == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropped += n
	s.droppedMatched += m
	if !s.warned || !now.Before(s.warnedAt.Add(warnInterval)) {
		s.warn(now)
	}
}

// flushWarn 在所有分片结束输入之后调用：还有没报告过的累计数时再告警一次。
func (s *sink) flushWarn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped > 0 {
		s.warn(s.warnedAt)
	}
}

// warn 写一行告警，报告累计数，然后清零。调用方持有锁。
func (s *sink) warn(now time.Time) {
	if s.stderr != nil {
		fmt.Fprintf(s.stderr, "httpgrep: dropped %d in-flight exchanges (%d matched) to stay under --max-memory\n",
			s.dropped, s.droppedMatched)
	}
	s.dropped, s.droppedMatched = 0, 0
	s.warnedAt, s.warned = now, true
}

// seen 记下一个引擎已经报告给 sink 的丢弃数，用来算增量。
type seen struct {
	evicted, matched int64
}

// delta 返回引擎统计 st 里还没报告过的丢弃数和其中已命中的，并记为已报告。
func (v *seen) delta(st engine.Stats) (n, m int64) {
	n, m = st.Evicted-v.evicted, st.EvictedMatched-v.matched
	v.evicted, v.matched = st.Evicted, st.EvictedMatched
	return n, m
}

// failed 返回写出失败的错误。
func (s *sink) failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Run 处理整个输入。matched 为真表示至少输出了一块。
//
// --cpus N 时 st 是各分片统计的合并（engine.Stats.Merge）：计数是总数，
// 峰值（PeakBuffered、PeakInFlight、PeakConns）是各分片峰值之和，只是上界，
// 不是同一时刻的全局峰值。
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
	out := &sink{w: output.NewWriter(cfg.Stdout, oo), stderr: cfg.Stderr, fail: make(chan struct{})}

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
		// 不设 Warn：内存告警由 sink 按各引擎统计里 Evicted 的增量统一限频（见 sink.drop）。
	}
	var d dispatcher
	if n > 1 {
		d = newMulti(n, ecfg, rd.free, out)
	} else {
		d = &single{e: engine.New(ecfg), free: rd.free, out: out}
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
		case <-out.fail: // 输出已经坏了，不再结束在途交互
			st = l.stats(d.abort())
			return out.matched, st, out.failed()
		}
	}
	st = l.stats(d.finish(l.clock))
	out.flushWarn()
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
	clock   time.Time    // 抓包时钟：所有包时间戳的最大值，管道输入时还会按真实时间往前推
	lastTS  time.Time    // 所有包时间戳的最大值
	lastRcv time.Time    // 收到最近一批包的真实时间；零值表示还没收到包
	readErr error        // 读记录时的错误（不含 io.EOF）
	st      engine.Stats // run 层填写的统计：Packets、Bytes、NotTCP、Fragments、Malformed、FirstTS
}

// stats 把 run 层的统计填进引擎合并后的统计 est。
func (l *loop) stats(est engine.Stats) engine.Stats {
	est.Packets, est.Bytes = l.st.Packets, l.st.Bytes
	est.NotTCP, est.Fragments, est.Malformed = l.st.NotTCP, l.st.Fragments, l.st.Malformed
	est.FirstTS, est.LastTS = l.st.FirstTS, l.lastTS
	return est
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
		st := &l.st
		if st.Packets == 0 || r.ts.Before(st.FirstTS) {
			st.FirstTS = r.ts
		}
		st.Packets++
		st.Bytes += int64(r.n)
		switch decode.Decode(l.link, b.buf[r.off:r.off+r.n], r.origLen, &l.seg) {
		case decode.OK:
			// 引擎要求时间单调不减：时间戳变小的包按当前时钟处理
			l.d.segment(b, &l.seg, l.clock)
		case decode.NotTCP:
			st.NotTCP++
		case decode.Fragment:
			st.Fragments++
		case decode.Malformed:
			st.Malformed++
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
