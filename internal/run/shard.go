package run

import (
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/engine"
)

// dispatcher 把解码出的段交给引擎。单分片时直接在主循环里调用引擎，
// 多分片时按连接分给各分片协程。
type dispatcher interface {
	// segment 处理批次 b 里的一个段；seg 只在调用期间有效。
	segment(b *batch, seg *decode.Segment, ts time.Time)
	// flush 在一批包处理完后调用：把时钟推进到 now，然后释放批次。
	flush(b *batch, now time.Time)
	// advance 在没有新包时推进时钟。
	advance(now time.Time)
	// finish 结束输入并等所有分片停下，返回合并后的引擎统计。
	finish(now time.Time) engine.Stats
	// abort 不结束在途交互，直接停下所有分片，返回合并后的引擎统计。
	abort() engine.Stats
}

// single 是单分片：引擎在主循环里运行。
type single struct {
	e    *engine.Engine
	free chan<- *batch
}

func (s *single) segment(_ *batch, seg *decode.Segment, ts time.Time) { s.e.Segment(seg, ts) }

func (s *single) flush(b *batch, now time.Time) {
	s.e.Advance(now)
	b.reset()
	s.free <- b
}

func (s *single) advance(now time.Time) { s.e.Advance(now) }

func (s *single) finish(now time.Time) engine.Stats {
	s.e.Finish(now)
	return s.e.Stats()
}

func (s *single) abort() engine.Stats { return s.e.Stats() }
