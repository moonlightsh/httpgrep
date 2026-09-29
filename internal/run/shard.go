package run

import (
	"net/netip"
	"sync"
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

// multi 是多分片：每个分片一个协程、一个引擎，按连接分包，时钟推进广播给所有分片。
type multi struct {
	shards []*shard
	free   chan<- *batch
	wg     sync.WaitGroup
}

// shard 是一个分片。
type shard struct {
	idx int
	e   *engine.Engine
	in  chan work
}

// work 是交给分片的一项工作：先处理批次 b 里分给它的段（b 可以为 nil），
// 再把时钟推进到 now；fin 为真时改为结束输入。
type work struct {
	b   *batch
	now time.Time
	fin bool
}

// newMulti 创建 n 个分片，内存上限平均分给各分片。
func newMulti(n int, cfg engine.Config, free chan<- *batch) *multi {
	cfg.MaxMemory /= int64(n)
	m := &multi{free: free}
	for i := range n {
		s := &shard{idx: i, e: engine.New(cfg), in: make(chan work, poolSize)}
		m.shards = append(m.shards, s)
		m.wg.Add(1)
		go m.run(s)
	}
	return m
}

// run 是分片协程。
func (m *multi) run(s *shard) {
	defer m.wg.Done()
	for w := range s.in {
		if w.b != nil {
			items := w.b.work[s.idx]
			for i := range items {
				s.e.Segment(&items[i].seg, items[i].ts)
			}
			m.release(w.b)
		}
		if w.fin {
			s.e.Finish(w.now)
		} else {
			s.e.Advance(w.now)
		}
	}
}

// release 在一个分片处理完批次后调用，最后一个分片把批次放回空闲池。
func (m *multi) release(b *batch) {
	if b.pending.Add(-1) == 0 {
		b.reset()
		m.free <- b
	}
}

func (m *multi) segment(b *batch, seg *decode.Segment, ts time.Time) {
	k := shardOf(seg, len(m.shards))
	b.work[k] = append(b.work[k], item{seg: *seg, ts: ts})
}

func (m *multi) flush(b *batch, now time.Time) {
	b.pending.Store(int32(len(m.shards)))
	for _, s := range m.shards {
		s.in <- work{b: b, now: now}
	}
}

func (m *multi) advance(now time.Time) {
	for _, s := range m.shards {
		s.in <- work{now: now}
	}
}

func (m *multi) finish(now time.Time) engine.Stats {
	for _, s := range m.shards {
		s.in <- work{now: now, fin: true}
	}
	return m.abort()
}

// abort 关闭各分片的输入，等它们处理完已经收到的工作后停下。
func (m *multi) abort() engine.Stats {
	for _, s := range m.shards {
		close(s.in)
	}
	m.wg.Wait()
	var st engine.Stats
	for _, s := range m.shards {
		st.Merge(s.e.Stats())
	}
	return st
}

// shardOf 按不区分方向的连接键选分片：两个端点排序后做哈希，
// 同一连接两个方向的包总是落到同一分片。
func shardOf(seg *decode.Segment, n int) int {
	a, b := seg.Src, seg.Dst
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	h := hashEndpoint(fnvOffset, a)
	h = hashEndpoint(h, b)
	// FNV-1a 的低位混合得差（端口只差低位时取模 4 分不开），先用 murmur3 的 fmix64 打散
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return int(h % uint64(n))
}

const (
	fnvOffset = 14695981039346656037
	fnvPrime  = 1099511628211
)

// hashEndpoint 把一个端点（16 字节地址和端口）混入 FNV-1a 哈希值 h。
func hashEndpoint(h uint64, ap netip.AddrPort) uint64 {
	addr := ap.Addr().As16()
	for _, c := range addr {
		h = (h ^ uint64(c)) * fnvPrime
	}
	p := ap.Port()
	h = (h ^ uint64(p>>8)) * fnvPrime
	return (h ^ uint64(p&0xff)) * fnvPrime
}
