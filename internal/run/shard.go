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
	// flush 在一批包处理完后调用：把时钟推进到 now，把这批包里因内存上限丢弃的交互数
	// 报给 sink（各分片的合成一次），然后释放批次。
	flush(b *batch, now time.Time)
	// advance 在没有新包时推进时钟，丢弃数照样报给 sink。
	advance(now time.Time)
	// finish 结束输入并等所有分片停下，返回合并后的引擎统计。丢弃数报给 sink，
	// 补报剩下的累计数由调用方（sink.flushWarn）负责。
	finish(now time.Time) engine.Stats
	// abort 不结束在途交互，直接停下所有分片，返回合并后的引擎统计。
	abort() engine.Stats
}

// single 是单分片：引擎在主循环里运行。
type single struct {
	e    *engine.Engine
	free chan<- *batch
	out  *sink
	seen seen
}

func (s *single) segment(_ *batch, seg *decode.Segment, ts time.Time) { s.e.Segment(seg, ts) }

func (s *single) flush(b *batch, now time.Time) {
	s.advance(now)
	b.reset()
	s.free <- b
}

func (s *single) advance(now time.Time) {
	s.e.Advance(now)
	s.report(now)
}

func (s *single) finish(now time.Time) engine.Stats {
	s.e.Finish(now)
	s.report(now)
	return s.e.Stats()
}

// report 把还没报告过的丢弃数报给 sink。
func (s *single) report(now time.Time) {
	n, m := s.seen.delta(s.e.Stats())
	s.out.drop(n, m, now)
}

func (s *single) abort() engine.Stats { return s.e.Stats() }

// multi 是多分片：每个分片一个协程、一个引擎，按连接分包，时钟推进广播给所有分片。
//
// 输出顺序：同一分片内按交互结束的先后排列；不同分片的块按各分片写出的先后交错，
// 同一批包里在不同分片结束的交互，先后不保证与单核时一致。
// 内存告警：各分片处理完一批包后把丢弃数加到批次上，最后一个处理完的分片把合计报给 sink，
// 由 sink 统一限频，--cpus N 时也只有一路告警。
type multi struct {
	shards []*shard
	free   chan<- *batch
	out    *sink
	wg     sync.WaitGroup
}

// shard 是一个分片。
type shard struct {
	idx  int
	e    *engine.Engine
	in   chan work
	seen seen // 分片协程独占
}

// work 是交给分片的一项工作：先处理批次 b 里分给它的段（b 可以为 nil），
// 再把时钟推进到 now；fin 为真时改为结束输入。
type work struct {
	b   *batch
	now time.Time
	fin bool
}

// newMulti 创建 n 个分片，内存上限平均分给各分片。每个分片至少 1 字节：
// 整除成 0 的话引擎会当作不限（cli 已经拒绝 --max-memory 小于 --cpus，这里是兜底）。
func newMulti(n int, cfg engine.Config, free chan<- *batch, out *sink) *multi {
	if cfg.MaxMemory > 0 {
		cfg.MaxMemory = max(cfg.MaxMemory/int64(n), 1)
	}
	m := &multi{free: free, out: out}
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
		}
		if w.fin {
			s.e.Finish(w.now)
		} else {
			s.e.Advance(w.now)
		}
		n, k := s.seen.delta(s.e.Stats())
		if w.b != nil {
			w.b.dropped.Add(n)
			w.b.droppedMatched.Add(k)
			m.release(w.b, w.now)
		} else {
			m.out.drop(n, k, w.now)
		}
	}
}

// release 在一个分片处理完批次（包括随后的 Advance）后调用，最后一个分片把各分片的丢弃数
// 合计报给 sink，再把批次放回空闲池。
// 放回时不会阻塞：批次总数等于 free 的容量（poolSize），空闲池总放得下所有批次。
func (m *multi) release(b *batch, now time.Time) {
	if b.pending.Add(-1) == 0 {
		m.out.drop(b.dropped.Load(), b.droppedMatched.Load(), now)
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
