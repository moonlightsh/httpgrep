package engine

import "time"

// Stats 是引擎和 run 层共同填写的统计。
type Stats struct {
	// 由 run 层填写
	Packets, Bytes               int64
	NotTCP, Fragments, Malformed int64
	FirstTS, LastTS              time.Time
	// 由引擎填写
	Connections, MidStream int64 // MidStream 是没看到 SYN 的连接数
	Exchanges, Matched     int64
	// 按交互状态计数。一个交互可能同时计入多项；Complete 只计没有任何异常的。
	// Evicted 是因内存上限丢弃的交互数，EvictedMatched 是其中已经命中的；它们不计入状态和 Matched。
	// Truncated 按消息计：一个交互的请求和响应都超过 --max-message 时加 2。
	Complete, NoRequest, Incomplete                    int64
	NoResponseTimeout, NoResponseClosed, NoResponseEOF int64
	Late, Evicted, EvictedMatched, Truncated           int64
	// Desyncs 和 Orphans 不计从未对齐过起始行的连接（比如 TLS），这样的连接计入 NonHTTP，
	// 每条连接一次；对齐之前的失步和 Orphan 在第一次对齐时补计。
	Gaps, GapBytes, Desyncs, Orphans, NonHTTP int64
	PeakBuffered                              int64
	PeakInFlight, PeakConns                   int
}

// Merge 合并多个分片的统计：计数相加，峰值相加，FirstTS 取最早，LastTS 取最晚。
func (s *Stats) Merge(o Stats) {
	s.Packets += o.Packets
	s.Bytes += o.Bytes
	s.NotTCP += o.NotTCP
	s.Fragments += o.Fragments
	s.Malformed += o.Malformed
	if !o.FirstTS.IsZero() && (s.FirstTS.IsZero() || o.FirstTS.Before(s.FirstTS)) {
		s.FirstTS = o.FirstTS
	}
	if o.LastTS.After(s.LastTS) {
		s.LastTS = o.LastTS
	}
	s.Connections += o.Connections
	s.MidStream += o.MidStream
	s.Exchanges += o.Exchanges
	s.Matched += o.Matched
	s.Complete += o.Complete
	s.NoRequest += o.NoRequest
	s.Incomplete += o.Incomplete
	s.NoResponseTimeout += o.NoResponseTimeout
	s.NoResponseClosed += o.NoResponseClosed
	s.NoResponseEOF += o.NoResponseEOF
	s.Late += o.Late
	s.Evicted += o.Evicted
	s.EvictedMatched += o.EvictedMatched
	s.Truncated += o.Truncated
	s.Gaps += o.Gaps
	s.GapBytes += o.GapBytes
	s.Desyncs += o.Desyncs
	s.Orphans += o.Orphans
	s.NonHTTP += o.NonHTTP
	s.PeakBuffered += o.PeakBuffered
	s.PeakInFlight += o.PeakInFlight
	s.PeakConns += o.PeakConns
}
