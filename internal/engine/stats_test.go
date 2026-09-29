package engine_test

import (
	"testing"
	"time"

	"httpgrep/internal/engine"
)

func TestStatsMerge(t *testing.T) {
	t1 := time.Date(2026, 9, 28, 7, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Second)
	t3 := t1.Add(2 * time.Second)
	a := engine.Stats{
		Packets: 1, Bytes: 2, NotTCP: 3, Fragments: 4, Malformed: 5,
		FirstTS: t2, LastTS: t2,
		Connections: 6, MidStream: 7, Exchanges: 8, Matched: 9,
		Complete: 10, NoRequest: 11, Incomplete: 12,
		NoResponseTimeout: 13, NoResponseClosed: 14, NoResponseEOF: 15,
		Late: 16, Evicted: 17, EvictedMatched: 18, Truncated: 19,
		Gaps: 20, GapBytes: 21, Desyncs: 22, Orphans: 23,
		PeakBuffered: 24, PeakInFlight: 25, PeakConns: 26,
	}
	b := engine.Stats{
		Packets: 100, Bytes: 200, NotTCP: 300, Fragments: 400, Malformed: 500,
		FirstTS: t1, LastTS: t3,
		Connections: 600, MidStream: 700, Exchanges: 800, Matched: 900,
		Complete: 1000, NoRequest: 1100, Incomplete: 1200,
		NoResponseTimeout: 1300, NoResponseClosed: 1400, NoResponseEOF: 1500,
		Late: 1600, Evicted: 1700, EvictedMatched: 1800, Truncated: 1900,
		Gaps: 2000, GapBytes: 2100, Desyncs: 2200, Orphans: 2300,
		PeakBuffered: 2400, PeakInFlight: 2500, PeakConns: 2600,
	}
	want := engine.Stats{
		Packets: 101, Bytes: 202, NotTCP: 303, Fragments: 404, Malformed: 505,
		FirstTS: t1, LastTS: t3,
		Connections: 606, MidStream: 707, Exchanges: 808, Matched: 909,
		Complete: 1010, NoRequest: 1111, Incomplete: 1212,
		NoResponseTimeout: 1313, NoResponseClosed: 1414, NoResponseEOF: 1515,
		Late: 1616, Evicted: 1717, EvictedMatched: 1818, Truncated: 1919,
		Gaps: 2020, GapBytes: 2121, Desyncs: 2222, Orphans: 2323,
		PeakBuffered: 2424, PeakInFlight: 2525, PeakConns: 2626,
	}
	got := a
	got.Merge(b)
	if got != want {
		t.Fatalf("Merge:\n got %+v\nwant %+v", got, want)
	}

	// 零值的时间不参与取最早、最晚。
	var z engine.Stats
	z.Merge(a)
	if !z.FirstTS.Equal(t2) || !z.LastTS.Equal(t2) {
		t.Fatalf("Merge into zero: FirstTS %v LastTS %v, want %v", z.FirstTS, z.LastTS, t2)
	}
	c := a
	c.Merge(engine.Stats{})
	if !c.FirstTS.Equal(t2) || !c.LastTS.Equal(t2) {
		t.Fatalf("Merge zero: FirstTS %v LastTS %v, want %v", c.FirstTS, c.LastTS, t2)
	}
}
