package run_test

import (
	"testing"

	"httpgrep/internal/run"
)

// 单条记录比批次（256 KiB）还大时，批次临时换成更大的缓冲区；复用前换回 256 KiB，
// 不让 4 个批次各留着最多 16 MiB。
func TestBatchBufferShrinksOnReset(t *testing.T) {
	if got := run.BatchCapAfterReset(8 << 20); got != 256<<10 {
		t.Fatalf("cap after reset = %d, want %d", got, 256<<10)
	}
	if got := run.BatchCapAfterReset(256 << 10); got != 256<<10 {
		t.Fatalf("cap after reset = %d, want %d", got, 256<<10)
	}
}
