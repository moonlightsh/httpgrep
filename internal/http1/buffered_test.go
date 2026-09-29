package http1_test

import (
	"strings"
	"testing"

	"httpgrep/internal/http1"
)

// Buffered 报告解析器内部缓存的字节：没收完的一行，以及 Upgrade 请求之后缓存的数据
// 加上每段 56 字节的记录。
func TestBuffered(t *testing.T) {
	t.Run("partial line", func(t *testing.T) {
		p := http1.NewParser(http1.Request, &rec{}, http1.Options{})
		p.Feed(0, []byte("GET / HTTP/1.1\r\nX: "+strings.Repeat("a", 1000)), -1, t0)
		if got := p.Buffered(); got != 1003 {
			t.Fatalf("Buffered = %d, want 1003", got)
		}
		p.Feed(1019, []byte("\r\n\r\n"), -1, t0)
		if got := p.Buffered(); got != 0 {
			t.Fatalf("Buffered after the head = %d, want 0", got)
		}
	})
	t.Run("upgrade hold", func(t *testing.T) {
		const up = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n" // 40 字节
		p := http1.NewParser(http1.Request, &rec{}, http1.Options{})
		p.Feed(0, []byte(up), -1, t0)
		p.Feed(40, []byte(strings.Repeat("x", 100)), -1, t0)
		if got := p.Buffered(); got != 156 {
			t.Fatalf("Buffered while held = %d, want 156", got)
		}
		p.Tunnel()
		if got := p.Buffered(); got != 0 {
			t.Fatalf("Buffered after Tunnel = %d, want 0", got)
		}
	})
}
