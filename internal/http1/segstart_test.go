package http1_test

import (
	"testing"

	"httpgrep/internal/http1"
)

// 扫描状态下，每次 Feed（一个 TCP 段）的开头也算行首候选：失步前的字节不以换行结尾时
// （JSON 这类 body 通常如此），下一个段开头的起始行照样能对齐。
// 同一次 Feed 里行中间的起始行仍然不算；跨 Feed 的起始行候选接着缓存，不从新 Feed 的开头重来。
func TestScanSegmentStart(t *testing.T) {
	const ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" // 40 字节
	okEv := func(off string) []string {
		return []string{"begin off=" + off, "raw head HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
			"head 200 HTTP/1.1", "raw body ok", "body ok", "end true"}
	}
	resync := http1.Options{Resync: true}
	t.Run("body tail without newline, then a new segment", func(t *testing.T) {
		r := run(http1.Response, resync, 0, data(`"end":1}`), data(ok))
		checkEvents(t, r, append([]string{"begin off=0 orphan", `raw unparsed "end":1}`, "end false"}, okEv("8")...))
	})
	t.Run("desync, unparsed tail without newline, then a new segment", func(t *testing.T) {
		r := run(http1.Response, http1.Options{}, 0, data("HTTP/1.1 200 OK\r\n"), gap(19), data("X: 1\r\n\r\nr1"), data(ok))
		checkEvents(t, r, append([]string{"begin off=0", "raw head HTTP/1.1 200 OK\r\n", "desync 17", "gap unparsed 19",
			"raw unparsed X: 1\r\n\r\nr1", "end false"}, okEv("46")...))
	})
	t.Run("start line in the middle of a segment is not a candidate", func(t *testing.T) {
		r := run(http1.Response, resync, 0, data("r1"+ok))
		checkEvents(t, r, []string{"begin off=0 orphan", "raw unparsed r1" + ok})
	})
	t.Run("candidate spanning two segments", func(t *testing.T) {
		r := run(http1.Response, resync, 0, data("tail"), data("HTTP/1.1 2"), data("00 OK\r\nContent-Length: 2\r\n\r\nok"))
		checkEvents(t, r, append([]string{"begin off=0 orphan", "raw unparsed tail", "end false"}, okEv("4")...))
	})
	t.Run("segment start that is not a start line", func(t *testing.T) {
		r := run(http1.Response, resync, 0, data("tail"), data("more"+ok))
		checkEvents(t, r, []string{"begin off=0 orphan", "raw unparsed tailmore" + ok})
	})
}
