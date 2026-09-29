package http1_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/http1"
)

func heapInUse() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// Upgrade 请求之后大量 1 字节的小包：缓存（数据加上每个包的记录）占用的内存
// 不能远超 64 KiB 上限；超出的部分在 Resume 时作为缺口交付。
func TestUpgradeHoldBoundedWithTinyPackets(t *testing.T) {
	const up = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"
	const total = 64 << 10
	r := &rec{}
	p := http1.NewParser(http1.Request, r, http1.Options{})
	p.Feed(0, []byte(up), -1, t0)
	payload := []byte(strings.Repeat("GET /2 HTTP/1.1\r\n\r\n", total/19+1)[:total])

	before := heapInUse()
	off := int64(len(up))
	// 每个包的时间都不同，和真实抓包一样，记录不能合并。
	for i := range payload {
		p.Feed(off, payload[i:i+1], int64(i), t0.Add(time.Duration(i)*time.Microsecond))
		off++
	}
	grown := int64(heapInUse()) - int64(before)
	// 切片按倍数扩容，实际占用最多是计入上限的两倍，再留一点余量。
	const limit = 2*64<<10 + 16<<10
	if grown > limit {
		t.Errorf("heap grew %d bytes while holding %d one-byte packets, want <= %d", grown, total, limit)
	}

	// 缓存放不下全部数据，Resume 时丢弃的部分以缺口交付。
	p.Resume()
	var gaps int
	for _, e := range r.ev {
		if strings.HasPrefix(e, "gap ") {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("gaps after resume = %d, want 1 (the dropped tail)", gaps)
	}
	runtime.KeepAlive(p)
}

// 缓存超过 64 KiB 的请求：超出的部分在 Resume 时作为 body 里的缺口交付，
// 缓存下来的字节加上缺口正好是整个 body，之后的请求照常解析。
func TestUpgradeHoldOverflowBecomesGap(t *testing.T) {
	const up = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"        // 40 字节
	const bigHead = "POST / HTTP/1.1\r\nContent-Length: 70000\r\n\r\n" // 42 字节
	const next = "GET /2 HTTP/1.1\r\n\r\n"
	body := strings.Repeat("b", 70000)
	events := func(held int) []string {
		return []string{
			"begin off=0", "raw head " + up, "head GET /ws HTTP/1.1 upgrade", "end true",
			"begin off=40", "raw head " + bigHead, "head POST / HTTP/1.1",
			"raw body " + body[:held], "body " + body[:held], fmt.Sprintf("gap body %d", 70000-held), "end true",
			"begin off=70082", "raw head " + next, "head GET /2 HTTP/1.1", "end true",
		}
	}
	// 整段喂入时缓存里只有一条记录（56 字节），能放下 65536-56-42 = 65438 字节 body。
	r := run(http1.Request, http1.Options{}, 0, data(up), data(bigHead+body), resume(), data(next))
	if want := events(65438); strings.Join(r.ev, "\n") != strings.Join(want, "\n") {
		t.Errorf("chunk=0 events:\n  got:  %.200q\n  want: %.200q", r.ev, want)
	}
	// 切分喂入时每段都有记录开销，缓存下来的 body 更少，但结构相同。
	for _, c := range []int{1, 1460} {
		r := run(http1.Request, http1.Options{}, c, data(up), data(bigHead+body), resume(), data(next))
		if len(r.ev) != 15 {
			t.Fatalf("chunk=%d events: %.300q", c, r.ev)
		}
		held := len(r.ev[8]) - len("body ")
		if held <= 0 || held > 65438 {
			t.Fatalf("chunk=%d: held %d body bytes", c, held)
		}
		if want := events(held); strings.Join(r.ev, "\n") != strings.Join(want, "\n") {
			t.Errorf("chunk=%d events:\n  got:  %.200q\n  want: %.200q", c, r.ev, want)
		}
	}
}
