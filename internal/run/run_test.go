package run_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/pcapgen"
	"httpgrep/internal/run"
)

// 普通文件输入：读完整份抓包，命中的交互整块写到 Stdout，matched 为真。
func TestRunFileOutputsMatchedExchange(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n"))
		c2 := pcapgen.NewConn(w, cli2, srv)
		c2.Handshake(ms(20))
		c2.ClientSend(ms(21), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c2.ServerSend(ms(22), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	var out bytes.Buffer
	matched, _, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "TOKEN-42")})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("matched = false, want true")
	}
	check(t, out.String(), "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 12.0ms\n"+
		"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"+
		"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n")
}

// 输入远大于一批（256 KiB）和整个批次池：包跨批次、批次复用之后，
// 每个交互的数据都不能串。400 个交互共约 1.7 MB，命中其中 4 个。
func TestRunLargeInputAcrossBatches(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		for i := range 400 {
			body := fmt.Sprintf("row-%03d:", i) + strings.Repeat("a", 3992)
			c.ClientSend(ms(float64(i*10)), fmt.Appendf(nil, "GET /%d HTTP/1.1\r\n\r\n", i))
			c.ServerSend(ms(float64(i*10+1)), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n"+body))
		}
	})
	var out bytes.Buffer
	matched, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "-E", "row-.07:")})
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("a", 3992)
	block := func(ts, i, row string) string {
		return "2026-09-28 " + ts + " 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n" +
			"GET /" + i + " HTTP/1.1\r\n\r\n" +
			"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\nrow-" + row + ":" + pad + "\n"
	}
	check(t, out.String(), block("15:30:12.415", "7", "007")+"--\n"+
		block("15:30:13.415", "107", "107")+"--\n"+
		block("15:30:14.415", "207", "207")+"--\n"+
		block("15:30:15.415", "307", "307"))
	if !matched || st.Exchanges != 400 || st.Matched != 4 {
		t.Fatalf("matched %v, stats %+v", matched, st)
	}
}

// 时钟不倒退：抓包里时间戳变小的包，按已经到达的最大时间戳交给引擎。
// 连接 2 的包排在连接 1 之后，时间戳却早 2 秒，它的交互按 15:30:15.347 计，耗时 0。
func TestRunClockNeverGoesBack(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(2999))
		c.ClientSend(ms(3000), []byte("GET /a HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(3002), []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT"))
		c2 := pcapgen.NewConn(w, cli2, srv)
		c2.Handshake(ms(999))
		c2.ClientSend(ms(1000), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c2.ServerSend(ms(1005), []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT"))
	})
	var out bytes.Buffer
	_, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "HIT")})
	if err != nil {
		t.Fatal(err)
	}
	check(t, out.String(), "2026-09-28 15:30:15.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 2.0ms\n"+
		"GET /a HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT\n--\n"+
		"2026-09-28 15:30:15.347 10.0.0.1:52815 -> 10.0.0.2:80 complete 0.0ms\n"+
		"GET /b HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHIT\n")
	if st.Complete != 2 {
		t.Fatalf("stats %+v", st)
	}
}

// 流量停下来、输入没有结束：Pipe 为真时超过 1 秒没有新包，时钟从最后一个包起按真实时间往前推，
// 只有请求的交互在 --timeout 2s 之后（约 2 秒，200ms 检查一次）以 no-response(timeout) 输出；
// Pipe 为假时时钟不动，3 秒内没有输出，输入结束后以 no-response(eof) 输出。
func TestRunPipeRealTimeFallback(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nX: HIT\r\n\r\n"))
	})
	head := "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 "
	req := "GET /a HTTP/1.1\r\nX: HIT\r\n\r\n"
	for _, tc := range []struct {
		name string
		pipe bool
		want string
	}{
		{"pipe", true, head + "no-response(timeout)\n" + req},
		{"file", false, head + "no-response(eof)\n" + req},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pr, pw := io.Pipe()
			defer pw.Close()
			out := newNotifyWriter()
			ch := goRun(run.Config{Input: pr, Pipe: tc.pipe, Stdout: out, Opts: opts(t, "--timeout", "2s", "HIT")})
			if _, err := pw.Write(in); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if tc.pipe {
				select {
				case <-out.wrote:
				case <-time.After(4500 * time.Millisecond):
					t.Fatal("no output within 4.5s")
				}
				if el := time.Since(start); el < 1800*time.Millisecond {
					t.Fatalf("output after %v, want about 2s", el)
				}
				check(t, out.String(), tc.want)
			} else {
				select {
				case <-out.wrote:
					t.Fatalf("output before input ended: %q", out.String())
				case <-time.After(3 * time.Second):
				}
			}
			pw.Close()
			r := wait(t, ch, 2*time.Second)
			if r.err != nil || !r.matched {
				t.Fatalf("matched %v err %v", r.matched, r.err)
			}
			check(t, out.String(), tc.want)
		})
	}
}

// Stop 关闭后最多再读 1 秒：读取卡在阻塞的 read 上（管道一直不关）时不等它，
// 约 1 秒后结束在途交互，只有请求的交互以 no-response(eof) 输出。
func TestRunStopGivesUpBlockedRead(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nX: HIT\r\n\r\n"))
	})
	pr, pw := io.Pipe()
	defer pw.Close()
	stop := make(chan struct{})
	var out bytes.Buffer
	ch := goRun(run.Config{Input: pr, Stop: stop, Stdout: &out, Opts: opts(t, "HIT")})
	if _, err := pw.Write(in); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	close(stop)
	r := wait(t, ch, 3*time.Second)
	if el := time.Since(start); el < 800*time.Millisecond || el > 2500*time.Millisecond {
		t.Fatalf("Run returned %v after Stop, want about 1s", el)
	}
	if r.err != nil || !r.matched {
		t.Fatalf("matched %v err %v", r.matched, r.err)
	}
	check(t, out.String(), "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n"+
		"GET /a HTTP/1.1\r\nX: HIT\r\n\r\n")
}

// Stop 关闭后 1 秒内写入的数据照样处理（连文件头都在 Stop 之后才到）；
// 读到输入结束就收尾，不等满 1 秒。
func TestRunStopReadsUntilEOF(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nX: HIT\r\n\r\n"))
		c.ServerSend(ms(4), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	pr, pw := io.Pipe()
	stop := make(chan struct{})
	var out bytes.Buffer
	ch := goRun(run.Config{Input: pr, Stop: stop, Stdout: &out, Opts: opts(t, "HIT")})
	start := time.Now()
	close(stop)
	time.Sleep(200 * time.Millisecond)
	if _, err := pw.Write(in); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	r := wait(t, ch, 3*time.Second)
	if el := time.Since(start); el > 900*time.Millisecond {
		t.Fatalf("Run returned %v after Stop, want right after EOF", el)
	}
	if r.err != nil || !r.matched {
		t.Fatalf("matched %v err %v", r.matched, r.err)
	}
	check(t, out.String(), "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 4.0ms\n"+
		"GET /a HTTP/1.1\r\nX: HIT\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")
}

// --cpus 4 时每个分片的内存上限是 --max-memory 的 1/4：一个缓存了约 100 KB 的在途请求
// 在 256K 的上限下放得下，在 64K 的分片上限下被丢弃，stderr 写一行告警。
func TestRunShardMemoryLimit(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("POST /up HTTP/1.1\r\nX: HIT\r\nContent-Length: 200000\r\n\r\n"))
		c.ClientSend(ms(1), bytes.Repeat([]byte("b"), 100000))
	})
	for _, tc := range []struct {
		cpus        string
		matched     bool
		evicted     int64
		stderr      string
		stdoutEmpty bool
	}{
		{"1", true, 0, "", false},
		{"4", false, 1, "httpgrep: dropped 1 in-flight exchanges (1 matched) to stay under --max-memory\n", true},
	} {
		t.Run("cpus="+tc.cpus, func(t *testing.T) {
			var out, errOut bytes.Buffer
			matched, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Stderr: &errOut,
				Opts: opts(t, "--cpus", tc.cpus, "--max-memory", "256K", "--max-message", "128K", "HIT")})
			if err != nil {
				t.Fatal(err)
			}
			if matched != tc.matched || st.Evicted != tc.evicted || (out.Len() == 0) != tc.stdoutEmpty {
				t.Fatalf("matched %v, Evicted %d, stdout %d bytes", matched, st.Evicted, out.Len())
			}
			check(t, errOut.String(), tc.stderr)
		})
	}
}
