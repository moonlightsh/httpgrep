package run_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/match"
	"httpgrep/internal/pcap"
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
// --cpus 4 时同样如此。Pipe 为假时时钟不动，3 秒内没有输出，输入结束后以 no-response(eof) 输出。
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
		cpus string
		want string
	}{
		{"pipe", true, "1", head + "no-response(timeout)\n" + req},
		{"pipe-cpus4", true, "4", head + "no-response(timeout)\n" + req}, // 时钟推进广播给所有分片
		{"file", false, "1", head + "no-response(eof)\n" + req},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pr, pw := io.Pipe()
			defer pw.Close()
			out := newNotifyWriter()
			ch := goRun(run.Config{Input: pr, Pipe: tc.pipe, Stdout: out, Opts: opts(t, "--cpus", tc.cpus, "--timeout", "2s", "HIT")})
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

// 200 个命中的交互交错在 50 条连接上：--cpus 1 和 --cpus 4 输出的块集合相同（排序后比较），
// 合并后的统计也相同。
func TestRunShardsSameBlocks(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		var conns []*pcapgen.Conn
		k := 0.0
		next := func() time.Time { k++; return ms(k) }
		for j := range 50 {
			c := pcapgen.NewConn(w, netip.AddrPortFrom(cli1.Addr(), uint16(40000+j)), srv)
			c.Handshake(next())
			conns = append(conns, c)
		}
		for r := range 4 {
			for j, c := range conns {
				c.ClientSend(next(), fmt.Appendf(nil, "GET /c%d/r%d HTTP/1.1\r\nX: HIT\r\n\r\n", j, r))
			}
			for j, c := range conns {
				c.ServerSend(next(), fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nc%02dr%d\n", j, r))
			}
		}
	})
	blocks := map[string][]string{}
	for _, cpus := range []string{"1", "4"} {
		var out bytes.Buffer
		matched, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Opts: opts(t, "--cpus", cpus, "HIT")})
		if err != nil {
			t.Fatal(err)
		}
		if !matched || st.Exchanges != 200 || st.Matched != 200 || st.Complete != 200 || st.Connections != 50 {
			t.Fatalf("cpus=%s: matched %v, stats %+v", cpus, matched, st)
		}
		b := strings.Split(out.String(), "--\n")
		slices.Sort(b)
		blocks[cpus] = b
	}
	if len(blocks["1"]) != 200 {
		t.Fatalf("cpus=1: %d blocks, want 200", len(blocks["1"]))
	}
	// 第 7 条连接第 2 轮：请求在第 50+100*2+7+1 毫秒，响应在其后 50 毫秒。
	want := "2026-09-28 15:30:12.603 10.0.0.1:40007 -> 10.0.0.2:80 complete 50.0ms\n" +
		"GET /c7/r2 HTTP/1.1\r\nX: HIT\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nc07r2\n"
	if !slices.Contains(blocks["1"], want) {
		t.Fatalf("cpus=1 output lacks %q", want)
	}
	if !slices.Equal(blocks["1"], blocks["4"]) {
		t.Fatalf("block sets differ\ncpus=1: %q\ncpus=4: %q", blocks["1"], blocks["4"])
	}
}

// 输入错误：不支持的链路层类型报 unsupported link type N；文件头错误原样返回 pcap 的错误；
// 读到一半记录损坏时，已经读到的交互照常结束并输出，然后返回 pcap.ErrCorrupt。
func TestRunInputErrors(t *testing.T) {
	var unsupported bytes.Buffer
	pcapgen.NewWriter(&unsupported, pcap.LinkType(147))
	good := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nX: HIT\r\n\r\n"))
	})
	// 小端记录头：时间 0，caplen 0x7fffffff 超出上限
	corrupt := append(slices.Clip(good), 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0x7f)
	for _, tc := range []struct {
		name    string
		in      []byte
		err     error  // 原样返回，按值比较；为 nil 时比较 msg
		msg     string // 错误文本
		stdout  string
		matched bool
	}{
		{name: "link", in: unsupported.Bytes(), msg: "unsupported link type 147"},
		{name: "pcapng", in: []byte{0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0}, err: pcap.ErrPcapNG},
		{name: "notpcap", in: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), err: pcap.ErrNotPcap},
		{name: "empty", in: nil, err: pcap.ErrEmpty},
		{name: "corrupt", in: corrupt, err: pcap.ErrCorrupt, matched: true,
			stdout: "2026-09-28 15:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\nGET /a HTTP/1.1\r\nX: HIT\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			matched, _, err := run.Run(run.Config{Input: bytes.NewReader(tc.in), Stdout: &out, Opts: opts(t, "HIT")})
			switch {
			case tc.err != nil && err != tc.err:
				t.Fatalf("err = %v, want %v", err, tc.err)
			case tc.err == nil && (err == nil || err.Error() != tc.msg):
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
			if matched != tc.matched {
				t.Fatalf("matched = %v, want %v", matched, tc.matched)
			}
			check(t, out.String(), tc.stdout)
		})
	}
}

// errWriter 的每次写入都失败。
type errWriter struct{}

var errDisk = errors.New("disk full")

func (errWriter) Write([]byte) (int, error) { return 0, errDisk }

// 输出写入失败：Run 返回这个错误，matched 为假；输入是一直不关的管道时也要马上返回，不等输入结束。
func TestRunWriteError(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nX: HIT\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	for _, cpus := range []string{"1", "4"} {
		t.Run("file/cpus="+cpus, func(t *testing.T) {
			matched, _, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: errWriter{}, Opts: opts(t, "--cpus", cpus, "HIT")})
			if err != errDisk || matched {
				t.Fatalf("matched %v err %v, want false %v", matched, err, errDisk)
			}
		})
		t.Run("pipe/cpus="+cpus, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pw.Close()
			ch := goRun(run.Config{Input: pr, Pipe: true, Stdout: errWriter{}, Opts: opts(t, "--cpus", cpus, "HIT")})
			if _, err := pw.Write(in); err != nil {
				t.Fatal(err)
			}
			r := wait(t, ch, 2*time.Second)
			if r.err != errDisk || r.matched {
				t.Fatalf("matched %v err %v, want false %v", r.matched, r.err, errDisk)
			}
		})
	}
}

// 统计：Packets、Bytes（按 caplen）统计所有记录，NotTCP、Fragments、Malformed 按解码结果计数，
// FirstTS、LastTS 是最早和最晚的时间戳；--cpus 4 时引擎的统计按分片合并。
func TestRunStats(t *testing.T) {
	syn := pcapgen.Frame(pcap.LinkEthernet, pcapgen.TCP(cli1, srv, 100, 0, decode.SYN, nil)) // 14+20+20 = 54 字节
	udp := pcapgen.TCP(cli1, srv, 100, 0, decode.SYN, nil)
	udp[9] = 17 // 协议号改成 UDP
	frag := pcapgen.TCP(cli1, srv, 100, 0, decode.SYN, nil)
	frag[6] = 0x20 // MF 置位
	short := pcapgen.TCP(cli1, srv, 100, 0, decode.SYN, nil)[:10]
	data := pcapgen.Frame(pcap.LinkEthernet, pcapgen.TCP(cli2, srv, 1, 1, decode.ACK, bytes.Repeat([]byte("x"), 100))) // 154 字节
	in := capture(t, func(w *pcapgen.Writer) {
		w.Record(ms(0), syn, 0)
		w.Record(ms(5), pcapgen.Frame(pcap.LinkEthernet, udp), 0)
		w.Record(ms(-2), pcapgen.Frame(pcap.LinkEthernet, frag), 0) // 时间戳比前一个早
		w.Record(ms(6), pcapgen.Frame(pcap.LinkEthernet, short), 0) // 24 字节
		w.Record(ms(7), data[:100], len(data))                      // 被 snaplen 截断，caplen 100
	})
	for _, cpus := range []string{"1", "4"} {
		t.Run("cpus="+cpus, func(t *testing.T) {
			_, st, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: io.Discard, Opts: opts(t, "--cpus", cpus, "HIT")})
			if err != nil {
				t.Fatal(err)
			}
			if st.Packets != 5 || st.Bytes != 286 || st.NotTCP != 1 || st.Fragments != 1 || st.Malformed != 1 ||
				!st.FirstTS.Equal(ms(-2)) || !st.LastTS.Equal(ms(7)) || st.Connections != 2 {
				t.Fatalf("stats %+v", st)
			}
		})
	}
}

// 输出到终端时命中的文字标红：TTY 时把关键词的高亮交给 output。
func TestRunTTYHighlight(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /HIT HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	var out bytes.Buffer
	if _, _, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, TTY: true, Opts: opts(t, "HIT")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "GET /\x1b[01;31mHIT\x1b[m HTTP/1.1") {
		t.Fatalf("no highlight in %q", out.String())
	}
}

// 关键词编译失败时返回 match 的错误，不读输入。
func TestRunBadPattern(t *testing.T) {
	_, _, err := run.Run(run.Config{Input: strings.NewReader(""), Stdout: io.Discard, Opts: opts(t, "-E", "(")})
	var ce *match.CompileError
	if !errors.As(err, &ce) || ce.Pattern != "(" {
		t.Fatalf("err = %v, want *match.CompileError for %q", err, "(")
	}
}
