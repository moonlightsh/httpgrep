package main_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"httpgrep/internal/pcap"
	"httpgrep/internal/pcapgen"
)

// bin 是被测的可执行文件：默认由 TestMain 编译到临时目录，
// 设置了 HTTPGREP_BIN 时改用它指向的程序。
var bin string

func TestMain(m *testing.M) {
	if p := os.Getenv("HTTPGREP_BIN"); p != "" {
		bin = p
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "httpgrep-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	bin = filepath.Join(dir, "httpgrep")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n%s", err, out)
		os.RemoveAll(dir)
		os.Exit(2)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// t0 在 TZ=UTC 下渲染成 2026-09-28 07:30:12.345。
var t0 = time.Date(2026, 9, 28, 7, 30, 12, 345_000_000, time.UTC)

var (
	cli1 = netip.MustParseAddrPort("10.0.0.1:52814")
	cli2 = netip.MustParseAddrPort("10.0.0.1:52815")
	srv  = netip.MustParseAddrPort("10.0.0.2:80")
)

// ms 返回 t0 之后 n 毫秒的时间。
func ms(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Millisecond))) }

// capture 用 build 生成一份以太网抓包。
func capture(t testing.TB, build func(w *pcapgen.Writer)) []byte {
	t.Helper()
	var b bytes.Buffer
	w := pcapgen.NewWriter(&b, pcap.LinkEthernet)
	build(w)
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// twoExchanges 是两条连接各一个交互的抓包，只有第一个含 TOKEN-42。
func twoExchanges(t testing.TB) []byte {
	return capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"))
		c.ServerSend(ms(12), []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n"))
		c2 := pcapgen.NewConn(w, cli2, srv)
		c2.Handshake(ms(20))
		c2.ClientSend(ms(21), []byte("GET /b HTTP/1.1\r\n\r\n"))
		c2.ServerSend(ms(22), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
}

// block1 是 twoExchanges 里第一个交互的输出块。
const block1 = "2026-09-28 07:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 12.0ms\n" +
	"GET /a HTTP/1.1\r\nHost: x\r\n\r\n" +
	"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nid=TOKEN-42\n"

// block2 是 twoExchanges 里第二个交互的输出块。
const block2 = "2026-09-28 07:30:12.366 10.0.0.1:52815 -> 10.0.0.2:80 complete 1.0ms\n" +
	"GET /b HTTP/1.1\r\n\r\n" +
	"HTTP/1.1 204 No Content\r\n\r\n"

// writeFile 把 data 写到临时文件，返回路径。
func writeFile(t testing.TB, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.pcap")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type result struct {
	stdout, stderr string
	code           int
}

// command 构造一次运行：时区固定为 UTC。
func command(ctx context.Context, stdin io.Reader, args ...string) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	return cmd, &stdout, &stderr
}

// exitCode 取进程的退出码；不是正常退出时 t.Fatal。
func exitCode(t testing.TB, err error) int {
	t.Helper()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode()
	default:
		t.Fatalf("run %s: %v", bin, err)
		return -1
	}
}

// runBin 运行一次，最多 20 秒。
func runBin(t testing.TB, stdin io.Reader, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd, stdout, stderr := command(ctx, stdin, args...)
	err := cmd.Run()
	return result{stdout.String(), stderr.String(), exitCode(t, err)}
}

// want 比较一次运行的结果。
func want(t *testing.T, got result, stdout, stderr string, code int) {
	t.Helper()
	if got.stdout != stdout || got.stderr != stderr || got.code != code {
		t.Fatalf("got code %d\nstdout %q\nstderr %q\nwant code %d\nstdout %q\nstderr %q",
			got.code, got.stdout, got.stderr, code, stdout, stderr)
	}
}

// 读文件、有命中：输出命中的块，退出码 0。
func TestMatchFromFileExits0(t *testing.T) {
	p := writeFile(t, twoExchanges(t))
	want(t, runBin(t, nil, "TOKEN-42", p), block1, "", 0)
}

// 没有命中：什么都不输出，退出码 1。
func TestNoMatchExits1(t *testing.T) {
	p := writeFile(t, twoExchanges(t))
	want(t, runBin(t, nil, "NOPE", p), "", "", 1)
}

// 参数错误：stderr 写出错信息和提示行，退出码 2，不读输入。
func TestBadArgumentsExit2(t *testing.T) {
	const try = "Try 'httpgrep --help' for more information.\n"
	for _, tc := range []struct {
		args   []string
		stderr string
	}{
		{nil, "httpgrep: no pattern given\n" + try},
		{[]string{"--bogus", "x"}, "httpgrep: unknown option: --bogus\n" + try},
		{[]string{"x", "a.pcap", "b.pcap"}, "httpgrep: only one input file is supported\n" + try},
	} {
		t.Run(fmt.Sprint(tc.args), func(t *testing.T) {
			want(t, runBin(t, bytes.NewReader(twoExchanges(t)), tc.args...), "", tc.stderr, 2)
		})
	}
}

// 输入出错：stderr 写 "httpgrep: <错误>"，没有提示行，退出码 2。
func TestInputErrorsExit2(t *testing.T) {
	// 一个 pcapng 的 Section Header Block，长 28 字节。
	pcapng := []byte("\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\x1c\x00\x00\x00")
	missing := filepath.Join(t.TempDir(), "missing.pcap")
	for _, tc := range []struct {
		name   string
		file   string
		stderr string
	}{
		{"pcapng", writeFile(t, pcapng), "httpgrep: pcapng is not supported; capture with tcpdump -w\n"},
		{"empty", writeFile(t, nil), "httpgrep: empty input\n"},
		{"not-pcap", writeFile(t, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
			"httpgrep: input is not a pcap stream; pipe it from tcpdump -U -w -\n"},
		{"missing", missing, "httpgrep: open " + missing + ": no such file or directory\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want(t, runBin(t, nil, "x", tc.file), "", tc.stderr, 2)
		})
	}
}

// 不给文件或文件写成 - 时读标准输入。
func TestReadsStdin(t *testing.T) {
	for _, args := range [][]string{{"TOKEN-42"}, {"TOKEN-42", "-"}, {"-e", "TOKEN-42", "-"}} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			want(t, runBin(t, bytes.NewReader(twoExchanges(t)), args...), block1, "", 0)
		})
	}
}

// -e 可以写多次，命中任意一个就输出；-E 把关键词按正则处理。
func TestPatternOptions(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		stdout string
	}{
		{[]string{"-e", "TOKEN-42", "-e", "No Content"}, block1 + "--\n" + block2},
		{[]string{"-e", "No Content", "-e", "NOPE"}, block2},
		{[]string{"-E", "TOKEN-[0-9]+"}, block1},
		{[]string{"TOKEN-[0-9]+"}, ""},
		{[]string{"-E", "-e", "NOPE", "-e", "No C.ntent"}, block2},
	} {
		t.Run(fmt.Sprint(tc.args), func(t *testing.T) {
			code := 0
			if tc.stdout == "" {
				code = 1
			}
			want(t, runBin(t, bytes.NewReader(twoExchanges(t)), tc.args...), tc.stdout, "", code)
		})
	}
}

// --help 把帮助写到 stdout，退出码 0，不需要关键词、不读输入。
// 帮助覆盖设计文档第 2 节的全部选项，并写明 --max-memory 是近似上限、哪些缓存不计入。
func TestHelp(t *testing.T) {
	got := runBin(t, nil, "--help")
	if got.code != 0 || got.stderr != "" {
		t.Fatalf("code %d, stderr %q", got.code, got.stderr)
	}
	for _, s := range []string{
		"Usage: httpgrep [OPTION]... PATTERN [FILE]",
		"-e PATTERN", "-E ", "--timeout DUR", "(default 30s)",
		"--max-memory SIZE", "Approximate limit for buffered data (default 256M)",
		"-E line buffers", "Upgrade", "resync",
		"--max-message SIZE", "(default 8M)", "--cpus N", "(default 1)",
		"--stats", "--help", "--version",
		"K, M, G", "Exit status is 0 if an exchange matched, 1 if none matched, 2 on error.",
	} {
		if !strings.Contains(got.stdout, s) {
			t.Errorf("help lacks %q", s)
		}
	}
}

// --version 输出 "httpgrep <版本>"；版本默认是 dev，可以用 -ldflags -X main.version 注入；
// 构建信息里有 vcs.revision 时附在后面。
func TestVersion(t *testing.T) {
	if os.Getenv("HTTPGREP_BIN") != "" {
		t.Skip("HTTPGREP_BIN 指向外部程序，版本号未知")
	}
	t.Run("default", func(t *testing.T) {
		rev, err := exec.Command("git", "rev-parse", "HEAD").Output()
		if err != nil {
			t.Skip("git 不可用：", err)
		}
		got := runBin(t, nil, "--version")
		wantOut := "httpgrep dev (revision " + strings.TrimSpace(string(rev)) + ")\n"
		if got.code != 0 || got.stderr != "" || got.stdout != wantOut {
			t.Fatalf("code %d, stdout %q, stderr %q; want stdout %q", got.code, got.stdout, got.stderr, wantOut)
		}
	})
	t.Run("ldflags", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "httpgrep")
		out, err := exec.Command("go", "build", "-buildvcs=false", "-ldflags", "-X main.version=1.2.3", "-o", p, ".").CombinedOutput()
		if err != nil {
			t.Fatalf("go build: %v\n%s", err, out)
		}
		stdout, err := exec.Command(p, "--version").Output()
		if err != nil || string(stdout) != "httpgrep 1.2.3\n" {
			t.Fatalf("stdout %q, err %v; want %q", stdout, err, "httpgrep 1.2.3\n")
		}
	})
}

// --stats 退出前把统计写到 stderr，每行一项 "标签: 值"，覆盖设计文档第 11 节的各项。
// twoExchanges 有 10 个包：每条连接握手 3 个、请求 1 个、响应 1 个；
// 每个包 54 字节头（以太网 14 + IPv4 20 + TCP 20），加上载荷 28+51+19+27，共 665 字节；
// 包数、字节数和抓包时长 0.023s 都已用 capinfos 核对。
func TestStats(t *testing.T) {
	got := runBin(t, bytes.NewReader(twoExchanges(t)), "--stats", "TOKEN-42")
	if got.code != 0 || got.stdout != block1 {
		t.Fatalf("code %d, stdout %q", got.code, got.stdout)
	}
	lines := strings.Split(strings.TrimSuffix(got.stderr, "\n"), "\n")
	stats := map[string]string{}
	var labels []string
	for _, l := range lines {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			t.Fatalf("bad stats line %q in\n%s", l, got.stderr)
		}
		stats[k] = v
		labels = append(labels, k)
	}
	exact := [][2]string{
		{"packets", "10"},
		{"bytes", "665"},
		{"capture duration", "0.023s"},
		{"connections", "2"},
		{"mid-stream connections", "0"},
		{"exchanges", "2"},
		{"matched", "1"},
		{"complete", "2"},
		{"no-request", "0"},
		{"incomplete", "0"},
		{"no-response(timeout)", "0"},
		{"no-response(closed)", "0"},
		{"no-response(eof)", "0"},
		{"late responses", "0"},
		{"orphan messages", "0"},
		{"evicted", "0"},
		{"evicted matched", "0"},
		{"truncated messages", "0"},
		{"gaps", "0"},
		{"gap bytes", "0"},
		{"desyncs", "0"},
		{"ip fragments", "0"},
		{"not tcp", "0"},
		{"malformed", "0"},
		{"peak in-flight exchanges", "1"},
		{"peak connections", "2"},
	}
	for _, kv := range exact {
		if stats[kv[0]] != kv[1] {
			t.Errorf("%s = %q, want %q", kv[0], stats[kv[0]], kv[1])
		}
	}
	pattern := [][2]string{
		{"elapsed", `^[0-9]+\.[0-9]{3}s$`},
		{"throughput", `^[0-9]+\.[0-9] MB/s$`},
		{"peak buffered", `^[1-9][0-9]* bytes$`},
	}
	for _, kv := range pattern {
		if !regexp.MustCompile(kv[1]).MatchString(stats[kv[0]]) {
			t.Errorf("%s = %q, want match %s", kv[0], stats[kv[0]], kv[1])
		}
	}
	if len(labels) != len(exact)+len(pattern) {
		t.Errorf("got %d stats lines, want %d:\n%s", len(labels), len(exact)+len(pattern), got.stderr)
	}
}

// notifyBuffer 是并发安全的输出缓冲，每次写入后通知 wrote。
type notifyBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	wrote chan struct{}
}

func newNotifyBuffer() *notifyBuffer { return &notifyBuffer{wrote: make(chan struct{}, 1)} }

func (b *notifyBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	select {
	case b.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func (b *notifyBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor 等 b 的内容满足 ok，最多 d；超时返回假。
func (b *notifyBuffer) waitFor(d time.Duration, ok func(string) bool) bool {
	deadline := time.After(d)
	for !ok(b.String()) {
		select {
		case <-b.wrote:
		case <-deadline:
			return ok(b.String())
		}
	}
	return true
}

// piped 是一个从管道读标准输入、还在运行的进程。
type piped struct {
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	stdout, stderr *notifyBuffer
	cancel         context.CancelFunc
}

// startPiped 启动进程，标准输入是一个由测试持有写端的管道。进程最多运行 30 秒。
func startPiped(t *testing.T, args ...string) *piped {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	p := &piped{cmd: cmd, stdout: newNotifyBuffer(), stderr: newNotifyBuffer(), cancel: cancel}
	cmd.Stdout, cmd.Stderr = p.stdout, p.stderr
	var err error
	if p.stdin, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		p.stdin.Close()
		cmd.Wait()
	})
	return p
}

// wait 关闭标准输入之前不调用；返回退出码。
func (p *piped) wait(t *testing.T) int {
	t.Helper()
	return exitCode(t, p.cmd.Wait())
}

// slowRequest 是只有一个请求、没有响应的抓包。
func slowRequest(t testing.TB) []byte {
	return capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"))
	})
}

const slowReq = "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"

// 标准输入是管道时，超过 1 秒没有新包，时钟按真实时间往前推：
// 管道不关，请求也会在 --timeout 之后以 no-response(timeout) 输出。
func TestPipeRealTimeFallback(t *testing.T) {
	p := startPiped(t, "--timeout", "1s", "slow")
	if _, err := p.stdin.Write(slowRequest(t)); err != nil {
		t.Fatal(err)
	}
	const block = "2026-09-28 07:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" + slowReq
	start := time.Now()
	if !p.stdout.waitFor(10*time.Second, func(s string) bool { return s == block }) {
		t.Fatalf("after %v stdout %q, want %q", time.Since(start), p.stdout.String(), block)
	}
	// 兜底要等 1 秒没有新包才开始推时钟，再过 --timeout 才超时；留 100ms 余量给计时误差。
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Fatalf("block came after %v, want >= 1s", d)
	}
	p.stdin.Close()
	if code := p.wait(t); code != 0 {
		t.Fatalf("code %d, stderr %q", code, p.stderr.String())
	}
}

// startSlow 启动一个读管道的进程，写入一个没有响应的请求，管道不关。
// 请求后面跟约 256 KiB 的纯 ACK，远大于管道缓冲（64 KiB）：Write 返回时进程一定已经在
// run.Run 里读输入，信号也已经注册（注册在 run.Run 之前）。不用固定时长的 sleep，
// 因为 macOS 首次执行新编译的程序可能要花几百毫秒做签名检查。
func startSlow(t *testing.T) *piped {
	t.Helper()
	p := startPiped(t, "slow")
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte(slowReq))
		for range 3800 { // 每个 70 字节（记录头 16 + 帧 54）
			c.ClientAck(ms(0))
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := p.stdin.Write(in)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("process did not read its input within 10s")
	}
	time.Sleep(100 * time.Millisecond)
	return p
}

// waitExit 等进程退出，最多 d；超时 t.Fatal。
func (p *piped) waitExit(t *testing.T, d time.Duration) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		return exitCode(t, err)
	case <-time.After(d):
		t.Fatalf("still running after %v; stdout %q", d, p.stdout.String())
		return -1
	}
}

// 第一次 SIGINT 或 SIGTERM：结束在途交互，命中的以 no-response(eof) 输出，按有没有命中退出（0）。
// 管道不关，进程最多再读 1 秒就结束。
func TestSignalEndsInFlight(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			p := startSlow(t)
			if err := p.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			code := p.waitExit(t, 10*time.Second)
			const block = "2026-09-28 07:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(eof)\n" + slowReq
			if code != 0 || p.stdout.String() != block || p.stderr.String() != "" {
				t.Fatalf("code %d, stdout %q, stderr %q; want 0, %q", code, p.stdout.String(), p.stderr.String(), block)
			}
		})
	}
}

// 第二次 SIGINT 立即退出，退出码 130，不再输出在途交互。
func TestSecondSIGINTExits130(t *testing.T) {
	p := startSlow(t)
	for range 2 {
		if err := p.cmd.Process.Signal(syscall.SIGINT); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code := p.waitExit(t, 5*time.Second); code != 130 || p.stdout.String() != "" {
		t.Fatalf("code %d, stdout %q; want 130 and no output", code, p.stdout.String())
	}
}
