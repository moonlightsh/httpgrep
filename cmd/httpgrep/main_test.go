// 测试用 package main 而不是 main_test：黑盒测试运行的是 go build 出来的程序，
// 测试二进制本身要链接 main.go 及其依赖，main.go 或 internal 包改动时 go test 的缓存才会失效。
package main

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
	args := []string{"build", "-o", bin}
	if raceEnabled {
		args = append(args, "-race")
	}
	out, err := exec.Command("go", append(args, ".")...).CombinedOutput()
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
		{[]string{"--cpus", "100000", "x"}, "httpgrep: invalid value for --cpus: 100000 (at most 1024)\n" + try},
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
		"--max-message SIZE", "(default 8M)", "--cpus N", "1 to 1024 (default 1)",
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
		{"non-HTTP connections", "0"},
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
// cmd.Wait 只能调用一次（第二次调用会一直阻塞），所以只在一个协程里调用它，
// 结果放在 err 里，done 关闭后可读；waitExit 和 Cleanup 都从 done 取结果。
type piped struct {
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	stdout, stderr *notifyBuffer
	cancel         context.CancelFunc
	done           chan struct{}
	err            error
}

// startPiped 启动进程，标准输入是一个由测试持有写端的管道。进程最多运行 30 秒。
func startPiped(t *testing.T, args ...string) *piped {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	p := &piped{cmd: cmd, stdout: newNotifyBuffer(), stderr: newNotifyBuffer(), cancel: cancel, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = p.stdout, p.stderr
	var err error
	if p.stdin, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		// 先杀掉进程再等：测试失败时进程可能还在运行。
		cancel()
		p.stdin.Close()
		<-p.done
	})
	return p
}

// wait 在关闭标准输入之后调用，等进程退出（最多 10 秒），返回退出码。
func (p *piped) wait(t *testing.T) int {
	t.Helper()
	return p.waitExit(t, 10*time.Second)
}

const slowReq = "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"

// 标准输入是管道时，超过 1 秒没有新包，时钟按真实时间往前推：
// 管道不关，请求也会在 --timeout 之后以 no-response(timeout) 输出。
//   - 2s：计划里的参数，约 2 秒（不到 3 秒）输出。
//   - 300ms：比 1 秒的阈值短，兜底要等 1 秒没有新包才开始推时钟，不能约 300ms 就输出。
//
// 输入用 slowInput（请求后面跟约 256 KiB 的纯 ACK）：Write 返回时进程已经读到了最后几批包，
// 计时从这时算起，不受进程启动慢（macOS 首次执行要做签名检查）的影响。
// 下界各留 100ms 余量给计时误差。上界多留约 1 秒：新编译的程序第一次运行时，
// macOS 上偶尔观察到输出晚约 0.8 秒。
func TestPipeRealTimeFallback(t *testing.T) {
	for _, tc := range []struct {
		timeout  string
		min, max time.Duration
	}{
		{"2s", 1900 * time.Millisecond, 4 * time.Second},
		{"300ms", 900 * time.Millisecond, 3 * time.Second},
	} {
		t.Run(tc.timeout, func(t *testing.T) {
			t.Parallel()
			p := startPiped(t, "--timeout", tc.timeout, "slow")
			if _, err := p.stdin.Write(slowInput(t)); err != nil {
				t.Fatal(err)
			}
			const block = "2026-09-28 07:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 no-response(timeout)\n" + slowReq
			start := time.Now()
			if !p.stdout.waitFor(10*time.Second, func(s string) bool { return s == block }) {
				t.Fatalf("after %v stdout %q, want %q", time.Since(start), p.stdout.String(), block)
			}
			if d := time.Since(start); d < tc.min || d > tc.max {
				t.Fatalf("block came after %v, want between %v and %v", d, tc.min, tc.max)
			}
			p.stdin.Close()
			if code := p.wait(t); code != 0 {
				t.Fatalf("code %d, stderr %q", code, p.stderr.String())
			}
		})
	}
}

// slowInput 是一个没有响应的请求，后面跟约 256 KiB 的纯 ACK，远大于管道缓冲（64 KiB）：
// 把它写进管道，Write 返回时进程一定已经在 run.Run 里读输入，信号也已经注册
// （注册在 run.Run 之前）。所有包的时间戳相同，ACK 不影响交互。
func slowInput(t testing.TB) []byte {
	return capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte(slowReq))
		for range 3800 { // 每个 70 字节（记录头 16 + 帧 54）
			c.ClientAck(ms(0))
		}
	})
}

// startSlow 启动一个读管道的进程，写入 slowInput，管道不关。
// 不用固定时长的 sleep 等进程就绪，因为 macOS 首次执行新编译的程序可能要花几百毫秒做签名检查。
func startSlow(t *testing.T) *piped {
	t.Helper()
	p := startPiped(t, "slow")
	in := slowInput(t)
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

// waitExit 等进程退出，最多 d；超时 t.Fatal（Cleanup 随后杀掉进程）。
func (p *piped) waitExit(t *testing.T, d time.Duration) int {
	t.Helper()
	select {
	case <-p.done:
		return exitCode(t, p.err)
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

// 标准输出被关闭时，和 grep 一样被 SIGPIPE 终止（Go 对 fd 1 写出 EPIPE 时的默认行为）。
func TestClosedStdoutKilledBySIGPIPE(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "TOKEN-42")
	cmd.Stdin = bytes.NewReader(twoExchanges(t))
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("err = %v, want killed by SIGPIPE", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGPIPE {
		t.Fatalf("exit %v, stderr %q; want killed by SIGPIPE", err, stderr.String())
	}
}

// 终端检测：管道、/dev/null、普通文件都不是终端，伪终端是。
func TestIsTerminal(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	file, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, tc := range []struct {
		name string
		f    *os.File
		want bool
	}{
		{"devnull", null, false},
		{"pipe", w, false},
		{"file", file, false},
	} {
		if got := isTerminal(tc.f); got != tc.want {
			t.Errorf("%s: isTerminal = %v, want %v", tc.name, got, tc.want)
		}
	}
	master, slave, err := openPTY()
	if err != nil {
		t.Skip("no pty: ", err)
	}
	defer master.Close()
	defer slave.Close()
	if !isTerminal(slave) {
		t.Error("pty: isTerminal = false, want true")
	}
}

// ctlHeader 是请求头里带控制字符 \x01 和 ESC 的抓包。
func ctlHeader(t testing.TB) []byte {
	return capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /c HTTP/1.1\r\nX-Ctl: a\x01b\x1bc\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
}

// ctlBlock 是 ctlHeader 不转义时的输出块。
const ctlBlock = "2026-09-28 07:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\n" +
	"GET /c HTTP/1.1\r\nX-Ctl: a\x01b\x1bc\r\n\r\n" +
	"HTTP/1.1 204 No Content\r\n\r\n"

// 输出到普通文件或管道时不转义、不加颜色，逐字节等于抓到的内容。
func TestNonTerminalOutputIsRaw(t *testing.T) {
	in := writeFile(t, ctlHeader(t))
	t.Run("pipe", func(t *testing.T) {
		want(t, runBin(t, nil, "X-Ctl", in), ctlBlock, "", 0)
	})
	t.Run("file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out")
		f, err := os.Create(out)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cmd := exec.Command(bin, "X-Ctl", in)
		cmd.Env = append(os.Environ(), "TZ=UTC")
		cmd.Stdout = f
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != ctlBlock {
			t.Fatalf("file content %q, want %q", got, ctlBlock)
		}
	})
}

// 输出到终端时：控制字符转成 \xNN，定位行标紫，命中的文字标红。
// 伪终端会把 \n 转成 \r\n，所以只比较不跨行的片段。
func TestTerminalOutputIsEscaped(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skip("no pty: ", err)
	}
	defer master.Close()
	cmd := exec.Command(bin, "X-Ctl", writeFile(t, ctlHeader(t)))
	cmd.Env = append(os.Environ(), "TZ=UTC")
	cmd.Stdout = slave
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close() // 只留子进程持有从端，子进程退出后读主端才会结束
	read := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(master) // 从端全部关闭后返回 EIO 或 EOF
		read <- b
	}()
	if code := exitCode(t, cmd.Wait()); code != 0 {
		t.Fatalf("code %d", code)
	}
	var got []byte
	select {
	case got = <-read:
	case <-time.After(10 * time.Second):
		t.Fatal("pty read did not finish")
	}
	for _, s := range []string{
		"\x1b[35m2026-09-28 07:30:12.345 10.0.0.1:52814 -> 10.0.0.2:80 complete 1.0ms\x1b[m",
		"\x1b[01;31mX-Ctl\x1b[m",
		`a\x01b\x1bc`,
	} {
		if !bytes.Contains(got, []byte(s)) {
			t.Errorf("terminal output lacks %q:\n%q", s, got)
		}
	}
	if bytes.IndexByte(got, 0x01) >= 0 {
		t.Errorf("terminal output has raw \\x01: %q", got)
	}
}

// bigCapture 是一条连接上 400 个交互的抓包，每个响应 4000 字节 body，共约 1.7 MB；
// 只有第 7 个含 row-007。
func bigCapture(t testing.TB) []byte {
	return capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		for i := range 400 {
			body := fmt.Sprintf("row-%03d:", i) + strings.Repeat("a", 3992)
			c.ClientSend(ms(float64(i*10)), fmt.Appendf(nil, "GET /%d HTTP/1.1\r\n\r\n", i))
			c.ServerSend(ms(float64(i*10+1)), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n"+body))
		}
	})
}

// gcLine 匹配 GODEBUG=gctrace=1 每次 GC 写到 stderr 的一行，取出 P 的个数（GOMAXPROCS）。
var gcLine = regexp.MustCompile(`(?m)^gc \d+ @.* (\d+) P( \(forced\))?$`)

// 运行时参数：GOMAXPROCS 取 --cpus（默认 1），软内存上限按 --max-memory 设置（1.5 倍）。
// 从外部观察：GOGC=off 时只有内存上限会触发 GC，gctrace 的每一行写明 P 的个数。
// --max-memory 1M 时上限是 1.5 MiB，处理约 1.7 MB 的输入必然触发 GC；
// 默认 256M 时上限是 384 MiB，这么小的输入不会触发 GC。
// 环境变量 GOMAXPROCS=2 用来确认 P 的个数来自 --cpus，而不是环境或 CPU 核数。
func TestRuntimeLimits(t *testing.T) {
	in := writeFile(t, bigCapture(t))
	for _, tc := range []struct {
		args []string
		p    string // 空串表示不应该发生 GC
	}{
		{[]string{"--max-memory", "1M", "--max-message", "64K"}, "1"},
		{[]string{"--max-memory", "1M", "--max-message", "64K", "--cpus", "3"}, "3"},
		{nil, ""},
	} {
		t.Run(fmt.Sprint(tc.args), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd, stdout, stderr := command(ctx, nil, append(tc.args, "row-007:", in)...)
			cmd.Env = append(cmd.Env, "GOGC=off", "GODEBUG=gctrace=1", "GOMAXPROCS=2")
			if code := exitCode(t, cmd.Run()); code != 0 {
				t.Fatalf("code %d, stderr %s", code, stderr)
			}
			if !strings.Contains(stdout.String(), "row-007:") {
				t.Fatalf("stdout %q", stdout)
			}
			ms := gcLine.FindAllStringSubmatch(stderr.String(), -1)
			switch {
			case tc.p == "" && len(ms) > 0:
				t.Fatalf("GC with GOGC=off and a 384 MiB limit: %s", ms[0][0])
			case tc.p == "":
			case len(ms) == 0:
				t.Fatalf("no GC with GOGC=off: memory limit not set; stderr:\n%s", stderr)
			default:
				for _, m := range ms {
					if m[1] != tc.p {
						t.Fatalf("GOMAXPROCS %s, want %s: %s", m[1], tc.p, m[0])
					}
				}
			}
		})
	}
}

// -E 的关键词编译失败：写出错信息，退出码 2（没有提示行，出错的是关键词内容而不是参数格式）。
func TestInvalidRegexExits2(t *testing.T) {
	want(t, runBin(t, bytes.NewReader(twoExchanges(t)), "-E", "("), "",
		"httpgrep: match: invalid pattern \"(\": error parsing regexp: missing closing ): `(`\n", 2)
}
