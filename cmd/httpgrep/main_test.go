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
