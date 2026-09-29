// Command httpgrep 在 tcpdump 抓包里检索 HTTP/1.x 交互，输出命中的请求和响应。
package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
	"unsafe"

	"httpgrep/internal/cli"
	"httpgrep/internal/engine"
	"httpgrep/internal/run"
)

// version 是版本号，发布时用 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	os.Exit(httpgrep(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// httpgrep 执行一次检索，返回退出码。
func httpgrep(args []string, stdin, stdout *os.File, stderr io.Writer) int {
	opts, err := cli.Parse(args)
	if err != nil {
		fmt.Fprintf(stderr, "httpgrep: %v\nTry 'httpgrep --help' for more information.\n", err)
		return 2
	}
	if opts.Help {
		io.WriteString(stdout, cli.Usage)
		return 0
	}
	if opts.Version {
		io.WriteString(stdout, versionString())
		return 0
	}
	f := stdin
	if opts.File != "" && opts.File != "-" {
		f, err = os.Open(opts.File)
		if err != nil {
			return fail(stderr, err)
		}
		defer f.Close()
	}
	// 输入不是普通文件（管道、FIFO、终端）时启用真实时间兜底。
	fi, err := f.Stat()
	if err != nil {
		return fail(stderr, err)
	}
	pipe := !fi.Mode().IsRegular()
	tty := isTerminal(stdout)
	// 默认只用 1 个核，--cpus N 时用 N 个（run 按连接分给 N 个分片）。
	runtime.GOMAXPROCS(opts.CPUs)
	debug.SetMemoryLimit(memoryLimit(opts.MaxMemory))
	stop := watchSignals()
	start := time.Now()
	matched, st, err := run.Run(run.Config{Input: f, Pipe: pipe, Stop: stop, Stdout: stdout, Stderr: stderr, TTY: tty, Opts: opts})
	if opts.Stats {
		printStats(stderr, st, time.Since(start))
	}
	if err != nil {
		return fail(stderr, err)
	}
	if !matched {
		return 1
	}
	return 0
}

// memoryLimit 返回 Go 运行时的软内存上限：--max-memory 的 1.5 倍（设计文档第 8 节）。
// --max-memory 大到结果溢出时为负，SetMemoryLimit 对负数不做调整，等于不设上限。
// 先除后乘会截断很小的值（1 字节时得 0，SetMemoryLimit(0) 会让 GC 一直运行），所以写成加法。
func memoryLimit(maxMemory int64) int64 { return maxMemory + maxMemory/2 }

// fail 写出错信息，返回退出码 2。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "httpgrep: %v\n", err)
	return 2
}

// versionString 返回 --version 的输出，见 versionFrom。
func versionString() string {
	var settings []debug.BuildSetting
	if bi, ok := debug.ReadBuildInfo(); ok {
		settings = bi.Settings
	}
	return versionFrom(settings)
}

// versionFrom 按构建信息 settings 返回 --version 的输出：版本号，有 vcs.revision 时附在后面；
// 构建时工作区有未提交的改动（vcs.modified=true）时，revision 后面加 -dirty。
func versionFrom(settings []debug.BuildSetting) string {
	var rev string
	dirty := false
	for _, kv := range settings {
		switch kv.Key {
		case "vcs.revision":
			rev = kv.Value
		case "vcs.modified":
			dirty = kv.Value == "true"
		}
	}
	s := "httpgrep " + version
	if rev != "" {
		if dirty {
			rev += "-dirty"
		}
		s += " (revision " + rev + ")"
	}
	return s + "\n"
}

// printStats 按设计文档第 11 节把统计写到 stderr，每行一项。
func printStats(w io.Writer, st engine.Stats, elapsed time.Duration) {
	var capture time.Duration
	if !st.FirstTS.IsZero() {
		capture = st.LastTS.Sub(st.FirstTS)
	}
	mbps := 0.0
	if sec := elapsed.Seconds(); sec > 0 {
		mbps = float64(st.Bytes) / 1e6 / sec
	}
	fmt.Fprintf(w, "packets: %d\n", st.Packets)
	fmt.Fprintf(w, "bytes: %d\n", st.Bytes)
	fmt.Fprintf(w, "capture duration: %.3fs\n", capture.Seconds())
	fmt.Fprintf(w, "elapsed: %.3fs\n", elapsed.Seconds())
	fmt.Fprintf(w, "throughput: %.1f MB/s\n", mbps)
	for _, kv := range []struct {
		label string
		n     int64
	}{
		{"connections", st.Connections},
		{"mid-stream connections", st.MidStream},
		{"exchanges", st.Exchanges},
		{"matched", st.Matched},
		{"complete", st.Complete},
		{"no-request", st.NoRequest},
		{"incomplete", st.Incomplete},
		{"no-response(timeout)", st.NoResponseTimeout},
		{"no-response(closed)", st.NoResponseClosed},
		{"no-response(eof)", st.NoResponseEOF},
		{"late responses", st.Late},
		{"orphan messages", st.Orphans},
		{"evicted", st.Evicted},
		{"evicted matched", st.EvictedMatched},
		{"truncated messages", st.Truncated},
		{"gaps", st.Gaps},
		{"gap bytes", st.GapBytes},
		{"desyncs", st.Desyncs},
		{"non-HTTP connections", st.NonHTTP},
		{"ip fragments", st.Fragments},
		{"not tcp", st.NotTCP},
		{"malformed", st.Malformed},
	} {
		fmt.Fprintf(w, "%s: %d\n", kv.label, kv.n)
	}
	fmt.Fprintf(w, "peak buffered: %d bytes\n", st.PeakBuffered)
	fmt.Fprintf(w, "peak in-flight exchanges: %d\n", st.PeakInFlight)
	fmt.Fprintf(w, "peak connections: %d\n", st.PeakConns)
}

// watchSignals 在第一次收到 SIGINT 或 SIGTERM 时关闭返回的通道；之后再收到 SIGINT
// 立即以退出码 130 退出，再收到 SIGTERM 不处理（已经在收尾）。
// SIGPIPE 不注册，保持 Go 的默认行为：写标准输出遇到 EPIPE 时进程被 SIGPIPE 终止。
func watchSignals() <-chan struct{} {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	stop := make(chan struct{})
	go func() {
		<-sigs
		close(stop)
		for sig := range sigs {
			if sig == syscall.SIGINT {
				os.Exit(130)
			}
		}
	}()
	return stop
}

// isTerminal 报告 f 是不是终端：能读出终端属性（termios）就是。
// 管道、普通文件和 /dev/null 上这个 ioctl 返回 ENOTTY。
// 用 SyscallConn 而不是 Fd，免得把文件切成阻塞模式。
func isTerminal(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var e syscall.Errno
	err = rc.Control(func(fd uintptr) {
		var t syscall.Termios
		_, _, e = syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios, uintptr(unsafe.Pointer(&t)))
	})
	return err == nil && e == 0
}
