// Command httpgrep 在 tcpdump 抓包里检索 HTTP/1.x 交互，输出命中的请求和响应。
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"httpgrep/internal/cli"
	"httpgrep/internal/run"
)

// version 是版本号，发布时用 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	os.Exit(httpgrep(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// httpgrep 执行一次检索，返回退出码。
func httpgrep(args []string, stdin *os.File, stdout, stderr io.Writer) int {
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
	matched, _, err := run.Run(run.Config{Input: f, Stdout: stdout, Stderr: stderr, Opts: opts})
	if err != nil {
		return fail(stderr, err)
	}
	if !matched {
		return 1
	}
	return 0
}

// fail 写出错信息，返回退出码 2。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "httpgrep: %v\n", err)
	return 2
}

// versionString 返回 --version 的输出：版本号，构建信息里有 vcs.revision 时附在后面。
func versionString() string {
	s := "httpgrep " + version
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "vcs.revision" && kv.Value != "" {
				s += " (revision " + kv.Value + ")"
			}
		}
	}
	return s + "\n"
}
