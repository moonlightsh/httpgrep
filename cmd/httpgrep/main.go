// Command httpgrep 在 tcpdump 抓包里检索 HTTP/1.x 交互，输出命中的请求和响应。
package main

import (
	"io"
	"os"

	"httpgrep/internal/cli"
	"httpgrep/internal/run"
)

func main() {
	os.Exit(httpgrep(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// httpgrep 执行一次检索，返回退出码。
func httpgrep(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, _ := cli.Parse(args)
	f, _ := os.Open(opts.File)
	defer f.Close()
	matched, _, _ := run.Run(run.Config{Input: f, Stdout: stdout, Stderr: stderr, Opts: opts})
	if !matched {
		return 1
	}
	return 0
}
