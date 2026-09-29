package run_test

import (
	"bytes"
	"testing"
	"time"

	"httpgrep/internal/cli"
	"httpgrep/internal/pcapgen"
	"httpgrep/internal/run"
)

// 不经 cli 校验、MaxMemory 小于分片数时，每个分片的上限至少是 1 字节，
// 不会被整除成 0（引擎把 0 当作不限）：上限 3 字节、4 个分片时连一条连接都放不下，
// 交互被丢弃，不会输出。
func TestRunShardShareNotZero(t *testing.T) {
	in := capture(t, func(w *pcapgen.Writer) {
		c := pcapgen.NewConn(w, cli1, srv)
		c.Handshake(ms(-1))
		c.ClientSend(ms(0), []byte("GET /HIT HTTP/1.1\r\n\r\n"))
		c.ServerSend(ms(1), []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	})
	o := cli.Options{Patterns: []string{"HIT"}, Timeout: 30 * time.Second, MaxMemory: 3, MaxMessage: 8 << 20, CPUs: 4}
	var out, errOut bytes.Buffer
	matched, _, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: &out, Stderr: &errOut, Opts: o})
	if err != nil {
		t.Fatal(err)
	}
	if matched || out.Len() != 0 {
		t.Fatalf("matched %v, stdout %q", matched, out.String())
	}
}
