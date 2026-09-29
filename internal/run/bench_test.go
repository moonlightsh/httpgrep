package run_test

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	"httpgrep/internal/pcapgen"
	"httpgrep/internal/run"
)

// BenchmarkRun 回放 200 条连接上的 4000 个交互（约 5 MB），关键词不命中。
func BenchmarkRun(b *testing.B) {
	in := capture(b, func(w *pcapgen.Writer) {
		var conns []*pcapgen.Conn
		k := 0.0
		for j := range 200 {
			c := pcapgen.NewConn(w, netip.AddrPortFrom(cli1.Addr(), uint16(20000+j)), srv)
			k++
			c.Handshake(ms(k))
			conns = append(conns, c)
		}
		body := strings.Repeat("abcdefghij", 100)
		for r := range 20 {
			for j, c := range conns {
				k++
				c.ClientSend(ms(k), fmt.Appendf(nil, "GET /c%d/r%d HTTP/1.1\r\nHost: x\r\n\r\n", j, r))
				c.ServerSend(ms(k), []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"+body))
			}
		}
	})
	for _, cpus := range []string{"1", "4"} {
		b.Run("cpus="+cpus, func(b *testing.B) {
			o := opts(b, "--cpus", cpus, "NOPE")
			b.SetBytes(int64(len(in)))
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := run.Run(run.Config{Input: bytes.NewReader(in), Stdout: io.Discard, Opts: o}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
