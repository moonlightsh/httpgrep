package cli_test

import (
	"testing"

	"httpgrep/internal/cli"
)

// 基准：典型命令行的解析速度。
func BenchmarkParse(b *testing.B) {
	args := []string{
		"-E", "-e", "error[0-9]+", "-e", "timeout\nreset",
		"--timeout=45s", "--max-memory=512M", "--max-message=16M",
		"--cpus=4", "--stats", "capture.pcap",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := cli.Parse(args); err != nil {
			b.Fatal(err)
		}
	}
}
