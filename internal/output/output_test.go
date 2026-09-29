package output_test

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"httpgrep/internal/output"
)

var tz = time.FixedZone("CST", 8*3600)

// render 渲染单个块，返回写出的字节。
func render(t *testing.T, opt output.Options, blocks ...*output.Block) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := output.NewWriter(&buf, opt)
	for i := range blocks {
		if err := w.Write(blocks[i]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	return buf.Bytes()
}

// locateLine 是一条只有定位行、没有内容的块。
func locateLine(t *testing.T, b output.Block) string {
	t.Helper()
	return string(render(t, output.Options{Location: tz}, &b))
}

func TestLocationLineFormat(t *testing.T) {
	got := locateLine(t, output.Block{
		Time:   time.Unix(1790580612, 345000000).In(tz), // 2026-09-28 15:30:12.345 +08
		Client: mustAddr("127.0.0.1:52814"),
		Server: mustAddr("127.0.0.1:7010"),
		Status: output.Status{},
		Duration: func() time.Duration {
			return time.Duration(12000000) // 12.0ms
		}(),
		HasDuration: true,
	})
	want := "2026-09-28 15:30:12.345 127.0.0.1:52814 -> 127.0.0.1:7010 complete 12.0ms\n"
	if got != want {
		t.Errorf("定位行不正确\n得到: %q\n期望: %q", got, want)
	}
}

func TestLocationLineIPv6(t *testing.T) {
	got := locateLine(t, output.Block{
		Time:        time.Unix(0, 0).In(tz),
		Client:      mustAddr("[::1]:52814"),
		Server:      mustAddr("[2001:db8::1]:80"),
		Status:      output.Status{},
		Duration:    400000,
		HasDuration: true,
		Messages:    nil,
	})
	want := "1970-01-01 08:00:00.000 [::1]:52814 -> [2001:db8::1]:80 complete 0.4ms\n"
	if got != want {
		t.Errorf("IPv6 定位行不正确\n得到: %q\n期望: %q", got, want)
	}
}

func mustAddr(s string) netip.AddrPort {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestStatusWords(t *testing.T) {
	tests := []struct {
		name string
		st   output.Status
		want string
	}{
		{"无异常", output.Status{}, "complete"},
		{"no-request", output.Status{NoRequest: true}, "no-request"},
		{"incomplete", output.Status{Incomplete: true}, "incomplete"},
		{"no-response timeout", output.Status{NoResponse: "timeout"}, "no-response(timeout)"},
		{"no-response eof", output.Status{NoResponse: "eof"}, "no-response(eof)"},
		{"no-request+incomplete", output.Status{NoRequest: true, Incomplete: true}, "no-request,incomplete"},
		{"no-request+no-response", output.Status{NoRequest: true, NoResponse: "closed"}, "no-request,no-response(closed)"},
		{"incomplete+no-response", output.Status{Incomplete: true, NoResponse: "eof"}, "incomplete,no-response(eof)"},
		{"全部", output.Status{NoRequest: true, Incomplete: true, NoResponse: "timeout"}, "no-request,incomplete,no-response(timeout)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := locateLine(t, output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.2.3.4:1"), Server: mustAddr("5.6.7.8:2"), Status: tt.st})
			want := "1970-01-01 08:00:00.000 1.2.3.4:1 -> 5.6.7.8:2 " + tt.want + "\n"
			if got != want {
				t.Errorf("状态词不正确\n得到: %q\n期望: %q", got, want)
			}
		})
	}
}

func TestDurationFormatting(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"0.4ms", 400000, "0.4ms"},
		{"20512.3ms", 20512345000, "20512.3ms"},
		{"0ms", 0, "0.0ms"},
		{"0.05ms 四舍五入", 50000, "0.1ms"},
		{"恰好 1ms", 1000000, "1.0ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := locateLine(t, output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.2.3.4:1"), Server: mustAddr("5.6.7.8:2"), Duration: tt.d, HasDuration: true})
			want := "1970-01-01 08:00:00.000 1.2.3.4:1 -> 5.6.7.8:2 complete " + tt.want + "\n"
			if got != want {
				t.Errorf("耗时不正确\n得到: %q\n期望: %q", got, want)
			}
		})
	}
}

// block1 是设计文档第 9 节的样例块（内容按编的样例构造）。
func sampleBlock() *output.Block {
	req := "POST /api/device/bind HTTP/1.1\r\nHost: 127.0.0.1:7010\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n{\"sn\":\"490419C6117A0087747906\",\"ch\":1}"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n15\r\n{\"code\":0,\"msg\":\"ok\"}\r\n0\r\n\r\n"
	return &output.Block{
		Time:        time.Unix(1790580612, 345000000),
		Client:      mustAddr("127.0.0.1:52814"),
		Server:      mustAddr("127.0.0.1:7010"),
		Duration:    12000000,
		HasDuration: true,
		Messages: []output.Message{
			{Pieces: []output.Piece{{Kind: output.PieceHead, Data: []byte(req[:49])}, {Kind: output.PieceBody, Data: []byte(req[49:])}}},
			{Pieces: []output.Piece{{Kind: output.PieceHead, Data: []byte(resp[:67])}, {Kind: output.PieceBody, Data: []byte(resp[67:])}}},
		},
	}
}

func TestDesignDocSample(t *testing.T) {
	got := string(render(t, output.Options{Location: tz}, sampleBlock()))
	want := "2026-09-28 15:30:12.345 127.0.0.1:52814 -> 127.0.0.1:7010 complete 12.0ms\n" +
		"POST /api/device/bind HTTP/1.1\n" +
		"Host: 127.0.0.1:7010\n" +
		"Content-Type: application/json\n" +
		"Content-Length: 38\n" +
		"\n" +
		"{\"sn\":\"490419C6117A0087747906\",\"ch\":1}\n" +
		"HTTP/1.1 200 OK\n" +
		"Content-Type: application/json\n" +
		"Transfer-Encoding: chunked\r\n\r\n15\n" +
		"{\"code\":0,\"msg\":\"ok\"}\n" +
		"0\n" +
		"\n"
	if got != want {
		t.Errorf("设计文档样例输出不正确\n得到:\n%q\n期望:\n%q", got, want)
	}
}

func TestSeparatorAndNoTransform(t *testing.T) {
	// 三块：第二块前面有 --，第三块前面也有，最后没有。
	base := output.Status{Incomplete: true}
	b1 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"), Status: base,
		Messages: []output.Message{{Pieces: []output.Piece{{Kind: output.PieceUnparsed, Data: []byte("AAA")}}}}}
	b2 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"), Status: base,
		Messages: []output.Message{{Pieces: []output.Piece{{Kind: output.PieceHead, Data: []byte("BBB")}}}}}
	b3 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"), Status: base,
		Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("CCC\r\n")}, {Data: []byte("D")}, {Data: []byte("")}}}}}
	got := string(render(t, output.Options{Location: tz}, b1, b2, b3))
	want := "1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 incomplete\nAAA\n" +
		"--\n" +
		"1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 incomplete\nBBB\n" +
		"--\n" +
		"1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 incomplete\nCCC\r\nD\n"
	if got != want {
		t.Errorf("-- 分隔与补换行不正确\n得到: %q\n期望: %q", got, want)
	}
}
