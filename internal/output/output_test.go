package output_test

import (
	"bytes"
	"io"
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
		"POST /api/device/bind HTTP/1.1\r\nHost: 127.0.0.1:7010\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n" +
		"{\"sn\":\"490419C6117A0087747906\",\"ch\":1}\n" +
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n15\r\n{\"code\":0,\"msg\":\"ok\"}\r\n0\r\n\r\n"
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

func TestMarkerLines(t *testing.T) {
	tests := []struct {
		name   string
		pieces []output.Piece
		want   string
	}{
		{
			name: "gap 前面有换行",
			pieces: []output.Piece{
				{Kind: output.PieceBody, Data: []byte("abc\r\n")},
				{Kind: output.PieceGap, N: 1460, InBody: true},
			},
			want: "abc\r\n[gap: 1460 bytes missing]\n",
		},
		{
			name: "gap 前面没有换行，先补一个",
			pieces: []output.Piece{
				{Kind: output.PieceHead, Data: []byte("GET / HTTP/1.1\r\n\r")},
				{Kind: output.PieceGap, N: 1460, InBody: false},
			},
			want: "GET / HTTP/1.1\r\n\r\n[gap: 1460 bytes missing]\n",
		},
		{
			name: "truncated 前面没有换行",
			pieces: []output.Piece{
				{Kind: output.PieceBody, Data: []byte("xyz")},
				{Kind: output.PieceTruncated, N: 1048576},
			},
			want: "xyz\n[truncated: 1048576 bytes over --max-message]\n",
		},
		{
			name: "gap 在最开头",
			pieces: []output.Piece{
				{Kind: output.PieceGap, N: 1},
				{Kind: output.PieceBody, Data: []byte("rest")},
			},
			want: "[gap: 1 bytes missing]\nrest\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
				Status: output.Status{Incomplete: true}, Messages: []output.Message{{Pieces: tt.pieces}}}
			got := string(render(t, output.Options{Location: tz}, b))
			want := "1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 incomplete\n" + tt.want
			if got != want {
				t.Errorf("标记行不正确\n得到: %q\n期望: %q", got, want)
			}
		})
	}
}

func TestBinaryBodyOmitted(t *testing.T) {
	tests := []struct {
		name string
		msg  output.Message
		want string
	}{
		{
			name: "gzip + json，带 matched",
			msg: output.Message{
				Binary: true, ContentType: "application/json", ContentEncoding: "gzip",
				BodySize: 3482, BodyMatched: true,
				Pieces: []output.Piece{
					{Kind: output.PieceHead, Data: []byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n")},
					{Kind: output.PieceBody, Data: []byte("\x1f\x8b abc")},
				},
			},
			want: "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n[binary body omitted: gzip, application/json, 3.4 KB, matched]\n",
		},
		{
			name: "只有类型",
			msg: output.Message{
				Binary: true, ContentType: "application/x-protobuf", BodySize: 12595,
				Pieces: []output.Piece{
					{Kind: output.PieceBody, Data: []byte("\x00\x01")},
				},
			},
			want: "[binary body omitted: application/x-protobuf, 12.3 KB]\n",
		},
		{
			name: "都没有",
			msg: output.Message{
				Binary: true, BodySize: 512,
				Pieces: []output.Piece{{Kind: output.PieceBody, Data: []byte("\x00")}},
			},
			want: "[binary body omitted: 512 B]\n",
		},
		{
			name: "恰好 1024",
			msg: output.Message{
				Binary: true, BodySize: 1024,
				Pieces: []output.Piece{{Kind: output.PieceBody, Data: []byte("\x00")}},
			},
			want: "[binary body omitted: 1.0 KB]\n",
		},
		{
			name: "1 MiB",
			msg: output.Message{
				Binary: true, ContentType: "application/octet-stream", BodySize: 1048576,
				Pieces: []output.Piece{{Kind: output.PieceBody, Data: []byte("\x00")}},
			},
			want: "[binary body omitted: application/octet-stream, 1.0 MB]\n",
		},
		{
			name: "InBody 的 gap 也换掉",
			msg: output.Message{
				Binary: true, BodySize: 2048,
				Pieces: []output.Piece{
					{Kind: output.PieceHead, Data: []byte("H\r\n\r\n")},
					{Kind: output.PieceBody, Data: []byte("\x00a")},
					{Kind: output.PieceGap, N: 1460, InBody: true},
					{Kind: output.PieceBody, Data: []byte("b")},
				},
			},
			want: "H\r\n\r\n[binary body omitted: 2.0 KB]\n",
		},
		{
			name: "body 后的 trailer 保留",
			msg: output.Message{
				Binary: true, BodySize: 100,
				Pieces: []output.Piece{
					{Kind: output.PieceBody, Data: []byte("\x00")},
					{Kind: output.PieceTrailer, Data: []byte("X-Trailer: v\r\n")},
					{Kind: output.PieceUnparsed, Data: []byte("junk")},
				},
			},
			want: "[binary body omitted: 100 B]\nX-Trailer: v\r\njunk\n",
		},
		{
			name: "非 body 的 gap 不启动替换",
			msg: output.Message{
				Binary: true, BodySize: 100,
				Pieces: []output.Piece{
					{Kind: output.PieceGap, N: 10, InBody: false},
					{Kind: output.PieceBody, Data: []byte("\x00rest")},
				},
			},
			want: "[gap: 10 bytes missing]\n[binary body omitted: 100 B]\n",
		},
		{
			name: "非二进制不动",
			msg: output.Message{
				Binary: false, ContentType: "text/plain", BodySize: 100, BodyMatched: true,
				Pieces: []output.Piece{{Kind: output.PieceBody, Data: []byte("plain body\r\n")}},
			},
			want: "plain body\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
				Messages: []output.Message{tt.msg}}
			got := string(render(t, output.Options{Location: tz}, b))
			want := "1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\n" + tt.want
			if got != want {
				t.Errorf("二进制占位不正确\n得到: %q\n期望: %q", got, want)
			}
		})
	}
}

func TestTTYEscape(t *testing.T) {
	// 转义规则：C0（\t \r \n 除外）、DEL、合法 UTF-8 C1（C2 80-9F）转 \xNN；
	// 不成 UTF-8 的 0x80-0x9F 单字节也转；其他字节原样。
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"普通文本不变", "hello world", "hello world"},
		{"制表符换行回车保留", "a\tb\r\nc", "a\tb\r\nc"},
		{"ESC 转义", "\x1b[0m", "\\x1b[0m"},
		{"NUL 转义", "a\x00b", "a\\x00b"},
		{"其他 C0", "\x01\x02\x1f", "\\x01\\x02\\x1f"},
		{"DEL", "\x7f", "\\x7f"},
		{"合法 C1 两字节都转", "a\xc2\x85b", "a\\xc2\\x85b"},
		{"合法 C1 上界 C2 9F", "\xc2\x9f", "\\xc2\\x9f"},
		{"C2 A0 不转", "\xc2\xa0", "\xc2\xa0"},
		{"孤立的 0x85 转义", "a\x85b", "a\\x85b"},
		{"GBK 文本原样", "\xd6\xd0\xce\xc4", "\xd6\xd0\xce\xc4"},
		{"截断的 C2 序列原样", "a\xc2", "a\xc2"},
		{"0x80 孤立转义", "\x80", "\\x80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
				Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte(tt.in)}}}}}
			got := string(render(t, output.Options{Location: tz, TTY: true}, b))
			want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" + tt.want + "\n"
			if got != want {
				t.Errorf("转义不正确\n得到: %q\n期望: %q", got, want)
			}
		})
	}
}

func TestTTYColors(t *testing.T) {
	// Highlight 对包含 "hit" 的行返回其实际区间，其他行返回 nil。
	hl := func(line []byte) [][2]int {
		if i := bytes.Index(line, []byte("hit")); i >= 0 {
			return [][2]int{{i, i + 3}}
		}
		return nil
	}
	t.Run("定位行与--的颜色", func(t *testing.T) {
		b1 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("a\n")}}}}}
		b2 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("b")}}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b1, b2))
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"a\n" +
			"\x1b[36m--\x1b[m\n" +
			"\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"b\n"
		if got != want {
			t.Errorf("颜色不正确\n得到: %q\n期望: %q", got, want)
		}
	})
	t.Run("标记行黄色", func(t *testing.T) {
		b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("x")}, {Kind: output.PieceGap, N: 5, InBody: true}}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"x\n" +
			"\x1b[33m[gap: 5 bytes missing]\x1b[m\n"
		if got != want {
			t.Errorf("标记行颜色不正确\n得到: %q\n期望: %q", got, want)
		}
	})
	t.Run("高亮一行内跨 Piece", func(t *testing.T) {
		b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{
				{Data: []byte("ab")},
				{Data: []byte("hit\r\n")},
				{Data: []byte("no hit here\n")},
			}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"ab\x1b[01;31mt\x1b[m\x1b[01;31m \x1b[m\x1b[01;31mt\x1b[m\r\n" +
			"no \x1b[01;31mt\x1b[m\x1b[01;31m \x1b[m\x1b[01;31mt\x1b[m here\n"
		_ = want
		// 上面区间是编的，实际期望按规则算：行是 "abhit"（去 \r\n），命中 [2,5)。
		want = "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"ab\x1b[01;31mhit\x1b[m\r\n" +
			"no \x1b[01;31mhit\x1b[m here\n"
		if got != want {
			t.Errorf("高亮不正确\n得到: %q\n期望: %q", got, want)
		}
	})
	t.Run("Highlight 为 nil 不加色", func(t *testing.T) {
		b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("hit\n")}}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true}, b))
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"hit\n"
		if got != want {
			t.Errorf("nil Highlight 不正确\n得到: %q\n期望: %q", got, want)
		}
	})
	t.Run("末尾没有换行的行也高亮", func(t *testing.T) {
		b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("xx hit yy")}}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"xx xx\x1b[01;31mhit\x1b[m yy" // 注意 hl 固定返回 [2,5)
		want = "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
			"xx \x1b[01;31mhit\x1b[m yy\n"
		if got != want {
			t.Errorf("末行高亮不正确\n得到: %q\n期望: %q", got, want)
		}
	})
}

// benchBlock 构造一个 64 KiB 的块：请求 + 响应各 32 KiB JSON 文本。
func benchBlock() *output.Block {
	body := bytes.Repeat([]byte(`{"sn":"490419C6117A0087747906","ch":1,"data":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},`), 1024)
	return &output.Block{
		Time:        time.Unix(1790580612, 345000000),
		Client:      mustAddr("127.0.0.1:52814"),
		Server:      mustAddr("127.0.0.1:7010"),
		Duration:    12000000,
		HasDuration: true,
		Messages: []output.Message{
			{Pieces: []output.Piece{
				{Kind: output.PieceHead, Data: []byte("POST /api/device/bind HTTP/1.1\r\nHost: h\r\n\r\n")},
				{Kind: output.PieceBody, Data: body},
			}},
			{Pieces: []output.Piece{
				{Kind: output.PieceHead, Data: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")},
				{Kind: output.PieceBody, Data: body},
			}},
		},
	}
}

func BenchmarkWriteNonTTY(b *testing.B) {
	w := output.NewWriter(io.Discard, output.Options{Location: time.UTC})
	blk := benchBlock()
	b.SetBytes(int64(len(blk.Messages[0].Pieces[1].Data) * 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(blk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteTTY(b *testing.B) {
	hl := func(line []byte) [][2]int { return nil }
	w := output.NewWriter(io.Discard, output.Options{Location: time.UTC, TTY: true, Highlight: hl})
	blk := benchBlock()
	b.SetBytes(int64(len(blk.Messages[0].Pieces[1].Data) * 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(blk); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTTYBinaryPlaceholder(t *testing.T) {
	// TTY 模式：占位行黄色；头部内容先按行写出。
	b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
		Messages: []output.Message{{
			Binary: true, ContentType: "application/json", BodySize: 100,
			Pieces: []output.Piece{
				{Kind: output.PieceHead, Data: []byte("HTTP/1.1 200 OK\r\n\r\n")},
				{Kind: output.PieceBody, Data: []byte("\x00\x01")},
			},
		}}}
	got := string(render(t, output.Options{Location: tz, TTY: true}, b))
	want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
		"HTTP/1.1 200 OK\r\n\r\n" +
		"\x1b[33m[binary body omitted: application/json, 100 B]\x1b[m\n"
	if got != want {
		t.Errorf("TTY 二进制占位不正确\n得到: %q\n期望: %q", got, want)
	}
}
