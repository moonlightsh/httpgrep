package output_test

import (
	"bytes"
	"io"
	"net/netip"
	"reflect"
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
			name: "body 后的 Unparsed 和非 body gap 保留",
			msg: output.Message{
				Binary: true, BodySize: 100,
				Pieces: []output.Piece{
					{Kind: output.PieceBody, Data: []byte("\x00data")},
					{Kind: output.PieceUnparsed, Data: []byte("junk\r\n")},
					{Kind: output.PieceGap, N: 9, InBody: false},
					{Kind: output.PieceBody, Data: []byte("tail")},
				},
			},
			want: "[binary body omitted: 100 B]\njunk\r\n[gap: 9 bytes missing]\ntail\n",
		},
		{
			// 带 Content-Encoding 即二进制：没有任何 body 类 Piece（比如空 body）也写占位行
			name: "没有 body 类 Piece 仍写占位",
			msg: output.Message{
				Binary: true, ContentEncoding: "gzip", BodySize: 0,
				Pieces: []output.Piece{
					{Kind: output.PieceHead, Data: []byte("HTTP/1.1 204 No Content\r\nContent-Encoding: gzip\r\n\r\n")},
				},
			},
			want: "HTTP/1.1 204 No Content\r\nContent-Encoding: gzip\r\n\r\n[binary body omitted: gzip, 0 B]\n",
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
		{"4 字节 emoji 原样", "a\xf0\x9f\x98\x80b", "a\xf0\x9f\x98\x80b"},
		{"3 字节中文原样", "\xe4\xb8\xad\xe6\x96\x87", "\xe4\xb8\xad\xe6\x96\x87"},
		{"F4 开头原样", "\xf4\x8f\xbf\xbf", "\xf4\x8f\xbf\xbf"},
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
		var gotLines []string
		record := func(line []byte) [][2]int {
			gotLines = append(gotLines, string(line))
			return hl(line)
		}
		b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{
				{Data: []byte("ab")},
				{Data: []byte("hit\r\n")},
				{Data: []byte("no hit here\n")},
			}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: record}, b))
		// 传给 Highlight 的行去掉 \n 和行尾的 \r
		wantLines := []string{"abhit", "no hit here"}
		if !reflect.DeepEqual(gotLines, wantLines) {
			t.Errorf("Highlight 收到的行不正确\n得到: %q\n期望: %q", gotLines, wantLines)
		}
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
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
	t.Run("重叠或乱序区间不 panic", func(t *testing.T) {
		cases := []struct {
			name   string
			ranges [][2]int
			want   string
		}{
			// 重叠：[3,6) 与 [0,5) 重叠的部分并入前一个区间，只剩 [5,6)
			{"重叠", [][2]int{{0, 5}, {3, 6}}, "\x1b[01;31mabcde\x1b[m\x1b[01;31mf\x1b[mg\n"},
			// 乱序：[0,2) 落在已写出的 [4,6) 之前，跳过
			{"乱序", [][2]int{{4, 6}, {0, 2}}, "abcd\x1b[01;31mef\x1b[mg\n"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				hl := func([]byte) [][2]int { return c.ranges }
				b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
					Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("abcdefg\n")}}}}}
				got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
				want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" + c.want
				if got != want {
					t.Errorf("区间处理不正确\n得到: %q\n期望: %q", got, want)
				}
			})
		}
	})
	t.Run("末尾没有换行的行也高亮", func(t *testing.T) {
		b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
			Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("xx hit yy")}}}}}
		got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
		want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
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

// zeroAllocBlock 构造覆盖各状态路径的块：no-response 状态、gap/truncated 标记、二进制占位。
func zeroAllocBlock() *output.Block {
	return &output.Block{
		Time:   time.Unix(1790580612, 345000000),
		Client: mustAddr("127.0.0.1:52814"), Server: mustAddr("127.0.0.1:7010"),
		Status: output.Status{NoResponse: "timeout"},
		Messages: []output.Message{
			{Pieces: []output.Piece{
				{Kind: output.PieceHead, Data: []byte("GET / HTTP/1.1\r\n\r\n")},
				{Kind: output.PieceGap, N: 1460, InBody: true},
			}},
			{Binary: true, ContentType: "application/json", ContentEncoding: "gzip", BodySize: 3482, BodyMatched: true,
				Pieces: []output.Piece{
					{Kind: output.PieceHead, Data: []byte("HTTP/1.1 200 OK\r\n\r\n")},
					{Kind: output.PieceBody, Data: []byte("\x1f\x8b abc")},
					{Kind: output.PieceTruncated, N: 1048576},
				}},
		},
	}
}

func TestWriteNonTTYZeroAlloc(t *testing.T) {
	w := output.NewWriter(io.Discard, output.Options{Location: time.UTC})
	blk := zeroAllocBlock()
	if err := w.Write(blk); err != nil { // 预热，让缓冲区按最大块就位
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if err := w.Write(blk); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("非 TTY 渲染应零分配，实际 %g 次/块", allocs)
	}
}

func TestWriteTTYZeroAlloc(t *testing.T) {
	// TTY 模式（含转义、高亮、颜色码）在缓冲区就位后也应零分配。
	ranges := [][2]int{{0, 3}, {10, 14}}
	hl := func([]byte) [][2]int { return ranges }
	w := output.NewWriter(io.Discard, output.Options{Location: time.UTC, TTY: true, Highlight: hl})
	blk := zeroAllocBlock()
	blk.Messages[0].Pieces = append([]output.Piece{{Data: []byte("hit \x01\xc2\x85 more hit\r\n")}}, blk.Messages[0].Pieces...)
	// 占位行里的类型也要转义：超过 32 字节、含多字节 UTF-8 和控制字符，转义路径同样不应分配
	blk.Messages[1].ContentType = "application/vnd.example.long-type+json; 中文\x1b"
	if err := w.Write(blk); err != nil { // 预热
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if err := w.Write(blk); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("TTY 渲染应零分配，实际 %g 次/块", allocs)
	}
}

func BenchmarkWriteNonTTY(b *testing.B) {
	w := output.NewWriter(io.Discard, output.Options{Location: time.UTC})
	blk := benchBlock()
	b.SetBytes(int64(len(blk.Messages[0].Pieces[1].Data) * 2))
	b.ReportAllocs()
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(blk); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTTYBinaryPlaceholder(t *testing.T) {
	// TTY 模式：占位行黄色；头部内容先按行写出。
	// 编码和类型来自线上头部，占位行里要和 Piece 内容一样转义，防止终端控制序列注入。
	tests := []struct {
		name     string
		ctype    string
		encoding string
		want     string
	}{
		{
			name:  "普通类型",
			ctype: "application/json",
			want:  "\x1b[33m[binary body omitted: application/json, 100 B]\x1b[m\n",
		},
		{
			name:     "类型和编码里的控制字符被转义",
			ctype:    "x\x1b]0;pwn\x07",
			encoding: "gz\x1b[2J\xc2\x9b",
			want:     "\x1b[33m[binary body omitted: gz\\x1b[2J\\xc2\\x9b, x\\x1b]0;pwn\\x07, 100 B]\x1b[m\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
				Messages: []output.Message{{
					Binary: true, ContentType: tt.ctype, ContentEncoding: tt.encoding, BodySize: 100,
					Pieces: []output.Piece{
						{Kind: output.PieceHead, Data: []byte("HTTP/1.1 200 OK\r\n\r\n")},
						{Kind: output.PieceBody, Data: []byte("\x00\x01")},
					},
				}}}
			got := string(render(t, output.Options{Location: tz, TTY: true}, b))
			want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
				"HTTP/1.1 200 OK\r\n\r\n" + tt.want
			if got != want {
				t.Errorf("TTY 二进制占位不正确\n得到: %q\n期望: %q", got, want)
			}
		})
	}
}

func TestNonTTYNoEscapeByteForByte(t *testing.T) {
	// 清单第 8 条：非 TTY 模式下除第 5-7 条规定的变动外，输出和输入逐字节相同。
	// 内容含 ESC、NUL、DEL、合法 C1、孤立 0x80-0x9F，但 Binary=false，必须原样输出。
	in := "a\x1b[31m\x00\x7f\xc2\x85\x80b"
	b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
		Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte(in)}}}}}
	got := string(render(t, output.Options{Location: tz}, b))
	want := "1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\n" + in + "\n"
	if got != want {
		t.Errorf("非 TTY 模式逐字节不变被破坏\n得到: %q\n期望: %q", got, want)
	}
}

func TestTTYHighlightOnRawBytes(t *testing.T) {
	// Highlight 收到的必须是原始字节（只去掉 \n 和行尾 \r），不是转义后的。
	// 关键词 \x01 的正则形式 "a.b" 应在原始内容 "a\x01b" 上命中。
	hl := func(line []byte) [][2]int {
		if i := bytes.Index(line, []byte("a\x01b")); i >= 0 {
			return [][2]int{{i, i + 3}}
		}
		// 转义后的行 "a\\x01b" 不应命中；若命中说明传错了
		if bytes.Index(line, []byte(`a\x01b`)) >= 0 {
			t.Errorf("Highlight 收到了转义后的行: %q", line)
		}
		return nil
	}
	b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
		Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("xx a\x01b yy\n")}}}}}
	got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
	// 期望：命中区间 [3,6) 对应原始 3 字节 a 0x01 b，转义后是 6 个字符 `a\x01b`，
	// 红色包住转义后的这一段。
	want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\n" +
		"xx \x1b[01;31ma\\x01b\x1b[m yy\n"
	if got != want {
		t.Errorf("原始字节高亮不正确\n得到: %q\n期望: %q", got, want)
	}
}

// BenchmarkWriteTTYManyHits 验证多命中长行的渲染是线性的：单行 80 KB、每 4 字节一个命中，
// 共 2 万个区间。区间在闭包外预先算好，每次返回同一个切片，实现侧应为 0 allocs。
func BenchmarkWriteTTYManyHits(b *testing.B) {
	const hits = 20000
	line := append(bytes.Repeat([]byte("aaaa"), hits), '\n') // 80 KB 单行
	ranges := make([][2]int, hits)
	for i := range ranges {
		ranges[i] = [2]int{i * 4, i*4 + 2}
	}
	hl := func([]byte) [][2]int { return ranges }
	w := output.NewWriter(io.Discard, output.Options{Location: time.UTC, TTY: true, Highlight: hl})
	blk := &output.Block{
		Time: time.Unix(0, 0), Client: mustAddr("127.0.0.1:1"), Server: mustAddr("127.0.0.1:2"),
		Messages: []output.Message{{Pieces: []output.Piece{{Kind: output.PieceBody, Data: line}}}},
	}
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Write(blk); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTTYFinalCRNotHighlighted(t *testing.T) {
	// 消息以 "abc\r" 结尾、没有换行时：\r 原样输出（在补的 \n 前），
	// 但传给 Highlight 的行不带 \r。
	var gotLine string
	hl := func(line []byte) [][2]int {
		gotLine = string(line)
		return nil
	}
	b := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
		Messages: []output.Message{{Pieces: []output.Piece{{Data: []byte("abc\r")}}}}}
	got := string(render(t, output.Options{Location: tz, TTY: true, Highlight: hl}, b))
	want := "\x1b[35m1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\x1b[m\nabc\r\n"
	if got != want {
		t.Errorf("末尾 CR 输出不正确\n得到: %q\n期望: %q", got, want)
	}
	if gotLine != "abc" {
		t.Errorf("Highlight 收到的行应为 %q，得到 %q", "abc", gotLine)
	}
}

func TestLocationNilFallsBackToLocal(t *testing.T) {
	// Location 为 nil 时用 time.Local。
	ts := time.Unix(1790580612, 345000000).In(time.Local)
	want := string(ts.AppendFormat(nil, "2006-01-02 15:04:05.000 ")) + "1.1.1.1:1 -> 2.2.2.2:2 complete\n"
	b := &output.Block{Time: time.Unix(1790580612, 345000000), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2")}
	if got := render(t, output.Options{}, b); string(got) != string(want) {
		t.Errorf("Location nil 回退不正确\n得到: %q\n期望: %q", got, want)
	}
}

func TestEmptyMessageAndEmptyBlock(t *testing.T) {
	// 没有任何 Message 的块只有定位行；空 Piece 的 Message 只补换行。
	b1 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2")}
	b2 := &output.Block{Time: time.Unix(0, 0), Client: mustAddr("1.1.1.1:1"), Server: mustAddr("2.2.2.2:2"),
		Messages: []output.Message{{}, {Pieces: []output.Piece{}}}}
	got := string(render(t, output.Options{Location: tz}, b1, b2))
	want := "1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\n" +
		"--\n" +
		"1970-01-01 08:00:00.000 1.1.1.1:1 -> 2.2.2.2:2 complete\n"
	if got != want {
		t.Errorf("空 Message 处理不正确\n得到: %q\n期望: %q", got, want)
	}
}
