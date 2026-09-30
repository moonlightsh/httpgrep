# httpgrep

grep for HTTP traffic. Pipe `tcpdump` into `httpgrep` and it prints every
HTTP/1.x exchange that contains your pattern: the full request and the full
response, exactly as they went over the wire.

```sh
sudo tcpdump -i lo -U --immediate-mode -w - port 8080 | httpgrep A1024
```

- Reads a pcap stream from stdin (live capture) or from a single pcap file.
- Reassembles TCP (out-of-order segments, retransmissions, packet loss) and
  parses HTTP/1.0 and HTTP/1.1, including keep-alive, pipelining, chunked
  bodies, trailers and `1xx` responses.
- Searches start lines, headers, trailers and the de-chunked body, with
  literal patterns or RE2 regular expressions.
- Prints whole exchanges, each labeled with time, addresses, status and
  latency. Requests that never get a response are reported after a timeout.
- Memory stays bounded (`--max-memory`). Can use several cores (`--cpus`).
- A single static binary written in pure Go: no libpcap, no tshark. On a
  server you only need `tcpdump`.

## Install

Download an archive from the
[Releases](https://github.com/moonlightsh/httpgrep/releases) page:

| Platform            | Archive                                  |
| ------------------- | ---------------------------------------- |
| Linux x86_64        | `httpgrep-<version>-linux-x86_64.tar.gz` |
| Linux arm64         | `httpgrep-<version>-linux-arm64.tar.gz`  |
| macOS Apple silicon | `httpgrep-<version>-mac-arm64.tar.gz`    |
| macOS Intel         | `httpgrep-<version>-mac-x86_64.tar.gz`   |

```sh
VERSION=v1.0.0
BASE=https://github.com/moonlightsh/httpgrep/releases/download/$VERSION
curl -LO "$BASE/httpgrep-$VERSION-linux-x86_64.tar.gz"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
tar -xzf "httpgrep-$VERSION-linux-x86_64.tar.gz"
sudo install "httpgrep-$VERSION-linux-x86_64/httpgrep" /usr/local/bin/
```

The Linux binaries are statically linked and run on kernel 3.2 or later
(CentOS 7 and newer). The macOS binaries are not signed. If you downloaded one
with a browser, clear the quarantine flag first:
`xattr -d com.apple.quarantine httpgrep`.

To build from source you need Go 1.27 or later:

```sh
go build -o httpgrep ./cmd/httpgrep
scripts/build-release.sh v1.0.0   # cross-compile all release archives into dist/
```

## Usage

```text
httpgrep [OPTION]... PATTERN [FILE]
httpgrep [OPTION]... -e PATTERN [-e PATTERN]... [FILE]
```

With no FILE, or when FILE is `-`, httpgrep reads standard input.

### Live capture

```sh
# Loopback traffic to a local service on port 8080
sudo tcpdump -i lo -U --immediate-mode -w - port 8080 | httpgrep A1024

# All interfaces, several patterns: an exchange matches if any pattern matches
sudo tcpdump -i any -U --immediate-mode -w - 'tcp port 80' \
  | httpgrep -e 'X-Request-Id: 7f3a9c' -e '"code":500'
```

- `-w -` writes raw packets to the pipe. Use tcpdump filter expressions to
  pick hosts and ports.
- `-U` makes tcpdump flush after every packet instead of after a full buffer.
- `--immediate-mode` stops libpcap from holding packets back. Without it,
  matches can show up to about 1 second late.
- Press Ctrl-C once to stop. httpgrep reads what is already in the pipe (for
  at most 1 second), prints matching exchanges that are still open (with the
  status `no-response(eof)`), then exits. Press it a second time to exit
  immediately.

### Capture files

```sh
httpgrep A1024 capture.pcap
httpgrep '' capture.pcap                        # an empty pattern matches every exchange
httpgrep -E '^HTTP/1\.[01] 5[0-9]{2} ' capture.pcap   # every 5xx response
httpgrep -E 'Authorization: Bearer [A-Za-z0-9._-]+' --stats capture.pcap
```

httpgrep reads pcap, not pcapng. Newer Wireshark and dumpcap write pcapng by
default. Convert with `editcap -F pcap in.pcapng out.pcap` or
`tcpdump -r in.pcapng -w out.pcap`.

Output written to a file or pipe is byte-exact, so it works with the usual
tools. For example, this prints the header line of every exchange that took
more than one second:

```sh
httpgrep '' capture.pcap | awk '$4 == "->" && $NF ~ /ms$/ && $NF + 0 > 1000'
```

### Options

| Option               | Default | Description                                                                         |
| -------------------- | ------- | ----------------------------------------------------------------------------------- |
| `-e PATTERN`         |         | Pattern to search for. Can be repeated.                                             |
| `-E`                 | off     | Treat all patterns as RE2 regular expressions.                                      |
| `--timeout DUR`      | `30s`   | End an unfinished exchange after `DUR` without new data.                            |
| `--max-memory SIZE`  | `256M`  | Approximate limit for all buffered data (see [Limits](#limits)).                    |
| `--max-message SIZE` | `8M`    | Limit for a single request or response. Bytes past it are not buffered or searched. |
| `--cpus N`           | `1`     | Split connections among N workers (1 to 1024).                                      |
| `--stats`            | off     | Print statistics to stderr before exiting.                                          |
| `--help`             |         | Show help and exit.                                                                 |
| `--version`          |         | Show version and exit.                                                              |

`SIZE` takes the suffixes `K`, `M` and `G`, in powers of 1024. `DUR` is a Go
duration such as `30s` or `2m`. Options can come before or after the pattern
and the file. Nothing after `--` is treated as an option.

Patterns are case-sensitive and matched line by line, so a pattern cannot
span a line break. A pattern that contains newlines is split into several
patterns.

## Output

Each matching exchange is printed as one block once it ends: when the
response is complete, the timeout expires, the connection closes, or the
input ends. Blocks are separated by `--`, as in grep. Here is the output of
`httpgrep A1024 capture.pcap`:

```text
2026-09-28 15:30:12.345 127.0.0.1:52814 -> 127.0.0.1:8080 complete 12.0ms
POST /api/orders HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json
Content-Length: 28

{"order_id":"A1024","qty":2}
HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: 30

{"id":"A1024","status":"new"}
--
2026-09-28 15:30:12.946 127.0.0.1:52990 -> 127.0.0.1:8080 no-response(eof)
GET /api/orders/A1024 HTTP/1.1
Host: 127.0.0.1:8080

```

The first line of each block has these fields:

- **Time**: capture time of the first request packet, in local time. If the
  request was not captured, the time of the response is used.
- **Client -> server** addresses. IPv6 addresses are written as `[::1]:52814`.
- **Status**: `complete`, or one or more of these, joined by commas:
  - `no-request`: the response was captured but its request was not. This
    usually happens when the connection started before the capture did.
  - `incomplete`: part of the request or response is missing.
  - `no-response(timeout|closed|eof)`: the request got no response before
    the timeout, the connection closed, or the input ended.
- **Latency**: from the end of the request to the end of the response, in
  milliseconds. Shown only when both are present.

Messages are printed as captured, including chunk-size lines. httpgrep adds
only these lines:

| Line                                                             | Meaning                                                            |
| ---------------------------------------------------------------- | ------------------------------------------------------------------ |
| `[gap: 1460 bytes missing]`                                      | These bytes were not captured (packet loss or snaplen).            |
| `[truncated: 1048576 bytes over --max-message]`                  | The rest of the message was not buffered.                          |
| `[binary body omitted: gzip, application/json, 3.4 KB, matched]` | A compressed or binary body. `matched` means it contained a match. |

When stdout is a terminal, matches are highlighted and control characters are
escaped (for example `\x1b`), so a captured payload cannot mess up your
terminal. When stdout is a file or a pipe, no colors are added and nothing is
escaped.

Exit status is 0 if any exchange matched, 1 if none matched, and 2 on error.

## What is searched

A pattern is matched against these parts of the request and the response:
the start line, headers, trailers, and the body after chunked decoding.
Chunk-size lines are not searched. By default patterns are literal strings.
With `-E` they are [RE2](https://github.com/google/re2/wiki/Syntax) regular
expressions: use `(?i)` for case-insensitive matching, and `^`/`$` match at
the start and end of each line.

Compressed bodies (`Content-Encoding: gzip` and so on) are not decompressed.
They are searched as the compressed bytes on the wire, so a pattern will
almost never match inside them. Bytes after a `101 Switching Protocols` or a
successful `CONNECT` are tunnel traffic and are not searched.

## Limits

- `--timeout` controls how long an exchange may sit idle, with no new data,
  before httpgrep gives up on the response and prints the exchange with the
  status `no-response(timeout)`. A response that arrives later is counted but
  not printed.
- `--max-memory` caps buffered request and response data, out-of-order
  segments, parser buffers, and a fixed amount per connection and per
  exchange. When the cap is exceeded, the oldest unfinished exchanges are
  dropped, then the least recently active connections. A warning goes to
  stderr, at most once every 10 seconds. The process itself uses somewhat
  more memory than this. The Go runtime soft limit is set to 1.5 times the
  cap.
- `--max-message` caps a single request or response. Bytes over the cap are
  replaced by a `[truncated: ...]` line and are not searched.
- `--cpus N` splits connections among N workers by address. Each worker gets
  1/N of `--max-memory`. Blocks are still printed whole, but blocks from
  different workers can interleave out of end-time order.

On an Apple M-series laptop, one core searches a 770 MB loopback capture
for a literal pattern in about one second (about 770 MB/s), using about
60 MB of memory. `--stats` prints the throughput, along with counters for
packets, connections, exchanges, gaps and memory.

## Supported input

- **Formats**: classic pcap, both byte orders, with microsecond or nanosecond
  timestamps. pcapng is rejected. A truncated last record, which is common
  when tcpdump is killed, is treated as end of input.
- **Link layers**: Ethernet (with VLAN and QinQ tags), Linux cooked capture
  v1 and v2 (`tcpdump -i any`), raw IP, and BSD/macOS loopback.
- **Protocols**: IPv4 and IPv6 (with extension headers), TCP, and plain-text
  HTTP/1.0 and HTTP/1.1.
- **Not supported**: HTTPS/TLS, HTTP/2 (including h2c), HTTP/3,
  WebSocket messages, IP fragment reassembly, reading more than one file,
  and other grep options such as `-i`, `-v` and `-c`.

## Development

```sh
go test -race ./...     # unit tests and end-to-end tests of the binary
go vet ./...
```

The code uses only the Go standard library. Tests generate their packet
captures with `internal/pcapgen`, so the repository contains no capture
files. The design spec, the architecture decision records and the glossary
are in [`docs/`](docs/) and [`CONTEXT.md`](CONTEXT.md). They are written in
Chinese.

GitHub Actions runs formatting, vet, build and race-enabled tests on Linux
and macOS for every push. When a release is published, it builds the four
platform archives and `SHA256SUMS` and attaches them to the release.
