package run

import (
	"errors"
	"io"
	"sync/atomic"
	"time"

	"httpgrep/internal/decode"
	"httpgrep/internal/pcap"
)

// batchSize 是一批包的缓冲区大小：读取协程把包拷进去，攒满一批才交给主循环一次，
// 不为每个包发一次 channel。
const batchSize = 256 << 10

// poolSize 是可复用的批次个数：读取协程填一批的同时，主循环和分片可以处理其余几批。
const poolSize = 4

// errStopped 表示 Run 已经返回，读取协程应当退出。
var errStopped = errors.New("run stopped")

// record 是批次里的一条 pcap 记录，数据在 batch.buf[off:off+n]。
type record struct {
	ts      time.Time
	off, n  int
	origLen int
}

// item 是分给某个分片的一个段，Payload 引用 batch.buf。
type item struct {
	seg decode.Segment
	ts  time.Time
}

// batch 是一批连续的包。
type batch struct {
	buf  []byte
	recs []record
	err  error    // 读取结束的原因（io.EOF 或读错误），只出现在最后一批
	work [][]item // 按分片分好的段，只在多分片时使用
	// pending 是还在处理这一批的分片数，减到 0 时批次放回空闲池。
	pending atomic.Int32
}

// reset 清空批次以便复用，保留已分配的容量。
func (b *batch) reset() {
	b.buf = b.buf[:0]
	b.recs = b.recs[:0]
	b.err = nil
	for i := range b.work {
		clear(b.work[i]) // 不留对旧数据的引用
		b.work[i] = b.work[i][:0]
	}
}

// header 是读取协程读文件头的结果。
type header struct {
	link pcap.LinkType
	err  error
}

// reader 在单独的协程里读 pcap，把包按批交给主循环。
type reader struct {
	src  io.Reader
	cur  *batch      // 正在填的批次
	free chan *batch // 空闲批次，容量等于批次总数，放回时不阻塞
	out  chan *batch // 填好的批次
	hdr  chan header
	done chan struct{} // Run 返回时关闭
}

// startReader 启动读取协程。shards 是分片数，决定每个批次的 work 个数。
func startReader(src io.Reader, shards int) *reader {
	rd := &reader{
		src:  src,
		free: make(chan *batch, poolSize),
		out:  make(chan *batch, poolSize),
		hdr:  make(chan header, 1),
		done: make(chan struct{}),
	}
	for range poolSize {
		rd.free <- &batch{buf: make([]byte, 0, batchSize), work: make([][]item, shards)}
	}
	go rd.loop()
	return rd
}

// Read 实现 io.Reader，供 pcap.Reader 使用。向底层要数据之前先把攒下的包交出去：
// 底层可能阻塞（管道里暂时没有数据），已经读到的包不能跟着等。
func (rd *reader) Read(p []byte) (int, error) {
	if rd.cur != nil && len(rd.cur.recs) > 0 && !rd.send() {
		return 0, errStopped
	}
	return rd.src.Read(p)
}

// send 交出当前批次并换一个空批次；Run 已经返回时放弃，返回 false。
func (rd *reader) send() bool {
	select {
	case rd.out <- rd.cur:
	case <-rd.done:
		rd.cur = nil
		return false
	}
	return rd.take()
}

// take 取一个空批次作为当前批次。
func (rd *reader) take() bool {
	select {
	case rd.cur = <-rd.free:
		return true
	case <-rd.done:
		rd.cur = nil
		return false
	}
}

// loop 是读取协程：读文件头，然后逐条读记录拷进批次。
func (rd *reader) loop() {
	r, err := pcap.NewReader(rd)
	if err != nil {
		rd.hdr <- header{err: err}
		return
	}
	rd.hdr <- header{link: r.LinkType()}
	if !rd.take() {
		return
	}
	for {
		p, err := r.Next()
		if rd.cur == nil { // Read 里交批次时发现 Run 已经返回
			return
		}
		if err != nil {
			rd.cur.err = err
			select {
			case rd.out <- rd.cur:
			case <-rd.done:
			}
			return
		}
		b := rd.cur
		if len(b.recs) > 0 && len(b.buf)+len(p.Data) > cap(b.buf) {
			if !rd.send() {
				return
			}
			b = rd.cur
		}
		if len(p.Data) > cap(b.buf) { // 单条记录比批次还大
			b.buf = make([]byte, 0, len(p.Data))
		}
		off := len(b.buf)
		b.buf = append(b.buf, p.Data...)
		b.recs = append(b.recs, record{ts: p.Timestamp, off: off, n: len(p.Data), origLen: p.OrigLen})
	}
}
