package run

// BatchCapAfterReset 返回一个被 n 字节的记录撑大过的批次在 reset 之后的缓冲区容量。
func BatchCapAfterReset(n int) int {
	b := &batch{buf: make([]byte, 0, n)}
	b.reset()
	return cap(b.buf)
}
