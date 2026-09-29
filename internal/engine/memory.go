package engine

// 计入内存上限的固定开销。
const (
	connOverhead     = 1024 // 每条连接
	exchangeOverhead = 512  // 每个在途交互
)

// Memory 返回当前的内存计量值：在途交互缓存的消息字节、乱序缓存、
// 每条连接和每个在途交互的固定开销。内存上限按它判断。
func (e *Engine) Memory() int64 {
	return e.buffered + e.asm.BufferedBytes() +
		int64(e.asm.Len())*connOverhead + int64(e.inFlight)*exchangeOverhead
}
