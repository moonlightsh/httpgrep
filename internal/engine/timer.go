package engine

import "time"

// timers 是在途交互的超时最小堆，按 key 排序。
//
// key 不随每个包更新：收到数据时只改 exchange.last，key 留在原处，
// 所以 key 不晚于真正的到期时间 last+Timeout。堆顶到期时再核对：
// 真正的到期时间更晚，就把 key 改成它、下沉，继续看新的堆顶；
// 相等才算超时。这样按真正的到期时间先后出堆，每个包只写一个字段，
// 每个交互每个超时周期最多多一次下沉。
type timers []*exchange

// push 把 x 放进堆，key 是 at。x 不能已经在堆里。
func (h *timers) push(x *exchange, at time.Time) {
	x.key = at
	*h = append(*h, x)
	x.hpos = len(*h)
	h.up(len(*h) - 1)
}

// remove 把 x 移出堆。x 不在堆里时什么都不做。
func (h *timers) remove(x *exchange) {
	if x.hpos == 0 {
		return
	}
	i := x.hpos - 1
	n := len(*h) - 1
	if i != n {
		h.swap(i, n)
	}
	(*h)[n] = nil
	*h = (*h)[:n]
	x.hpos = 0
	if i != n {
		h.down(i)
		h.up(i)
	}
}

// fixTop 在堆顶的 key 变晚之后恢复堆序。
func (h *timers) fixTop() { h.down(0) }

func (h timers) less(i, j int) bool { return h[i].key.Before(h[j].key) }

func (h timers) swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].hpos, h[j].hpos = i+1, j+1
}

func (h timers) up(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !h.less(i, p) {
			return
		}
		h.swap(i, p)
		i = p
	}
}

func (h timers) down(i int) {
	n := len(h)
	for {
		l := 2*i + 1
		if l >= n {
			return
		}
		m := l
		if r := l + 1; r < n && h.less(r, l) {
			m = r
		}
		if !h.less(m, i) {
			return
		}
		h.swap(i, m)
		i = m
	}
}
