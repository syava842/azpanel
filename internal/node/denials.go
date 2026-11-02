package node

import (
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/nodeapi"
)

// maxDenials — сколько последних отказов хука агент держит в памяти.
const maxDenials = 1000

// Denials — кольцевой буфер последних отказов хука. Живёт в памяти: после
// перезапуска агента пуст, панель забирает отказы раз в цикл сбора.
type Denials struct {
	mu   sync.Mutex
	buf  []nodeapi.Denial
	next int // куда писать, когда буфер полон
	max  int
}

func NewDenials(max int) *Denials { return &Denials{max: max} }

// Add добавляет отказ; при переполнении вытесняет самый старый.
func (d *Denials) Add(x nodeapi.Denial) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.buf) < d.max {
		d.buf = append(d.buf, x)
		return
	}
	d.buf[d.next] = x
	d.next = (d.next + 1) % d.max
}

// Since — отказы строго новее since, по возрастанию времени записи.
func (d *Denials) Since(since time.Time) []nodeapi.Denial {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]nodeapi.Denial, 0, len(d.buf))
	for i := range d.buf {
		x := d.buf[(d.next+i)%len(d.buf)]
		if x.Time.After(since) {
			out = append(out, x)
		}
	}
	return out
}
