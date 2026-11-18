package node

import "time"

const (
	rateMinGap = 2 * time.Second  // замеры чаще не сдвигают базу расчёта
	rateMaxGap = 10 * time.Minute // по замеру старше скорость не считается
)

// rateSample — прошлый замер счётчиков сеанса и посчитанная по нему скорость.
type rateSample struct {
	rx, tx   int64
	at       time.Time
	rrx, rtx int64
	ok       bool
}

// rate — скорость сеанса в байт/с по прошлому замеру того же ключа. Запросы
// чаще rateMinGap (панель и сборщик почти одновременно) получают прежнюю
// скорость, иначе разность за доли секунды дала бы нули и скачки. Сброс
// счётчика (новое значение меньше) скорость не даёт.
func (a *API) rate(key string, rx, tx int64, now time.Time) (int64, int64, bool) {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	if a.rates == nil {
		a.rates = map[string]rateSample{}
	}
	prev, have := a.rates[key]
	dt := now.Sub(prev.at)
	if have && dt >= 0 && dt < rateMinGap {
		return prev.rrx, prev.rtx, prev.ok
	}
	cur := rateSample{rx: rx, tx: tx, at: now}
	if have && dt <= rateMaxGap && rx >= prev.rx && tx >= prev.tx {
		sec := dt.Seconds()
		cur.rrx, cur.rtx, cur.ok = int64(float64(rx-prev.rx)/sec), int64(float64(tx-prev.tx)/sec), true
	}
	a.rates[key] = cur
	for k, s := range a.rates { // ушедшие сеансы
		if now.Sub(s.at) > rateMaxGap {
			delete(a.rates, k)
		}
	}
	return cur.rrx, cur.rtx, cur.ok
}
