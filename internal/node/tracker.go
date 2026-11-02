// Package node — агент узла: учёт сессий OpenVPN и ответы хуку лимита.
package node

import (
	"sort"
	"sync"
	"time"

	"github.com/syava842/azpanel/internal/antizapret"
)

// Key — одна сессия: экземпляр OpenVPN, имя клиента, адрес ip:port.
type Key struct {
	Instance string
	CN       string
	Addr     string
}

type snapshot struct {
	taken    time.Time
	keys     map[Key]struct{}
	sessions []antizapret.Session // для показа; лимит считается по keys
}

// Tracker считает сессии по снимкам управляющих сокетов и событиям хуков
// между снимками. Экземпляр, к которому идёт подключение, во время
// client-connect не отвечает, поэтому одних снимков мало.
type Tracker struct {
	mu    sync.Mutex
	snaps map[string]snapshot
	conns map[Key]time.Time
	discs map[Key]time.Time
}

func NewTracker() *Tracker {
	return &Tracker{snaps: map[string]snapshot{}, conns: map[Key]time.Time{}, discs: map[Key]time.Time{}}
}

// ApplySnapshot заменяет снимок экземпляра. taken — время начала опроса:
// события позже него снимок мог не увидеть, поэтому они сохраняются.
func (t *Tracker) ApplySnapshot(instance string, taken time.Time, sessions []antizapret.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := make(map[Key]struct{}, len(sessions))
	for _, s := range sessions {
		keys[Key{Instance: instance, CN: s.CommonName, Addr: s.RealAddr}] = struct{}{}
	}
	t.snaps[instance] = snapshot{taken: taken, keys: keys, sessions: append([]antizapret.Session(nil), sessions...)}
	for k, ev := range t.conns {
		if k.Instance == instance && !ev.After(taken) {
			delete(t.conns, k)
		}
	}
	for k, ev := range t.discs {
		if k.Instance == instance && !ev.After(taken) {
			delete(t.discs, k)
		}
	}
}

// present: событие новее снимка побеждает снимок; из двух событий — позднее.
func (t *Tracker) present(k Key) bool {
	snap := t.snaps[k.Instance]
	_, inSnap := snap.keys[k]
	c, hasC := t.conns[k]
	d, hasD := t.discs[k]
	cAfter := hasC && c.After(snap.taken)
	dAfter := hasD && d.After(snap.taken)
	switch {
	case cAfter && (!dAfter || c.After(d)):
		return true
	case dAfter:
		return false
	default:
		return inSnap
	}
}

func (t *Tracker) keysOf(cn string) map[Key]struct{} {
	out := map[Key]struct{}{}
	for _, s := range t.snaps {
		for k := range s.keys {
			if k.CN == cn && t.present(k) {
				out[k] = struct{}{}
			}
		}
	}
	for k := range t.conns {
		if k.CN == cn && t.present(k) {
			out[k] = struct{}{}
		}
	}
	return out
}

func (t *Tracker) Count(cn string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keysOf(cn))
}

// Admit засчитывает подключение, если у клиента меньше limit сессий.
// limit 0 — без ограничения. count — сколько сессий будет с этой (или есть
// сейчас, если отказ).
func (t *Tracker) Admit(k Key, at time.Time, limit int) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := t.keysOf(k.CN)
	delete(keys, k) // повтор того же подключения не считается вторым
	if limit > 0 && len(keys) >= limit {
		return false, len(keys)
	}
	t.conns[k] = at
	return true, len(keys) + 1
}

// Known — у экземпляра есть снимок. События хуков от неизвестных
// экземпляров агент не засчитывает: иначе их не вычистит ни один снимок.
func (t *Tracker) Known(instance string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.snaps[instance]
	return ok
}

// Instances — экземпляры, у которых есть снимок, по алфавиту.
func (t *Tracker) Instances() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.snaps))
	for inst := range t.snaps {
		out = append(out, inst)
	}
	sort.Strings(out)
	return out
}

// Sessions — сессии из последних снимков всех экземпляров, для показа.
// События хуков между снимками сюда не входят: список отстаёт от учёта
// лимита не больше чем на один опрос.
func (t *Tracker) Sessions() []antizapret.Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []antizapret.Session
	for _, s := range t.snaps {
		out = append(out, s.sessions...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.CommonName != b.CommonName {
			return a.CommonName < b.CommonName
		}
		return a.RealAddr < b.RealAddr
	})
	return out
}

// Forget убирает снимок и события экземпляра: он остановлен или так долго
// молчит, что его снимок уже ничего не значит.
func (t *Tracker) Forget(instance string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.snaps, instance)
	for k := range t.conns {
		if k.Instance == instance {
			delete(t.conns, k)
		}
	}
	for k := range t.discs {
		if k.Instance == instance {
			delete(t.discs, k)
		}
	}
}

func (t *Tracker) Disconnect(k Key, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.discs[k] = at
}

// Counts — число сессий по каждому клиенту, у которого они есть.
func (t *Tracker) Counts() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cns := map[string]struct{}{}
	for _, s := range t.snaps {
		for k := range s.keys {
			cns[k.CN] = struct{}{}
		}
	}
	for k := range t.conns {
		cns[k.CN] = struct{}{}
	}
	out := map[string]int{}
	for cn := range cns {
		if n := len(t.keysOf(cn)); n > 0 {
			out[cn] = n
		}
	}
	return out
}
