//go:build !linux

package update

// acquireLock — вне Linux обновление не ставится (бинарники только linux),
// замок нужен лишь для сборки и тестов на других системах.
func acquireLock(string) (func(), error) { return func() {}, nil }
