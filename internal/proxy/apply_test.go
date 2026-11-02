package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/proxyapi"
)

// kernel — подмена ядра: хранит текущую таблицу nat и считает вызовы.
type kernel struct {
	rules    string
	restores []string
	persists int

	failRestoreAt int // номер вызова Restore (с 1), который падает; 0 — не падает
	failVerify    bool
	failPersist   bool
	failRollback  bool
}

func (k *kernel) applier() *Applier {
	return &Applier{
		Save: func(context.Context) (string, error) {
			if k.failVerify && len(k.restores) == 1 {
				// После первой подстановки ядро «не приняло» правки.
				return strings.ReplaceAll(k.rules, "198.51.100.99", "198.51.100.20"), nil
			}
			return k.rules, nil
		},
		Restore: func(_ context.Context, rules string) error {
			k.restores = append(k.restores, rules)
			if k.failRestoreAt == len(k.restores) {
				return errors.New("iptables-restore: Bad rule (does a matching rule exist in that chain?)")
			}
			if k.failRollback && len(k.restores) > 1 {
				return errors.New("откат: нет доступа")
			}
			k.rules = rules
			return nil
		},
		Persist: func(context.Context) error {
			k.persists++
			if k.failPersist {
				return errors.New("netfilter-persistent: нет места")
			}
			return nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func newKernel(t *testing.T) *kernel {
	return &kernel{rules: readTestdata(t, "iptables-save.txt")}
}

func TestApplierSetTargetSavesAfterRestore(t *testing.T) {
	k := newKernel(t)
	res, err := k.applier().SetTarget(context.Background(), proxyapi.GroupWireGuard, "198.51.100.99")
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "198.51.100.20" || res.To != "198.51.100.99" || res.Changed != 7 || !res.Saved {
		t.Fatalf("%+v", res)
	}
	if len(k.restores) != 1 || k.persists != 1 {
		t.Fatalf("restore %d, persist %d", len(k.restores), k.persists)
	}
	tb, _ := ParseNAT(k.rules)
	for _, g := range tb.Groups() {
		want := "198.51.100.20"
		if g.Name == proxyapi.GroupWireGuard {
			want = "198.51.100.99"
		}
		if g.Target != want {
			t.Errorf("%s → %s", g.Name, g.Target)
		}
	}
}

func TestApplierRestoreErrorRollsBack(t *testing.T) {
	k := newKernel(t)
	orig := k.rules
	k.failRestoreAt = 1
	_, err := k.applier().SetTarget(context.Background(), proxyapi.GroupWireGuard, "198.51.100.99")
	if err == nil || !strings.Contains(err.Error(), "Bad rule") || !strings.Contains(err.Error(), "возвращены") {
		t.Fatalf("err = %v", err)
	}
	if len(k.restores) != 2 || k.restores[1] != orig || k.rules != orig {
		t.Fatalf("снимок не восстановлен: вызовов %d", len(k.restores))
	}
	if k.persists != 0 {
		t.Fatal("после ошибки правила сохраняться не должны")
	}
}

func TestApplierVerifyMismatchRollsBack(t *testing.T) {
	k := newKernel(t)
	orig := k.rules
	k.failVerify = true
	_, err := k.applier().SetTarget(context.Background(), proxyapi.GroupWireGuard, "198.51.100.99")
	if err == nil || !strings.Contains(err.Error(), "нужен 198.51.100.99") {
		t.Fatalf("err = %v", err)
	}
	if k.rules != orig || k.persists != 0 {
		t.Fatal("откат не сделан")
	}
}

func TestApplierPersistErrorRollsBack(t *testing.T) {
	k := newKernel(t)
	orig := k.rules
	k.failPersist = true
	_, err := k.applier().SetTarget(context.Background(), proxyapi.GroupOpenVPN, "198.51.100.99")
	if err == nil || !strings.Contains(err.Error(), "не сохранены") {
		t.Fatalf("err = %v", err)
	}
	if k.rules != orig {
		t.Fatal("правила остались новыми, а сохранение не удалось")
	}
}

func TestApplierRollbackFailureIsReported(t *testing.T) {
	k := newKernel(t)
	k.failRestoreAt = 1
	k.failRollback = true
	_, err := k.applier().SetTarget(context.Background(), proxyapi.GroupOpenVPN, "198.51.100.99")
	if err == nil || !strings.Contains(err.Error(), "откат прежних правил не удался") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplierNoChangeTouchesNothing(t *testing.T) {
	k := newKernel(t)
	res, err := k.applier().SetTarget(context.Background(), proxyapi.GroupOpenVPN, "198.51.100.20")
	if err != nil || res.Changed != 0 || res.Saved {
		t.Fatalf("res %+v err %v", res, err)
	}
	if len(k.restores) != 0 || k.persists != 0 {
		t.Fatal("ничего не должно было запускаться")
	}
}

func TestApplierInputErrors(t *testing.T) {
	k := newKernel(t)
	for _, c := range [][2]string{{"что-то", "198.51.100.1"}, {"openvpn", "x"}} {
		_, err := k.applier().SetTarget(context.Background(), c[0], c[1])
		if !IsInput(err) {
			t.Errorf("%v: ждали ошибку запроса, получено %v", c, err)
		}
	}
	if len(k.restores) != 0 {
		t.Fatal("с неверным запросом правила не трогаем")
	}
}
