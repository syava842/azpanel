package node

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/syava842/azpanel/internal/nodeapi"
)

const (
	replicaSetupLocal = "ANTIZAPRET_WARP=n\nANTIZAPRET_WARP_PRIVATE_KEY=LOCALKEY\nVPN_WARP_ENDPOINT=local:1\nOLD=1\n"
	primarySetup      = "ANTIZAPRET_WARP=3\nANTIZAPRET_WARP_PRIVATE_KEY=PRIMARYKEY\nVPN_WARP_ENDPOINT=primary:2\nOPENVPN_HOST=vpn.example\n"
)

type syncLayout struct {
	apiEnv
	f     *fakeExec
	set   SyncSet
	base  string
	roles *RoleStore
}

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newSyncLayout(t *testing.T) syncLayout {
	t.Helper()
	e, f, _ := tasksEnv(t)
	base := t.TempDir()
	set := SyncSet{
		AntiZapretDir: filepath.Join(base, "antizapret"),
		EasyRSADir:    filepath.Join(base, "easyrsa3"),
		WireGuardDir:  filepath.Join(base, "wireguard"),
		AmneziaWGDir:  filepath.Join(base, "amnezia"),
		KnotDir:       filepath.Join(base, "knot"),
		LimitsPath:    filepath.Join(base, "data", "limits.json"),
	}
	put(t, filepath.Join(set.EasyRSADir, "pki", "ca.crt"), "CA")
	put(t, filepath.Join(set.EasyRSADir, "pki", "crl.pem"), "CRL")
	put(t, filepath.Join(set.EasyRSADir, "pki", "issued", "alice.crt"), "ALICE")
	put(t, filepath.Join(set.EasyRSADir, "pki", "private", "ca.key"), "CAKEY")
	put(t, filepath.Join(set.WireGuardDir, "antizapret.conf"), "AZCONF")
	put(t, filepath.Join(set.WireGuardDir, "vpn.conf"), "VPNCONF")
	put(t, filepath.Join(set.WireGuardDir, "key"), "WGKEY")
	put(t, filepath.Join(set.WireGuardDir, "warp-vpn.conf"), "WARPCONF")
	put(t, filepath.Join(set.AmneziaWGDir, "antizapret.conf"), "AMNEZIA")
	put(t, filepath.Join(set.AntiZapretDir, "setup"), replicaSetupLocal)
	put(t, filepath.Join(set.AntiZapretDir, "doall.sh"), "#!/bin/sh")
	put(t, filepath.Join(set.AntiZapretDir, "config", "include-hosts.txt"), "a.example\n")
	put(t, filepath.Join(set.AntiZapretDir, "config", "readme.md"), "не txt")
	put(t, filepath.Join(set.AntiZapretDir, "client", "openvpn", "antizapret", "antizapret-alice-(1.2.3.4).ovpn"), "OVPN")
	put(t, filepath.Join(set.KnotDir, "custom-a.lua"), "LUA")
	put(t, filepath.Join(set.KnotDir, "kresd.conf"), "не custom")
	put(t, set.LimitsPath, `{"limits":{}}`)

	roles := &RoleStore{Path: filepath.Join(base, "data", "role.json")}
	e.api.Sync = &SyncService{
		Set: set, Role: roles, Self: "/opt/azpanel/bin/azpanel",
		ParamsDir: filepath.Join(base, "params"), StageDir: filepath.Join(base, "stage"),
	}
	return syncLayout{apiEnv: e, f: f, set: set, base: base, roles: roles}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func buildTar(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := files[n]
		if err := nodeapi.WriteSyncEntry(tw, nodeapi.SyncEntry{Path: n, Size: int64(len(c)), Mode: "0640"}, strings.NewReader(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestSyncManifestCoversExactlyTheSet(t *testing.T) {
	l := newSyncLayout(t)
	m, err := l.client.SyncManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]nodeapi.SyncEntry{}
	for _, e := range m.Files {
		got[e.Path] = e
	}
	p := func(parts ...string) string { return filepath.ToSlash(filepath.Join(parts...)) }
	for _, want := range []string{
		p(l.set.EasyRSADir, "pki", "ca.crt"), p(l.set.EasyRSADir, "pki", "crl.pem"),
		p(l.set.EasyRSADir, "pki", "issued", "alice.crt"), p(l.set.EasyRSADir, "pki", "private", "ca.key"),
		p(l.set.WireGuardDir, "antizapret.conf"), p(l.set.WireGuardDir, "vpn.conf"), p(l.set.WireGuardDir, "key"),
		p(l.set.AmneziaWGDir, "antizapret.conf"),
		p(l.set.AntiZapretDir, "setup"), p(l.set.AntiZapretDir, "config", "include-hosts.txt"),
		p(l.set.AntiZapretDir, "client", "openvpn", "antizapret", "antizapret-alice-(1.2.3.4).ovpn"),
		p(l.set.KnotDir, "custom-a.lua"), filepath.ToSlash(l.set.LimitsPath),
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("в манифесте нет %s", want)
		}
	}
	for _, not := range []string{
		p(l.set.WireGuardDir, "warp-vpn.conf"), p(l.set.AntiZapretDir, "doall.sh"),
		p(l.set.AntiZapretDir, "config", "readme.md"), p(l.set.KnotDir, "kresd.conf"),
		p(l.set.AntiZapretDir, "banned_clients"),
	} {
		if _, ok := got[not]; ok {
			t.Errorf("в манифесте лишний %s", not)
		}
	}
	if e := got[p(l.set.EasyRSADir, "pki", "crl.pem")]; e.SHA256 != sum("CRL") || e.Size != 3 {
		t.Errorf("crl.pem: %+v", e)
	}
	// Отпечаток setup считается без аккаунта WARP: у основного и реплики он сходится.
	wantSetup := "ANTIZAPRET_WARP=n\nOLD=1\n"
	if e := got[p(l.set.AntiZapretDir, "setup")]; e.SHA256 != sum(wantSetup) || e.Size != int64(len(wantSetup)) {
		t.Errorf("setup: %+v", e)
	}
	if !sort.SliceIsSorted(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path }) {
		t.Error("манифест не отсортирован")
	}
}

func TestSyncFileRejectsPathsOutsideSet(t *testing.T) {
	l := newSyncLayout(t)
	ctx := context.Background()
	for _, bad := range []string{
		"", "/etc/passwd", "relative/x", filepath.Join(l.set.AntiZapretDir, "doall.sh"),
		filepath.Join(l.set.WireGuardDir, "warp-vpn.conf"),
		filepath.Join(l.set.EasyRSADir, "..", "antizapret", "doall.sh"),
		filepath.Join(l.set.KnotDir, "kresd.conf"),
	} {
		rc, err := l.client.SyncFile(ctx, bad)
		if err == nil {
			rc.Close()
			t.Errorf("%q прочитан", bad)
			continue
		}
		if status(err) != 400 {
			t.Errorf("%q: статус %d (%v), ждали 400", bad, status(err), err)
		}
	}
	rc, err := l.client.SyncFile(ctx, filepath.Join(l.set.EasyRSADir, "pki", "crl.pem"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "CRL" {
		t.Fatalf("crl.pem = %q", b)
	}
	// Ключи WARP из setup наружу не отдаются.
	rc, err = l.client.SyncFile(ctx, filepath.Join(l.set.AntiZapretDir, "setup"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(rc)
	rc.Close()
	if strings.Contains(string(b), "LOCALKEY") || strings.Contains(string(b), "WARP_ENDPOINT") || !strings.Contains(string(b), "OLD=1") {
		t.Fatalf("setup = %q", b)
	}
	if _, err := l.client.SyncFile(ctx, filepath.Join(l.set.AntiZapretDir, "banned_clients")); status(err) != 404 {
		t.Fatalf("нет файла: %v", err)
	}
}

func TestSyncDoesNotFollowSymlinks(t *testing.T) {
	l := newSyncLayout(t)
	outside := filepath.Join(l.base, "outside")
	put(t, filepath.Join(outside, "secret"), "SECRET")
	clientDir := filepath.Join(l.set.AntiZapretDir, "client")
	if err := os.Symlink(outside, filepath.Join(clientDir, "evil")); err != nil {
		t.Skip("симлинки недоступны:", err)
	}
	if err := os.Symlink(filepath.Join(l.set.AntiZapretDir, "doall.sh"), filepath.Join(l.set.KnotDir, "custom-link.lua")); err != nil {
		t.Skip("симлинки недоступны:", err)
	}
	m, err := l.client.SyncManifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Files {
		if strings.Contains(e.Path, "secret") || strings.Contains(e.Path, "custom-link") {
			t.Errorf("симлинк попал в манифест: %s", e.Path)
		}
	}
	for _, p := range []string{filepath.Join(clientDir, "evil", "secret"), filepath.Join(l.set.KnotDir, "custom-link.lua")} {
		if rc, err := l.client.SyncFile(context.Background(), p); err == nil {
			rc.Close()
			t.Errorf("%s прочитан через симлинк", p)
		}
	}
	// В архиве запись «через симлинк» отклоняется до записи.
	l.roles.Set(nodeapi.SyncRole{Role: nodeapi.RoleReplica})
	_, err = l.client.SyncApply(context.Background(), buildTar(t, map[string]string{filepath.Join(clientDir, "evil", "x"): "X"}), false)
	if status(err) != 400 {
		t.Fatalf("запись через симлинк: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(outside, "x")); serr == nil {
		t.Fatal("файл записан вне набора")
	}
}

func TestSyncApplyRefusedOnPrimary(t *testing.T) {
	l := newSyncLayout(t)
	_, err := l.client.SyncApply(context.Background(), buildTar(t, map[string]string{filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt"): "x\n"}), false)
	if status(err) != 409 || !strings.Contains(err.Error(), "основной") {
		t.Fatalf("err = %v", err)
	}
}

func TestSyncApplyRejectsPathOutsideSet(t *testing.T) {
	l := newSyncLayout(t)
	l.roles.Set(nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: "g"})
	inSet := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	for name, files := range map[string]map[string]string{
		"скрипт AntiZapret":  {inSet: "x\n", filepath.Join(l.set.AntiZapretDir, "doall.sh"): "evil"},
		"ключи WARP":         {filepath.Join(l.set.WireGuardDir, "warp-vpn.conf"): "evil"},
		"системный файл":     {"/etc/passwd": "evil"},
		"выход через «..»":   {filepath.Join(l.set.EasyRSADir, "..", "antizapret", "doall.sh"): "evil"},
		"относительный путь": {"config/include-hosts.txt": "x"},
		"не custom*.lua":     {filepath.Join(l.set.KnotDir, "kresd.conf"): "evil"},
		"не *.txt в config":  {filepath.Join(l.set.AntiZapretDir, "config", "x.sh"): "evil"},
	} {
		_, err := l.client.SyncApply(context.Background(), buildTar(t, files), false)
		if status(err) != 400 {
			t.Errorf("%s: %v, ждали 400", name, err)
		}
	}
	if len(l.f.calls) != 0 {
		t.Fatalf("задача запущена при отказе: %v", l.f.calls)
	}
	if ents, _ := os.ReadDir(l.api.Sync.StageDir); len(ents) != 0 {
		t.Fatalf("в каталоге приёма остались архивы: %d", len(ents))
	}
	if b, _ := os.ReadFile(filepath.Join(l.set.AntiZapretDir, "doall.sh")); string(b) != "#!/bin/sh" {
		t.Fatal("doall.sh изменён")
	}
}

func TestSyncApplyAcceptedStartsTask(t *testing.T) {
	l := newSyncLayout(t)
	l.roles.Set(nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: "g"})
	inSet := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	task, err := l.client.SyncApply(context.Background(), buildTar(t, map[string]string{inSet: "b.example\n"}), true)
	if err != nil || task.Kind != TaskSyncApply || len(task.ID) != 12 {
		t.Fatalf("%+v %v", task, err)
	}
	if len(l.f.calls) != 1 {
		t.Fatalf("команд: %v", l.f.calls)
	}
	call := strings.Join(l.f.calls[0], " ")
	if !strings.Contains(call, "/opt/azpanel/bin/azpanel internal sync-apply --params ") {
		t.Fatalf("команда задачи: %s", call)
	}
	// Файл параметров лежит там, где его ждёт режим internal, и описывает архив.
	ents, _ := os.ReadDir(l.api.Sync.ParamsDir)
	if len(ents) != 1 {
		t.Fatalf("файлов параметров: %d", len(ents))
	}
	var p SyncApplyParams
	data, _ := os.ReadFile(filepath.Join(l.api.Sync.ParamsDir, ents[0].Name()))
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || !p.Prune || p.Set != l.set {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := os.Stat(p.Archive); err != nil {
		t.Fatalf("архив задачи: %v", err)
	}
	l.f.done()
}

type recorder struct{ calls []string }

func (r *recorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if len(args) > 0 && args[0] == "list-units" {
		return []byte("kresd@1.service loaded active running x\nkresd@2.service loaded active running x\n"), nil
	}
	return nil, nil
}

func applyTar(t *testing.T, set SyncSet, files map[string]string, prune bool) (*recorder, error) {
	t.Helper()
	stage := t.TempDir()
	arch := filepath.Join(stage, "archive.tar")
	if err := os.WriteFile(arch, buildTar(t, files).Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	var log bytes.Buffer
	err := RunSyncApply(context.Background(), SyncApplyParams{Set: set, Archive: arch, Stage: stage, Prune: prune}, &SyncEnv{Run: rec.run, Out: &log})
	if _, serr := os.Stat(stage); serr == nil {
		t.Error("каталог приёма не удалён")
	}
	return rec, err
}

func TestRunSyncApplyKeepsReplicaWarpKeys(t *testing.T) {
	l := newSyncLayout(t)
	setup := filepath.Join(l.set.AntiZapretDir, "setup")
	rec, err := applyTar(t, l.set, map[string]string{setup: primarySetup}, false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(setup)
	got := string(b)
	for _, want := range []string{"ANTIZAPRET_WARP=3", "OPENVPN_HOST=vpn.example", "ANTIZAPRET_WARP_PRIVATE_KEY=LOCALKEY", "VPN_WARP_ENDPOINT=local:1"} {
		if !strings.Contains(got, want) {
			t.Errorf("в setup нет %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"PRIMARYKEY", "primary:2", "OLD=1", "ANTIZAPRET_WARP=n"} {
		if strings.Contains(got, bad) {
			t.Errorf("в setup остался %q:\n%s", bad, got)
		}
	}
	if len(rec.calls) != 0 {
		t.Errorf("setup не требует перезапуска служб: %v", rec.calls)
	}
	// Повторная синхронизация тем же содержимым ничего не меняет.
	l2 := string(b)
	if _, err := applyTar(t, l.set, map[string]string{setup: primarySetup}, false); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(setup); string(b2) != l2 {
		t.Errorf("повторное применение изменило setup:\n%s", b2)
	}
}

func TestRunSyncApplyWritesFilesAndRestartsOnlyAffected(t *testing.T) {
	l := newSyncLayout(t)
	crl := filepath.Join(l.set.EasyRSADir, "pki", "crl.pem")
	newIssued := filepath.Join(l.set.EasyRSADir, "pki", "issued", "bob.crt")
	az := filepath.Join(l.set.WireGuardDir, "antizapret.conf")
	rec, err := applyTar(t, l.set, map[string]string{crl: "CRL2", newIssued: "BOB", az: "AZCONF2"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{crl: "CRL2", newIssued: "BOB", az: "AZCONF2"} {
		if b, _ := os.ReadFile(p); string(b) != want {
			t.Errorf("%s = %q", p, b)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(az); fi.Mode().Perm() != 0o640 {
			t.Errorf("права %v", fi.Mode().Perm())
		}
	}
	// Перезапущен только wg-quick@antizapret: OpenVPN читает CRL и выданные
	// сертификаты сам, перезапуск оборвал бы все сессии.
	if len(rec.calls) != 1 || rec.calls[0] != "systemctl try-restart wg-quick@antizapret" {
		t.Fatalf("команды: %v", rec.calls)
	}
}

func TestRunSyncApplyRestartsOpenVPNOnCAChangeAndKresdOnLua(t *testing.T) {
	l := newSyncLayout(t)
	rec, err := applyTar(t, l.set, map[string]string{
		filepath.Join(l.set.EasyRSADir, "pki", "ca.crt"): "CA2",
		filepath.Join(l.set.KnotDir, "custom-a.lua"):     "LUA2",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rec.calls, "\n")
	for _, want := range []string{"try-restart openvpn-server@antizapret-udp", "try-restart openvpn-server@vpn-tcp", "try-restart kresd@1", "try-restart kresd@2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет команды %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "wg-quick") {
		t.Errorf("WireGuard перезапущен без причины:\n%s", joined)
	}
}

func TestRunSyncApplyPrune(t *testing.T) {
	l := newSyncLayout(t)
	keep := filepath.Join(l.set.AntiZapretDir, "config", "include-hosts.txt")
	gone := filepath.Join(l.set.AntiZapretDir, "client", "openvpn", "antizapret", "antizapret-alice-(1.2.3.4).ovpn")
	warp := filepath.Join(l.set.WireGuardDir, "warp-vpn.conf")
	if _, err := applyTar(t, l.set, map[string]string{keep: "новое\n"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gone); err == nil {
		t.Error("лишний профиль не удалён")
	}
	if _, err := os.Stat(warp); err != nil {
		t.Error("файл вне набора удалён")
	}
	if _, err := os.Stat(filepath.Join(l.set.AntiZapretDir, "setup")); err != nil {
		t.Error("setup удалён")
	}
	if _, err := os.Stat(filepath.Join(l.set.AntiZapretDir, "doall.sh")); err != nil {
		t.Error("файл AntiZapret вне набора удалён")
	}
	if _, err := applyTar(t, l.set, map[string]string{}, true); err == nil {
		t.Error("пустой архив с удалением принят")
	}
}

func TestRunSyncApplyRevalidatesArchive(t *testing.T) {
	l := newSyncLayout(t)
	// Подмена параметров или архива не должна выводить запись за пределы набора.
	doall := filepath.Join(l.set.AntiZapretDir, "doall.sh")
	if _, err := applyTar(t, l.set, map[string]string{doall: "evil"}, false); err == nil {
		t.Fatal("запись вне набора принята задачей")
	}
	if b, _ := os.ReadFile(doall); string(b) != "#!/bin/sh" {
		t.Fatal("doall.sh изменён")
	}
}

func TestReplicaRejectsMutatingRoutes(t *testing.T) {
	l := newSyncLayout(t)
	ctx := context.Background()
	if err := l.client.SetSyncRole(ctx, nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: "Москва"}); err != nil {
		t.Fatal(err)
	}
	info, err := l.client.Info(ctx)
	if err != nil || info.Role != nodeapi.RoleReplica || info.Group != "Москва" {
		t.Fatalf("%+v %v", info, err)
	}
	_, err = l.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindOpenVPN})
	if status(err) != 409 || !strings.Contains(err.Error(), "реплика группы «Москва»") {
		t.Fatalf("POST /v1/clients на реплике: %v", err)
	}
	if len(*l.calls) != 0 {
		t.Fatalf("client.sh вызван на реплике: %v", *l.calls)
	}
	for name, call := range map[string]func() error{
		"renew":   func() error { _, err := l.client.Renew(ctx, "alice", 30); return err },
		"delete":  func() error { _, err := l.client.DeleteClient(ctx, nodeapi.KindOpenVPN, "alice"); return err },
		"limit":   func() error { return l.client.SetLimit(ctx, "alice", 2) },
		"blocked": func() error { _, err := l.client.SetBlocked(ctx, "alice", true); return err },
		"rebuild": func() error { _, err := l.client.RebuildProfiles(ctx); return err },
		"setup":   func() error { _, err := l.client.SetSetup(ctx, map[string]string{"ROUTE_ALL": "y"}); return err },
		"routing": func() error {
			_, err := l.client.PatchRouting(ctx, "include-hosts.txt", nodeapi.RoutingPatch{Add: []string{"x.example"}})
			return err
		},
		"put": func() error { _, err := l.client.ReplaceRouting(ctx, "include-hosts.txt", "x\n", ""); return err },
		"restore": func() error {
			_, err := l.client.RestoreRouting(ctx, "include-hosts.txt", "20261102T101500.123Z")
			return err
		},
	} {
		if err := call(); status(err) != 409 {
			t.Errorf("%s на реплике: %v, ждали 409", name, err)
		}
	}
	// Чтение и действия, не меняющие данные группы, работают.
	if _, err := l.client.Clients(ctx); err != nil {
		t.Errorf("GET /v1/clients: %v", err)
	}
	if _, err := l.client.SyncManifest(ctx); err != nil {
		t.Errorf("манифест: %v", err)
	}

	// Вернули основным — запрос проходит.
	if err := l.client.SetSyncRole(ctx, nodeapi.SyncRole{Role: nodeapi.RolePrimary}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindOpenVPN}); err != nil {
		t.Fatalf("POST /v1/clients на основном: %v", err)
	}
}

func TestSyncRoleValidationAndPersistence(t *testing.T) {
	l := newSyncLayout(t)
	ctx := context.Background()
	if r, err := l.client.SyncRole(ctx); err != nil || r.Role != nodeapi.RolePrimary {
		t.Fatalf("роль по умолчанию: %+v %v", r, err)
	}
	for _, bad := range []nodeapi.SyncRole{{Role: "master"}, {Role: ""}, {Role: nodeapi.RoleReplica, Group: strings.Repeat("я", 65)}, {Role: nodeapi.RoleReplica, Group: "a\nb"}} {
		if err := l.client.SetSyncRole(ctx, bad); status(err) != 400 {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if err := l.client.SetSyncRole(ctx, nodeapi.SyncRole{Role: nodeapi.RoleReplica, Group: "g"}); err != nil {
		t.Fatal(err)
	}
	// Роль переживает перезапуск агента: хранится в файле.
	again := &RoleStore{Path: l.roles.Path}
	if r, err := again.Get(); err != nil || r.Role != nodeapi.RoleReplica || r.Group != "g" {
		t.Fatalf("после перезапуска: %+v %v", r, err)
	}
	// Повреждённый файл не превращает реплику в основной.
	os.WriteFile(l.roles.Path, []byte("{не json"), 0o600)
	_, err := l.client.CreateClient(ctx, nodeapi.CreateClient{Name: "bob", Kind: nodeapi.KindOpenVPN})
	if status(err) != 500 {
		t.Fatalf("повреждённая роль: %v", err)
	}
}

func TestReplicaAllowsBackup(t *testing.T) {
	l := newSyncLayout(t)
	l.roles.Set(nodeapi.SyncRole{Role: nodeapi.RoleReplica})
	if _, err := l.client.CreateBackup(context.Background()); err != nil {
		t.Fatalf("бэкап на реплике (перед «Выровнять») запрещён: %v", err)
	}
	l.f.done()
}

func TestSyncRequiresToken(t *testing.T) {
	l := newSyncLayout(t)
	req, _ := http.NewRequest(http.MethodGet, l.srv.URL+"/v1/sync/file?path="+url.QueryEscape("/etc/passwd"), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без токена: %d", resp.StatusCode)
	}
}

func TestIsWarpAccountKey(t *testing.T) {
	for k, want := range map[string]bool{
		"ANTIZAPRET_WARP_PRIVATE_KEY": true, "VPN_WARP_PUBLIC_KEY": true, "DNS_WARP_ENDPOINT": true, "ANTIZAPRET_WARP_ADDRESS": true,
		"ANTIZAPRET_WARP": false, "WARP_MTU": false, "DNS_WARP": false, "RECONNECT_WARP": false, "WARP_PROTECTION": false,
		"WIREGUARD_ENABLE": false, "OPENVPN_HOST": false, "SOME_ADDRESS": false,
	} {
		if IsWarpAccountKey(k) != want {
			t.Errorf("%s: %v, ждали %v", k, !want, want)
		}
	}
}
