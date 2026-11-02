package panel

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/warp"
)

type warpPeerRow struct{ Endpoint, Handshake, Rx, Tx string }

type warpIfaceRow struct {
	Name  string
	Peers []warpPeerRow
}

// warpDomainRow — строка списка доменов; Raw — когда агент прислал только
// строку целиком (старый ответ без разбора по «|»).
type warpDomainRow struct {
	Domain, Source string
	Enabled, Known bool
	Raw            string
}

// warpModes — режимы установки AZ-WARP в порядке установщика.
var warpModes = []struct{ Value, Title string }{
	{"warp", "Cloudflare WARP"},
	{"slave", "Донор (Shadowsocks)"},
	{"wg", "WireGuard"},
	{"vless", "VLESS"},
	{"hy2", "Hysteria2"},
	{"openvpn", "OpenVPN"},
}

// warpToggles — кнопки включения и выключения списков сервисов.
var warpToggles = []struct{ Action, List, Title string }{
	{"enable", "gemini", "Включить gemini"}, {"disable", "gemini", "Выключить gemini"},
	{"enable", "chatgpt", "Включить chatgpt"}, {"disable", "chatgpt", "Выключить chatgpt"},
}

func (s *Server) warpPage(w http.ResponseWriter, r *http.Request) {
	s.warpView(w, r, http.StatusOK, "", nil)
}

func (s *Server) warpView(w http.ResponseWriter, r *http.Request, status int, errText string, typed map[string]string) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	data := map[string]any{"Typed": typed, "Modes": warpModes, "Toggles": warpToggles}
	if errText != "" {
		data["Error"] = errText
	}
	wp, err := n.Warp(ctx)
	if err != nil {
		_, tx := s.svcErr(err)
		data["WarpErr"] = "сводка WARP недоступна: " + tx
		s.render(w, r, status, "warp", data)
		return
	}
	ifaces := make([]warpIfaceRow, 0, len(wp.Builtin))
	for _, i := range wp.Builtin {
		row := warpIfaceRow{Name: i.Name}
		for _, p := range i.Peers {
			hs := "—"
			if p.LatestHandshake != nil {
				hs = formatTime(p.LatestHandshake)
			}
			row.Peers = append(row.Peers, warpPeerRow{Endpoint: p.Endpoint, Handshake: hs,
				Rx: humanBytes(uint64(max(p.RxBytes, 0))), Tx: humanBytes(uint64(max(p.TxBytes, 0)))})
		}
		ifaces = append(ifaces, row)
	}
	data["Builtin"] = ifaces
	data["AZ"] = wp.AZ
	data["OutboundShown"] = wp.AZ.OutboundLabel
	if wp.AZ.OutboundLabel == "" {
		data["OutboundShown"] = wp.AZ.OutboundMode
	}
	if wp.AZ.Installed {
		if dl, err := n.WarpDomains(ctx); err != nil {
			_, tx := s.svcErr(err)
			data["DomErr"] = "домены недоступны: " + tx
		} else {
			data["Domains"] = warpDomainRows(dl)
		}
		if il, err := n.WarpIPs(ctx); err != nil {
			_, tx := s.svcErr(err)
			data["IPErr"] = "подсети недоступны: " + tx
		} else {
			data["IPs"] = il.Lines
		}
	}
	s.render(w, r, status, "warp", data)
}

func warpDomainRows(l nodeapi.WarpList) []warpDomainRow {
	if len(l.Domains) > 0 {
		out := make([]warpDomainRow, 0, len(l.Domains))
		for _, d := range l.Domains {
			out = append(out, warpDomainRow{Domain: d.Domain, Source: d.Source, Enabled: d.Enabled, Known: true})
		}
		return out
	}
	out := make([]warpDomainRow, 0, len(l.Lines))
	for _, line := range l.Lines {
		out = append(out, warpDomainRow{Raw: line}) // разбора нет — строка целиком
	}
	return out
}

// warpEdit разбирает правку списка и отправляет её агенту. kind — domains|ips.
func (s *Server) warpEdit(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, ok := s.svc(w, r)
		if !ok {
			return
		}
		action := r.PostForm.Get("action")
		arg := strings.TrimSpace(r.PostForm.Get("arg"))
		op := nodeapi.WarpOp{Op: action, Arg: arg}
		bad := func(text string) { s.warpView(w, r, http.StatusBadRequest, text, nil) }
		switch {
		case kind == "domains" && (action == "add" || action == "remove"):
			if !warp.ValidDomain(arg) {
				bad("Недопустимый домен: латиница, цифры, «.» и «-», например example.com.")
				return
			}
		case kind == "domains" && (action == "enable" || action == "disable"):
			if arg != "gemini" && arg != "chatgpt" {
				bad("Включать и выключать можно списки gemini и chatgpt.")
				return
			}
		case kind == "domains" && action == "save":
			op.Arg = ""
		case kind == "ips" && (action == "ipadd" || action == "ipremove"):
			if !warp.ValidSubnet(arg) {
				bad("Недопустимая подсеть: адрес или сеть IPv4 вида 1.2.3.0/24.")
				return
			}
		default:
			bad("Неизвестное действие.")
			return
		}
		e := nodeapi.WarpEdit{Ops: []nodeapi.WarpOp{op}, Sync: r.PostForm.Get("sync") == "1"}
		var t nodeapi.Task
		var err error
		if kind == "domains" {
			t, err = n.EditWarpDomains(r.Context(), e)
		} else {
			t, err = n.EditWarpIPs(r.Context(), e)
		}
		opName := "warp_" + kind
		target := strings.TrimSpace(action + " " + op.Arg)
		if err != nil {
			s.serviceRefused(w, r, opName, target, err)
			return
		}
		detail := ""
		if e.Sync {
			detail = "с синхронизацией;"
		}
		s.taskStarted(w, r, opName, target, detail, t)
	}
}

func (s *Server) warpSync(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	t, err := n.WarpSync(r.Context())
	if err != nil {
		s.serviceRefused(w, r, "warp_sync", "az-warp", err)
		return
	}
	s.taskStarted(w, r, "warp_sync", "az-warp", "", t)
}

func (s *Server) warpUpdate(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	if !formConfirmed(r) {
		s.warpView(w, r, http.StatusBadRequest, "Отметьте подтверждение: AZ-WARP обновится и перезапустит свои службы.", nil)
		return
	}
	t, err := n.WarpUpdate(r.Context())
	if err != nil {
		s.serviceRefused(w, r, "warp_update", "az-warp", err)
		return
	}
	s.taskStarted(w, r, "warp_update", "az-warp", "", t)
}

// warpInstall — форма вопросов установщика AZ-WARP. Секреты (ключи, пароли) в
// журнал, аудит и ответ не попадают.
func (s *Server) warpInstall(w http.ResponseWriter, r *http.Request) {
	n, ok := s.svc(w, r)
	if !ok {
		return
	}
	f := r.PostForm
	get := func(k string) string { return strings.TrimSpace(f.Get(k)) }
	typed := map[string]string{"mode": get("mode"), "subnet": get("subnet"), "mtu": get("mtu"), "warp_key": get("warp_key"),
		"slave_link": get("slave_link"), "slave_port": get("slave_port"), "proxy_link": get("proxy_link"),
		"wg_endpoint": get("wg_endpoint"), "wg_address": get("wg_address"), "wg_public_key": get("wg_public_key"),
		"wg_keepalive": get("wg_keepalive"), "wg_conf_index": get("wg_conf_index"), "ovpn_path": get("ovpn_path"), "ovpn_user": get("ovpn_user")}
	bad := func(text string) { s.warpView(w, r, http.StatusBadRequest, text, typed) }
	a := nodeapi.WarpInstallAnswers{
		Mode: get("mode"), NoGemini: f.Get("no_gemini") == "1", NoChatGPT: f.Get("no_chatgpt") == "1",
		Subnet: get("subnet"), ForceSubnet: f.Get("force_subnet") == "1",
		SlaveLink: get("slave_link"), SlavePort: get("slave_port"), SlaveKey: get("slave_key"),
		ProxyLink: get("proxy_link"), OvpnPath: get("ovpn_path"), OvpnUser: get("ovpn_user"), OvpnPass: f.Get("ovpn_pass"),
	}
	for _, x := range []struct {
		key string
		dst *int
		msg string
	}{
		{"mtu", &a.MTU, "MTU: число от 1280 до 1500."},
		{"warp_key", &a.WarpKey, "Номер источника ключей: целое число."},
		{"wg_conf_index", &a.WGConfIndex, "Номер найденного .conf: целое число."},
	} {
		v := get(x.key)
		if v == "" {
			continue
		}
		num, err := strconv.Atoi(v)
		if err != nil {
			bad(x.msg)
			return
		}
		*x.dst = num
	}
	if a.Mode == "wg" && a.WGConfIndex == 0 {
		a.WG = &nodeapi.WarpWGManual{Endpoint: get("wg_endpoint"), Address: get("wg_address"), PrivateKey: get("wg_private_key"),
			PublicKey: get("wg_public_key"), PresharedKey: get("wg_preshared_key"), Keepalive: get("wg_keepalive")}
	}
	if err := a.Validate(); err != nil {
		bad(err.Error())
		return
	}
	t, err := n.InstallWarp(r.Context(), a)
	if err != nil {
		s.Log.Warn("действие", "user", s.user(r), "op", "warp_install", "mode", a.Mode, "err", err)
		st, tx := s.svcErr(err)
		s.auditRefused(r, "warp_install", a.Mode, st, tx)
		s.warpView(w, r, st, tx, typed)
		return
	}
	detail := "режим " + a.Mode
	if a.Subnet != "" {
		detail += ", подсеть " + a.Subnet
	}
	if a.MTU != 0 {
		detail += ", MTU " + strconv.Itoa(a.MTU)
	}
	s.taskStarted(w, r, "warp_install", a.Mode, detail+";", t)
}
