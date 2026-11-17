package warp

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// InstallOptions — что установщик AZ-WARP найдёт на сервере и предложит на
// выбор: те же проверки, что в install.sh, чтобы форма панели показывала те же
// варианты и умолчания.
type InstallOptions struct {
	PhysMTU int `json:"phys_mtu"` // MTU интерфейса маршрута по умолчанию
	RecMTU  int `json:"rec_mtu"`  // рекомендуемый: PhysMTU − 80, не ниже 1280
	// GeminiListed, ChatGPTListed — блок уже есть в domains.txt (остался от
	// прошлой установки): установщик вопрос не задаст.
	GeminiListed  bool          `json:"gemini_listed,omitempty"`
	ChatGPTListed bool          `json:"chatgpt_listed,omitempty"`
	WarpSources   []WarpSource  `json:"warp_sources"` // в порядке меню установщика
	WGConfs       []WGConfFound `json:"wg_confs,omitempty"`
	OvpnFiles     []OvpnFound   `json:"ovpn_files,omitempty"`
}

// WarpSource — пункт меню «Выбор источника WARP-ключей».
type WarpSource struct {
	ID    string `json:"id"` // system | wgcf | root | generate
	Label string `json:"label"`
}

// WGConfFound — WireGuard-конфиг, который установщик покажет в списке.
type WGConfFound struct {
	Path     string `json:"path"`
	Endpoint string `json:"endpoint,omitempty"`
}

// OvpnFound — .ovpn из /root или /root/warper; Auth — конфиг спросит логин и пароль.
type OvpnFound struct {
	Path string `json:"path"`
	Auth bool   `json:"auth,omitempty"`
}

// Пути и константы install.sh.
const cfWarpPubKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

var warpSystemCandidates = []string{"/etc/wireguard/warp-vpn.conf", "/etc/wireguard/warp-antizapret.conf", "/etc/wireguard/warp.conf"}

// WarpSourceIDs — допустимые источники ключей WARP.
var WarpSourceIDs = map[string]bool{"system": true, "wgcf": true, "root": true, "generate": true}

// Options собирает варианты установки. root — корень файловой системы ("" — "/"),
// для тестов.
func (w *Warper) Options(root string) InstallOptions {
	at := func(p string) string { return filepath.Join(root, filepath.FromSlash(p)) }
	dir := filepath.ToSlash(w.dir())
	var o InstallOptions
	o.PhysMTU = physMTU(root)
	o.RecMTU = o.PhysMTU - 80
	if o.RecMTU < 1280 {
		o.RecMTU = 1280
	}
	domains := at(dir + "/domains.txt")
	o.GeminiListed = hasListBlock(domains, "GEMINI")
	o.ChatGPTListed = hasListBlock(domains, "CHATGPT")

	// resolve_warp_system_conf: первый кандидат с ключом Cloudflare.
	for _, c := range warpSystemCandidates {
		data, err := os.ReadFile(at(c))
		if err != nil || !strings.Contains(string(data), cfWarpPubKey) {
			continue
		}
		if confValue(string(data), "PrivateKey", "= ") != "" {
			addr := confValue(string(data), "Address", "= ")
			if addr == "" {
				addr = "без адреса"
			}
			o.WarpSources = append(o.WarpSources, WarpSource{"system", c + " (" + addr + ") — ключи AntiZapret, рекомендуется"})
		}
		break
	}
	for _, s := range []struct{ id, path string }{
		{"wgcf", dir + "/wgcf/wgcf-profile.conf"},
		{"root", "/root/wgcf-profile.conf"},
	} {
		data, err := os.ReadFile(at(s.path))
		if err != nil || !strings.Contains(string(data), cfWarpPubKey) {
			continue
		}
		if confValue(string(data), "PrivateKey", " = ") != "" {
			o.WarpSources = append(o.WarpSources, WarpSource{s.id, s.path + " (" + confValue(string(data), "Address", " = ") + ")"})
		}
	}
	o.WarpSources = append(o.WarpSources, WarpSource{"generate", "Сгенерировать новый ключ WARP"})

	for _, d := range []string{"/root", dir} {
		for _, f := range globSorted(at(d), "*.conf") {
			data, err := os.ReadFile(f)
			if err != nil || !validWGConf(string(data)) {
				continue
			}
			o.WGConfs = append(o.WGConfs, WGConfFound{Path: d + "/" + filepath.Base(f), Endpoint: wgEndpoint(string(data))})
		}
	}
	for _, d := range []string{"/root", dir} {
		for _, f := range globSorted(at(d), "*.ovpn") {
			data, err := os.ReadFile(f)
			if err != nil || !ovpnRemoteRe.Match(data) {
				continue
			}
			o.OvpnFiles = append(o.OvpnFiles, OvpnFound{Path: d + "/" + filepath.Base(f), Auth: ovpnAuthRe.Match(data)})
		}
	}
	// install.sh сортирует найденные .ovpn общим списком (find … | sort).
	sort.Slice(o.OvpnFiles, func(i, j int) bool { return o.OvpnFiles[i].Path < o.OvpnFiles[j].Path })
	return o
}

var (
	ovpnRemoteRe = regexp.MustCompile(`(?mi)^[ \t]*remote[ \t]`)
	ovpnAuthRe   = regexp.MustCompile(`(?mi)^[ \t]*auth-user-pass`)
	virtIfaceRe  = regexp.MustCompile(`lo|tun|tap|wg|singbox|docker|veth|br-`)
)

// physMTU — как detect_physical_mtu: интерфейс маршрута по умолчанию, иначе
// первый не виртуальный; MTU из /sys, иначе 1500.
func physMTU(root string) int {
	iface := defaultRouteIface(filepath.Join(root, "proc", "net", "route"))
	if iface == "" {
		entries, _ := os.ReadDir(filepath.Join(root, "sys", "class", "net"))
		for _, e := range entries {
			if !virtIfaceRe.MatchString(e.Name()) {
				iface = e.Name()
				break
			}
		}
	}
	if iface != "" {
		if data, err := os.ReadFile(filepath.Join(root, "sys", "class", "net", iface, "mtu")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1500
}

func defaultRouteIface(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 && fs[1] == "00000000" {
			return fs[0]
		}
	}
	return ""
}

func hasListBlock(path, name string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimRight(l, "\r") == "# --- "+name+" ---" {
			return true
		}
	}
	return false
}

// confValue — значение первой строки «Key<sep>…», как grep -m1 '^Key' | awk -F sep.
func confValue(data, key, sep string) string {
	for _, l := range strings.Split(data, "\n") {
		if !strings.HasPrefix(l, key) {
			continue
		}
		_, v, ok := strings.Cut(l, sep)
		if !ok {
			return ""
		}
		if f := strings.Fields(v); len(f) > 0 {
			return f[0]
		}
		return ""
	}
	return ""
}

// validWGConf — _is_valid_wg_conf: есть [Peer], Endpoint и PublicKey, и это не
// конфиг самого Cloudflare WARP.
func validWGConf(s string) bool {
	has := func(prefix string) bool {
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, prefix) {
				return true
			}
		}
		return false
	}
	if !has("[Peer]") || !has("Endpoint") || !has("PublicKey") {
		return false
	}
	for _, bad := range []string{"engage.cloudflareclient.com", "162.159.192.1", "162.159.193.1", cfWarpPubKey} {
		if strings.Contains(s, bad) {
			return false
		}
	}
	return true
}

func wgEndpoint(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "Endpoint") {
			_, v, _ := strings.Cut(l, "= ")
			return strings.Join(strings.Fields(v), "")
		}
	}
	return ""
}

func globSorted(dir, pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, pattern))
	var out []string
	for _, f := range m {
		if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}
