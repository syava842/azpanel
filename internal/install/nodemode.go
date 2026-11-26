package install

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"

	"github.com/syava842/azpanel/internal/agenttls"
	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/nodeapi"
	"github.com/syava842/azpanel/internal/paths"
	"github.com/syava842/azpanel/internal/secrets"
)

// Режим node: агент узла для панели на другом сервере. Порты:
//   - TLS-порт для панели — NodeAgentPort (9100) на всех интерфейсах: на него
//     панель стучится по умолчанию;
//   - петлевой API — 127.0.0.1:NodeLocalAPIPort (9102). Он нужен проверке
//     после обновления (/v1/info новой версии); хук ходит в агент через
//     unix-сокет и от него не зависит. На одном порту с 0.0.0.0:9100 Linux
//     его не откроет (address already in use), поэтому порт другой.
var (
	nodeTLSPort   = nodeapi.NodeAgentPort
	nodeLocalPort = config.NodeLocalAPIPort
)

// nodePlan — что мастер поставит в режиме node.
type nodePlan struct {
	key   nodeapi.NodeKey
	cfg   config.Config
	steps []step
	fp    string // отпечаток сертификата агента, известен после шага
	// reused — ключ не задан, токен и адрес панели взяты у прежней установки
	// узла (existingNodeKey).
	reused bool
	// port — фактический TLS-порт агента: при переустановке — прежний из
	// listen_tls, иначе NodeAgentPort.
	port int
}

// tlsPort — порт из listen_tls; не разобрать — порт по умолчанию.
func tlsPort(listen string) int {
	if _, ps, err := net.SplitHostPort(listen); err == nil {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 {
			return n
		}
	}
	return nodeTLSPort
}

// runNode — мастер в режиме node: ключ, проверки, итог, подтверждение,
// применение. До подтверждения изменяющих вызовов нет.
func (w *Wizard) runNode(a Answers) error {
	if err := w.preflight(a); err != nil {
		return err
	}
	if err := w.panelHere(); err != nil {
		return err
	}
	cfg, err := w.Host.LoadConfig()
	if err != nil {
		return fmt.Errorf("текущий конфиг: %w", err)
	}
	key, reused := w.existingNodeKey(cfg)
	if !reused {
		if key, err = w.nodeKey(); err != nil {
			return err
		}
	}
	listenTLS := cfg.Node.ListenTLS
	cfg, err = nodeConfig(cfg, key.PanelIP)
	if err != nil {
		return err
	}
	if reused {
		// Повторная установка подключённого узла: порт агента — прежний.
		cfg.Node.ListenTLS = listenTLS
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("прежний конфиг узла неверен: %w. Ничего не изменено", err)
		}
		w.printf("  Ключ узла не задан: узел уже подключён — беру прежние токен (%s) и адрес панели %s.\n", paths.SecretsFile(), key.PanelIP)
	}
	if err := w.nodePortsFree(); err != nil {
		return err
	}
	if a.Address == "" {
		if ip, err := ExternalIP(w.Host.Fetch); err == nil {
			a.Address = ip
		}
	}
	p := &nodePlan{key: key, cfg: cfg, reused: reused, port: tlsPort(cfg.Node.ListenTLS)}
	w.nodeSteps(a, p)
	w.nodeSummary(a, p)
	if err := w.confirm(); err != nil {
		return err
	}
	if err := w.apply(p.steps); err != nil {
		return err
	}
	w.nodeReport(a, p)
	return nil
}

// existingNodeKey — «ключ» прежней установки узла для повторного azpanel
// install без ключа: install.env с MODE=node, NODE_TOKEN в secrets.env,
// listen_tls и ровно один адрес в allow_ips конфига. Чего-то нет или задан
// ключ (AZPANEL_NODE_KEY, AZPANEL_NODE_KEY_FILE — он заменяет прежний) —
// false, и ключ спрашивается как при первой установке.
func (w *Wizard) existingNodeKey(cfg config.Config) (nodeapi.NodeKey, bool) {
	if w.Getenv(nodeapi.NodeKeyEnv) != "" || w.Getenv(nodeapi.NodeKeyFileEnv) != "" {
		return nodeapi.NodeKey{}, false
	}
	data, err := w.Host.ReadFile(filepath.Join(paths.Etc(), "install.env"))
	if err != nil {
		return nodeapi.NodeKey{}, false
	}
	if kv, err := ParseEnvFile(data); err != nil || kv[KeyMode] != ModeNode {
		return nodeapi.NodeKey{}, false
	}
	if cfg.Node.ListenTLS == "" || len(cfg.Node.AllowIPs) != 1 {
		return nodeapi.NodeKey{}, false
	}
	data, err = w.Host.ReadFile(paths.SecretsFile())
	if err != nil {
		return nodeapi.NodeKey{}, false
	}
	sec, err := secrets.Parse(data)
	if err != nil {
		return nodeapi.NodeKey{}, false
	}
	k := nodeapi.NodeKey{PanelIP: cfg.Node.AllowIPs[0], Token: sec[secrets.NodeToken]}
	if _, err := k.Encode(); err != nil { // проверка адреса и токена
		return nodeapi.NodeKey{}, false
	}
	return k, true
}

// panelHere: на сервере уже стоит панель (install.env с MODE=panel+node или
// юнит azpanel-panel) — отказ до изменений. Режим node переписал бы конфиг и
// токен агента под чужую панель, и своя панель потеряла бы свой узел.
func (w *Wizard) panelHere() error {
	const msg = "На этом сервере стоит панель; узел для другой панели ставится на отдельный сервер. Ничего не изменено"
	if data, err := w.Host.ReadFile(filepath.Join(paths.Etc(), "install.env")); err == nil {
		if kv, err := ParseEnvFile(data); err == nil && kv[KeyMode] == ModePanelNode {
			return errors.New(msg)
		}
	}
	// ReadFile, а не Stat: юнит — обычный файл, а его чтение подменяется в
	// тестах по имени.
	if _, err := w.Host.ReadFile(filepath.Join(w.unitDirNote(), panelUnitName)); err == nil {
		return errors.New(msg)
	}
	return nil
}

// nodeKey — ключ узла из AZPANEL_NODE_KEY или AZPANEL_NODE_KEY_FILE; нет или
// неверен — вопрос (с терминалом) или ошибка до изменений (без него).
func (w *Wizard) nodeKey() (nodeapi.NodeKey, error) {
	k, err := nodeapi.ReadNodeKey("", w.Getenv, nil)
	if err == nil {
		return k, nil
	}
	given := w.Getenv(nodeapi.NodeKeyEnv) != "" || w.Getenv(nodeapi.NodeKeyFileEnv) != ""
	if !w.Interactive {
		if given {
			return k, fmt.Errorf("ключ узла: %w. Ничего не изменено", err)
		}
		return k, errors.New("нужен ключ узла (из панели: Узлы → Добавить): задайте " + nodeapi.NodeKeyEnv + " или " + nodeapi.NodeKeyFileEnv + ". Ничего не изменено")
	}
	if given {
		w.printf("  %v\n", err)
	}
	for {
		v, err := w.secret("Ключ узла (из панели: Узлы → Добавить)")
		if err != nil {
			return k, err
		}
		if v == "" {
			continue
		}
		if k, err = nodeapi.ParseNodeKey(v); err == nil {
			return k, nil
		}
		w.printf("  %v\n", err)
	}
}

// nodeConfig включает TLS-порт для панели с белым списком из одного её
// адреса и уводит петлевой API с порта 9100 (вместе с адресом агента для
// панели на этом же сервере, если она там когда-нибудь появится).
func nodeConfig(cfg config.Config, panelIP string) (config.Config, error) {
	ip, err := netip.ParseAddr(panelIP)
	if err != nil {
		return cfg, fmt.Errorf("в ключе узла неверный адрес панели %q", panelIP)
	}
	ip = ip.Unmap()
	wildcard := "0.0.0.0"
	if ip.Is6() {
		wildcard = "::"
	}
	n := &cfg.Node
	n.ListenTLS = net.JoinHostPort(wildcard, strconv.Itoa(nodeTLSPort))
	n.AllowIPs = []string{ip.String()}
	if ap, err := netip.ParseAddrPort(n.APIListen); err == nil && int(ap.Port()) == nodeTLSPort {
		old := n.APIListen
		n.APIListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(nodeLocalPort))
		if cfg.Panel.NodeURL == "http://"+old {
			cfg.Panel.NodeURL = "http://" + n.APIListen
		}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("конфиг по ключу узла неверен: %w", err)
	}
	return cfg, nil
}

// nodePortsFree: порты агента заняты не им — отказ до изменений. Занят
// прежним агентом (юнит уже стоит) — не помеха: шаг запуска его перезапустит.
func (w *Wizard) nodePortsFree() error {
	if _, err := w.Host.Stat(filepath.Join(w.unitDirNote(), nodeUnitName)); err == nil {
		return nil
	}
	for _, port := range []int{nodeTLSPort, nodeLocalPort} {
		if w.Host.PortBusy(port) {
			return fmt.Errorf("порт %d занят другой программой: агенту узла нужны TCP %d и %d. Ничего не изменено", port, nodeTLSPort, nodeLocalPort)
		}
	}
	return nil
}

func (w *Wizard) nodeSteps(a Answers, p *nodePlan) {
	h := w.Host
	add := func(name string, do func() error) { p.steps = append(p.steps, step{name, do}) }
	add("каталоги", h.MkLayout)
	add("бинарник", h.CopyBinary)
	add("конфиг", func() error { return h.WriteConfig(p.cfg) })
	// Токен из ключа заменяет прежний: панель знает именно его.
	add("секреты", func() error { return h.WriteSecrets(map[string]string{secrets.NodeToken: p.key.Token}) })
	add("сертификат агента", func() error {
		fp, err := h.AgentCert()
		p.fp = fp
		return err
	})
	add("юнит", func() error { return h.WriteUnit(nodeUnitName, NodeUnit(paths.Binary())) })
	add("хук лимита", h.InstallHook)
	add("ответы (install.env)", func() error {
		return h.WriteInstallEnv(secrets.Marshal(map[string]string{KeyMode: ModeNode}))
	})
	add("запуск", func() error {
		for _, args := range [][]string{{"daemon-reload"}, {"enable", "azpanel-node"}, {"restart", "azpanel-node"}} {
			if err := h.Systemctl(args...); err != nil {
				return err
			}
		}
		if err := h.WaitAgent(); err != nil {
			return fmt.Errorf("агент не ответил: %w; журнал — %s", err, filepath.Join(paths.Log(), "node.log"))
		}
		return nil
	})
	if a.Firewall {
		add("файрвол", func() error { return h.OpenFirewall(p.port) })
	}
}

func (w *Wizard) nodeSummary(a Answers, p *nodePlan) {
	n := p.cfg.Node
	w.printf("\nИтог\n")
	w.printf("  тип установки: %s\n", modeTitle(ModeNode))
	w.printf("  azpanel в %s\n", paths.Root())
	w.printf("  служба azpanel-node (%s), хук лимита в %s\n", w.unitDirNote(), w.ScriptsDir)
	w.printf("  панель %s: TLS-порт агента %s, белый список — только %s\n", p.key.PanelIP, n.ListenTLS, p.key.PanelIP)
	if n.APIListen != "" {
		w.printf("  API агента на этом сервере: %s\n", n.APIListen)
	}
	if p.reused {
		w.printf("  токен API — прежний, из %s\n", paths.SecretsFile())
	} else {
		w.printf("  токен API из ключа узла — в %s (прежний заменяется)\n", paths.SecretsFile())
	}
	w.printf("  сертификат агента — %s (создаётся, если его нет)\n", filepath.Join(paths.Etc(), "tls", agenttls.CertFile))
	if a.Firewall {
		w.printf("  правило iptables для TCP %d\n", p.port)
	}
	w.printf("\n")
}

func (w *Wizard) nodeReport(a Answers, p *nodePlan) {
	w.printf("\nГотово. Агент узла ждёт панель %s.\n", p.key.PanelIP)
	w.printf("  Отпечаток сертификата агента (SHA-256): %s\n", agenttls.FormatFingerprint(p.fp))
	addr := "<IP этого сервера>"
	if a.Address != "" {
		addr = bracketHost(a.Address)
	}
	w.printf("  В панели: Узлы → этот узел → адрес %s:%d → «Подключить», сверьте отпечаток.\n", addr, p.port)
	w.printf("Откройте TCP %d для %s: по нему панель обращается к агенту.\n", p.port, p.key.PanelIP)
	w.printf("Проверка установки: azpanel doctor\n")
}
