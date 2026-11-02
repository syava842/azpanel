package config

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Apply — как изменение поля вступает в силу.
type Apply string

const (
	ApplyNow          Apply = "now"           // сразу, без перезапуска
	ApplyRestartPanel Apply = "restart_panel" // после перезапуска панели
	ApplyRestartNode  Apply = "restart_node"  // после перезапуска агента узла
	ApplyForeign      Apply = "foreign"       // читает другой сервис: его перезапускают вручную
	ApplyDangerous    Apply = "dangerous"     // может отрезать доступ: перезапуск панели и 2 минуты на подтверждение
)

// Kind — вид поля в форме.
type Kind string

const (
	KindString   Kind = "string"
	KindInt      Kind = "int"
	KindBool     Kind = "bool"
	KindChoice   Kind = "choice"   // одно из Choices
	KindList     Kind = "list"     // список строк, по одной в строке
	KindIntList  Kind = "intlist"  // список целых, по одному в строке
	KindMulti    Kind = "multi"    // подмножество Choices (флажки)
	KindReadonly Kind = "readonly" // служебное, в форме не редактируется
)

// Field — описание одного поля Config для страницы настроек. Таблица Fields
// сверяется с типом Config рефлексией (TestMetaCoversConfig): поле без
// описания роняет тест.
type Field struct {
	Path    string // путь в config.toml: «panel.listen»
	Section string // раздел формы: node, panel, log, telegram, proxy
	Title   string
	Hint    string
	Kind    Kind
	Apply   Apply
	Choices []string
	// Page — если поле редактируется на отдельной странице панели, форма
	// настроек даёт ссылку на неё вместо поля ввода.
	Page string
}

// Section — раздел формы настроек.
type Section struct{ Key, Title string }

// Sections — разделы в порядке показа.
var Sections = []Section{
	{"node", "Агент узла"},
	{"panel", "Панель"},
	{"log", "Журнал службы"},
	{"telegram", "Telegram-бот"},
	{"proxy", "Прокси-агент"},
}

// Fields — описания всех полей Config.
func Fields() []Field { return slices.Clone(fields) }

// FieldByPath — описание поля по пути.
func FieldByPath(path string) (Field, bool) {
	for _, f := range fields {
		if f.Path == path {
			return f, true
		}
	}
	return Field{}, false
}

var fields = []Field{
	{Path: "config_version", Title: "Версия структуры", Hint: "Служебное поле; меняется миграцией.", Kind: KindReadonly, Apply: ApplyNow},

	{Path: "node.openvpn_socket_dir", Section: "node", Title: "Каталог сокетов OpenVPN", Hint: "Где OpenVPN держит управляющие сокеты.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.openvpn_scripts_dir", Section: "node", Title: "Каталог скриптов OpenVPN", Hint: "Сюда агент ставит хук учёта сессий.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.poll_seconds", Section: "node", Title: "Опрос OpenVPN, секунд", Hint: "От 1 до 60.", Kind: KindInt, Apply: ApplyRestartNode},
	{Path: "node.query_timeout_ms", Section: "node", Title: "Таймаут запроса к OpenVPN, мс", Hint: "От 100 до 5000.", Kind: KindInt, Apply: ApplyRestartNode},
	{Path: "node.api_listen", Section: "node", Title: "Адрес API агента", Hint: "Только петлевой интерфейс: 127.0.0.1:порт или [::1]:порт; пусто — API выключен. Вместе с ним поменяйте адрес агента в настройках панели.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.listen_tls", Section: "node", Title: "Внешний порт агента (TLS)", Hint: "адрес:порт, например 0.0.0.0:9100; пусто — выключен. Сертификат самоподписанный (etc/tls), панель закрепляет его отпечаток. Нужен белый список ниже.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.allow_ips", Section: "node", Title: "Белый список панелей для внешнего порта", Hint: "IP или сети, по одному в строке; чужие адреса закрываются до TLS. Обязателен при внешнем порте.", Kind: KindList, Apply: ApplyRestartNode},
	{Path: "node.amneziawg_dir", Section: "node", Title: "Каталог AmneziaWG", Hint: "Серверные конфиги AmneziaWG для набора синхронизации; пусто или нет каталога — пропускается.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.knot_resolver_dir", Section: "node", Title: "Каталог Knot Resolver", Hint: "Откуда берутся custom*.lua для набора синхронизации.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.antizapret_dir", Section: "node", Title: "Каталог AntiZapret", Hint: "Корень установки AntiZapret-VPN.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.easyrsa_pki", Section: "node", Title: "Каталог PKI EasyRSA", Hint: "Каталог pki с сертификатами клиентов.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.wireguard_dir", Section: "node", Title: "Каталог WireGuard", Hint: "Каталог с конфигами интерфейсов.", Kind: KindString, Apply: ApplyRestartNode},
	{Path: "node.client_sh_timeout_seconds", Section: "node", Title: "Таймаут client.sh, секунд", Hint: "От 10 до 600.", Kind: KindInt, Apply: ApplyRestartNode},

	{Path: "panel.listen", Section: "panel", Title: "Адрес панели", Hint: "Только петлевой интерфейс: наружу панель выходит через nginx. Фрагмент nginx (proxy_pass) обновляется при применении; если панель не смогла его записать, поправьте его вручную, пока идёт таймер возврата.", Kind: KindString, Apply: ApplyDangerous},
	{Path: "panel.node_url", Section: "panel", Title: "Адрес агента", Hint: "http://127.0.0.1:9100 или https://…", Kind: KindString, Apply: ApplyRestartPanel},
	{Path: "panel.collect_seconds", Section: "panel", Title: "Сбор статистики, секунд", Hint: "От 10 до 600.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "panel.history_days", Section: "panel", Title: "Хранить историю, дней", Hint: "От 1 до 365.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "panel.session_hours", Section: "panel", Title: "Жизнь сессии, часов", Hint: "От 1 до 720.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "panel.require_admin_2fa", Section: "panel", Title: "Требовать 2FA у администраторов", Hint: "Администратор без двухфакторной проверки обязан включить её после входа.", Kind: KindBool, Apply: ApplyRestartPanel},
	{Path: "panel.allow_ips", Section: "panel", Title: "Белый список адресов", Hint: "IP или сети; пусто — без ограничения. Меняется на отдельной странице с таймером возврата.", Kind: KindList, Apply: ApplyDangerous, Page: "/settings/access"},
	{Path: "panel.public_url", Section: "panel", Title: "Внешний адрес панели", Hint: "https://vpn.example.org; префикс пути добавляется сам. Пусто — ссылки портала относительные.", Kind: KindString, Apply: ApplyRestartPanel},
	{Path: "panel.base_path", Section: "panel", Title: "Префикс пути", Hint: "Пусто или /azpanel/ (с косой чертой в начале и в конце). Фрагмент nginx (location) обновляется при применении; если панель не смогла его записать, поправьте его вручную, пока идёт таймер возврата — иначе панель перестанет открываться.", Kind: KindString, Apply: ApplyDangerous},
	{Path: "panel.trusted_proxies", Section: "panel", Title: "Доверенные прокси", Hint: "Адреса или сети, чьим X-Forwarded-For панель верит, по одному в строке. Лишний адрес даст подделывать адрес клиента, неверный — покажет везде адрес прокси. Осторожно с 127.0.0.1: заголовку верят и от любого локального HTTP- или SOCKS-прокси на этом хосте.", Kind: KindList, Apply: ApplyDangerous},
	{Path: "panel.experimental", Section: "panel", Title: "Отложенные возможности", Hint: "Узлы, группы синхронизации, Telegram-бот и самообновление azpanel. Выключено: страницы скрыты, бот и проверка обновлений не запускаются.", Kind: KindBool, Apply: ApplyRestartPanel},

	{Path: "log.max_size_mb", Section: "log", Title: "Размер файла журнала, МБ", Hint: "От 1 до 1000.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "log.keep", Section: "log", Title: "Хранить файлов журнала", Hint: "От 1 до 100.", Kind: KindInt, Apply: ApplyRestartPanel},

	{Path: "telegram.enabled", Section: "telegram", Title: "Бот включён", Hint: "Нужен TELEGRAM_BOT_TOKEN в секретах.", Kind: KindBool, Apply: ApplyRestartPanel},
	{Path: "telegram.strangers", Section: "telegram", Title: "Незнакомые", Hint: "closed — молчать, request — принимать заявки на привязку.", Kind: KindChoice, Apply: ApplyRestartPanel, Choices: []string{"closed", "request"}},
	{Path: "telegram.notify_chats", Section: "telegram", Title: "Чаты уведомлений", Hint: "Числовые ID чатов, по одному в строке.", Kind: KindIntList, Apply: ApplyRestartPanel},
	{Path: "telegram.notify", Section: "telegram", Title: "Виды уведомлений", Hint: "Что присылать в чаты уведомлений: node_down, load_high, reboot, sync_mismatch, hook_error, limit_denials, antizapret_update (новые коммиты AntiZapret), update_result (итог обновления), cert_expiring, access_expiring, azpanel_update (вышла новая версия azpanel).", Kind: KindMulti, Apply: ApplyRestartPanel, Choices: TelegramNotifyKinds},
	{Path: "telegram.cpu_percent", Section: "telegram", Title: "Порог CPU, %", Hint: "От 1 до 100.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "telegram.mem_percent", Section: "telegram", Title: "Порог памяти, %", Hint: "От 1 до 100.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "telegram.disk_percent", Section: "telegram", Title: "Порог диска, %", Hint: "От 1 до 100.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "telegram.load_minutes", Section: "telegram", Title: "Держится минут", Hint: "Сколько минут нагрузка выше порога до уведомления; от 1 до 1440.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "telegram.summary_at", Section: "telegram", Title: "Сводка в", Hint: "ЧЧ:ММ по UTC; пусто — без сводки.", Kind: KindString, Apply: ApplyRestartPanel},
	{Path: "telegram.backup_every_days", Section: "telegram", Title: "Бэкап в чат, дней", Hint: "0 — выключено; до 365.", Kind: KindInt, Apply: ApplyRestartPanel},
	{Path: "telegram.backup_chats", Section: "telegram", Title: "Чаты для бэкапа", Hint: "Числовые ID чатов, по одному в строке.", Kind: KindIntList, Apply: ApplyRestartPanel},

	{Path: "proxy.listen", Section: "proxy", Title: "Адрес прокси-агента", Hint: "Читает отдельный сервис azpanel-proxy на VPS с proxy.sh: после сохранения перезапустите его там.", Kind: KindString, Apply: ApplyForeign},
	{Path: "proxy.listen_tls", Section: "proxy", Title: "Внешний порт прокси-агента (TLS)", Hint: "адрес:порт, например 0.0.0.0:9101; пусто — выключен. Нужен белый список ниже.", Kind: KindString, Apply: ApplyForeign},
	{Path: "proxy.allow_ips", Section: "proxy", Title: "Белый список панелей для внешнего порта", Hint: "IP или сети, по одному в строке; обязателен при внешнем порте.", Kind: KindList, Apply: ApplyForeign},
}

// leaf возвращает значение поля Config по пути из тегов toml.
func leaf(c *Config, path string) (reflect.Value, error) {
	v := reflect.ValueOf(c).Elem()
	for _, part := range strings.Split(path, ".") {
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, fmt.Errorf("нет поля %s", path)
		}
		t := v.Type()
		found := false
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).Tag.Get("toml") == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return reflect.Value{}, fmt.Errorf("нет поля %s", path)
		}
	}
	return v, nil
}

// Get — значение поля в виде текста для формы: списки — по элементу в строке.
func Get(c Config, path string) string {
	v, err := leaf(&c, path)
	if err != nil {
		return ""
	}
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Slice:
		var out []string
		for i := 0; i < v.Len(); i++ {
			out = append(out, fmt.Sprint(v.Index(i).Interface()))
		}
		return strings.Join(out, "\n")
	}
	return ""
}

// SplitList — записи списка через перевод строки, запятую, точку с запятой
// или пробел.
func SplitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
}

// Set разбирает текст формы и кладёт значение в поле. Неверный вид
// (не число, не булево) — ошибка с путём поля; диапазоны проверяет Validate.
func Set(c *Config, path, text string) error {
	f, ok := FieldByPath(path)
	if !ok {
		return fmt.Errorf("неизвестное поле %s", path)
	}
	v, err := leaf(c, path)
	if err != nil {
		return err
	}
	text = strings.TrimSpace(text)
	switch v.Kind() {
	case reflect.String:
		v.SetString(text)
	case reflect.Int:
		n, err := strconv.Atoi(text)
		if err != nil {
			return fmt.Errorf("%s: «%s» — не целое число", f.Path, text)
		}
		v.SetInt(int64(n))
	case reflect.Bool:
		switch strings.ToLower(text) {
		case "true", "on", "1":
			v.SetBool(true)
		case "false", "off", "0", "":
			v.SetBool(false)
		default:
			return fmt.Errorf("%s: «%s» — не булево значение", f.Path, text)
		}
	case reflect.Slice:
		items := SplitList(text)
		switch v.Type().Elem().Kind() {
		case reflect.String:
			out := make([]string, 0, len(items))
			out = append(out, items...)
			v.Set(reflect.ValueOf(out))
		case reflect.Int64:
			out := make([]int64, 0, len(items))
			for _, it := range items {
				n, err := strconv.ParseInt(it, 10, 64)
				if err != nil {
					return fmt.Errorf("%s: «%s» — не число", f.Path, it)
				}
				out = append(out, n)
			}
			v.Set(reflect.ValueOf(out))
		default:
			return fmt.Errorf("%s: неподдерживаемый вид списка", f.Path)
		}
	default:
		return fmt.Errorf("%s: неподдерживаемый вид поля", f.Path)
	}
	return nil
}

// ErrorField находит поле, о котором говорит ошибка Validate или Set
// (в тексте — путь вида «panel.base_path»).
func ErrorField(err error) (Field, bool) {
	if err == nil {
		return Field{}, false
	}
	msg := err.Error()
	var best Field
	for _, f := range fields {
		if strings.Contains(msg, f.Path) && len(f.Path) > len(best.Path) {
			best = f
		}
	}
	return best, best.Path != ""
}

// Change — изменённое поле.
type Change struct {
	Field    Field
	Old, New string
}

// Diff — поля, чьи значения различаются; значения — текст формы.
func Diff(old, new Config) []Change {
	var out []Change
	for _, f := range fields {
		if f.Kind == KindReadonly {
			continue
		}
		a, b := Get(old, f.Path), Get(new, f.Path)
		if a != b {
			out = append(out, Change{Field: f, Old: a, New: b})
		}
	}
	return out
}
