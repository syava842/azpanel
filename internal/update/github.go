package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	// Repo — приватный репозиторий с релизами.
	Repo = "syava842/azpanel"
	// TokenKey — ключ токена GitHub (fine-grained, Contents: Read) в secrets.env.
	TokenKey = "GITHUB_TOKEN"
	// SumsName и SigName — файлы релиза: суммы архивов и подпись сумм.
	SumsName = "SHA256SUMS"
	SigName  = "SHA256SUMS.sig"

	defaultAPI  = "https://api.github.com"
	maxMeta     = 4 << 20  // ответ API
	maxArchive  = 64 << 20 // архив и любое вложение релиза
	maxSmallAss = 1 << 20  // SHA256SUMS и подпись
)

// ArchiveName — имя архива релиза: azpanel_<версия>_linux_<arch>.tar.gz.
func ArchiveName(version, arch string) string {
	return "azpanel_" + version + "_linux_" + arch + ".tar.gz"
}

// Asset — вложение релиза.
type Asset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Release — релиз GitHub.
type Release struct {
	Tag        string  `json:"tag_name"`
	Body       string  `json:"body"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// Version — версия без префикса «v».
func (r Release) Version() string { return strings.TrimPrefix(r.Tag, "v") }

// Asset ищет вложение по имени.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// Client — обращения к API GitHub с токеном. Токен не попадает ни в ошибки,
// ни в журналы: все тексты ошибок проходят через Redact.
type Client struct {
	BaseURL string // пусто — https://api.github.com
	Token   string
	HTTP    *http.Client
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultAPI
}

func (c *Client) httpc() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Redact убирает токен из текста.
func Redact(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}

func (c *Client) fail(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(Redact(err.Error(), c.Token))
}

func (c *Client) get(ctx context.Context, path, accept string, limit int64) ([]byte, error) {
	if c.Token == "" {
		return nil, errors.New("токен GitHub не задан")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+path, nil)
	if err != nil {
		return nil, c.fail(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.httpc().Do(req)
	if err != nil {
		return nil, c.fail(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("GitHub отказал (%d): токен неверен, просрочен или без права Contents: Read", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return nil, errors.New("GitHub: релиз или репозиторий не найден (проверьте токен)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub ответил %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, c.fail(err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("ответ GitHub больше %d байт", limit)
	}
	return body, nil
}

// Latest — последний опубликованный релиз.
func (c *Client) Latest(ctx context.Context) (Release, error) {
	body, err := c.get(ctx, "/repos/"+Repo+"/releases/latest", "application/vnd.github+json", maxMeta)
	if err != nil {
		return Release{}, err
	}
	var r Release
	if err := json.Unmarshal(body, &r); err != nil {
		return Release{}, errors.New("ответ GitHub не разобран")
	}
	if r.Tag == "" {
		return Release{}, errors.New("в ответе GitHub нет тега релиза")
	}
	return r, nil
}

// Download скачивает вложение через API (Accept: application/octet-stream).
func (c *Client) Download(ctx context.Context, a Asset) ([]byte, error) {
	limit := int64(maxArchive)
	if a.Name == SumsName || a.Name == SigName {
		limit = maxSmallAss
	}
	return c.get(ctx, "/repos/"+Repo+"/releases/assets/"+strconv.FormatInt(a.ID, 10), "application/octet-stream", limit)
}

// Fetched — скачанный и ещё не проверенный релиз.
type Fetched struct {
	Version string
	Name    string // имя архива
	Archive []byte
	Sums    []byte
	Sig     []byte
}

// Fetch скачивает архив своей архитектуры, SHA256SUMS и подпись.
func (c *Client) Fetch(ctx context.Context, r Release, arch string) (Fetched, error) {
	f := Fetched{Version: r.Version(), Name: ArchiveName(r.Version(), arch)}
	var err error
	for _, p := range []struct {
		name string
		dst  *[]byte
	}{{f.Name, &f.Archive}, {SumsName, &f.Sums}, {SigName, &f.Sig}} {
		a, ok := r.Asset(p.name)
		if !ok {
			return Fetched{}, fmt.Errorf("в релизе %s нет файла %s", r.Tag, p.name)
		}
		if *p.dst, err = c.Download(ctx, a); err != nil {
			return Fetched{}, err
		}
	}
	return f, nil
}

// ParseVersion разбирает «x.y.z» (префикс v допустим, суффикс -пре/+сборка
// отбрасывается). dev и мусор — ошибка.
func ParseVersion(s string) ([3]int, error) {
	var v [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("версия %q не вида x.y.z", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("версия %q не вида x.y.z", s)
		}
		v[i] = n
	}
	return v, nil
}

// Newer — b строго новее a. Непонятная версия — ошибка.
func Newer(a, b string) (bool, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return false, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return false, err
	}
	for i := range va {
		if vb[i] != va[i] {
			return vb[i] > va[i], nil
		}
	}
	return false, nil
}
