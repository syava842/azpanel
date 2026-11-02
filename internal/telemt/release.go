package telemt

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://api.github.com"
	releasePath    = "/repos/telemt/telemt/releases/latest"
	maxArchive     = 100 << 20 // архив релиза ~6 МБ; больше — что-то не то
	maxBinary      = 200 << 20
)

// Asset — файл релиза.
type Asset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"` // «sha256:…», GitHub выставляет не всегда
	URL    string `json:"browser_download_url"`
}

// Release — релиз telemt на GitHub.
type Release struct {
	Tag        string  `json:"tag_name"`
	Name       string  `json:"name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	HTMLURL    string  `json:"html_url"`
	Assets     []Asset `json:"assets"`
}

// Version — номер версии из тега («3.5.16», «v3.5.16» → «3.5.16»).
func (r Release) Version() string {
	return versionRe.FindString(r.Tag)
}

func (r Release) asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

func (e *Env) httpClient() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

// LatestRelease — последний релиз telemt (публичный API GitHub без токена).
func (e *Env) LatestRelease(ctx context.Context) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, orStr(e.APIBase, defaultAPIBase)+releasePath, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("запрос релиза telemt: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return Release{}, fmt.Errorf("ответ GitHub не разобран: %w", err)
	}
	if rel.Draft || rel.Prerelease || rel.Version() == "" {
		return Release{}, errors.New("последний релиз telemt не годится для установки (черновик, предрелиз или без номера)")
	}
	return rel, nil
}

// AssetName — имя архива релиза: telemt-<arch>-linux-<libc>.tar.gz.
func AssetName(arch, libc string) string {
	return "telemt-" + arch + "-linux-" + libc + ".tar.gz"
}

func (e *Env) assetName() (string, error) {
	arch := e.Arch
	if arch == "" {
		switch runtime.GOARCH {
		case "amd64":
			arch = "x86_64"
		case "arm64":
			arch = "aarch64"
		default:
			return "", fmt.Errorf("неподдерживаемая архитектура: %s", runtime.GOARCH)
		}
	}
	return AssetName(arch, orStr(e.Libc, "gnu")), nil
}

// CompareVersions сравнивает номера x.y.z: -1, 0, 1.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(versionRe.FindString(a), "."), strings.Split(versionRe.FindString(b), ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func (e *Env) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: файл больше %d МБ", url, limit>>20)
	}
	return data, nil
}

// wantSum — ожидаемая сумма архива: из файла .sha256 («<hex>  <имя>»), иначе
// из digest релиза. Ни того ни другого — отказ: ставить бинарник без проверки
// нельзя (установщик в такой ситуации лишь предупреждает; здесь строже).
func (e *Env) wantSum(ctx context.Context, rel Release, asset Asset) (string, error) {
	if sa, ok := rel.asset(asset.Name + ".sha256"); ok {
		data, err := e.get(ctx, sa.URL, 4<<10)
		if err == nil {
			if f := strings.Fields(string(data)); len(f) > 0 && len(f[0]) == 64 {
				return strings.ToLower(f[0]), nil
			}
			return "", errors.New("файл .sha256 неожиданного вида")
		}
		e.logf("файл .sha256 не скачан (%v), пробую digest релиза", err)
	}
	if h, ok := strings.CutPrefix(asset.Digest, "sha256:"); ok && len(h) == 64 {
		return strings.ToLower(h), nil
	}
	return "", errors.New("у релиза нет ни .sha256, ни digest — проверить контрольную сумму нечем, установка отменена")
}

// fetchBinary скачивает архив релиза, сверяет сумму и кладёт распакованный
// бинарник в dst (0755). Существующий dst не трогается до успешной проверки.
func (e *Env) fetchBinary(ctx context.Context, rel Release, dst string) error {
	name, err := e.assetName()
	if err != nil {
		return err
	}
	asset, ok := rel.asset(name)
	if !ok {
		return fmt.Errorf("в релизе %s нет архива %s", rel.Tag, name)
	}
	want, err := e.wantSum(ctx, rel, asset)
	if err != nil {
		return err
	}
	e.logf("качаю %s", asset.URL)
	data, err := e.get(ctx, asset.URL, maxArchive)
	if err != nil {
		return fmt.Errorf("архив не скачан: %w", err)
	}
	sum := sha256.Sum256(data)
	if have := hex.EncodeToString(sum[:]); have != want {
		return fmt.Errorf("контрольная сумма не сошлась: ждали %s, получили %s", want, have)
	}
	e.logf("контрольная сумма сошлась")
	bin, err := extractBinary(data)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, bin, 0o755)
}

// extractBinary достаёт файл telemt из tar.gz.
func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("архив не распаковался: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("в архиве нет файла telemt")
		}
		if err != nil {
			return nil, fmt.Errorf("архив повреждён: %w", err)
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != "telemt" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxBinary+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBinary {
			return nil, errors.New("бинарник в архиве слишком велик")
		}
		return data, nil
	}
}
