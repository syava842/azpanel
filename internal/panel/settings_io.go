package panel

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/syava842/azpanel/internal/config"
	"github.com/syava842/azpanel/internal/secrets"
)

const (
	maxImport  = 1 << 20 // предел файла импорта и тела формы
	tarCfgName = "config.toml"
	tarSecName = "secrets.env"
)

func (s *Server) exportPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "settings_export", nil)
}

// exportDownload отдаёт config.toml; с флажком — tar из config.toml и
// secrets.env. Секреты уходят только по явному выбору и только POST-ом.
func (s *Server) exportDownload(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	cfgBytes, err := config.Marshal(cfg)
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "настройки не закодированы: "+err.Error())
		return
	}
	withSecrets := r.PostForm.Get("with_secrets") == "1"
	h := w.Header()
	if !withSecrets {
		h.Set("Content-Type", "application/toml; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="config.toml"`)
		s.audit(r, "settings_export", "config.toml", "", "без секретов")
		w.Write(cfgBytes)
		return
	}
	sec, err := secrets.Load(s.secretsPath())
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "secrets.env не прочитан: "+err.Error())
		return
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{{tarCfgName, cfgBytes}, {tarSecName, secrets.Marshal(sec)}} {
		err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.data)), ModTime: s.now()})
		if err == nil {
			_, err = tw.Write(f.data)
		}
		if err != nil {
			s.errorPage(w, r, http.StatusInternalServerError, "архив не собран")
			return
		}
	}
	if err := tw.Close(); err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "архив не собран")
		return
	}
	h.Set("Content-Type", "application/x-tar")
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="azpanel-settings-%s.tar"`, s.now().UTC().Format("2006-01-02")))
	s.audit(r, "settings_export", "config.toml+secrets.env", "", "с секретами")
	w.Write(buf.Bytes())
}

// parseImport разбирает загруженный файл: tar из экспорта либо голый
// config.toml. Секреты возвращаются только если они есть в архиве.
func parseImport(data []byte) (cfg config.Config, sec map[string]string, err error) {
	cfgData := data
	if len(data) >= 262 && string(data[257:262]) == "ustar" {
		files := map[string][]byte{}
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return cfg, nil, fmt.Errorf("архив не читается: %w", err)
			}
			if h.Name == tarCfgName || h.Name == tarSecName {
				b, err := io.ReadAll(io.LimitReader(tr, maxImport))
				if err != nil {
					return cfg, nil, fmt.Errorf("архив не читается: %w", err)
				}
				files[h.Name] = b
			}
		}
		if files[tarCfgName] == nil {
			return cfg, nil, errors.New("в архиве нет config.toml")
		}
		cfgData = files[tarCfgName]
		if b := files[tarSecName]; b != nil {
			if sec, err = secrets.Parse(b); err != nil {
				return cfg, nil, fmt.Errorf("secrets.env в архиве: %w", err)
			}
		}
	}
	cfg, err = config.Parse(cfgData)
	return cfg, sec, err
}

// settingsImport принимает файл, проверяет его и показывает «было → стало»;
// применяется только после подтверждения. Секреты берутся только с флажком.
func (s *Server) settingsImport(w http.ResponseWriter, r *http.Request) {
	s.initAccess()
	cur, err := s.loadConfig()
	if err != nil {
		s.errorPage(w, r, http.StatusServiceUnavailable, "настройки недоступны: "+err.Error())
		return
	}
	fail := func(text string) {
		s.render(w, r, http.StatusBadRequest, "settings_export", map[string]any{"Error": text})
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		fail("Выберите файл config.toml или архив из экспорта.")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxImport+1))
	if err == nil && len(bytes.TrimSpace(data)) == 0 {
		fail("Файл пуст.")
		return
	}
	if err != nil || len(data) > maxImport {
		fail("Файл не читается или больше 1 МБ.")
		return
	}
	cfg, sec, err := parseImport(data)
	if err != nil {
		fail("Файл не принят, ничего не изменено: " + err.Error())
		return
	}
	d := &settingsDraft{source: "импорт файла", old: cur, cfg: cfg}
	if r.PostForm.Get("with_secrets") == "1" && len(sec) > 0 {
		d.secrets = sec
	}
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	if cur, err = s.loadConfig(); err == nil {
		d.old = cur
	}
	s.previewDraft(w, r, d, cur)
}
