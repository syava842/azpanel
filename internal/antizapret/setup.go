package antizapret

import (
	"os"
	"strings"
)

// ReadSetup читает /root/antizapret/setup — строки KEY=VALUE, как их пишет
// setup.sh AntiZapret. Кавычки вокруг значения снимаются. Файл только
// читается: меняет его родной setup.sh.
func ReadSetup(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(k, " \t") {
			continue
		}
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, nil
}
