package main

import (
	"context"
	"fmt"
	"io"

	"github.com/syava842/azpanel/internal/install"
	"github.com/syava842/azpanel/internal/nodeapi"
)

func init() {
	// nginx-snippet --params ФАЙЛ: фрагмент панели под новые base_path и адрес.
	// UpdateSnippet сам делает копию в backup/nginx, nginx -t, откат и reload.
	internalModes["nginx-snippet"] = func(ctx context.Context, args []string, out io.Writer) error {
		var p nodeapi.NginxSnippetRequest
		if err := readParams(args, &p); err != nil {
			return err
		}
		if err := install.ValidateSnippetArgs(p.BasePath, p.Upstream); err != nil {
			return err
		}
		done, err := install.NewNginx().UpdateSnippet(p.BasePath, p.Upstream)
		if err != nil {
			return err
		}
		if !done {
			fmt.Fprintln(out, "фрагмент панели в nginx не установлен: nginx не менялся")
			return nil
		}
		fmt.Fprintln(out, "фрагмент nginx обновлён, nginx -t прошёл, nginx перезагружен")
		return nil
	}
}
