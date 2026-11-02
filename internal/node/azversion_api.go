package node

import (
	"net/http"

	"github.com/syava842/azpanel/internal/antizapret"
	"github.com/syava842/azpanel/internal/nodeapi"
)

func (a *API) azVersion(w http.ResponseWriter, r *http.Request) {
	if a.AZVersion == nil {
		writeErr(w, http.StatusServiceUnavailable, "версия AntiZapret не настроена")
		return
	}
	v := a.AZVersion.Get(r.Context())
	out := nodeapi.AZVersion{
		Current: v.Current, CurrentSource: v.CurrentSource, UpToDate: v.UpToDate,
		Truncated: v.Truncated, Message: v.Message, Error: v.Error,
		Behind: make([]nodeapi.AZCommit, 0, len(v.Behind)),
	}
	if v.Latest != nil {
		c := azCommit(*v.Latest)
		out.Latest = &c
	}
	for _, c := range v.Behind {
		out.Behind = append(out.Behind, azCommit(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func azCommit(c antizapret.Commit) nodeapi.AZCommit {
	return nodeapi.AZCommit{SHA: c.SHA, Message: c.Message, Date: c.Date}
}
