package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientSendsTokenAndEscapesPath(t *testing.T) {
	mux := http.NewServeMux()
	var gotAuth, gotFile string
	mux.HandleFunc("GET /v1/clients/{name}/profiles/{kind}/{variant}/{file}", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotFile = r.PathValue("file")
		w.Write([]byte("PROFILE"))
	})
	mux.HandleFunc("POST /v1/clients", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorBody{Error: "клиент OpenVPN с таким именем уже есть"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL+"/", "TOKEN")
	data, err := c.Profile(context.Background(), "alice", Profile{Kind: "openvpn", Variant: "antizapret-udp", File: "antizapret-alice-(1.2.3.4)-udp.ovpn"})
	if err != nil || string(data) != "PROFILE" {
		t.Fatalf("data %q, err %v", data, err)
	}
	if gotAuth != "Bearer TOKEN" || gotFile != "antizapret-alice-(1.2.3.4)-udp.ovpn" {
		t.Fatalf("auth %q, file %q", gotAuth, gotFile)
	}

	_, err = c.CreateClient(context.Background(), CreateClient{Name: "alice", Kind: KindOpenVPN})
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict || e.Message != "клиент OpenVPN с таким именем уже есть" {
		t.Fatalf("err = %v", err)
	}
}

func TestClientAZUpdateRoutes(t *testing.T) {
	mux := http.NewServeMux()
	var gotUpdate AZUpdateRequest
	var gotRestore AZRestoreRequest
	mux.HandleFunc("GET /v1/antizapret/version", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AZVersion{Current: "abc", Behind: []AZCommit{{SHA: "def", Message: "Update parse.sh"}}})
	})
	mux.HandleFunc("GET /v1/antizapret/update/preflight", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AZPreflight{OK: false, Reasons: []string{"мало места"}})
	})
	mux.HandleFunc("POST /v1/antizapret/update", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotUpdate)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(AZUpdateState{Action: AZActionUpdate, Status: AZStatusRunning, Phase: AZPhasePrepare})
	})
	mux.HandleFunc("POST /v1/antizapret/restore", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotRestore)
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(ErrorBody{Error: "нет такого бэкапа"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New(srv.URL, "T")
	ctx := context.Background()

	v, err := c.AZVersion(ctx)
	if err != nil || v.Current != "abc" || len(v.Behind) != 1 {
		t.Fatalf("version: %+v %v", v, err)
	}
	p, err := c.AZPreflight(ctx)
	if err != nil || p.OK || p.Reasons[0] != "мало места" {
		t.Fatalf("preflight: %+v %v", p, err)
	}
	st, err := c.AZUpdate(ctx, AZUpdateRequest{Commit: "def", Values: map[string]string{"MTU": "1400"}})
	if err != nil || st.Status != AZStatusRunning || gotUpdate.Commit != "def" || gotUpdate.Values["MTU"] != "1400" {
		t.Fatalf("update: %+v %v / %+v", st, err, gotUpdate)
	}
	_, err = c.AZRestore(ctx, "backup-azpanel-x.tar.gz")
	var e *Error
	if !errors.As(err, &e) || e.Status != 422 || gotRestore.Backup != "backup-azpanel-x.tar.gz" {
		t.Fatalf("restore: %v / %+v", err, gotRestore)
	}
}
