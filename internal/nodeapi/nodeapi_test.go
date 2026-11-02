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
