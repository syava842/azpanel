// Package agentproto — запрос и ответ между хуком и агентом через unix-сокет:
// одна строка JSON в каждую сторону.
package agentproto

import (
	"encoding/json"
	"net"
	"time"
)

const (
	OpConnect    = "connect"
	OpDisconnect = "disconnect"
	OpList       = "list"
)

type Request struct {
	Op       string `json:"op"`
	Instance string `json:"instance,omitempty"`
	CN       string `json:"cn,omitempty"`
	Addr     string `json:"addr,omitempty"`
}

type Response struct {
	Allow   bool           `json:"allow"`
	Count   int            `json:"count,omitempty"`
	Limit   int            `json:"limit,omitempty"`
	Blocked bool           `json:"blocked,omitempty"`
	Counts  map[string]int `json:"counts,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// Call отправляет один запрос и ждёт ответ; timeout — на всё вместе,
// включая соединение.
func Call(sock string, req Request, timeout time.Duration) (Response, error) {
	var resp Response
	deadline := time.Now().Add(timeout)
	conn, err := (&net.Dialer{Deadline: deadline}).Dial("unix", sock)
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return resp, err
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return resp, err
	}
	err = json.NewDecoder(conn).Decode(&resp)
	return resp, err
}
