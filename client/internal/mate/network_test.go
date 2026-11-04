package mate

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func reply(p Sync, mode string) ServerSync {
	m := ServerSync{Protocol: 1, Type: "sync", ServerTime: time.Now().Unix(), Config: RemoteConfig{Revision: 1, Mode: mode, PollInterval: 5}, PolicyRevision: 1, Policies: []Policy{}, Commands: []Command{}, AckEvents: []string{}, AckResults: []string{}}
	for _, e := range p.Events {
		m.AckEvents = append(m.AckEvents, e.ID)
	}
	for _, r := range p.Results {
		m.AckResults = append(m.AckResults, r.ID)
	}
	if p.Snapshot != nil {
		m.AckSnapshotSeq = p.Snapshot.Seq
	}
	return m
}
func TestRealNetworkFallbackToHTTP(t *testing.T) {
	var attempts atomic.Int32
	received := make(chan Sync, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/v1/addresses" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/api/agent/v1/ws" {
			attempts.Add(1)
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			w.WriteHeader(401)
			return
		}
		var p Sync
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(reply(p, "polling"))
		select {
		case received <- p:
		default:
		}
	}))
	defer server.Close()
	a := Agent{Config: Config{Server: server.URL, Token: strings.Repeat("a", 64), StatePath: statePath(t)}, State: NewState(), Runner: fake(), Version: "test"}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case p := <-received:
		if p.ActualMode != "polling" || p.FallbackReason == "" || attempts.Load() < 3 {
			t.Errorf("fallback did not report effective mode: %+v", p)
		}
	case <-ctx.Done():
		t.Error("no HTTP fallback request received")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestLiveSwitchHTTPToWebSocketAndBack(t *testing.T) {
	var polls atomic.Int32
	var connections atomic.Int32
	finished := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/v1/addresses" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/api/agent/v1/ws" {
			connections.Add(1)
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			var p Sync
			if err = wsjson.Read(ctx, c, &p); err != nil {
				t.Error(err)
				return
			}
			if p.ActualMode != "websocket" {
				t.Errorf("expected websocket mode, got %s", p.ActualMode)
			}
			m := reply(p, "polling")
			m.Config.Revision = 2
			_ = wsjson.Write(ctx, c, m)
			_, _, _ = c.Read(ctx)
			return
		}
		var p Sync
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(400)
			return
		}
		count := polls.Add(1)
		mode := "websocket"
		if count > 1 {
			mode = "polling"
		}
		m := reply(p, mode)
		if count > 1 {
			m.Config.Revision = 2
		}
		_ = json.NewEncoder(w).Encode(m)
		if count > 1 {
			select {
			case finished <- struct{}{}:
			default:
			}
		}
	}))
	defer server.Close()
	s := NewState()
	s.Remote.Mode = "polling"
	a := Agent{Config: Config{Server: server.URL, StatePath: statePath(t)}, State: s, Runner: fake(), Version: "test"}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Error("transport switch did not complete")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 1 {
		t.Fatalf("unexpected WebSocket probes in manual HTTP mode: %d", connections.Load())
	}
}
