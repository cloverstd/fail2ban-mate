package mate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type netEvent struct {
	conn *websocket.Conn
	msg  *ServerSync
	err  error
	dial bool
	http bool
}
type Agent struct {
	Config        Config
	State         *State
	Runner        Runner
	Version       string
	Geo           *GeoDB
	geoModified   time.Time
	snapshot      *Snapshot
	forceSnapshot bool
	scanError     string
	policyError   string
}

func (a *Agent) persist() error { return WriteJSON(a.Config.StatePath, a.State) }
func (a *Agent) scan(ctx context.Context) error {
	if fi, err := os.Stat(a.Config.GeoPath); err == nil && fi.ModTime() != a.geoModified {
		if db, e := OpenGeo(a.Config.GeoPath); e == nil {
			a.Geo.Close()
			a.Geo = db
			a.geoModified = fi.ModTime()
		}
	}
	before := a.State.Sequence
	snap, err := (Collector{Runner: a.Runner, Geo: a.Geo}).Scan(ctx, a.State)
	if snap != nil {
		a.snapshot = snap
	}
	a.scanError = ""
	if err != nil {
		a.scanError = err.Error()
	}
	a.policyError = ""
	if len(a.State.Policies) > 0 || len(a.State.Owned) > 0 || a.State.PolicyRevision != a.State.AppliedPolicyRevision {
		if e := ApplyPolicies(ctx, a.Runner, a.State, a.Config.StatePath, time.Now().Unix()); e != nil {
			a.policyError = e.Error()
		}
	}
	if before != a.State.Sequence {
		return a.persist()
	}
	return nil
}
func (a *Agent) payload(actual, reason string, full bool) (Sync, error) {
	s := a.State
	p := Sync{Protocol: 1, Type: "sync", Version: a.Version, ActualMode: actual, FallbackReason: reason, ConfigRevision: s.Remote.Revision, PolicyRevision: s.AppliedPolicyRevision, Events: []Event{}, Results: []Result{}}
	p.Error = strings.Join(nonempty(a.scanError, a.policyError), "; ")
	if len(p.Error) > 1000 {
		p.Error = p.Error[:1000]
	}
	count := min(100, len(s.Events))
	p.Events = append(p.Events, s.Events[:count]...)
	for _, e := range p.Events {
		p.Sequence = max(p.Sequence, e.Seq)
	}
	keys := []string{}
	for k := range s.Results {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys[:min(100, len(keys))] {
		p.Results = append(p.Results, s.Results[k])
	}
	if full && a.snapshot != nil {
		s.Sequence++
		copy := *a.snapshot
		copy.Seq = s.Sequence
		p.Snapshot = &copy
		p.Sequence = s.Sequence
		if err := a.persist(); err != nil {
			return p, err
		}
	}
	return p, nil
}
func nonempty(v ...string) []string {
	out := []string{}
	for _, s := range v {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
func (a *Agent) accept(ctx context.Context, m ServerSync) error {
	if m.Protocol != 1 || m.Type != "sync" || m.Config.PollInterval < 5 || m.Config.PollInterval > 300 || (m.Config.Mode != "websocket" && m.Config.Mode != "polling") {
		return fmt.Errorf("invalid server protocol")
	}
	// Refuse commands/policy if the clock cannot safely evaluate their deadlines.
	if diff := time.Now().Unix() - m.ServerTime; diff > 120 || diff < -120 {
		return fmt.Errorf("system clock differs from server by more than 120 seconds; enable NTP")
	}
	for _, p := range m.Policies {
		if _, err := canonical(p.IP); err != nil {
			return fmt.Errorf("invalid server policy")
		}
	}
	s := a.State
	ack := map[string]bool{}
	for _, id := range m.AckEvents {
		ack[id] = true
	}
	remaining := []Event{}
	for _, e := range s.Events {
		if !ack[e.ID] {
			remaining = append(remaining, e)
		}
	}
	s.Events = remaining
	for _, id := range m.AckResults {
		delete(s.Results, id)
	}
	if m.Config.Revision >= s.Remote.Revision {
		s.Remote = m.Config
	}
	if m.PolicyRevision >= s.PolicyRevision {
		s.Policies = m.Policies
		s.PolicyRevision = m.PolicyRevision
	}
	// Save desired policies before touching fail2ban; expiry must survive a crash.
	if err := a.persist(); err != nil {
		return err
	}
	if err := ApplyPolicies(ctx, a.Runner, s, a.Config.StatePath, time.Now().Unix()); err != nil {
		a.policyError = err.Error()
	} else {
		a.policyError = ""
	}
	for _, cmd := range m.Commands {
		r := Execute(ctx, a.Runner, s, cmd, a.Config.StatePath)
		s.Results[r.ID] = r
		if err := a.persist(); err != nil {
			return err
		}
	}
	// Retain deduplication longer than the server's command lifetime and retention.
	for id, t := range s.CompletedAt {
		if t < time.Now().Add(-31*24*time.Hour).Unix() {
			delete(s.Completed, id)
			delete(s.CompletedAt, id)
		}
	}
	if m.SnapshotRequired {
		a.forceSnapshot = true
	}
	return a.persist()
}
func (a *Agent) httpSync(ctx context.Context, p Sync) (*ServerSync, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", a.Config.Server+"/api/agent/v1/sync", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Config.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP sync connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP sync status %d", res.StatusCode)
	}
	var msg ServerSync
	err = json.NewDecoder(io.LimitReader(res.Body, 8*1024*1024)).Decode(&msg)
	return &msg, err
}
func (a *Agent) dial(ctx context.Context) (*websocket.Conn, error) {
	u, err := url.Parse(a.Config.Server + "/api/agent/v1/ws")
	if err != nil {
		return nil, err
	}
	u.Scheme = "wss"
	if strings.HasPrefix(a.Config.Server, "http://") {
		u.Scheme = "ws"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+a.Config.Token)
	conn, res, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		if res != nil && res.Body != nil {
			_ = res.Body.Close()
		}
		return nil, fmt.Errorf("WebSocket connection failed")
	}
	conn.SetReadLimit(8 * 1024 * 1024)
	return conn, nil
}
func (a *Agent) Run(ctx context.Context) error {
	defer func() { a.Geo.Close() }()
	if err := a.scan(ctx); err != nil {
		return err
	}
	events := make(chan netEvent, 64)
	emit := func(e netEvent) {
		select {
		case events <- e:
		case <-ctx.Done():
			if e.dial && e.conn != nil {
				_ = e.conn.CloseNow()
			}
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var conn *websocket.Conn
	var dialing, inHTTP bool
	var connectedAt, lastWS, nextHTTP, lastFull time.Time
	transport := TransportState{}
	a.forceSnapshot = true
	dirty := true
	nextScan := time.Now()
	closeConn := func() {
		if conn != nil {
			_ = conn.CloseNow()
			conn = nil
		}
	}
	defer func() { closeConn() }()
	failed := func() {
		closeConn()
		transport.Failure(time.Now())
		if transport.Fallback {
			nextHTTP = time.Now()
			log.Print(transport.Reason)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-events:
			if e.dial {
				dialing = false
				if a.State.Remote.Mode == "polling" {
					if e.conn != nil {
						_ = e.conn.CloseNow()
					}
					continue
				}
				if e.err != nil {
					failed()
					continue
				}
				conn = e.conn
				connectedAt = time.Now()
				lastWS = time.Time{}
				dirty = true
				a.forceSnapshot = true
				go func(c *websocket.Conn) {
					for {
						readCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
						var m ServerSync
						err := wsjson.Read(readCtx, c, &m)
						cancel()
						if err != nil {
							emit(netEvent{conn: c, err: errors.New("WebSocket disconnected")})
							return
						}
						emit(netEvent{conn: c, msg: &m})
					}
				}(conn)
				continue
			}
			if e.http {
				inHTTP = false
			} else if e.conn != conn {
				continue
			}
			if e.err != nil {
				if e.http {
					log.Print(e.err)
					nextHTTP = time.Now().Add(time.Duration(a.State.Remote.PollInterval) * time.Second)
				} else {
					failed()
				}
				continue
			}
			if e.msg != nil {
				oldMode := a.State.Remote.Mode
				oldPolicy := a.State.AppliedPolicyRevision
				oldConfig := a.State.Remote.Revision
				if err := a.accept(ctx, *e.msg); err != nil {
					var storageError *os.PathError
					if errors.As(err, &storageError) {
						return err
					}
					log.Printf("server response rejected: %v", err)
					continue
				}
				if e.msg.AckSnapshotSeq > 0 {
					lastFull = time.Now()
					a.forceSnapshot = false
				}
				if oldMode != a.State.Remote.Mode {
					if a.State.Remote.Mode == "polling" {
						closeConn()
						transport = TransportState{}
						nextHTTP = time.Now()
					} else {
						transport = TransportState{}
						transport.NextDial = time.Now()
					}
				}
				if len(e.msg.Commands) > 0 || oldPolicy != a.State.AppliedPolicyRevision || oldConfig != a.State.Remote.Revision {
					dirty = true
					nextScan = time.Now()
				}
			}
		case t := <-tick.C:
			if !t.Before(nextScan) {
				before := a.State.Sequence
				beforePolicy := a.State.AppliedPolicyRevision
				if err := a.scan(ctx); err != nil {
					return err
				}
				if before != a.State.Sequence || beforePolicy != a.State.AppliedPolicyRevision {
					dirty = true
				}
				nextScan = time.Now().Add(3 * time.Second)
			}
			if a.State.Remote.Mode == "websocket" && conn == nil && !dialing && !t.Before(transport.NextDial) {
				dialing = true
				go func() { c, err := a.dial(ctx); emit(netEvent{conn: c, err: err, dial: true}) }()
			}
			if conn != nil && transport.Stable(time.Since(connectedAt)) {
				dirty = true
				log.Print("WebSocket stable; restored preferred transport")
			}
			actual := "websocket"
			if a.State.Remote.Mode == "polling" || transport.Fallback || conn == nil {
				actual = "polling"
			}
			full := a.forceSnapshot || time.Since(lastFull) >= 5*time.Minute
			if conn != nil && (dirty || time.Since(lastWS) >= 30*time.Second) {
				p, err := a.payload(actual, transport.Reason, full)
				if err != nil {
					return err
				}
				writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err = wsjson.Write(writeCtx, conn, p)
				cancel()
				if err != nil {
					failed()
				} else {
					lastWS = time.Now()
					dirty = false
				}
			}
			if (a.State.Remote.Mode == "polling" || transport.Fallback) && !inHTTP && !t.Before(nextHTTP) {
				p, err := a.payload("polling", transport.Reason, full)
				if err != nil {
					return err
				}
				inHTTP = true
				nextHTTP = t.Add(time.Duration(a.State.Remote.PollInterval) * time.Second)
				go func() { msg, err := a.httpSync(ctx, p); emit(netEvent{msg: msg, err: err, http: true}) }()
			}
		}
	}
}
