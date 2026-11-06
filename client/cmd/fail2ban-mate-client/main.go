package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cloverstd/fail2ban-mate/client/internal/mate"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: fail2ban-mate-client run|enroll|geo-update|version")
	}
	if os.Args[1] == "firewall-capability" {
		return nil
	}
	if os.Args[1] == "version" {
		fmt.Println(version)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	config := f.String("config", "/etc/fail2ban-mate/config.json", "config path")
	server := f.String("server", "", "control server URL")
	code := f.String("enrollment", "", "one-time enrollment credential")
	geo := f.String("path", "/var/lib/fail2ban-mate/city.mmdb", "MMDB path")
	force := f.Bool("force", false, "restore a pending firewall transaction immediately")
	boot := f.Bool("boot", false, "restore an unfinished firewall transaction before UFW starts")
	tool := f.String("tool", "", "isolated firewall validation tool")
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	switch os.Args[1] {
	case "firewall-check":
		return mate.FirewallCheck(ctx, *tool)
	case "geo-update":
		return mate.UpdateGeo(ctx, *geo)
	case "enroll":
		u, err := url.Parse(*server)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
			return fmt.Errorf("server must be an origin URL")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
			return fmt.Errorf("server must use HTTPS")
		}
		if len(*code) != 64 {
			return fmt.Errorf("a valid one-time enrollment credential is required")
		}
		c := mate.Config{Server: strings.TrimRight(*server, "/"), StatePath: "/var/lib/fail2ban-mate/state.json", GeoPath: "/var/lib/fail2ban-mate/city.mmdb", Fail2banClient: "/usr/bin/fail2ban-client"}
		previousServer := ""
		if old, e := os.ReadFile(*config); e == nil {
			if e = json.Unmarshal(old, &c); e != nil {
				return fmt.Errorf("existing config is invalid; refusing to overwrite")
			}
			previousServer = c.Server
			c.Server = strings.TrimRight(*server, "/")
		}
		data, _ := json.Marshal(map[string]string{"enrollment": *code})
		req, err := http.NewRequestWithContext(ctx, "POST", c.Server+"/api/agent/v1/enroll", bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		client := http.Client{Timeout: 30 * time.Second}
		res, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("enrollment connection failed")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("enrollment failed (%d); regenerate the installation command", res.StatusCode)
		}
		var response struct {
			Token  string `json:"token"`
			NodeID string `json:"node_id"`
		}
		if err = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&response); err != nil {
			return err
		}
		if len(response.Token) != 64 || response.NodeID == "" {
			return fmt.Errorf("invalid enrollment response")
		}
		if c.NodeID != "" && (c.NodeID != response.NodeID || previousServer != c.Server) {
			old, e := mate.LoadState(c.StatePath)
			if e != nil {
				return e
			}
			fresh := mate.NewState()
			fresh.Owned = old.Owned
			if e = mate.WriteJSON(c.StatePath, fresh); e != nil {
				return e
			}
		}
		c.Token = response.Token
		c.NodeID = response.NodeID
		if err = mate.WriteJSON(*config, c); err != nil {
			return err
		}
		log.Print("enrolled successfully; node token stored in protected config")
		return nil
	case "run", "cleanup", "firewall-recover":
		b, err := os.ReadFile(*config)
		if err != nil {
			return err
		}
		var c mate.Config
		if err = json.Unmarshal(b, &c); err != nil {
			return err
		}
		if c.Server == "" || len(c.Token) != 64 || c.StatePath == "" || c.Fail2banClient == "" {
			return fmt.Errorf("invalid client configuration")
		}
		if err = os.MkdirAll(filepath.Dir(c.StatePath), 0700); err != nil {
			return err
		}
		if os.Args[1] == "firewall-recover" {
			return mate.RecoverFirewall(ctx, c, *boot, *force)
		}
		// A single process owns the durable journal. Fail rather than race a second agent.
		lock, err := os.OpenFile(c.StatePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return fmt.Errorf("another client already owns this state file")
		}
		s, err := mate.LoadState(c.StatePath)
		if err != nil {
			return err
		}
		if os.Args[1] == "cleanup" {
			s.Policies = []mate.Policy{}
			return mate.ApplyPolicies(ctx, mate.ExecRunner{Path: c.Fail2banClient}, s, c.StatePath, time.Now().Unix())
		}
		agent := mate.Agent{Config: c, State: s, Runner: mate.ExecRunner{Path: c.Fail2banClient}, Version: version}
		return agent.Run(ctx)
	default:
		return fmt.Errorf("unknown command")
	}
}
