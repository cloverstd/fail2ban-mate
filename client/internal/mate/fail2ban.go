package mate

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

var jailName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,127}$`)

type Runner interface {
	Run(context.Context, ...string) (string, error)
}
type ExecRunner struct{ Path string }

func (r ExecRunner) Run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.Path, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("fail2ban-client %s failed: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
func canonical(s string) (string, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return "", fmt.Errorf("invalid IP")
	}
	return ip.Unmap().String(), nil
}
func Jails(ctx context.Context, r Runner) ([]string, error) {
	out, err := r.Run(ctx, "status")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "Jail list:"); i >= 0 {
			raw := strings.TrimSpace(line[i+len("Jail list:"):])
			list := []string{}
			for _, v := range strings.Split(raw, ",") {
				v = strings.TrimSpace(v)
				if v == "" {
					continue
				}
				if !jailName.MatchString(v) {
					return nil, fmt.Errorf("invalid jail name in status")
				}
				list = append(list, v)
			}
			sort.Strings(list)
			return list, nil
		}
	}
	return nil, fmt.Errorf("unrecognized fail2ban status output")
}
func IPs(output string) []string {
	seen := map[string]bool{}
	for _, t := range strings.FieldsFunc(output, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ',' || r == '\'' || r == '"' || r == '[' || r == ']' || r == '|'
	}) {
		if ip, err := canonical(t); err == nil {
			seen[ip] = true
		}
	}
	out := []string{}
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
func Ignored(output, ip string) bool {
	addr, _ := netip.ParseAddr(ip)
	for _, t := range strings.FieldsFunc(output, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ',' || r == '\'' || r == '"' || r == '[' || r == ']' || r == '|'
	}) {
		if v, err := canonical(t); err == nil && v == ip {
			return true
		}
		if p, err := netip.ParsePrefix(t); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

type Locator interface{ Lookup(string) Geo }
type Collector struct {
	Runner Runner
	Geo    Locator
}

func (c Collector) Scan(ctx context.Context, s *State) (*Snapshot, error) {
	names, err := Jails(ctx, c.Runner)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{Jails: []JailSnapshot{}, Unavailable: []string{}}
	present := map[string]bool{}
	var failures []string
	// Keeping all unacknowledged events is preferable to silently dropping them.
	if len(s.Events) > 50000 {
		return nil, fmt.Errorf("event queue full; restore connectivity before sampling resumes")
	}
	for _, name := range names {
		present[name] = true
		out, err := c.Runner.Run(ctx, "get", name, "banip")
		if err != nil {
			snap.Unavailable = append(snap.Unavailable, name)
			failures = append(failures, name)
			continue
		}
		old := s.Known[name]
		current := map[string]Ban{}
		bans := []Ban{}
		for _, ip := range IPs(out) {
			b, ok := old[ip]
			if !ok {
				b = Ban{Jail: name, IP: ip, ObservedAt: time.Now().Unix()}
				if c.Geo != nil {
					b.Geo = c.Geo.Lookup(ip)
				}
				s.Sequence++
				s.Events = append(s.Events, Event{Ban: b, ID: UUID(), Seq: s.Sequence, Kind: "ban"})
			}
			current[ip] = b
			bans = append(bans, b)
		}
		for ip, b := range old {
			if _, ok := current[ip]; !ok {
				s.Sequence++
				b.ObservedAt = time.Now().Unix()
				s.Events = append(s.Events, Event{Ban: b, ID: UUID(), Seq: s.Sequence, Kind: "unban"})
			}
		}
		s.Known[name] = current
		snap.Jails = append(snap.Jails, JailSnapshot{Name: name, Bans: bans})
	}
	for name, old := range s.Known {
		if !present[name] {
			for _, b := range old {
				s.Sequence++
				b.ObservedAt = time.Now().Unix()
				s.Events = append(s.Events, Event{Ban: b, ID: UUID(), Seq: s.Sequence, Kind: "unban"})
			}
			delete(s.Known, name)
		}
	}
	s.Unavailable = snap.Unavailable
	snap.Seq = s.Sequence
	if len(failures) > 0 {
		return snap, fmt.Errorf("cannot read jails: %s", strings.Join(failures, ", "))
	}
	return snap, nil
}
