package mate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	jails   []string
	bans    map[string][]string
	ignores map[string][]string
	failed  map[string]bool
	calls   [][]string
}

func fake() *fakeRunner {
	return &fakeRunner{jails: []string{"sshd"}, bans: map[string][]string{}, ignores: map[string][]string{}, failed: map[string]bool{}}
}
func (f *fakeRunner) Run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	if args[0] == "status" {
		return "Status\n|- Number of jail: 1\n`- Jail list: " + strings.Join(f.jails, ", "), nil
	}
	j := args[1]
	if f.failed[j] {
		return "", fmt.Errorf("read failed")
	}
	if args[0] == "get" {
		if args[2] == "banip" {
			return strings.Join(f.bans[j], " "), nil
		}
		if args[2] == "ignoreip" {
			return "These IP addresses/networks are ignored:\n|- " + strings.Join(f.ignores[j], "\n|- "), nil
		}
	}
	if args[0] == "set" {
		op, ip := args[2], args[3]
		switch op {
		case "banip":
			f.bans[j] = append(f.bans[j], ip)
		case "unbanip":
			f.bans[j] = remove(f.bans[j], ip)
		case "addignoreip":
			f.ignores[j] = append(f.ignores[j], ip)
		case "delignoreip":
			f.ignores[j] = remove(f.ignores[j], ip)
		default:
			return "", fmt.Errorf("unknown operation")
		}
		return "1", nil
	}
	return "", fmt.Errorf("unexpected command")
}
func remove(s []string, value string) []string {
	out := []string{}
	for _, v := range s {
		if v != value {
			out = append(out, v)
		}
	}
	return out
}
func statePath(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "state.json") }
func TestCollectorReconcilePreservesFailedJails(t *testing.T) {
	ctx := context.Background()
	f := fake()
	f.bans["sshd"] = []string{"8.8.8.8", "2001:db8::1"}
	s := NewState()
	c := Collector{Runner: f}
	snap, err := c.Scan(ctx, s)
	if err != nil || len(snap.Jails[0].Bans) != 2 || len(s.Events) != 2 {
		t.Fatalf("initial scan: %v %+v", err, snap)
	}
	_, _ = c.Scan(ctx, s)
	if len(s.Events) != 2 {
		t.Fatal("unchanged scan duplicated events")
	}
	f.failed["sshd"] = true
	snap, err = c.Scan(ctx, s)
	if err == nil || len(snap.Unavailable) != 1 || len(s.Known["sshd"]) != 2 || len(s.Events) != 2 {
		t.Fatal("failed read erased bans")
	}
	f.failed["sshd"] = false
	f.bans["sshd"] = []string{}
	_, _ = c.Scan(ctx, s)
	if len(s.Events) != 4 || s.Events[2].Kind != "unban" {
		t.Fatal("unban delta missing")
	}
	f.jails = []string{}
	_, err = c.Scan(ctx, s)
	if err != nil || len(s.Known) != 0 {
		t.Fatal("vanished jail not removed")
	}
}
func TestPoliciesExpireOfflineAndPreserveOriginalWhitelist(t *testing.T) {
	ctx := context.Background()
	f := fake()
	f.ignores["sshd"] = []string{"1.1.1.1", "10.0.0.0/8"}
	f.bans["sshd"] = []string{"8.8.8.8"}
	s := NewState()
	s.Known["sshd"] = map[string]Ban{"8.8.8.8": {IP: "8.8.8.8"}}
	expiry := int64(200)
	for _, ip := range []string{"1.1.1.1", "10.1.2.3", "8.8.8.8"} {
		s.Policies = append(s.Policies, Policy{ID: ip, IP: ip, ExpiresAt: &expiry})
	}
	s.PolicyRevision = 2
	path := statePath(t)
	if err := ApplyPolicies(ctx, f, s, path, 100); err != nil {
		t.Fatal(err)
	}
	if len(s.Owned) != 1 || !s.Owned["sshd\n8.8.8.8"] || len(f.bans["sshd"]) != 0 {
		t.Fatal("ownership or unban failed")
	}
	// Restart the agent without any connection to the control plane.
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = ApplyPolicies(ctx, f, loaded, path, 201); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.ignores["sshd"], []string{"1.1.1.1", "10.0.0.0/8"}) {
		t.Fatalf("removed pre-existing entries: %v", f.ignores)
	}
	if len(loaded.Owned) != 0 {
		t.Fatal("expired ownership not cleaned up")
	}
}
func TestPoliciesReapplyAfterFail2banRestartAndDiscoverNewJails(t *testing.T) {
	f := fake()
	s := NewState()
	s.Policies = []Policy{{ID: "p", IP: "8.8.8.8"}}
	path := statePath(t)
	ctx := context.Background()
	if err := ApplyPolicies(ctx, f, s, path, 100); err != nil {
		t.Fatal(err)
	}
	f.ignores = map[string][]string{}
	f.jails = append(f.jails, "nginx-auth")
	if err := ApplyPolicies(ctx, f, s, path, 100); err != nil {
		t.Fatal(err)
	}
	for _, j := range f.jails {
		if !Ignored(strings.Join(f.ignores[j], " "), "8.8.8.8") {
			t.Fatalf("rule not applied to %s", j)
		}
	}
	s.Policies = nil
	if err := ApplyPolicies(ctx, f, s, path, 100); err != nil {
		t.Fatal(err)
	}
	if len(f.ignores["sshd"])+len(f.ignores["nginx-auth"]) != 0 {
		t.Fatal("revocation failed")
	}
}
func TestCommandRetryAcrossRestartAndWhitelistGuard(t *testing.T) {
	ctx := context.Background()
	f := fake()
	s := NewState()
	path := statePath(t)
	c := Command{ID: UUID(), Kind: "ban", Jail: "sshd", IP: "8.8.8.8", ExpiresAt: time.Now().Unix() + 600}
	first := Execute(ctx, f, s, c, path)
	if first.Status != "succeeded" {
		t.Fatal(first)
	}
	if err := WriteJSON(path, s); err != nil {
		t.Fatal(err)
	}
	loaded, _ := LoadState(path)
	before := len(f.calls)
	again := Execute(ctx, f, loaded, c, path)
	if again != first || len(f.calls) != before {
		t.Fatal("duplicate command executed again")
	}
	loaded.Policies = []Policy{{IP: "1.1.1.1"}}
	c.ID = UUID()
	c.IP = "1.1.1.1"
	if Execute(ctx, f, loaded, c, path).Status != "failed" {
		t.Fatal("whitelisted IP was banned")
	}
	c.ID = UUID()
	c.IP = "8.8.8.8"
	c.Jail = "sshd; touch /tmp/evil"
	if Execute(ctx, f, loaded, c, path).Status != "failed" {
		t.Fatal("unsafe jail accepted")
	}
	c.ID = UUID()
	c.Jail = "sshd"
	c.ExpiresAt = 1
	if Execute(ctx, f, loaded, c, path).Status != "failed" {
		t.Fatal("expired command executed")
	}
}
func TestDurableQueueAndWireSequence(t *testing.T) {
	s := NewState()
	for i := int64(1); i <= 150; i++ {
		s.Events = append(s.Events, Event{ID: UUID(), Seq: i, Kind: "ban", Ban: Ban{IP: "8.8.8.8", Jail: "sshd"}})
	}
	s.Sequence = 150
	path := statePath(t)
	if err := WriteJSON(path, s); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Fatal("state file permissions not private")
	}
	a := Agent{State: st, Config: Config{StatePath: path}, Runner: fake()}
	p, err := a.payload("polling", "", false)
	if err != nil || len(p.Events) != 100 || p.Sequence != 100 {
		t.Fatalf("batch sequence skips undelivered events: %+v %v", p, err)
	}
	m := ServerSync{Protocol: 1, Type: "sync", ServerTime: time.Now().Unix(), Config: RemoteConfig{Mode: "polling", PollInterval: 30}, Policies: []Policy{}}
	for _, e := range p.Events {
		m.AckEvents = append(m.AckEvents, e.ID)
	}
	if err = a.accept(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(a.State.Events) != 50 {
		t.Fatal("ack removed wrong events")
	}
	p, err = a.payload("polling", "", false)
	if err != nil || p.Sequence != 150 {
		t.Fatal("remaining events not retained")
	}
	// Corruption must never silently discard queued operations.
	_ = os.WriteFile(path, []byte("{"), 0600)
	if _, err = LoadState(path); err == nil {
		t.Fatal("corrupted state silently reset")
	}
}
func TestFallbackAndRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	s := TransportState{}
	for i := 0; i < 3; i++ {
		s.Failure(now.Add(time.Duration(i) * time.Second))
	}
	if !s.Fallback || s.NextDial.Sub(now) != 302*time.Second {
		t.Fatalf("fallback/probe interval incorrect: %+v", s)
	}
	if s.Stable(59*time.Second) || !s.Fallback {
		t.Fatal("probe restored too early")
	}
	if !s.Stable(60*time.Second) || s.Fallback || s.Failures != 0 {
		t.Fatal("stable connection did not recover")
	}
	// Individually stable connections can still flap 3 times within 5 minutes.
	s = TransportState{}
	for i := 0; i < 3; i++ {
		s.Stable(60 * time.Second)
		s.Failure(now.Add(time.Duration(i) * 70 * time.Second))
	}
	if !s.Fallback {
		t.Fatal("frequent disconnects not detected")
	}
	s = TransportState{}
	s.Failure(now)
	s.Stable(60 * time.Second)
	s.Failure(now.Add(6 * time.Minute))
	if s.Fallback || len(s.Drops) != 1 {
		t.Fatal("old drops did not expire")
	}
}
func TestParsingAndIgnoreCIDR(t *testing.T) {
	if !Ignored("|- 127.0.0.1/8\n`- 2001:db8::/32", "2001:db8::1") {
		t.Fatal("IPv6 prefix not recognized")
	}
	for _, v := range []string{"127.1", "012.1.1.1", "8.8.8.8/24", "fe80::1%eth0"} {
		if _, err := canonical(v); err == nil {
			t.Fatalf("invalid IP accepted: %s", v)
		}
	}
	if got := IPs("8.8.8.8 2001:db8::1\n8.8.8.8"); len(got) != 2 {
		t.Fatal(got)
	}
}

func TestReplacingDynamicPolicyKeepsOtherSourcesAndExpiresOffline(t *testing.T) {
	ctx := context.Background()
	f := fake()
	path := statePath(t)
	s := NewState()
	expiry := int64(200)
	s.Policies = []Policy{
		{ID: "manual", IP: "8.8.8.8"},
		{ID: "other", IP: "1.1.1.1", ExpiresAt: &expiry},
		{ID: "dynamic", IP: "8.8.8.8", ExpiresAt: &expiry},
		{ID: "moving", IP: "9.9.9.9", ExpiresAt: &expiry},
	}
	if err := ApplyPolicies(ctx, f, s, path, 100); err != nil {
		t.Fatal(err)
	}
	s.Policies[2].IP = "1.1.1.1"
	s.Policies[3].IP = "8.8.4.4"
	if err := ApplyPolicies(ctx, f, s, path, 110); err != nil {
		t.Fatal(err)
	}
	for _, jail := range f.jails {
		ignored := strings.Join(f.ignores[jail], " ")
		if Ignored(ignored, "9.9.9.9") || !Ignored(ignored, "8.8.4.4") ||
			!Ignored(ignored, "8.8.8.8") || !Ignored(ignored, "1.1.1.1") {
			t.Fatalf("wrong policy after replacement: %v", f.ignores)
		}
	}
	restarted, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyPolicies(ctx, f, restarted, path, 200); err != nil {
		t.Fatal(err)
	}
	for _, jail := range f.jails {
		if !reflect.DeepEqual(f.ignores[jail], []string{"8.8.8.8"}) {
			t.Fatalf("wrong policy after offline expiry: %v", f.ignores)
		}
	}
}
