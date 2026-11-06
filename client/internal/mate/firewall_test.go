package mate

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "firewall-check" {
		f := flag.NewFlagSet("firewall-check", flag.ExitOnError)
		tool := f.String("tool", "", "")
		_ = f.Parse(os.Args[2:])
		if err := FirewallCheck(context.Background(), *tool); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestFirewallProtectedSSH(t *testing.T) {
	allow := FirewallRule{ID: "allow", Enabled: true, Direction: "in", Action: "allow", Family: "ipv4", Protocol: "tcp", Source: "192.0.2.10", DestinationPort: "22"}
	deny := FirewallRule{ID: "deny", Enabled: true, Direction: "in", Action: "deny", Family: "any", Protocol: "tcp", DestinationPort: "20:30"}
	protection := []SSHProtection{{Source: "192.0.2.10/32", Port: 22}}
	defaults := FirewallDefaults{In: "deny", Out: "allow", Route: "deny"}
	if err := protectSSH([]FirewallRule{deny, allow}, defaults, protection); err == nil {
		t.Fatal("an earlier deny blocks the SSH allow")
	}
	if err := protectSSH([]FirewallRule{allow, deny}, defaults, protection); err != nil {
		t.Fatal(err)
	}
	allow.InInterface = "eth0"
	if err := protectSSH([]FirewallRule{allow}, defaults, protection); err == nil {
		t.Fatal("an interface-scoped allow cannot protect all SSH paths")
	}
	allow.InInterface = ""
	allow.Source = "192.0.2.10\nCOMMIT"
	if err := allow.validate(); err == nil {
		t.Fatal("accepted injected restore command")
	}
}

func TestFirewallUserFormat(t *testing.T) {
	r := FirewallRule{ID: "example", Priority: 10, Enabled: true, Direction: "route", Action: "reject",
		Family: "ipv6", Protocol: "udp", Source: "2001:db8::1", Destination: "2001:db8:1::/64",
		SourcePort: "80", DestinationPort: "100:200", InInterface: "eth0", OutInterface: "eth1", Comment: "区域"}
	if err := r.validate(); err != nil {
		t.Fatal(err)
	}
	tuple, line := r.compile(true)
	parsed, blocked := userRules("### RULES ###\n"+tuple+"\n"+line+"\n### END RULES ###", true)
	if len(blocked) != 0 || len(parsed) != 1 || parsed[0].DestinationPort != "100:200" ||
		parsed[0].InInterface != "eth0" || parsed[0].OutInterface != "eth1" || parsed[0].Comment != r.Comment {
		t.Fatalf("UFW rule round trip failed: %+v %v", parsed, blocked)
	}
}

// Run only in a disposable mount and network namespace. Each fixture root
// contains etc/ufw, etc/default/ufw and that distribution's usr/share/ufw.
func TestFirewallFixture(t *testing.T) {
	fixture := os.Getenv("MATE_UFW_FIXTURE")
	if fixture == "" {
		t.Skip("MATE_UFW_FIXTURE is not set")
	}
	files, err := readFirewallFiles(fixture)
	if err != nil {
		t.Fatal(err)
	}
	observation := analyzeFirewall(fixture, files, []int{22})
	if observation.Status != "active" || len(observation.Blocked) != 0 {
		t.Fatalf("fixture cannot be imported: %s %v", observation.Status, observation.Blocked)
	}
	if len(observation.Protection) == 0 {
		t.Fatal("SSH protection was not imported")
	}
	target := FirewallTarget{Defaults: observation.Defaults, Rules: observation.Rules, Protection: observation.Protection}
	if os.Getenv("MATE_UFW_INTEGRATION") != "1" {
		if _, err := renderFirewall(fixture, files, target, true); err != nil {
			t.Fatal(err)
		}
		return
	}
	own, _ := os.Readlink("/proc/self/ns/net")
	init, _ := os.Readlink("/proc/1/ns/net")
	if own == "" || own == init || os.Geteuid() != 0 {
		t.Fatal("integration tests require an isolated network namespace")
	}
	// The harness mounts disposable files over /etc; refuse the real host paths.
	if _, err := os.Stat("/etc/ufw/.mate-test"); err != nil {
		t.Fatal("integration tests require a disposable UFW directory")
	}
	ctx := context.Background()
	if _, err := firewallExec(ctx, "", "ufw", "--force", "enable"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-N", "DOCKER-USER"}, {"-I", "FORWARD", "-j", "DOCKER-USER"}, {"-N", "f2b-sshd"}, {"-I", "INPUT", "-j", "f2b-sshd"}} {
		if _, err := firewallExec(ctx, "", "iptables", args...); err != nil {
			t.Fatal(err)
		}
	}
	checkSSH := isolatedSSHProbe(t, target.Protection[0].Source)
	checkSSH()
	oldLive, oldExternal, err := liveFirewall(ctx, observation.IPv6)
	if err != nil {
		t.Fatal(err)
	}
	files, err = readFirewallFiles("/")
	if err != nil {
		t.Fatal(err)
	}
	desired, err := renderFirewall(fixture, files, target, true)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := stagedFirewall(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFirewallFiles(desired); err != nil {
		t.Fatal(err)
	}
	if _, err := firewallExec(ctx, "", "ufw", "reload"); err != nil {
		t.Fatal(err)
	}
	live, external, err := liveFirewall(ctx, observation.IPv6)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFirewall(expected, live, target.Defaults); err != nil {
		t.Fatal(err)
	}
	if firewallFingerprint(external) != firewallFingerprint(oldExternal) {
		t.Fatal("UFW changed external chains")
	}
	checkSSH()
	for _, p := range target.Protection {
		if !slices.ContainsFunc(live["iptables"], func(line string) bool { return strings.Contains(line, p.Source) }) {
			t.Fatalf("protected SSH source %s missing", p.Source)
		}
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	config := Config{StatePath: statePath}
	j := firewallJournal{Pending: &firewallPending{ID: UUID(), Deadline: 1, Backup: files}}
	if err := WriteJSON(firewallJournalPath(config), &j); err != nil {
		t.Fatal(err)
	}
	lock, err := firewallLock(config, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecoverFirewall(ctx, config, false, false); err != nil {
		t.Fatal(err)
	}
	pending, err := readFirewallJournal(config)
	if err != nil || pending.Pending == nil {
		t.Fatal("watchdog raced an active transaction")
	}
	lock.Close()
	if err := RecoverFirewall(ctx, config, false, false); err != nil {
		t.Fatal(err)
	}
	done, err := readFirewallJournal(config)
	if err != nil || done.Pending != nil || done.Attempt.Status != "rolled_back" {
		t.Fatal("watchdog did not persist rollback")
	}
	checkSSH()
	restored, _, err := liveFirewall(ctx, observation.IPv6)
	if err != nil || firewallFingerprint(oldLive) != firewallFingerprint(restored) {
		t.Fatal("original firewall was not restored")
	}
}

func isolatedSSHProbe(t *testing.T, protected string) func() {
	t.Helper()
	allowed, _, _ := strings.Cut(protected, "/")
	const denied = "198.18.23.2"
	ctx := context.Background()
	peer := exec.Command("unshare", "--net", "sh", "-c", "echo ready; exec sleep 90")
	out, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Process.Kill(); _ = peer.Wait() })
	if !bufio.NewScanner(out).Scan() {
		t.Fatal("test peer namespace failed")
	}
	pid := fmt.Sprint(peer.Process.Pid)
	run := func(name string, args ...string) {
		if _, err := firewallExec(ctx, "", name, args...); err != nil {
			t.Fatal(err)
		}
	}
	run("ip", "link", "add", "matehost", "type", "veth", "peer", "name", "matepeer")
	run("ip", "link", "set", "matepeer", "netns", pid)
	run("ip", "link", "set", "matehost", "up")
	run("ip", "addr", "add", "198.18.23.1/32", "dev", "matehost")
	run("nsenter", "-t", pid, "-n", "ip", "link", "set", "matepeer", "up")
	for _, ip := range []string{allowed, denied} {
		run("nsenter", "-t", pid, "-n", "ip", "addr", "add", ip+"/32", "dev", "matepeer")
		run("ip", "route", "add", ip+"/32", "dev", "matehost")
	}
	run("nsenter", "-t", pid, "-n", "ip", "route", "add", "198.18.23.1/32", "dev", "matepeer")
	listener, err := net.Listen("tcp4", "198.18.23.1:22")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return func() {
		for _, ip := range []string{allowed, denied} {
			run("nsenter", "-t", pid, "-n", "ip", "route", "replace", "198.18.23.1/32", "dev", "matepeer", "src", ip)
			_, err := firewallExec(ctx, "", "nsenter", "-t", pid, "-n", "timeout", "2", "bash", "-c", "exec 3<>/dev/tcp/198.18.23.1/22")
			if (err == nil) != (ip == allowed) {
				t.Fatalf("SSH policy for source %s: %v", ip, err)
			}
		}
	}
}
