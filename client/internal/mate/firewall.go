package mate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ufwFiles = []string{"ufw/before.rules", "ufw/before6.rules", "ufw/user.rules", "ufw/user6.rules",
	"ufw/after.rules", "ufw/after6.rules", "default/ufw", "ufw/ufw.conf"}
var policyKeys = []string{"DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY", "DEFAULT_FORWARD_POLICY"}

type FirewallObservation struct {
	Status          string              `json:"status"`
	Fingerprint     string              `json:"fingerprint,omitempty"`
	ObservedAt      int64               `json:"observed_at"`
	Defaults        FirewallDefaults    `json:"defaults"`
	Rules           []FirewallRule      `json:"rules"`
	Protection      []SSHProtection     `json:"protection"`
	Baseline        map[string][]string `json:"baseline,omitempty"`
	PlannedBaseline map[string][]string `json:"planned_baseline,omitempty"`
	Live            map[string][]string `json:"live,omitempty"`
	External        map[string][]string `json:"external,omitempty"`
	Blocked         []string            `json:"blocked,omitempty"`
	IPv6            bool                `json:"ipv6"`
}

type FirewallTarget struct {
	ID          string           `json:"id"`
	NodeID      string           `json:"node_id"`
	Fingerprint string           `json:"fingerprint"`
	Defaults    FirewallDefaults `json:"defaults"`
	Protection  []SSHProtection  `json:"protection"`
	Rules       []FirewallRule   `json:"rules"`
}

type FirewallReceipt struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Error   string   `json:"error,omitempty"`
	Event   string   `json:"event,omitempty"`
	EventID string   `json:"event_id,omitempty"`
	Changed []string `json:"changed,omitempty"`
}

type firewallJournal struct {
	DriftPaused bool
	Confirmed   string
	Files       map[string]string
	LiveHash    string
	Attempt     *FirewallReceipt
	Pending     *firewallPending
}

type firewallPending struct {
	Event    string
	ID       string
	Deadline int64
	Backup   map[string]string
	EventID  string
	Changed  []string
}

type firewallManager struct {
	Config      Config
	Observation *FirewallObservation
	Receipt     *FirewallReceipt
	Next        time.Time
}

func firewallExec(ctx context.Context, input string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(input)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %.600s", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func firewallFingerprint(value any) string {
	b, _ := json.Marshal(value)
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

func readFirewallFiles(root string) (map[string]string, error) {
	files := map[string]string{}
	for _, name := range ufwFiles {
		path := filepath.Join(root, "etc", name)
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() || fi.Size() > 256*1024 {
			return nil, fmt.Errorf("unsupported UFW file %s", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		files[name] = string(data)
	}
	return files, nil
}

func setting(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(strings.TrimSpace(value), "\"'")
		}
	}
	return ""
}

func firewallDefaults(text string) FirewallDefaults {
	policies := map[string]string{"DROP": "deny", "ACCEPT": "allow", "REJECT": "reject"}
	return FirewallDefaults{policies[setting(text, policyKeys[0])], policies[setting(text, policyKeys[1])], policies[setting(text, policyKeys[2])]}
}

func meaningful(text string) []string {
	out := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

var narrowV6 = regexp.MustCompile(`^-A ufw6-before-input -i [\w.-]+ -p icmpv6 (--icmpv6-type (neighbor-solicitation|neighbor-advertisement) -m hl --hl-eq 255|--icmpv6-type 130 -s fe80::/10 -m hl --hl-eq 1) -j ACCEPT$`)

func baselineFor(root, name, text string, rules []FirewallRule) (string, error) {
	template, err := os.ReadFile(filepath.Join(root, "usr/share/ufw", filepath.Base(name)))
	if err != nil {
		return text, err
	}
	stock := meaningful(string(template))
	actual := meaningful(text)
	if slices.Equal(actual, stock) {
		return text, nil
	}
	if !strings.Contains(name, "/before") {
		return text, fmt.Errorf("custom after rules")
	}
	v6 := strings.HasSuffix(name, "6.rules")
	prefix := "ufw"
	if v6 {
		prefix = "ufw6"
	}
	if _, block, ok := strings.Cut(text, "# BEGIN source allowlist: all ports and protocols\n"); ok {
		body, _, ok := strings.Cut(block, "# END source allowlist")
		if !ok {
			return text, fmt.Errorf("invalid source allowlist block")
		}
		plain := strings.Replace(text, "# BEGIN source allowlist: all ports and protocols\n"+body+"# END source allowlist", "", 1)
		if !slices.Equal(meaningful(plain), stock) {
			return text, fmt.Errorf("additional custom rules beside source allowlist")
		}
		input := "-A " + prefix + "-before-input "
		expected := []string{input + "-i lo -j ACCEPT"}
		if !v6 {
			for _, r := range rules {
				p, err := network(r.Source)
				if err != nil || !p.Addr().Is4() || r.Direction != "in" || r.Protocol != "any" || r.Action != "allow" ||
					r.Destination != "" || r.InInterface != "" || r.OutInterface != "" {
					return text, fmt.Errorf("source allowlist differs from user rules")
				}
				expected = append(expected, input+"-s "+p.String()+" -j ACCEPT")
			}
		} else if len(rules) > 0 {
			return text, fmt.Errorf("IPv6 user rules are shadowed by the source allowlist")
		}
		expected = append(expected, input+"-m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT")
		if v6 {
			for _, icmp := range []string{"133", "134", "135", "136"} {
				source := ""
				if icmp == "134" {
					source = "-s fe80::/10 "
				}
				expected = append(expected, input+source+"-p ipv6-icmp --icmpv6-type "+icmp+" -m hl --hl-eq 255 -j ACCEPT")
			}
		}
		if !slices.Equal(meaningful(body), append(slices.Clone(expected), input+"-j DROP", "-A "+prefix+"-before-forward -j DROP")) {
			return text, fmt.Errorf("unknown source allowlist rules or ordering")
		}
		if !v6 {
			expected = append(expected[:1], expected[len(expected)-1])
		}
		result := []string{}
		for _, line := range stock {
			if strings.HasPrefix(line, input) || strings.HasPrefix(line, "-A "+prefix+"-before-forward ") {
				continue
			}
			if line == "COMMIT" {
				result = append(result, expected...)
			}
			result = append(result, line)
		}
		return strings.Join(result, "\n") + "\n", nil
	}
	// JP uses a subset of package rules, plus interface-scoped IPv6 discovery.
	for _, line := range actual {
		if !slices.Contains(stock, line) && !(v6 && narrowV6.MatchString(line)) {
			return text, fmt.Errorf("unrecognized custom rule")
		}
	}
	return text, nil
}

func analyzeFirewall(root string, files map[string]string, sshPorts []int) FirewallObservation {
	o := FirewallObservation{Status: "active", Defaults: firewallDefaults(files["default/ufw"]),
		IPv6: setting(files["default/ufw"], "IPV6") == "yes", Rules: []FirewallRule{}, Protection: []SSHProtection{},
		Baseline: map[string][]string{}, ObservedAt: time.Now().Unix()}
	if setting(files["ufw/ufw.conf"], "ENABLED") != "yes" {
		o.Status = "inactive"
	}
	if setting(files["default/ufw"], "MANAGE_BUILTINS") != "no" {
		o.Blocked = append(o.Blocked, "UFW requires MANAGE_BUILTINS=no")
	}
	for _, v6 := range []bool{false, true} {
		suffix := ".rules"
		if v6 {
			suffix = "6.rules"
		}
		rules, blocked := userRules(files["ufw/user"+suffix], v6)
		o.Rules = append(o.Rules, rules...)
		for _, rule := range blocked {
			o.Blocked = append(o.Blocked, "user"+suffix+": "+rule)
		}
		for _, kind := range []string{"before", "after"} {
			name := "ufw/" + kind + suffix
			o.Baseline[name] = meaningful(files[name])
			planned, err := baselineFor(root, name, files[name], rules)
			if err != nil {
				o.Blocked = append(o.Blocked, name+": "+err.Error())
			} else if !slices.Equal(o.Baseline[name], meaningful(planned)) {
				if o.PlannedBaseline == nil {
					o.PlannedBaseline = map[string][]string{}
				}
				o.PlannedBaseline[name] = meaningful(planned)
			}
		}
	}
	for _, hook := range []string{"before.init", "after.init"} {
		path := filepath.Join(root, "etc/ufw", hook)
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0111 != 0 {
			a, _ := os.ReadFile(path)
			b, err := os.ReadFile(filepath.Join(root, "usr/share/ufw", hook))
			if err != nil || string(a) != string(b) {
				o.Blocked = append(o.Blocked, "custom executable UFW hook: "+hook)
			}
		}
	}
	seen := map[SSHProtection]bool{}
	for i, r := range o.Rules {
		o.Rules[i].Priority = (i + 1) * 10
		if r.Direction != "in" || r.Action != "allow" || (r.Protocol != "tcp" && r.Protocol != "any") {
			continue
		}
		lo, hi, _ := ports(r.DestinationPort)
		for _, port := range sshPorts {
			if port < lo || port > hi {
				continue
			}
			source := r.Source
			if source == "" && r.Family == "ipv4" {
				source = "0.0.0.0/0"
			} else if source == "" {
				source = "::/0"
			}
			p := SSHProtection{source, port}
			if !seen[p] {
				o.Protection = append(o.Protection, p)
				seen[p] = true
			}
		}
	}
	return o
}

func liveFirewall(ctx context.Context, ipv6 bool) (map[string][]string, map[string][]string, error) {
	live, external := map[string][]string{}, map[string][]string{}
	for i, tool := range []string{"iptables", "ip6tables"} {
		if i == 1 && !ipv6 {
			break
		}
		out, err := firewallExec(ctx, "", tool, "-w", "3", "-S")
		if err != nil {
			return nil, nil, err
		}
		for _, line := range meaningful(out) {
			if strings.HasPrefix(line, "-P ") || strings.Contains(line, " ufw") {
				live[tool] = append(live[tool], line)
			} else if strings.Contains(line, "DOCKER") || strings.Contains(line, "f2b-") {
				external[tool] = append(external[tool], line)
			}
		}
	}
	if out, err := firewallExec(ctx, "", "nft", "list", "chain", "inet", "f2b-table", "f2b-chain"); err == nil {
		external["nftables / Fail2ban"] = meaningful(out)
	}
	return live, external, nil
}

func collectFirewall(ctx context.Context) (FirewallObservation, map[string]string, string) {
	o := FirewallObservation{Status: "unavailable", ObservedAt: time.Now().Unix(), Rules: []FirewallRule{}, Protection: []SSHProtection{}}
	if _, err := exec.LookPath("ufw"); err != nil {
		o.Blocked = []string{"UFW is not installed"}
		return o, nil, ""
	}
	files, err := readFirewallFiles("/")
	if err != nil {
		o.Blocked = []string{err.Error()}
		return o, nil, ""
	}
	ssh, _ := firewallExec(ctx, "", "/usr/sbin/sshd", "-T")
	var sshPorts []int
	for _, line := range strings.Split(ssh, "\n") {
		if raw, ok := strings.CutPrefix(line, "port "); ok {
			port, _ := strconv.Atoi(raw)
			if port > 0 {
				sshPorts = append(sshPorts, port)
			}
		}
	}
	o = analyzeFirewall("/", files, sshPorts)
	live, external, err := liveFirewall(ctx, o.IPv6)
	if err != nil {
		o.Status = "unavailable"
		o.Blocked = append(o.Blocked, err.Error())
		return o, files, ""
	}
	o.Live, o.External = live, external
	if !slices.Contains(live["iptables"], "-A INPUT -j ufw-before-input") {
		o.Status = "inactive"
	}
	liveHash := firewallFingerprint(live)
	o.Fingerprint = firewallFingerprint([]string{firewallFingerprint(files), liveHash})
	return o, files, liveHash
}

func renderFirewall(root string, old map[string]string, target FirewallTarget, first bool) (map[string]string, error) {
	if len(target.Rules) > 2000 {
		return nil, fmt.Errorf("too many firewall rules")
	}
	for _, r := range target.Rules {
		if err := r.validate(); err != nil {
			return nil, err
		}
	}
	if err := protectSSH(target.Rules, target.Defaults, target.Protection); err != nil {
		return nil, err
	}
	newFiles := map[string]string{}
	for k, v := range old {
		newFiles[k] = v
	}
	settings := newFiles["default/ufw"]
	for i, action := range []string{target.Defaults.In, target.Defaults.Out, target.Defaults.Route} {
		value := verdict(action)
		if value == "" {
			return nil, fmt.Errorf("invalid default policy")
		}
		pattern := regexp.MustCompile("(?m)^" + policyKeys[i] + "=.*$")
		if !pattern.MatchString(settings) {
			return nil, fmt.Errorf("missing default policy")
		}
		settings = pattern.ReplaceAllString(settings, policyKeys[i]+"=\""+value+"\"")
	}
	newFiles["default/ufw"] = settings
	for _, v6 := range []bool{false, true} {
		suffix := ".rules"
		if v6 {
			suffix = "6.rules"
		}
		user, before := "ufw/user"+suffix, "ufw/before"+suffix
		if first {
			rules, bad := userRules(old[user], v6)
			if len(bad) > 0 {
				return nil, fmt.Errorf("unsupported user rules")
			}
			value, err := baselineFor(root, before, old[before], rules)
			if err != nil {
				return nil, err
			}
			newFiles[before] = value
		}
		header, body, ok := strings.Cut(old[user], "### RULES ###")
		_, footer, hasFooter := strings.Cut(body, "### END RULES ###")
		if !ok || !hasFooter {
			return nil, fmt.Errorf("unknown UFW user rules file format")
		}
		var block strings.Builder
		for _, r := range target.Rules {
			if !r.Enabled || (r.Family != "any" && (r.Family == "ipv6") != v6) {
				continue
			}
			if v6 && setting(settings, "IPV6") != "yes" {
				return nil, fmt.Errorf("enable IPv6 in UFW before applying IPv6 rules")
			}
			tuple, line := r.compile(v6)
			fmt.Fprintf(&block, "\n%s\n%s\n", tuple, line)
		}
		newFiles[user] = header + "### RULES ###\n" + block.String() + "\n### END RULES ###" + footer
	}
	return newFiles, nil
}

// Build the same filter chains in a throwaway network namespace to validate and
// obtain the kernel's normalized representation before touching live files.
func stagedFirewall(ctx context.Context, files map[string]string) (map[string][]string, error) {
	expected := map[string][]string{}
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	for i, tool := range []string{"iptables", "ip6tables"} {
		if i == 1 && setting(files["default/ufw"], "IPV6") != "yes" {
			break
		}
		suffix := ".rules"
		if i == 1 {
			suffix = "6.rules"
		}
		var definitions, rules []string
		prefix := "ufw"
		if i == 1 {
			prefix = "ufw6"
		}
		for _, direction := range []string{"input", "output", "forward"} {
			definitions = append(definitions, ":"+prefix+"-skip-to-policy-"+direction+" - [0:0]")
		}
		seen := map[string]bool{}
		for _, part := range []string{"before", "user", "after"} {
			for _, line := range meaningful(files["ufw/"+part+suffix]) {
				switch {
				case line == "*filter", line == "COMMIT":
				case strings.HasPrefix(line, ":"):
					name := strings.Fields(line)[0]
					if !seen[name] {
						definitions = append(definitions, line)
						seen[name] = true
					}
				case strings.HasPrefix(line, "-A "), strings.HasPrefix(line, "-I "):
					rules = append(rules, line)
				default:
					return nil, fmt.Errorf("unsupported UFW filter file line")
				}
			}
		}
		input := "*filter\n" + strings.Join(append(definitions, rules...), "\n") + "\nCOMMIT\n"
		out, err := firewallExec(ctx, input, "unshare", "--net", binary, "firewall-check", "--tool", tool)
		if err != nil {
			return nil, err
		}
		expected[tool] = meaningful(out)
	}
	return expected, nil
}

func FirewallCheck(ctx context.Context, tool string) error {
	if tool != "iptables" && tool != "ip6tables" {
		return fmt.Errorf("invalid firewall check tool")
	}
	// Never allow this internal command to load rules in the caller's namespace.
	own, e1 := os.Readlink("/proc/self/ns/net")
	init, e2 := os.Readlink("/proc/1/ns/net")
	if e1 != nil || e2 != nil || own == init {
		return fmt.Errorf("firewall check requires an isolated network namespace")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1024*1024))
	if err != nil {
		return err
	}
	if _, err = firewallExec(ctx, string(data), tool+"-restore", "--noflush"); err != nil {
		return err
	}
	out, err := firewallExec(ctx, "", tool, "-S")
	if err == nil {
		fmt.Print(out)
	}
	return err
}

func verifyFirewall(expected, live map[string][]string, defaults FirewallDefaults) error {
	for tool, rules := range expected {
		actual := live[tool]
		for i, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			v := verdict([]string{defaults.In, defaults.Out, defaults.Route}[i])
			// UFW implements reject through its reject chain and a DROP policy.
			if v == "REJECT" {
				v = "DROP"
			}
			if !slices.Contains(actual, "-P "+chain+" "+v) {
				return fmt.Errorf("%s policy for %s differs from target", tool, chain)
			}
		}
		expectedChains, actualChains := map[string][]string{}, map[string][]string{}
		for _, line := range rules {
			if strings.HasPrefix(line, "-A ") {
				chain := strings.Fields(line)[1]
				expectedChains[chain] = append(expectedChains[chain], line)
			}
		}
		for _, line := range actual {
			if strings.HasPrefix(line, "-A ") {
				chain := strings.Fields(line)[1]
				actualChains[chain] = append(actualChains[chain], line)
			}
		}
		prefix := "ufw"
		if tool == "ip6tables" {
			prefix = "ufw6"
		}
		for _, direction := range []string{"input", "output", "forward"} {
			user := prefix + "-user-" + direction
			before := prefix + "-before-" + direction
			if !slices.Equal(expectedChains[user], actualChains[user]) {
				return fmt.Errorf("%s user rules differ in %s", tool, user)
			}
			expectedChains[before] = append(expectedChains[before], "-A "+before+" -j "+user)
		}
		for chain, entries := range expectedChains {
			if !slices.Equal(entries, actualChains[chain]) {
				return fmt.Errorf("%s staged rules differ in %s", tool, chain)
			}
		}
	}
	return nil
}

func firewallLock(config Config, blocking bool) (*os.File, error) {
	f, err := os.OpenFile(config.StatePath+".ufw.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	flags := syscall.LOCK_EX
	if !blocking {
		flags |= syscall.LOCK_NB
	}
	if err = syscall.Flock(int(f.Fd()), flags); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func firewallJournalPath(c Config) string { return c.StatePath + ".ufw.json" }

func readFirewallJournal(c Config) (firewallJournal, error) {
	var j firewallJournal
	b, err := os.ReadFile(firewallJournalPath(c))
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err == nil {
		err = json.Unmarshal(b, &j)
	}
	return j, err
}

func writeFirewallFiles(files map[string]string) error {
	for _, name := range ufwFiles {
		path := filepath.Join("/etc", name)
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("cannot safely replace %s", path)
		}
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(current) == files[name] {
			continue
		}
		if err := AtomicWrite(path, []byte(files[name]), fi.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func restoreFirewall(ctx context.Context, c Config, j *firewallJournal, boot bool, reason string) error {
	if j.Pending == nil {
		return nil
	}
	err := writeFirewallFiles(j.Pending.Backup)
	if err == nil && !boot {
		if setting(j.Pending.Backup["ufw/ufw.conf"], "ENABLED") == "yes" {
			_, err = firewallExec(ctx, "", "ufw", "reload")
		} else {
			_, err = firewallExec(ctx, "", "ufw", "--force", "disable")
		}
	}
	if err != nil {
		j.Attempt = &FirewallReceipt{ID: j.Pending.ID, Status: "failed", Error: "rollback: " + err.Error(), Event: j.Pending.Event, EventID: j.Pending.EventID, Changed: j.Pending.Changed}
		_ = WriteJSON(firewallJournalPath(c), j)
		return err
	}
	j.Attempt = &FirewallReceipt{ID: j.Pending.ID, Status: "rolled_back", Error: reason, Event: j.Pending.Event, EventID: j.Pending.EventID, Changed: j.Pending.Changed}
	j.DriftPaused = j.DriftPaused || j.Pending.Event == "drift"
	j.Pending = nil
	return WriteJSON(firewallJournalPath(c), j)
}

func RecoverFirewall(ctx context.Context, c Config, boot, force bool) error {
	lock, err := firewallLock(c, boot || force)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	j, err := readFirewallJournal(c)
	if err != nil || j.Pending == nil || (!boot && !force && time.Now().Unix() < j.Pending.Deadline) {
		return err
	}
	return restoreFirewall(ctx, c, &j, boot, "publication was not confirmed")
}

func (m *firewallManager) scan(ctx context.Context, confirm func(context.Context, string, bool) error) bool {
	if time.Now().Before(m.Next) {
		return false
	}
	m.Next = time.Now().Add(30 * time.Second)
	o, files, liveHash := collectFirewall(ctx)
	m.Observation = &o
	lock, err := firewallLock(m.Config, false)
	if err != nil {
		return true
	}
	defer lock.Close()
	j, err := readFirewallJournal(m.Config)
	if err != nil {
		o.Blocked = append(o.Blocked, "cannot read firewall journal")
		return true
	}
	m.Receipt = j.Attempt
	if j.Confirmed != "" && firewallFingerprint(files) == firewallFingerprint(j.Files) && liveHash == j.LiveHash {
		o.Blocked = nil
	}
	if j.Pending != nil {
		_ = restoreFirewall(ctx, m.Config, &j, false, "agent restarted before confirmation")
		m.Receipt = j.Attempt
	} else if j.Confirmed != "" && !j.DriftPaused &&
		files != nil && (firewallFingerprint(files) != firewallFingerprint(j.Files) || liveHash != j.LiveHash) {
		m.install(ctx, &j, j.Confirmed, files, j.Files, firewallDefaults(j.Files["default/ufw"]), true, confirm)
	}
	return true
}

func (m *firewallManager) apply(ctx context.Context, t FirewallTarget, claim func(context.Context, string) error, confirm func(context.Context, string, bool) error) {
	if t.NodeID != m.Config.NodeID || !ruleID.MatchString(t.ID) {
		return
	}
	lock, err := firewallLock(m.Config, false)
	if err != nil {
		return
	}
	defer lock.Close()
	j, err := readFirewallJournal(m.Config)
	if err != nil || j.Pending != nil || (j.Attempt != nil && j.Attempt.ID == t.ID) {
		return
	}
	o, old, _ := collectFirewall(ctx)
	m.Observation = &o
	fail := func(err error) {
		j.Attempt = &FirewallReceipt{ID: t.ID, Status: "failed", Error: err.Error()}
		if WriteJSON(firewallJournalPath(m.Config), j) == nil {
			m.Receipt = j.Attempt
		}
	}
	if o.Status != "active" || o.Fingerprint != t.Fingerprint || (j.Confirmed == "" && len(o.Blocked) != 0) ||
		len(t.Protection) == 0 {
		fail(fmt.Errorf("UFW state changed or cannot be safely managed; refresh preview"))
		return
	}
	if err := claim(ctx, t.ID); err != nil {
		return
	}
	if j.Confirmed == "" {
		staged, err := stagedFirewall(ctx, old)
		if err == nil {
			err = verifyFirewall(staged, o.Live, o.Defaults)
		}
		if err != nil {
			fail(fmt.Errorf("live UFW rules differ from import: %w", err))
			return
		}
	}
	baseline := old
	if j.Confirmed != "" {
		baseline = j.Files
	}
	desired, err := renderFirewall("/", baseline, t, j.Confirmed == "")
	if err != nil {
		fail(err)
		return
	}
	m.install(ctx, &j, t.ID, old, desired, t.Defaults, false, confirm)
}

func (m *firewallManager) install(ctx context.Context, j *firewallJournal, id string, old, desired map[string]string,
	defaults FirewallDefaults, drift bool, confirm func(context.Context, string, bool) error) {
	path := firewallJournalPath(m.Config)
	event, eventID := "", ""
	var changed []string
	if drift {
		event, eventID = "drift", UUID()
		for _, name := range ufwFiles {
			if old[name] != desired[name] {
				changed = append(changed, name)
			}
		}
		if len(changed) == 0 {
			changed = append(changed, "kernel filter rules")
		}
	}
	fail := func(err error) {
		j.DriftPaused = j.DriftPaused || drift
		j.Attempt = &FirewallReceipt{ID: id, Status: "failed", Error: err.Error(), Event: event, EventID: eventID, Changed: changed}
		if WriteJSON(path, j) == nil {
			m.Receipt = j.Attempt
		}
	}
	if _, err := firewallExec(ctx, "", "systemctl", "is-active", "--quiet", "fail2ban-mate-firewall.timer"); err != nil {
		fail(fmt.Errorf("firewall rollback timer is inactive"))
		return
	}
	expected, err := stagedFirewall(ctx, desired)
	if err != nil {
		fail(err)
		return
	}
	j.Pending = &firewallPending{ID: id, Deadline: time.Now().Add(120 * time.Second).Unix(), Backup: old, Event: event, EventID: eventID, Changed: changed}
	if err = WriteJSON(path, j); err != nil {
		j.Pending = nil
		fail(err)
		return
	}
	applyCtx, cancel := context.WithDeadline(ctx, time.Unix(j.Pending.Deadline-5, 0))
	defer cancel()
	err = writeFirewallFiles(desired)
	if err == nil {
		_, err = firewallExec(applyCtx, "", "ufw", "reload")
	}
	var live map[string][]string
	if err == nil {
		live, _, err = liveFirewall(applyCtx, setting(desired["default/ufw"], "IPV6") == "yes")
	}
	if err == nil {
		err = verifyFirewall(expected, live, defaults)
	}
	if err == nil {
		err = confirm(applyCtx, id, drift)
	}
	if err == nil {
		commit := firewallJournal{Confirmed: id, Files: desired, LiveHash: firewallFingerprint(live),
			Attempt: &FirewallReceipt{ID: id, Status: "applied", Event: event, EventID: eventID, Changed: changed}}
		err = WriteJSON(path, &commit)
		if err == nil {
			*j = commit
		}
	}
	if err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = restoreFirewall(rollbackCtx, m.Config, j, false, err.Error())
	}
	m.Receipt = j.Attempt
	m.Next = time.Time{}
}
