package mate

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type FirewallRule struct {
	ID              string `json:"id"`
	Priority        int    `json:"priority"`
	Enabled         bool   `json:"enabled"`
	Direction       string `json:"direction"`
	Action          string `json:"action"`
	Family          string `json:"family"`
	Protocol        string `json:"protocol"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	SourcePort      string `json:"source_port"`
	DestinationPort string `json:"destination_port"`
	InInterface     string `json:"in_interface"`
	OutInterface    string `json:"out_interface"`
	Comment         string `json:"comment"`
}

type FirewallDefaults struct {
	In    string `json:"in"`
	Out   string `json:"out"`
	Route string `json:"route"`
}

type SSHProtection struct {
	Source string `json:"source"`
	Port   int    `json:"port"`
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var ruleID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var portSyntax = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?$`)

func network(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil && !p.Addr().Is4In6() {
		return p.Masked(), nil
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.Zone() == "" && !ip.Is4In6() {
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid address or CIDR")
}

func ports(s string) (int, int, error) {
	if s == "" {
		return 1, 65535, nil
	}
	if !portSyntax.MatchString(s) {
		return 0, 0, fmt.Errorf("invalid port range")
	}
	a, b, rangePort := strings.Cut(s, ":")
	minPort, _ := strconv.Atoi(a)
	maxPort := minPort
	if rangePort {
		maxPort, _ = strconv.Atoi(b)
	}
	if minPort < 1 || maxPort < minPort || maxPort > 65535 {
		return 0, 0, fmt.Errorf("invalid port range")
	}
	return minPort, maxPort, nil
}

func verdict(action string) string {
	switch action {
	case "allow":
		return "ACCEPT"
	case "deny":
		return "DROP"
	case "reject":
		return "REJECT"
	default:
		return ""
	}
}

func (r FirewallRule) validate() error {
	if len([]rune(r.Comment)) > 256 || !ruleID.MatchString(r.ID) || !slices.Contains([]string{"in", "out", "route"}, r.Direction) ||
		verdict(r.Action) == "" || !slices.Contains([]string{"any", "ipv4", "ipv6"}, r.Family) ||
		!slices.Contains([]string{"any", "tcp", "udp", "icmp"}, r.Protocol) {
		return fmt.Errorf("invalid rule identity, direction, action, family or protocol")
	}
	for _, iface := range []string{r.InInterface, r.OutInterface} {
		if iface != "" && !interfaceName.MatchString(iface) {
			return fmt.Errorf("invalid interface")
		}
	}
	if (r.Direction == "in" && r.OutInterface != "") || (r.Direction == "out" && r.InInterface != "") {
		return fmt.Errorf("interface does not match rule direction")
	}
	for _, addr := range []string{r.Source, r.Destination} {
		if addr == "" {
			continue
		}
		p, err := network(addr)
		if err != nil || r.Family == "any" || p.Addr().Is4() != (r.Family == "ipv4") {
			return fmt.Errorf("address does not match IP family")
		}
	}
	for _, port := range []string{r.SourcePort, r.DestinationPort} {
		if _, _, err := ports(port); err != nil || (port != "" && r.Protocol != "tcp" && r.Protocol != "udp") {
			return fmt.Errorf("ports require TCP or UDP")
		}
	}
	return nil
}

func (r FirewallRule) compile(v6 bool) (string, string) {
	prefix, any := "ufw", "0.0.0.0/0"
	if v6 {
		prefix, any = "ufw6", "::/0"
	}
	chain := map[string]string{"in": "input", "out": "output", "route": "forward"}[r.Direction]
	args := []string{"-A", prefix + "-user-" + chain}
	if r.Source != "" {
		p, _ := network(r.Source)
		args = append(args, "-s", p.String())
	}
	if r.Destination != "" {
		p, _ := network(r.Destination)
		args = append(args, "-d", p.String())
	}
	if r.InInterface != "" {
		args = append(args, "-i", r.InInterface)
	}
	if r.OutInterface != "" {
		args = append(args, "-o", r.OutInterface)
	}
	protocol := r.Protocol
	if v6 && protocol == "icmp" {
		protocol = "ipv6-icmp"
	}
	if protocol != "any" {
		args = append(args, "-p", protocol)
	}
	if r.SourcePort != "" {
		args = append(args, "--sport", r.SourcePort)
	}
	if r.DestinationPort != "" {
		args = append(args, "--dport", r.DestinationPort)
	}
	action, direction := r.Action, r.Direction
	if r.InInterface != "" {
		direction = "in_" + r.InInterface
	}
	if r.OutInterface != "" {
		direction = "out_" + r.OutInterface
		if r.InInterface != "" {
			direction = "in_" + r.InInterface + "!" + direction
		}
	}
	if r.Direction == "route" {
		action = "route:" + action
		if direction == "route" {
			direction = "in"
		}
	}
	value := func(v, fallback string) string {
		if v == "" {
			return fallback
		}
		return v
	}
	tuple := fmt.Sprintf("### tuple ### %s %s %s %s %s %s %s comment=%s", action, r.Protocol,
		value(r.DestinationPort, "any"), value(r.Destination, any), value(r.SourcePort, "any"),
		value(r.Source, any), direction, hex.EncodeToString([]byte(r.Comment)))
	if r.Protocol == "icmp" {
		// UFW CLI has no ICMP rule tuple. The framework still loads this rule.
		tuple = "# ICMP rule managed by Fail2ban Mate"
	}
	args = append(args, "-m", "comment", "--comment", "mate:"+r.ID, "-j", verdict(r.Action))
	return tuple, strings.Join(args, " ")
}

func parseUserRule(line string, v6 bool, comment string) (FirewallRule, error) {
	fields := strings.Fields(line)
	r := FirewallRule{ID: UUID(), Enabled: true, Family: "ipv4", Protocol: "any", Comment: comment}
	if v6 {
		r.Family = "ipv6"
	}
	prefix := "ufw"
	if v6 {
		prefix = "ufw6"
	}
	r.Direction = map[string]string{prefix + "-user-input": "in", prefix + "-user-output": "out", prefix + "-user-forward": "route"}[fields[1]]
	for i := 2; i+1 < len(fields); i += 2 {
		key, value := fields[i], fields[i+1]
		switch key {
		case "-s":
			r.Source = value
		case "-d":
			r.Destination = value
		case "-i":
			r.InInterface = value
		case "-o":
			r.OutInterface = value
		case "-p":
			r.Protocol = value
			if value == "ipv6-icmp" || value == "icmpv6" {
				r.Protocol = "icmp"
			}
		case "--sport":
			r.SourcePort = value
		case "--dport":
			r.DestinationPort = value
		case "-j":
			r.Action = map[string]string{"ACCEPT": "allow", "DROP": "deny", "REJECT": "reject"}[value]
		case "-m":
			if value != "tcp" && value != "udp" && value != "comment" {
				return r, fmt.Errorf("unsupported match %s", value)
			}
		case "--comment":
			if !strings.HasPrefix(value, "mate:") {
				return r, fmt.Errorf("unsupported comment match")
			}
			r.ID = strings.TrimPrefix(value, "mate:")
		default:
			return r, fmt.Errorf("unsupported option %s", key)
		}
	}
	if len(fields)%2 != 0 {
		return r, fmt.Errorf("invalid firewall rule")
	}
	return r, r.validate()
}

func userRules(file string, v6 bool) ([]FirewallRule, []string) {
	rules := []FirewallRule{}
	var blocked []string
	inside, comment := false, ""
	prefix := "ufw-user-"
	if v6 {
		prefix = "ufw6-user-"
	}
	for _, line := range strings.Split(file, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "### RULES ###":
			inside = true
		case line == "### END RULES ###", line == "COMMIT":
			inside = false
		case inside && strings.HasPrefix(line, "### tuple ###"):
			_, encoded, _ := strings.Cut(line, " comment=")
			raw, _ := hex.DecodeString(encoded)
			comment = string([]rune(string(raw))[:min(256, len([]rune(string(raw))))])
		case strings.HasPrefix(line, "-A "+prefix+"input "), strings.HasPrefix(line, "-A "+prefix+"output "), strings.HasPrefix(line, "-A "+prefix+"forward "):
			r, err := parseUserRule(line, v6, comment)
			if err != nil || !inside {
				blocked = append(blocked, line)
			} else {
				r.Priority = (len(rules) + 1) * 10
				rules = append(rules, r)
			}
		case inside && line != "" && !strings.HasPrefix(line, "#"):
			blocked = append(blocked, line)
		}
	}
	return rules, blocked
}

// Reject any earlier overlapping deny unless a preceding allow covers the
// complete protected source network, regardless of interface or destination.
func protectSSH(rules []FirewallRule, defaults FirewallDefaults, protections []SSHProtection) error {
	if len(protections) == 0 {
		return fmt.Errorf("configure at least one protected SSH source")
	}
	for _, p := range protections {
		source, err := network(p.Source)
		if err != nil || p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("invalid protected SSH source or port")
		}
		allowed := defaults.In == "allow"
		for _, r := range rules {
			low, high, _ := ports(r.DestinationPort)
			if !r.Enabled || r.Direction != "in" || (r.Protocol != "any" && r.Protocol != "tcp") ||
				(r.Family != "any" && (r.Family == "ipv4") != source.Addr().Is4()) || p.Port < low || p.Port > high {
				continue
			}
			matches, covers := true, true
			if r.Source != "" {
				prefix, _ := network(r.Source)
				matches = prefix.Overlaps(source)
				covers = prefix.Bits() <= source.Bits() && prefix.Contains(source.Addr())
			}
			if !matches {
				continue
			}
			if r.Action != "allow" {
				allowed = false
				break
			}
			if covers && r.Destination == "" && r.SourcePort == "" && r.InInterface == "" {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("rules may block protected SSH source %s port %d", p.Source, p.Port)
		}
	}
	return nil
}
