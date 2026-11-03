package mate

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func Active(p Policy, at int64) bool { return p.ExpiresAt == nil || *p.ExpiresAt > at }
func IsAllowed(s *State, ip string, at int64) bool {
	for _, p := range s.Policies {
		if p.IP == ip && Active(p, at) {
			return true
		}
	}
	return false
}

// The ownership journal is written BEFORE adding an ignore entry, so a crash
// between the command and its acknowledgement does not lose cleanup ownership.
func ApplyPolicies(ctx context.Context, r Runner, s *State, path string, at int64) error {
	active := map[string]bool{}
	for _, p := range s.Policies {
		if Active(p, at) {
			active[p.IP] = true
		}
	}
	names, err := Jails(ctx, r)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, jail := range names {
		present[jail] = true
		if len(active) == 0 && len(s.Owned) == 0 {
			continue
		}
		ignored, err := r.Run(ctx, "get", jail, "ignoreip")
		if err != nil {
			return err
		}
		for ip := range active {
			key := jail + "\n" + ip
			if !Ignored(ignored, ip) {
				s.Owned[key] = true
				if err = WriteJSON(path, s); err != nil {
					return err
				}
				if _, err = r.Run(ctx, "set", jail, "addignoreip", ip); err != nil {
					return err
				}
			}
			if _, banned := s.Known[jail][ip]; banned {
				if _, err = r.Run(ctx, "set", jail, "unbanip", ip); err != nil {
					return err
				}
			}
		}
		for key := range s.Owned {
			parts := strings.SplitN(key, "\n", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid ownership journal")
			}
			if parts[0] != jail || active[parts[1]] {
				continue
			}
			// delignoreip removes only this exact managed address, never a pre-existing CIDR.
			exact := false
			for _, v := range IPs(ignored) {
				if v == parts[1] {
					exact = true
				}
			}
			if exact {
				if _, err = r.Run(ctx, "set", jail, "delignoreip", parts[1]); err != nil {
					return err
				}
			}
			delete(s.Owned, key)
		}
	}
	for key := range s.Owned {
		jail := strings.SplitN(key, "\n", 2)[0]
		if !present[jail] {
			delete(s.Owned, key)
		}
	}
	s.AppliedPolicyRevision = s.PolicyRevision
	return WriteJSON(path, s)
}
func Execute(ctx context.Context, r Runner, s *State, cmd Command, path string) Result {
	if done, ok := s.Completed[cmd.ID]; ok {
		return done
	}
	result := Result{ID: cmd.ID, Status: "failed"}
	ip, err := canonical(cmd.IP)
	switch {
	case err != nil || !jailName.MatchString(cmd.Jail):
		result.Error = "invalid command target"
	case cmd.ExpiresAt <= time.Now().Unix():
		result.Error = "command expired"
	case cmd.Kind != "ban" && cmd.Kind != "unban":
		result.Error = "unsupported operation"
	case cmd.Kind == "ban" && IsAllowed(s, ip, time.Now().Unix()):
		result.Error = "IP is globally whitelisted"
	default:
		out, e := r.Run(ctx, "get", cmd.Jail, "banip")
		if e != nil {
			result.Error = e.Error()
			break
		}
		banned := false
		for _, v := range IPs(out) {
			if v == ip {
				banned = true
			}
		}
		if (cmd.Kind == "ban" && banned) || (cmd.Kind == "unban" && !banned) {
			result.Status = "succeeded"
			break
		}
		op := "banip"
		if cmd.Kind == "unban" {
			op = "unbanip"
		}
		if _, e = r.Run(ctx, "set", cmd.Jail, op, ip); e != nil {
			result.Error = e.Error()
		} else {
			result.Status = "succeeded"
		}
	}
	s.Completed[cmd.ID] = result
	s.CompletedAt[cmd.ID] = time.Now().Unix()
	s.Results[cmd.ID] = result
	// If persistence fails, the caller terminates before reporting success.
	return result
}
