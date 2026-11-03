package mate

import "time"

// TransportState contains only connection policy; timers and I/O stay in Agent.
type TransportState struct {
	Failures int
	Drops    []time.Time
	Fallback bool
	Reason   string
	NextDial time.Time
}

func (t *TransportState) Failure(now time.Time) {
	t.Failures++
	recent := []time.Time{}
	for _, d := range t.Drops {
		if now.Sub(d) <= 5*time.Minute {
			recent = append(recent, d)
		}
	}
	t.Drops = append(recent, now)
	if t.Failures >= 3 || len(t.Drops) >= 3 {
		t.Fallback = true
		t.Reason = "WebSocket 连续失败或频繁断开，已切换 HTTP"
		t.NextDial = now.Add(5 * time.Minute)
	} else {
		t.NextDial = now.Add(time.Duration(1<<min(t.Failures, 4)) * time.Second)
	}
}
func (t *TransportState) Stable(duration time.Duration) bool {
	if duration < 60*time.Second {
		return false
	}
	t.Failures = 0
	restored := t.Fallback
	t.Fallback = false
	t.Reason = ""
	return restored
}
