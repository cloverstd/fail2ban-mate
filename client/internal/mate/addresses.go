package mate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Use the control plane itself to observe each public egress address. Interface
// addresses can be private or behind NAT and must not be presented as public IPs.
func reportAddress(ctx context.Context, server, token, version, family string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, family, address)
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, "GET", server+"/api/agent/v1/addresses", nil)
	if err != nil {
		return fmt.Errorf("invalid control plane URL")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "fail2ban-mate-client/"+version)
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s address probe unavailable", family)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1024))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("address probe status %d", res.StatusCode)
	}
	return nil
}

func monitorAddresses(ctx context.Context, server, token, version string) {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		for _, family := range []string{"tcp4", "tcp6"} {
			// One unavailable family must never interrupt synchronization or the
			// other family's probe. The server keeps the last observed address.
			_ = reportAddress(ctx, server, token, version, family)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
