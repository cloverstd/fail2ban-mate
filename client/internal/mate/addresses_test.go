package mate

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAddressProbeUsesRequestedFamilyAndNodeCredentials(t *testing.T) {
	for _, tc := range []struct{ family, address, other string }{
		{"tcp4", "127.0.0.1:0", "tcp6"},
		{"tcp6", "[::1]:0", "tcp4"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			listener, err := net.Listen(tc.family, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.URL.Path != "/api/agent/v1/addresses" || r.Header.Get("Authorization") != "Bearer test-token" || r.UserAgent() != "fail2ban-mate-client/test" {
					t.Errorf("unexpected address probe metadata")
				}
				w.WriteHeader(http.StatusOK)
			}))
			_ = server.Listener.Close()
			server.Listener = listener
			server.Start()
			defer server.Close()
			if err = reportAddress(context.Background(), server.URL, "test-token", "test", tc.family); err != nil {
				t.Fatal(err)
			}
			if err = reportAddress(context.Background(), server.URL, "test-token", "test", tc.other); err == nil {
				t.Fatal("probe silently used the other address family")
			}
			if requests.Load() != 1 {
				t.Fatalf("unexpected successful probes: %d", requests.Load())
			}
		})
	}
}

func TestMissingFamilyDoesNotStopProbesAndCancellation(t *testing.T) {
	got := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { monitorAddresses(ctx, server.URL, "token", "test"); close(done) }()
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("IPv4 probe did not reach the server")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("address monitor did not stop on cancellation")
	}
}

func TestAddressProbeDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	if err := reportAddress(context.Background(), server.URL, "token", "test", "tcp4"); err == nil || leaked.Load() {
		t.Fatal("probe followed a redirect or accepted a redirect as success")
	}
}
