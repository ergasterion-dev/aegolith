package run

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"localhost": true, "LocalHost": true, "127.0.0.1": true, "127.9.9.9": true, "::1": true,
		"localhost.": false, "a.localhost": false, "10.0.0.1": false, "waf.example.test": false,
		"": false, "[::1]": false, "::ffff:127.0.0.1": true,
	} {
		if got := IsLoopback(host); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestDialPinsLocalhost checks that "localhost" is dialled at a loopback
// address without asking a resolver, which could name another host.
func TestDialPinsLocalhost(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	var lookups atomic.Int32
	dialer := &net.Dialer{Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			lookups.Add(1)
			return nil, errors.New("no resolver in this test")
		},
	}}
	dial := pinnedDial(dialer)
	for _, host := range []string{"localhost", "LOCALHOST", "localhost."} {
		conn, err := dial(context.Background(), "tcp", net.JoinHostPort(host, port))
		if err != nil {
			t.Fatalf("dialling %s: %v", host, err)
		}
		addr := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
		conn.Close()
		if !addr.IsLoopback() {
			t.Errorf("%s was dialled at %s", host, addr)
		}
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("the resolver was asked %d times", n)
	}
	// Other names still go to the resolver.
	if _, err := dial(context.Background(), "tcp", net.JoinHostPort("waf.example.test", port)); err == nil {
		t.Error("a name the resolver cannot answer was dialled")
	}
	if lookups.Load() == 0 {
		t.Error("another name did not reach the resolver")
	}
}

func TestNewClientDialsLocalhostAtLoopback(t *testing.T) {
	t.Parallel()
	var remote atomic.Value
	u := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
		remote.Store(r.RemoteAddr)
	})
	tr, ok := NewClient(testTimeout).Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		t.Fatal("the client's transport does not pin its dial")
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("the client skips TLS verification")
	}
	u.Host = net.JoinHostPort("localhost", u.Port())
	resp, err := NewClient(testTimeout).Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	addr, err := netip.ParseAddrPort(remote.Load().(string))
	if err != nil || !addr.Addr().IsLoopback() {
		t.Errorf("request came from %v", remote.Load())
	}
}
