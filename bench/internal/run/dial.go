package run

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// IsLoopback reports whether host is "localhost" or a loopback address. No
// name is looked up.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// loopbackAddrs are where the name localhost is dialled.
var loopbackAddrs = []string{"127.0.0.1", "::1"}

// pinnedDial returns a dial function that connects the name localhost, in any
// case and with or without a final dot, to a loopback address without asking
// a resolver, which could send it elsewhere. Other addresses are dialled with
// d as given.
func pinnedDial(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
			return d.DialContext(ctx, network, addr)
		}
		var errs []error
		for _, ip := range loopbackAddrs {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}
