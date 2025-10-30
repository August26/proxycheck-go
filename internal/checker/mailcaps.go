package checker

import (
	"context"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// probeTCPViaSocks5 tries to open a TCP connection via the given SOCKS5 proxy
// to targetAddr (e.g. "smtp.gmail.com:587"). If we get a TCP handshake within
// timeout, we consider that capability allowed.
func probeTCPViaSocks5(ctx context.Context, proxyHost string, proxyPort int, user, pass string, targetAddr string) bool {
	socksAddr := net.JoinHostPort(proxyHost, strconv.Itoa(proxyPort))

	var auth *proxy.Auth
	if user != "" || pass != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}

	dialer, err := proxy.SOCKS5("tcp", socksAddr, auth, &net.Dialer{
		Timeout:   4 * time.Second,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return false
	}

	// context-aware dial wrapper
	type d interface {
		Dial(network, addr string) (net.Conn, error)
	}
	sd, ok := dialer.(d)
	if !ok {
		return false
	}

	// we'll emulate context timeout manually:
	done := make(chan bool, 1)
	var conn net.Conn
	var dialErr error
	go func() {
		c, err := sd.Dial("tcp", targetAddr)
		conn = c
		dialErr = err
		done <- true
	}()

	select {
	case <-ctx.Done():
		return false
	case <-done:
		if dialErr != nil {
			return false
		}
		if conn != nil {
			_ = conn.Close()
		}
		return true
	}
}
