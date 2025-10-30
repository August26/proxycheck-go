package parser

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/August26/proxycheck-go/internal/model"
)

// LoadFromFile reads a file line by line and returns a slice of ProxyInput.
// It supports formats:
//   ip:port
//   ip:port:username:password
//   username:password@ip:port
//
// Empty lines and lines starting with '#' are ignored.
func LoadFromFile(path string) ([]model.ProxyInput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	var out []model.ProxyInput
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}

		pi, err := parseProxyLine(line)
		if err != nil {
			// For now: skip invalid lines silently.
			// Later we can log debug info with slog.
			continue
		}
		out = append(out, pi)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan input file: %w", err)
	}
	return out, nil
}

// parseProxyLine parses a single proxy line into ProxyInput.
//
// Supported:
//   1. ip:port
//   2. ip:port:user:pass
//   3. user:pass@ip:port
//
func parseProxyLine(line string) (model.ProxyInput, error) {
	// Case 1: username:password@ip:port
	if strings.Contains(line, "@") {
		parts := strings.SplitN(line, "@", 2)
		if len(parts) != 2 {
			return model.ProxyInput{}, fmt.Errorf("invalid proxy format: %q", line)
		}
		auth := parts[0]
		hostport := parts[1]

		user, pass, err := splitUserPass(auth)
		if err != nil {
			return model.ProxyInput{}, err
		}

		host, port, err := splitHostPort(hostport)
		if err != nil {
			return model.ProxyInput{}, err
		}

		return model.ProxyInput{
			Host:     host,
			Port:     port,
			Username: user,
			Password: pass,
			Type:     "",
			Raw:      line,
		}, nil
	}

	// No "@"
	// Could be:
	//   ip:port
	//   ip:port:user:pass
	col := strings.Split(line, ":")

	switch len(col) {
	case 2:
		// ip:port
		host := col[0]
		portStr := col[1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return model.ProxyInput{}, fmt.Errorf("invalid port in %q", line)
		}
		return model.ProxyInput{
			Host: host,
			Port: port,
			Raw:  line,
		}, nil

	case 4:
		// ip:port:user:pass
		host := col[0]
		portStr := col[1]
		user := col[2]
		pass := col[3]

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return model.ProxyInput{}, fmt.Errorf("invalid port in %q", line)
		}

		return model.ProxyInput{
			Host:     host,
			Port:     port,
			Username: user,
			Password: pass,
			Raw:      line,
		}, nil

	default:
		return model.ProxyInput{}, fmt.Errorf("unrecognized proxy format: %q", line)
	}
}

func splitUserPass(s string) (string, string, error) {
	up := strings.SplitN(s, ":", 2)
	if len(up) != 2 {
		return "", "", fmt.Errorf("invalid auth (expected user:pass): %q", s)
	}
	return up[0], up[1], nil
}

// splitHostPort handles host:port for IPv4 or hostname.
func splitHostPort(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid host:port: %q", s)
	}
	host := parts[0]
	portStr := parts[1]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return host, port, nil
}
