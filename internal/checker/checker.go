package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/August26/proxycheck-go/internal/model"
)

// RunBatch concurrently processes all proxies and returns their check results.
func RunBatch(ctx context.Context, proxies []model.ProxyInput, cfg model.Config) []model.ProxyCheckResult {
	resultsCh := make(chan model.ProxyCheckResult, len(proxies))
	wg := &sync.WaitGroup{}

	sem := make(chan struct{}, cfg.Concurrency)

	for _, p := range proxies {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			res := checkOneProxyWithRetries(ctx, p, cfg)
			resultsCh <- res
		}()
	}

	wg.Wait()
	close(resultsCh)

	out := make([]model.ProxyCheckResult, 0, len(proxies))
	for r := range resultsCh {
		out = append(out, r)
	}
	return out
}

// checkOneProxyWithRetries attempts to check a proxy multiple times (cfg.Retries).
// We stop early if we get a successful (Alive=true) result.
// LatencyMs is taken from the first successful attempt.
// If all attempts fail, we return the last attempt's result.
func checkOneProxyWithRetries(ctx context.Context, p model.ProxyInput, cfg model.Config) model.ProxyCheckResult {
	var finalRes model.ProxyCheckResult
	var firstSuccessLatency int64
	var haveSuccess bool

	for attempt := 1; attempt <= cfg.Retries; attempt++ {
		res := checkOneProxyOnce(ctx, p, cfg)

		finalRes = res

		if res.Alive {
			if !haveSuccess {
				firstSuccessLatency = res.LatencyMs
			}
			haveSuccess = true
			break
		}
	}

	if haveSuccess {
		finalRes.LatencyMs = firstSuccessLatency
		finalRes.Alive = true
	} else {
		finalRes.Alive = false
	}

	return finalRes
}

// checkOneProxyOnce decides which checker to run (http/https vs socks5).
func checkOneProxyOnce(ctx context.Context, p model.ProxyInput, cfg model.Config) model.ProxyCheckResult {
	proxyCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	start := time.Now()

	var res model.ProxyCheckResult
	switch cfg.ProxyType {
    case "socks5":
        res = checkSOCKS5(proxyCtx, p, cfg.Resolver)
		res.Capabilities = guessCapabilities(proxyCtx, p)
    case "https":
        res = checkHTTPS(proxyCtx, p, cfg.Resolver)
    default:
        res = checkSOCKS5(proxyCtx, p, cfg.Resolver)
		res.Capabilities = guessCapabilities(proxyCtx, p)
    }

	res.LatencyMs = time.Since(start).Milliseconds()

	// fraud score now uses the ISP/org
	if res.IP != "" {
		res.FraudScore = EstimateFraudScore(res.IP, res.ISP)
	}

	return res
}

// guessCapabilities is a placeholder until we implement full SMTP/POP3/IMAP/UDP probing.
// We infer:
// - UDP is generally only possible for SOCKS5
// - SMTP/POP3/IMAP => false until we actively prove it
func guessCapabilities(ctx context.Context, in model.ProxyInput) model.ProxyCapabilities {
	caps := model.ProxyCapabilities{}
	
	// SMTP ports commonly used: 587 (submission), 465 (smtps legacy)
	if probeTCPViaSocks5(ctx, in.Host, in.Port, in.Username, in.Password, "smtp.gmail.com:587") ||
		probeTCPViaSocks5(ctx, in.Host, in.Port, in.Username, in.Password, "smtp.gmail.com:465") {
		caps.SMTP = true
	}

	// POP3 ports: 110 (plain), 995 (SSL)
	if probeTCPViaSocks5(ctx, in.Host, in.Port, in.Username, in.Password, "pop.gmail.com:995") ||
		probeTCPViaSocks5(ctx, in.Host, in.Port, in.Username, in.Password, "pop.gmail.com:110") {
		caps.POP3 = true
	}

	// IMAP ports: 143 (plain), 993 (SSL)
	if probeTCPViaSocks5(ctx, in.Host, in.Port, in.Username, in.Password, "imap.gmail.com:993") ||
		probeTCPViaSocks5(ctx, in.Host, in.Port, in.Username, in.Password, "imap.gmail.com:143") {
		caps.IMAP = true
	}

	// UDP capability check (SOCKS5 UDP ASSOCIATE)
	caps.UDP = supportsSocks5UDP(ctx, in.Host, in.Port, in.Username, in.Password)

	return caps
}

// ------------------------------------------------------------------------------------
// HTTP(S) proxy checker implementation
// ------------------------------------------------------------------------------------

// httpbinResponse matches the fields we care about from https://httpbin.org/get.
type httpbinResponse struct {
    Origin  string            `json:"origin"`  // what IP httpbin thinks we are
    Headers map[string]string `json:"headers"` // headers seen by httpbin
	Status  int 		      `json:"status"`
}

// checkHTTPS tries to reach probeURL using the given proxy as HTTP(S) CONNECT proxy.
func checkHTTPS(ctx context.Context, p model.ProxyInput, resolver model.IPResolver) model.ProxyCheckResult {
	out := model.ProxyCheckResult{
		Input: p,
	}

	client, err := buildHTTPClientForProxy(p, ctx)
	if err != nil {
		out.Alive = false
		out.Error = "client_build_error: " + err.Error()
		return out
	}

	// Step 2: get anonymity headers
	hb, err := fetchHttpbin(ctx, client)
	if err == nil {
		out.RawHeaders = hb.Headers

		// httpbin's "origin" may be multiple IPs in "a, b", возьмём первый
		reportedIP := firstIPToken(hb.Origin)

		out.Anonymity = DetermineAnonymity(AnonymityInput{
			IPReportedByServer: reportedIP,
			ProxyExitIP:        hb.Origin,
			HeadersObserved:    hb.Headers,
		})
	} else {
		// if httpbin fails, fallback
		out.Anonymity = "unknown"
	}

	info, err := resolver.Lookup(hb.Origin)
	if err != nil {
		return out
	}

	out.Alive = true
	out.StatusCode = hb.Status
	out.IP = hb.Origin
	out.Country = info.Country
	out.City = info.City
	out.ISP = info.ISP // we'll treat ASN org as ISP for now

	return out
}

// ------------------------------------------------------------------------------------
// SOCKS5 proxy checker implementation
// ------------------------------------------------------------------------------------

func checkSOCKS5(ctx context.Context, p model.ProxyInput, resolver model.IPResolver) model.ProxyCheckResult {
	out := model.ProxyCheckResult{
		Input: p,
	}

	client, err := buildSOCKS5HTTPClient(p, ctx)
	if err != nil {
		out.Alive = false
		out.Error = "client_build_error: " + err.Error()
		return out
	}

	hb, err := fetchHttpbin(ctx, client)
	if err == nil {
		out.RawHeaders = hb.Headers

		reportedIP := firstIPToken(hb.Origin)

		out.Anonymity = DetermineAnonymity(AnonymityInput{
			IPReportedByServer: reportedIP,
			ProxyExitIP:        hb.Origin,
			HeadersObserved:    hb.Headers,
		})
	} else {
		out.Anonymity = "unknown"
	}

	info, err := resolver.Lookup(hb.Origin)
	if err != nil {
		return out
	}

	out.Alive = true
	out.StatusCode = hb.Status
	out.IP = hb.Origin
	out.Country = info.Country
	out.City = info.City
	out.ISP = info.ISP

	return out
}

// ------------------------------------------------------------------------------------
// Shared helpers for performing the probe request and building clients
// ------------------------------------------------------------------------------------

// buildHTTPClientForProxy builds an *http.Client that tunnels through an HTTP(S) proxy.
func buildHTTPClientForProxy(p model.ProxyInput, ctx context.Context) (*http.Client, error) {
	// We will construct URL like:
	//   http://user:pass@host:port
	// or https://..., but for CONNECT proxy usually scheme "http" is fine.
	u := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", p.Host, p.Port),
	}
	if p.Username != "" || p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
		// We also set DialContext with timeout caps, though the per-request context still dominates.
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second, // base dial timeout; final timeout enforced by ctx too
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		// We don't set Timeout here because we pass context with deadline per request.
	}

	return client, nil
}

// buildSOCKS5HTTPClient builds an *http.Client that uses a SOCKS5 proxy
// to perform HTTP(S) requests (we still do a normal HTTP GET to probeURL,
// but the TCP connection to the remote will be established through SOCKS5).
func buildSOCKS5HTTPClient(p model.ProxyInput, ctx context.Context) (*http.Client, error) {
	addr := fmt.Sprintf("%s:%d", p.Host, p.Port)

	var auth *proxy.Auth
	if p.Username != "" || p.Password != "" {
		auth = &proxy.Auth{
			User:     p.Username,
			Password: p.Password,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", addr, auth, &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	// dialer.DialContext doesn't exist in x/net/proxy, it's Dial only.
	// So we wrap it to satisfy http.Transport.DialContext.
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		type d interface {
			Dial(network, address string) (net.Conn, error)
		}
		if dd, ok := dialer.(d); ok {
			return dd.Dial(network, addr)
		}
		return nil, errors.New("socks5 dialer does not implement Dial")
	}

	transport := &http.Transport{
		DialContext:           dialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
	}
	return client, nil
}

func fetchHttpbin(ctx context.Context, client *http.Client) (httpbinResponse, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/get", nil)
    if err != nil {
        return httpbinResponse{}, err
    }

    resp, err := client.Do(req)
    if err != nil {
        return httpbinResponse{}, err
    }
    defer resp.Body.Close()

    var parsed httpbinResponse
    dec := json.NewDecoder(resp.Body)
    if err := dec.Decode(&parsed); err != nil {
        return httpbinResponse{}, err
    }
	parsed.Status = resp.StatusCode

    return parsed, nil
}

func firstIPToken(origin string) string {
	if origin == "" {
		return ""
	}
	parts := strings.Split(origin, ",")
	return strings.TrimSpace(parts[0])
}
