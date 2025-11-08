package checker

// import "strings"

// ClassifyAnonymity tries to guess anonymity level based on what the
// destination server reports seeing.
//
// We expect to eventually pass in:
// - headers that the remote server received from our proxy
// - the "reported client IP" seen by that server
// - and the exit IP of the proxy
//
// For now we accept a lightweight struct so we can mock it.
type AnonymityInput struct {
	// IPReportedByServer: the IP address that the remote service thinks is
	// our client IP.
	IPReportedByServer string

	// ProxyExitIP: the IP address the proxy is actually using externally.
	// (Ideally we fetch it from a "what is my ip" style endpoint.)
	ProxyExitIP string

	// HeadersObserved: headers that the remote service saw that may leak
	// info. For example "X-Forwarded-For: <real client ip>" or "Via: proxy".
	HeadersObserved map[string]string
}

// DetermineAnonymity returns "transparent", "anonymous", "elite", or "unknown".
func DetermineAnonymity(in AnonymityInput) string {
	if in.ProxyExitIP == "" || in.IPReportedByServer == "" {
		return "unknown"
	}

	// If the server sees our real client IP (not equal to proxy exit IP),
	// then the proxy is *transparent* (it leaked us).
	if in.IPReportedByServer != in.ProxyExitIP {
		return "transparent"
	}

	leakHeaders := []string{
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "Forwarded",
        "Via",
        "X-Real-IP",
        "Proxy-Connection",
    }

	leaked := false
    for _, h := range leakHeaders {
        if v := in.HeadersObserved[h]; v != "" {
            leaked = true
            break
        }
    }

    if leaked {
        return "anonymous"
    }

	// If we got here: remote only sees proxy IP, and we didn't obviously announce we're a proxy.
	return "elite"
}
