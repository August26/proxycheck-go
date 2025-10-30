package checker

import (
	"net"
	"strings"
)

// EstimateFraudScore attempts to generate a simple heuristic risk score (0..100).
// Higher score = more likely to be flagged as "bad"/high-risk infra (datacenter,
// obvious hosting, suspicious).
//
// This is intentionally naive in the first version. The idea is that we'll swap
// or enrich this later with ASN-based classification or external threat intel.
func EstimateFraudScore(ip string, isp string) float64 {
	if ip == "" {
		return 80.0
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		// invalid IP? suspicious
		return 90.0
	}

	// If it's RFC1918 / private ranges, it's not a real exit IP => useless / suspicious.
	if isPrivateIP(parsed) {
		return 95.0
	}

	// quick+dirty ISP checks for datacenter-ish keywords
	// (we'll evolve this later; right now it's just to provide some signal)
	lowerISP := strings.ToLower(isp)
	if strings.Contains(lowerISP, "cloud") ||
		strings.Contains(lowerISP, "hosting") ||
		strings.Contains(lowerISP, "data") ||
		strings.Contains(lowerISP, "server") ||
		strings.Contains(lowerISP, "colo") ||
		strings.Contains(lowerISP, "digitalocean") ||
		strings.Contains(lowerISP, "aws") ||
		strings.Contains(lowerISP, "amazon") ||
		strings.Contains(lowerISP, "google") ||
		strings.Contains(lowerISP, "azure") ||
		strings.Contains(lowerISP, "hetzner") ||
		strings.Contains(lowerISP, "ovh") {
		return 70.0
	}

	// residential / mobile ISPs typically have lower suspicion
	return 20.0
}

func isPrivateIP(ip net.IP) bool {
	// This checks common private/reserved ranges like:
	// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
	// also link-local, loopback, etc.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}
