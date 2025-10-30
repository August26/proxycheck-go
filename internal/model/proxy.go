package model

// ProxyInput is a normalized representation of a proxy entry
// parsed from file lines such as:
//   ip:port
//   ip:port:username:password
//   username:password@ip:port
type ProxyInput struct {
    Host       string // IPv4 or hostname
    Port       int
    Username   string
    Password   string
    Type       string // "http", "https", "socks5", "" if unknown at parse time
    Raw        string // original line for debugging
}

// ProxyCapabilities describes what traffic appears allowed
// through the proxy (to be filled later during checking).
type ProxyCapabilities struct {
    SMTP   bool // can connect TCP to smtp targets (e.g. port 587)
    POP3   bool // can connect TCP to pop3 targets (110/995)
    IMAP   bool // can connect TCP to imap targets (143/993)
    UDP    bool // can relay UDP (SOCKS5 UDP ASSOCIATE)
}

// ProxyCheckResult is the final result for a single proxy
// after running checks.
type ProxyCheckResult struct {
    Input          ProxyInput
    Alive          bool
    StatusCode     int    // HTTP status (or 0 if not HTTP)
    LatencyMs      int64  // timeout
    Country        string
    City           string
    ISP            string // provider / ASN name
    IP             string // external IP
    Anonymity      string // transparent / anonymous / elite
    FraudScore     float64 // 0..100 heuristic
	Capabilities   ProxyCapabilities
    Error          string // if failed

	RawHeaders map[string]string // internal: headers observed by remote
}

// BatchStats aggregates summary analytics for an entire run.
type BatchStats struct {
    TotalProxies              int `json:"total_proxies"`
    UniqueProxies             int `json:"unique_proxies"`
    AliveProxies              int `json:"alive_proxies"`
    AvgLatencyMs              float64 `json:"avg_latency_ms"`
    AvgFraudScore             float64 `json:"avg_fraud_score"`
    TotalProcessingTimeMs     int64 `json:"total_processing_time_ms"`
    SuccessRatePct            float64 `json:"success_rate_pct"`
}
