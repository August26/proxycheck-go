package model

type GeoInfo struct {
    Country string
    City    string
    ISP     string
}

type IPResolver interface {
	Lookup(ip string) (GeoInfo, error)
}

type Config struct {
    ProxyType       string // https or socks5
    TimeoutSeconds  int
    InputFile       string
    OutputFile      string
	OutputFormat     string // json or csv
	CheckCapabilities bool  // whether to probe smtp/pop3/imap/udp
	Concurrency      int
	Verbose          bool
	Retries           int // how many retry attempts per proxy
	Resolver 		IPResolver
}

