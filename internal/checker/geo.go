package checker

// GeoInfo describes geographical / provider information associated with an IP.
// country/city/isp are human-readable strings for reporting.
type GeoInfo struct {
	Country string
	City    string
	ISP     string
}
