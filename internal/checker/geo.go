package checker

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

    "github.com/August26/proxycheck-go/internal/model"
	"github.com/oschwald/geoip2-golang"
)

type GeoInfo = model.GeoInfo

type Resolver struct {
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
}

func NewResolver() (*Resolver, error) {
	baseDir, err := defaultGeoPath()
	if err != nil {
		return nil, err
	}

	cityPath := filepath.Join(baseDir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(baseDir, "GeoLite2-ASN.mmdb")

	// если нет — скачиваем
	if _, err := os.Stat(cityPath); os.IsNotExist(err) {
		fmt.Println("Downloading GeoLite2-City.mmdb ...")
		if err := downloadMMDB(cityPath, "https://git.io/GeoLite2-City.mmdb"); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(asnPath); os.IsNotExist(err) {
		fmt.Println("Downloading GeoLite2-ASN.mmdb ...")
		if err := downloadMMDB(asnPath, "https://git.io/GeoLite2-ASN.mmdb"); err != nil {
			return nil, err
		}
	}

	cityDB, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("open city db: %w", err)
	}
	asnDB, err := geoip2.Open(asnPath)
	if err != nil {
		cityDB.Close()
		return nil, fmt.Errorf("open asn db: %w", err)
	}
	return &Resolver{cityDB: cityDB, asnDB: asnDB}, nil
}

func (r *Resolver) Close() {
	if r.cityDB != nil {
		r.cityDB.Close()
	}
	if r.asnDB != nil {
		r.asnDB.Close()
	}
}

func (r *Resolver) Lookup(ipStr string) (GeoInfo, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoInfo{}, fmt.Errorf("invalid IP: %s", ipStr)
	}

	cityRec, err := r.cityDB.City(ip)
	if err != nil {
		return GeoInfo{}, err
	}

	country := cityRec.Country.IsoCode
	cityName := cityRec.City.Names["en"]
	if cityName == "" && len(cityRec.Subdivisions) > 0 {
		cityName = cityRec.Subdivisions[0].Names["en"]
	}

	isp := ""
	if asnRec, err := r.asnDB.ASN(ip); err == nil {
		isp = asnRec.AutonomousSystemOrganization
	}

	return GeoInfo{Country: country, City: cityName, ISP: isp}, nil
}

// --- helpers ---

func downloadMMDB(dst, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to download %s: %s", url, resp.Status)
	}

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return nil
}

func defaultGeoPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(home, ".local", "share", "geoip")
	if runtime.GOOS == "windows" {
		base = filepath.Join(home, "AppData", "Local", "geoip")
	}
	if err := os.MkdirAll(base, 0755); err != nil {
		return "", err
	}
	return base, nil
}
