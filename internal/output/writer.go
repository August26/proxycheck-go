package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/August26/proxycheck-go/internal/model"
)

// PrintResultsTable prints a human-readable table of per-proxy results.
func PrintResultsTable(w io.Writer, results []model.ProxyCheckResult) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)

	// header
	fmt.Fprintln(tw, "IP:PORT\tALIVE\tLAT(ms)\tCOUNTRY\tCITY\tISP\tANONYMITY\tFRAUD\tSTATUS\tSMTP\tPOP3\tIMAP\tUDP")

	for _, r := range results {
		hostport := fmt.Sprintf("%s:%d", r.Input.Host, r.Input.Port)

		alive := "no"
		if r.Alive {
			alive = "yes"
		}

		lat := "-"
		if r.LatencyMs > 0 {
			lat = fmt.Sprintf("%d", r.LatencyMs)
		}

		country := dashIfEmpty(r.Country)
		city := dashIfEmpty(r.City)
		isp := dashIfEmpty(r.ISP)
		anon := dashIfEmpty(r.Anonymity)

		fraud := "-"
		if r.FraudScore > 0 {
			fraud = fmt.Sprintf("%.1f", r.FraudScore)
		}

		status := "-"
		if r.StatusCode > 0 {
			status = fmt.Sprintf("%d", r.StatusCode)
		} else if r.Error != "" {
			status = r.Error
		}

		smtp := boolToYN(r.Capabilities.SMTP)
		pop3 := boolToYN(r.Capabilities.POP3)
		imap := boolToYN(r.Capabilities.IMAP)
		udp := boolToYN(r.Capabilities.UDP)

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			hostport,
			alive,
			lat,
			country,
			city,
			isp,
			anon,
			fraud,
			status,
			smtp,
			pop3,
			imap,
			udp,
		)
	}

	tw.Flush()
}

// PrintSummary prints the aggregated batch stats.
func PrintSummary(w io.Writer, stats model.BatchStats) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Summary:")
	fmt.Fprintf(w, "  Total proxies:            %d\n", stats.TotalProxies)
	fmt.Fprintf(w, "  Unique proxies:           %d\n", stats.UniqueProxies)
	fmt.Fprintf(w, "  Alive proxies:            %d\n", stats.AliveProxies)
	fmt.Fprintf(w, "  Avg latency (alive):      %.1f ms\n", stats.AvgLatencyMs)
	fmt.Fprintf(w, "  Avg fraud score (alive):  %.1f\n", stats.AvgFraudScore)
	fmt.Fprintf(w, "  Batch time:               %.2f s\n", float64(stats.TotalProcessingTimeMs)/1000.0)
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func boolToYN(b bool) string {
	if b {
		return "y"
	}
	return "n"
}

// WriteFile writes all proxy results + summary stats to a file in json or csv format.
func WriteFile(path string, format string, results []model.ProxyCheckResult, stats model.BatchStats) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch format {
	case "json":
		return writeJSON(f, results, stats)
	case "csv":
		return writeCSV(f, results, stats)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// writeJSON writes an object with "results" and "summary".
func writeJSON(w io.Writer, results []model.ProxyCheckResult, stats model.BatchStats) error {
	payload := struct {
		Results []model.ProxyCheckResult `json:"results"`
		Summary model.BatchStats         `json:"summary"`
	}{
		Results: results,
		Summary: stats,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// writeCSV writes a CSV with per-proxy rows (summary is not included in CSV for now).
func writeCSV(w io.Writer, results []model.ProxyCheckResult, stats model.BatchStats) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// header
	header := []string{
		"host",
		"port",
		"alive",
		"latency_ms",
		"country",
		"city",
		"isp",
		"ip",
		"anonymity",
		"fraud_score",
		"status_code",
		"error",
		"smtp",
		"pop3",
		"imap",
		"udp",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		row := []string{
			r.Input.Host,
			fmt.Sprintf("%d", r.Input.Port),
			boolToYN(r.Alive),
			fmt.Sprintf("%d", r.LatencyMs),
			r.Country,
			r.City,
			r.ISP,
			r.IP,
			r.Anonymity,
			fmt.Sprintf("%.1f", r.FraudScore),
			fmt.Sprintf("%d", r.StatusCode),
			r.Error,
			boolToYN(r.Capabilities.SMTP),
			boolToYN(r.Capabilities.POP3),
			boolToYN(r.Capabilities.IMAP),
			boolToYN(r.Capabilities.UDP),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}
