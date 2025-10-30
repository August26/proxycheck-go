package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/August26/proxycheck-go/internal/analytics"
	"github.com/August26/proxycheck-go/internal/checker"
	"github.com/August26/proxycheck-go/internal/logging"
	"github.com/August26/proxycheck-go/internal/model"
	"github.com/August26/proxycheck-go/internal/output"
	"github.com/August26/proxycheck-go/internal/parser"
)

func main() {
	var cfg model.Config

	flag.StringVar(&cfg.ProxyType, "type", "socks5", "proxy type: https | socks5")
	flag.IntVar(&cfg.TimeoutSeconds, "timeout", 5, "timeout in seconds for each proxy check")
	flag.StringVar(&cfg.InputFile, "input", "", "path to file with proxy list")
	flag.StringVar(&cfg.OutputFile, "output", "", "optional path to write results (json/csv)")
	flag.StringVar(&cfg.OutputFormat, "format", "json", "output format: json | csv")
	flag.BoolVar(&cfg.CheckCapabilities, "check-capabilities", false, "probe smtp/pop3/imap/udp capabilities")
	flag.IntVar(&cfg.Concurrency, "concurrency", 50, "number of concurrent workers")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "enable debug logs")
	flag.IntVar(&cfg.Retries, "retries", 3, "number of retry attempts per proxy (min 1)")

	flag.Parse()

	log := logging.NewLogger(cfg.Verbose)

	if cfg.InputFile == "" {
		fmt.Fprintln(os.Stderr, "--input is required")
		os.Exit(1)
	}

	if cfg.Retries < 1 {
		cfg.Retries = 1
	}

	log.Info("starting proxycheck-go",
		"type", cfg.ProxyType,
		"timeout_seconds", cfg.TimeoutSeconds,
		"concurrency", cfg.Concurrency,
		"check_capabilities", cfg.CheckCapabilities,
		"retries", cfg.Retries,
	)

	proxies, err := parser.LoadFromFile(cfg.InputFile)
	if err != nil {
		log.Error("failed to load proxies", "err", err)
		os.Exit(1)
	}

	log.Info("proxies loaded", "count", len(proxies))

	ctx := context.Background()
	start := time.Now()

	results := checker.RunBatch(ctx, proxies, cfg)

	duration := time.Since(start)
	stats := analytics.Compute(results, duration)

	log.Info("batch finished",
		"total_ms", stats.TotalProcessingTimeMs,
		"alive", stats.AliveProxies,
		"total", stats.TotalProxies,
	)

	// Print table and summary to stdout
	output.PrintResultsTable(os.Stdout, results)
	output.PrintSummary(os.Stdout, stats)

	if cfg.OutputFile != "" {
		if err := output.WriteFile(cfg.OutputFile, cfg.OutputFormat, results, stats); err != nil {
			log.Error("failed to write output file", "err", err, "path", cfg.OutputFile)
		} else {
			log.Info("results written",
				"path", cfg.OutputFile,
				"format", cfg.OutputFormat,
			)
		}
	}
}
