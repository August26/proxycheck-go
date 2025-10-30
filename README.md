<p align="center">
  <img src="assets/cover.webp" alt="proxycheck-go cover" width="100%">
</p>

<h1 align="center">proxycheck-go</h1>

`proxycheck-go` is a fast, concurrent, open-source proxy checker written in Go.

It validates large proxy lists, measures performance, extracts metadata (geo / ISP / anonymity), estimates risk, and produces batch analytics.  
Target audience: researchers, ops teams, anti-fraud teams, proxy resellers, scraping infra engineers.

## Installation

```sh
go install github.com/August26/proxycheck-go
```

## Build from source

```sh
go build ./cmd/proxycheck-go  
```

## Usage

```sh
./proxycheck-go --input proxies.txt --verbose --type socks5 --timeout 5 --output=result.json --check-capabilities    
```

## Features

### Input formats
The tool accepts multiple proxy notations out of the box:
- `ip:port`
- `ip:port:username:password`
- `username:password@ip:port`

Supported IPv4.

### Protocol support
You can choose which proxy protocol(s) to test:
- `https`
- `socks5`

### Per-proxy result
For each proxy we attempt a connection and produce a `ProxyCheckResult`:

- `alive`: whether the proxy responded successfully within timeout
- `status_code`: HTTP status code if applicable
- `latency_ms`: round-trip time in milliseconds
- `country`, `city`, `isp`: geolocation / provider info of the *outgoing* IP
- `ip`: the external IP as seen by the destination
- `anonymity`: transparent / anonymous / elite / unknown
- `fraud_score`: heuristic risk score (0..100). Higher = more risky (e.g. known datacenter IP ranges).  
  NOTE: this starts as a simple heuristic and will evolve.
- `capabilities`: whether the proxy seems to allow specific traffic types (see below)
- `error`: if the proxy failed the check, reason is stored here

#### Anonymity Levels
- `transparent`: The proxy forwards your real IP address to the destination server.
The server (test-url) can see who you are and that you’re connecting through a proxy.
This is the lowest level of privacy.
- `anonymous`: The proxy hides your real IP address but identifies itself as a proxy.
The server cannot see your true IP, but it detects headers like Via, X-Forwarded-For, Forwarded, or Proxy-Connection, which reveal that a proxy is being used.
- `elite`: The proxy hides both your real IP address and the fact that it’s a proxy at all.
To the destination server, you appear as a regular, direct client.
- `unknown`: The anonymity level could not be determined (the proxy did not respond, returned invalid data, or timed out).

### Capabilities audit
Optionally, the tool can attempt to detect what kind of traffic is allowed through the proxy:

```json
{
  "smtp": true,
  "pop3": false,
  "imap": false,
  "udp": true
}
```

- `smtp`: the proxy was able to open a TCP tunnel to a known SMTP endpoint (e.g. port 587) and receive a banner
- `pop3`: TCP tunnel to a POP3 endpoint (ports 110/995)
- `imap`: TCP tunnel to an IMAP endpoint (ports 143/993)
- `udp`: for SOCKS5 proxies, we attempt a UDP ASSOCIATE request and a small round-trip (for example DNS).

If successful, `udp = true`.
This check is slower and can be turned on via a CLI flag (planned: --check-capabilities).

Why this matters:
- Some providers block outbound email ports (587 / 465 / 25).
- Some SOCKS5 servers do not allow UDP relay.

Being able to distinguish these is valuable for email automation, VoIP tunneling, game traffic, etc.

### Batch analytics
After scanning all proxies, proxy-inspector prints a summary:
- total proxies
- unique proxies (ip:port uniqueness)
- alive proxies
- average latency (alive only)
- average fraud score (alive only)
- total processing time for the entire batch
This helps you quickly judge list quality (is this provider selling trash or good inventory?).

### Output

```text
$ proxycheck-go --file proxies.txt --type socks5 --output table

┌──────────────────────────┬─────────┬──────────────┬──────────-──┬─────────┬─────────────┐
│ Proxy                    │ Latency │ Anonymity    │ FraudScore  │ SMTP    │ IMAP  │ UDP │
├──────────────────────────┼─────────┼──────────────┼──────────-──┼─────────┼─────────────┤
│ 203.0.113.5:1080         │ 312ms   │ elite        │ 20          │ Y       │ Y    │ Y    │
│ 203.0.113.99:1080        │ 892ms   │ anonymous    │ 70          │ N       │ N    │ N    │
└──────────────────────────┴─────────┴──────────────┴──────────-──┴─────────┴─────────────┘

Unique proxies: 120 (out of 140)
Reachable:      85/120 (70.8%)
Avg latency:    412ms
Avg fraud:      48.2/100
Runtime:        3.2s
```

Optional file export:

```text
--output results.json --format json
--output results.csv --format csv
```

Final summary block:

```text
Summary:
  Total proxies:            340
  Unique proxies:           327
  Alive proxies:            198
  Avg latency (alive):      142.5 ms
  Avg fraud score (alive):  27.1
  Batch time:               3.42 s
```

### Logging
`proxycheck-go` uses structured logging. By default it prints high-level INFO logs like:
- how many proxies were loaded
- timeout setting
- concurrency level
- total batch time
With `--verbose`, it will also emit DEBUG logs such as:
- per-proxy connection attempts
- timeout / handshake errors
- capability test results

This is extremely useful for troubleshooting why certain proxies fail.

### Concurrency
All checks run concurrently using a worker pool.
You can control parallelism using `--concurrency <N>`.
This makes it practical to validate thousands of proxies quickly.

### CLI usage
```text
proxy-inspector \
  --type socks5 \
  --timeout 5 \
  --concurrency 50 \
  --input proxies.txt \
  --output results.json \
  --format json \
  --check-capabilities \
  --verbose \
  --retry 3

Flags:
--type "https" | "socks5"
--timeout request timeout in seconds (default: 5)
--concurrency number of parallel workers (default: 50)
--input path to the file with proxies
--output optional path for results dump
--format output format: json or csv
--check-capabilities
attempt SMTP / POP3 / IMAP / UDP capability probing
--verbose enable debug logs
--retry <N> number of retries per proxy (default: 1)
```

### License
This project is released under the MIT License. See LICENSE for details.
MIT means:
- You can use this code for private or commercial work
- You can modify, redistribute, and even sell derivatives
- You must keep the copyright notice
- No warranty is provided (use at your own risk)
