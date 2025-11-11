
# potscan

Lightweight TCP/UDP port scanner built in Go.

## Build

Using `go build` (recommended for local builds):

```bash
go build -o potscan .
```

Or install with `go install` (requires module-aware mode and `$GOBIN`/`$GOPATH/bin` on PATH):

```bash
go install github.com/KhaledLemes/potmap@latest
```

After building, the binary `potscan` will be available in the current directory (or in `$GOBIN` for `go install`).

---

## Commands

This CLI exposes two primary commands:

- `Scan` — run a TCP scan.
  - aliases: `scan`, `sc`, `S`, `s`, `tcp`

- `uScan` — run a UDP scan.
  - aliases: `uscan`, `usc`, `us`, `uS`, `u`, `udp`

> Note: aliases above are the recommended short forms. If your project defines different aliases, update accordingly.

---

## Flags (global / command-level)

Common flags used by the scanner:

- `--ip`, `-i` —  Target IP address to scan.  
  Example: `--ip 192.168.0.1`  
  - Default value is 127.0.0.1

- `--ports`, `-p` — List of ports to scan. Accepts repeated use, comma-separated list and range.  
  Examples:
  - `--ports 80 --ports 443`
  - `--ports 80,443,8080`
  - Single range: `--ports 1000-1010`
  > When a range is provided, additional `--ports` arguments are not allowed.

- `--showclosed`, `--seeall` — Print closed ports in output (by default closed ports are hidden).



---

## Usage examples

Build once:

```bash
go build -o potscan .
```

Run a TCP scan (explicit ports):
 -i 192.168.0.1 -p 22,80,443
```bash
./potscan S --ip 192.168.0.1 --ports 22 --ports 80 --ports 443
# or
./potscan uS -i 192.168.0.1 -p 22,80,443
#or
./potscan s -p 100-1000
#or even
./potscan S
```

Run a UDP scan (default common UDP ports used if none provided):

```bash
./potscan udp --ip 10.0.0.5
# scans common UDP ports (53,67,68,69,123,161,162,500,514,3478,4500)
```

Use a range (single argument):

```bash
./potscan tcp --ip 192.168.0.1 --ports 1000-1010
```

Show closed ports in the output:

```bash
./potscan tcp --ip 192.168.0.1 --ports 80 --showclosed
# or
./potscan tcp -i 192.168.0.1 -p 80 -s
```

---

## Behavior notes

- **UDP semantics:** UDP is connectionless. Lack of response can mean the port is *open* (service silent) or *filtered* (dropped by firewall). A returned ICMP "port unreachable" (often seen as `connection refused` at user-level) typically indicates the port is **closed**.

- **TCP semantics:** TCP responses are more definitive: `SYN+ACK` → open; `RST` → closed; no response → filtered.

- **Defaults:** If `--ports` is not provided, the scanner applies a sensible default list depending on the command (TCP or UDP).

- **Validation:** The scanner validates that ports are numeric and fit in the `uint16` range (0–65535). If a range is provided, the start and end are validated and expanded into individual ports.

---

## Examples of aliases (summary)

- `tcp` → `s`  
- `udp` → `u`  
- `--ip` → `-i`  
- `--ports` → `-p`  
- `--showclosed` → `-s`

> If the actual implementation uses different short flags/aliases, replace the mapping above accordingly.

---
