# Syntecxhub_Port_Scanner

[![CI](https://github.com/DevRisny/Syntecxhub_Port_Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/DevRisny/Syntecxhub_Port_Scanner/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

Project 1 of the **Syntecxhub Cyber Security Internship**: a fast, multi-threaded **TCP port scanner** in Python. Standard library only, nothing to install.

> **Legal note:** scan only your own computer or systems you have **written permission** to test. The tool blocks public IP addresses unless you add `--i-have-permission`.

## Features
| Feature | Details |
|---|---|
| Targets | one host/IP, a hostname, or a network like `192.168.1.0/24` (max 256 hosts) |
| Ports | single `80`, range `20-100`, list `22,80,443`, or `--top-ports` (101 common ports) |
| Speed | thread pool (`-w`), per-port timeout (`-t`), optional random order (`--randomize`) |
| Port status | `OPEN`, `CLOSED` (refused), `TIMEOUT` (no reply, maybe filtered), `ERROR` |
| Service info | service name from the OS + optional **banner grabbing** (`-b`): SSH/FTP/SMTP banners and HTTP `Server` header |
| Output | live results, summary table, log file, **JSON** (`--json`) and **CSV** (`--csv`) export |
| Safety | permission gate for non-private targets, network size limit, clean Ctrl+C (keeps partial results) |
| Quality | input validation, exception handling, 19 unit tests |

## Requirements
Python 3.9 or newer.

## Install (optional)
```bash
pip install .          # adds the `portscan` command
portscan 127.0.0.1 --top-ports
```
You can also run it directly: `python port_scanner.py ...` (examples below use this form).

## Usage
```bash
python port_scanner.py 127.0.0.1                         # ports 1-1024 (default)
python port_scanner.py 127.0.0.1 -p 80                   # one port
python port_scanner.py 127.0.0.1 -p 20-100               # range
python port_scanner.py 127.0.0.1 -p 22,80,443 -b         # list + banner grabbing
python port_scanner.py localhost --top-ports             # common ports
python port_scanner.py 192.168.1.0/24 --top-ports -t 0.5 # whole home network
python port_scanner.py 127.0.0.1 -p 1-5000 --json out.json --csv out.csv
python port_scanner.py scanme.example.org --i-have-permission   # only with permission!
```

| Option | Meaning | Default |
|---|---|---|
| `-p, --ports` | port, range or list | `1-1024` |
| `--top-ports` | scan common ports (cannot be used with `-p`) | off |
| `-t, --timeout` | seconds per port | `1.0` |
| `-w, --threads` | number of threads | `100` |
| `-b, --banner` | read service banner from open ports | off |
| `--randomize` | random port order | off |
| `--show-closed` | print closed ports too | off |
| `-l, --log` | log file | `scan_results.log` |
| `--json FILE`, `--csv FILE` | save results | off |
| `--no-color` | plain text output | colours on in a terminal |
| `--i-have-permission` | allow a non-private target | off |

## Example output (real run on my own machine)
```
Syntecxhub Port Scanner
Target: 127.0.0.1 | hosts: 1 | ports: 14 | timeout: 1.0s | threads: 100
  [+]  2222/tcp            OPEN     unknown  | SSH-2.0-OpenSSH_9.6 (demo)
  [+]  8765/tcp            OPEN     unknown  | SimpleHTTP/0.6 Python/3.13.16

Summary
  127.0.0.1: 2 open port(s)
      2222/tcp  unknown      SSH-2.0-OpenSSH_9.6 (demo)
      8765/tcp  unknown      SimpleHTTP/0.6 Python/3.13.16
Done in 0.41s - 2 open, 12 closed, 0 timeout, 0 error
```

## How it works
```
 target ──► resolve_targets() ──► check_permission()
                                        │
 ports  ──► parse_ports()               ▼
                     └──────────► ThreadPoolExecutor
                                   scan_port(ip, port)
                                   connect_ex() ─► OPEN / CLOSED / TIMEOUT / ERROR
                                   grab_banner()  (optional)
                                        │
                                        ▼
                  live print + log file + summary + JSON / CSV
```
1. `connect_ex()` returns `0` when the TCP handshake works, so the port is open. "Connection refused" means closed. No reply means `TIMEOUT` (often a firewall).
2. Many scans run at the same time in threads, so 1000 ports finish in a second or two.
3. Banner grabbing waits briefly for the service to talk first (SSH, FTP, SMTP). If it stays silent, it sends a small HTTP `HEAD` request.

## Run the tests
```bash
python -m unittest -v
```
Tests use temporary local servers, so no outside network is touched: open/closed ports, banners, HTTP header, timeout handling, port and CIDR parsing, permission gate, JSON/CSV export.

## Limits (honest notes)
- This is a full-connect scan. It is easy for a target to see and log. It does not do stealth (SYN) scans.
- `TIMEOUT` can mean a firewall drops packets, or the network is slow. Try a bigger `-t`.
- IPv4 only.

## What I learned
Socket programming (TCP handshake, `connect_ex`, timeouts), concurrency with threads, banner grabbing, input validation, safe and ethical scanning rules, logging, and testing network code with local test servers.
