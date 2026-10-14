# Changelog

## 2.0.0
- Network scanning with CIDR notation (up to 256 hosts)
- `--top-ports` preset (101 common ports)
- Banner grabbing (`-b`): SSH/FTP/SMTP banners and HTTP `Server` header
- JSON and CSV export, live coloured output, summary table
- Safety gate: non-private targets need `--i-have-permission`
- Better status detection: refused = CLOSED, no reply = TIMEOUT
- `portscan` console command via `pip install .`
- 19 unit tests, ruff lint and format checks, GitHub Actions CI

## 1.0.0
- First version: threaded TCP connect scanner (single host, port range, log file)
