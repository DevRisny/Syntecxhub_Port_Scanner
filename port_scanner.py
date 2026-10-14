#!/usr/bin/env python3
"""
Syntecxhub Cyber Security Internship - Project 1: TCP Port Scanner (v2)

A multi-threaded TCP connect scanner (standard library only).

Features
  * One host, a hostname, or a small network (CIDR, up to 256 hosts)
  * One port, a range, a list, or the built-in "common ports" list
  * Threads (ThreadPoolExecutor) for speed, optional random port order
  * Status per port: OPEN / CLOSED / TIMEOUT (filtered?) / ERROR
  * Service names and optional banner grabbing (-b)
  * Live output, summary table, log file, JSON and CSV export
  * Safety gate: non-private targets need --i-have-permission
  * Clean error handling (bad host, bad ports, Ctrl+C, network errors)

Use only on systems you own or have written permission to test.
"""

import argparse
import csv
import errno
import ipaddress
import json
import logging
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

OPEN, CLOSED, TIMEOUT, ERROR = "OPEN", "CLOSED", "TIMEOUT", "ERROR"

# connect_ex() error codes (Linux/macOS + Windows)
TIMEOUT_CODES = {errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT, 10035, 10060}
CLOSED_CODES = {errno.ECONNREFUSED, 10061}

MAX_HOSTS = 256
DEFAULT_PORTS = "1-1024"

COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
}

# Common ports list used by --top-ports
TOP_PORTS = [
    7,
    9,
    13,
    20,
    21,
    22,
    23,
    25,
    26,
    37,
    53,
    79,
    80,
    81,
    88,
    106,
    110,
    111,
    113,
    119,
    135,
    139,
    143,
    144,
    179,
    199,
    389,
    427,
    443,
    444,
    445,
    465,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1110,
    1433,
    1720,
    1723,
    1755,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
]


class ScanError(Exception):
    """A problem the user can fix (bad target, no permission, ...)."""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
class Style:
    """Adds ANSI colours when enabled (turned off for files / --no-color)."""

    CODES = {"green": 32, "red": 31, "yellow": 33, "cyan": 36, "bold": 1, "dim": 2}

    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, name):
        if not self.enabled:
            return text
        return f"\033[{self.CODES[name]}m{text}\033[0m"


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def parse_ports(text):
    """'80', '20-100' or '22,80,443' (or a mix) -> sorted list of ints."""
    ports = set()
    try:
        for part in text.split(","):
            part = part.strip()
            if "-" in part:
                start, end = (int(x) for x in part.split("-", 1))
                if start > end:
                    raise ValueError("range start is bigger than range end")
                ports.update(range(start, end + 1))
            elif part:
                ports.add(int(part))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"bad port list '{text}': {exc}") from None
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    if min(ports) < 1 or max(ports) > 65535:
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return sorted(ports)


def expand_targets(target, max_hosts=MAX_HOSTS):
    """'host' -> ['host'];  '192.168.1.0/24' -> every usable address."""
    if "/" not in target:
        return [target]
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScanError(f"bad network '{target}': {exc}") from None
    if net.num_addresses > max_hosts:
        raise ScanError(
            f"network too big ({net.num_addresses} addresses). "
            f"Maximum is {max_hosts} (for example a /24)."
        )
    return [str(ip) for ip in net.hosts()]


def resolve_targets(target):
    """Return ([(name, ip), ...], [error text, ...])."""
    resolved, errors = [], []
    for name in expand_targets(target):
        try:
            resolved.append((name, socket.gethostbyname(name)))
        except socket.gaierror as exc:
            errors.append(f"{name}: cannot resolve ({exc})")
    return resolved, errors


def is_local_address(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def check_permission(resolved, confirmed):
    """Public addresses need an explicit --i-have-permission."""
    public = [ip for _, ip in resolved if not is_local_address(ip)]
    if public and not confirmed:
        raise ScanError(
            f"{public[0]} is not a private/local address. Only scan systems you "
            "own or have written permission to test. If you do, run again "
            "with --i-have-permission."
        )


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def grab_banner(sock, timeout):
    """Read a service banner from an open socket (best effort)."""
    data = b""
    try:
        sock.settimeout(0.4)  # many services talk first (ssh, ftp, smtp)
        try:
            data = sock.recv(512)
        except socket.timeout:
            data = b""
        if not data:  # silent service: try an HTTP request
            sock.settimeout(min(timeout, 2.0))
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = sock.recv(512)
    except OSError:
        pass
    text = data.decode("utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    if lines[0].startswith("HTTP/"):
        for ln in lines:
            if ln.lower().startswith("server:"):
                return ln[7:].strip()[:80]
    return "".join(ch for ch in lines[0] if ch.isprintable())[:80]


def scan_port(ip, port, timeout=1.0, banner=False):
    """Scan one port and return a result dict."""
    result = {
        "ip": ip,
        "port": port,
        "status": ERROR,
        "service": service_name(port),
        "banner": "",
        "detail": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((ip, port))
        if code == 0:
            result["status"] = OPEN
            if banner:
                result["banner"] = grab_banner(sock, timeout)
        elif code in CLOSED_CODES:
            result["status"] = CLOSED
            result["detail"] = "connection refused"
        elif code in TIMEOUT_CODES:
            result["status"] = TIMEOUT
            result["detail"] = "no reply (filtered or slow)"
        else:
            result["detail"] = f"errno {code}: {errno.errorcode.get(code, 'unknown')}"
    except socket.timeout:
        result["status"] = TIMEOUT
        result["detail"] = "no reply (filtered or slow)"
    except OSError as exc:
        result["detail"] = str(exc)
    finally:
        sock.close()
    return result


def run_scan(
    resolved,
    ports,
    timeout=1.0,
    threads=100,
    banner=False,
    show_closed=False,
    randomize=False,
    logger=None,
    style=None,
    out=print,
):
    """Scan every (host, port). Returns (results, interrupted)."""
    style = style or Style(False)
    names = {ip: name for name, ip in resolved}
    tasks = [(ip, port) for _, ip in resolved for port in ports]
    if randomize:
        random.shuffle(tasks)
    total = len(tasks)
    show_progress = total >= 300 and sys.stderr.isatty()

    results, interrupted = [], False
    pool = ThreadPoolExecutor(max_workers=threads)
    futures = [pool.submit(scan_port, ip, port, timeout, banner) for ip, port in tasks]
    try:
        for done, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            results.append(res)
            host = names[res["ip"]]
            if logger:
                logger.info(
                    f"{host}:{res['port']} {res['status']} {res['banner'] or res['detail']}".strip()
                )
            label = f"{host}:{res['port']}/tcp" if len(resolved) > 1 else f"{res['port']:>5}/tcp"
            if res["status"] == OPEN:
                extra = res["service"] + (f"  | {res['banner']}" if res["banner"] else "")
                out(f"  {style('[+]', 'green')} {label:<20} {style('OPEN', 'green'):<8} {extra}")
            elif res["status"] in (TIMEOUT, ERROR):
                out(f"  {style('[!]', 'yellow')} {label:<20} {res['status']:<8} {res['detail']}")
            elif show_closed:
                out(f"  {style('[-]', 'dim')} {label:<20} {res['status']:<8} {res['detail']}")
            if show_progress and done % 50 == 0:
                print(f"\r  progress: {done}/{total}", end="", file=sys.stderr)
        pool.shutdown()
    except KeyboardInterrupt:
        interrupted = True
        pool.shutdown(wait=False, cancel_futures=True)
        out("\nScan stopped by user (Ctrl+C). Showing results so far.")
    if show_progress:
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)
    results.sort(key=lambda r: (r["ip"], r["port"]))
    return results, interrupted


def summarize(results, resolved, elapsed, style, out=print):
    """Print the final summary table and return the counts."""
    names = {ip: name for name, ip in resolved}
    counts = {s: 0 for s in (OPEN, CLOSED, TIMEOUT, ERROR)}
    for r in results:
        counts[r["status"]] += 1

    out("")
    out(style("Summary", "bold"))
    for ip in sorted({r["ip"] for r in results}, key=lambda x: ipaddress.ip_address(x)):
        open_ports = [r for r in results if r["ip"] == ip and r["status"] == OPEN]
        title = names[ip] if names[ip] == ip else f"{names[ip]} ({ip})"
        out(f"  {style(title, 'cyan')}: {len(open_ports)} open port(s)")
        for r in open_ports:
            out(f"     {r['port']:>5}/tcp  {r['service']:<12} {r['banner']}".rstrip())
    out(
        f"Done in {elapsed:.2f}s - {counts[OPEN]} open, {counts[CLOSED]} closed, "
        f"{counts[TIMEOUT]} timeout, {counts[ERROR]} error"
    )
    return counts


def write_json(path, results, meta):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scan": meta, "results": results}, f, indent=2)


def write_csv(path, results, names):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "ip", "port", "status", "service", "banner", "detail"])
        for r in results:
            w.writerow(
                [
                    names.get(r["ip"], r["ip"]),
                    r["ip"],
                    r["port"],
                    r["status"],
                    r["service"],
                    r["banner"],
                    r["detail"],
                ]
            )


def setup_logging(log_file):
    logger = logging.getLogger("portscanner")
    logger.setLevel(logging.INFO)
    for h in list(logger.handlers):
        h.close()
        logger.removeHandler(h)
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
    logger.addHandler(handler)
    return logger


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Multi-threaded TCP port scanner. Only scan systems you "
        "own or have permission to test."
    )
    p.add_argument("target", help="hostname, IP, or network like 192.168.1.0/24")
    group = p.add_mutually_exclusive_group()
    group.add_argument(
        "-p", "--ports", type=parse_ports, help=f"80 | 20-100 | 22,80,443 (default {DEFAULT_PORTS})"
    )
    group.add_argument(
        "--top-ports", action="store_true", help=f"scan the {len(TOP_PORTS)} most common ports"
    )
    p.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="seconds to wait per port (default 1.0)"
    )
    p.add_argument("-w", "--threads", type=int, default=100, help="number of threads (default 100)")
    p.add_argument(
        "-b", "--banner", action="store_true", help="try to read a service banner from open ports"
    )
    p.add_argument("--randomize", action="store_true", help="scan ports in random order")
    p.add_argument("--show-closed", action="store_true", help="also print closed ports")
    p.add_argument("-l", "--log", default="scan_results.log", help="log file")
    p.add_argument("--json", metavar="FILE", help="save results as JSON")
    p.add_argument("--csv", metavar="FILE", help="save results as CSV")
    p.add_argument("--no-color", action="store_true", help="turn off colours")
    p.add_argument(
        "--i-have-permission", action="store_true", help="confirm you may scan a non-private target"
    )
    return p


def main(argv=None, out=print):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.threads < 1:
        parser.error("timeout must be > 0 and threads must be >= 1")
    ports = TOP_PORTS if args.top_ports else args.ports or parse_ports(DEFAULT_PORTS)
    style = Style(sys.stdout.isatty() and not args.no_color)

    try:
        resolved, errors = resolve_targets(args.target)
        for err in errors:
            out(style(f"  skipped {err}", "yellow"))
        if not resolved:
            raise ScanError(f"cannot resolve '{args.target}'")
        check_permission(resolved, args.i_have_permission)
    except ScanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    logger = setup_logging(args.log)
    started_at = datetime.now().isoformat(timespec="seconds")
    out(style("Syntecxhub Port Scanner", "bold"))
    out(
        f"Target: {args.target} | hosts: {len(resolved)} | ports: {len(ports)} | "
        f"timeout: {args.timeout}s | threads: {args.threads}"
    )
    logger.info(f"START target={args.target} hosts={len(resolved)} ports={len(ports)}")

    t0 = time.time()
    results, interrupted = run_scan(
        resolved,
        ports,
        args.timeout,
        args.threads,
        args.banner,
        args.show_closed,
        args.randomize,
        logger,
        style,
        out,
    )
    elapsed = time.time() - t0
    counts = summarize(results, resolved, elapsed, style, out)
    logger.info(f"END {counts}" + (" (interrupted)" if interrupted else ""))

    names = {ip: name for name, ip in resolved}
    meta = {
        "target": args.target,
        "started": started_at,
        "duration_seconds": round(elapsed, 2),
        "hosts": len(resolved),
        "ports_scanned": len(ports),
        "interrupted": interrupted,
        "counts": counts,
    }
    try:
        if args.json:
            write_json(args.json, results, meta)
            out(f"JSON saved to {args.json}")
        if args.csv:
            write_csv(args.csv, results, names)
            out(f"CSV saved to {args.csv}")
    except OSError as exc:
        print(f"Error: could not write output file: {exc}", file=sys.stderr)
        return 1
    out(f"Log saved to {args.log}")
    return 130 if interrupted else 0


def cli():
    """Console-script entry point (installed as the 'portscan' command)."""
    sys.exit(main())


if __name__ == "__main__":
    cli()
