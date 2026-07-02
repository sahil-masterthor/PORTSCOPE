#!/usr/bin/env python3
"""
Port Scanner
============
A fast, multithreaded TCP port scanner that identifies open ports on a
target host and reports the common service usually associated with each.

LEGAL / ETHICAL NOTICE
-----------------------
Only scan systems you own, or systems you have explicit written permission
to test. Scanning systems without authorization may violate computer-misuse
laws (e.g. the CFAA in the US, the Computer Misuse Act in the UK, and
equivalents elsewhere), even when no damage is done. This tool is provided
for authorized security testing, learning, and systems administration.

USAGE
-----
    python3 port_scanner.py example.com
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py 192.168.1.10 -p 22,80,443,8080
    python3 port_scanner.py 192.168.1.10 -p 1-65535 -t 200 --timeout 0.5
    python3 port_scanner.py 192.168.1.10 --json scan_result.json

Run `python3 port_scanner.py -h` for the full list of options.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Common ports -> (service name, short description)
# This is purely a lookup table for *labeling* a result; it has no bearing
# on what's actually running there (a banner grab, when possible, gives a
# stronger signal than the port number alone).
# --------------------------------------------------------------------------
COMMON_PORTS = {
    20: ("FTP-DATA", "FTP data transfer"),
    21: ("FTP", "File Transfer Protocol (control)"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted remote login"),
    25: ("SMTP", "Mail transfer"),
    53: ("DNS", "Domain Name System"),
    67: ("DHCP", "Dynamic Host Configuration (server)"),
    68: ("DHCP", "Dynamic Host Configuration (client)"),
    69: ("TFTP", "Trivial File Transfer Protocol"),
    80: ("HTTP", "Web server"),
    110: ("POP3", "Mail retrieval"),
    111: ("RPCBind", "ONC RPC portmapper"),
    119: ("NNTP", "Usenet news"),
    123: ("NTP", "Network Time Protocol"),
    135: ("MSRPC", "Microsoft RPC"),
    137: ("NetBIOS-NS", "NetBIOS Name Service"),
    138: ("NetBIOS-DGM", "NetBIOS Datagram"),
    139: ("NetBIOS-SSN", "NetBIOS Session (SMB over NetBIOS)"),
    143: ("IMAP", "Mail retrieval"),
    161: ("SNMP", "Network management"),
    179: ("BGP", "Border Gateway Protocol"),
    194: ("IRC", "Internet Relay Chat"),
    389: ("LDAP", "Directory access"),
    443: ("HTTPS", "Encrypted web server"),
    445: ("SMB", "Windows file sharing"),
    465: ("SMTPS", "SMTP over SSL"),
    514: ("Syslog", "System logging"),
    515: ("LPD", "Line Printer Daemon"),
    587: ("SMTP-SUB", "Mail submission"),
    631: ("IPP", "Internet Printing Protocol"),
    636: ("LDAPS", "Directory access over SSL"),
    873: ("Rsync", "File synchronization"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),
    1080: ("SOCKS", "SOCKS proxy"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle database listener"),
    1723: ("PPTP", "VPN tunneling"),
    2049: ("NFS", "Network File System"),
    2082: ("cPanel", "cPanel control panel"),
    2083: ("cPanel-SSL", "cPanel control panel (SSL)"),
    2222: ("SSH-ALT", "SSH on alternate port"),
    27017: ("MongoDB", "Document database"),
    3000: ("Dev-HTTP", "Common dev server (Node/React/etc.)"),
    3306: ("MySQL", "MySQL/MariaDB database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5000: ("Dev-HTTP", "Common dev server (Flask/etc.)"),
    5432: ("PostgreSQL", "PostgreSQL database"),
    5672: ("AMQP", "RabbitMQ / message queuing"),
    5900: ("VNC", "Virtual Network Computing (remote desktop)"),
    5984: ("CouchDB", "Document database"),
    6379: ("Redis", "In-memory data store"),
    7001: ("WebLogic", "Oracle WebLogic admin"),
    8000: ("HTTP-ALT", "Alternate HTTP / dev server"),
    8008: ("HTTP-ALT", "Alternate HTTP"),
    8080: ("HTTP-PROXY", "Alternate HTTP / proxy / app server"),
    8443: ("HTTPS-ALT", "Alternate HTTPS / admin console"),
    8888: ("HTTP-ALT", "Alternate HTTP / Jupyter, etc."),
    9000: ("HTTP-ALT", "Alternate HTTP / PHP-FPM"),
    9092: ("Kafka", "Event streaming"),
    9200: ("Elasticsearch", "Search & indexing (HTTP)"),
    11211: ("Memcached", "In-memory caching"),
    27018: ("MongoDB", "Document database (shard)"),
    50000: ("DB2", "IBM DB2 database"),
}

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREY = "\033[90m"


def supports_color() -> bool:
    return sys.stdout.isatty()


def c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or a mix like '22,80,1000-1010'."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    bad = [p for p in ports if p < 1 or p > 65535]
    if bad:
        raise ValueError(f"Port(s) out of range (1-65535): {bad}")
    return sorted(ports)


def resolve_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def grab_banner(ip: str, port: int, timeout: float) -> str | None:
    """Best-effort banner grab. Returns a short, cleaned-up string or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Many services (HTTP, etc.) wait for the client to speak first.
            if port in (80, 8080, 8000, 8008, 8888, 9000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            if not data:
                return None
            text = data.decode(errors="replace").strip()
            # Collapse to a single line, trim length for display.
            text = " ".join(text.split())
            return text[:120]
    except (OSError, socket.timeout):
        return None


def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict:
    result = {"port": port, "open": False, "service": None, "description": None, "banner": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((ip, port))
            if code == 0:
                result["open"] = True
    except OSError:
        pass

    if result["open"]:
        name, desc = COMMON_PORTS.get(port, ("Unknown", "No common-service mapping for this port"))
        result["service"] = name
        result["description"] = desc
        if grab:
            result["banner"] = grab_banner(ip, port, timeout)
    return result


def scan(target: str, ports: list[int], threads: int, timeout: float, grab: bool, quiet: bool):
    color = supports_color() and not quiet
    ip = resolve_target(target)

    if not quiet:
        print(c("=" * 60, GREY, color))
        print(c(f"  Port Scanner -> {target} ({ip})", BOLD + CYAN, color))
        print(c(f"  Ports: {len(ports)}   Threads: {threads}   Timeout: {timeout}s", DIM, color))
        print(c("=" * 60, GREY, color))

    started = time.time()
    open_results: list[dict] = []
    closed_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, ip, p, timeout, grab): p for p in ports}
        done = 0
        total = len(futures)
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            res = fut.result()
            if res["open"]:
                open_results.append(res)
                if not quiet:
                    line = f"[OPEN]  {res['port']:>6}  {res['service']:<14} {res['description']}"
                    print(c(line, GREEN, color))
                    if res["banner"]:
                        print(c(f"          banner: {res['banner']}", DIM, color))
            else:
                closed_count += 1
            if not quiet and total > 200 and done % 500 == 0:
                pct = done / total * 100
                print(c(f"  ... {done}/{total} scanned ({pct:.0f}%)", GREY, color), file=sys.stderr)

    elapsed = time.time() - started
    open_results.sort(key=lambda r: r["port"])

    summary = {
        "target": target,
        "ip": ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ports_scanned": len(ports),
        "open_ports": open_results,
        "closed_or_filtered": closed_count,
        "duration_seconds": round(elapsed, 2),
    }

    if not quiet:
        print(c("-" * 60, GREY, color))
        print(c(f"  Done in {elapsed:.2f}s  |  {len(open_results)} open  |  "
                f"{closed_count} closed/filtered", BOLD, color))
        print(c("=" * 60, GREY, color))

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner with common-service identification.",
        epilog="Only scan hosts you own or are authorized to test.",
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan: '1-1024', '22,80,443', or a mix (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of concurrent worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.75,
                         help="Per-connection timeout in seconds (default: 0.75)")
    parser.add_argument("--no-banner", action="store_true",
                         help="Skip banner grabbing (faster, less intrusive)")
    parser.add_argument("--json", metavar="FILE",
                         help="Write full results as JSON to FILE (use this to feed the dashboard)")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Suppress live output; only print/save the final summary")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    try:
        summary = scan(
            target=args.target,
            ports=ports,
            threads=max(1, args.threads),
            timeout=args.timeout,
            grab=not args.no_banner,
            quiet=args.quiet,
        )
    except socket.gaierror:
        print(f"Error: could not resolve host '{args.target}'", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        sys.exit(130)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
        if not args.quiet:
            print(f"\nResults written to {args.json}")

    if args.quiet:
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
