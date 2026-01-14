#!/usr/bin/env python3
"""
Simple TCP Port Scanner
Author: Daniel Michael

Usage:
    python port_scanner.py
"""

import socket
from datetime import datetime

# A small set of common ports to scan by default
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3389: "RDP"
}

def scan_port(target, port, timeout=0.5):
    """Return True if port is open, False otherwise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_target(target, ports):
    print(f"\n[+] Starting scan on: {target}")
    print(f"[+] Ports to scan: {len(ports)}")
    print(f"[+] Time: {datetime.now()}\n")

    open_ports = []

    for port in ports:
        if scan_port(target, port):
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"  [OPEN] Port {port:<5} ({service})")
            open_ports.append(port)

    if not open_ports:
        print("\n[-] No open ports found in the selected list.")
    else:
        print(f"\n[+] Scan complete. {len(open_ports)} open ports detected.")

def parse_port_input(port_input):
    """
    Accepts:
      - 'common' → use COMMON_PORTS
      - '1-1024' → a range
      - '80,443,8080' → list of ports
    """
    port_input = port_input.strip().lower()

    if port_input == "common":
        return sorted(COMMON_PORTS.keys())

    ports = set()

    # Handle comma-separated list
    for part in port_input.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:  # Range like 20-80
            try:
                start, end = part.split("-")
                start = int(start)
                end = int(end)
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                print(f"[!] Invalid range: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
                else:
                    print(f"[!] Port out of range (1-65535): {p}")
            except ValueError:
                print(f"[!] Invalid port: {part}")

    return sorted(ports)

def main():
    print("=== Simple TCP Port Scanner ===")
    print("NOTE: Only scan systems you own or have permission to test.\n")

    target = input("Target (IP or hostname, e.g. 127.0.0.1): ").strip()
    if not target:
        print("No target entered. Exiting.")
        return

    print("\nPort selection:")
    print("  - Type 'common' to scan common ports (recommended)")
    print("  - Or enter range/list (e.g. '1-1024' or '22,80,443')")

    port_input = input("Ports to scan: ").strip()
    ports = parse_port_input(port_input)

    if not ports:
        print("No valid ports selected. Exiting.")
        return

    try:
        scan_target(target, ports)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except socket.gaierror:
        print("[!] Hostname could not be resolved.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()
