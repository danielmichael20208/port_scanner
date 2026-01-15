#!/usr/bin/env python3
"""
Hybrid Mode Port Scanner (Fingerprint Edition)
Features:
- TCP connect scan
- Banner grabbing
- TTL extraction
- Basic OS fingerprinting
- SIEM JSON log emission
"""

import socket
import re
import json
from datetime import datetime, timezone
from tools.log_writer_example import log_event

DEFAULT_PORTS = [22, 80, 443, 139, 445, 3389, 8080, 8443]  # Expand as needed


def guess_os_from_ttl(ttl):
    """Rough OS fingerprinting from TTL."""
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco/Networking Device"
    return "Unknown"


def grab_banner(sock):
    try:
        sock.settimeout(1.5)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except Exception:
        return None


def extract_ttl_from_socket(sock):
    try:
        # Retrieve TTL from IP level
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        return ttl
    except Exception:
        return None


def scan_port(host, port):
    result = {
        "port": port,
        "open": False,
        "service": None,
        "banner": None,
        "ttl": None,
        "os_guess": None
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)

        # Connect scan
        connect = sock.connect_ex((host, port))
        if connect == 0:
            result["open"] = True
            result["banner"] = grab_banner(sock)
            result["ttl"] = extract_ttl_from_socket(sock)
            result["os_guess"] = guess_os_from_ttl(result["ttl"])

        sock.close()
    except Exception:
        pass

    return result


def scan_host(host, ports=DEFAULT_PORTS):
    events = []

    for port in ports:
        res = scan_port(host, port)

        if res["open"]:
            service = identify_service(port, res["banner"])
            res["service"] = service

            # Log event to SIEM
            log_event(
                source="scan",
                component="PortScanner",
                level="OPEN",
                event_type="PORT_OPEN",
                message=f"Port {port} open ({service}).",
                context={
                    "host": host,
                    "port": port,
                    "service": service,
                    "ttl": res["ttl"],
                    "os_guess": res["os_guess"],
                    "banner": res["banner"]
                }
            )

            events.append(res)

    return events


def identify_service(port, banner):
    """Map port + banners to services."""
    common = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    if banner:
        if "SSH" in banner.upper():
            return "SSH"
        if "HTTP" in banner.upper():
            return "HTTP"
        if "SMB" in banner.upper():
            return "SMB"
        if "RDP" in banner.upper():
            return "RDP"
    return common.get(port, "Unknown")


if __name__ == "__main__":
    print("=== Port Scanner (Fingerprint Edition) ===")
    host = input("Enter target host (default = 127.0.0.1): ").strip() or "127.0.0.1"

    print(f"Scanning {host} ...")
    results = scan_host(host)

    if not results:
        print("No open ports found.")
    else:
        print("\nOpen ports discovered:")
        for r in results:
            print(f"{r['port']}/tcp open {r['service']} (OS: {r['os_guess']}, TTL={r['ttl']})")

    print("\n(Event logs written to data/logs_web.json)")
