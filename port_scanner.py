#!/usr/bin/env python3
"""
Hybrid Mode Port Scanner (Fingerprint Edition)
Cybersecurity tool that performs:
✔ TCP connect scanning
✔ Full port state enumeration
✔ Banner grabbing
✔ TTL extraction
✔ OS fingerprinting
✔ Structured SIEM JSON logging for DanielOS
"""

import socket
from tools.log_writer import log_event

DEFAULT_PORTS = [22, 80, 443, 139, 445, 3389, 8080, 8443]


def guess_os_from_ttl(ttl):
    if ttl is None:
        return "Unknown"
    if ttl <= 64: return "Linux/Unix"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Networking"
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
        return sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
    except Exception:
        return None


def scan_port(host, port, timeout=1.0):
    result = {
        "port": port,
        "state": None,
        "service": None,
        "banner": None,
        "ttl": None,
        "os_guess": None,
        "reason": None
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        code = sock.connect_ex((host, port))

        if code == 0:
            result["state"] = "open"
            result["banner"] = grab_banner(sock)
            result["ttl"] = extract_ttl_from_socket(sock)
            result["os_guess"] = guess_os_from_ttl(result["ttl"])
            result["reason"] = "connection-accepted"

        elif code in (111, 10061):
            result["state"] = "refused"
            result["reason"] = "connection-refused"

        elif code == 113:
            result["state"] = "filtered"
            result["reason"] = "icmp-filtered"

        else:
            result["state"] = "closed"
            result["reason"] = f"connect-ex-code-{code}"

        sock.close()

    except socket.timeout:
        result["state"] = "timeout"
        result["reason"] = "no-response"

    except Exception as e:
        result["state"] = "error"
        result["reason"] = str(e)

    return result


def identify_service(port, banner):
    common = {
        22: "SSH", 80: "HTTP", 443: "HTTPS",
        139: "NetBIOS", 445: "SMB", 3389: "RDP",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }
    if banner:
        b = banner.upper()
        if "SSH" in b: return "SSH"
        if "HTTP" in b: return "HTTP"
        if "SMB" in b: return "SMB"
        if "RDP" in b: return "RDP"
    return common.get(port, "Unknown")


def scan_host(host, ports=DEFAULT_PORTS):
    results = []

    for port in ports:
        res = scan_port(host, port)
        state = res["state"]

        # severity mapping
        if state == "open":
            res["service"] = identify_service(port, res["banner"])
            level = "WARN"
            event_type = "PORT_OPEN"

        elif state in ("refused", "filtered", "closed", "timeout"):
            level = "INFO"
            event_type = f"PORT_{state.upper()}"

        else:
            level = "ERROR"
            event_type = "PORT_ERROR"

        log_event(
            source="SCAN",
            level=level,
            event_type=event_type,
            message=f"{state.upper()} port {port}",
            context={
                "host": host,
                "port": port,
                "state": state,
                "reason": res["reason"],
                "service": res.get("service"),
                "ttl": res.get("ttl"),
                "os_guess": res.get("os_guess"),
                "banner": res.get("banner"),
            }
        )

        results.append(res)

    return results


if __name__ == "__main__":
    print("=== Port Scanner (Fingerprint Edition) ===")
    target = input("Enter target (default: 127.0.0.1): ").strip() or "127.0.0.1"
    print(f"Scanning {target}...\n")

    scan_results = scan_host(target)

    for r in scan_results:
        svc = f"({r['service']})" if r.get("service") else ""
        os = f"OS={r['os_guess']}" if r.get("os_guess") else ""
        print(f"{r['port']}/tcp {r['state'].upper()} {svc} {os}")

    print("\n(Event logs written to data/logs_web.json)")

    from tools.upload_logs import upload_logs
    upload_logs()
    from tools.upload_logs import upload_logs
    upload_logs("auto")
