# Port Scanner

A lightweight Python tool that scans TCP ports on a target host and identifies which services are open. Useful for cybersecurity learning, basic reconnaissance, and network diagnostics.

## Features
- Scan common ports or custom ranges
- Detect open TCP ports
- Recognize service banners (FTP, SSH, HTTP, etc.)
- Prevent out-of-range and malformed input
- Graceful keyboard interrupt handling
- Local and remote scanning support

## Technologies
- Python 3
- Socket
- Standard library networking
- Basic CLI I/O

## How It Works
- The scanner attempts to establish TCP connections on selected ports:
- SYN → SYN/ACK → OPEN
- SYN → RST → CLOSED
- TIMEOUT → FILTERED/UNKNOWN
- Open ports are printed along with known service names (SSH, HTTP, etc).

## How to Run
```bash
python port_scanner.py
