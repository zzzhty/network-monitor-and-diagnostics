#!/usr/bin/env python3
"""Fail if Tailscale bootstrap DNS returns fake IPs (system DNS by default)."""
import ipaddress
import socket
import subprocess
import sys

failed = False
for host in ("login.tailscale.com", "controlplane.tailscale.com",
             "log.tailscale.com", "derp1.tailscale.com"):
    try:
        if len(sys.argv) == 2:
            result = subprocess.run(
                ["dig", "@127.0.0.1", "-p", sys.argv[1], "+short",
                 "+time=2", "+tries=1", host, "A"],
                check=True, text=True, capture_output=True, timeout=4)
            addresses = []
            for line in result.stdout.splitlines():
                try:
                    addresses.append(ipaddress.ip_address(line))
                except ValueError:  # CNAME
                    pass
        else:
            addresses = {ipaddress.ip_address(row[4][0]) for row in
                         socket.getaddrinfo(host, 443, socket.AF_INET,
                                            socket.SOCK_STREAM)}
        if not addresses or any(ip in ipaddress.ip_network("198.18.0.0/15")
                                for ip in addresses):
            raise ValueError("empty DNS answer or fake-ip: " + str(addresses))
        print("PASS real DNS:", host, ", ".join(map(str, addresses)))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("FAIL DNS:", host, exc)
        failed = True
sys.exit(1 if failed else 0)
