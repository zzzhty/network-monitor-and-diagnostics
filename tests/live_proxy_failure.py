#!/usr/bin/env python3
"""Run real mihomo without TUN, with a dead VPS; requires direct internet access.

Uses temporary data/ports and the physical default interface, never the service.
Optional config path permits replaying the same checks against an old config.
This does not test host routing, resolved integration, or a real TUN crash.
"""
from pathlib import Path
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def replace_once(config, old, new):
    if config.count(old) != 1:
        raise RuntimeError("Cannot isolate config field")
    return config.replace(old, new, 1)


def check_connectivity_probe(mixed, dns, interface, env):
    host = "connectivity-check.ubuntu.com"
    answer = subprocess.check_output(
        ["dig", "@127.0.0.1", "-p", str(dns), "+short", "+time=2", "+tries=1",
         host, "A"], text=True, timeout=5)
    addresses = []
    for line in answer.splitlines():
        try:
            addresses.append(ipaddress.ip_address(line))
        except ValueError:  # CNAME
            pass
    if not addresses or any(ip in ipaddress.ip_network("198.18.0.0/15")
                            for ip in addresses):
        raise RuntimeError("NetworkManager probe needs real DNS addresses: " + answer.strip())
    # Replay the interface-bound request with the isolated resolver's answer.
    # Also require DIRECT when the same domain is sent through mihomo.
    paths = (
        ("physical interface", ["--noproxy", "*", "--interface", interface,
                                "--resolve", f"{host}:80:{addresses[0]}"]),
        ("dead VPS", ["--noproxy", "", "--proxy", f"http://127.0.0.1:{mixed}"]),
    )
    for name, options in paths:
        result = subprocess.run(
            ["curl", "-4", *options, "--connect-timeout", "4", "--max-time", "10",
             "-fsS", "-D", "-", "-o", "/dev/null", f"http://{host}/"],
            check=True, env=env, capture_output=True, text=True)
        if "x-networkmanager-status: online" not in result.stdout.lower():
            raise RuntimeError("NetworkManager probe did not report online: " + result.stdout)
        print("PASS NetworkManager probe with", name, flush=True)


def main():
    config = Path(sys.argv[1]).read_text() if len(sys.argv) > 1 else (ROOT / "config.yaml").read_text()
    route = json.loads(subprocess.check_output(
        ["ip", "-j", "route", "show", "table", "main", "default"], text=True))[0]
    interface = route["dev"]
    mixed, dns, api = port(), port(), port()
    config = replace_once(config, "tun:\n  enable: true", "tun:\n  enable: false")
    config = replace_once(config, "mixed-port: 7890", f"mixed-port: {mixed}")
    config = replace_once(config, "127.0.0.1:9090", f"127.0.0.1:{api}")
    config = replace_once(config, "127.0.0.1:1053", f"127.0.0.1:{dns}")
    config = replace_once(config, "geo-auto-update: true", "geo-auto-update: false")
    # The dead endpoint is held but not listening, so the VPS cannot connect.
    with socket.socket() as dead, tempfile.TemporaryDirectory(prefix="mihomo-test-") as tmp:
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        # Isolate the single upstream field in either the template or an operator config.
        server_lines = [line for line in config.splitlines() if line.lstrip().startswith("server:")]
        if len(server_lines) != 1:
            raise RuntimeError("Expected one upstream server field for isolation")
        isolated = server_lines[0].partition("server:")[0] + "server: 127.0.0.1"
        config = replace_once(config, server_lines[0], isolated)
        config = replace_once(config, "port: 1080", f"port: {dead_port}")
        config = replace_once(config, "interface-name: tailscale0", "interface-name: lo")
        config += f"\ninterface-name: {interface}\n"
        directory = Path(tmp)
        (directory / "config.yaml").write_text(config)
        for name in ("geoip.metadb", "GeoSite.dat"):
            shutil.copyfile(ROOT / name, directory / name)
        env = {k: v for k, v in os.environ.items() if k.lower() not in
               ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with (directory / "mihomo.log").open("w+") as log:
            process = subprocess.Popen(["/usr/bin/mihomo", "-d", tmp],
                                       stdout=log, stderr=log, env=env)
            try:
                for _ in range(60):
                    if process.poll() is not None:
                        raise RuntimeError("isolated mihomo exited")
                    try:
                        with opener.open(f"http://127.0.0.1:{api}/version", timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("isolated mihomo did not become ready")
                subprocess.run([sys.executable, str(ROOT / "scripts/check-tailscale-dns.py"),
                                str(dns)], check=True, timeout=25)
                check_connectivity_probe(mixed, dns, interface, env)
                for host, path in (("login.tailscale.com", "/"),
                                   ("controlplane.tailscale.com", "/derpmap/default")):
                    subprocess.run(["curl", "--noproxy", "", "--proxy",
                                    f"http://127.0.0.1:{mixed}", "--connect-timeout", "4",
                                    "--max-time", "10", "-fsS", "-o", "/dev/null",
                                    f"https://{host}{path}"], check=True, env=env)
                    print("PASS HTTPS with dead VPS:", host, flush=True)
                result = subprocess.run(["curl", "--noproxy", "", "--proxy",
                                         f"http://127.0.0.1:{mixed}", "--connect-timeout", "3",
                                         "--max-time", "5", "-fsS", "-o", "/dev/null",
                                         "https://www.cloudflare.com/cdn-cgi/trace"], env=env,
                                        capture_output=True)
                if result.returncode == 0:
                    raise RuntimeError("VPS negative control unexpectedly succeeded")
                print("PASS negative control: ordinary overseas request fails with dead VPS")
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
