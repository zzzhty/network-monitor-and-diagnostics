"""One-click layered egress diagnosis for the loopback GUI.

Fixed public probe targets and a fixed candidate battery only; the verdict is
a pure function of the collected results. No client input reaches argv or
URLs, the private store is only read, and node addresses never leave the
host. This automates the manual fault matrix in docs/diagnostics-runbook.md
section 3.3; it does not replace the runbook when the GUI is unreachable.
"""
import concurrent.futures
import socket
import time

import nmd_monitor

SCHEMA_VERSION = 1
# Public constant targets. They are fixed server-side and mirror the rule
# layers: DIRECT, GEOSITE,cn -> DIRECT, MATCH -> selected node, and the same
# egress chain without any DNS step. Never client-supplied.
DIRECT_FOREIGN_URL = "https://connectivity-check.ubuntu.com/"
EGRESS_CN_URL = "https://www.baidu.com/"
EGRESS_FOREIGN_URL = "https://www.cloudflare.com/"
EGRESS_EXIT_IP_URL = "https://1.1.1.1/"
HTTP_PROBES = (("direct_foreign", DIRECT_FOREIGN_URL), ("egress_cn", EGRESS_CN_URL),
               ("egress_foreign", EGRESS_FOREIGN_URL), ("egress_exit_ip", EGRESS_EXIT_IP_URL))
HTTP_TIMEOUT_S = 8
HTTP_CONNECT_S = 5
TCP_TIMEOUT_S = 3
DEGRADED_MS = 3000
CURL_ERROR_CODES = {6: "dns_error", 7: "connect_error", 28: "timeout",
                    35: "tls_error", 60: "tls_verify_error"}
# Tailnet addresses are route-excluded from the TUN, so a raw TCP connect to
# them bypasses mihomo; every other server address would route through the
# TUN itself and could not serve as a bypass probe.
TCP_SKIP_REASON = "server_routed_through_tun"


def http_probe(url):
    """One fixed-target HEAD via the system path; argv constants only."""
    argv = ["/usr/bin/curl", "--disable", "--globoff", "--silent", "--head",
            "--output", "/dev/null", "--max-time", str(HTTP_TIMEOUT_S),
            "--connect-timeout", str(HTTP_CONNECT_S), "--max-redirs", "0",
            "--proto", "=http,https", "--write-out",
            "%{http_code} %{time_total}", "--proxy", "", "--url", url]
    code, out, error = nmd_monitor._run(argv, HTTP_TIMEOUT_S + 2)
    if error:
        return {"status": "fail", "error": error, "total_ms": None}
    if code != 0:
        return {"status": "fail", "error": CURL_ERROR_CODES.get(code, "probe_error"), "total_ms": None}
    try:
        http, total = out.split()
        http, total = int(http), float(total)
        if not 100 <= http <= 599 or total < 0:
            raise ValueError()
    except (ValueError, IndexError):
        return {"status": "fail", "error": "invalid_probe_output", "total_ms": None}
    total_ms = int(round(total * 1000))
    if 200 <= http < 400:
        return {"status": "ok", "error": None, "total_ms": total_ms}
    return {"status": "fail", "error": "http_status", "total_ms": total_ms}


def tcp_probe(host, port):
    """Raw TCP connect for tailnet-kind candidates; no proxy, no DNS name."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), TCP_TIMEOUT_S):
            return "ok", int(round((time.monotonic() - start) * 1000))
    except ConnectionRefusedError:
        return "refused", None
    except (socket.timeout, TimeoutError):
        return "timeout", None
    except OSError:
        return "unreachable", None


def verdict(probes, candidates):
    """Pure decision tree over the fixed results; no network, clock or store.

    Controller faults are always reported distinctly and never counted as
    node failures, matching the auto-evaluator semantics.
    """
    def ok(name):
        return probes.get(name, {}).get("status") == "ok"

    healths = [row.get("health") for row in candidates]
    tcps = [row.get("tcp") for row in candidates if row.get("kind") == "tailnet"]
    all_fail = bool(healths) and all(health == "fail" for health in healths)
    if not ok("direct_foreign"):
        code = "local_internet_down"
    elif any(health == "controller_unreachable" for health in healths):
        code = "controller_unreachable"
    elif all_fail and "refused" in tcps:
        code = "node_service_down"
    elif all_fail and ({"timeout", "unreachable"} & set(tcps)):
        code = "node_network_unreachable"
    elif all_fail and "ok" in tcps and not ok("egress_exit_ip"):
        # Port answers TCP but neither healthchecks nor the chain respond: a
        # hung node service (or a dead node-side egress) — distinguish from
        # network loss, which the tcp probe above already classifies.
        code = "node_service_unresponsive"
    elif (any(health == "fail" for health in healths)
            and ok("egress_exit_ip") and not ok("egress_foreign")):
        code = "exit_dns_poisoned"
    elif all(ok(name) for name, _ in HTTP_PROBES) and all(health != "fail" for health in healths):
        total = probes.get("egress_foreign", {}).get("total_ms")
        code = "egress_degraded" if total is not None and total > DEGRADED_MS else "egress_healthy"
    else:
        code = "egress_anomaly"
    return {"code": code, "hint_key": code}


def build_report(directory, http_probe=http_probe, tcp_probe=tcp_probe,
                 delay_probe=None, selector_now=None, now=None):
    """Run the fixed parallel battery once; reads the private store, never writes."""
    import egress_sources
    value = egress_sources.Store(directory).load()
    policy = egress_sources._policy(value.get("auto"))
    pins = policy.get("candidates") if isinstance(policy, dict) else None
    candidates = []
    if pins:
        for pin in pins:
            source = value["sources"].get(pin["source"], {})
            candidates.append({"source": pin["source"], "kind": source.get("kind"),
                               "node": pin["node"]})
    if delay_probe is None:
        client = egress_sources.Controller(value)

        def delay_probe(source_id, node):
            return client.delay("nmd-" + source_id, node)

    def run_candidate(entry):
        result = dict(entry)
        try:
            result["delay_ms"] = int(delay_probe(entry["source"], entry["node"]))
            result["health"] = "ok"
        except egress_sources.ControllerProbeError:
            # No trustworthy node result; never a node failure.
            result["health"], result["delay_ms"] = "controller_unreachable", None
        except egress_sources.SourceError as exc:
            result["health"] = "fail" if str(exc) == "delay_test_failed" else "controller_unreachable"
            result["delay_ms"] = None
        source = value["sources"].get(entry["source"], {})
        if entry["kind"] == "tailnet" and "server" in source:
            result["tcp"], result["tcp_ms"] = tcp_probe(source["server"], source["port"])
        else:
            result["tcp"], result["tcp_ms"] = "skipped", None
            result["tcp_reason"] = TCP_SKIP_REASON
        return result

    def run_selector():
        if selector_now is not None:
            return selector_now(value)
        try:
            current = egress_sources.Controller(value).current().get("now")
            return current if isinstance(current, str) and current else None
        except (egress_sources.SourceError, OSError, ValueError):
            return None

    # Every task bounds itself (--max-time / connect timeout / probe timeout);
    # the pool only spreads them, so wall time stays inside the endpoint budget.
    with concurrent.futures.ThreadPoolExecutor(max_workers=5 + len(candidates)) as pool:
        http_futures = [(name, pool.submit(http_probe, url)) for name, url in HTTP_PROBES]
        candidate_futures = [pool.submit(run_candidate, entry) for entry in candidates]
        selector_future = pool.submit(run_selector)
        probes = {name: future.result() for name, future in http_futures}
        rows = [future.result() for future in candidate_futures]
        selector = selector_future.result()
    return {"schema_version": SCHEMA_VERSION, "generated_at": now() if now else time.time(),
            "probes": probes, "verdict": verdict(probes, rows),
            "candidates": rows, "selector_now": selector}
