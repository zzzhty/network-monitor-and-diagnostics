"""Child-process-only socket/SSL fakes. Never open a socket or resolve a name."""
import json
from pathlib import Path
import socket
import ssl
import time


def install(scenario, report):
    now = 0.0
    events = []
    attempts = iter(scenario.get('connect', [{}]))

    def record(*event):
        events.append(event)
        Path(report).write_text(json.dumps(events))

    def advance(delay, limit=None):
        nonlocal now
        if limit is not None and delay > limit:
            now += limit
            raise socket.timeout('SYNTHETIC_PRIVATE_TIMEOUT')
        now += delay

    def fail(name):
        errors = {
            'dns': socket.gaierror,
            'refused': ConnectionRefusedError,
            'timeout': socket.timeout,
            'verify': ssl.SSLCertVerificationError,
            'tls': ssl.SSLError,
        }
        if name:
            raise errors[name]('SYNTHETIC_PRIVATE_ERROR')

    def resolve(host, port, *args, **kwargs):
        record('dns', host, port)
        if scenario.get('dns_block'):
            time.sleep(30)  # The real parent deadline must kill this child.
        advance(scenario.get('dns_delay', 0.1))
        fail(scenario.get('dns_error'))
        if scenario.get('empty_dns'):
            return []
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                 ('2001:db8::1', port, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                 ('192.0.2.1', port))][:len(scenario.get('connect', [{}]))]

    class FakeSocket:
        def __init__(self, family, socktype, proto=0, *args, **kwargs):
            self.index = sum(event[0] == 'socket' for event in events)
            self.timeout = None
            self.closed = False
            record('socket', self.index, family, socktype, proto)

        def settimeout(self, timeout):
            self.timeout = timeout
            record('timeout', self.index, timeout)

        def connect(self, address):
            record('connect', self.index, address)
            plan = next(attempts)
            advance(plan.get('delay', 0.2), self.timeout)
            fail(plan.get('error'))

        def close(self):
            if not self.closed:
                self.closed = True
                record('close', self.index)

    class Context:
        def wrap_socket(self, sock, server_hostname=None):
            record('tls', server_hostname)
            advance(scenario.get('tls_delay', 0.3), sock.timeout)
            fail(scenario.get('tls_error'))
            return sock

    def context():
        advance(scenario.get('context_delay', 0))
        return Context()

    # Patch the network primitives, leaving the production child and _run intact.
    socket.getaddrinfo = resolve
    socket.socket = FakeSocket
    ssl.create_default_context = context
    time.monotonic = lambda: now
