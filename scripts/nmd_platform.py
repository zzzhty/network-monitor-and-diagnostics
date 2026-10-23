"""OS boundaries for diagnostics; no network configuration or lifecycle changes."""
import hashlib
import os
import re
from pathlib import Path
import stat
import sys


def name():
    if sys.platform.startswith('linux'):
        return 'linux'
    return 'macos' if sys.platform == 'darwin' else 'unsupported'


def state_parts(parts):
    """Allow only macOS's fixed, root-owned /var, /tmp and /etc aliases.

    User-controlled symlinks and '..' components are still rejected by the caller.
    Never resolve an entire user-supplied state path.
    """
    aliases = {'var': '/private/var', 'tmp': '/private/tmp', 'etc': '/private/etc'}
    if sys.platform == 'darwin' and len(parts) > 1 and parts[1] in aliases:
        alias, target = '/' + parts[1], aliases[parts[1]]
        info = os.lstat(alias)
        if stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or os.path.normpath('/' + os.readlink(alias).lstrip('/')) != target:
                raise ValueError('unsafe_system_directory_alias')
            return Path(target).parts + parts[2:]
    return parts


def database_path(fd):
    """Keep SQLite tied to the verified directory, including after a rename.

    Linux uses procfs. Darwin's volume/file-ID lookup is verified against fstat;
    an unavailable filesystem/OS mechanism fails closed instead of following the
    original pathname. The open directory handle keeps the inode alive.
    """
    if sys.platform.startswith('linux'):
        return f'/proc/self/fd/{fd}/monitor.sqlite3'
    if sys.platform == 'darwin':
        expected = os.fstat(fd)
        directory = f'/.vol/{expected.st_dev}/{expected.st_ino}'
        try:
            actual = os.stat(directory)
        except OSError:
            raise ValueError('state_directory_identity_unavailable') from None
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise ValueError('state_directory_identity_unavailable')
        return directory + '/monitor.sqlite3'
    raise ValueError('unsupported_platform')


def _empty_local(platform):
    return dict(platform=platform, status='unknown', error='local_unavailable',
                interfaces=[], interface_states={}, interface_observation_error=None,
                route_fingerprint=None, ipv4_default_routes=None,
                route_observation_error=None, services={},
                service_observation_error='unsupported_platform')


def _linux_sample(run):
    local = _empty_local('linux')
    local['error'] = None
    try:
        local['interfaces'] = sorted(p.name for p in Path('/sys/class/net').iterdir())[:64]
        local['interface_states'] = {}
        for name in local['interfaces']:
            try:
                state = (Path('/sys/class/net') / name / 'operstate').read_text().strip()
                local['interface_states'][name] = state if state in ('up', 'down', 'unknown', 'dormant', 'notpresent', 'lowerlayerdown', 'testing') else 'unknown'
            except OSError:
                local['interface_states'][name] = 'unknown'
        local['status'] = 'observed'
    except OSError:
        local['error'] = 'local_unavailable'
        local['interface_observation_error'] = 'local_unavailable'
    try:
        with open('/proc/net/route', 'rb') as f:
            routes = f.read(65536)
        local['route_fingerprint'] = hashlib.sha256(routes).hexdigest()[:16]
        local['ipv4_default_routes'] = sum(1 for line in routes.splitlines()[1:] if len(line.split()) > 1 and line.split()[1] == b'00000000')
    except OSError:
        local['route_fingerprint'] = None
        local['route_observation_error'] = 'route_unavailable'
    code, output, error = run(['/usr/bin/systemctl', '--no-pager', 'show',
                                 'mihomo.service', 'tailscaled.service', 'systemd-resolved.service',
                                 '--property=Id,ActiveState,SubState,LoadState'], 2)
    local['services'] = {}
    if code == 0 and not error:
        for block in output.strip().split('\n\n'):
            fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            name = fields.get('Id')
            if name in ('mihomo.service', 'tailscaled.service', 'systemd-resolved.service'):
                local['services'][name] = {key: value for key, value in fields.items()
                                          if key in ('ActiveState', 'SubState', 'LoadState') and re.fullmatch(r'[a-z-]{1,32}', value)}
    if local['services']:
        local['status'] = 'observed'
    local['service_observation_error'] = error or (None if code == 0 else 'service_query_unavailable')
    return local


def _macos_sample(run):
    local = _empty_local('macos')
    code, output, error = run(['/sbin/ifconfig', '-a'], 2)
    if code == 0 and not error:
        states, current = {}, None
        for line in output.splitlines():
            match = re.match(r'^([A-Za-z0-9_.:-]{1,32}): flags=[0-9a-fA-F]+<[^>]*>', line)
            if match:
                current = match.group(1)
                if len(states) < 64:
                    states[current] = 'unknown'
                else:
                    current = None
            elif current is not None:
                match = re.fullmatch(r'\s+status: (active|inactive)\s*', line)
                if match:
                    states[current] = 'up' if match.group(1) == 'active' else 'down'
        if states:
            local.update(interfaces=sorted(states), interface_states=states,
                         status='observed', error=None)
        else:
            local['interface_observation_error'] = 'invalid_interface_output'
    else:
        local['interface_observation_error'] = error or 'interface_query_unavailable'

    code, output, error = run(['/usr/sbin/netstat', '-rn', '-f', 'inet'], 2)
    if code == 0 and not error:
        lines = [line.split() for line in output.splitlines() if line.strip()]
        header = next((i for i, fields in enumerate(lines)
                       if fields[:3] == ['Destination', 'Gateway', 'Flags'] and 'Netif' in fields), None)
        if header is not None and all(len(row) >= 4 for row in lines[header + 1:]):
            routes = lines[header + 1:]
            local['route_fingerprint'] = hashlib.sha256(repr(sorted(routes)).encode()).hexdigest()[:16]
            local['ipv4_default_routes'] = sum(row[0] in ('default', '0.0.0.0') for row in routes)
            local.update(status='observed', error=None)
        else:
            local['route_observation_error'] = 'invalid_route_output'
    else:
        local['route_observation_error'] = error or 'route_query_unavailable'
    return local


def sample_local(run):
    """Read a bounded, fixed set of passive OS metadata, never tool configs.

    Names and link status are evidence only; none of these facts prove internet
    connectivity, traffic routing through a proxy, or service health.
    """
    platform = name()
    if platform == 'linux':
        return _linux_sample(run)
    if platform == 'macos':
        return _macos_sample(run)
    result = _empty_local(platform)
    result.update(error='unsupported_platform', interface_observation_error='unsupported_platform',
                  route_observation_error='unsupported_platform')
    return result


def capabilities():
    platform = name()
    return dict(schema_version=1, component='nmd-observability', read_only_gui=platform != 'linux',
                local_egress_control=platform == 'linux',
                commands=['monitor run', 'monitor status', 'monitor config-check', 'gui', 'demo'],
                platform=platform, supported_platforms=['linux', 'macos'],
                network_mutations=False, native_desktop=False,
                local_observations=dict(interfaces=platform in ('linux', 'macos'),
                                        ipv4_routes=platform in ('linux', 'macos'),
                                        systemd_services=platform == 'linux'),
                background_service=platform == 'linux',
                limitations=(['systemd_services_unsupported', 'background_service_unsupported',
                              'network_management_unsupported', 'egress_sources_disabled'] if platform == 'macos'
                             else ['unsupported_platform'] if platform == 'unsupported' else []))
