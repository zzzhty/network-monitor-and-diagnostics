"""Independent, read-only connectivity collector for Linux and macOS. No probes without opt-in targets.

Protocol v1: snapshots contain collector metadata and newest-first samples/incidents/gaps.
A system probe follows kernel routing (including TUN); it is NOT a TUN bypass.
"""
import contextlib
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit, quote

import nmd_platform

SCHEMA_VERSION = 1
DEFAULT_CONFIG = dict(schema_version=1, interval_seconds=30, timeout_seconds=5,
                      retention_hours=168, max_samples=100000, probes=[])


def validate_config(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT_CONFIG):
        raise ValueError('invalid_config_keys')
    cfg = dict(DEFAULT_CONFIG, **value)
    if type(cfg['schema_version']) is not int or cfg['schema_version'] != 1:
        raise ValueError('unsupported_schema')
    for key, low, high in [('interval_seconds', 5, 3600), ('timeout_seconds', 1, 30),
                           ('retention_hours', 24, 720), ('max_samples', 100, 200000)]:
        v = cfg[key]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not low <= v <= high:
            raise ValueError('invalid_' + key)
    if type(cfg['max_samples']) is not int:
        raise ValueError('invalid_max_samples')
    if not isinstance(cfg['probes'], list) or len(cfg['probes']) > 16:
        raise ValueError('invalid_probes')
    probes, ids = [], set()
    for raw in cfg['probes']:
        if not isinstance(raw, dict) or set(raw) - {'id', 'type', 'target', 'path', 'proxy', 'enabled'}:
            raise ValueError('invalid_probe_keys')
        p = dict(path='system', **raw) if 'path' not in raw else dict(raw)
        if not isinstance(p.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', p.get('id', '')) or p['id'] in ids or p['id'] == 'local':
            raise ValueError('invalid_probe_id')
        ids.add(p['id'])
        if 'enabled' in p and type(p['enabled']) is not bool:
            raise ValueError('invalid_enabled')
        if p.get('type') not in ('http', 'dns', 'tcp', 'tls') or p['path'] not in ('system', 'proxy'):
            raise ValueError('invalid_probe_type_or_path')
        target = p.get('target')
        if not isinstance(target, str) or len(target) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in target):
            raise ValueError('invalid_target')
        if p['type'] == 'http':
            u = _url(target, ('http', 'https'))
        else:
            u = _url('tcp://' + target, ('tcp',))
            if u.path not in ('', '/') or (p['type'] == 'dns' and u.port is not None):
                raise ValueError('invalid_target')
            if p['type'] in ('tcp', 'tls') and u.port is None:
                raise ValueError('port_required')
        if p['path'] == 'proxy':
            if p['type'] != 'http':
                raise ValueError('proxy_requires_http')
            _url(p.get('proxy', ''), ('http', 'https', 'socks5', 'socks5h'))
        elif 'proxy' in p:
            raise ValueError('unexpected_proxy')
        probes.append(p)
    cfg['probes'] = probes
    return cfg


def _url(value, schemes):
    if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError('invalid_url')
    try:
        u = urlsplit(value)
        if u.scheme not in schemes or not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment or '%' in u.netloc or '\\' in value:
            raise ValueError('invalid_url')
        if u.port is not None and not 1 <= u.port <= 65535:
            raise ValueError('invalid_port')
    except ValueError:
        raise ValueError('invalid_url') from None
    return u


def load_config(path=None):
    if path is None:
        return validate_config({})
    with open(path, 'rb') as f:
        data = f.read(65537)
    if len(data) > 65536:
        raise ValueError('config_too_large')
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError('duplicate_config_key')
            d[k] = v
        return d
    return validate_config(json.loads(data, object_pairs_hook=pairs))


def _run(argv, timeout):
    """Fixed argv only; no inherited proxies, curlrc, credentials or shell."""
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, start_new_session=True)
    except FileNotFoundError:
        return None, '', 'tool_missing'
    except OSError:
        return None, '', 'launch_error'
    try:
        out, _ = proc.communicate(timeout=timeout)
        if len(out) > 65536:
            return None, '', 'output_too_large'
        return proc.returncode, out.decode('ascii', 'replace'), None
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return None, '', 'timeout'


_SOCKET_CODE = '''import socket,ssl,sys,time,json
kind,host,port,timeout=sys.argv[1:]
start=time.monotonic(); deadline=start+float(timeout); s=None
def remaining():
 budget=deadline-time.monotonic()
 if budget<=0: raise socket.timeout()
 return budget
try:
 # getaddrinfo itself is bounded by the parent process deadline.
 addresses=socket.getaddrinfo(host,int(port) if port else None,type=socket.SOCK_STREAM)
 timings={'dns':time.monotonic()-start}
 remaining()
 if kind=='dns': print(json.dumps(timings)); sys.exit(0)
 error=OSError('no_addresses')
 for family,socktype,proto,_,address in addresses:
  remaining()
  try:
   s=socket.socket(family,socktype,proto)
   s.settimeout(remaining()); s.connect(address)
   remaining()
   break
  except OSError as exc:
   if s is not None: s.close()
   s=None; error=exc
 if s is None:
  remaining()
  raise error
 timings['connect']=time.monotonic()-start
 if kind=='tls':
  context=ssl.create_default_context()
  s.settimeout(remaining())
  s=context.wrap_socket(s,server_hostname=host)
  remaining()
  timings['tls']=time.monotonic()-start
 timings['total']=time.monotonic()-start
 print(json.dumps(timings))
except socket.gaierror: sys.exit(6)
except (socket.timeout,TimeoutError): sys.exit(28)
except ssl.SSLCertVerificationError: sys.exit(60)
except ssl.SSLError: sys.exit(35)
except (OSError,ValueError): sys.exit(7)
finally:
 if s is not None: s.close()
'''


def sample_probe(config, stop_event=None):
    cfg = validate_config(config)
    now = time.time()
    local = {'id': 'local', 'type': 'passive', 'path': 'local', 'status': 'unknown',
             'error': None, 'timings': {}, 'observed_at': now}
    local.update(nmd_platform.sample_local(_run))
    results = [local]
    for p in cfg['probes']:
        r = {k: p[k] for k in ('id', 'type', 'path')}
        r.update(status='unknown', error=None, timings={}, observed_at=time.time())
        if stop_event is not None and stop_event.is_set():
            r.update(status='skipped', error='collector_stopping')
            results.append(r)
            continue
        if not p.get('enabled', True):
            r.update(status='skipped', error='disabled')
            results.append(r)
            continue
        timeout = cfg['timeout_seconds']
        if p['type'] == 'http':
            argv = ['/usr/bin/curl', '--disable', '--globoff', '--silent', '--head', '--output', '/dev/null',
                    '--max-time', str(timeout), '--connect-timeout', str(timeout),
                    '--max-redirs', '0', '--proto', '=http,https', '--write-out',
                    '%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}']
            argv += ['--proxy', p['proxy'], '--noproxy', ''] if p['path'] == 'proxy' else ['--proxy', '']
            argv += ['--url', p['target']]
        else:
            u = urlsplit('tcp://' + p['target'])
            argv = [sys.executable, '-I', '-c', _SOCKET_CODE, p['type'], u.hostname,
                    str(u.port or ''), str(timeout)]
        code, out, error = _run(argv, timeout + 0.5)
        r['observed_at'] = time.time()
        if error:
            r.update(status='failure' if error == 'timeout' else 'unknown', error=error)
        elif code != 0:
            r.update(status='failure', error={6: 'dns_error', 7: 'connect_error', 28: 'timeout',
                                            35: 'tls_error', 60: 'tls_verify_error'}.get(code, 'probe_error'))
        else:
            try:
                if p['type'] == 'http':
                    parts = out.split()
                    http = int(parts[0])
                    r['timings'] = dict(zip(('dns', 'connect', 'tls', 'first_byte', 'total'), map(float, parts[1:])))
                    if len(parts) != 6 or not 100 <= http <= 599:
                        raise ValueError()
                    r['http_status'] = http
                    r['status'] = 'success' if 200 <= http < 400 else 'failure'
                    if r['status'] == 'failure': r['error'] = 'http_status'
                else:
                    r['timings'] = json.loads(out)
                    r['status'] = 'success'
                if any(not isinstance(v, (float, int)) or not math.isfinite(v) or v < 0 for v in r['timings'].values()):
                    raise ValueError()
            except (ValueError, IndexError, TypeError, AttributeError):
                r.update(status='unknown', error='invalid_probe_output', timings={})
        results.append(r)
    return results


class _StateDirectory:
    """Pinned directory; only trusted owners may rename its ancestors.

    SQLite can canonicalize identity paths, including journal paths. The
    ancestor policy is therefore required as well as descriptor traversal.
    Processes running as this UID (or root) are outside this protection boundary.
    """
    def __init__(self, fd):
        self.fd = fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def database_path(self):
        return nmd_platform.database_path(self.fd)


def _check_directory(fd, leaf=False):
    st = os.fstat(fd)
    mode = stat.S_IMODE(st.st_mode)
    if leaf:
        if st.st_uid != os.getuid() or mode & 0o077:
            raise ValueError('state_directory_must_be_owner_private')
    elif (st.st_uid not in (0, os.getuid()) or
          (mode & 0o022 and not (st.st_uid == 0 and mode & stat.S_ISVTX))):
        raise ValueError('unsafe_state_directory_ancestor')


def _directory(path, create=False):
    if isinstance(path, _StateDirectory):
        return _StateDirectory(os.dup(path.fd))
    # Do not resolve symlinks or normalize away '..' before validating components.
    parts = Path(os.path.abspath(os.curdir), path).parts
    if '..' in parts:
        raise ValueError('unsafe_state_directory_component')
    parts = nmd_platform.state_parts(parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _check_directory(fd, leaf=len(parts) == 1)
        for index, name in enumerate(parts[1:], 1):
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            _check_directory(fd, leaf=index == len(parts) - 1)
        return _StateDirectory(fd)
    except OSError as error:
        os.close(fd)
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError('symlink_or_invalid_state_directory') from None
        raise
    except BaseException:
        os.close(fd)
        raise


def _regular(directory, name, create=False):
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= os.O_RDWR | os.O_CREAT if create else os.O_RDONLY
    try:
        fd = os.open(name, flags, 0o600, dir_fd=directory.fd)
    except FileNotFoundError:
        if create:
            raise
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError('unsafe_state_file') from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ValueError('unsafe_state_file')
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError('state_file_must_be_owner_private')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_database_files(directory):
    for suffix in ('', '-wal', '-shm', '-journal'):
        fd = _regular(directory, 'monitor.sqlite3' + suffix)
        if fd is not None:
            os.close(fd)


@contextlib.contextmanager
def collector_lock(state_dir):
    with _directory(state_dir, True) as directory:
        fd = _regular(directory, 'collector.lock', create=True)
        try:
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RuntimeError('collector_already_running') from None
            yield directory
        finally:
            os.close(fd)


class Store:
    def __init__(self, state_dir, config):
        self.config = validate_config(config)
        self._directory = _directory(state_dir, True)
        self.db = None
        try:
            _check_database_files(self._directory)
            fd = _regular(self._directory, 'monitor.sqlite3', create=True)
            os.close(fd)
            self.db = sqlite3.connect(self._directory.database_path)
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.executescript('''
            CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY,ts REAL,payload TEXT);
            CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
            CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,probe TEXT,first_failure REAL,confirmed_at REAL,last_success REAL,recovery_first REAL,recovered_at REAL,end_reason TEXT);
            CREATE TABLE IF NOT EXISTS gaps(id INTEGER PRIMARY KEY,start REAL,end REAL,reason TEXT);
            CREATE TABLE IF NOT EXISTS auto_events(id INTEGER PRIMARY KEY,ts REAL,kind TEXT,detail TEXT);
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
            ''')
            self.states = {}
            previous = self.meta('last_sample_at')
            if previous is not None: self.gap(previous, time.time(), 'collector_restart')
            self.setmeta('schema_version', 1)
            self.db.commit()
        except BaseException:
            if self.db is not None:
                self.db.close()
            self._directory.close()
            raise

    def meta(self, key):
        row = self.db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def setmeta(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', (key, json.dumps(value)))

    def gap(self, start, end, reason):
        self.db.execute('INSERT INTO gaps(start,end,reason) VALUES(?,?,?)', (start, end, reason))
        self.db.execute("UPDATE incidents SET end_reason='observation_gap' WHERE recovered_at IS NULL AND end_reason IS NULL")
        self.states.clear()

    def auto_event(self, kind, detail):
        now = time.time()
        detail_json = json.dumps(detail, sort_keys=True)
        if kind in {'controller_unreachable', 'auto_error'}:
            previous = self.meta('auto_fault')
            if (previous and previous['kind'] == kind and previous['detail'] == detail
                    and 0 <= now - previous['ts'] < 300):
                return
            self.setmeta('auto_fault', {'kind': kind, 'detail': detail, 'ts': now})
        # Keep a durable high-water mark, including legacy databases, so pruning
        # all rows never reuses notification IDs.
        maximum = self.db.execute('SELECT COALESCE(MAX(id),0) FROM auto_events').fetchone()[0]
        event_id = max(self.meta('auto_event_id') or 0, maximum) + 1
        self.db.execute('INSERT INTO auto_events(id,ts,kind,detail) VALUES(?,?,?,?)',
                        (event_id, now, kind, detail_json))
        self.setmeta('auto_event_id', event_id)

    def record(self, results, now=None):
        explicit_time = now is not None
        now = time.time() if now is None else now
        cycle_end = now
        for result in results:
            now = cycle_end if explicit_time else result.get('observed_at', cycle_end)
            self.db.execute('INSERT INTO samples(ts,payload) VALUES(?,?)', (now, json.dumps(result)))
            key, status = result['id'], result['status']
            if result['type'] == 'passive': continue
            s = self.states.setdefault(key, dict(fail=0, success=0, last_success=None, first=None, incident=None, recovery=None))
            if status not in ('success', 'failure'):
                if s['incident'] is not None:
                    self.db.execute("UPDATE incidents SET end_reason='observation_gap' WHERE id=?", (s['incident'],))
                    self.db.execute('INSERT INTO gaps(start,end,reason) VALUES(?,?,?)', (s.get('last_observed', now), now, 'probe_unknown:' + key))
                s['incident'] = None
                s['last_success'] = None
                s['fail'] = s['success'] = 0
                s['first'] = s['recovery'] = None
                continue
            s['last_observed'] = now
            if status == 'failure':
                s['success'] = 0; s['recovery'] = None
                if s['fail'] == 0: s['first'] = now
                s['fail'] += 1
                if s['fail'] >= 3 and s['incident'] is None:
                    cur = self.db.execute('INSERT INTO incidents(probe,first_failure,confirmed_at,last_success) VALUES(?,?,?,?)', (key, s['first'], now, s['last_success']))
                    s['incident'] = cur.lastrowid
            else:
                s['fail'] = 0; s['first'] = None; s['last_success'] = now
                if s['success'] == 0: s['recovery'] = now
                s['success'] += 1
                if s['incident'] is not None and s['success'] >= 2:
                    self.db.execute("UPDATE incidents SET recovery_first=?,recovered_at=?,end_reason='recovered' WHERE id=?", (s['recovery'], now, s['incident']))
                    s['incident'] = None
        now = cycle_end
        self.setmeta('last_sample_at', now)
        self.setmeta('interval_seconds', self.config['interval_seconds'])
        self.setmeta('expected_cycle_seconds', max(self.config['interval_seconds'], (4 if nmd_platform.name() == 'macos' else 2) + sum(p.get('enabled', True) for p in self.config['probes']) * (self.config['timeout_seconds'] + 0.5)))
        cutoff = now - self.config['retention_hours'] * 3600
        n = self.config['max_samples']
        maximum = self.db.execute('SELECT COALESCE(MAX(id),0) FROM auto_events').fetchone()[0]
        self.setmeta('auto_event_id', max(self.meta('auto_event_id') or 0, maximum))
        # Freeze the newest-n boundary in this write transaction before deleting.
        # SQLite 3.37 can evaluate a DELETE's self-reading subquery after its
        # time-range deletions, incorrectly retaining older in-window samples.
        boundary = self.db.execute('SELECT id FROM samples ORDER BY id DESC LIMIT 1 OFFSET ?', (n - 1,)).fetchone()
        # Fewer than n rows need only time pruning; NULL disables id pruning.
        self.db.execute('DELETE FROM samples WHERE ts < ? OR id < ?', (cutoff, boundary[0] if boundary else None))
        self.db.execute('DELETE FROM auto_events WHERE ts < ? OR id NOT IN (SELECT id FROM auto_events ORDER BY id DESC LIMIT ?)', (cutoff, n))
        for table, column in [('incidents', 'confirmed_at'), ('gaps', 'end')]:
            condition = 'end_reason IS NOT NULL AND' if table == 'incidents' else ''
            self.db.execute(f'DELETE FROM {table} WHERE {condition} ({column} < ? OR id NOT IN (SELECT id FROM {table} ORDER BY id DESC LIMIT ?))', (cutoff, n))
        self.db.commit()

    def close(self):
        try:
            if self.db is not None:
                try:
                    self.db.commit()
                finally:
                    self.db.close()
                    self.db = None
        finally:
            self._directory.close()


def run_auto_cycle(store, sources_dir, cfg):
    """One failover evaluation inside the collector cycle; monitoring must survive it."""
    try:
        import egress_sources
    except ImportError:
        return 0.0
    started = time.monotonic()
    try:
        runtime = store.meta('auto_runtime') or {}
        fault = False
        def emit(kind, detail):
            nonlocal fault
            fault |= kind in {'controller_unreachable', 'auto_error'}
            store.auto_event(kind, detail)
        runtime = egress_sources.auto_evaluate(sources_dir, runtime, emit)
        if not fault:
            store.setmeta('auto_fault', None)
        store.setmeta('auto_runtime', runtime)
    except egress_sources.SourceError:
        return 0.0  # No registry or unreadable private store here: auto is simply off.
    except Exception:
        try:
            store.auto_event('auto_error', {'error': 'auto_cycle_failed'})
            store.db.commit()
        except Exception: pass
        return 0.0
    elapsed = time.monotonic() - started
    if runtime:
        # One delay probe per candidate may exceed the plain interval; keep the
        # freshness window honest so the GUI does not flap while auto is active.
        probes = max(2, len(runtime.get('fails') or ()))
        try:
            store.setmeta('expected_cycle_seconds',
                          max(cfg['interval_seconds'] + elapsed + 2 * probes, store.meta('expected_cycle_seconds') or 0))
        except Exception: pass
    store.db.commit()
    return elapsed


def collect(config, state_dir, once=False, stop_event=None, sources_dir=None):
    if sources_dir is not None and nmd_platform.name() != 'linux':
        raise ValueError('egress_control_unsupported_platform')
    cfg = validate_config(config)
    with collector_lock(state_dir) as directory:
        store = Store(directory, cfg)
        previous_wall = previous_mono = None
        previous_duration = 0
        try:
            while stop_event is None or not stop_event.is_set():
                wall, mono = time.time(), time.monotonic()
                if previous_wall is not None:
                    elapsed, delta = mono - previous_mono, wall - previous_wall
                    if elapsed > max(cfg['interval_seconds'], previous_duration) + max(2, cfg['interval_seconds']) or abs(delta - elapsed) > 2:
                        store.gap(previous_wall, wall, 'sleep_or_clock_jump')
                results = sample_probe(cfg, stop_event=stop_event)
                store.record(results)
                if sources_dir is not None:
                    run_auto_cycle(store, sources_dir, cfg)
                previous_wall, previous_mono = wall, mono
                if once: break
                previous_duration = time.monotonic() - mono
                delay = max(0, cfg['interval_seconds'] - previous_duration)
                if stop_event is not None: stop_event.wait(delay)
                else: time.sleep(delay)
        finally: store.close()


def read_snapshot(state_dir, limit=100):
    if type(limit) is not int or not 1 <= limit <= 1000: raise ValueError('invalid_limit')
    result = {'schema_version': 1, 'generated_at': time.time(), 'collector': {'state': 'no_data', 'last_sample_at': None}, 'samples': [], 'incidents': [], 'gaps': [], 'auto_events': []}
    try: directory = _directory(state_dir)
    except FileNotFoundError: return result
    with directory:
        _check_database_files(directory)
        fd = _regular(directory, 'monitor.sqlite3')
        if fd is None: return result
        os.close(fd)
        db = sqlite3.connect('file:' + quote(directory.database_path, safe='/') + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            meta = {r['key']: json.loads(r['value']) for r in db.execute('SELECT * FROM metadata')}
            last = meta.get('last_sample_at')
            result['collector'] = dict(meta, state='fresh' if last is not None and 0 <= time.time() - last <= meta.get('expected_cycle_seconds', meta.get('interval_seconds', 30)) * 2 else 'stale')
            result['samples'] = [dict(json.loads(r['payload']), sample_id=r['id'], recorded_at=r['ts']) for r in db.execute('SELECT * FROM samples ORDER BY id DESC LIMIT ?', (limit,))]
            for table in ('incidents', 'gaps'):
                result[table] = [dict(r) for r in db.execute(f'SELECT * FROM {table} ORDER BY id DESC LIMIT ?', (limit,))]
            try:
                result['auto_events'] = [dict(r, detail=json.loads(r['detail']) if r['detail'] else None)
                                         for r in db.execute('SELECT * FROM auto_events ORDER BY id DESC LIMIT ?', (limit,))]
            except sqlite3.OperationalError:
                pass  # Databases from before auto mode simply have no events yet.
            return result
        finally: db.close()
