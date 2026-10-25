"""SQLite event/gap timeline metrics replayed from fixtures and recomputed
by an independent reference model.

Every scenario uses a private TemporaryDirectory state dir and a controlled
clock; this module never reads ~/.local/state/nmd-monitor, /var/lib/nmd-monitor
or any installed configuration (HOME/XDG_STATE_HOME are pinned per module).

Metric definitions pinned here (documented semantics, docs/mvp.md):
- incident: per active probe, 3 consecutive failure samples confirm an
  incident (first_failure = 1st failure of the streak, confirmed_at = 3rd,
  last_success = last success before the streak, else NULL); 2 consecutive
  successes confirm recovery (recovery_first = 1st, recovered_at = 2nd,
  end_reason='recovered').
- unknown/skipped: neither failure nor recovery evidence. With an open
  incident it ends the fragment (end_reason='observation_gap') and adds one
  gap row [last definite observation, now, 'probe_unknown:<id>']; streaks
  reset. Consecutive unknowns add no further rows.
- probe absent from a cycle: no evidence at all; state is untouched
  (insufficient information, not a failure).
- collector restart: one gap [last_sample_at, reopen wall time,
  'collector_restart'] closes every open incident as 'observation_gap'.
- retention (applied on every record): cutoff = now - retention_hours*3600,
  n = max_samples; samples and auto_events keep ts >= cutoff and the newest
  n ids; gaps keep end >= cutoff and the newest n ids; closed incidents need
  confirmed_at >= cutoff and newest-n ids; open incidents are exempt.
- freshness: fresh iff 0 <= now - last_sample_at <= 2*expected_cycle_seconds;
  a backward clock reads stale (missing evidence), never 'failed'.
"""
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import nmd_monitor as m

_env = {}


def setUpModule():
    root = tempfile.TemporaryDirectory()
    _env['root'] = root
    _env['patch'] = patch.dict(os.environ, {'HOME': root.name, 'XDG_STATE_HOME': root.name})
    _env['patch'].start()


def tearDownModule():
    _env['patch'].stop()
    root = _env.pop('root')
    root.cleanup()


class Reference:
    """Independent replay of the documented timeline semantics.

    Deliberately shares no code with nmd_monitor; scenarios are compared
    against raw SQLite rows, not against the product's own reader.
    """

    def __init__(self):
        self.states = {}
        self.incidents = []
        self.gaps = []
        self.samples = []
        self.last_sample_at = None

    @staticmethod
    def next_id(rows):
        # INTEGER PRIMARY KEY without AUTOINCREMENT uses the retained maximum;
        # pruning the largest row (including an empty table) permits id reuse.
        return max((row['_id'] for row in rows), default=0) + 1

    def _state(self, probe):
        return self.states.setdefault(probe, dict(fail=0, success=0, last_success=None,
                                                  first=None, incident=None, recovery=None,
                                                  last_observed=None))

    def cycle(self, at, rows):
        """rows: iterable of (probe, status) or (probe, status, 'passive')."""
        for row in rows:
            probe, status = row[0], row[1]
            if len(row) > 2:
                self.samples.append(at)
                continue  # passive rows are samples only
            s = self._state(probe)
            if status not in ('success', 'failure'):
                if s['incident'] is not None:
                    s['incident']['end_reason'] = 'observation_gap'
                    self.gaps.append(dict(_id=self.next_id(self.gaps),
                                          start=s['last_observed'] if s['last_observed'] is not None else at,
                                          end=at, reason='probe_unknown:' + probe))
                s['incident'] = None
                s['last_success'] = None
                s['fail'] = s['success'] = 0
                s['first'] = s['recovery'] = None
                self.samples.append(at)
                continue
            s['last_observed'] = at
            if status == 'failure':
                s['success'] = 0
                s['recovery'] = None
                if s['fail'] == 0:
                    s['first'] = at
                s['fail'] += 1
                if s['fail'] >= 3 and s['incident'] is None:
                    incident = dict(_id=self.next_id(self.incidents), probe=probe,
                                    first_failure=s['first'], confirmed_at=at,
                                    last_success=s['last_success'], recovery_first=None,
                                    recovered_at=None, end_reason=None)
                    self.incidents.append(incident)
                    s['incident'] = incident
            else:
                s['fail'] = 0
                s['first'] = None
                s['last_success'] = at
                if s['success'] == 0:
                    s['recovery'] = at
                s['success'] += 1
                if s['incident'] is not None and s['success'] >= 2:
                    s['incident'].update(recovery_first=s['recovery'], recovered_at=at,
                                         end_reason='recovered')
                    s['incident'] = None
            self.samples.append(at)
        self.last_sample_at = at

    def restart(self, at):
        if self.last_sample_at is not None:
            self.gaps.append(dict(_id=self.next_id(self.gaps), start=self.last_sample_at,
                                  end=at, reason='collector_restart'))
            for incident in self.incidents:
                if incident['recovered_at'] is None and incident['end_reason'] is None:
                    incident['end_reason'] = 'observation_gap'
            self.states = {}

    def prune(self, at, retention_hours, max_samples):
        cutoff = at - retention_hours * 3600
        n = max_samples
        newest = {incident['_id'] for incident in self.incidents[-n:]}
        self.incidents = [i for i in self.incidents
                          if i['end_reason'] is None or (i['_id'] in newest and i['confirmed_at'] >= cutoff)]
        newest = {gap['_id'] for gap in self.gaps[-n:]}
        self.gaps = [g for g in self.gaps if g['_id'] in newest and g['end'] >= cutoff]
        self.samples = [ts for ts in self.samples[-n:] if ts >= cutoff]


class Driver:
    """Feeds fixture cycles to a real Store in a private temporary state dir."""

    def __init__(self, state, config):
        self.state = Path(state)
        self.config = config
        self.store = m.Store(self.state, config)

    def cycle(self, at, rows):
        results = []
        for row in rows:
            probe, status = row[0], row[1]
            kind = row[2] if len(row) > 2 else 'http'
            results.append(dict(id=probe, type=kind, path='system' if kind != 'passive' else 'local',
                                status=status, error=None, timings={}, observed_at=at))
        self.store.record(results, now=at)

    def restart(self, at):
        self.store.close()
        with patch.object(m.time, 'time', return_value=at):
            self.store = m.Store(self.state, self.config)

    def close(self):
        self.store.close()

    def rows(self):
        db = sqlite3.connect(f'file:{self.state / "monitor.sqlite3"}?mode=ro', uri=True)
        try:
            incidents = [dict(zip(('id', 'probe', 'first_failure', 'confirmed_at', 'last_success',
                                   'recovery_first', 'recovered_at', 'end_reason'), row))
                         for row in db.execute('SELECT id,probe,first_failure,confirmed_at,'
                                               'last_success,recovery_first,recovered_at,'
                                               'end_reason FROM incidents ORDER BY id')]
            gaps = [dict(zip(('id', 'start', 'end', 'reason'), row))
                    for row in db.execute('SELECT id,start,end,reason FROM gaps ORDER BY id')]
            samples = db.execute('SELECT count(*) FROM samples').fetchone()[0]
        finally:
            db.close()
        return incidents, gaps, samples


def expected_rows(reference):
    def public_rows(rows):
        return [dict(id=row['_id'], **{k: v for k, v in row.items() if k != '_id'}) for row in rows]
    incidents = public_rows(reference.incidents)
    gaps = public_rows(reference.gaps)
    return incidents, gaps, len(reference.samples)


class TimelineMetricsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)

    def replay(self, config, run):
        """run(driver, reference) applies one shared scenario to both sides."""
        driver = Driver(self.base / 'state', config)
        reference = Reference()
        self.addCleanup(driver.close)
        run(driver, reference)
        expected = expected_rows(reference)
        self.assertEqual(driver.rows(), expected)
        return driver, reference

    def test_mixed_timeline_matches_reference_model(self):
        def run(driver, reference):
            steps = [
                (100, [('a', 'success'), ('b', 'success')]),
                (130, [('a', 'failure'), ('b', 'failure')]),
                (160, [('a', 'failure'), ('b', 'unknown')]),
                (190, [('a', 'failure'), ('b', 'failure')]),
                (220, [('a', 'success'), ('b', 'failure')]),
                (250, [('a', 'success'), ('b', 'failure')]),
                (280, [('a', 'skipped')]),
                (310, [('b', 'unknown')]),
                (340, [('b', 'failure'), ('c', 'failure')]),
                (370, [('b', 'failure'), ('c', 'failure')]),
                (400, [('b', 'failure'), ('c', 'failure')]),
                (430, [('b', 'success'), ('c', 'unknown')]),
            ]
            for at, rows in steps:
                driver.cycle(at, rows)
                reference.cycle(at, rows)
            driver.restart(500)
            reference.restart(500)
            driver.cycle(530, [('b', 'success')])
            reference.cycle(530, [('b', 'success')])
        incidents, gaps, samples = self.replay({}, run)[0].rows()
        # Spot checks beyond the model comparison: confirmed/recovered stamps
        # and the no-fake-recovery rule after a restart-closed fragment.
        self.assertEqual(incidents[0], dict(id=1, probe='a', first_failure=130, confirmed_at=190,
                                            last_success=100, recovery_first=220, recovered_at=250,
                                            end_reason='recovered'))
        self.assertIsNone(incidents[3]['recovered_at'])
        self.assertEqual(incidents[3]['end_reason'], 'observation_gap')
        self.assertEqual(gaps[-1]['reason'], 'collector_restart')

    def test_probe_missing_from_a_cycle_is_no_evidence(self):
        def run(driver, reference):
            steps = [
                (10, [('a', 'failure'), ('b', 'failure')]),
                (11, [('a', 'failure'), ('b', 'failure')]),
                (12, [('a', 'failure')]),            # b absent: state untouched
                (13, [('a', 'failure')]),            # a confirmed at 12 already
                (20, [('b', 'failure')]),            # b's pre-absence streak still counts
                (21, [('b', 'success')]),
                (22, [('b', 'success')]),            # b recovers normally
            ]
            for at, rows in steps:
                driver.cycle(at, rows)
                reference.cycle(at, rows)
        incidents, _, _ = self.replay({}, run)[0].rows()
        by_probe = {row['probe']: row for row in incidents}
        self.assertEqual(by_probe['a']['confirmed_at'], 12)
        self.assertEqual(by_probe['b']['confirmed_at'], 20)
        self.assertEqual(by_probe['b']['recovered_at'], 22)
        self.assertEqual(by_probe['b']['end_reason'], 'recovered')

    def test_passive_rows_are_samples_never_incidents(self):
        def run(driver, reference):
            for at in (50, 60, 70, 80, 90):
                rows = [('local', 'failure', 'passive'), ('local2', 'unknown', 'passive')]
                driver.cycle(at, rows)
                reference.cycle(at, rows)
        incidents, gaps, samples = self.replay({}, run)[0].rows()
        self.assertEqual(incidents, [])
        self.assertEqual(gaps, [])
        self.assertEqual(samples, 10)

    def test_duplicate_cycles_are_distinct_evidence_without_reconfirmation(self):
        def run(driver, reference):
            for _ in range(3):
                driver.cycle(500, [('d', 'failure')])
                reference.cycle(500, [('d', 'failure')])
            driver.cycle(500, [('d', 'failure')])   # replayed confirmed batch
            reference.cycle(500, [('d', 'failure')])
            for _ in range(2):
                driver.cycle(500, [('d', 'success')])
                reference.cycle(500, [('d', 'success')])
        incidents, _, samples = self.replay({}, run)[0].rows()
        self.assertEqual(incidents, [dict(id=1, probe='d', first_failure=500, confirmed_at=500,
                                          last_success=None, recovery_first=500, recovered_at=500,
                                          end_reason='recovered')])
        self.assertEqual(samples, 6)

    def test_cross_day_retention_boundary_prunes_by_cutoff_and_keeps_open_incident(self):
        config = {'retention_hours': 24, 'max_samples': 100000}

        def run(driver, reference):
            steps = [
                (0, [('a', 'failure')]), (1, [('a', 'failure')]), (2, [('a', 'failure')]),
                (100, [('c', 'failure')]), (101, [('c', 'failure')]), (102, [('c', 'failure')]),
                (103, [('c', 'success')]), (104, [('c', 'success')]),
                (3600, [('b', 'success')]),
                (7197, [('e', 'failure')]), (7198, [('e', 'failure')]), (7199, [('e', 'failure')]),
                (7198, [('d', 'failure')]), (7199, [('d', 'failure')]), (7200, [('d', 'failure')]),
                (7200, [('e', 'unknown')]),
                (7201, [('d', 'success')]), (7202, [('d', 'success')]),
                (7200, [('b', 'success')]),
                (93600, [('b', 'success')]),   # cutoff here = 93600 - 86400 = 7200
            ]
            for at, rows in steps:
                driver.cycle(at, rows)
                reference.cycle(at, rows)
                reference.prune(at, config['retention_hours'], config['max_samples'])
        incidents, gaps, samples = self.replay(config, run)[0].rows()
        # Exactly-at-cutoff rows survive; older closed evidence and samples go.
        self.assertEqual([row['probe'] for row in incidents], ['a', 'd'])
        self.assertEqual(incidents[0]['end_reason'], None)            # open incident exempt
        self.assertEqual(incidents[1]['confirmed_at'], 7200)          # boundary kept
        self.assertEqual([(gap['start'], gap['end'], gap['reason']) for gap in gaps],
                         [(7199, 7200, 'probe_unknown:e')])           # gap end == cutoff kept
        self.assertEqual(samples, 6)   # rows at ts >= 7200: d@7200, e-unknown@7200, b@7200, d@7201, d@7202, b@93600

    def test_row_caps_apply_per_table_and_open_incidents_are_exempt(self):
        # 100 is the smallest legal max_samples; 103 closed groups overflow it.
        config = {'retention_hours': 720, 'max_samples': 100}

        def run(driver, reference):
            for i in range(103):
                base = i * 4
                for at, status in ((base, 'failure'), (base + 1, 'failure'),
                                   (base + 2, 'failure'), (base + 3, 'unknown')):
                    driver.cycle(at, [('g', status)])
                    reference.cycle(at, [('g', status)])
                    reference.prune(at, config['retention_hours'], config['max_samples'])
            for at in (1000, 1001, 1002):
                driver.cycle(at, [('h', 'failure')])
                reference.cycle(at, [('h', 'failure')])
                reference.prune(at, config['retention_hours'], config['max_samples'])
        incidents, gaps, samples = self.replay(config, run)[0].rows()
        # The newest-100 window already contains the open h incident, so it
        # displaces one closed g row: 99 closed g + open h = 100 kept.
        self.assertEqual(len(incidents), 100)
        self.assertEqual(incidents[-1]['probe'], 'h')
        self.assertEqual(incidents[-1]['end_reason'], None)
        self.assertEqual([row['probe'] for row in incidents[:-1]], ['g'] * 99)
        self.assertEqual(len(gaps), 100)
        self.assertEqual(samples, 100)

    def test_backward_clock_and_row_limit_keep_the_intersection(self):
        config = {'retention_hours': 24, 'max_samples': 100}
        def run(driver, reference):
            for at in [*range(100000, 100099), 0, 100100]:
                rows = [('local', 'success', 'passive')]
                driver.cycle(at, rows)
                reference.cycle(at, rows)
                reference.prune(at, config['retention_hours'], config['max_samples'])
        driver, reference = self.replay(config, run)
        self.assertEqual(driver.rows()[2], 99)
        self.assertEqual(reference.samples[0], 100001)

    def test_pruned_incident_and_gap_ids_are_reused_on_new_evidence(self):
        config = {'retention_hours': 24, 'max_samples': 100}
        for keep_older_id in (False, True):
            with self.subTest(keep_older_id=keep_older_id):
                driver = Driver(self.base / str(keep_older_id), config)
                self.addCleanup(driver.close)
                reference = Reference()

                def cycle(at, rows):
                    driver.cycle(at, rows)
                    reference.cycle(at, rows)
                    reference.prune(at, 24, 100)
                    self.assertEqual(driver.rows(), expected_rows(reference))

                # A backward clock can expire the highest id while retaining a lower one.
                if keep_older_id:
                    for at, status in [(100000, 'failure'), (100001, 'failure'),
                                       (100002, 'failure'), (100003, 'unknown')]:
                        cycle(at, [('kept', status)])
                for at, status in [(1, 'failure'), (2, 'failure'), (3, 'failure'), (4, 'unknown')]:
                    cycle(at, [('expired', status)])
                cycle(86405, [])
                remaining = [1] if keep_older_id else []
                for rows in driver.rows()[:2]:
                    self.assertEqual([r['id'] for r in rows], remaining)
                for at, status in [(86406, 'failure'), (86407, 'failure'),
                                   (86408, 'failure'), (86409, 'unknown')]:
                    cycle(at, [('new', status)])
                # Also cover gap allocation through the restart path.
                driver.restart(86410)
                reference.restart(86410)
                actual = driver.rows()
                self.assertEqual([r['id'] for r in actual[0]], [1, 2] if keep_older_id else [1])
                self.assertEqual([r['id'] for r in actual[1]], [1, 2, 3] if keep_older_id else [1, 2])
                self.assertEqual(actual, expected_rows(reference))

    def test_backward_clock_across_restart_keeps_reversed_gap_evidence(self):
        def run(driver, reference):
            for at in (1000, 1001, 1002):
                driver.cycle(at, [('a', 'failure')])
                reference.cycle(at, [('a', 'failure')])
            driver.restart(900)   # wall clock stepped back during the downtime
            reference.restart(900)
        incidents, gaps, _ = self.replay({}, run)[0].rows()
        self.assertEqual(gaps, [dict(id=1, start=1002, end=900, reason='collector_restart')])
        self.assertEqual(incidents[0]['end_reason'], 'observation_gap')
        self.assertIsNone(incidents[0]['recovered_at'])
        # The reader must surface the reversed gap instead of failing.
        snapshot = m.read_snapshot(self.base / 'state')
        self.assertEqual(snapshot['gaps'][0]['end'], 900)

    def test_collector_backward_wall_clock_records_sleep_or_clock_jump(self):
        target = self.base / 'collector'
        stop = threading.Event()
        calls = []

        def sample(cfg, stop_event=None):
            calls.append(1)
            if len(calls) == 2:
                stop.set()
            return [dict(id='p', type='http', path='system', status='success',
                         error=None, timings={}, observed_at=0.0)]

        with patch.object(m, 'sample_probe', side_effect=sample), \
                patch.object(stop, 'wait'), \
                patch.object(m.nmd_platform, 'name', return_value='linux'), \
                patch.object(m.time, 'time', side_effect=[2000, 2000, 900, 900]), \
                patch.object(m.time, 'monotonic', side_effect=[10, 10.5, 11, 11.5]):
            m.collect({}, target, stop_event=stop)
        db = sqlite3.connect(f'file:{target / "monitor.sqlite3"}?mode=ro', uri=True)
        try:
            gaps = db.execute('SELECT start,end,reason FROM gaps').fetchall()
            samples = db.execute('SELECT count(*) FROM samples').fetchone()[0]
        finally:
            db.close()
        self.assertEqual(gaps, [(2000, 900, 'sleep_or_clock_jump')])
        self.assertEqual(samples, 2)

    def test_freshness_boundaries_and_backward_clock_are_stale_not_failed(self):
        state = self.base / 'freshness'
        driver = Driver(state, {'interval_seconds': 30})
        try:
            with patch.object(m.nmd_platform, 'name', return_value='linux'):
                driver.cycle(1000, [('p', 'success')])
        finally:
            driver.close()
        for now, expected in ((1060, 'fresh'), (1061, 'stale'), (950, 'stale')):
            with self.subTest(now=now), patch.object(m.time, 'time', return_value=now):
                self.assertEqual(m.read_snapshot(state)['collector']['state'], expected)

    def test_module_never_resolves_real_state_paths(self):
        import observability
        default = Path(observability.default_state_dir())
        self.assertEqual(default.parts[:len(Path(_env['root'].name).parts)], Path(_env['root'].name).parts)
        self.assertNotIn('.local/state/nmd-monitor', str(default))
        self.assertNotIn('/var/lib/nmd-monitor', str(default))


if __name__ == '__main__':
    unittest.main()
