"""Appliance clock sync: the write itself, and the two ways it must not fire.

An appliance kept off the internet cannot correct its own clock, so the
bridge writes the host's to `/configuration/vs/0`. Two properties carry
the safety of that feature. The field is write-only, so nothing about
the write may reach the state cache -- a cached copy would be state the
bridge invented and the appliance can never confirm. And a timestamp far
outside the appliance's certificate validity window can break its
certificate verification, so a host whose own clock is wrong has to skip
the write rather than push its wrong answer onto the hardware.
"""
import threading
import time
import types
from datetime import datetime

import cbor2
import pytest

from mqtt_demo.bridge import CMD_SYNC_CLOCK, PushBridge
from mqtt_demo.clock_sync import (
    INITIAL_DELAY_S,
    PLAUSIBLE_FROM,
    ClockSyncTask,
    zone_name,
)
from mqtt_demo.config import SharedConfig
from mqtt_demo.descriptor import ClockSync
from mqtt_demo.samples.oven import OVEN

HREF = '/configuration/vs/0'
FIELD = 'x.com.samsung.da.currentTime'
SPEC = ClockSync(path_segs=['configuration', 'vs', '0'], field=FIELD,
                 requires_href=HREF)


class _Session:
    """Records posts; answers with whatever code the test asked for."""

    def __init__(self, code=0x44):
        self.code = code
        self.posts = []

    def post(self, path_segs, payload, timeout=None):
        self.posts.append((list(path_segs), cbor2.loads(payload)))
        return self.code, b''


def _task(session, now, **kwargs):
    return ClockSyncTask(session, SPEC.path_segs, SPEC.field,
                         interval_s=86400.0, now_fn=lambda: now, **kwargs)


# --- the write ------------------------------------------------------

def test_write_carries_local_wall_clock_in_the_appliance_format():
    # Asserted by parsing rather than against a literal timestamp, which
    # tools/check_share_safety.py rejects in public files.
    now = datetime(2026, 9, 8, 14, 30, 5)
    session = _Session()
    task = _task(session, now)

    assert task.sync_now() is True
    [(path_segs, body)] = session.posts
    assert path_segs == ['configuration', 'vs', '0']
    written = body[FIELD]
    assert datetime.strptime(written, '%Y-%m-%dT%H:%M:%S') == now
    # Second precision, a literal T, and no offset or trailing Z: the
    # appliance takes a bare local wall clock.
    assert len(written) == 19 and written[10] == 'T'


def test_a_rejected_write_is_reported_and_leaves_the_schedule_alone():
    # The write is unverified on the oven this repo targets. A device
    # that answers 4.05 must not look like a successful sync, or the
    # next one would be deferred a full interval on nothing.
    session = _Session(code=0x85)
    task = _task(session, datetime(2026, 9, 8, 14, 30, 5))

    assert task.sync_now() is False
    assert task.sync_count == 0
    assert task.last_sync_ts is None


# --- the zone the stamp was written in -------------------------------

class _Log:
    """Captures each formatted line, whichever level it came in at."""

    def __init__(self):
        self.lines = []

    def _record(self, msg, *args):
        self.lines.append(msg % args)

    info = warning = _record


@pytest.fixture
def host_zone(monkeypatch):
    """Put the host in a named zone for the duration of one test."""
    def _set(name):
        monkeypatch.setenv('TZ', name)
        time.tzset()
    yield _set
    monkeypatch.undo()
    time.tzset()


@pytest.mark.parametrize('zone, expected', [
    ('UTC', 'UTC'),
    ('Europe/London', 'BST'),
])
def test_the_log_line_names_the_zone_the_stamp_came_from(
        host_zone, zone, expected):
    # The wire format carries no offset, so a container left on UTC
    # writes a panel an hour behind during BST and still answers 2.04.
    # The stamp alone cannot tell those apart; the zone beside it can.
    host_zone(zone)
    session = _Session()
    log = _Log()
    task = _task(session, datetime(2026, 9, 8, 14, 30, 5), logger=log)

    assert task.sync_now() is True
    assert len(log.lines) == 1
    assert f'14:30:05 {expected} ->' in log.lines[0]


def test_a_skipped_write_names_the_zone_too(host_zone):
    # Same reasoning on the gate: a host reading outside the window is
    # worth knowing the zone of, since a zone fault is one way to get
    # there.
    host_zone('Europe/London')
    session = _Session()
    log = _Log()
    task = _task(session, datetime(2000, 1, 1, 0, 0, 0), logger=log)

    assert task.sync_now() is False
    assert session.posts == []
    assert 'GMT' in log.lines[0]


def test_the_zone_falls_back_rather_than_raising():
    # zone_name sits on a log path. A platform that cannot resolve the
    # local zone must not take the sync down with it.
    class _NoZone:
        def astimezone(self):
            raise OSError('no local zone')

    assert zone_name(_NoZone()) == time.tzname[0]


# --- host-clock gate ------------------------------------------------

@pytest.mark.parametrize('now', [
    datetime(1970, 1, 1, 0, 0, 0),      # container up before NTP lands
    datetime(2025, 12, 31, 23, 59, 59),  # just under the floor
    datetime(2046, 1, 1, 0, 0, 0),      # ceiling is exclusive
])
def test_an_implausible_host_clock_writes_nothing(now):
    session = _Session()
    task = _task(session, now)

    assert task.sync_now() is False
    assert session.posts == []


def test_the_floor_itself_is_plausible():
    session = _Session()
    task = _task(session, PLAUSIBLE_FROM)

    assert task.sync_now() is True


# --- schedule across reconnects -------------------------------------

def test_first_session_waits_only_the_initial_delay():
    task = _task(_Session(), datetime(2026, 9, 8, 14, 0, 0))

    assert task._initial_delay() == INITIAL_DELAY_S


def test_a_reconnect_does_not_restart_the_interval():
    # The task is session-scoped but the schedule is not: a bridge
    # reconnecting every few minutes would otherwise write the clock on
    # every reconnect instead of once a day.
    task = _task(_Session(), datetime(2026, 9, 8, 14, 0, 0),
                 last_sync_ts=time.time() - 3600.0)

    assert task._initial_delay() == pytest.approx(86400.0 - 3600.0, abs=5.0)


def test_an_overdue_sync_still_honours_the_initial_delay():
    # Due long ago, but the connect burst (seed + discovery) comes first.
    task = _task(_Session(), datetime(2026, 9, 8, 14, 0, 0),
                 last_sync_ts=time.time() - 90_000.0)

    assert task._initial_delay() == INITIAL_DELAY_S


def test_run_forever_exits_on_stop_without_writing():
    session = _Session()
    task = _task(session, datetime(2026, 9, 8, 14, 0, 0))
    stop = threading.Event()
    stop.set()

    task.run_forever(stop)

    assert session.posts == []


# --- bridge wiring ---------------------------------------------------

def _bridge(*, descriptor_spec=SPEC, interval_h=24.0, links=(HREF,)):
    bridge = object.__new__(PushBridge)
    bridge.descriptor = types.SimpleNamespace(clock_sync=descriptor_spec)
    bridge.shared = types.SimpleNamespace(CLOCK_SYNC_INTERVAL_H=interval_h)
    bridge.clock_sync_enabled = (descriptor_spec is not None
                                 and interval_h > 0)
    bridge._last_clock_sync_ts = None
    bridge.log = types.SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
    )
    bridge.cache = types.SimpleNamespace(links={href: {} for href in links})
    return bridge


def test_the_task_is_skipped_when_the_device_lacks_the_resource():
    bridge = _bridge(links=('/mode/vs/0',))

    assert bridge._build_clock_sync(_Session()) is None


def test_the_task_is_built_when_the_resource_is_present():
    bridge = _bridge()

    task = bridge._build_clock_sync(_Session())

    assert task is not None
    assert task.href == HREF
    assert task.interval_s == 86400.0


def test_a_zero_interval_disables_the_task():
    bridge = _bridge(interval_h=0.0)

    assert bridge.clock_sync_enabled is False
    assert bridge._build_clock_sync(_Session()) is None


def test_the_button_write_never_enters_the_cache():
    # handle_command merges a successful write into the cache
    # optimistically. The clock field is write-only, so the button is
    # handled off that path -- this test fails the moment it is folded
    # back into the descriptor command handlers.
    bridge = _bridge()
    session = _Session()
    bridge.clock_sync = bridge._build_clock_sync(session)
    bridge.cmd_topic_prefix = 'samsung_oven/cmd/'
    bridge.cmd_handlers = {}
    applied = []
    bridge.cache.apply_optimistic = lambda *a: applied.append(a)

    bridge.handle_command(f'samsung_oven/{CMD_SYNC_CLOCK}', 'Sync')

    assert len(session.posts) == 1
    assert applied == []


def test_the_button_is_ignored_while_no_session_is_up():
    bridge = _bridge()
    bridge.clock_sync = None
    bridge.cmd_topic_prefix = 'samsung_oven/cmd/'
    bridge.cmd_handlers = {}

    bridge.handle_command(f'samsung_oven/{CMD_SYNC_CLOCK}', 'Sync')


# --- config + descriptor --------------------------------------------

def test_the_interval_defaults_to_a_day(monkeypatch):
    monkeypatch.delenv('CLOCK_SYNC_INTERVAL_H', raising=False)

    assert SharedConfig.from_env().CLOCK_SYNC_INTERVAL_H == 24.0


def test_the_interval_is_env_tunable(monkeypatch):
    monkeypatch.setenv('CLOCK_SYNC_INTERVAL_H', '6')

    assert SharedConfig.from_env().CLOCK_SYNC_INTERVAL_H == 6.0


def test_the_oven_declares_the_clock_resource():
    assert OVEN.clock_sync == SPEC
