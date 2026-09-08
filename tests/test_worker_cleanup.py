"""Deterministic baseline checks for the current OCF worker stop contract."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from mqtt_demo import bridge as bridge_module
from mqtt_demo.bridge import PushBridge
from smartthings_local.ocf.keepalive import KeepaliveTask
from smartthings_local.ocf.observe_refresh import ObserveRefreshTask
from smartthings_local.ocf.poll_scheduler import PollScheduler, PollTier
from smartthings_local.ocf.state_cache import StateCache

_THREAD_DEADLINE_S = 2.0


class _Session:
    def ping(self):
        return None

    def refresh_observes(self, paths):
        return None


class _Descriptor:
    def on_observation(self, state, href, rep):
        return None


class _ObservedEvent(threading.Event):
    def __init__(self):
        super().__init__()
        self.waiting = threading.Event()

    def wait(self, timeout=None):
        self.waiting.set()
        return super().wait(timeout)


def _assert_worker_stops(target, name: str):
    stop = _ObservedEvent()
    errors: list[str] = []

    def run():
        try:
            target(stop)
        except Exception as error:  # noqa: BLE001  # pragma: no cover
            errors.append(type(error).__name__)

    worker = threading.Thread(target=run, name=name, daemon=True)
    worker.start()
    assert stop.waiting.wait(_THREAD_DEADLINE_S), (
        f"{name} did not enter an interruptible wait"
    )
    stop.set()
    worker.join(_THREAD_DEADLINE_S)
    assert not worker.is_alive(), f"{name} did not stop"
    assert errors == [], f"{name} raised {errors[0]}"


def test_keepalive_worker_stops_without_waiting_for_interval():
    task = KeepaliveTask(_Session(), interval_s=3600.0)
    _assert_worker_stops(task.run_forever, "test-keepalive")


def test_observe_refresh_worker_stops_without_waiting_for_interval():
    task = ObserveRefreshTask(_Session(), [], interval_s=3600.0)
    _assert_worker_stops(task.run_forever, "test-observe-refresh")


def test_poll_scheduler_worker_stops_without_leaking_thread():
    scheduler = PollScheduler(
        _Session(),
        StateCache(_Descriptor()),
        [PollTier("idle", interval_s=3600.0, paths=())],
    )
    _assert_worker_stops(scheduler.run_forever, "test-poll-scheduler")


class _SessionWorker:
    def __init__(self, *args, **kwargs):
        self.stop = None
        self.started = threading.Event()
        self.exited = threading.Event()
        self.on_reachable = kwargs.get("on_reachable")
        self.on_unreachable = kwargs.get("on_unreachable")
        self.last_success_ts = 0.0

    def run_forever(self, stop):
        self.stop = stop
        self.started.set()
        stop.wait()
        self.exited.set()


class _JoinedSession:
    def __init__(self, workers, start_index, error=None):
        self.workers = workers
        self.start_index = start_index
        self.error = error

    def join(self):
        assert all(
            worker.started.wait(_THREAD_DEADLINE_S)
            for worker in self.workers[self.start_index:]
        )
        if self.error is not None:
            raise self.error


class _BlockingJoinedSession(_JoinedSession):
    def __init__(self, workers):
        super().__init__(workers, 0)
        self.joined = threading.Event()
        self.release = threading.Event()

    def join(self):
        super().join()
        self.joined.set()
        assert self.release.wait(_THREAD_DEADLINE_S)


def _bridge():
    bridge = object.__new__(PushBridge)
    bridge.descriptor = SimpleNamespace(
        observe_paths=(),
        poll_tiers=[],
        is_active=lambda _state: False,
        clock_sync=None,
    )
    bridge.shared = SimpleNamespace(PING_INTERVAL_S=3600.0)
    bridge.app = SimpleNamespace(klass="test")
    bridge.log = SimpleNamespace(info=lambda *args: None, warning=lambda *args: None)
    bridge.cache = SimpleNamespace(links={})
    bridge.stop = threading.Event()
    bridge._session_stop_lock = threading.Lock()
    bridge._session_stop = None
    bridge.scheduler = None
    bridge.keepalive = None
    bridge.observe_refresh = None
    bridge.clock_sync = None
    bridge.clock_sync_enabled = False
    bridge._seed_from_device0 = lambda _session: None
    bridge._retag_logger_with_serial = lambda: None
    bridge.maybe_publish_state = lambda **kwargs: None
    bridge.set_availability = lambda _online: None
    return bridge


@pytest.mark.parametrize(
    ("session_count", "join_error"),
    [
        pytest.param(2, None, id="reconnect"),
        pytest.param(1, RuntimeError("reader failed"), id="reader-error"),
    ],
)
def test_bridge_retires_session_workers_before_returning(
    monkeypatch, session_count, join_error
):
    workers = []

    def worker_factory(*args, **kwargs):
        worker = _SessionWorker(*args, **kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(bridge_module, "PollScheduler", worker_factory)
    monkeypatch.setattr(bridge_module, "KeepaliveTask", worker_factory)
    monkeypatch.setattr(bridge_module, "ObserveRefreshTask", worker_factory)

    bridge = _bridge()

    session_stops = []
    for session_index in range(session_count):
        start_index = len(workers)
        session = _JoinedSession(
            workers,
            start_index,
            error=join_error if session_index == session_count - 1 else None,
        )
        if session.error is None:
            bridge._run_session_inner(session)
        else:
            with pytest.raises(RuntimeError, match="reader failed"):
                bridge._run_session_inner(session)

        session_workers = workers[start_index:]
        assert len(session_workers) == 3
        assert len({id(worker.stop) for worker in session_workers}) == 1
        session_stops.append(session_workers[0].stop)

    assert len(workers) == session_count * 3
    assert len({id(stop) for stop in session_stops}) == session_count
    assert all(stop is not bridge.stop for stop in session_stops)
    assert all(stop.is_set() for stop in session_stops)
    assert not bridge.stop.is_set()
    assert all(worker.exited.is_set() for worker in workers)
    keepalive_workers = tuple(
        workers[index] for index in range(1, len(workers), 3)
    )
    assert all(worker.on_reachable is None for worker in keepalive_workers)
    assert all(worker.on_unreachable is None for worker in keepalive_workers)
    assert bridge.scheduler is None
    assert bridge.keepalive is None
    assert bridge.observe_refresh is None
    assert bridge._session_stop is None


def test_bridge_retires_started_worker_when_later_thread_fails_to_start(
    monkeypatch,
):
    workers = []

    def worker_factory(*args, **kwargs):
        worker = _SessionWorker(*args, **kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(bridge_module, "PollScheduler", worker_factory)
    monkeypatch.setattr(bridge_module, "KeepaliveTask", worker_factory)
    monkeypatch.setattr(bridge_module, "ObserveRefreshTask", worker_factory)

    bridge = _bridge()

    original_start = threading.Thread.start
    start_count = 0

    def fail_second_start(thread):
        nonlocal start_count
        start_count += 1
        if start_count == 2:
            raise RuntimeError("synthetic thread start failure")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_second_start)

    with pytest.raises(RuntimeError, match="synthetic thread start failure"):
        bridge._run_session_inner(SimpleNamespace(join=lambda: None))

    assert len(workers) == 3
    assert workers[0].started.wait(_THREAD_DEADLINE_S)
    assert workers[0].exited.wait(_THREAD_DEADLINE_S)
    assert workers[0].stop is not bridge.stop
    assert workers[0].stop.is_set()
    assert workers[1].stop is None
    assert workers[2].stop is None
    assert bridge.scheduler is None
    assert bridge.keepalive is None
    assert bridge.observe_refresh is None
    assert bridge._session_stop is None


def test_request_stop_wakes_current_session_workers(monkeypatch):
    workers = []

    def worker_factory(*args, **kwargs):
        worker = _SessionWorker(*args, **kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(bridge_module, "PollScheduler", worker_factory)
    monkeypatch.setattr(bridge_module, "KeepaliveTask", worker_factory)
    monkeypatch.setattr(bridge_module, "ObserveRefreshTask", worker_factory)

    bridge = _bridge()
    session = _BlockingJoinedSession(workers)
    session_thread = threading.Thread(
        target=bridge._run_session_inner,
        args=(session,),
        daemon=True,
    )
    session_thread.start()

    try:
        assert session.joined.wait(_THREAD_DEADLINE_S)
        session_stop = bridge._session_stop
        assert session_stop is not None
        assert not session_stop.is_set()

        bridge.request_stop()

        assert bridge.stop.is_set()
        assert session_stop.is_set()
        assert all(
            worker.exited.wait(_THREAD_DEADLINE_S) for worker in workers
        )
        assert session_thread.is_alive()
    finally:
        session.release.set()
        session_thread.join(_THREAD_DEADLINE_S)

    assert not session_thread.is_alive()
    assert bridge._session_stop is None


def test_session_workers_observe_stop_requested_before_handoff(monkeypatch):
    workers = []

    def worker_factory(*args, **kwargs):
        worker = _SessionWorker(*args, **kwargs)
        workers.append(worker)
        return worker

    monkeypatch.setattr(bridge_module, "PollScheduler", worker_factory)
    monkeypatch.setattr(bridge_module, "KeepaliveTask", worker_factory)
    monkeypatch.setattr(bridge_module, "ObserveRefreshTask", worker_factory)

    bridge = _bridge()
    bridge.request_stop()
    bridge._run_session_inner(_JoinedSession(workers, 0))

    assert len(workers) == 3
    assert all(worker.stop.is_set() for worker in workers)
    assert all(worker.exited.wait(_THREAD_DEADLINE_S) for worker in workers)
    assert bridge._session_stop is None
