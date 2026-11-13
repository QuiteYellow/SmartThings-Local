"""WRITE_MAX_ATTEMPTS plumbing: env var -> SharedConfig -> the session.

The library flag exists so a lost write can be measured on real hardware
before retransmission is turned on anywhere. That measurement happens on
the bridge, so the bridge has to be able to set it -- and, far more
importantly, has to keep defaulting to one send until someone chooses
otherwise.
"""
import inspect
import logging
import types

import pytest

import mqtt_demo.bridge as bridge
from mqtt_demo.config import SharedConfig


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv('WRITE_MAX_ATTEMPTS', raising=False)


def test_default_is_one_send():
    # The default has to stay today's behaviour: retransmitting into an
    # appliance already dropping under load turns one lost write into
    # several, and §4.5 dedupe is unverified on the appliances here.
    assert SharedConfig.from_env().WRITE_MAX_ATTEMPTS == 1


def test_env_var_is_read(monkeypatch):
    monkeypatch.setenv('WRITE_MAX_ATTEMPTS', '3')
    assert SharedConfig.from_env().WRITE_MAX_ATTEMPTS == 3


def test_a_non_numeric_value_fails_at_startup(monkeypatch):
    # Same contract as the other int knobs: a typo stops the process
    # rather than silently reverting to a default nobody asked for.
    monkeypatch.setenv('WRITE_MAX_ATTEMPTS', 'yes')
    with pytest.raises(ValueError):
        SharedConfig.from_env()


class _StopAfterConstruction(Exception):
    """Ends session_once at the point this test cares about, before it
    starts a reader thread and a supervision loop."""


def test_session_once_passes_it_through(monkeypatch):
    """The plumbing that makes the flag reachable at all: without this
    the constructor argument exists but nothing on the bridge sets it."""
    captured = {}

    class _FakeSession:
        def __init__(self, host, port, **kw):
            captured.update(kw)

        def connect(self):
            raise _StopAfterConstruction()

    monkeypatch.setattr(bridge, 'DtlsCoapSession', _FakeSession)

    b = bridge.PushBridge.__new__(bridge.PushBridge)
    b.app = types.SimpleNamespace(ip='192.0.2.9', ocf_port=49155, index=0)
    b.shared = types.SimpleNamespace(
        CERT_PATH='/tmp/cert.pem', KEY_PATH='/tmp/key.pem',
        WRITE_MAX_ATTEMPTS=4,
    )
    b.log = logging.getLogger('test-bridge')
    b._on_notification = lambda *a: None
    b._resolve_port = lambda: 49155     # no DTLS probe against a real host

    with pytest.raises(_StopAfterConstruction):
        bridge.PushBridge.session_once(b)

    assert captured['write_max_attempts'] == 4


def test_shared_config_field_is_wired_into_the_session_call():
    """A guard against the field being added and then never read: the
    call site must name the SharedConfig attribute, not a literal."""
    source = inspect.getsource(bridge.PushBridge.session_once)
    assert 'write_max_attempts=self.shared.WRITE_MAX_ATTEMPTS' in source
