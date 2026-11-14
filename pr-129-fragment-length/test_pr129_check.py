"""Offline tests for pr129_check.py. No appliance, no network.

The session and discovery are replaced with fakes, so these cover the
script's own decisions: which arms run, the handshake ceiling, the gap floor,
and what reaches the output. Two tests read the installed library's source,
so that a change to the log line or the alert wording the script depends on
fails here and not silently on someone's hardware.
"""

import inspect
import logging
from types import SimpleNamespace

import pytest

import pr129_check as check
from smartthings_local.errors import (
    FragmentLimitTimeoutError,
    PeerInitiatedHandshakeError,
    SessionError,
    SessionTimeoutError,
)
from smartthings_local.protocol import _dtls_base, dtls_session

SECRET_HOST = "192.0.2.77"


class FakeSession:
    """Stands in for DtlsCoapSession. Behaviour is set per fragment length."""

    plan = {}
    created = []

    def __init__(self, host, port, *, auth, local_port):
        self.host = host
        self.port = port
        self.local_port = local_port
        self.length = auth._max_fragment_length
        self.behaviour = self.plan[self.length]
        self.closed = False
        FakeSession.created.append(self)

    def connect(self, timeout):
        outcome = self.behaviour["connect"]
        if outcome == "alert48":
            logging.getLogger(dtls_session.__name__).warning(
                "dtls handshake failed at the TLS layer: %s",
                "peer sent fatal alert 48")
            raise SessionError()
        if outcome == "leaky":
            logging.getLogger(dtls_session.__name__).warning(
                "dtls handshake failed at the TLS layer: %s",
                f"bad thing from {SECRET_HOST}")
            raise SessionError()
        if isinstance(outcome, type):
            raise outcome()

    @property
    def negotiated_fragment_length(self):
        return self.length

    def start_reader(self):
        pass

    def get(self, path, timeout):
        outcome = self.behaviour["get"]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self):
        self.closed = True


@pytest.fixture
def harness(monkeypatch, tmp_path):
    FakeSession.created = []
    monkeypatch.setattr(check, "DtlsCoapSession", FakeSession)
    monkeypatch.setattr(
        check.FragmentingCertificateAuth, "_load_client_credential",
        lambda self: ([], None))
    monkeypatch.setattr(
        check, "discover_ocf_secure_ports",
        lambda host, **kw: SimpleNamespace(found=True, ports=(49155,)))
    sleeps = []
    monkeypatch.setattr(check.time, "sleep", sleeps.append)
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("x")

    def run(*hosts, extra=()):
        argv = [*hosts, "--cert", str(cert), "--key", str(key), "--yes",
                *extra]
        return check.main(argv)

    run.sleeps = sleeps
    return run


def test_both_arms_run_when_the_first_completes(harness, capsys):
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x" * 150)},
        512: {"connect": None, "get": (69, b"x" * 9000)},
    }
    assert harness(SECRET_HOST) == 0
    out = capsys.readouterr().out
    assert [s.length for s in FakeSession.created] == [1024, 512]
    assert all(s.closed for s in FakeSession.created)
    assert all(s.local_port == check.DEFAULT_LOCAL_PORT
               for s in FakeSession.created)
    assert "GET /oic/d: 2.05, 150 bytes" in out
    assert "GET /device/0: 2.05, 9000 bytes" in out
    assert "handshakes used: 2 of 4" in out
    assert SECRET_HOST not in out
    # The gap floor holds whatever the timing: one wait between the arms.
    assert any(s > 0 for s in harness.sleeps)


def test_peer_alert_is_named_and_arm_two_is_skipped(harness, capsys):
    FakeSession.plan = {1024: {"connect": "alert48"}}
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert "fatal alert 48 (unknown_ca)" in out
    assert "arm 2: skipped" in out
    assert len(FakeSession.created) == 1


@pytest.mark.parametrize("error, text", [
    (SessionTimeoutError, "no answer within"),
    (PeerInitiatedHandshakeError, "opening its own handshake"),
])
def test_other_handshake_failures_skip_arm_two(harness, capsys, error, text):
    FakeSession.plan = {1024: {"connect": error}}
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert text in out
    assert len(FakeSession.created) == 1


def test_a_reason_carrying_an_address_is_withheld(harness, capsys):
    FakeSession.plan = {1024: {"connect": "leaky"}}
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert SECRET_HOST not in out
    assert "withheld" in out


def test_fragment_limit_timeout_is_reported(harness, capsys):
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x")},
        512: {"connect": None, "get": FragmentLimitTimeoutError(512)},
    }
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert "FragmentLimitTimeoutError, the first block never arrived " \
        "(length 512)" in out


def test_the_ceiling_holds_across_appliances(harness, capsys):
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x")},
        512: {"connect": None, "get": (69, b"x")},
    }
    harness(SECRET_HOST, "192.0.2.78", extra=("--max-handshakes", "3"))
    out = capsys.readouterr().out
    assert len(FakeSession.created) == 3
    assert "ceiling (3) is reached" in out


def test_the_ceiling_cannot_be_raised(harness):
    with pytest.raises(SystemExit):
        harness(SECRET_HOST, extra=("--max-handshakes", "5"))


def test_ambiguous_ports_are_refused(harness, capsys, monkeypatch):
    monkeypatch.setattr(
        check, "discover_ocf_secure_ports",
        lambda host, **kw: SimpleNamespace(found=True, ports=(1, 2)))
    harness(SECRET_HOST)
    assert "refusing to guess" in capsys.readouterr().out
    assert FakeSession.created == []


def test_the_library_still_logs_the_line_the_script_reads():
    source = inspect.getsource(dtls_session.DtlsCoapSession.connect)
    assert '"dtls handshake failed at the TLS layer: %s"' in source


def test_the_engine_still_words_a_peer_alert_the_same_way():
    source = inspect.getsource(_dtls_base)
    assert 'f"peer sent fatal alert {description}"' in source
    assert check._PEER_ALERT.search("peer sent fatal alert 48")
