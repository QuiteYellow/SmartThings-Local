"""Offline tests for pr129_check.py. No appliance, and no traffic.

One test binds a local UDP socket and sends nothing on it.

Most tests replace the session and discovery with fakes, so they cover the
script's own decisions: which arms run, the handshake ceiling, the gap floor,
and what reaches the output. One test runs the library's real
`DtlsCoapSession.connect()` over a fake connection that fails with an alert,
so a change to how the library logs that failure fails here. One test reads
the engine's source for the alert wording, which the fake cannot exercise.
"""

import inspect
import logging
import re
import warnings
from types import SimpleNamespace

import pytest
from OpenSSL import SSL

import pr129_check as check
from smartthings_local.errors import (
    FragmentLimitTimeoutError,
    PeerInitiatedHandshakeError,
    SessionError,
    SessionTimeoutError,
)
from smartthings_local.protocol import _dtls_base, _dtls_cert, dtls_session

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
        self.reads = []
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
        self.reads.append("/" + "/".join(path))
        outcome = self.behaviour.get("by_path", {}).get(
            tuple(path), self.behaviour.get("get"))
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self):
        self.closed = True


def _directory(ports, answered=True):
    return SimpleNamespace(
        found=bool(ports), ports=tuple(ports), response_received=answered)


@pytest.fixture
def harness(monkeypatch, tmp_path):
    FakeSession.created = []
    monkeypatch.setattr(check, "DtlsCoapSession", FakeSession)
    monkeypatch.setattr(
        check.FragmentingCertificateAuth, "_load_client_credential",
        lambda self: ([], None))
    monkeypatch.setattr(
        check, "discover_ocf_secure_ports",
        lambda host, **kw: _directory((49155,)))
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
        512: {"connect": None, "get": (69, b"x" * 150),
              "by_path": {("device", "0"): (69, b"x" * 9000)}},
    }
    assert harness(SECRET_HOST) == 0
    out = capsys.readouterr().out
    assert [s.length for s in FakeSession.created] == [1024, 512]
    assert all(s.closed for s in FakeSession.created)
    assert all(s.local_port == check.DEFAULT_LOCAL_PORT
               for s in FakeSession.created)
    assert "GET /oic/d: 2.05, 150 bytes" in out
    assert "GET /device/0: 2.05, 9000 bytes" in out
    assert [s.reads for s in FakeSession.created] == [
        ["/oic/d", "/device/0"], ["/oic/d", "/device/0"]]
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
    (SessionTimeoutError, "not completed within"),
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
        512: {"connect": None, "get": (69, b"x" * 149),
              "by_path": {("device", "0"): FragmentLimitTimeoutError(512)}},
    }
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    arm2 = out[out.index("arm 2:"):]
    # The small read comes first, so a timeout on /device/0 cannot hide
    # whether the 512 session answered at all.
    assert arm2.index("GET /oic/d: 2.05, 149 bytes") < arm2.index(
        "GET /device/0: FragmentLimitTimeoutError, the first block never "
        "arrived (length 512)")
    assert FakeSession.created[1].closed


def test_arm_one_reads_device0_at_1024(harness, capsys):
    """The primed read targets 1024, so arm 1 reads /device/0 after /oic/d."""
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x" * 150),
               "by_path": {("device", "0"): (69, b"x" * 4607)}},
        512: {"connect": None, "get": (69, b"x" * 150)},
    }
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    arm1 = out[out.index("arm 1:"):out.index("arm 2:")]
    assert arm1.index("GET /oic/d: 2.05, 150 bytes") < arm1.index(
        "GET /device/0: 2.05, 4607 bytes")


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
        lambda host, **kw: _directory((1, 2)))
    harness(SECRET_HOST)
    assert "refusing to guess" in capsys.readouterr().out
    assert FakeSession.created == []


def test_an_answer_with_no_secure_port_still_counts_as_an_answer(
        harness, capsys, monkeypatch):
    monkeypatch.setattr(
        check, "discover_ocf_secure_ports",
        lambda host, **kw: _directory(()))
    monkeypatch.setattr(check, "LIVENESS_BUDGET_S", 0.05)
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert "the directory answered, but no secure port came through" in out
    assert "did not answer" not in out
    assert FakeSession.created == []


def test_a_slow_directory_is_asked_again_until_the_port_comes_through(
        harness, capsys, monkeypatch):
    """#20 run 2: the washer answered, but too slowly for one attempt."""
    clock = [1000.0]
    monkeypatch.setattr(check.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        check.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    calls = []

    def directory(host, **kw):
        calls.append(kw)
        clock[0] += 1.5
        # The first two attempts answer without the port.
        return _directory(() if len(calls) <= 2 else (49155,))

    monkeypatch.setattr(check, "discover_ocf_secure_ports", directory)
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x")},
        512: {"connect": None, "get": (69, b"x")},
    }
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert "secure port discovered from the plaintext directory" in out
    assert "no secure port" not in out
    assert len(FakeSession.created) == 2
    assert calls[0] == {"timeout": check.DISCOVERY_TIMEOUT_S, "retries": 1}
    assert check.DISCOVERY_TIMEOUT_S > 5.76


def test_silence_reads_as_no_answer(harness, capsys, monkeypatch):
    monkeypatch.setattr(
        check, "discover_ocf_secure_ports",
        lambda host, **kw: _directory((), answered=False))
    monkeypatch.setattr(check, "LIVENESS_BUDGET_S", 0.05)
    harness(SECRET_HOST)
    assert "did not answer" in capsys.readouterr().out


@pytest.mark.parametrize("error, status", [
    (KeyboardInterrupt, 130),
    (RuntimeError, 1),
])
def test_every_exit_reminds_the_user_to_re_enable(
        harness, capsys, monkeypatch, error, status):
    def boom(self, label, host):
        raise error()
    monkeypatch.setattr(check._Run, "appliance", boom)
    assert harness(SECRET_HOST) == status
    assert "Re-enable your integration now." in capsys.readouterr().out


@pytest.mark.parametrize("reason", [
    "fe80::1c2b:3a4d",
    "oven-kitchen.local",
    "serial 0ABC1DEFGH2XYZ",
    "bad from 192.0.2.77",
    "uuid 1b2c3d4e-0000-4000-8000-000000000000",
    "/home/someone/certs/client.key",
])
def test_identifying_shapes_are_withheld(reason):
    assert "withheld" in check._describe_reason(reason)


def test_every_engine_reason_still_prints():
    """Each refusal reason the installed engine can raise passes the filter.

    Reads the literals from the engine's source, so a new reason with a word
    the allowlist lacks fails here instead of being withheld on hardware.
    """
    filled = {"{description}": "48", "{curve:04x}": "0017",
              "{suite:04x}": "c02b", "{type(exc).__name__}": "ValueError",
              "{hash_id}": "4", "{sig_id}": "1"}
    reasons = []
    # A reason can be several adjacent literals across lines, so the whole
    # run of them is captured and joined, as Python joins them.
    call = re.compile(r'_(?:abandon|fail)\(\s*((?:f?"[^"]*"\s*)+)\)')
    piece = re.compile(r'f?"([^"]*)"')
    for module in (_dtls_base, _dtls_cert):
        for run in call.findall(inspect.getsource(module)):
            literal = "".join(piece.findall(run))
            for placeholder, value in filled.items():
                literal = literal.replace(placeholder, value)
            assert "{" not in literal, literal
            reasons.append(literal)
    assert len(reasons) > 20
    withheld = [r for r in reasons if "withheld" in check._describe_reason(r)]
    assert withheld == []


def test_a_warning_prints_its_class_and_no_path(capsys):
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.showwarning = check._show_warning
        warnings.warn("detail that may name a path", DeprecationWarning)
    err = capsys.readouterr().err
    assert err == "warning: DeprecationWarning\n"


def test_record_overflow_is_named():
    assert "record_overflow" in check._describe_reason(
        "peer sent fatal alert 22")


class _AlertConnection:
    """A connection whose handshake fails the way the engine's does."""

    def do_handshake(self):
        raise SSL.Error("peer sent fatal alert 48")


class _AlertAuth:
    def __init__(self, *args, **kwargs):
        pass

    def configure_context(self, context):
        raise AssertionError("the context path must not be used")

    def create_dtls_connection(self, *, mtu):
        return _AlertConnection()

    def _load_client_credential(self):
        return [], None


def test_the_real_session_hands_the_alert_to_the_script(
        harness, capsys, monkeypatch):
    """Runs the library's own connect(), so its log call is what is tested.

    A change of level, logger or wording in that call fails this test.
    """
    monkeypatch.setattr(check, "DtlsCoapSession", dtls_session.DtlsCoapSession)
    monkeypatch.setattr(
        check.FragmentingCertificateAuth, "from_files",
        staticmethod(lambda *a, **k: _AlertAuth()))
    # Not the script's default port, so a real run with the default does not
    # collide with this test. Below Linux's ephemeral range (32768-60999), so
    # a temporary socket cannot hold it either.
    harness("127.0.0.1", extra=("--local-port", "26961"))
    out = capsys.readouterr().out
    assert "fatal alert 48 (unknown_ca)" in out
    assert "no reason logged" not in out


def test_the_engine_still_words_a_peer_alert_the_same_way():
    source = inspect.getsource(_dtls_base)
    assert 'f"peer sent fatal alert {description}"' in source
    assert check._PEER_ALERT.search("peer sent fatal alert 48")


def test_the_quiet_time_starts_when_the_appliance_answers_again(
        harness, capsys, monkeypatch):
    """A drop-off after arm 1 must not shorten the wait before arm 2."""
    clock = [1000.0]
    monkeypatch.setattr(check.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        check.time, "sleep", lambda s: clock.__setitem__(0, clock[0] + s))
    polls = []

    def directory(host, **kw):
        polls.append(clock[0])
        # Call 1 is the first discovery. Calls 2 to 9, the liveness polls
        # after arm 1, are silent: 3 s each plus the script's 2 s pause,
        # so the appliance answers again 40 s after the handshake.
        if 2 <= len(polls) <= 9:
            clock[0] += 3.0
            return _directory((), answered=False)
        return _directory((49155,))

    monkeypatch.setattr(check, "discover_ocf_secure_ports", directory)
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x")},
        512: {"connect": None, "get": (69, b"x")},
    }
    harness(SECRET_HOST)
    out = capsys.readouterr().out
    assert "plaintext CoAP answered after 40.0 s" in out
    # The full floor, counted from the answer, not from the handshake end.
    assert f"waiting {check.MIN_GAP_S:.0f} s before the next handshake" in out


def test_paths_are_read_in_order_after_oic_d(harness, capsys):
    FakeSession.plan = {
        1024: {"connect": None, "get": (69, b"x" * 150)},
        512: {"connect": None, "get": (69, b"x" * 150)},
    }
    harness(SECRET_HOST, extra=("--path", "/information/vs/0",
                                "--path", "/oic/res"))
    assert [s.reads for s in FakeSession.created] == [
        ["/oic/d", "/information/vs/0", "/oic/res"]] * 2


@pytest.mark.parametrize("bad", [
    "oic/res", "/oic/res?if=oic.if.ll", "/oic//res", "/oic/sec/doxm",
    "/oic/sec",
])
def test_unsafe_or_malformed_paths_are_refused(harness, bad):
    with pytest.raises(SystemExit):
        harness(SECRET_HOST, extra=("--path", bad))
    assert FakeSession.created == []


def test_more_paths_than_the_cap_are_refused(harness):
    extra = []
    for number in range(check.MAX_PATHS + 1):
        extra += ["--path", f"/r{number}/vs/0"]
    with pytest.raises(SystemExit):
        harness(SECRET_HOST, extra=tuple(extra))
    assert FakeSession.created == []
