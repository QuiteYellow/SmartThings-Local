"""Deterministic tests for bounded DTLS handshake timing."""

from __future__ import annotations

import socket
from uuid import UUID

import pytest
from OpenSSL import SSL

from smartthings_local.errors import AuthenticationError, SessionTimeoutError
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.dtls_session import DtlsCoapSession
from smartthings_local.protocol.endpoint import ResolvedUdpEndpoint


class _Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class _Auth:
    def __init__(self, clock=None, configure_delay=0.0):
        self.clock = clock
        self.configure_delay = configure_delay

    def configure_context(self, _context):
        if self.clock is not None:
            self.clock.advance(self.configure_delay)


class _IdentityAuth(_Auth):
    def __init__(self, identity):
        super().__init__()
        self.identity = identity

    def _authenticated_server_identity(self, _connection):
        if isinstance(self.identity, Exception):
            raise self.identity
        return self.identity


class _Connection:
    def __init__(self, outcomes=None, outputs=None, timer=None):
        self.outcomes = list(outcomes or ())
        self.outputs = list(outputs or ())
        self.timer = timer
        self.bio_writes = []
        self.timeout_calls = 0

    def set_connect_state(self):
        return None

    def set_ciphertext_mtu(self, _mtu):
        return None

    def do_handshake(self):
        outcome = self.outcomes.pop(0) if self.outcomes else "want-read"
        if outcome == "want-read":
            raise SSL.WantReadError()
        if isinstance(outcome, Exception):
            raise outcome

    def bio_read(self, _size):
        if self.outputs:
            return self.outputs.pop(0)
        raise SSL.WantReadError()

    def bio_write(self, data):
        self.bio_writes.append(data)

    def DTLSv1_get_timeout(self):
        return self.timer

    def DTLSv1_handle_timeout(self):
        self.timeout_calls += 1


class _Socket:
    def __init__(self, clock, inbound=()):
        self.clock = clock
        self.inbound = list(inbound)
        self.timeouts = []
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def recv(self, _size):
        if self.inbound:
            result = self.inbound.pop(0)
            if isinstance(result, Exception):
                self.clock.advance(self.timeouts[-1])
                raise result
            return result
        self.clock.advance(self.timeouts[-1])
        raise TimeoutError()

    def close(self):
        self.closed = True


def _session(auth=None):
    return DtlsCoapSession(
        "device.example",
        5684,
        auth=auth or _Auth(),
    )


def _install_handshake(
    monkeypatch,
    clock,
    *,
    outcomes=(),
    outputs=(),
    inbound=(),
    timer=None,
):
    connection = _Connection(outcomes, outputs, timer)
    sock = _Socket(clock, inbound)
    endpoint = ResolvedUdpEndpoint(
        socket.AF_INET,
        ("192.0.2.10", 5684),
    )
    open_calls = []

    def open_socket(*args, **kwargs):
        open_calls.append((args, kwargs))
        sock.settimeout(kwargs["timeout"])
        return sock, endpoint

    monkeypatch.setattr(dtls_session.SSL, "Context", lambda *_args: object())
    monkeypatch.setattr(
        dtls_session.SSL,
        "Connection",
        lambda *_args: connection,
    )
    monkeypatch.setattr(
        dtls_session,
        "open_host_filtered_udp_socket",
        open_socket,
    )
    monkeypatch.setattr(dtls_session.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(dtls_session.time, "sleep", clock.advance)
    monkeypatch.setattr(
        dtls_session.time,
        "time",
        lambda: pytest.fail("wall clock must not control handshake deadlines"),
    )
    return connection, sock, endpoint, open_calls


@pytest.mark.parametrize("timeout", (True, "1", object()))
def test_connect_timeout_type_is_explicit(timeout):
    with pytest.raises(TypeError, match="number or None"):
        _session().connect(timeout=timeout)


@pytest.mark.parametrize(
    "timeout",
    (
        0,
        -1,
        float("nan"),
        float("inf"),
        float("-inf"),
        10**1000,
    ),
)
def test_connect_timeout_must_be_positive_and_finite(timeout):
    with pytest.raises(ValueError, match="positive finite"):
        _session().connect(timeout=timeout)


def test_connect_timeout_caps_every_blocking_poll(monkeypatch):
    clock = _Clock()
    _connection, sock, _endpoint, open_calls = _install_handshake(
        monkeypatch,
        clock,
    )
    session = _session()

    with pytest.raises(SessionTimeoutError):
        session.connect(timeout=4.75)

    assert clock.now == pytest.approx(104.75)
    assert sock.closed
    assert open_calls == [
        (
            ("device.example", 5684),
            {
                "family": socket.AF_UNSPEC,
                "local_port": None,
                "timeout": 0.5,
            },
        )
    ]
    assert max(sock.timeouts) <= 0.5
    assert sock.timeouts[-1] == pytest.approx(0.25)


def test_short_timeout_is_not_rounded_up_to_poll_interval(monkeypatch):
    clock = _Clock()
    _connection, sock, _endpoint, open_calls = _install_handshake(
        monkeypatch,
        clock,
    )

    with pytest.raises(SessionTimeoutError):
        _session().connect(timeout=0.125)

    assert clock.now == pytest.approx(100.125)
    assert open_calls[0][1]["timeout"] == pytest.approx(0.125)
    assert sock.timeouts == pytest.approx([0.125, 0.125])


def test_default_timeout_uses_session_constant(monkeypatch):
    clock = _Clock()
    _connection, sock, _endpoint, _open_calls = _install_handshake(
        monkeypatch,
        clock,
    )
    session = _session()
    session.HANDSHAKE_TIMEOUT_S = 0.2

    with pytest.raises(SessionTimeoutError):
        session.connect()

    assert clock.now == pytest.approx(100.2)
    assert sock.closed


def test_context_setup_consumes_the_same_deadline(monkeypatch):
    clock = _Clock()
    socket_opened = False

    def open_socket(*_args, **_kwargs):
        nonlocal socket_opened
        socket_opened = True
        raise AssertionError("expired setup must not open a socket")

    monkeypatch.setattr(dtls_session.SSL, "Context", lambda *_args: object())
    monkeypatch.setattr(dtls_session.SSL, "Connection", lambda *_args: _Connection())
    monkeypatch.setattr(dtls_session, "open_host_filtered_udp_socket", open_socket)
    monkeypatch.setattr(dtls_session.time, "monotonic", clock.monotonic)
    session = _session(_Auth(clock, configure_delay=0.2))

    with pytest.raises(SessionTimeoutError):
        session.connect(timeout=0.1)

    assert not socket_opened


def test_socket_setup_consumes_the_same_deadline(monkeypatch):
    clock = _Clock()
    connection = _Connection()
    connection.do_handshake = lambda: pytest.fail(
        "expired socket setup must not start a handshake"
    )
    sock = _Socket(clock)
    endpoint = ResolvedUdpEndpoint(
        socket.AF_INET,
        ("192.0.2.10", 5684),
    )

    def open_socket(*_args, **kwargs):
        sock.settimeout(kwargs["timeout"])
        clock.advance(0.2)
        return sock, endpoint

    monkeypatch.setattr(dtls_session.SSL, "Context", lambda *_args: object())
    monkeypatch.setattr(
        dtls_session.SSL,
        "Connection",
        lambda *_args: connection,
    )
    monkeypatch.setattr(dtls_session, "open_host_filtered_udp_socket", open_socket)
    monkeypatch.setattr(dtls_session.time, "monotonic", clock.monotonic)

    with pytest.raises(SessionTimeoutError):
        _session().connect(timeout=0.1)

    assert sock.closed


def test_successful_handshake_preserves_connected_session_state(monkeypatch):
    clock = _Clock()
    connection, sock, endpoint, _open_calls = _install_handshake(
        monkeypatch,
        clock,
        outcomes=("want-read", "success"),
        inbound=(b"synthetic server flight",),
    )
    session = _session()

    session.connect(timeout=1.0)

    assert connection.bio_writes == [b"synthetic server flight"]
    assert session.conn is connection
    assert session.sock is sock
    assert session.endpoint is endpoint
    assert session.dest == endpoint.sockaddr
    assert session.server_certificate_identity is None
    assert not sock.closed


def test_successful_profiled_handshake_publishes_server_identity(monkeypatch):
    clock = _Clock()
    identity = UUID(bytes=b"\xab" * 16)
    connection, sock, endpoint, _open_calls = _install_handshake(
        monkeypatch,
        clock,
        outcomes=("want-read", "success"),
        inbound=(b"synthetic server flight",),
    )
    session = _session(_IdentityAuth(identity))

    session.connect(timeout=1.0)

    assert session.server_certificate_identity == identity
    assert session.conn is connection
    assert session.sock is sock
    assert session.endpoint is endpoint
    assert not sock.closed


@pytest.mark.parametrize(
    "identity",
    (ValueError("missing identity"), "not-a-uuid", UUID(int=0)),
)
def test_profiled_handshake_fails_closed_without_valid_server_identity(
    monkeypatch,
    identity,
):
    clock = _Clock()
    _connection, sock, _endpoint, _open_calls = _install_handshake(
        monkeypatch,
        clock,
        outcomes=("want-read", "success"),
        inbound=(b"synthetic server flight",),
    )
    session = _session(_IdentityAuth(identity))

    with pytest.raises(AuthenticationError) as captured:
        session.connect(timeout=1.0)

    assert captured.value.code == "authentication"
    assert str(identity) not in str(captured.value)
    assert session.server_certificate_identity is None
    assert session.conn is None
    assert session.sock is None
    assert sock.closed


def test_connect_services_openssl_retransmit_timer(monkeypatch):
    clock = _Clock()
    outbound = b"\x16\xfe\xfd" + b"\x00" * 8 + b"\x00\x01x"
    connection, sock, _endpoint, _open_calls = _install_handshake(
        monkeypatch,
        clock,
        outcomes=("want-read", "want-read", "success"),
        outputs=(outbound, outbound),
        inbound=(TimeoutError(), b"synthetic server flight"),
        timer=0.0,
    )

    _session().connect(timeout=2.0)

    assert connection.timeout_calls == 1
    assert sock.sent == [outbound, outbound]
    assert connection.bio_writes == [b"synthetic server flight"]


@pytest.mark.parametrize("success_delay", (0.1, 0.2))
def test_handshake_success_at_or_after_deadline_is_retained(
    monkeypatch,
    success_delay,
):
    clock = _Clock()
    connection, sock, endpoint, _open_calls = _install_handshake(
        monkeypatch,
        clock,
    )

    def late_success():
        clock.advance(success_delay)

    connection.do_handshake = late_success

    session = _session()
    session.connect(timeout=0.1)

    assert session.conn is connection
    assert session.sock is sock
    assert session.endpoint is endpoint
    assert session.dest == endpoint.sockaddr
    assert not sock.closed
