"""Exact transcript and session contract for opt-in HVR peer cleanup."""

from __future__ import annotations

import socket

import pytest

from smartthings_local.errors import (
    HandshakePeerCleanupError,
    SessionClosedError,
    SessionTimeoutError,
)
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.auth import (
    SamsungServerProfile,
    ServerCertificateAuth,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession
from smartthings_local.protocol.endpoint import ResolvedUdpEndpoint


def _handshake_record(
    message_type,
    *,
    record_sequence,
    body=b'',
    version=b'\xfe\xfd',
    epoch=0,
    fragment_offset=0,
    fragment_length=None,
):
    if fragment_length is None:
        fragment_length = len(body)
    message = (
        bytes((message_type,))
        + len(body).to_bytes(3, 'big')
        + b'\x00\x00'
        + fragment_offset.to_bytes(3, 'big')
        + fragment_length.to_bytes(3, 'big')
        + body
    )
    return (
        b'\x16'
        + version
        + epoch.to_bytes(2, 'big')
        + record_sequence.to_bytes(6, 'big')
        + len(message).to_bytes(2, 'big')
        + message
    )


def _eligible_transcript(*, marker=b''):
    transcript = dtls_session._HvrPeerCleanupTranscript()
    transcript.record_sent(
        _handshake_record(1, record_sequence=0, body=b'first')
    )
    transcript.record_received(
        _handshake_record(3, record_sequence=0, body=marker)
    )
    transcript.record_sent(
        _handshake_record(1, record_sequence=1, body=b'cookie')
    )
    return transcript


def test_exact_hvr_only_transcript_builds_standard_epoch_zero_alert():
    transcript = _eligible_transcript()

    assert transcript.cleanup_alert() == (
        b'\x15\xfe\xfd'
        + b'\x00\x00'
        + (2).to_bytes(6, 'big')
        + b'\x00\x02\x02\x28'
    )


def test_transcript_retains_metadata_without_handshake_payload():
    marker = b'private-cookie-material'
    transcript = _eligible_transcript(marker=marker)

    with pytest.raises(TypeError):
        vars(transcript)
    retained = tuple(
        getattr(transcript, name)
        for name in transcript.__slots__
    )
    assert all(marker not in value for value in retained if isinstance(value, bytes))


@pytest.mark.parametrize(
    'mutate',
    (
        lambda transcript: setattr(transcript, '_sent_client_hellos', 1),
        lambda transcript: setattr(transcript, '_received_datagrams', 0),
        lambda transcript: setattr(transcript, '_received_records', 0),
        lambda transcript: setattr(
            transcript,
            '_sent_client_hello_after_hvr',
            False,
        ),
        lambda transcript: setattr(transcript, '_invalid', True),
        lambda transcript: setattr(
            transcript,
            '_last_client_hello_header',
            None,
        ),
        lambda transcript: setattr(
            transcript,
            '_last_client_hello_header',
            transcript._last_client_hello_header[:5]
            + ((1 << 48) - 1).to_bytes(6, 'big')
            + transcript._last_client_hello_header[11:],
        ),
    ),
)
def test_cleanup_alert_fails_closed_when_required_metadata_is_missing(
    mutate,
):
    transcript = _eligible_transcript()
    mutate(transcript)

    assert transcript.cleanup_alert() is None


@pytest.mark.parametrize(
    'record',
    (
        _handshake_record(2, record_sequence=0),
        _handshake_record(3, record_sequence=0, epoch=1),
        _handshake_record(
            3,
            record_sequence=0,
            body=b'fragment',
            fragment_offset=1,
        ),
        b'\x15\xfe\xfd\x00\x00' + b'\x00' * 8,
        b'\x16\xfe\xfd\x00\x00' + b'\x00' * 7,
    ),
)
def test_non_hvr_or_malformed_inbound_record_disables_cleanup(record):
    transcript = _eligible_transcript()
    transcript.record_received(record)

    assert transcript.cleanup_alert() is None


def test_mixed_hvr_and_non_hvr_datagram_disables_cleanup():
    transcript = _eligible_transcript()
    transcript.record_received(
        _handshake_record(3, record_sequence=1)
        + _handshake_record(2, record_sequence=2)
    )

    assert transcript.cleanup_alert() is None


def test_non_client_hello_outbound_record_disables_cleanup():
    transcript = _eligible_transcript()
    transcript.record_sent(_handshake_record(11, record_sequence=2))

    assert transcript.cleanup_alert() is None


def test_transcript_record_bound_fails_closed():
    transcript = _eligible_transcript()
    for sequence in range(32):
        transcript.record_received(
            _handshake_record(3, record_sequence=sequence)
        )

    assert transcript.cleanup_alert() is None


class _Connection:
    def set_connect_state(self):
        return None

    def set_ciphertext_mtu(self, _mtu):
        return None


class _Socket:
    def __init__(self, send_result=None, send_error=None):
        self.closed = False
        self.send_error = send_error
        self.send_result = send_result
        self.sent = []
        self.timeouts = []

    def send(self, data):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(data)
        return len(data) if self.send_result is None else self.send_result

    def close(self):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)


def _profiled_session(*, local_port=49745):
    profile = SamsungServerProfile.discover_device()
    return DtlsCoapSession(
        'device.example',
        5684,
        auth=ServerCertificateAuth(server_profile=profile),
        local_port=local_port,
    )


def _install_connect(monkeypatch, drive, *, udp_socket=None):
    udp_socket = udp_socket or _Socket()
    endpoint = ResolvedUdpEndpoint(
        socket.AF_INET,
        ('192.0.2.10', 5684),
    )
    monkeypatch.setattr(dtls_session.SSL, 'Context', lambda *_args: object())
    monkeypatch.setattr(
        dtls_session.SSL,
        'Connection',
        lambda *_args: _Connection(),
    )
    monkeypatch.setattr(
        ServerCertificateAuth,
        'configure_context',
        lambda self, context: None,
    )
    monkeypatch.setattr(
        dtls_session,
        'open_host_filtered_udp_socket',
        lambda *_args, **_kwargs: (udp_socket, endpoint),
    )
    monkeypatch.setattr(dtls_session, '_drive_dtls_handshake', drive)
    return udp_socket


def _hvr_timeout_driver(
    _connection,
    _socket,
    *,
    on_datagram,
    on_record_sent,
    **_kwargs,
):
    on_record_sent(_handshake_record(1, record_sequence=0, body=b'first'))
    on_datagram(_handshake_record(3, record_sequence=0, body=b'cookie'))
    on_record_sent(_handshake_record(1, record_sequence=1, body=b'cookie'))
    return False


def test_connect_sends_one_cleanup_alert_and_returns_retry_to_caller(
    monkeypatch,
):
    udp_socket = _install_connect(monkeypatch, _hvr_timeout_driver)
    session = _profiled_session()

    with pytest.raises(HandshakePeerCleanupError) as captured:
        session.connect(timeout=1.0, cleanup_hvr_peer=True)

    assert captured.value.code == 'handshake_peer_cleanup'
    assert isinstance(captured.value, SessionTimeoutError)
    assert udp_socket.sent == [
        b'\x15\xfe\xfd'
        + b'\x00\x00'
        + (2).to_bytes(6, 'big')
        + b'\x00\x02\x02\x28'
    ]
    assert udp_socket.timeouts == [0.0]
    assert udp_socket.closed
    assert session.sock is None
    assert session.conn is None


@pytest.mark.parametrize(
    'udp_socket',
    (
        _Socket(send_result=0),
        _Socket(send_error=OSError('synthetic send failure')),
    ),
)
def test_cleanup_send_failure_remains_an_ordinary_timeout(
    monkeypatch,
    udp_socket,
):
    _install_connect(monkeypatch, _hvr_timeout_driver, udp_socket=udp_socket)

    with pytest.raises(SessionTimeoutError) as captured:
        _profiled_session().connect(timeout=1.0, cleanup_hvr_peer=True)

    assert type(captured.value) is SessionTimeoutError
    assert udp_socket.closed


def test_non_hvr_timeout_never_sends_cleanup_alert(monkeypatch):
    def drive(
        _connection,
        _socket,
        *,
        on_datagram,
        on_record_sent,
        **_kwargs,
    ):
        on_record_sent(_handshake_record(1, record_sequence=0))
        on_datagram(_handshake_record(2, record_sequence=0))
        on_record_sent(_handshake_record(1, record_sequence=1))
        return False

    udp_socket = _install_connect(monkeypatch, drive)

    with pytest.raises(SessionTimeoutError) as captured:
        _profiled_session().connect(timeout=1.0, cleanup_hvr_peer=True)

    assert type(captured.value) is SessionTimeoutError
    assert udp_socket.sent == []


def test_cancelled_hvr_handshake_never_sends_cleanup_alert(monkeypatch):
    def drive(*args, **kwargs):
        _hvr_timeout_driver(*args, **kwargs)
        raise dtls_session._HandshakeCancelled()

    udp_socket = _install_connect(monkeypatch, drive)

    with pytest.raises(SessionClosedError):
        _profiled_session().connect(timeout=1.0, cleanup_hvr_peer=True)

    assert udp_socket.sent == []
    assert udp_socket.closed


@pytest.mark.parametrize('value', (None, 0, True, -1, 65536))
def test_cleanup_requires_fixed_nonzero_local_port(value):
    with pytest.raises(ValueError, match='fixed non-zero local port'):
        _profiled_session(local_port=value).connect(cleanup_hvr_peer=True)


def test_cleanup_requires_builtin_bool():
    with pytest.raises(TypeError, match='must be a bool'):
        _profiled_session().connect(cleanup_hvr_peer=1)


def test_cleanup_requires_real_profiled_certificate_provider():
    session = DtlsCoapSession(
        'device.example',
        5684,
        cert_path='/synthetic/client.pem',
        key_path='/synthetic/client.key',
        local_port=49745,
    )

    with pytest.raises(ValueError, match='Samsung server profile'):
        session.connect(cleanup_hvr_peer=True)
