"""A peer that opens its own handshake is not a session fault.

An OCF server with a message for an endpoint it holds no session for opens
one itself, so its ClientHello can arrive while we are mid-handshake from
our fixed local port. OpenSSL, being the client, rejects it and the whole
handshake dies -- which used to surface as `session error: session operation
failed`, a warning, and an error-count bump for behaviour that is expected
and self-clearing. These tests pin the classification and the retry.
"""

from __future__ import annotations

import logging
import threading
import types

import pytest
from OpenSSL import SSL

import mqtt_demo.bridge as bridge
from smartthings_local.errors import PeerInitiatedHandshakeError, SessionError
from smartthings_local.protocol import dtls_session


def _record(content_type, epoch, sequence, fragment):
    return (
        bytes([content_type])
        + b'\xfe\xfd'
        + epoch.to_bytes(2, 'big')
        + sequence.to_bytes(6, 'big')
        + len(fragment).to_bytes(2, 'big')
        + fragment
    )


def _handshake(msg_type, body=b'\x00' * 20, msg_seq=0):
    return (
        bytes([msg_type])
        + len(body).to_bytes(3, 'big')
        + msg_seq.to_bytes(2, 'big')
        + (0).to_bytes(3, 'big')
        + len(body).to_bytes(3, 'big')
        + body
    )


CLIENT_HELLO = _record(22, 0, 1, _handshake(1))


def test_a_peer_client_hello_is_recognised():
    assert dtls_session._carries_peer_client_hello(CLIENT_HELLO)


def test_a_client_hello_behind_another_record_is_still_found():
    # Flights arrive coalesced; the appliance's own record was observed at
    # record sequence 1, behind nothing, but a server flight can pack five.
    datagram = _record(20, 0, 0, b'\x01') + CLIENT_HELLO
    assert dtls_session._carries_peer_client_hello(datagram)


@pytest.mark.parametrize(
    'datagram',
    (
        _record(22, 0, 1, _handshake(2)),          # ServerHello
        _record(22, 0, 0, _handshake(3)),          # HelloVerifyRequest
        _record(21, 0, 0, b'\x02\x28'),            # fatal alert
        _record(23, 1, 4, b'\x00' * 16),           # application data
        # Epoch 1 is encrypted, so a byte that merely looks like a
        # ClientHello type must never be read as one.
        _record(22, 1, 0, _handshake(1)),
        CLIENT_HELLO[:-4],                         # truncated
        b'\x16\xfe',                               # too short for a header
        b'',
    ),
)
def test_everything_else_is_not_a_client_hello(datagram):
    assert not dtls_session._carries_peer_client_hello(datagram)


class _NullAuth:
    def configure_context(self, _context):
        return None


def _driver(datagrams, error):
    def drive(_conn, _sock, **kwargs):
        for datagram in datagrams:
            kwargs['on_datagram'](datagram)
        raise error
    return drive


def test_connect_classifies_a_peer_initiated_handshake(caplog, monkeypatch):
    monkeypatch.setattr(
        dtls_session,
        '_drive_dtls_handshake',
        _driver([CLIENT_HELLO], SSL.Error([('SSL routines', '', 'unexpected message')])),
    )
    session = dtls_session.DtlsCoapSession(
        '127.0.0.1', 49155, auth=_NullAuth())

    with caplog.at_level(logging.INFO, logger=dtls_session.__name__):
        with pytest.raises(PeerInitiatedHandshakeError) as raised:
            session.connect(timeout=1.0)

    assert str(raised.value) == 'peer initiated a concurrent handshake'
    assert 'already' in caplog.text and 'unexpected message' in caplog.text
    # Expected peer behaviour must not be reported as a fault.
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    # It is still a SessionError, so existing handling keeps working.
    assert isinstance(raised.value, SessionError)


def test_a_handshake_failure_without_a_peer_hello_is_unchanged(
        caplog, monkeypatch):
    monkeypatch.setattr(
        dtls_session,
        '_drive_dtls_handshake',
        _driver(
            [_record(22, 0, 0, _handshake(3))],
            SSL.Error([('SSL routines', '', 'tlsv1 alert unknown ca')]),
        ),
    )
    session = dtls_session.DtlsCoapSession(
        '127.0.0.1', 49155, auth=_NullAuth())

    with caplog.at_level(logging.INFO, logger=dtls_session.__name__):
        with pytest.raises(SessionError) as raised:
            session.connect(timeout=1.0)

    assert type(raised.value) is SessionError
    assert 'tlsv1 alert unknown ca' in caplog.text
    assert [r for r in caplog.records if r.levelno >= logging.WARNING]


def _loop_bridge(errors):
    """A PushBridge shell whose session_once raises `errors` in turn."""
    b = bridge.PushBridge.__new__(bridge.PushBridge)
    b.app = types.SimpleNamespace(ip='192.0.2.9', ocf_port=49155, index=0)
    b.log = logging.getLogger('test-bridge-loop')
    b.stop = threading.Event()
    b.session = None
    b.session_started_ts = None
    b.error_count = 0
    b.waits = []
    remaining = list(errors)

    def session_once():
        if not remaining:
            b.stop.set()
            return
        raise remaining.pop(0)

    def wait(seconds):
        b.waits.append(seconds)
        return b.stop.is_set()

    b.session_once = session_once
    b.set_availability = lambda _value: None
    b.stop.wait = wait
    return b


def test_the_loop_retries_at_once_and_counts_no_error(caplog):
    b = _loop_bridge([PeerInitiatedHandshakeError()])

    with caplog.at_level(logging.INFO, logger='test-bridge-loop'):
        b.run_forever()

    assert b.error_count == 0
    assert b.waits[0] == bridge._PEER_HANDSHAKE_RETRY_S
    assert 'opening its own session' in caplog.text
    assert 'reconnect in' not in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_a_real_fault_still_backs_off_and_counts(caplog):
    b = _loop_bridge([SessionError()])

    with caplog.at_level(logging.INFO, logger='test-bridge-loop'):
        b.run_forever()

    assert b.error_count == 1
    assert b.waits[0] != bridge._PEER_HANDSHAKE_RETRY_S
    assert 'reconnect in' in caplog.text


def test_a_collision_does_not_grow_the_backoff_for_a_later_fault(monkeypatch):
    # A refused handshake says nothing about the device or the network, so
    # the delay a genuine fault gets afterwards must be the first-fault one.
    # The reconnect jitter is pinned, since comparing two random draws is
    # how this test would flake.
    monkeypatch.setattr(bridge.random, 'uniform', lambda _low, _high: 1.0)

    collided = _loop_bridge(
        [PeerInitiatedHandshakeError(), SessionError()])
    collided.run_forever()
    plain = _loop_bridge([SessionError()])
    plain.run_forever()

    assert collided.waits[1] == plain.waits[0]
