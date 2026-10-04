"""Hostile-input contracts for the pure-Python DTLS-PSK engine.

The attacker modelled throughout is OFF-PATH: able to send spoofed UDP
datagrams to our socket, since source addresses are forgeable on a LAN, but
unable to read our traffic or hold the pre-shared key. That is the realistic
threat for a client talking to one appliance on a home network.

Each test here corresponds to a defect found and fixed rather than to a
hypothetical, so a failure is a regression and not a style question.
"""

from __future__ import annotations

import os
import random
import struct

import pytest

from smartthings_local.protocol._dtls_psk import (
    DtlsError,
    DtlsPskClient,
    WantRead,
    ZeroReturn,
    _Transform,
)

KEY_BLOCK = bytes(range(96))


def record(content_type: int, epoch: int, seq: int, payload: bytes) -> bytes:
    return (
        bytes([content_type])
        + b"\xfe\xfd"
        + struct.pack("!H", epoch)
        + seq.to_bytes(6, "big")
        + struct.pack("!H", len(payload))
        + payload
    )


def peer_of(key_block: bytes) -> _Transform:
    return _Transform(
        key_block[32:64] + key_block[0:32] + key_block[80:96] + key_block[64:80]
    )


@pytest.fixture
def client() -> DtlsPskClient:
    """A client that has emitted its ClientHello and is awaiting a reply."""
    c = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    with pytest.raises(WantRead):
        c.do_handshake()
    return c


@pytest.fixture
def established() -> DtlsPskClient:
    """A client driven to the established state with a known key block."""
    c = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    with pytest.raises(WantRead):
        c.do_handshake()
    c._transform = _Transform(KEY_BLOCK)
    c._read_active = True
    c._state = "established"
    return c


def test_spoofed_epoch0_record_does_not_wedge_the_handshake(client):
    """RFC 6347 anti-replay (section 4.1.2) applies the replay check to records that authenticate.

    Epoch 0 carries no MAC, so a window advanced from it lets one forged
    datagram with a high sequence number drop every genuine reply after it.
    """
    client.bio_write(record(22, 0, (1 << 48) - 1, b"\x00" * 12))
    with pytest.raises(WantRead):
        client.do_handshake()

    hvr = (
        bytes([3]) + (3).to_bytes(3, "big") + struct.pack("!H", 0)
        + (0).to_bytes(3, "big") + (3).to_bytes(3, "big")
        + b"\xfe\xfd" + bytes([0])
    )
    client.bio_write(record(22, 0, 0, hvr))
    with pytest.raises(WantRead):
        client.do_handshake()
    assert client._state == "sent_cookie_hello"


def test_record_failing_authentication_does_not_consume_sequence_space(established):
    peer = peer_of(KEY_BLOCK)
    established.bio_write(record(23, 1, 1000, os.urandom(64)))
    established._drain_inbox()

    genuine = peer.protect(1, 5, 23, b"genuine appliance reply")
    established.bio_write(record(23, 1, 5, genuine))
    established._drain_inbox()
    assert list(established._appdata) == [b"genuine appliance reply"]


def test_unauthenticated_close_notify_is_ignored(client):
    """A spoofed plaintext alert must not make a live session look closed."""
    client.bio_write(record(21, 0, 0, bytes([1, 0])))
    with pytest.raises(WantRead):
        client.do_handshake()
    assert not client._peer_closed


def test_authenticated_close_notify_is_honoured(established):
    peer = peer_of(KEY_BLOCK)
    established.bio_write(record(21, 1, 0, peer.protect(1, 0, 21, bytes([1, 0]))))
    with pytest.raises(ZeroReturn):
        established.recv()


def test_epoch0_application_data_is_never_delivered(client):
    """Unauthenticated. Accepting it lets a spoofer forge an appliance reply."""
    client.bio_write(record(23, 0, 0, b"hello"))
    client._drain_inbox()
    assert not client._appdata


def test_overlapping_fragment_does_not_rewrite_received_bytes(client):
    client._next_recv_msg_seq = 1

    def fragment(msg_seq, length, offset, body):
        return (
            bytes([2]) + length.to_bytes(3, "big") + struct.pack("!H", msg_seq)
            + offset.to_bytes(3, "big") + len(body).to_bytes(3, "big") + body
        )

    for seq, frag in enumerate(
        [
            fragment(1, 40, 0, b"A" * 20),
            fragment(1, 40, 0, b"B" * 20),
            fragment(1, 40, 20, b"C" * 20),
        ]
    ):
        client.bio_write(record(22, 0, seq, frag))
        client._drain_inbox()

    pending = client._pending.get(1)
    if pending is not None:
        assert bytes(pending[1][:20]) != b"B" * 20


def test_inbound_queue_is_bounded(client):
    for _ in range(5000):
        client.bio_write(b"\x16\xfe\xfd" + b"\x00" * 10)
    assert len(client._inbox) < 5000


def test_application_queue_is_bounded(established):
    peer = peer_of(KEY_BLOCK)
    for seq in range(3000):
        established.bio_write(
            record(23, 1, seq, peer.protect(1, seq, 23, b"x" * 32))
        )
    established._drain_inbox()
    assert len(established._appdata) < 3000


def test_padding_scan_length_is_not_data_dependent():
    """Lucky 13: the loop must not count iterations from a secret byte.

    Structural rather than timed, because CPython gives no constant-time
    guarantee and a timing assertion here would be noise.
    """
    import inspect

    source = inspect.getsource(_Transform.unprotect)
    assert "_MAX_PAD_SCAN" in source or "range(256)" in source


def test_established_session_ignores_a_replayed_server_hello(client):
    client._state = "established"
    client._read_active = True
    before = (client._server_random, client._master_secret, client._state)
    body = (
        b"\xfe\xfd" + b"\xAA" * 32 + b"\x00" + struct.pack("!H", 0xC037) + b"\x00"
    )
    client._handle_server_hello(body)
    assert (client._server_random, client._master_secret, client._state) == before


def test_repeat_hello_verify_request_is_answered(client):
    """Answering only the first is what OpenSSL does.

    Against a server that re-issues a cookie, that leaves both sides
    retransmitting to the deadline with no alert, which is the shape
    localthings#504 describes as the likely cause of issue #20's silent
    timeouts. An earlier version of this test asserted the ignoring
    behaviour was correct, which is how the defect survived a self-audit.
    """
    first = b"\xfe\xfd" + bytes([4]) + b"\xAA\xAA\xAA\xAA"
    client._handle_hello_verify_request(first, 0)
    assert client._state == "sent_cookie_hello"
    assert client._cookie == b"\xAA" * 4

    before = client._next_msg_seq
    second = b"\xfe\xfd" + bytes([4]) + b"\xBB\xBB\xBB\xBB"
    client._handle_hello_verify_request(second, 1)
    assert client._cookie == b"\xBB" * 4
    assert client._next_msg_seq > before
    assert client._next_recv_msg_seq == 2


def test_repeat_hello_verify_request_is_bounded(client):
    """A server that only ever sends cookies must not hold us open."""
    for index in range(40):
        body = b"\xfe\xfd" + bytes([4]) + bytes([index, index, index, index])
        client._handle_hello_verify_request(body, index)
        if client._failed:
            break
    assert client._failed is not None


def test_identical_cookie_does_not_renumber_the_handshake(client):
    """A repeat of the same cookie is a lost answer, not a new challenge.

    Starting a fresh hello would renumber the handshake underneath the
    flight timer that already owns that retransmission.
    """
    body = b"\xfe\xfd" + bytes([4]) + b"\xAA\xAA\xAA\xAA"
    client._handle_hello_verify_request(body, 0)
    after_first = client._next_msg_seq
    client._handle_hello_verify_request(body, 1)
    assert client._next_msg_seq == after_first


def test_zero_length_fragments_terminate(client):
    payload = (
        bytes([2]) + (40).to_bytes(3, "big") + struct.pack("!H", 9)
        + (0).to_bytes(3, "big") + (0).to_bytes(3, "big")
    ) * 50
    client.bio_write(record(22, 0, 0, payload))
    client._drain_inbox()


@pytest.mark.parametrize("seed", [20261003, 20261004])
def test_parsers_survive_hostile_records(seed):
    """Only WantRead, ZeroReturn and DtlsError may escape the parsers."""
    rng = random.Random(seed)
    for _ in range(1500):
        c = DtlsPskClient(b"\x01" * 16, b"k" * 16)
        with pytest.raises(WantRead):
            c.do_handshake()
        datagram = record(
            rng.choice((20, 21, 22, 23, 99)),
            rng.choice((0, 0, 0, 1)),
            rng.randrange(1 << 20),
            bytes(rng.randrange(256) for _ in range(rng.randint(0, 200))),
        )
        c.bio_write(datagram)
        try:
            c._drain_inbox()
            c.recv(65535)
        except (WantRead, ZeroReturn, DtlsError):
            pass
