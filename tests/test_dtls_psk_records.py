"""Record layer and key schedule contracts for the pure-Python DTLS-PSK engine.

AES-128-CBC with HMAC-SHA256, MAC-then-encrypt, TLS 1.2 explicit IV. These
are the properties a reviewer should be able to demand of a hand-written
record layer: a record only verifies in the direction it was written for,
nothing that fails authentication decodes, and the replay window never
reports a fresh sequence number as a replay or the reverse.
"""

from __future__ import annotations

import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from smartthings_local.protocol._dtls_psk import (
    DtlsError,
    DtlsPskClient,
    WantRead,
    _prf,
    _ReplayWindow,
    _Transform,
)

KEY_BLOCK = bytes(range(96))
PAYLOAD_SIZES = (0, 1, 15, 16, 17, 47, 48, 49, 1024)


def peer_of(key_block: bytes) -> _Transform:
    """The mirrored key block the other end derives from the same secret.

    ssl_tls.c:823-827 orders the block client MAC, server MAC, client key,
    server key, so the peer sees those pairs swapped.
    """
    return _Transform(
        key_block[32:64] + key_block[0:32] + key_block[80:96] + key_block[64:80]
    )


@pytest.fixture
def transform() -> _Transform:
    return _Transform(KEY_BLOCK)


@pytest.fixture
def peer() -> _Transform:
    return peer_of(KEY_BLOCK)


@pytest.mark.parametrize("size", PAYLOAD_SIZES)
def test_record_round_trips_to_the_peer(transform, peer, size):
    payload = os.urandom(size)
    fragment = transform.protect(1, 7, 23, payload)
    assert peer.unprotect(1, 7, 23, fragment) == payload


@pytest.mark.parametrize("size", PAYLOAD_SIZES)
def test_record_is_block_aligned(transform, size):
    fragment = transform.protect(1, 7, 23, os.urandom(size))
    assert (len(fragment) - 16) % 16 == 0


@pytest.mark.parametrize("size", PAYLOAD_SIZES)
def test_write_keys_do_not_verify_our_own_record(transform, size):
    """The two directions must be separated, or a reflection attack lands."""
    fragment = transform.protect(1, 7, 23, os.urandom(size))
    assert transform.unprotect(1, 7, 23, fragment) is None


def test_key_directions_differ(transform):
    assert transform._mac_enc != transform._mac_dec
    assert transform._enc_key != transform._dec_key


def test_every_single_bit_flip_is_rejected(transform, peer):
    fragment = transform.protect(1, 2, 23, b"A" * 64)
    for index in range(len(fragment)):
        tampered = bytearray(fragment)
        tampered[index] ^= 0x01
        assert peer.unprotect(1, 2, 23, bytes(tampered)) is None, index


def test_correct_context_is_accepted(transform, peer):
    fragment = transform.protect(1, 5, 23, b"payload")
    assert peer.unprotect(1, 5, 23, fragment) == b"payload"


@pytest.mark.parametrize(
    "epoch,seq,content_type",
    [(1, 6, 23), (2, 5, 23), (1, 5, 22)],
    ids=["wrong-sequence", "wrong-epoch", "wrong-content-type"],
)
def test_wrong_context_is_rejected(transform, peer, epoch, seq, content_type):
    """The 13-byte MAC header binds epoch, sequence, type and length."""
    fragment = transform.protect(1, 5, 23, b"payload")
    assert peer.unprotect(epoch, seq, content_type, fragment) is None


@pytest.mark.parametrize(
    "mangle",
    [lambda f: f[:-16], lambda f: f[:-1], lambda f: b"", lambda f: b"\x00" * 16],
    ids=["truncated", "not-block-multiple", "empty", "iv-only"],
)
def test_malformed_fragments_are_rejected(transform, peer, mangle):
    fragment = transform.protect(1, 0, 23, b"x" * 32)
    assert peer.unprotect(1, 0, 23, mangle(fragment)) is None


@pytest.mark.parametrize("pad", range(256))
def test_no_forged_padding_decodes_without_a_mac(transform, pad):
    """Encrypted under the read key but carrying no MAC: must never decode."""
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(transform._dec_key), modes.CBC(iv)).encryptor()
    fragment = iv + encryptor.update(bytes([pad]) * 64) + encryptor.finalize()
    assert transform.unprotect(1, 0, 23, fragment) is None


def accept(window: _ReplayWindow, seq: int) -> bool:
    """Mirror the record path: check, then commit only if it is not a replay."""
    if window.is_replay(seq):
        return False
    window.accept(seq)
    return True


def test_replay_window_accepts_then_rejects():
    window = _ReplayWindow()
    assert accept(window, 0)
    assert not accept(window, 0)
    assert accept(window, 10)
    assert not accept(window, 10)
    assert accept(window, 5)
    assert not accept(window, 5)


def test_replay_window_edges():
    window = _ReplayWindow()
    accept(window, 1000)
    assert not accept(window, 100), "far past must be dropped"
    assert accept(window, 1000 - 63), "inside the window must be accepted"
    assert not accept(window, 1000 - 64), "one past the window must be dropped"


def test_replay_check_is_side_effect_free():
    """is_replay must not advance the window, or a failed MAC poisons it."""
    window = _ReplayWindow()
    window.accept(5)
    for _ in range(100):
        window.is_replay(1 << 40)
    assert not window.is_replay(6)
    assert window.is_replay(5)


@pytest.mark.parametrize("jump", [1 << 20, 1 << 32, 1 << 47, (1 << 48) - 1])
def test_sequence_jump_costs_window_not_jump(jump):
    """Regression: an unclamped shift asked for a 17 TB integer.

    Python integers are arbitrary precision, so ``bitmap << (seq - highest)``
    allocates one bit per skipped sequence number. A 2**47 jump reached
    180 GB of resident memory before being killed by hand on 2026-10-03.
    """
    window = _ReplayWindow()
    window.accept(0)
    window.accept(jump)
    assert window._bitmap.bit_length() <= 64


def test_far_past_accept_is_bounded():
    window = _ReplayWindow()
    window.accept(1 << 40)
    window.accept(0)
    assert window._bitmap.bit_length() <= 64


def test_prf_prefix_is_stable():
    """RFC 5246 section 5: output is a stream, so a shorter read is a prefix."""
    long = _prf(b"secret", b"label", b"seed", 100)
    assert _prf(b"secret", b"label", b"seed", 32) == long[:32]
    assert len(_prf(b"secret", b"label", b"seed", 7)) == 7


def test_prf_label_separates():
    long = _prf(b"secret", b"label", b"seed", 100)
    assert _prf(b"secret", b"other", b"seed", 32) != long[:32]


def test_identity_and_key_are_validated():
    with pytest.raises(TypeError):
        DtlsPskClient("not-bytes", b"k" * 16)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DtlsPskClient(b"", b"k" * 16)
    with pytest.raises(ValueError):
        DtlsPskClient(b"\x01" * 16, b"short")


def test_send_before_handshake_is_refused():
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    with pytest.raises(DtlsError):
        client.send(b"secret")


def test_bio_read_signals_want_read_when_empty():
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    with pytest.raises(WantRead):
        client.bio_read(1024)


def test_recv_preserves_the_tail_beyond_capacity():
    """A short read must not discard the rest of the record."""
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    client._appdata.append(b"0123456789")
    assert client.recv(4) == b"0123"
    assert client.recv(65535) == b"456789"


def test_server_key_exchange_refuses_an_off_curve_point():
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    client._state = "got_server_hello"
    bogus = b"\x04" + b"\x01" * 64
    body = (
        struct.pack("!H", 0) + bytes([3]) + struct.pack("!H", 0x0017)
        + bytes([len(bogus)]) + bogus
    )
    client._handle_server_key_exchange(body)
    assert client._failed is not None


def test_server_key_exchange_refuses_an_unexpected_curve():
    """ca_adapter_net_ssl.c:1726 pins secp256r1, so nothing else is offered."""
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    client._state = "got_server_hello"
    body = (
        struct.pack("!H", 0) + bytes([3]) + struct.pack("!H", 0x001D)
        + bytes([32]) + b"\x02" * 32
    )
    client._handle_server_key_exchange(body)
    assert client._failed is not None


def test_server_hello_refuses_an_unoffered_suite():
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    client._state = "sent_cookie_hello"
    body = (
        b"\xfe\xfd" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 0x002F) + b"\x00"
    )
    client._handle_server_hello(body)
    assert client._failed is not None


def test_server_hello_refuses_a_version_downgrade():
    client = DtlsPskClient(b"\x01" * 16, b"k" * 16)
    client._state = "sent_cookie_hello"
    body = (
        b"\xfe\xff" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 0xC037) + b"\x00"
    )
    client._handle_server_hello(body)
    assert client._failed is not None
