"""Pure-Python DTLS 1.2 client for TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256.

Exists because OpenSSL's DTLS 1.2 PSK client callback passes the identity as
a NUL-terminated `char *` and returns the key length, so it cannot carry a
recovered OwnerPSK identity containing a zero byte. See #115.

Implements exactly the one ciphersuite these appliances offer for PSK, client
side only. No X.509, no resumption, no renegotiation (the appliance disables
it), no ciphersuite negotiation.

The record layer, handshake reassembler, cookie exchange and retransmission
timer live in `_dtls_base`, shared with the certificate engine; this module is
the PSK half alone.

This is live on the PSK path, not a spare part: `auth.py` imports
`DtlsPskClient` and `PskAuth` builds one per connection, which is what
`DtlsCoapSession.connect()` and the `dtls_probe` diagnostic get when the
credential is a PSK. Read the timing note below with that in mind.

Every wire decision below was read from the appliance firmware's own
Mbed TLS 2.7.8 sources rather than from a specification. Line references are
to that upstream tree (TizenRT's `iotivity_1.2-rel` fork), not to this
repository:

- `config.h:2860` defines MBEDTLS_LIGHT_DEVICE unconditionally, which compiles
  out ENCRYPT_THEN_MAC (2888) and EXTENDED_MASTER_SECRET (2886, 2889). So the
  record layout is classic MAC-then-encrypt and the master secret is the
  classic derivation.
- `ssl_tls.c:823-827` gives the key-block split: client MAC || server MAC ||
  client key || server key.
- `ssl_tls.c:1136` gives the ECDHE-PSK premaster: len(Z) || Z || len(psk) || psk.
- `ssl_cli.c:2692-2752` gives the ServerKeyExchange shape (psk hint, then
  ServerECDHParams, no signature).
- `ssl_cli.c:3324-3342` gives the ClientKeyExchange shape.
- `ca_adapter_net_ssl.c:1726` pins secp256r1.

Interface mirrors the memory-BIO subset of `OpenSSL.SSL.Connection` that
`_drive_dtls_handshake` and `DtlsCoapSession` already drive, and the
unmodified driver completes a handshake against it. `WantRead`, `ZeroReturn`
and `DtlsError` are therefore aliased to pyOpenSSL's exceptions. Replacing
those with engine-neutral types belongs with the connection seam, which is
a separate change and a design question for whoever owns
`AuthenticationProvider`.

Security posture: we are the client, on a LAN, against one appliance, holding
a pre-shared key. MAC and padding verification use a single combined failure
flag and `hmac.compare_digest`, which removes the obvious early-return oracle,
but CPython cannot promise constant time end to end. Lucky-13 resistance is
therefore not claimed. The peer is known, the key is pre-shared and the
traffic is a trickle of CoAP polls on a LAN, so the attack has no practical
surface here; the limit is stated rather than engineered away.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ._dtls_base import (
    _CT_CHANGE_CIPHER_SPEC,
    _ECCURVETYPE_NAMED,
    _HT_CLIENT_KEY_EXCHANGE,
    _HT_FINISHED,
    _HT_SERVER_KEY_EXCHANGE,
    _MAX_PENDING_MESSAGES,
    _NAMED_CURVE_SECP256R1,
    _VERIFY_DATA_LEN,
    DtlsError,
    WantRead,
    ZeroReturn,
    _DtlsClientBase,
    _prf,
    _ReplayWindow,
    logger,
)

__all__ = ["DtlsError", "DtlsPskClient", "WantRead", "ZeroReturn"]

# Re-exported so the names the record-layer tests reach for stay where they
# were when this module held the whole engine.
_ = (_prf, _ReplayWindow, _MAX_PENDING_MESSAGES, logger)

_SUITE = 0xC037  # ssl_ciphersuites.h:184
_MAC_LEN = 32
_KEY_LEN = 16
_BLOCK = 16
_MAX_PAD_SCAN = 256


class _Transform:
    """AES-128-CBC + HMAC-SHA256, MAC-then-encrypt, TLS 1.2 explicit IV."""

    __slots__ = ("_dec_key", "_enc_key", "_mac_dec", "_mac_enc")

    def __init__(self, key_block: bytes) -> None:
        # ssl_tls.c:823-827 -- client MAC, server MAC, client key, server key.
        self._mac_enc = key_block[0:_MAC_LEN]
        self._mac_dec = key_block[_MAC_LEN:_MAC_LEN * 2]
        self._enc_key = key_block[_MAC_LEN * 2:_MAC_LEN * 2 + _KEY_LEN]
        self._dec_key = key_block[_MAC_LEN * 2 + _KEY_LEN:_MAC_LEN * 2 + _KEY_LEN * 2]

    @staticmethod
    def _mac_input(epoch: int, seq: int, content_type: int, payload: bytes) -> bytes:
        # ssl_tls.c ssl_encrypt_buf: seq(8) || type(1) || version(2) || len(2).
        return (
            struct.pack("!H", epoch)
            + seq.to_bytes(6, "big")
            + struct.pack("!BHH", content_type, 0xFEFD, len(payload))
            + payload
        )

    def protect(self, epoch: int, seq: int, content_type: int, payload: bytes) -> bytes:
        """Return the encrypted record fragment for one plaintext payload."""
        mac = hmac.new(
            self._mac_enc,
            self._mac_input(epoch, seq, content_type, payload),
            hashlib.sha256,
        ).digest()
        content = payload + mac
        pad = _BLOCK - (len(content) + 1) % _BLOCK
        if pad == _BLOCK:
            pad = 0
        block = content + bytes([pad]) * (pad + 1)
        iv = os.urandom(_BLOCK)
        encryptor = Cipher(algorithms.AES(self._enc_key), modes.CBC(iv)).encryptor()
        return iv + encryptor.update(block) + encryptor.finalize()

    def unprotect(
        self, epoch: int, seq: int, content_type: int, fragment: bytes
    ) -> bytes | None:
        """Return the plaintext payload, or None if the record is not authentic.

        Padding and MAC are both checked, and the two results are combined into
        one failure flag so neither outcome returns earlier than the other.
        """
        if len(fragment) < _BLOCK * 2 or (len(fragment) - _BLOCK) % _BLOCK:
            return None
        iv, ciphertext = fragment[:_BLOCK], fragment[_BLOCK:]
        decryptor = Cipher(algorithms.AES(self._dec_key), modes.CBC(iv)).decryptor()
        plain = decryptor.update(ciphertext) + decryptor.finalize()

        pad = plain[-1]
        bad = 0
        # A padding length that cannot fit is clamped so the MAC is still
        # computed over a well-defined region rather than short-circuiting.
        if pad + 1 + _MAC_LEN > len(plain):
            bad = 1
            pad = 0
        # Scan a fixed number of trailing bytes so the loop count depends on
        # the record length, which is public, instead of the padding byte,
        # which is not. Bytes outside the padding are masked out arithmetically
        # rather than skipped. CPython still gives no constant-time guarantee;
        # this removes the obvious signal, it does not eliminate Lucky 13.
        scan = min(len(plain), _MAX_PAD_SCAN)
        for index in range(scan):
            byte = plain[len(plain) - 1 - index]
            within = 1 if index <= pad else 0
            bad |= (byte ^ pad) & (-within)

        content = plain[: len(plain) - pad - 1]
        payload, mac = content[:-_MAC_LEN], content[-_MAC_LEN:]
        expected = hmac.new(
            self._mac_dec,
            self._mac_input(epoch, seq, content_type, payload),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(mac, expected):
            bad = 1
        return None if bad else payload


class DtlsPskClient(_DtlsClientBase):
    """One DTLS 1.2 ECDHE-PSK session, driven through a memory BIO."""

    def __init__(self, identity: bytes, key: bytes, mtu: int = 1400) -> None:
        if type(identity) is not bytes or type(key) is not bytes:
            raise TypeError("identity and key must be bytes")
        if not 1 <= len(identity) <= 0xFFFF:
            raise ValueError("identity must be 1 to 65535 bytes")
        if len(key) not in (16, 32):
            raise ValueError("key must be 16 or 32 bytes")
        super().__init__(mtu=mtu)
        self._identity = identity
        self._psk = key

    # -- hooks -----------------------------------------------------------

    def _offered_suites(self) -> tuple[int, ...]:
        return (_SUITE,)

    def _hello_extensions(self) -> bytes:
        return (
            struct.pack("!HHHH", 0x000A, 4, 2, _NAMED_CURVE_SECP256R1)
            + struct.pack("!HH", 0x000B, 2)
            + bytes([1, 0])
        )

    def _handle_other_handshake(
        self, msg_type: int, message: bytes, body: bytes
    ) -> None:
        if msg_type == _HT_SERVER_KEY_EXCHANGE:
            self._transcript += message
            self._handle_server_key_exchange(body)

    def _send_client_flight(self) -> None:
        """ClientKeyExchange + ChangeCipherSpec + Finished."""
        self._start_flight()
        public = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        cke = (
            struct.pack("!H", len(self._identity))
            + self._identity
            + bytes([len(public)])
            + public
        )
        self._emit_handshake(_HT_CLIENT_KEY_EXCHANGE, cke, transcript=True)

        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), self._peer_point
        )
        shared = self._private_key.exchange(ec.ECDH(), peer)
        # ssl_tls.c:1136 -- len(Z) || Z || len(psk) || psk
        premaster = (
            struct.pack("!H", len(shared))
            + shared
            + struct.pack("!H", len(self._psk))
            + self._psk
        )
        self._master_secret = _prf(
            premaster,
            b"master secret",
            self._client_random + self._server_random,
            48,
        )
        key_block = _prf(
            self._master_secret,
            b"key expansion",
            self._server_random + self._client_random,
            _MAC_LEN * 2 + _KEY_LEN * 2,
        )

        self._emit_record(_CT_CHANGE_CIPHER_SPEC, b"\x01")
        self._transform = _Transform(key_block)
        self._send_epoch = 1
        self._send_seq = 0

        verify = _prf(
            self._master_secret,
            b"client finished",
            hashlib.sha256(self._transcript).digest(),
            _VERIFY_DATA_LEN,
        )
        self._emit_handshake(_HT_FINISHED, verify, transcript=True)
    def _handle_server_key_exchange(self, body: bytes) -> None:
        if self._state != "got_server_hello":
            return
        # ssl_cli.c:2692 -- psk_identity_hint first, then ServerECDHParams,
        # and no signature for a PSK key exchange.
        if len(body) < 2:
            self._fail("short ServerKeyExchange")
            return
        hint_len = int.from_bytes(body[0:2], "big")
        offset = 2 + hint_len
        if offset + 4 > len(body):
            self._fail("malformed ServerKeyExchange")
            return
        if body[offset] != _ECCURVETYPE_NAMED:
            self._fail("server offered a non-named curve")
            return
        curve = int.from_bytes(body[offset + 1:offset + 3], "big")
        if curve != _NAMED_CURVE_SECP256R1:
            self._fail(f"server offered unexpected curve 0x{curve:04x}")
            return
        point_len = body[offset + 3]
        point = body[offset + 4:offset + 4 + point_len]
        if len(point) != point_len or point_len == 0:
            self._fail("malformed server ECDH point")
            return
        try:
            # Rejects points that are malformed or not on the curve.
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError:
            self._fail("server ECDH point is not on secp256r1")
            return
        self._peer_point = point
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._state = "got_server_params"
