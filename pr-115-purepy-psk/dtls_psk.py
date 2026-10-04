"""Pure-Python DTLS 1.2 client for TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256.

Spike for [[../PUREPY_DTLS_PSK_PLAN.md]]. Implements exactly the one
ciphersuite Samsung appliances offer for PSK, client side only. No X.509, no
resumption, no renegotiation (the appliance disables it at
`ca_adapter_net_ssl.c:1728`), no ciphersuite negotiation.

Every wire decision here was read out of the appliance's own mbedTLS 2.7.8 in
`local-tools/tizenrt-iotivity-audit/`, not from a spec:

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
`_drive_dtls_handshake` and `DtlsCoapSession` already drive, so it drops into
the existing session loop. `WantRead`/`ZeroReturn` are aliased to pyOpenSSL's
exceptions for that reason; Phase 0 of the plan replaces them with
engine-neutral types defined by the seam.

Security posture: we are the client, on a LAN, against one appliance, holding
a pre-shared key. MAC and padding verification use a single combined failure
flag and `hmac.compare_digest`, which removes the obvious early-return oracle,
but CPython cannot promise constant time end to end. That is an accepted and
stated limit, not an oversight -- see "Lucky 13" in the plan's risk section.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
from collections import deque

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:  # Drop-in with the existing driver; see module docstring.
    from OpenSSL import SSL as _SSL

    WantRead = _SSL.WantReadError
    ZeroReturn = _SSL.ZeroReturnError
    DtlsError = _SSL.Error
except ImportError:  # pragma: no cover - standalone use
    class WantRead(Exception):
        """No progress is possible until more inbound data arrives."""

    class ZeroReturn(Exception):
        """The peer closed the connection cleanly."""

    class DtlsError(Exception):
        """The session failed and cannot continue."""

logger = logging.getLogger(__name__)

_CT_CHANGE_CIPHER_SPEC = 20
_CT_ALERT = 21
_CT_HANDSHAKE = 22
_CT_APPLICATION_DATA = 23

_HT_CLIENT_HELLO = 1
_HT_SERVER_HELLO = 2
_HT_HELLO_VERIFY_REQUEST = 3
_HT_SERVER_KEY_EXCHANGE = 12
_HT_SERVER_HELLO_DONE = 14
_HT_CLIENT_KEY_EXCHANGE = 16
_HT_FINISHED = 20

_VERSION = b"\xfe\xfd"
_SUITE = 0xC037  # ssl_ciphersuites.h:184
_NAMED_CURVE_SECP256R1 = 0x0017
_ECCURVETYPE_NAMED = 3

_RECORD_HEADER = 13
_HANDSHAKE_HEADER = 12
_MAC_LEN = 32
_KEY_LEN = 16
_BLOCK = 16
_VERIFY_DATA_LEN = 12
_MAX_SEQ = (1 << 48) - 1
_REPLAY_WINDOW = 64

# A flight of ours is tiny; this only bounds a hostile peer's reassembly cost.
_MAX_HANDSHAKE_MESSAGE = 16384
_MAX_OUTBOX = 262144
_MAX_PENDING_MESSAGES = 16
# A flood must cost bounded memory. The session loop drains after every
# datagram, so these are only ever reached under attack or a stalled caller.
_MAX_INBOX = 64
_MAX_APPDATA = 256
_MAX_PAD_SCAN = 256

_ALERT_CLOSE_NOTIFY = 0
_ALERT_FATAL = 2
_ALERT_WARNING = 1


def _prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 PRF with SHA-256 (RFC 5246 section 5)."""
    out = bytearray()
    a = hmac.new(secret, label + seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return bytes(out[:length])


class _ReplayWindow:
    """RFC 6347 section 4.1.2.6 sliding window, one per read epoch."""

    __slots__ = ("_bitmap", "_highest")

    def __init__(self) -> None:
        self._bitmap = 0
        self._highest = -1

    def is_replay(self, seq: int) -> bool:
        """Report whether ``seq`` is a replay, without committing to it.

        Separated from :meth:`accept` because a record that fails
        authentication must leave the window untouched. Advancing on an
        unauthenticated record lets one spoofed datagram carrying a high
        sequence number wedge the session permanently (RFC 6347 4.1.2.6
        applies the replay check to records that authenticate).
        """
        if seq > self._highest:
            return False
        offset = self._highest - seq
        return offset >= _REPLAY_WINDOW or bool(self._bitmap & (1 << offset))

    def accept(self, seq: int) -> None:
        """Commit an authenticated sequence number to the window.

        The shift is clamped to the window width. Python integers are
        arbitrary precision, so an unclamped ``bitmap << (seq - highest)``
        asks the allocator for one bit per skipped sequence number: a jump of
        2**47 is a 17 TB integer, which exhausts the machine rather than
        raising. Everything above the window width is discarded by the mask
        anyway, so clamping changes no behaviour.
        """
        if seq > self._highest:
            shift = min(seq - self._highest, _REPLAY_WINDOW)
            self._bitmap = ((self._bitmap << shift) | 1) & ((1 << _REPLAY_WINDOW) - 1)
            self._highest = seq
            return
        offset = self._highest - seq
        if offset < _REPLAY_WINDOW:
            self._bitmap |= 1 << offset


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


class DtlsPskClient:
    """One DTLS 1.2 ECDHE-PSK session, driven through a memory BIO."""

    def __init__(self, identity: bytes, key: bytes, mtu: int = 1400) -> None:
        if type(identity) is not bytes or type(key) is not bytes:
            raise TypeError("identity and key must be bytes")
        if not 1 <= len(identity) <= 0xFFFF:
            raise ValueError("identity must be 1 to 65535 bytes")
        if len(key) not in (16, 32):
            raise ValueError("key must be 16 or 32 bytes")
        if type(mtu) is not int or not 256 <= mtu <= 65535:
            raise ValueError("mtu must be between 256 and 65535")

        self._identity = identity
        self._psk = key
        self._mtu = mtu

        self._inbox: deque[bytes] = deque()
        self._outbox = bytearray()
        self._appdata: deque[bytes] = deque()

        self._state = "start"
        self._transcript = bytearray()
        self._send_epoch = 0
        self._send_seq = 0
        self._next_msg_seq = 0
        self._recv_windows: dict[int, _ReplayWindow] = {}
        self._transform: _Transform | None = None
        self._read_active = False

        self._client_random = b""
        self._server_random = b""
        self._cookie = b""
        self._master_secret = b""
        self._private_key: ec.EllipticCurvePrivateKey | None = None
        self._peer_point: bytes = b""

        self._pending: dict[int, tuple[int, bytearray, bytearray]] = {}
        self._ready: dict[int, tuple[int, bytes]] = {}
        self._next_recv_msg_seq = 0

        self._flight: list[bytes] = []
        self._rto = 1.0
        self._flight_deadline: float | None = None
        self._peer_closed = False
        self._failed: str | None = None

    # -- memory BIO ------------------------------------------------------

    def bio_write(self, datagram: bytes) -> int:
        """Hand one inbound UDP datagram to the engine.

        Returns 0 and drops the datagram when the queue is full, rather than
        letting an unanswered flood grow without limit.
        """
        if len(self._inbox) >= _MAX_INBOX:
            logger.debug("DTLS: inbound queue full, dropping datagram")
            return 0
        self._inbox.append(bytes(datagram))
        return len(datagram)

    def bio_read(self, capacity: int = 65535) -> bytes:
        """Drain pending outbound records. Raises WantRead when there are none."""
        if not self._outbox:
            raise WantRead()
        chunk = bytes(self._outbox[:capacity])
        del self._outbox[:capacity]
        return chunk

    # -- handshake -------------------------------------------------------

    def do_handshake(self) -> None:
        """Advance the handshake. Raises WantRead until it completes."""
        if self._failed:
            raise DtlsError(self._failed)
        if self._state == "established":
            return
        if self._state == "start":
            self._send_client_hello(cookie=b"")
            self._state = "sent_hello"
        self._drain_inbox()
        if self._failed:
            raise DtlsError(self._failed)
        if self._state != "established":
            raise WantRead()

    def _send_client_hello(self, cookie: bytes) -> None:
        if not cookie:
            self._client_random = os.urandom(32)
        body = bytearray(_VERSION)
        body += self._client_random
        body.append(0)  # session_id
        body.append(len(cookie))
        body += cookie
        body += struct.pack("!HH", 2, _SUITE)
        body += bytes([1, 0])  # null compression
        extensions = (
            struct.pack("!HHHH", 0x000A, 4, 2, _NAMED_CURVE_SECP256R1)
            + struct.pack("!HH", 0x000B, 2)
            + bytes([1, 0])
        )
        body += struct.pack("!H", len(extensions)) + extensions
        # Keep ClientHello when the server skips HelloVerifyRequest.
        # The cookie path resets the transcript before its replacement hello.
        self._start_flight()
        self._emit_handshake(_HT_CLIENT_HELLO, bytes(body), transcript=True)

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

    # -- record emission -------------------------------------------------

    def _start_flight(self) -> None:
        self._flight = []
        self._rto = 1.0

    def _emit_handshake(self, msg_type: int, body: bytes, *, transcript: bool) -> None:
        header = struct.pack(
            "!B3sH3s3s",
            msg_type,
            len(body).to_bytes(3, "big"),
            self._next_msg_seq,
            (0).to_bytes(3, "big"),
            len(body).to_bytes(3, "big"),
        )
        self._next_msg_seq += 1
        message = header + body
        if transcript:
            self._transcript += message
        self._emit_record(_CT_HANDSHAKE, message)

    def _emit_record(self, content_type: int, payload: bytes) -> None:
        if self._send_seq > _MAX_SEQ:
            self._fail("DTLS sequence number space exhausted")
            raise DtlsError(self._failed)
        epoch, seq = self._send_epoch, self._send_seq
        if self._transform is not None and epoch > 0:
            fragment = self._transform.protect(epoch, seq, content_type, payload)
        else:
            fragment = payload
        record = (
            bytes([content_type])
            + _VERSION
            + struct.pack("!H", epoch)
            + seq.to_bytes(6, "big")
            + struct.pack("!H", len(fragment))
            + fragment
        )
        self._send_seq += 1
        if len(self._outbox) + len(record) > _MAX_OUTBOX:
            self._fail("DTLS outbound buffer overflow")
            raise DtlsError(self._failed)
        self._outbox += record
        # Only handshake-epoch flights are retransmitted; application records
        # are the caller's to retry.
        if content_type in (_CT_HANDSHAKE, _CT_CHANGE_CIPHER_SPEC):
            self._flight.append(record)
            self._flight_deadline = _now() + self._rto

    # -- inbound ---------------------------------------------------------

    def _drain_inbox(self) -> None:
        while self._inbox:
            datagram = self._inbox.popleft()
            offset = 0
            while offset + _RECORD_HEADER <= len(datagram):
                length = int.from_bytes(
                    datagram[offset + 11:offset + _RECORD_HEADER], "big"
                )
                end = offset + _RECORD_HEADER + length
                if end > len(datagram):
                    break
                self._handle_record(datagram[offset:end])
                offset = end
                if self._failed:
                    return

    def _handle_record(self, record: bytes) -> None:
        content_type = record[0]
        epoch = int.from_bytes(record[3:5], "big")
        fragment = record[_RECORD_HEADER:]
        if record[1:3] != _VERSION:
            # DTLS 1.2 servers may frame HelloVerifyRequest as DTLS 1.0.
            # Accept that framing only for the initial plaintext cookie reply.
            if not (record[1:3] == b"\xfe\xff" and epoch == 0
                    and content_type == _CT_HANDSHAKE
                    and self._state == "sent_hello"
                    and fragment[:1] == bytes([_HT_HELLO_VERIFY_REQUEST])):
                return
        seq = int.from_bytes(record[5:11], "big")

        expected_epoch = 1 if self._read_active else 0
        if epoch != expected_epoch:
            # A retransmitted earlier-epoch record, or one we cannot read yet.
            return
        if epoch > 0:
            if self._transform is None:
                return
            window = self._recv_windows.setdefault(epoch, _ReplayWindow())
            if window.is_replay(seq):
                return
            payload = self._transform.unprotect(epoch, seq, content_type, fragment)
            if payload is None:
                logger.debug("DTLS: discarding record that failed authentication")
                return
            window.accept(seq)
        else:
            # Epoch 0 carries no MAC, so there is nothing a replay window
            # could safely be updated from. Handshake de-duplication is done
            # on message_seq instead, which the state machine guards.
            payload = fragment

        if content_type == _CT_HANDSHAKE:
            self._handle_handshake_fragment(payload, authenticated=epoch > 0)
        elif content_type == _CT_CHANGE_CIPHER_SPEC:
            if payload == b"\x01" and self._state == "sent_client_flight":
                self._read_active = True
                self._recv_windows.pop(1, None)
        elif content_type == _CT_ALERT:
            self._handle_alert(payload, authenticated=epoch > 0)
        elif content_type == _CT_APPLICATION_DATA:
            if epoch == 0:
                # Never authenticated. An off-path spoofer could otherwise
                # inject a forged appliance response before the handshake.
                logger.debug("DTLS: dropping unauthenticated epoch-0 app data")
                return
            if payload:
                if len(self._appdata) >= _MAX_APPDATA:
                    # Shed the stalest record: for request/response traffic
                    # the newest reply is the one still worth having.
                    self._appdata.popleft()
                    logger.debug("DTLS: application queue full, dropped oldest")
                self._appdata.append(payload)

    def _handle_alert(self, payload: bytes, *, authenticated: bool) -> None:
        """Act on one alert.

        close_notify is honoured only when the record authenticated: a
        spoofed plaintext one would otherwise make a live session look as
        though the appliance had hung up. Fatal alerts are honoured during
        the handshake even unauthenticated, because that is the only way to
        learn of a handshake_failure rather than waiting out the timeout.
        An off-path spoofer can end a handshake that way, which is the same
        capability they already have by flooding, and matches what OpenSSL
        and Mbed TLS do here.
        """
        if len(payload) < 2:
            return
        level, description = payload[0], payload[1]
        if description == _ALERT_CLOSE_NOTIFY:
            if authenticated:
                self._peer_closed = True
            return
        if level == _ALERT_FATAL:
            self._fail(f"peer sent fatal alert {description}")

    def _handle_handshake_fragment(
        self, payload: bytes, *, authenticated: bool = False
    ) -> None:
        if self._state == "established" and authenticated:
            # Renegotiation is disabled on the appliance
            # (ca_adapter_net_ssl.c:1728) and unsupported here.
            logger.debug("DTLS: ignoring handshake record on a live session")
            return
        offset = 0
        while offset + _HANDSHAKE_HEADER <= len(payload):
            msg_type = payload[offset]
            length = int.from_bytes(payload[offset + 1:offset + 4], "big")
            msg_seq = int.from_bytes(payload[offset + 4:offset + 6], "big")
            frag_off = int.from_bytes(payload[offset + 6:offset + 9], "big")
            frag_len = int.from_bytes(payload[offset + 9:offset + 12], "big")
            body_start = offset + _HANDSHAKE_HEADER
            if body_start + frag_len > len(payload) or frag_off + frag_len > length:
                return
            if length > _MAX_HANDSHAKE_MESSAGE:
                self._fail("handshake message too large")
                return
            body = payload[body_start:body_start + frag_len]
            offset = body_start + frag_len

            # HelloVerifyRequest is answered immediately and never reassembled.
            if msg_type == _HT_HELLO_VERIFY_REQUEST and frag_off == 0:
                self._handle_hello_verify_request(body)
                continue
            if msg_seq < self._next_recv_msg_seq:
                continue  # already consumed; a server retransmit
            complete = self._reassemble(msg_type, msg_seq, length, frag_off, body)
            if complete is not None:
                if len(self._ready) >= _MAX_PENDING_MESSAGES:
                    self._fail("too many out-of-order handshake messages")
                    return
                self._ready[msg_seq] = (msg_type, complete)
                self._deliver_ready()
            if self._failed:
                return

    def _deliver_ready(self) -> None:
        """Deliver complete messages strictly in message_seq order.

        A flight can arrive reordered, and delivering out of order would both
        corrupt the transcript and strand the skipped message.
        """
        while self._next_recv_msg_seq in self._ready:
            msg_seq = self._next_recv_msg_seq
            msg_type, body = self._ready.pop(msg_seq)
            self._deliver_handshake(msg_type, msg_seq, body)
            if self._failed:
                return

    def _reassemble(
        self, msg_type: int, msg_seq: int, length: int, frag_off: int, body: bytes
    ) -> bytes | None:
        if frag_off == 0 and len(body) == length:
            return body
        if len(self._pending) > _MAX_PENDING_MESSAGES:
            self._fail("too many incomplete handshake messages")
            return None
        entry = self._pending.get(msg_seq)
        if entry is None or entry[0] != length:
            entry = (length, bytearray(length), bytearray(length))
            self._pending[msg_seq] = entry
        _, buffer, seen = entry
        buffer[frag_off:frag_off + len(body)] = body
        seen[frag_off:frag_off + len(body)] = b"\x01" * len(body)
        if all(seen):
            del self._pending[msg_seq]
            return bytes(buffer)
        return None

    def _deliver_handshake(self, msg_type: int, msg_seq: int, body: bytes) -> None:
        self._next_recv_msg_seq = msg_seq + 1
        # Reconstructed as an unfragmented message, per RFC 6347 4.2.6.
        message = (
            bytes([msg_type])
            + len(body).to_bytes(3, "big")
            + struct.pack("!H", msg_seq)
            + (0).to_bytes(3, "big")
            + len(body).to_bytes(3, "big")
            + body
        )
        if msg_type == _HT_SERVER_HELLO:
            self._transcript += message
            self._handle_server_hello(body)
        elif msg_type == _HT_SERVER_KEY_EXCHANGE:
            self._transcript += message
            self._handle_server_key_exchange(body)
        elif msg_type == _HT_SERVER_HELLO_DONE:
            self._transcript += message
            if self._state == "got_server_params":
                self._state = "sent_client_flight"
                self._send_client_flight()
        elif msg_type == _HT_FINISHED:
            self._handle_server_finished(body)

    def _handle_hello_verify_request(self, body: bytes) -> None:
        if self._state != "sent_hello" or len(body) < 3:
            return
        cookie_len = body[2]
        if 3 + cookie_len > len(body):
            return
        self._cookie = body[3:3 + cookie_len]
        # RFC 6347 4.2.1 / ssl_srv.c:1409: the cookie ClientHello keeps
        # counting, so it carries message_seq 1 and the server mirrors it.
        self._transcript = bytearray()
        # The HelloVerifyRequest is the server's message_seq 0, so the
        # ServerHello that follows is 1 -- it mirrors our cookie ClientHello
        # (RFC 6347 4.2.1, ssl_srv.c:1409). Ordered delivery must expect 1.
        self._next_recv_msg_seq = 1
        self._ready.clear()
        self._send_client_hello(cookie=self._cookie)
        self._state = "sent_cookie_hello"

    def _handle_server_hello(self, body: bytes) -> None:
        if self._state not in ("sent_hello", "sent_cookie_hello"):
            return
        if len(body) < 35:
            self._fail("short ServerHello")
            return
        if body[0:2] != _VERSION:
            self._fail("server selected a version other than DTLS 1.2")
            return
        self._server_random = body[2:34]
        offset = 34
        session_len = body[offset]
        offset += 1 + session_len
        if offset + 3 > len(body):
            self._fail("malformed ServerHello")
            return
        suite = int.from_bytes(body[offset:offset + 2], "big")
        if suite != _SUITE:
            self._fail(f"server selected unexpected ciphersuite 0x{suite:04x}")
            return
        if body[offset + 2] != 0:
            self._fail("server selected a compression method")
            return
        self._state = "got_server_hello"

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

    def _handle_server_finished(self, body: bytes) -> None:
        if not self._read_active or self._state != "sent_client_flight":
            return
        expected = _prf(
            self._master_secret,
            b"server finished",
            hashlib.sha256(self._transcript).digest(),
            _VERIFY_DATA_LEN,
        )
        if len(body) != _VERIFY_DATA_LEN or not hmac.compare_digest(body, expected):
            self._fail("server Finished did not verify")
            return
        self._state = "established"
        self._flight = []
        self._flight_deadline = None

    def _fail(self, reason: str) -> None:
        if self._failed is None:
            self._failed = reason
            logger.debug("DTLS session failed: %s", reason)

    # -- application data ------------------------------------------------

    def send(self, data: bytes) -> int:
        """Encrypt and queue one application record."""
        if self._state != "established":
            raise DtlsError("session is not established")
        if self._failed:
            raise DtlsError(self._failed)
        self._emit_record(_CT_APPLICATION_DATA, bytes(data))
        return len(data)

    def recv(self, capacity: int = 65535) -> bytes:
        """Return one decrypted application record."""
        if not self._appdata:
            self._drain_inbox()
        if self._failed:
            raise DtlsError(self._failed)
        if self._appdata:
            record = self._appdata.popleft()
            if len(record) > capacity:
                # Never drop the tail: hand back the rest on the next call.
                self._appdata.appendleft(record[capacity:])
                return record[:capacity]
            return record
        if self._peer_closed:
            raise ZeroReturn()
        raise WantRead()

    def shutdown(self) -> None:
        """Queue a close_notify."""
        if self._state == "established" and not self._failed:
            self._emit_record(_CT_ALERT, bytes([_ALERT_WARNING, _ALERT_CLOSE_NOTIFY]))

    # -- retransmission --------------------------------------------------

    def DTLSv1_get_timeout(self):  # noqa: N802 - mirrors the pyOpenSSL name
        """Seconds until the current flight should be retransmitted."""
        if self._flight_deadline is None or not self._flight:
            return None
        return max(0.0, self._flight_deadline - _now())

    def DTLSv1_handle_timeout(self):  # noqa: N802 - mirrors the pyOpenSSL name
        """Requeue the last flight and back off, per RFC 6347 section 4.2.4."""
        if not self._flight or self._flight_deadline is None:
            return None
        for record in self._flight:
            self._outbox += record
        self._rto = min(self._rto * 2, 60.0)
        self._flight_deadline = _now() + self._rto
        return None


def _now() -> float:
    import time

    return time.monotonic()
