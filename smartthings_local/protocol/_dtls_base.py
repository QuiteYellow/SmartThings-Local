"""Shared DTLS 1.2 client machinery for this package's own engines.

The record layer, the handshake reassembler, the cookie exchange and the
retransmission timer are identical whatever credential a session carries, and
every defect fixed in them has been fixed once. This module holds that half so
there is one copy of it:

- `_dtls_psk.DtlsPskClient`, TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, shipped in
  v0.1.23 and validated against a Samsung oven.
- `_dtls_cert.DtlsCertClient`, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, which
  exists because the appliances on #20 drop off the network unless the client
  offers `max_fragment_length`, and no Python binding of OpenSSL exposes that
  setter.

A subclass supplies the parts that differ: the offered ciphersuites and
extensions, the record transform, the key-block length, the client flight, and
any handshake message the shared state machine does not itself handle.

Every wire decision here was read from the appliance firmware's own
Mbed TLS 2.7.8 sources rather than from a specification. Line references are to
that upstream tree (TizenRT's `iotivity_1.2-rel` fork), not to this repository.

Interface mirrors the memory-BIO subset of `OpenSSL.SSL.Connection` that
`_drive_dtls_handshake` and `DtlsCoapSession` already drive, so the unmodified
driver completes a handshake against either engine. `WantRead`, `ZeroReturn`
and `DtlsError` are aliased to pyOpenSSL's exceptions for that reason.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
from collections import deque

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
_HT_CERTIFICATE = 11
_HT_SERVER_KEY_EXCHANGE = 12
_HT_CERTIFICATE_REQUEST = 13
_HT_SERVER_HELLO_DONE = 14
_HT_CERTIFICATE_VERIFY = 15
_HT_CLIENT_KEY_EXCHANGE = 16
_HT_FINISHED = 20

_VERSION = b"\xfe\xfd"
_NAMED_CURVE_SECP256R1 = 0x0017
_ECCURVETYPE_NAMED = 3

_RECORD_HEADER = 13
_HANDSHAKE_HEADER = 12
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

# A server may legitimately re-issue a cookie; one that only ever does so is
# either broken or stalling, and must not hold the handshake open.
_MAX_HELLO_VERIFY = 5

_ALERT_CLOSE_NOTIFY = 0
_ALERT_FATAL = 2
_ALERT_HANDSHAKE_FAILURE = 40
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
    """RFC 6347 anti-replay (section 4.1.2) sliding window, one per read epoch."""

    __slots__ = ("_bitmap", "_highest")

    def __init__(self) -> None:
        self._bitmap = 0
        self._highest = -1

    def is_replay(self, seq: int) -> bool:
        """Report whether ``seq`` is a replay, without committing to it.

        Separated from :meth:`accept` because a record that fails
        authentication must leave the window untouched. Advancing on an
        unauthenticated record lets one spoofed datagram carrying a high
        sequence number wedge the session permanently (RFC 6347 anti-replay (section 4.1.2)
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


class _DtlsClientBase:
    """One DTLS 1.2 session, driven through a memory BIO.

    Subclasses own the credential and the ciphersuite. This class owns the
    record layer, the handshake transcript, flight retransmission and the
    inbound state machine, and calls into the subclass through the hooks
    marked below.
    """

    def __init__(self, mtu: int = 1400) -> None:
        if type(mtu) is not int or not 256 <= mtu <= 65535:
            raise ValueError("mtu must be between 256 and 65535")
        # Accepted for interface compatibility with OpenSSL's connection.
        # The PSK engine never fragments, because a PSK flight is a few
        # hundred bytes. The certificate engine does, and reads this value.
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
        self._transform = None
        self._suite: int | None = None
        self._read_active = False

        self._client_random = b""
        self._server_random = b""
        self._cookie = b""
        self._master_secret = b""
        self._private_key = None
        self._peer_point: bytes = b""

        self._pending: dict[int, tuple[int, bytearray, bytearray]] = {}
        self._ready: dict[int, tuple[int, bytes]] = {}
        self._next_recv_msg_seq = 0

        self._flight: list[bytes] = []
        self._rto = 1.0
        self._flight_deadline: float | None = None
        self._peer_closed = False
        self._hello_verify_count = 0
        self._failed: str | None = None
        self._abandon_alert = b""

    # -- subclass hooks --------------------------------------------------

    def _offered_suites(self) -> tuple[int, ...]:
        """Ciphersuites for the ClientHello, in offer order."""
        raise NotImplementedError

    def _hello_extensions(self) -> bytes:
        """Encoded extensions block for the ClientHello, without its length."""
        raise NotImplementedError

    def _make_transform(self, key_block: bytes):
        """Build the record transform for the negotiated suite."""
        raise NotImplementedError

    def _key_block_len(self) -> int:
        """Bytes of key material the negotiated suite needs."""
        raise NotImplementedError

    def _send_client_flight(self) -> None:
        """Emit the client's half of the handshake, through ChangeCipherSpec."""
        raise NotImplementedError

    def _on_server_hello(self, body: bytes, offset: int) -> None:
        """Read whatever follows the selected suite and compression method.

        `offset` points just past the compression method. The default reads
        nothing, which is what a suite with no negotiated extension needs.
        """

    def _handle_other_handshake(
        self, msg_type: int, message: bytes, body: bytes
    ) -> None:
        """Handle a message the shared state machine does not know.

        `message` is the reassembled message with its handshake header, which
        is the form the transcript takes; `body` is the payload alone. The
        subclass appends to the transcript itself, because only it knows
        whether a given message belongs in the hash.
        """


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
        suites = self._offered_suites()
        body += struct.pack("!H", 2 * len(suites))
        for suite in suites:
            body += struct.pack("!H", suite)
        body += bytes([1, 0])  # null compression
        extensions = self._hello_extensions()
        body += struct.pack("!H", len(extensions)) + extensions
        # Keep ClientHello when the server skips HelloVerifyRequest.
        # The cookie path resets the transcript before its replacement hello.
        self._start_flight()
        self._emit_handshake(_HT_CLIENT_HELLO, bytes(body), transcript=True)


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
        hello_verify_only = False
        if record[1:3] != _VERSION:
            # OpenSSL frames its HelloVerifyRequest as DTLS 1.0 under cookie
            # exchange; the interop tests pin that. The appliance does not:
            # its header was recorded as 16 fe fd 00 .. 2f, and Mbed TLS
            # derives that version from the negotiated one, so other
            # generations are unmeasured rather than known to match.
            #
            # Hence the exception, kept narrow. In either hello state a peer
            # can already send a 1.2-framed HelloVerifyRequest, so accepting
            # the same message in a second framing grants nothing further --
            # and both states have to be here, because a server that frames
            # its first challenge this way frames its second one the same,
            # and dropping that one leaves us retransmitting to the deadline:
            # exactly the OpenSSL behaviour _handle_hello_verify_request
            # exists to avoid.
            if not (record[1:3] == b"\xfe\xff" and epoch == 0
                    and content_type == _CT_HANDSHAKE
                    and self._state in ("sent_hello", "sent_cookie_hello")
                    and fragment[:1] == bytes([_HT_HELLO_VERIFY_REQUEST])):
                return
            # The check above reads the first message in the record, while
            # _handle_handshake_fragment walks every message in it, so the
            # exemption has to travel with the record or anything packed
            # behind the HelloVerifyRequest inherits it.
            hello_verify_only = True
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
            self._handle_handshake_fragment(
                payload,
                authenticated=epoch > 0,
                hello_verify_only=hello_verify_only,
            )
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
        self,
        payload: bytes,
        *,
        authenticated: bool = False,
        hello_verify_only: bool = False,
    ) -> None:
        if self._state == "established" and authenticated:
            # Renegotiation is disabled on the appliance
            # (ca_adapter_net_ssl.c:1728) and unsupported here.
            logger.debug("DTLS: ignoring handshake record on a live session")
            return
        offset = 0
        while offset + _HANDSHAKE_HEADER <= len(payload):
            msg_type = payload[offset]
            if hello_verify_only and msg_type != _HT_HELLO_VERIFY_REQUEST:
                # A DTLS 1.0-framed record is admitted for one message only.
                # Abandon the rest of it rather than reading a ServerHello
                # out of a framing the state machine never accepted.
                return
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
                self._handle_hello_verify_request(body, msg_seq)
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
        entry = self._pending.get(msg_seq)
        if entry is None or entry[0] != length:
            # Only a fragment that opens a new msg_seq can grow the table, so
            # only that one is capped. Guarding the whole function instead let
            # the table reach _MAX_PENDING_MESSAGES + 1 under `>`, and would
            # have failed a fragment of a message already being reassembled
            # under `>=`. A length change on an existing msg_seq replaces its
            # entry rather than adding one.
            if entry is None and len(self._pending) >= _MAX_PENDING_MESSAGES:
                self._fail("too many incomplete handshake messages")
                return None
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
        elif msg_type == _HT_SERVER_HELLO_DONE:
            self._transcript += message
            if self._state == "got_server_params":
                self._state = "sent_client_flight"
                self._send_client_flight()
        elif msg_type == _HT_FINISHED:
            self._handle_server_finished(body)
        else:
            # ServerKeyExchange, Certificate and CertificateRequest differ by
            # credential, so the subclass owns both the parse and whether the
            # message enters the transcript.
            self._handle_other_handshake(msg_type, message, body)

    def _handle_hello_verify_request(self, body: bytes, msg_seq: int) -> None:
        """Answer a HelloVerifyRequest, including a repeated one.

        A server may re-issue a cookie in reply to a ClientHello that already
        carries one. Answering only the first is what OpenSSL does, and it
        leaves both sides retransmitting until the handshake deadline with no
        alert -- the shape this project reported on localthings#504 as the
        leading explanation for issue #20's silent 12 s timeouts. There is no
        reason to inherit that here, so each one is answered, bounded by
        _MAX_HELLO_VERIFY so a server that only ever sends cookies cannot
        hold the handshake open indefinitely.
        """
        if self._state not in ("sent_hello", "sent_cookie_hello"):
            return
        if len(body) < 3:
            return
        cookie_len = body[2]
        if 3 + cookie_len > len(body):
            return
        cookie = body[3:3 + cookie_len]
        if self._state == "sent_cookie_hello":
            self._hello_verify_count += 1
            if self._hello_verify_count > _MAX_HELLO_VERIFY:
                self._fail("server kept re-issuing HelloVerifyRequest")
                return
            if cookie == self._cookie:
                # An identical cookie does not say why it arrived. Our answer
                # may have been lost, or the server may have re-challenged
                # inside the same clock second: Mbed TLS derives the cookie
                # deterministically from a 4-byte timestamp and the client id
                # under a key it generates once (ssl_cookie.c ssl_cookie_hmac),
                # so a repeat within that second is byte-identical rather than
                # rotated. Either way the flight timer owns the retransmission,
                # so do not start a new hello and renumber the handshake
                # underneath it.
                return
        self._cookie = cookie
        # RFC 6347 4.2.1: the transcript starts at the ClientHello that
        # carries the accepted cookie, so everything before it is discarded.
        self._transcript = bytearray()
        # The server mirrors our message_seq (ssl_srv.c:1409), so the next
        # message it sends follows the HelloVerifyRequest we just read.
        # Hardcoding 1 here breaks as soon as a second cookie arrives.
        self._next_recv_msg_seq = msg_seq + 1
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
        if suite not in self._offered_suites():
            self._fail(f"server selected unexpected ciphersuite 0x{suite:04x}")
            return
        self._suite = suite
        if body[offset + 2] != 0:
            self._fail("server selected a compression method")
            return
        self._on_server_hello(body, offset + 3)
        if self._failed:
            return
        self._state = "got_server_hello"


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

    def _abandon(self, reason: str) -> None:
        """Fail a handshake that we stop, and keep the alert that ends it.

        A failure that only sets `_failed` sends nothing, so the peer keeps
        its handshake state for this client. An epoch-zero fatal
        `handshake_failure` ends that state on TizenRT's `iotivity_1.2-rel`
        fork: mbedTLS 2.7.8 returns `MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE` for
        it (`ssl_tls.c:4310-4312`), and the fork's `SSL_CHECK_FAIL` calls
        `RemovePeerFromList` for that code (`ca_adapter_net_ssl.c:215-249`,
        used at `:2234`). This is read in code, not measured on an appliance.

        The alert is kept apart from the outbox, because the handshake driver
        stops reading the outbox when `do_handshake` raises. The driver
        collects it with `_take_abandon_alert`.
        """
        if self._failed is None and self._send_epoch == 0:
            start = len(self._outbox)
            try:
                self._emit_record(
                    _CT_ALERT, bytes([_ALERT_FATAL, _ALERT_HANDSHAKE_FAILURE])
                )
            except DtlsError:
                pass
            else:
                self._abandon_alert = bytes(self._outbox[start:])
                del self._outbox[start:]
        self._fail(reason)

    def _take_abandon_alert(self) -> bytes:
        """Return the alert that `_abandon` kept, once, or b"" if none."""
        alert, self._abandon_alert = self._abandon_alert, b""
        return alert

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
        """Return one decrypted application record.

        Buffered data is handed back before any failure or close is
        reported. One call drains every queued datagram, so a reply and the
        teardown that follows it can both be processed before the caller
        sees either, and a reply that already authenticated is not the
        caller's to lose. Both reference stacks get this for free by
        processing one record per read: mbedtls_ssl_read returns after a
        single mbedtls_ssl_read_record (ssl_tls.c:7261-7292), as does
        OpenSSL, so neither can retract data it has already returned.

        The failure is still raised, on the call after the buffer empties.
        """
        if not self._appdata:
            self._drain_inbox()
        if self._appdata:
            record = self._appdata.popleft()
            if len(record) > capacity:
                # Never drop the tail: hand back the rest on the next call.
                self._appdata.appendleft(record[capacity:])
                return record[:capacity]
            return record
        if self._failed:
            raise DtlsError(self._failed)
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
