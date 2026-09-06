"""Shared memory-BIO driver for bounded DTLS handshakes."""

from __future__ import annotations

import select
import time
from collections.abc import Callable

from OpenSSL import SSL

from .coap import split_dtls

_HANDSHAKE_POLL_S = 0.5
_MAX_DATAGRAM_SIZE = 65535
_DTLS_RECORD_HEADER_BYTES = 13
_DTLS_CONTENT_TYPE_ALERT = 21
_DTLS_CONTENT_TYPE_HANDSHAKE = 22
_DTLS_HANDSHAKE_CLIENT_HELLO = 1
_DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST = 3
_DTLS_ALERT_LEVEL_FATAL = 2
_DTLS_ALERT_HANDSHAKE_FAILURE = 40
_DTLS_EPOCH_ZERO = b'\x00\x00'
_DTLS_VERSIONS = frozenset((b'\xfe\xff', b'\xfe\xfd'))
_MAX_CLEANUP_TRANSCRIPT_RECORDS = 32


def _complete_epoch_zero_handshake_types(record):
    """Return complete handshake message types from one strict DTLS record."""
    if (
        len(record) < _DTLS_RECORD_HEADER_BYTES
        or record[0] != _DTLS_CONTENT_TYPE_HANDSHAKE
        or record[1:3] not in _DTLS_VERSIONS
        or record[3:5] != _DTLS_EPOCH_ZERO
        or int.from_bytes(record[11:13], 'big')
        != len(record) - _DTLS_RECORD_HEADER_BYTES
    ):
        return None

    payload = record[_DTLS_RECORD_HEADER_BYTES:]
    offset = 0
    message_types = []
    while offset < len(payload):
        if len(payload) - offset < 12:
            return None
        message_length = int.from_bytes(payload[offset + 1:offset + 4], 'big')
        fragment_offset = int.from_bytes(payload[offset + 6:offset + 9], 'big')
        fragment_length = int.from_bytes(payload[offset + 9:offset + 12], 'big')
        end = offset + 12 + fragment_length
        if (
            fragment_offset != 0
            or fragment_length != message_length
            or end > len(payload)
        ):
            return None
        message_types.append(payload[offset])
        offset = end
    return tuple(message_types) if message_types else None


def _strict_dtls_records(datagram):
    """Split one complete DTLS datagram or reject all of it."""
    offset = 0
    records = []
    while offset < len(datagram):
        if len(datagram) - offset < _DTLS_RECORD_HEADER_BYTES:
            return None
        payload_length = int.from_bytes(datagram[offset + 11:offset + 13], 'big')
        end = offset + _DTLS_RECORD_HEADER_BYTES + payload_length
        if end > len(datagram):
            return None
        records.append(datagram[offset:end])
        if len(records) > _MAX_CLEANUP_TRANSCRIPT_RECORDS:
            return None
        offset = end
    return tuple(records) if records else None


class _HvrPeerCleanupTranscript:
    """Retain only bounded metadata needed for the HVR cleanup decision."""

    __slots__ = (
        '_invalid',
        '_last_client_hello_header',
        '_received_datagrams',
        '_received_records',
        '_sent_client_hello_after_hvr',
        '_sent_client_hellos',
    )

    def __init__(self):
        self._invalid = False
        self._last_client_hello_header = None
        self._received_datagrams = 0
        self._received_records = 0
        self._sent_client_hello_after_hvr = False
        self._sent_client_hellos = 0

    def record_sent(self, record):
        """Record one complete epoch-zero ClientHello without its payload."""
        message_types = _complete_epoch_zero_handshake_types(record)
        if message_types != (_DTLS_HANDSHAKE_CLIENT_HELLO,):
            self._invalid = True
            return
        self._sent_client_hellos += 1
        if self._sent_client_hellos > _MAX_CLEANUP_TRANSCRIPT_RECORDS:
            self._invalid = True
            return
        if self._received_records:
            self._sent_client_hello_after_hvr = True
        header = record[:_DTLS_RECORD_HEADER_BYTES]
        previous = self._last_client_hello_header
        if previous is None or header[5:11] >= previous[5:11]:
            self._last_client_hello_header = header

    def record_received(self, datagram):
        """Record only whether a bounded datagram contains complete HVRs."""
        self._received_datagrams += 1
        if self._received_datagrams > _MAX_CLEANUP_TRANSCRIPT_RECORDS:
            self._invalid = True
            return
        records = _strict_dtls_records(datagram)
        if records is None:
            self._invalid = True
            return
        if (
            self._received_records + len(records)
            > _MAX_CLEANUP_TRANSCRIPT_RECORDS
        ):
            self._invalid = True
            return
        for record in records:
            message_types = _complete_epoch_zero_handshake_types(record)
            if (
                message_types is None
                or any(
                    message_type != _DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST
                    for message_type in message_types
                )
            ):
                self._invalid = True
                return
            self._received_records += 1

    def cleanup_alert(self):
        """Build one epoch-zero alert only for an exact HVR-only transcript."""
        header = self._last_client_hello_header
        if (
            self._invalid
            or self._sent_client_hellos < 2
            or not self._sent_client_hello_after_hvr
            or self._received_datagrams < 1
            or self._received_records < 1
            or header is None
        ):
            return None
        sequence = int.from_bytes(header[5:11], 'big')
        if sequence >= (1 << 48) - 1:
            return None
        return (
            bytes((_DTLS_CONTENT_TYPE_ALERT,))
            + header[1:3]
            + _DTLS_EPOCH_ZERO
            + (sequence + 1).to_bytes(6, 'big')
            + b'\x00\x02'
            + bytes(
                (
                    _DTLS_ALERT_LEVEL_FATAL,
                    _DTLS_ALERT_HANDSHAKE_FAILURE,
                )
            )
        )


class _HandshakeCancelled(Exception):
    """Internal signal that a handshake wake socket became readable."""


def _drive_dtls_handshake(
    connection,
    sock,
    *,
    deadline: float,
    retries: int | None = None,
    on_datagram: Callable[[bytes], None] | None = None,
    on_record_sent: Callable[[bytes], None] | None = None,
    wake_socket=None,
) -> bool:
    """Drive one memory-BIO DTLS handshake up to a monotonic deadline.

    OpenSSL owns the retransmission schedule. ``retries`` optionally limits
    how many expired retransmission timers are serviced; a normal session is
    bounded only by its deadline, while the diagnostic probe retains its
    explicit retry budget.

    Return ``True`` once OpenSSL reports the handshake complete. The deadline
    prevents another setup, retry, or network-wait iteration; it does not tear
    down a session that completed while ``do_handshake()`` was running. TLS and
    socket failures are left to the caller to classify.
    """
    retransmits = 0
    while time.monotonic() < deadline:
        try:
            connection.do_handshake()
            return True
        except SSL.WantReadError:
            pass

        try:
            output = connection.bio_read(_MAX_DATAGRAM_SIZE)
        except SSL.WantReadError:
            output = None
        if output:
            for record in split_dtls(output):
                if sock.send(record) != len(record):
                    raise OSError("incomplete UDP send")
                if on_record_sent is not None:
                    on_record_sent(record)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        wait = min(_HANDSHAKE_POLL_S, remaining)
        timed_out = False
        if wake_socket is None:
            sock.settimeout(wait)
            try:
                datagram = sock.recv(_MAX_DATAGRAM_SIZE)
            except TimeoutError:
                timed_out = True
        else:
            readable, _, _ = select.select(
                (sock, wake_socket),
                (),
                (),
                wait,
            )
            if wake_socket in readable:
                raise _HandshakeCancelled()
            if sock not in readable:
                timed_out = True
            else:
                datagram = sock.recv(_MAX_DATAGRAM_SIZE)

        if timed_out:
            timer = connection.DTLSv1_get_timeout()
            if timer is not None and timer <= 0:
                if retries is not None and retransmits >= retries:
                    break
                connection.DTLSv1_handle_timeout()
                retransmits += 1
            continue

        if not datagram:
            continue
        if on_datagram is not None:
            on_datagram(datagram)
        connection.bio_write(datagram)

    return False
