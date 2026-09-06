"""CoAP-over-DTLS client for Samsung RT-OCF appliances (RFC 7252 + 6347).

Replaces the TLS-over-TCP transport used in the original dryer bridge.
Both the oven (UDP/49154) and the dryer (UDP/49155) speak CoAP-over-DTLS
with the ECDHE-ECDSA-AES128-GCM-SHA256 cipher and a client cert.

Wire-level details that matter (from local-tools/oven-findings.md §17):
  * DTLS ciphertext MTU must be 1200; otherwise OpenSSL fragments the
    client cert across two datagrams and TizenRT drops the second.
  * Samsung's RT-OCF uses ACK+separate-CON for the larger responses.
    The reader MUST correlate by (token, mid) — not arrival order —
    or interleaved one-shot / OBSERVE traffic mis-attributes.
  * Multi-block GET requires the SAME CoAP token across every block
    of the response ("token-stable Block2"). Fresh-token-per-block
    is silently dropped by the server, and a transfer that opens at
    NUM>0 under a token the server has not seen gets no reply at all.

Reader thread owns the UDP socket. Callers issue get()/post() and block
on a per-token Event the reader signals. OBSERVE notifications are
delivered via the on_notification callback.

A notification carries only the first block of a large representation
(RFC 7959 §2.6). Because a continuation cannot borrow the observation's
token (§3.4) and this server will not continue a transfer it did not
start, such a notification is withheld and the resource is re-read from
block 0 on a fresh one-shot token by a worker thread. See #39.
"""
import errno
import logging
import math
import os
import socket
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from OpenSSL import SSL

from ..errors import (
    AuthenticationError,
    BlockwiseError,
    EndpointError,
    HandshakePeerCleanupError,
    MalformedMessageError,
    SessionClosedError,
    SessionError,
    SessionIdentifierError,
    SessionResetError,
    SessionTimeoutError,
)
from . import auth as _auth
from . import coap as _coap
from .auth import (
    AuthenticationProvider,
    CertificateAuth,
    SamsungServerProfile,
    ServerCertificateAuth,
)
from .coap import (
    ACCEPT,
    BLOCK1,
    BLOCK2,
    BLOCK2_COMPLETE,
    BLOCK_SZX,
    CF_CBOR,
    CONTENT_FORMAT,
    ETAG,
    METHOD_DELETE,
    METHOD_GET,
    METHOD_POST,
    OBSERVE,
    OBSERVE_DEREGISTER,
    OBSERVE_REGISTER,
    RESPONSE_EMPTY_ACK,
    RESPONSE_MESSAGE,
    RESPONSE_RESET,
    SIZE1,
    SIZE2,
    TYPE_CON,
    URI_PATH,
    URI_QUERY,
    Block2Accumulator,
    block_fields,
    block_value,
    build_coap,
    build_get_request,
    classify_coap_response,
    fmt_code,
)
from .dtls_handshake import (
    _HANDSHAKE_POLL_S,
    _HvrPeerCleanupTranscript,
    _drive_dtls_handshake,
    _HandshakeCancelled,
)
from .endpoint import open_host_filtered_udp_socket

# Private compatibility exports used by dtls_probe and existing callers.
_DTLS_CIPHERS = _auth._DTLS_CIPHERS
_OCF_ROOT_CA = _auth._OCF_ROOT_CA
_load_pem_chain = _auth._load_pem_chain
_split_dtls = _coap.split_dtls

logger = logging.getLogger(__name__)

# Diagnostic logging — when DEBUG_BRIDGE=1 in env, the bridge dumps
# every received CoAP frame, every /operational/state/vs/0 + /oven/vs/0
# + /power/vs/0 + /mode/vs/0-options rep change, the full link tree at
# seed time, and the /oic/res directory. Useful for reverse-engineering
# new resources and field semantics; otherwise quiet.
DEBUG_BRIDGE = os.environ.get('DEBUG_BRIDGE') == '1'

# Per-block retransmission: send up to this many times before giving up.
# Each attempt waits at most _BLOCK_ACK_TIMEOUT seconds (capped by the
# overall deadline). Matches RFC 7252 CON retransmit behaviour.
_BLOCK_MAX_ATTEMPTS = 3
_BLOCK_ACK_TIMEOUT  = 4.0
_MAX_BLOCK1_BODY_BYTES = 512 * 1024
_MAX_BLOCK1_REQUESTS = 1024

# Base per-attempt wait for a write retransmission, doubled per attempt
# (RFC 7252 §4.2). Retransmission itself is off by default: a device that
# is already dropping under load turns one lost write into several, and
# MID dedupe (§4.5) is unverified on RT-OCF, which does not reliably emit
# RST either. Enable per session via write_max_attempts once pacing has
# been shown insufficient on real hardware (LocalThings#384).
_WRITE_ACK_TIMEOUT = 2.0

# How often a request wait re-checks that the reader is still alive. Short
# enough that a mid-exchange reader death fails fast instead of burning
# the whole per-attempt timeout, long enough to stay off the CPU.
_BLOCK_LIVENESS_POLL_S = 0.25

# Inter-request pacing: minimum seconds between CoAP CON sends on one session.
# Samsung's RT-OCF stacks drop requests when hit faster than their firmware
# ceiling (dryer ~14 req/s, oven ~8 req/s, dishwasher unknown). 5 req/s
# (200 ms) is conservative enough for all tested devices; tune per device
# once the ceiling is measured empirically.
_DEFAULT_RATE_LIMIT_RPS = 5.0

# Maximum relations held for OBSERVE refetch at once. A notification storm
# on more resources than this is already past what the 5/s ceiling can
# drain, so the excess is dropped rather than queued indefinitely.
_MAX_PENDING_REFETCH = 16

# Timeout for one notification refetch. Generous relative to a poll:
# the resource is known large (that is why it blocked) and the worker
# is serialized, so a slow one delays only later refetches.
_REFETCH_TIMEOUT_S = 15.0

# RFC 7641 section 3.4 compares the 24-bit Observe value as serial-number
# arithmetic. After 128 seconds without an accepted notification, receipt time
# is allowed to re-establish ordering after a server restart.
_OBSERVE_SEQUENCE_MODULUS = 1 << 24
_OBSERVE_SEQUENCE_HALF_RANGE = 1 << 23
_OBSERVE_SEQUENCE_RESET_S = 128.0
_MAX_OBSERVE_RELATIONS = 0xFF


class _EtagChanged(Exception):
    """Internal: the server's ETag changed partway through a Block2
    transfer, so the blocks in hand are from two different versions."""


@dataclass(slots=True)
class _MidExchange:
    """One pending request, indexed independently by token and MID."""

    pending: tuple[threading.Event, dict]
    acknowledged: bool = False


# ICMP errors a connected UDP socket surfaces on the next recv. On these
# appliances they show up while the device is rebooting, while it holds an
# orphaned association, or across a router blip, and the next datagram
# usually works. UDP delivery was never guaranteed, so treat them as
# advisory and keep reading. Unconnected sockets never see any of this,
# which is why the reader survived them before the connected-socket change
# in d677c72 (v0.1.3). The session moved back to an unconnected socket for
# issue #66, so this set is now defensive: it costs nothing and still covers
# any caller that supplies a connected socket adapter of its own.
_ADVISORY_ERRNOS = frozenset(
    value for value in (
        getattr(errno, name, None)
        for name in ('ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH',
                     'EHOSTDOWN', 'ENETDOWN')
    ) if value is not None
)

def _validate_handshake_timeout(timeout, default):
    """Return one finite, positive DTLS handshake timeout."""
    value = default if timeout is None else timeout
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError('timeout must be a number or None')
    try:
        value = float(value)
    except OverflowError:
        raise ValueError(
            'timeout must be a positive finite number or None') from None
    if not math.isfinite(value) or value <= 0:
        raise ValueError('timeout must be a positive finite number or None')
    return value


_MAX_REQUEST_OPTION_BYTES = 1024
_MAX_REQUEST_OPTION_COUNT = 32
_MAX_REQUEST_OPTION_NUMBER = 65535
_MANAGED_REQUEST_OPTIONS = frozenset((
    URI_PATH, URI_QUERY, OBSERVE, CONTENT_FORMAT, ACCEPT,
    BLOCK2, BLOCK1, SIZE2, SIZE1,
))


def _validated_text_options(values, *, name, allow_empty):
    """Return bounded UTF-8 option values without echoing caller data."""
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise TypeError(f'{name} must be an iterable of strings')
    try:
        iterator = iter(values)
    except TypeError:
        raise TypeError(f'{name} must be an iterable of strings') from None
    result = []
    for value in iterator:
        if len(result) >= _MAX_REQUEST_OPTION_COUNT:
            raise ValueError(f'{name} must contain at most 32 values')
        if not isinstance(value, str):
            raise TypeError(f'{name} values must be strings')
        try:
            encoded = value.encode('utf-8')
        except UnicodeEncodeError:
            raise ValueError(f'{name} values must be valid UTF-8') from None
        if (not allow_empty and not encoded) or \
                len(encoded) > _MAX_REQUEST_OPTION_BYTES:
            raise ValueError(f'{name} values must be non-empty and bounded')
        result.append(value)
    return tuple(result)


def _validated_observe_paths(paths):
    """Return unique bounded Observe paths and their canonical hrefs."""
    if isinstance(paths, (str, bytes, bytearray, memoryview)):
        raise TypeError('paths must be an iterable of path iterables')
    try:
        iterator = iter(paths)
    except TypeError:
        raise TypeError(
            'paths must be an iterable of path iterables') from None
    result = []
    seen_hrefs = set()
    for index, path in enumerate(iterator):
        if index >= _MAX_OBSERVE_RELATIONS:
            raise ValueError('paths must contain at most 255 paths')
        normalized = _validated_text_options(
            path, name='path', allow_empty=False)
        href = '/' + '/'.join(normalized)
        if href in seen_hrefs:
            continue
        seen_hrefs.add(href)
        result.append((normalized, href))
    return tuple(result)


def _validated_observe_query_overrides(queries_by_href, target_hrefs):
    """Validate explicit path-to-query overrides before relation mutation."""
    if queries_by_href is None:
        return {}
    if not isinstance(queries_by_href, Mapping):
        raise TypeError('queries_by_href must be a mapping or None')
    if len(queries_by_href) > len(target_hrefs):
        raise ValueError('queries_by_href contains a non-target href')
    result = {}
    for href, query in queries_by_href.items():
        if not isinstance(href, str):
            raise TypeError('queries_by_href keys must be href strings')
        if href not in target_hrefs:
            raise ValueError('queries_by_href contains a non-target href')
        result[href] = _validated_text_options(
            query, name='query', allow_empty=False)
    return result


def _validated_extra_options(extra_options):
    """Return bounded, ordered options not owned by the request methods."""
    if isinstance(extra_options, (str, bytes, bytearray, memoryview)):
        raise TypeError('extra_options must contain (number, bytes) tuples')
    try:
        iterator = iter(extra_options)
    except TypeError:
        raise TypeError(
            'extra_options must contain (number, bytes) tuples') from None
    result = []
    previous = -1
    for item in iterator:
        if len(result) >= _MAX_REQUEST_OPTION_COUNT:
            raise ValueError('extra_options must contain at most 32 values')
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError(
                'extra_options must contain (number, bytes) tuples')
        number, value = item
        if isinstance(number, bool) or not isinstance(number, int):
            raise TypeError('extra option numbers must be integers')
        if not 1 <= number <= _MAX_REQUEST_OPTION_NUMBER:
            raise ValueError('extra option numbers must be bounded')
        if number < previous:
            raise ValueError('extra options must be ordered by number')
        if number in _MANAGED_REQUEST_OPTIONS:
            raise ValueError('extra option is managed by the CoAP transport')
        if not isinstance(value, bytes):
            raise TypeError('extra option values must be bytes')
        if len(value) > _MAX_REQUEST_OPTION_BYTES:
            raise ValueError('extra option values must be bounded')
        result.append((number, value))
        previous = number
    return tuple(result)


class ConnectCancellation:
    """One-way, socket-backed cancellation signal for ``connect()``.

    Each active connection attempt receives its own wake socket. ``set()``
    makes every subscribed socket readable immediately, without a polling
    thread. Session shutdown shares that wake path without changing a
    caller-supplied signal.
    """

    __slots__ = ("_is_set", "_lock", "_writers")

    def __init__(self) -> None:
        self._is_set = False
        self._lock = threading.Lock()
        self._writers: set[socket.socket] = set()

    def set(self) -> None:
        """Cancel current and future connection attempts using this signal."""
        with self._lock:
            if self._is_set:
                return
            self._is_set = True
            for writer in self._writers:
                try:
                    writer.send(b"\0")
                except OSError:
                    pass

    def is_set(self) -> bool:
        """Return whether cancellation has been requested."""
        with self._lock:
            return self._is_set

    def _subscribe(self) -> tuple[socket.socket, socket.socket]:
        reader, writer = socket.socketpair()
        reader.setblocking(False)
        try:
            self._subscribe_writer(writer)
        except Exception:
            reader.close()
            writer.close()
            raise
        return reader, writer

    def _subscribe_writer(self, writer: socket.socket) -> None:
        """Attach an existing wake writer without taking ownership of it."""
        with self._lock:
            self._writers.add(writer)
            if self._is_set:
                writer.send(b"\0")

    def _unsubscribe_writer(self, writer: socket.socket) -> bool:
        """Detach a shared wake writer and report cancellation state."""
        with self._lock:
            self._writers.discard(writer)
            return self._is_set

    def _unsubscribe(
        self,
        reader: socket.socket,
        writer: socket.socket,
    ) -> bool:
        interrupted = self._unsubscribe_writer(writer)
        reader.close()
        writer.close()
        return interrupted


class DtlsCoapSession:
    """Single sustained DTLS-CoAP session.

    Caller drives lifecycle:
        sess = DtlsCoapSession(host, port, cert_path=cert, key_path=key)
        sess.connect()
        sess.start_reader()
        sess.subscribe([...], on_notification=cb)   # OBSERVE
        code, body = sess.get(['device', '0'])      # Block2 fetch
        code, _    = sess.post(['mode','vs','0'], cbor)
        sess.close()

    Authentication comes from an immutable provider. For compatibility,
    cert_path/key_path and cert_pem/key_pem create a CertificateAuth provider
    internally — exactly one legacy pair is required when auth is omitted.
    """

    HANDSHAKE_TIMEOUT_S = 12.0
    READER_RECV_TIMEOUT_S = 1.0  # short so stop_event propagates quickly
    MAX_BLOCKS = 32              # safety bound for Block2 fetches

    def __init__(self, host, port, cert_path=None, key_path=None, *,
                 cert_pem=None, key_pem=None,
                 on_notification=None, mtu=1200,
                 rate_limit_rps: float = _DEFAULT_RATE_LIMIT_RPS,
                 local_port=None, family=socket.AF_UNSPEC,
                 write_max_attempts: int = 1,
                 auth: AuthenticationProvider | None = None,
                 on_legacy_notification=None,
                 on_observe_pending=None,
                 on_observe_error=None):
        file_supplied = cert_path is not None or key_path is not None
        memory_supplied = cert_pem is not None or key_pem is not None
        if auth is not None and (file_supplied or memory_supplied):
            raise ValueError(
                "pass auth or legacy certificate arguments, not both")
        if auth is None and file_supplied and memory_supplied:
            raise ValueError(
                "pass either cert_path/key_path or cert_pem/key_pem, not both")
        if auth is None and memory_supplied:
            if cert_pem is None or key_pem is None:
                raise ValueError("cert_pem and key_pem must be passed together")
        elif auth is None and (cert_path is None or key_path is None):
            raise ValueError(
                "must pass either cert_path/key_path or cert_pem/key_pem")
        if auth is not None and not isinstance(auth, AuthenticationProvider):
            raise TypeError("auth must implement AuthenticationProvider")

        self.host = host
        self.port = port
        self.cert_path = str(cert_path) if cert_path is not None else None
        self.key_path  = str(key_path) if key_path is not None else None
        self.cert_pem = cert_pem
        self.key_pem  = key_pem
        if auth is None:
            if cert_pem is not None:
                auth = CertificateAuth.from_memory(cert_pem, key_pem)
            else:
                auth = CertificateAuth.from_files(self.cert_path, self.key_path)
        self.auth = auth
        self.on_notification = on_notification  # fn(href, payload_bytes)
        self.on_legacy_notification = on_legacy_notification
        self.on_observe_pending = on_observe_pending
        self.on_observe_error = on_observe_error
        self.mtu = mtu
        self._min_req_interval = 1.0 / rate_limit_rps
        self._write_max_attempts = max(1, int(write_max_attempts))
        # Optional fixed UDP source port. A client that dies without
        # close_notify leaves an orphaned DTLS association on the device,
        # keyed to the old 5-tuple; reconnecting from a fresh ephemeral
        # port presents as a *new* peer and the orphan lingers until the
        # device's own timer reaps it (observed 5-15 min on always-on
        # appliances). Binding the same source port on every connect makes
        # a restart re-handshake over the SAME 5-tuple, which RFC 6347
        # §4.2.8 requires the server to treat as a rebooted peer: complete
        # the new handshake and discard the old association. Verified
        # accepted by RT-OCF (oven, 2026-07-26).
        self.local_port = local_port
        self.family = family

        self.sock = None
        self.conn = None
        self.dest = None
        self.endpoint = None
        # Populated only when a SamsungServerProfile verified the peer. The
        # UUID comes from the authenticated hardware-certificate subject; it
        # is not necessarily the OCF device UUID returned by /oic/d.
        self.server_certificate_identity = None

        # Terminal session shutdown has its own wake signal so
        # quiesce_for_close() can interrupt connect() even when the caller did
        # not supply a ConnectCancellation. The lifecycle lock makes handshake
        # publication atomic with that one-way transition.
        self._lifecycle_cancel = ConnectCancellation()
        self._lifecycle_lock = threading.Lock()

        self._send_lock = threading.Lock()
        # Only the thread performing orderly close may send an Observe
        # deregistration after terminal quiescence. A thread-local exception
        # keeps concurrent application senders blocked without changing the
        # existing private send-hook signatures used by test/session adapters.
        self._orderly_close_send_thread_id = None
        # Guards the MID/token counters and pending-request registries.
        # The refetch worker makes the session its own second concurrent
        # get() caller, so two threads can mint tokens at once; without
        # this they can collide and one transfer silently absorbs the
        # other's blocks.
        self._state_lock = threading.Lock()
        # Serialize public relation mutations without holding _state_lock over
        # network sends. The reader must remain free to dispatch an immediate
        # registration response while refresh, unsubscribe, or close runs.
        self._observe_operation_lock = threading.RLock()
        # Randomize MID and token counter starting points so reconnects
        # don't reuse identifiers from previous sessions — Samsung's
        # RT-OCF appears to remember observer state across DTLS
        # sessions, and re-registering with a token it still thinks is
        # active is silently no-ops.
        self._mid = int.from_bytes(os.urandom(2), 'big')
        self._tok_counter = int.from_bytes(os.urandom(4), 'big')
        # OBSERVE tokens are 1-byte (Samsung silently drops TKL>1
        # OBSERVE registrations). Pick a random starting byte in the
        # 0x40..0xff range so each session uses fresh values.
        self._observe_tok_counter = 0x40 + (os.urandom(1)[0] & 0xBF)
        # token (bytes) → (Event, container_dict)
        self._pending = {}
        # request MID (int) → _MidExchange. Empty ACK and RST frames carry
        # no token, so request lifecycle state must also be reachable by the
        # MID that was registered before send.
        self._pending_mids = {}
        # token (bytes) → href (str)
        self._observe_tokens = {}
        # An Observe relation is identified by path plus URI query. Keep the
        # exact registration options for refetch and deregistration.
        self._observe_queries = {}
        # Some Samsung generations return a plain initial 2.05 and later push
        # on the same token without RFC 7641's Observe option. One later packet
        # with a different MID is required before that relation is trusted.
        self._observe_plain_response_mids = {}
        self._legacy_observe_tokens = set()
        self._legacy_observe_mids = {}
        # token → (last accepted 24-bit Observe value, monotonic receipt time)
        self._observe_sequences = {}

        # OBSERVE refetch queue: (href, query, legacy) → sequence number of the
        # newest notification that asked for it. Drained by a worker thread
        # because _dispatch_coap cannot block (see _queue_refetch).
        self._refetch_cond = threading.Condition()
        self._refetch_pending = {}
        self._refetch_seq = 0
        self._refetch_thread = None

        self._stop = threading.Event()
        self._reader_thread = None
        # Set while the reader owns the socket. Cleared when it exits for
        # any reason, so callers fail fast through _check_live() instead of
        # waiting out a request timeout against a session nobody is reading.
        self._reader_running = threading.Event()
        self._last_send_ts = 0.0

    def pace(self) -> None:
        """Sleep only the part of the rate-limit interval not already consumed
        since the last real send. Uses _stop so session teardown wakes it."""
        remaining = self._min_req_interval - (time.monotonic() - self._last_send_ts)
        if remaining > 0:
            self._stop.wait(remaining)

    def _pace_orderly_close(self) -> None:
        """Honor request spacing after terminal quiescence.

        ``quiesce_for_close()`` sets ``_stop`` so ordinary paced work wakes
        immediately.  A later orderly close still has to space its explicit
        Observe deregistrations, so this teardown-only path cannot wait on the
        already-set event.
        """
        remaining = self._min_req_interval - (time.monotonic() - self._last_send_ts)
        if remaining > 0:
            time.sleep(remaining)

    # ---- lifecycle ---------------------------------------------------

    def connect(
        self,
        *,
        timeout: float | None = None,
        cancel: ConnectCancellation | None = None,
        cleanup_hvr_peer: bool = False,
    ):
        """Perform a cancellable DTLS handshake using a monotonic deadline.

        ``timeout`` overrides ``HANDSHAKE_TIMEOUT_S`` for this call. OpenSSL
        owns DTLS retransmission timing while every receive is capped by the
        remaining budget, so wall-clock adjustments cannot change the bound.
        Once OpenSSL reports completion, that completed session is retained
        even if the call returns just after the deadline. A
        ``ConnectCancellation`` wakes the network wait immediately and does not
        alter an already established session. ``cleanup_hvr_peer`` is an
        opt-in recovery signal for a Samsung-profiled handshake that times out
        after only the DTLS cookie exchange. It requires a fixed local port,
        emits at most one standards-based alert, and leaves retry policy to the
        caller.
        """
        handshake_timeout = _validate_handshake_timeout(
            timeout, self.HANDSHAKE_TIMEOUT_S)
        if cancel is not None and not isinstance(cancel, ConnectCancellation):
            raise TypeError("cancel must be a ConnectCancellation or None")
        if type(cleanup_hvr_peer) is not bool:
            raise TypeError("cleanup_hvr_peer must be a bool")
        if cleanup_hvr_peer and (
            type(self.auth) not in (CertificateAuth, ServerCertificateAuth)
            or type(getattr(self.auth, "_server_profile", None))
            is not SamsungServerProfile
        ):
            raise ValueError(
                "HVR peer cleanup requires a Samsung server profile"
            )
        if cleanup_hvr_peer and (
            isinstance(self.local_port, bool)
            or not isinstance(self.local_port, int)
            or not 1 <= self.local_port <= 65535
        ):
            raise ValueError(
                "HVR peer cleanup requires a fixed non-zero local port"
            )
        if self._lifecycle_cancel.is_set() or \
                (cancel is not None and cancel.is_set()):
            raise SessionClosedError()
        deadline = time.monotonic() + handshake_timeout
        ctx = SSL.Context(SSL.DTLS_METHOD)
        self.auth.configure_context(ctx)
        if self._lifecycle_cancel.is_set() or \
                (cancel is not None and cancel.is_set()):
            raise SessionClosedError()

        conn = SSL.Connection(ctx, None)
        conn.set_connect_state()
        conn.set_ciphertext_mtu(self.mtu)
        if self._lifecycle_cancel.is_set() or \
                (cancel is not None and cancel.is_set()):
            raise SessionClosedError()

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SessionTimeoutError()
        sock, endpoint = open_host_filtered_udp_socket(
            self.host,
            self.port,
            family=self.family,
            local_port=self.local_port,
            timeout=min(_HANDSHAKE_POLL_S, remaining),
        )
        dest = endpoint.sockaddr
        if self._lifecycle_cancel.is_set() or \
                (cancel is not None and cancel.is_set()):
            sock.close()
            raise SessionClosedError()

        wake_subscription = None
        subscription_failed = False
        wake_owner = cancel or self._lifecycle_cancel
        lifecycle_writer_shared = cancel is not None
        # Production endpoints are real sockets and can share select() with
        # the wake socket. Retain the timeout-driven path for structural socket
        # adapters that intentionally expose no file descriptor.
        if callable(getattr(sock, "fileno", None)):
            try:
                wake_subscription = wake_owner._subscribe()
                if lifecycle_writer_shared:
                    self._lifecycle_cancel._subscribe_writer(
                        wake_subscription[1])
            except OSError:
                subscription_failed = True
        if subscription_failed:
            if wake_subscription is not None:
                if lifecycle_writer_shared:
                    self._lifecycle_cancel._unsubscribe_writer(
                        wake_subscription[1])
                wake_owner._unsubscribe(*wake_subscription)
            sock.close()
            raise SessionError() from OSError(
                "connection cancellation setup failed"
            )

        backend_failed = False
        io_failed = False
        cancelled = False
        interrupted = False
        completed = False
        cleanup_transcript = (
            _HvrPeerCleanupTranscript() if cleanup_hvr_peer else None
        )
        try:
            try:
                completed = _drive_dtls_handshake(
                    conn,
                    sock,
                    deadline=deadline,
                    wake_socket=(
                        wake_subscription[0]
                        if wake_subscription is not None
                        else None
                    ),
                    on_datagram=(
                        cleanup_transcript.record_received
                        if cleanup_transcript is not None
                        else None
                    ),
                    on_record_sent=(
                        cleanup_transcript.record_sent
                        if cleanup_transcript is not None
                        else None
                    ),
                )
            except _HandshakeCancelled:
                cancelled = True
            except SSL.Error:
                backend_failed = True
            except OSError:
                io_failed = True
        finally:
            if wake_subscription is not None:
                if lifecycle_writer_shared:
                    interrupted = self._lifecycle_cancel._unsubscribe_writer(
                        wake_subscription[1])
                interrupted = (
                    wake_owner._unsubscribe(*wake_subscription)
                    or interrupted
                )
        if cancelled or (interrupted and not completed):
            sock.close()
            raise SessionClosedError()
        if backend_failed:
            sock.close()
            raise SessionError() from ConnectionError('DTLS backend failed')
        if io_failed:
            sock.close()
            raise EndpointError() from OSError('UDP handshake I/O failed')
        if not completed:
            cleanup_sent = False
            if cleanup_transcript is not None:
                cleanup_alert = cleanup_transcript.cleanup_alert()
                if cleanup_alert is not None:
                    try:
                        # The handshake deadline has expired. Keep this single
                        # advisory datagram non-blocking so cleanup cannot
                        # extend the caller's timeout budget.
                        sock.settimeout(0.0)
                        cleanup_sent = (
                            sock.send(cleanup_alert) == len(cleanup_alert)
                        )
                    except Exception:
                        pass
            sock.close()
            if cleanup_sent:
                raise HandshakePeerCleanupError()
            raise SessionTimeoutError()

        try:
            identity_reader = getattr(
                self.auth,
                "_authenticated_server_identity",
                None,
            )
            if identity_reader is not None:
                server_certificate_identity = identity_reader(conn)
                if server_certificate_identity is not None and (
                    type(server_certificate_identity) is not UUID
                    or server_certificate_identity.int == 0
                ):
                    raise ValueError(
                        "verified server identity was unavailable"
                    )
            else:
                server_certificate_identity = None
        except Exception:
            self._send_close_notify(conn, sock)
            sock.close()
            raise AuthenticationError() from ConnectionError(
                "verified server identity was unavailable"
            )

        with self._lifecycle_lock:
            if self._lifecycle_cancel.is_set():
                sock.close()
                raise SessionClosedError()
            self.sock = sock
            self.conn = conn
            self.dest = dest
            self.endpoint = endpoint
            self.server_certificate_identity = server_certificate_identity
            self._stop.clear()

    def start_reader(self):
        """Spawn the reader thread. Must be called after connect()."""
        with self._lifecycle_lock:
            if self.sock is None:
                raise RuntimeError("connect() before start_reader()")
            self._check_live()
            self._reader_running.set()
            t = threading.Thread(target=self._reader_loop,
                                 daemon=True, name='dtls-reader')
            t.start()
            self._reader_thread = t

    def _check_live(self):
        """Raise if the session cannot carry a request. A dead reader is
        as fatal as a closed connection: the socket may still accept
        sends, but no response will ever be dispatched, so waiting out the
        request timeout only delays the inevitable SessionClosedError.

        Callers that never start a reader (config-flow style) keep the old
        behaviour — only the conn check applies while _reader_thread is
        None."""
        if self._lifecycle_cancel.is_set() or self.conn is None:
            raise SessionClosedError()
        if self._reader_thread is not None and \
                not self._reader_running.is_set():
            raise SessionClosedError()

    def join(self):
        """Block until the reader thread exits (i.e. socket dies)."""
        if self._reader_thread is not None:
            self._reader_thread.join()
        if self._refetch_thread is not None:
            self._refetch_thread.join()

    def _send_observe_dereg(self, tok, path_segs, query=()):
        """Send a single OBSERVE deregister GET (Observe option = 1)
        on the existing token. Best-effort — caller swallows errors."""
        mid = self._next_mid()
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        for value in query:
            opts.append((URI_QUERY, value.encode()))
        opts.append((OBSERVE, OBSERVE_DEREGISTER))
        opts.append((ACCEPT, CF_CBOR))
        self._send_dgram(build_coap(TYPE_CON, METHOD_GET, mid, tok, opts))

    def _send_observe_dereg_after_quiesce(self, tok, path_segs, query=()):
        """Permit one orderly-close deregistration on the closing thread."""
        previous = self._orderly_close_send_thread_id
        self._orderly_close_send_thread_id = threading.get_ident()
        try:
            self._send_observe_dereg(tok, path_segs, query)
        finally:
            self._orderly_close_send_thread_id = previous

    @staticmethod
    def _send_close_notify(connection, sock):
        """Best-effort flush the encrypted DTLS close-notify record."""
        try:
            connection.shutdown()
        except (SSL.WantReadError, SSL.ZeroReturnError):
            pass
        except Exception:
            pass
        try:
            while True:
                try:
                    outbound = connection.bio_read(65535)
                except SSL.WantReadError:
                    break
                if not outbound:
                    break
                for record in _split_dtls(outbound):
                    if sock.send(record) != len(record):
                        raise OSError('incomplete UDP send')
        except Exception:
            pass

    def quiesce_for_close(self):
        """Stop new work while retaining an established socket for close()."""
        with self._lifecycle_lock:
            self._lifecycle_cancel.set()
            # Synchronize with an in-progress application send. Once this lock
            # is released, _send_dgram() observes lifecycle cancellation before
            # touching DTLS.
            with self._send_lock:
                self._stop.set()
        with self._refetch_cond:
            self._refetch_pending.clear()
            self._refetch_cond.notify_all()
        self._close_pending_requests()

    def close(self):
        """Tear down session. Sends best-effort OBSERVE deregisters
        first so Samsung's RT-OCF cleans up its observer table —
        without this, the per-cert observer state survives DTLS close
        and a quick reconnect with the same tokens silently no-ops."""
        with self._observe_operation_lock:
            self._close_orderly()

    def _close_orderly(self):
        # Send dereg for every active observation while the conn is
        # still healthy. Tiny sleep lets the records reach the wire
        # before we shut DTLS down.
        if self.conn is not None and self._observe_tokens:
            quiesced = self._lifecycle_cancel.is_set()
            with self._state_lock:
                observations = tuple(self._observe_tokens.items())
                observe_queries = dict(self._observe_queries)
            for tok, href in observations:
                segs = [s for s in href.split('/') if s]
                try:
                    if quiesced:
                        self._pace_orderly_close()
                        self._send_observe_dereg_after_quiesce(
                            tok,
                            segs,
                            observe_queries.get(tok, ()),
                        )
                    else:
                        self.pace()
                        self._send_observe_dereg(
                            tok, segs, observe_queries.get(tok, ()))
                except Exception as e:
                    logger.warning("dereg %s: %s", href, e)
            time.sleep(0.1)

        self.quiesce_for_close()
        with self._send_lock:
            if self.conn is not None and self.sock is not None:
                self._send_close_notify(self.conn, self.sock)
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        # Publish the closed state before draining pending requests. A caller
        # that passed its entry check just before close() will then fail the
        # post-registration liveness check instead of registering after the
        # drain and waiting against a session that can no longer respond.
        with self._lifecycle_lock:
            self.sock = None
            self.conn = None
            self.dest = None
            self.endpoint = None
        self._clear_observe_relations()

    def abort(self):
        """Immediately stop work and close the established transport."""
        self.quiesce_for_close()
        with self._observe_operation_lock:
            with self._lifecycle_lock:
                sock = self.sock
                self.sock = None
                self.conn = None
                self.dest = None
                self.endpoint = None
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            self._clear_observe_relations()

    # ---- send / receive plumbing -------------------------------------

    def _next_available_mid_locked(self):
        """Return the next MID that is not owned by a live request.

        Probing one more candidate than there are live exchanges is enough
        by the pigeonhole principle: the candidates are consecutive and so
        distinct, and at most len(_pending_mids) of them can be taken. In
        practice that means a single probe, instead of a walk over all
        65,536 identifiers to discover what the dict size already implied.
        """
        for _ in range(min(len(self._pending_mids) + 1, 0x10000)):
            self._mid = (self._mid + 1) & 0xFFFF
            if self._mid not in self._pending_mids:
                return self._mid
        raise SessionIdentifierError()

    def _next_mid(self):
        with self._state_lock:
            return self._next_available_mid_locked()

    def _register_pending_request(self, tok, ev, container):
        """Atomically allocate a MID and index one request by MID and token."""
        with self._state_lock:
            if tok in self._pending:
                raise SessionIdentifierError()
            mid = self._next_available_mid_locked()
            pending = (ev, container)
            exchange = _MidExchange(pending)
            self._pending[tok] = pending
            self._pending_mids[mid] = exchange
        return mid, exchange

    def _unregister_pending_request(self, tok, mid, exchange):
        """Remove only the exact request registered under both indices."""
        with self._state_lock:
            if self._pending.get(tok) is exchange.pending:
                self._pending.pop(tok, None)
            if self._pending_mids.get(mid) is exchange:
                self._pending_mids.pop(mid, None)

    def _close_pending_requests(self):
        """Fail, unregister, and wake every request that can no longer finish."""
        with self._state_lock:
            pending_by_id = {
                id(record): record for record in self._pending.values()
            }
            pending_by_id.update(
                (id(exchange.pending), exchange.pending)
                for exchange in self._pending_mids.values()
            )
            pending = list(pending_by_id.values())
            for _ev, container in pending:
                # Only fail an exchange that has no answer yet. A response
                # the reader dispatched before it tore down is a real one —
                # the request finished, the session merely died after it —
                # and both callers check 'err' before 'code', so stamping
                # one here discards a write the device already confirmed.
                if 'code' not in container:
                    container.setdefault('err', SessionClosedError())
            self._pending.clear()
            self._pending_mids.clear()
        for ev, _container in pending:
            ev.set()

    def _next_tok(self):
        with self._state_lock:
            self._tok_counter = (self._tok_counter + 1) & 0xFFFFFFFF
            # 4-byte tokens — fits within tkl=8 cap with headroom and
            # avoids collisions across long-running OBSERVE subscriptions.
            return self._tok_counter.to_bytes(4, 'big')

    def _next_available_observe_tok_locked(self):
        """Return an unused nonzero one-byte Observe token."""
        for _ in range(min(len(self._observe_tokens) + 1, 0xFF)):
            self._observe_tok_counter = (self._observe_tok_counter + 1) & 0xFF
            if self._observe_tok_counter == 0:
                self._observe_tok_counter = 1
            token = bytes([self._observe_tok_counter])
            if token not in self._observe_tokens:
                return token
        raise SessionIdentifierError()

    def _retire_observe_token_locked(self, tok):
        """Remove every relation-state index for one Observe token."""
        self._observe_tokens.pop(tok, None)
        self._observe_queries.pop(tok, None)
        self._observe_plain_response_mids.pop(tok, None)
        self._legacy_observe_tokens.discard(tok)
        self._legacy_observe_mids.pop(tok, None)
        self._observe_sequences.pop(tok, None)

    def _clear_observe_relations(self):
        with self._state_lock:
            self._observe_tokens.clear()
            self._observe_queries.clear()
            self._observe_plain_response_mids.clear()
            self._legacy_observe_tokens.clear()
            self._legacy_observe_mids.clear()
            self._observe_sequences.clear()

    def _observe_relation_active(self, href, query, legacy):
        """Return whether one relation still owns this callback identity."""
        with self._state_lock:
            for tok, observed_href in self._observe_tokens.items():
                if observed_href != href or \
                        self._observe_queries.get(tok, ()) != query:
                    continue
                if legacy:
                    if tok in self._legacy_observe_tokens:
                        return True
                elif tok in self._observe_sequences or (
                        tok in self._observe_plain_response_mids
                        and tok not in self._legacy_observe_tokens):
                    # A probationary optionless response is not proof of an
                    # Observe relation, but its complete representation still
                    # belongs on the ordinary notification callback. Keep a
                    # Block2 refetch alive until the token is retired or later
                    # proves the legacy relation.
                    return True
        return False

    def _discard_refetches_for_hrefs(self, hrefs):
        """Discard queued work for retired paths; running work self-checks."""
        hrefs = frozenset(hrefs)
        if not hrefs:
            return
        with self._refetch_cond:
            for key in tuple(self._refetch_pending):
                if key[0] in hrefs:
                    self._refetch_pending.pop(key, None)
            self._refetch_cond.notify_all()

    @staticmethod
    def _observe_sequence_is_fresh(previous, current, received_at):
        """Apply RFC 7641's 24-bit serial-number freshness comparison."""
        if previous is None:
            return True
        previous_value, previous_received_at = previous
        if received_at - previous_received_at > _OBSERVE_SEQUENCE_RESET_S:
            return True
        delta = (current - previous_value) % _OBSERVE_SEQUENCE_MODULUS
        return 0 < delta < _OBSERVE_SEQUENCE_HALF_RANGE

    def _send_dgram(self, datagram):
        """Send a CoAP datagram. Holds the send lock for the
        BIO-drain so two writers can't interleave records.

        The orderly-close deregistration helper grants only its calling thread
        a teardown send after application workers have joined. All ordinary
        request paths remain blocked once terminal quiescence begins.
        """
        with self._send_lock:
            orderly_close_send = (
                self._orderly_close_send_thread_id == threading.get_ident())
            if (self._lifecycle_cancel.is_set() and not orderly_close_send) or \
                    self.conn is None:
                raise SessionClosedError()
            send_failed = False
            try:
                self.conn.send(datagram)
                self._last_send_ts = time.monotonic()
                while True:
                    o = self.conn.bio_read(65535)
                    if not o:
                        break
                    for r in _split_dtls(o):
                        if self.sock.send(r) != len(r):
                            raise OSError('incomplete UDP send')
            except SSL.WantReadError:
                pass
            except OSError:
                send_failed = True
            if send_failed:
                raise EndpointError() from OSError('UDP send failed')

    def _reader_loop(self):
        """Pump UDP socket → DTLS BIO → CoAP parser. Demuxes to pending
        / observe handlers. Exits on socket error or stop event."""
        sock = self.sock
        conn = self.conn
        sock.settimeout(self.READER_RECV_TIMEOUT_S)
        try:
            while not self._stop.is_set():
                try:
                    d = sock.recv(65535)
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._stop.is_set():
                        return          # close() got here first
                    if e.errno in _ADVISORY_ERRNOS:
                        logger.debug("reader: advisory %s from %s, continuing",
                                     errno.errorcode.get(e.errno, e.errno),
                                     self.host)
                        continue
                    logger.warning("reader exiting: socket error %s from %s",
                                   errno.errorcode.get(e.errno, e.errno),
                                   self.host)
                    return
                except ValueError:
                    # recv on a socket closed underneath the reader.
                    if not self._stop.is_set():
                        logger.warning("reader exiting: socket closed "
                                       "underneath it")
                    return
                if not d:
                    continue
                # pyOpenSSL's SSL.Connection is not thread-safe — the
                # same SSL object must not be touched by multiple
                # threads concurrently. Drain decrypted records into a
                # local list under _send_lock so the reader never races
                # a sender's conn.send()/bio_read(). Dispatch happens
                # AFTER releasing the lock because _dispatch_coap may
                # call _send_dgram (auto-ACK for CON frames), which
                # re-acquires the lock — holding it across dispatch
                # would deadlock.
                packets = []
                exit_reader = False
                with self._send_lock:
                    try:
                        conn.bio_write(d)
                    except SSL.Error as e:
                        logger.warning("DTLS bio_write: %s", e)
                        return
                    while True:
                        try:
                            pl = conn.recv(65535)
                        except SSL.WantReadError:
                            break
                        except SSL.ZeroReturnError:
                            logger.info("DTLS peer closed connection")
                            exit_reader = True
                            break
                        except SSL.Error as e:
                            logger.warning("DTLS recv: %s", e)
                            exit_reader = True
                            break
                        if not pl:
                            break
                        packets.append(pl)
                for pl in packets:
                    try:
                        self._dispatch_coap(pl)
                    except Exception as e:
                        logger.warning("dispatch: %s", e)
                if exit_reader:
                    return
        finally:
            # Reader no longer owns the socket — callers must fail fast.
            self._reader_running.clear()
            # Make sure pending waiters don't hang if the reader dies.
            self._close_pending_requests()
            # Nothing will answer a refetch now either.
            with self._refetch_cond:
                self._refetch_pending.clear()
                self._refetch_cond.notify_all()
            # Two-phase shutdown retains relation metadata for close(), which
            # runs after application workers have joined and sends the paced
            # deregistration sweep. Unexpected reader death has no later
            # orderly phase and must still retire everything immediately.
            if not self._lifecycle_cancel.is_set():
                self._clear_observe_relations()

    def _dispatch_coap(self, datagram):
        try:
            classification = classify_coap_response(datagram)
        except MalformedMessageError as e:
            logger.debug("malformed CoAP: %s", e)
            return

        message = classification.message
        if message is None:
            return
        mt = message.mtype
        code = message.code
        mid = message.mid
        tok = message.token
        ropts = message.options
        payload = message.payload

        if DEBUG_BRIDGE:
            kind = ['CON', 'NON', 'ACK', 'RST'][mt]
            logger.info("rx %s code=%s mid=%04x tok=%s opts=%d pl=%d",
                        kind, fmt_code(code), mid, tok.hex() or '-',
                        len(ropts), len(payload))

        # ACK back any CON from the device to suppress retransmits.
        # RFC 7252 §4.2 — ACK is a bare frame (token len 0, code 0).
        if classification.acknowledgement is not None:
            try:
                self._send_dgram(classification.acknowledgement)
            except Exception as e:
                logger.warning("ACK send: %s", e)

        # Empty ACK with no options & no payload = "separate response
        # coming" — used by Samsung's RT-OCF for the larger reads. Stop
        # the retransmit timer on the client side and wait for the CON.
        if classification.kind == RESPONSE_EMPTY_ACK:
            with self._state_lock:
                exchange = self._pending_mids.get(mid)
                if exchange is not None:
                    exchange.acknowledged = True
                    ev, _container = exchange.pending
            if exchange is not None:
                ev.set()
            return

        # A reset rejects the matching exchange. Like an empty ACK it has no
        # response token, so surface it through the request's MID registry.
        if classification.kind == RESPONSE_RESET:
            with self._state_lock:
                exchange = self._pending_mids.get(mid)
                if exchange is not None:
                    ev, container = exchange.pending
                    if 'code' not in container and 'err' not in container:
                        container['err'] = SessionResetError()
            if exchange is not None:
                ev.set()
            return
        if classification.kind != RESPONSE_MESSAGE:
            return

        # Pending one-shot? Resolve and return. Block1 keeps one token for the
        # entire upload, so a delayed response for the previous chunk must not
        # resolve the currently registered chunk.
        with self._state_lock:
            rec = self._pending.get(tok)
            if rec is not None:
                ev, container = rec
                if self._block1_response_matches(message, container):
                    container['code']    = code
                    container['mtype']   = mt
                    container['mid']     = mid
                    container['options'] = ropts
                    container['payload'] = payload
                    container['message'] = message
                else:
                    rec = None
        if rec is not None:
            ev.set()
            return

        # OBSERVE notification?
        with self._state_lock:
            href = self._observe_tokens.get(tok)
            observe_query = self._observe_queries.get(tok, ())
        if href is not None:
            if code != 0x45:
                with self._state_lock:
                    self._retire_observe_token_locked(tok)
                logger.debug("observe %s: non-2.05 %s",
                             href, fmt_code(code))
                cb = self.on_observe_error
                if cb is not None:
                    try:
                        cb(href, code)
                    except Exception as e:
                        logger.debug("observe error callback %s: %s", href, e)
                return
            block_values = [
                value for number, value in ropts if number == BLOCK2
            ]
            blockwise_refetch = False
            if block_values:
                if len(block_values) != 1 or len(block_values[0]) > 3:
                    logger.debug("observe %s: malformed Block2 option", href)
                    return
                try:
                    block_number, more, _ = block_fields(block_values[0])
                except ValueError:
                    logger.debug("observe %s: malformed Block2 option", href)
                    return
                blockwise_refetch = bool(more or block_number)
            observe_values = [
                value for number, value in ropts if number == OBSERVE
            ]
            legacy = False
            if observe_values:
                if len(observe_values) != 1 or len(observe_values[0]) > 3:
                    logger.debug("observe %s: malformed Observe option", href)
                    return
                sequence = int.from_bytes(observe_values[0], 'big')
                received_at = time.monotonic()
                with self._state_lock:
                    previous = self._observe_sequences.get(tok)
                    if not self._observe_sequence_is_fresh(
                            previous, sequence, received_at):
                        return
                    self._observe_sequences[tok] = (sequence, received_at)
                    self._observe_plain_response_mids.pop(tok, None)
                    self._legacy_observe_tokens.discard(tok)
                    self._legacy_observe_mids.pop(tok, None)
            else:
                pending = False
                with self._state_lock:
                    if tok in self._observe_sequences:
                        return
                    initial_mid = self._observe_plain_response_mids.get(tok)
                    if tok in self._legacy_observe_tokens:
                        if self._legacy_observe_mids.get(tok) == mid:
                            return
                        self._legacy_observe_mids[tok] = mid
                        legacy = True
                    elif initial_mid is None:
                        self._observe_plain_response_mids[tok] = mid
                        pending = True
                    elif initial_mid == mid:
                        return
                    else:
                        self._legacy_observe_tokens.add(tok)
                        self._legacy_observe_mids[tok] = mid
                        legacy = True
                if pending:
                    logger.debug(
                        "observe %s: probationary 2.05 without Observe option",
                        href,
                    )
                    cb = self.on_observe_pending
                    if cb is not None:
                        try:
                            cb(href)
                        except Exception as e:
                            logger.debug(
                                "observe pending callback %s: %s", href, e)
                    with self._state_lock:
                        if self._observe_tokens.get(tok) != href or \
                                self._observe_queries.get(tok, ()) != \
                                observe_query or \
                                self._observe_plain_response_mids.get(tok) != \
                                mid or tok in self._legacy_observe_tokens or \
                                tok in self._observe_sequences:
                            return
            # RFC 7959 §2.6: a notification carries only the first block
            # of the representation. Handing the callback a partial CBOR
            # buffer is what #39 was about, so anything with M=1 (or a
            # block past the first) goes to the refetch worker instead.
            if blockwise_refetch:
                self._queue_refetch(
                    href, tuple(observe_query), legacy=legacy)
                return
            cb = (
                self.on_legacy_notification
                if legacy and self.on_legacy_notification is not None
                else self.on_notification
            )
            if cb is not None:
                try:
                    cb(href, payload)
                except Exception as e:
                    logger.warning("notification callback %s: %s",
                                   href, e)
            return

        # Stale token (post-reconnect or unknown) — drop quietly.

    # ---- OBSERVE refetch ---------------------------------------------

    @staticmethod
    def _log_refetch(msg, *args):
        """Refetch outcomes are debug-level in normal operation, which is
        below the bridge's INFO default, so a healthy session stays quiet.
        DEBUG_BRIDGE=1 promotes them to INFO for hardware validation:
        that shows which token the re-read used and whether it completed,
        without also turning on every per-block retransmit line."""
        (logger.info if DEBUG_BRIDGE else logger.debug)(msg, *args)

    def _queue_refetch(self, href, query=(), *, legacy=False):
        """Queue a blockwise notification for re-reading.

        Called from the reader thread, so it must not block: _dispatch_coap
        runs there and _blockwise_get waits on an Event only that same
        thread can set, which would deadlock the session outright. Latest
        wins per relation — a burst of notifications for one path/query shape
        collapses into a single re-read of its final state."""
        key = (href, tuple(query), bool(legacy))
        with self._refetch_cond:
            if (key not in self._refetch_pending
                    and len(self._refetch_pending) >= _MAX_PENDING_REFETCH):
                self._log_refetch(
                    "refetch %s dropped: queue full (%d pending)",
                    href, len(self._refetch_pending))
                return
            self._refetch_seq += 1
            self._refetch_pending[key] = self._refetch_seq
            self._refetch_cond.notify()
        self._start_refetch_worker()

    def _start_refetch_worker(self):
        """Start the refetch worker on first use. Sessions that never see
        a blockwise notification never grow the thread."""
        if self._refetch_thread is not None or self._stop.is_set():
            return
        with self._state_lock:
            if self._refetch_thread is not None or self._stop.is_set():
                return
            self._refetch_thread = threading.Thread(
                target=self._refetch_loop, daemon=True,
                name=f'stl-refetch-{self.host}')
            self._refetch_thread.start()

    def _refetch_loop(self):
        """Re-read blockwise-notified resources, one at a time.

        Serialized on purpose. Each re-read is a multi-block transfer and
        _blockwise_get paces between blocks, so running one at a time is
        what keeps a notification storm under the firmware's request
        ceiling."""
        while self._refetch_alive():
            with self._refetch_cond:
                while not self._refetch_pending and self._refetch_alive():
                    self._refetch_cond.wait(1.0)
                if not self._refetch_pending:
                    return
                key, seq = next(iter(self._refetch_pending.items()))
                del self._refetch_pending[key]
            self._refetch_one(key, seq)

    def _refetch_alive(self):
        """False once the session is closing or the reader has died. A
        refetch needs the reader to resolve its token, so outliving it
        would leave join() waiting on a thread with nothing to do."""
        if self._stop.is_set():
            return False
        return self._reader_thread is None or self._reader_running.is_set()

    def _refetch_one(self, key, seq):
        """Re-read one href from block 0 and deliver it if it is still
        the freshest thing we know about that resource."""
        href, query, legacy = key
        if not self._observe_relation_active(href, query, legacy):
            return
        self.pace()
        segs = [s for s in href.split('/') if s]
        try:
            code, payload, blocks, tok = self._blockwise_get(
                segs, query, _REFETCH_TIMEOUT_S)
        except Exception as e:
            # Device silent, session gone, ETag never settled, block cap
            # hit. Whatever the reason, dropping the notification is the
            # contract: the poll tiers still carry freshness, and handing
            # over the first block is the bug this replaced.
            self._log_refetch("refetch %s failed: %s", href, e)
            return
        if code != 0x45:
            self._log_refetch("refetch %s returned %s", href, fmt_code(code))
            return
        with self._refetch_cond:
            # A newer notification landed while we were reading. That one
            # has its own refetch queued, so this result is already stale.
            if self._refetch_pending.get(key, 0) > seq:
                self._log_refetch(
                    "refetch %s tok=%s blocks=%d bytes=%d superseded",
                    href, tok.hex(), blocks, len(payload))
                return
        if not self._observe_relation_active(href, query, legacy):
            return
        self._log_refetch("refetch %s tok=%s blocks=%d bytes=%d ok",
                          href, tok.hex(), blocks, len(payload))
        cb = (
            self.on_legacy_notification
            if legacy and self.on_legacy_notification is not None
            else self.on_notification
        )
        if cb is not None:
            try:
                cb(href, payload)
            except Exception as e:
                logger.warning("notification callback %s: %s", href, e)

    # ---- request primitives ------------------------------------------

    def get(self, path_segs, query=(), timeout=10.0, *, extra_options=()):
        """Token-stable Block2 GET. Returns (code, payload_bytes).

        Reuses one CoAP token across every block of a multi-block
        response — Samsung's server keys per-transfer state on the
        token, and dropping a fresh token on block 1+ silently drops
        the request."""
        self._check_live()
        path_segs = _validated_text_options(
            path_segs, name='path_segs', allow_empty=False)
        query = _validated_text_options(
            query, name='query', allow_empty=False)
        extra_options = _validated_extra_options(extra_options)
        code, blob, _blocks, _tok = self._blockwise_get(
            path_segs, query, timeout, extra_options=extra_options)
        return code, blob

    def _blockwise_get(
            self, path_segs, query=(), timeout=10.0, *, extra_options=()):
        """Shared token-stable Block2 reassembly (RFC 7959 §2.4).

        Returns (code, payload, block_count, token). The last two are
        diagnostics for the refetch log; get() drops them.

        Mints one fresh 4-byte token and holds it across every block of
        the transfer. Also the notification-refetch primitive: RFC 7959
        §3.4 forbids continuing a blockwise notification on the
        observation's token, and Samsung's RT-OCF drops a transfer that
        opens at NUM>0 under a token it has not seen, so a truncated
        notification is recovered by re-reading from block 0 through
        this same path rather than by a §2.6 continuation.

        Restarts once if the server's ETag changes mid-transfer, then
        gives up: RFC 7959 §2.4 requires the client to compare ETags
        when the server supplies them. None of the tested appliances
        emit option 4, so on those this is inert."""
        try:
            return self._blockwise_get_once(
                path_segs, query, timeout, extra_options)
        except _EtagChanged:
            logger.debug("GET %s /%s: ETag changed mid-transfer, restarting",
                         self.host, '/'.join(path_segs))
        try:
            return self._blockwise_get_once(
                path_segs, query, timeout, extra_options)
        except _EtagChanged:
            logger.debug(
                "GET %s /%s: representation kept changing mid-transfer",
                self.host, '/'.join(path_segs))
            raise BlockwiseError() from None

    def _blockwise_get_once(
            self, path_segs, query, timeout, extra_options):
        """One attempt at a full Block2 transfer. Raises _EtagChanged if
        the server's representation changed while we were reassembling."""
        tok = self._next_tok()
        accumulator = Block2Accumulator(tok, max_blocks=self.MAX_BLOCKS)
        etag = None
        deadline = time.monotonic() + timeout
        while not accumulator.complete:
            num = accumulator.expected_number
            self.pace()
            message = self._exchange_block(
                tok,
                path_segs,
                query,
                num,
                accumulator.szx,
                deadline,
                extra_options,
            )
            prior_blocks = accumulator.blocks_received

            # RFC 7959 §2.4: compare ETags across blocks, or we splice
            # two versions of the resource into one buffer.
            if message.code >> 5 == 2:
                block_etag = next(
                    (value for number, value in message.options
                     if number == ETAG),
                    None,
                )
                if prior_blocks == 0:
                    etag = block_etag
                elif etag is not None and block_etag != etag:
                    raise _EtagChanged()

            status = accumulator.add_response(message)
            if status == BLOCK2_COMPLETE:
                return (
                    accumulator.code,
                    accumulator.payload,
                    accumulator.blocks_received,
                    tok,
                )

        raise BlockwiseError()

    def _exchange_block(
            self, tok, path_segs, query, num, szx, deadline,
            extra_options):
        """Send one block request under `tok` and return its response
        message, retransmitting up to _BLOCK_MAX_ATTEMPTS times.

        A response whose Block2 NUM is not the one we asked for is a
        retransmit of an earlier block, not the next one. Concatenating
        it would corrupt the buffer, so keep waiting on the same
        attempt budget instead.

        Every attempt sends the byte-identical datagram, so the exchange is
        registered once outside the loop. RFC 7252 §4.2 defines a
        retransmission as the same message, and a fresh MID per attempt
        instead presents each retry to the appliance as a brand-new
        request that it may answer separately."""
        ev = threading.Event()
        container = {}
        mid, exchange = self._register_pending_request(tok, ev, container)
        datagram = build_get_request(
            TYPE_CON,
            mid,
            tok,
            path_segs,
            query,
            block_number=num if num > 0 else None,
            block_szx=szx,
            extra_options=extra_options,
        )
        try:
            for attempt in range(_BLOCK_MAX_ATTEMPTS):
                # Close the reader-death registration race: after this request
                # is visible to reader-finally, recheck that the reader still
                # owns the session before sending.
                self._check_live()
                if time.monotonic() >= deadline:
                    raise SessionTimeoutError()
                self._send_dgram(datagram)
                while True:
                    with self._state_lock:
                        error = container.get('err')
                        message = container.get('message')
                        if (error is None and message is not None
                                and self._block_num_matches(
                                    message, num, szx)):
                            return message
                        if error is None and message is not None:
                            logger.debug(
                                "GET %s /%s block %d: stale block, "
                                "still waiting",
                                self.host, '/'.join(path_segs), num,
                            )
                            for key in (
                                    'code', 'mtype', 'mid', 'options',
                                    'payload', 'message'):
                                container.pop(key, None)
                        acknowledged = exchange.acknowledged
                        ev.clear()
                    if error is not None:
                        raise error
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        if acknowledged:
                            raise SessionTimeoutError()
                        break
                    per_wait = (
                        remaining if acknowledged
                        else min(_BLOCK_ACK_TIMEOUT, max(0.1, remaining))
                    )
                    if not self._wait_live(ev, per_wait):
                        if acknowledged:
                            raise SessionTimeoutError()
                        break
                remaining = deadline - time.monotonic()
                if remaining <= 0 or attempt == _BLOCK_MAX_ATTEMPTS - 1:
                    logger.debug(
                        "GET %s /%s block %d: timed out after %d attempt(s)",
                        self.host, '/'.join(path_segs), num, attempt + 1,
                    )
                    raise SessionTimeoutError()
                logger.debug(
                    "GET %s /%s block %d: attempt %d/%d timeout, retrying",
                    self.host, '/'.join(path_segs), num,
                    attempt + 1, _BLOCK_MAX_ATTEMPTS,
                )
        finally:
            self._unregister_pending_request(tok, mid, exchange)
        raise SessionTimeoutError()

    def _wait_live(self, ev, per_wait):
        """Wait for one response, giving up early if the reader dies
        underneath us.

        Only the reader thread can resolve a token, so once it is gone
        the wait can never succeed. Polling in slices turns what would
        be a full per-attempt timeout into an immediate SessionClosedError,
        which is the same fail-fast contract get() and post() get from
        _check_live() at entry — it just has to hold for the whole
        exchange, not only its first moment."""
        deadline = time.monotonic() + per_wait
        while True:
            slice_s = min(
                _BLOCK_LIVENESS_POLL_S,
                deadline - time.monotonic(),
            )
            if slice_s <= 0:
                return False
            if ev.wait(slice_s):
                return True
            self._check_live()

    @staticmethod
    def _block_num_matches(message, num, szx):
        """Return whether ``message`` answers the requested byte offset."""
        if message.code >> 5 != 2:
            return True
        block2 = [value for number, value in message.options
                  if number == BLOCK2]
        if not block2:
            return num == 0
        response_num, _more, response_szx = block_fields(block2[0])
        requested_offset = num << (szx + 4)
        response_offset = response_num << (response_szx + 4)
        return response_offset == requested_offset

    @staticmethod
    def _block1_response_matches(message, container):
        """Return whether ``message`` can answer the pending Block1 chunk.

        A Block1 upload deliberately reuses its token across every chunk.
        Samsung can deliver an acknowledgement for the previous chunk after
        the next one is registered, so successful responses that carry Block1
        must cover the byte range currently pending. Responses without Block1
        are left to the caller's protocol validation: errors and a final 2.xx
        response may legitimately omit it, while an intermediate 2.31 may not.
        """
        expected_start = container.get('expected_block1_start')
        if message.code >> 5 != 2 or expected_start is None:
            return True
        block_values = [
            value for number, value in message.options if number == BLOCK1]
        if not block_values:
            return True
        if len(block_values) != 1 or len(block_values[0]) > 3:
            return False
        response_num, _response_more, response_szx = \
            block_fields(block_values[0])
        if response_szx > BLOCK_SZX:
            return False
        response_size = 1 << (response_szx + 4)
        response_start = response_num * response_size
        response_end = response_start + response_size
        expected_end = container['expected_block1_end']
        if container['expected_block1_more']:
            return response_end == expected_end
        return (
            response_start <= expected_start < response_end
            and expected_end <= response_end
        )

    def post(
            self, path_segs, body_cbor, timeout=8.0, *, query=(),
            extra_options=()):
        """POST a CBOR-encoded body and return (code, payload_bytes).

        Bodies through one 1024-byte OCF block retain the single-frame path.
        Larger bodies use token-stable Block1 framing. ``body_cbor`` must
        already be encoded.

        timeout bounds the whole call, pacing included, so post() returns
        within it rather than within it plus a rate-limit interval.

        Retransmits the CON up to write_max_attempts times within that
        deadline, reusing the same Message ID: that is what lets a
        server implementing RFC 7252 §4.5 answer a duplicate from its dedupe
        cache instead of re-running a non-idempotent write. A caller-side
        retry cannot offer that, since it mints a fresh MID and token.
        Defaults to one attempt — see _WRITE_ACK_TIMEOUT."""
        self._check_live()
        path_segs = _validated_text_options(
            path_segs, name='path_segs', allow_empty=False)
        query = _validated_text_options(
            query, name='query', allow_empty=False)
        extra_options = _validated_extra_options(extra_options)
        if not isinstance(body_cbor, bytes):
            raise TypeError('body_cbor must be bytes')
        if len(body_cbor) > _MAX_BLOCK1_BODY_BYTES:
            raise ValueError('body_cbor must contain at most 524288 bytes')
        block_size = 1 << (BLOCK_SZX + 4)
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        for q in query:
            opts.append((URI_QUERY, q.encode()))
        opts.append((CONTENT_FORMAT, CF_CBOR))
        opts.append((ACCEPT, CF_CBOR))
        if len(body_cbor) > block_size:
            return self._post_blockwise(
                path_segs,
                body_cbor,
                opts,
                extra_options,
                timeout=timeout,
            )
        tok = self._next_tok()
        opts.extend(extra_options)
        ev = threading.Event()
        container = {}
        mid, exchange = self._register_pending_request(tok, ev, container)
        # Built once and resent verbatim: §4.2 defines a retransmission as
        # the same message, and a fresh MID would present each retry to the
        # appliance as a brand-new write it may run again.
        datagram = build_coap(TYPE_CON, METHOD_POST, mid, tok, opts,
                              body_cbor)
        attempts = self._write_max_attempts
        # Armed before the first pace, not after the send: every attempt
        # shares one budget, and a caller that asked for 8s should not wait
        # 8s plus however long the rate limiter withheld the request.
        deadline = time.time() + timeout
        try:
            for attempt in range(attempts):
                self.pace()
                with self._state_lock:
                    answered = 'code' in container or 'err' in container
                    acknowledged = exchange.acknowledged
                # Neither can be true before the first send, so attempt 0 is
                # byte-for-byte the single send this used to do. On a
                # retransmit either one means the datagram arrived: the
                # answer landed while we paced, or the device acked it
                # separately and owes us only the response.
                if not answered:
                    # The reader can exit between the entry liveness check
                    # and the registration above, and again during any pace.
                    # Rechecking here closes that race — but only while
                    # nothing has answered, because an answer that beat a
                    # dying reader is a write the device confirmed and must
                    # not be discarded as a closed session.
                    self._check_live()
                    if not acknowledged:
                        try:
                            self._send_dgram(datagram)
                        except EndpointError:
                            # Attempt 0 is the caller's only datagram, so its
                            # failure is theirs to see. A retransmit is
                            # best-effort: a send can still fail locally,
                            # and the reader treats the same errnos as
                            # advisory. Failing the exchange on one would make
                            # retransmitting less robust than not bothering,
                            # while the original datagram may still be
                            # answered inside the budget already running.
                            if not attempt:
                                raise
                            logger.debug(
                                "POST %s /%s: retransmit %d/%d send failed",
                                self.host, '/'.join(path_segs),
                                attempt + 1, attempts,
                            )
                last = attempt == attempts - 1
                while True:
                    with self._state_lock:
                        error = container.get('err')
                        has_response = 'code' in container
                        response = (
                            (container['code'], container['payload'])
                            if has_response else None
                        )
                        if error is None and not has_response:
                            ev.clear()
                        acknowledged = exchange.acknowledged
                    if error is not None:
                        raise error
                    if has_response:
                        return response
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise SessionTimeoutError()
                    # An empty ACK stops retransmission (§5.2.2): the device
                    # took the write and owes only the separate response, so
                    # spend the rest of the caller's budget waiting for it.
                    if acknowledged or last:
                        per_wait = remaining
                    else:
                        per_wait = min(_WRITE_ACK_TIMEOUT * (2 ** attempt),
                                       remaining)
                    if self._wait_live(ev, per_wait):
                        continue        # something moved — re-read the state
                    if acknowledged or last:
                        raise SessionTimeoutError()
                    break               # attempt exhausted, retransmit
                # Retry only if the next attempt's pace still fits inside the
                # caller's deadline: pace() sleeps up to a whole interval, so
                # asking merely for "any budget left" returns late.
                if deadline - time.time() <= self._min_req_interval:
                    break
                logger.debug(
                    "POST %s /%s: attempt %d/%d timeout, retransmitting",
                    self.host, '/'.join(path_segs), attempt + 1, attempts,
                )
            raise SessionTimeoutError()
        finally:
            self._unregister_pending_request(tok, mid, exchange)

    def _post_blockwise(
            self, path_segs, body_cbor, base_options, extra_options, *,
            timeout):
        """Upload one bounded body with token-stable Block1 framing."""
        tok = self._next_tok()
        deadline = time.monotonic() + timeout
        offset = 0
        szx = BLOCK_SZX
        request_count = 0

        while offset < len(body_cbor):
            self._check_live()
            block_size = 1 << (szx + 4)
            if offset % block_size:
                raise BlockwiseError()
            num = offset // block_size
            chunk = body_cbor[offset:offset + block_size]
            end_offset = offset + len(chunk)
            more = int(end_offset < len(body_cbor))
            request_count += 1
            if request_count > _MAX_BLOCK1_REQUESTS:
                raise BlockwiseError()

            opts = list(base_options)
            opts.append((BLOCK1, block_value(num, more, szx)))
            if offset == 0:
                size_width = max(
                    1, (len(body_cbor).bit_length() + 7) // 8)
                opts.append((
                    SIZE1,
                    len(body_cbor).to_bytes(size_width, 'big'),
                ))
            opts.extend(extra_options)
            message = self._exchange_block1(
                tok,
                path_segs,
                opts,
                chunk,
                block_num=num,
                start=offset,
                end=end_offset,
                more=more,
                deadline=deadline,
            )
            code = message.code
            payload = message.payload
            response_blocks = [
                value for number, value in message.options
                if number == BLOCK1]

            if more:
                if code != 0x5F:
                    if code >> 5 == 2:
                        raise BlockwiseError()
                    return code, payload
                if len(response_blocks) > 1:
                    raise BlockwiseError()
                if not response_blocks or len(response_blocks[0]) > 3:
                    raise BlockwiseError()
                _response_num, response_more, response_szx = \
                    block_fields(response_blocks[0])
                if not response_more or response_szx > szx:
                    raise BlockwiseError()
                szx = response_szx
                if offset % (1 << (szx + 4)):
                    raise BlockwiseError()
                offset = end_offset
                continue

            if code >> 5 != 2:
                return code, payload
            if code == 0x5F:
                raise BlockwiseError()
            if len(response_blocks) > 1:
                raise BlockwiseError()
            if response_blocks:
                block = response_blocks[0]
                if len(block) > 3:
                    raise BlockwiseError()
                _response_num, response_more, response_szx = \
                    block_fields(block)
                if response_more or response_szx > szx:
                    raise BlockwiseError()
            return code, payload

        raise BlockwiseError()

    def _exchange_block1(
            self, tok, path_segs, options, payload, *, block_num, start, end,
            more, deadline):
        """Send one Block1 chunk under a stable token and Message ID."""
        ev = threading.Event()
        container = {
            'expected_block1_start': start,
            'expected_block1_end': end,
            'expected_block1_more': more,
        }
        mid, exchange = self._register_pending_request(tok, ev, container)
        try:
            datagram = build_coap(
                TYPE_CON, METHOD_POST, mid, tok, options, payload)
            for attempt in range(_BLOCK_MAX_ATTEMPTS):
                self.pace()
                with self._state_lock:
                    error = container.get('err')
                    message = container.get('message')
                    acknowledged = exchange.acknowledged
                # A response may land while a retry is being paced. Honour it
                # before checking reader liveness so a response dispatched just
                # before teardown is not discarded or resent.
                if error is not None:
                    raise error
                if message is not None:
                    return message
                self._check_live()
                if time.monotonic() >= deadline:
                    raise SessionTimeoutError()
                if not acknowledged:
                    try:
                        self._send_dgram(datagram)
                    except EndpointError:
                        if not attempt:
                            raise
                        logger.debug(
                            "POST %s /%s block %d: retransmit %d/%d "
                            "send failed",
                            self.host, '/'.join(path_segs), block_num,
                            attempt + 1, _BLOCK_MAX_ATTEMPTS,
                        )

                last = attempt == _BLOCK_MAX_ATTEMPTS - 1
                while True:
                    with self._state_lock:
                        error = container.get('err')
                        message = container.get('message')
                        if error is None and message is None:
                            ev.clear()
                        acknowledged = exchange.acknowledged
                    if error is not None:
                        raise error
                    if message is not None:
                        return message
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SessionTimeoutError()
                    per_wait = (
                        remaining if acknowledged
                        else min(_BLOCK_ACK_TIMEOUT, remaining)
                    )
                    if self._wait_live(ev, per_wait):
                        continue
                    if acknowledged or last:
                        raise SessionTimeoutError()
                    break

                if deadline - time.monotonic() <= self._min_req_interval:
                    break
                logger.debug(
                    "POST %s /%s block %d: attempt %d/%d timeout, "
                    "retransmitting",
                    self.host, '/'.join(path_segs), block_num,
                    attempt + 1, _BLOCK_MAX_ATTEMPTS,
                )
            raise SessionTimeoutError()
        finally:
            self._unregister_pending_request(tok, mid, exchange)

    def delete(
            self, path_segs, timeout=8.0, *, query=(), extra_options=()):
        """Single-frame DELETE. Returns (code, payload_bytes).

        ``timeout`` bounds the whole call, including request pacing.
        """
        self._check_live()
        path_segs = _validated_text_options(
            path_segs, name='path_segs', allow_empty=False)
        query = _validated_text_options(
            query, name='query', allow_empty=False)
        extra_options = _validated_extra_options(extra_options)
        tok = self._next_tok()
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        for q in query:
            opts.append((URI_QUERY, q.encode()))
        opts.append((ACCEPT, CF_CBOR))
        opts.extend(extra_options)
        ev = threading.Event()
        container = {}
        mid, exchange = self._register_pending_request(tok, ev, container)
        datagram = build_coap(TYPE_CON, METHOD_DELETE, mid, tok, opts)
        deadline = time.time() + timeout
        try:
            self.pace()
            self._check_live()
            self._send_dgram(datagram)
            while True:
                with self._state_lock:
                    error = container.get('err')
                    has_response = 'code' in container
                    response = (
                        (container['code'], container['payload'])
                        if has_response else None
                    )
                    if error is None and not has_response:
                        ev.clear()
                if error is not None:
                    raise error
                if has_response:
                    return response
                remaining = deadline - time.time()
                if remaining <= 0 or not self._wait_live(ev, remaining):
                    raise SessionTimeoutError()
        finally:
            self._unregister_pending_request(tok, mid, exchange)

    def ping(self):
        """RFC 7252 §4.4 CoAP Ping — empty CON, no token, no payload.
        Fire-and-forget: we do not wait for the matching RST because
        Samsung's RT-OCF doesn't reliably emit one (verified
        2026-06-04: every sync ping timed out while polls succeeded
        at 200+/window). The send itself is the keepalive — it
        tickles Samsung's observer state so OBSERVE subscriptions
        aren't aged out.

        Real half-open-session detection lives in PollScheduler's
        `last_success_ts`, surfaced through KeepaliveTask's
        `liveness_fn`."""
        self._check_live()
        mid = self._next_mid()
        self._send_dgram(build_coap(TYPE_CON, 0, mid, b'', []))
        return mid

    def refresh_observes(self, paths, *, queries_by_href=None):
        """Replace only the requested Observe paths and report send results.

        Existing query-separated relations are preserved unless an exact href
        is present in ``queries_by_href``. Deregistration is best-effort; each
        old local relation is retired even when its send fails. A successful
        href means its replacement registration datagram was sent, not that a
        later response has confirmed the relation.
        """
        with self._observe_operation_lock:
            return self._refresh_observes_locked(
                paths, queries_by_href=queries_by_href)

    def _refresh_observes_locked(self, paths, *, queries_by_href=None):
        self._check_live()
        normalized_paths = _validated_observe_paths(paths)
        target_hrefs = frozenset(href for _path, href in normalized_paths)
        query_overrides = _validated_observe_query_overrides(
            queries_by_href, target_hrefs)

        # Snapshot every target before any network work so query preservation
        # and the mutation set describe the same relation generation.
        with self._state_lock:
            observations = tuple(
                (tok, href, self._observe_queries.get(tok, ()))
                for tok, href in self._observe_tokens.items()
                if href in target_hrefs
            )

        preserved_queries = {}
        for _tok, href, query in observations:
            queries = preserved_queries.setdefault(href, [])
            if query not in queries:
                queries.append(query)

        for tok, href, query in observations:
            try:
                self.pace()
                self._send_observe_dereg(
                    tok, [segment for segment in href.split('/') if segment],
                    query)
            except Exception as e:
                logger.warning("refresh dereg %s: %s", href, e)
            finally:
                with self._state_lock:
                    self._retire_observe_token_locked(tok)
        self._discard_refetches_for_hrefs(target_hrefs)

        successful = []
        successful_hrefs = set()
        failures = 0
        for path, href in normalized_paths:
            queries = (
                (query_overrides[href],)
                if href in query_overrides
                else tuple(preserved_queries.get(href, ())) or ((),)
            )
            for query in queries:
                try:
                    # subscribe() owns pacing for its registration send.
                    self.subscribe(path, query=query)
                except Exception as e:
                    failures += 1
                    logger.warning("refresh subscribe %s: %s", href, e)
                else:
                    if href not in successful_hrefs:
                        successful.append(href)
                        successful_hrefs.add(href)
        return tuple(successful), failures

    def unsubscribe(self, path_segs):
        """Deregister and retire every active relation for one exact path."""
        with self._observe_operation_lock:
            return self._unsubscribe_locked(path_segs)

    def _unsubscribe_locked(self, path_segs):
        self._check_live()
        path_segs = _validated_text_options(
            path_segs, name='path_segs', allow_empty=False)
        href = '/' + '/'.join(path_segs)
        with self._state_lock:
            observations = tuple(
                (tok, self._observe_queries.get(tok, ()))
                for tok, observed_href in self._observe_tokens.items()
                if observed_href == href
            )

        first_error = None
        for tok, query in observations:
            try:
                self.pace()
                self._send_observe_dereg(tok, path_segs, query)
            except Exception as e:
                if first_error is None:
                    first_error = e
            finally:
                with self._state_lock:
                    self._retire_observe_token_locked(tok)
        self._discard_refetches_for_hrefs((href,))
        if first_error is not None:
            raise first_error
        return len(observations)

    def subscribe(self, path_segs, *, query=()):
        """Register an OBSERVE on the given path. The initial 2.05
        notification and all subsequent state-change notifications
        will fire on_notification(href, payload_bytes).

        Returns the token used (in case the caller wants to deregister
        later)."""
        with self._observe_operation_lock:
            return self._subscribe_locked(path_segs, query=query)

    def _subscribe_locked(self, path_segs, *, query=()):
        self._check_live()
        path_segs = _validated_text_options(
            path_segs, name='path_segs', allow_empty=False)
        query = _validated_text_options(
            query, name='query', allow_empty=False)
        self.pace()
        self._check_live()
        href = '/' + '/'.join(path_segs)
        # Register the token BEFORE sending — otherwise the device
        # could respond between send() and the dict insert, and the
        # reader thread would drop the initial 2.05 as "stale".
        with self._state_lock:
            tok = self._next_available_observe_tok_locked()
            self._observe_tokens[tok] = href
            self._observe_queries[tok] = query
            try:
                mid = self._next_available_mid_locked()
            except Exception:
                self._retire_observe_token_locked(tok)
                raise
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        for value in query:
            opts.append((URI_QUERY, value.encode()))
        opts.append((OBSERVE, OBSERVE_REGISTER))
        opts.append((ACCEPT, CF_CBOR))
        try:
            self._send_dgram(
                build_coap(TYPE_CON, METHOD_GET, mid, tok, opts))
        except Exception:
            with self._state_lock:
                self._retire_observe_token_locked(tok)
            raise
        return tok
