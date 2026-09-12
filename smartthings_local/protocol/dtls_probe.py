"""DTLS ClientHello probe — a cheap, deterministic liveness + diagnostic
primitive that sits in front of a full handshake.

Two problems this solves:

  1. Liveness.  A 1-byte UDP probe cannot tell a silent port from a real
     DTLS server: anything that doesn't return ICMP-unreachable looks
     "live", so a discovery loop pays the full HANDSHAKE_TIMEOUT_S
     (12 s) on every false-positive port.  A real DTLS server, by
     contrast, answers a ClientHello with a HelloVerifyRequest (RFC 6347
     §4.2.1 stateless cookie exchange) in ~1 RTT, *before* any
     certificate work.  So one ClientHello round-trip distinguishes the
     real port from dead ones deterministically and cheaply — then the
     expensive cert handshake is committed to exactly one port.

  2. Diagnosis.  The full handshake collapses "no DTLS server here",
     "server up but rejected my cert", and "server up but no shared
     cipher/version" into one opaque timeout/error.  Everything the
     server volunteers about itself — chosen cipher, its cert chain, its
     CertificateRequest, or a fatal Alert — arrives in its first flight,
     *before* we send our own certificate.  Driving the handshake only
     that far (no client cert required) characterizes a device.  This is
     how you tell an OCF-PKI-wall device (rejects at cert-verify) from a
     cipher/version mismatch without a cert it would ever accept.

The production probe generates its frozen ClientHello through the same OpenSSL
memory-BIO profile as DtlsCoapSession.connect(), including the exact cipher
list, security level, and MTU. The opt-in diagnostic drive retains the full
memory-BIO pump for characterizing later server flights.
"""

import concurrent.futures as cf
import math
import socket
import time
import warnings
from dataclasses import dataclass

from OpenSSL import SSL

from ..errors import ProbeError
from .auth import PskAuth, _DTLS_CIPHERS, _OCF_ROOT_CA, _load_pem_chain
from .coap import split_dtls
from .dtls_handshake import _drive_dtls_handshake
from .endpoint import open_host_filtered_udp_socket

# DTLS record content types (RFC 6347 §4.1)
_CT_CHANGE_CIPHER_SPEC = 20
_CT_ALERT = 21
_CT_HANDSHAKE = 22
_CT_APP_DATA = 23

# Handshake message types (RFC 5246 §7.4 / RFC 6347)
_HS_NAMES = {
    0: 'HelloRequest',
    1: 'ClientHello',
    2: 'ServerHello',
    3: 'HelloVerifyRequest',
    # RFC 5077. Sent in the clear ahead of the server's ChangeCipherSpec, so
    # a completed handshake legitimately reports it.
    4: 'NewSessionTicket',
    11: 'Certificate',
    12: 'ServerKeyExchange',
    13: 'CertificateRequest',
    14: 'ServerHelloDone',
    15: 'CertificateVerify',
    16: 'ClientKeyExchange',
    20: 'Finished',
}

# TLS alert descriptions (RFC 5246 §7.2) — the ones a picky OCF stack
# actually sends are called out; the rest are here so a probe never
# reports a bare number.
_ALERT_NAMES = {
    0: 'close_notify',
    10: 'unexpected_message',
    20: 'bad_record_mac',
    40: 'handshake_failure',
    42: 'bad_certificate',
    43: 'unsupported_certificate',
    44: 'certificate_revoked',
    45: 'certificate_expired',
    46: 'certificate_unknown',
    47: 'illegal_parameter',
    48: 'unknown_ca',
    49: 'access_denied',
    50: 'decode_error',
    51: 'decrypt_error',
    70: 'protocol_version',
    71: 'insufficient_security',
    80: 'internal_error',
    86: 'inappropriate_fallback',
    90: 'user_canceled',
    112: 'unrecognized_name',
    # RFC 4279 §2. The alert a PSK carrier fails with, so an `auth=PskAuth`
    # diagnosis names it instead of reporting a bare number.
    115: 'unknown_psk_identity',
    116: 'certificate_required',
}

# Outcome classes, coarsest first.
DEAD = 'dead'            # no DTLS response at all — silent/non-DTLS port
LIVE = 'live'            # DTLS server confirmed (HelloVerifyRequest/ServerHello)
COMPLETED = 'completed'  # full handshake succeeded (cert accepted)
REJECTED = 'rejected'    # server sent a fatal Alert

# Aggregate stateless-probe outcomes.
SELECTED = 'selected'
UNREACHABLE = 'unreachable'
AMBIGUOUS = 'ambiguous'

# First-flight response classes retained by the production liveness API.
HELLO_VERIFY_REQUEST = 'hello_verify_request'
SERVER_HELLO = 'server_hello'
ALERT = 'alert'

_DTLS_VERSIONS = frozenset((b'\xfe\xff', b'\xfe\xfd'))


@dataclass(frozen=True, slots=True)
class DtlsLivenessResult:
    """Bounded, non-sensitive result for one stateless port probe."""

    port: int
    response_kind: str | None
    attempts: int
    rtt_s: float | None = None
    alert: tuple[int, str] | None = None
    error_code: str | None = None

    @property
    def is_dtls_server(self):
        """Return whether a structurally valid first-flight reply arrived."""
        return self.response_kind is not None


@dataclass(frozen=True, slots=True)
class DtlsPortProbeResult:
    """Selection result for one bounded concurrent probe set."""

    outcome: str
    selected_port: int | None
    results: tuple[DtlsLivenessResult, ...]

    @property
    def live_ports(self):
        """Return proven listeners in caller-supplied order."""
        return tuple(
            result.port for result in self.results if result.is_dtls_server)


def _validate_liveness_options(port, retries, timeout, mtu):
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError('port must be an integer')
    if not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    if isinstance(retries, bool) or not isinstance(retries, int):
        raise TypeError('retries must be an integer')
    if not 0 <= retries <= 4:
        raise ValueError('retries must be between zero and four')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError('timeout must be a number')
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('timeout must be greater than zero and at most 30')
    if isinstance(mtu, bool) or not isinstance(mtu, int):
        raise TypeError('mtu must be an integer')
    if not 576 <= mtu <= 16384:
        raise ValueError('mtu is outside the safe UDP range')


def _validate_probe_family(family):
    if isinstance(family, bool) or not isinstance(family, int):
        raise TypeError('family must be an address-family integer')
    if family not in (socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6):
        raise ValueError('family must be AF_UNSPEC, AF_INET, or AF_INET6')


def _client_hello_flight(*, mtu):
    """Build and freeze the same narrow first flight as a real session."""
    context = SSL.Context(SSL.DTLS_METHOD)
    context.load_verify_locations(_OCF_ROOT_CA)
    context.set_verify(SSL.VERIFY_PEER, lambda *args: True)
    context.set_cipher_list(_DTLS_CIPHERS)

    connection = SSL.Connection(context, None)
    connection.set_connect_state()
    connection.set_ciphertext_mtu(mtu)
    try:
        connection.do_handshake()
    except SSL.WantReadError:
        pass

    records = []
    while True:
        try:
            outbound = connection.bio_read(65535)
        except SSL.WantReadError:
            break
        if not outbound:
            break
        records.extend(split_dtls(outbound))
    if not records:
        raise ProbeError()
    return tuple(records)


def _is_complete_hello_verify(body):
    """Validate the DTLS version and length-prefixed cookie."""
    return (
        len(body) >= 3
        and body[:2] in _DTLS_VERSIONS
        and len(body) == 3 + body[2]
    )


def _is_complete_server_hello(body):
    """Validate the fixed fields, session ID, and optional extensions."""
    if len(body) < 38 or body[:2] not in _DTLS_VERSIONS:
        return False
    session_id_length = body[34]
    if session_id_length > 32:
        return False
    fixed_end = 38 + session_id_length
    if len(body) == fixed_end:
        return True
    if len(body) < fixed_end + 2:
        return False
    extensions_length = int.from_bytes(body[fixed_end:fixed_end + 2], 'big')
    return len(body) == fixed_end + 2 + extensions_length


def _parse_liveness_response(datagram):
    """Return the kind and validated alert for an epoch-zero first flight."""
    records = split_dtls(datagram)
    if not records or sum(map(len, records)) != len(datagram):
        return None, None

    fallback_kind = None
    fallback_alert = None
    for record in records:
        if len(record) < 13 or record[1:3] not in _DTLS_VERSIONS:
            continue
        if record[3:5] != b'\x00\x00':
            continue
        fragment = record[13:]
        if record[0] == _CT_HANDSHAKE:
            offset = 0
            while offset + 12 <= len(fragment):
                header = fragment[offset:offset + 12]
                message_length = int.from_bytes(header[1:4], 'big')
                fragment_offset = int.from_bytes(header[6:9], 'big')
                fragment_length = int.from_bytes(header[9:12], 'big')
                end = offset + 12 + fragment_length
                if end > len(fragment):
                    break
                if fragment_offset == 0 and fragment_length == message_length:
                    body = fragment[offset + 12:end]
                    if header[0] == 3 and _is_complete_hello_verify(body):
                        return HELLO_VERIFY_REQUEST, None
                    if header[0] == 2 and _is_complete_server_hello(body):
                        if fallback_kind is None:
                            fallback_kind = SERVER_HELLO
                offset = end
        elif record[0] == _CT_ALERT and len(fragment) == 2:
            level, description = fragment
            fallback_kind = ALERT
            fallback_alert = (
                level,
                _ALERT_NAMES.get(description, str(description)),
            )
            if level == 2:
                return fallback_kind, fallback_alert
    return fallback_kind, fallback_alert


def _classify_liveness_response(datagram):
    """Classify a structurally complete epoch-zero DTLS first flight."""
    return _parse_liveness_response(datagram)[0]


def _probe_dtls_port_with_flight(
        host, port, *, flight, timeout, retries, family):
    """Send one frozen ClientHello flight on a host-filtered UDP socket."""
    attempt_budget = float(timeout) / (retries + 1)
    attempts = 0
    sock = None
    try:
        sock, _endpoint = open_host_filtered_udp_socket(
            host,
            port,
            family=family,
            timeout=attempt_budget,
        )
        started = time.monotonic()
        for attempts in range(1, retries + 2):
            for record in flight:
                if sock.send(record) != len(record):
                    raise OSError('short UDP send')
            attempt_deadline = started + attempts * attempt_budget
            while True:
                remaining = attempt_deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    datagram = sock.recv(65535)
                except TimeoutError:
                    break
                response_kind, alert = _parse_liveness_response(datagram)
                if response_kind is None:
                    # The socket already rejects other hosts, and an
                    # appliance may legitimately answer from a port other than
                    # the one dialled. An unrelated or malformed datagram from
                    # it must still not consume a retransmission or count as
                    # DTLS proof.
                    continue
                return DtlsLivenessResult(
                    port=port,
                    response_kind=response_kind,
                    attempts=attempts,
                    rtt_s=time.monotonic() - started,
                    alert=alert,
                )
        return DtlsLivenessResult(
            port=port,
            response_kind=None,
            attempts=attempts,
            error_code='no_dtls_response',
        )
    except OSError:
        return DtlsLivenessResult(
            port=port,
            response_kind=None,
            attempts=attempts,
            error_code='endpoint_unavailable',
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_dtls_port(
        host, port, *, timeout=3.0, retries=2, mtu=1200,
        family=socket.AF_UNSPEC):
    """Prove one DTLS listener without sending a cookie-bearing flight.

    The ClientHello is generated once. Packet-loss retries resend those exact
    bytes and no response is ever fed back into OpenSSL, so this function
    cannot emit a second ClientHello or allocate a server association.

    ``timeout`` bounds socket I/O after synchronous platform name resolution;
    resolver timing remains controlled by the operating system.
    """
    _validate_liveness_options(port, retries, timeout, mtu)
    _validate_probe_family(family)
    try:
        flight = _client_hello_flight(mtu=mtu)
    except Exception:  # noqa: BLE001 - return only a fixed failure code
        return DtlsLivenessResult(
            port=port,
            response_kind=None,
            attempts=0,
            error_code='client_hello_unavailable',
        )
    return _probe_dtls_port_with_flight(
        host,
        port,
        flight=flight,
        timeout=timeout,
        retries=retries,
        family=family,
    )


def probe_dtls_ports(
        host, ports, *, preferred_port=None, timeout=3.0, retries=2,
        mtu=1200, family=socket.AF_UNSPEC):
    """Probe a bounded port set concurrently and select without guessing.

    One proven listener is selected. If multiple listeners answer, a proven
    ``preferred_port`` wins; otherwise the explicit outcome is ``ambiguous``.
    Results preserve the caller's de-duplicated port order. Each worker's
    ``timeout`` starts after synchronous platform name resolution.
    """
    _validate_probe_family(family)
    ordered_ports = tuple(dict.fromkeys(ports))
    if not ordered_ports:
        return DtlsPortProbeResult(UNREACHABLE, None, ())
    if len(ordered_ports) > 32:
        raise ValueError('at most 32 DTLS ports may be probed')
    for port in ordered_ports:
        _validate_liveness_options(port, retries, timeout, mtu)
    if preferred_port is not None:
        _validate_liveness_options(preferred_port, retries, timeout, mtu)

    try:
        flight = _client_hello_flight(mtu=mtu)
    except Exception:  # noqa: BLE001 - duplicate one fixed result per port
        results = tuple(
            DtlsLivenessResult(
                port=port,
                response_kind=None,
                attempts=0,
                error_code='client_hello_unavailable',
            )
            for port in ordered_ports
        )
        return DtlsPortProbeResult(UNREACHABLE, None, results)

    by_port = {}
    with cf.ThreadPoolExecutor(
            max_workers=len(ordered_ports),
            thread_name_prefix='smartthings-dtls-probe') as executor:
        futures = {
            executor.submit(
                _probe_dtls_port_with_flight,
                host,
                port,
                flight=flight,
                timeout=timeout,
                retries=retries,
                family=family,
            ): port
            for port in ordered_ports
        }
        for future in cf.as_completed(futures):
            port = futures[future]
            try:
                by_port[port] = future.result()
            except Exception:  # noqa: BLE001 - isolate one bounded worker
                by_port[port] = DtlsLivenessResult(
                    port=port,
                    response_kind=None,
                    attempts=0,
                    error_code='probe_worker_failed',
                )

    results = tuple(by_port[port] for port in ordered_ports)
    live_ports = tuple(
        result.port for result in results if result.is_dtls_server)
    if preferred_port is not None and preferred_port in live_ports:
        return DtlsPortProbeResult(SELECTED, preferred_port, results)
    if len(live_ports) == 1:
        return DtlsPortProbeResult(SELECTED, live_ports[0], results)
    if live_ports:
        return DtlsPortProbeResult(AMBIGUOUS, None, results)
    return DtlsPortProbeResult(UNREACHABLE, None, results)


class ProbeResult:
    """What a single ClientHello probe learned about one host:port."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.outcome = DEAD
        self.rtt_s = None
        # Ordered, de-duplicated handshake message names the server sent.
        self.handshake_msgs = []
        # (level, description_name) if a fatal/warning Alert was seen.
        self.alert = None
        # Raw inbound datagrams, for callers that want to dig deeper.
        self.datagrams = []
        self.error = None

    @property
    def is_dtls_server(self):
        """True when a DTLS server was proven present, regardless of
        whether it liked our credentials."""
        return self.outcome in (LIVE, COMPLETED, REJECTED)

    def __repr__(self):
        bits = [f'{self.host}:{self.port}', self.outcome]
        if self.rtt_s is not None:
            bits.append(f'{self.rtt_s * 1000:.0f}ms')
        if self.handshake_msgs:
            bits.append('+'.join(self.handshake_msgs))
        if self.alert:
            bits.append(f'alert={self.alert[1]}')
        if self.error:
            bits.append(f'err={self.error}')
        return f'<ProbeResult {" ".join(bits)}>'


def classify_datagram(dgram):
    """Parse one inbound UDP datagram into a list of
    (content_type, detail) tuples — detail is the handshake message name
    for handshake records, an (level, description_name) tuple for alerts,
    or None otherwise.  Pure; safe to unit-test on captured bytes."""
    out = []
    for rec in split_dtls(dgram):
        ct = rec[0]
        frag = rec[13:]
        if ct == _CT_HANDSHAKE and frag:
            out.append((ct, _HS_NAMES.get(frag[0], f'hs{frag[0]}')))
        elif ct == _CT_ALERT and len(frag) >= 2:
            out.append((ct, (frag[0], _ALERT_NAMES.get(frag[1], str(frag[1])))))
        else:
            out.append((ct, None))
    return out


def probe(host, port, *, cert_pem=None, key_pem=None,
          cert_path=None, key_path=None,
          stateless=True, retries=2, timeout=3.0, mtu=1200,
          family=socket.AF_UNSPEC):
    """Run the backward-compatible stateless liveness probe.

    Production callers should prefer :func:`probe_dtls_port`, whose immutable
    result cannot retain remote datagrams or host names. This adapter preserves
    the original ``ProbeResult`` shape. ``stateless=False`` remains only as a
    deprecated compatibility path to the explicitly named stateful diagnostic.

    Never raises on a network/handshake failure — those are folded into
    the ProbeResult so a discovery loop can race many ports safely.
    """
    if not stateless:
        warnings.warn(
            'probe(stateless=False) is deprecated; use '
            'diagnose_dtls_handshake() explicitly',
            DeprecationWarning,
            stacklevel=2,
        )
        return diagnose_dtls_handshake(
            host,
            port,
            cert_pem=cert_pem,
            key_pem=key_pem,
            cert_path=cert_path,
            key_path=key_path,
            retries=retries,
            timeout=timeout,
            mtu=mtu,
            family=family,
        )

    result = ProbeResult(host, port)
    liveness = probe_dtls_port(
        host,
        port,
        timeout=timeout,
        retries=retries,
        mtu=mtu,
        family=family,
    )
    if liveness.response_kind == HELLO_VERIFY_REQUEST:
        result.outcome = LIVE
        result.handshake_msgs.append('HelloVerifyRequest')
    elif liveness.response_kind == SERVER_HELLO:
        result.outcome = LIVE
        result.handshake_msgs.append('ServerHello')
    elif liveness.response_kind == ALERT:
        result.alert = liveness.alert
        result.outcome = (
            REJECTED
            if liveness.alert is not None and liveness.alert[0] == 2
            else LIVE
        )
    result.rtt_s = liveness.rtt_s
    if liveness.error_code not in (None, 'no_dtls_response'):
        result.error = ProbeError()
    return result


def _accept_any_peer_chain(*_args):
    """Accept any chain a server sends.

    A probe classifies what arrives; it does not gate on our trust decision.
    """
    return True


def _validate_diagnostic_auth(auth, cert_pem, key_pem, cert_path, key_path):
    if auth is None:
        return
    if (cert_pem is not None or key_pem is not None
            or cert_path is not None or key_path is not None):
        raise ValueError(
            'pass either auth or cert_pem/key_pem/cert_path/key_path, '
            'not both')
    if not callable(getattr(auth, 'configure_context', None)):
        raise TypeError('auth must be an AuthenticationProvider')


def _diagnostic_context(*, auth, cert_pem, key_pem, cert_path, key_path):
    """Build one diagnostic context that never gates on our trust decision."""
    ctx = SSL.Context(SSL.DTLS_METHOD)
    ctx.load_verify_locations(_OCF_ROOT_CA)
    ctx.set_verify(SSL.VERIFY_PEER, _accept_any_peer_chain)
    ctx.set_cipher_list(_DTLS_CIPHERS)
    if auth is not None:
        auth.configure_context(ctx)
        # Providers configure a context to *gate* on trust: CertificateAuth
        # installs OpenSSL's own verdict, and a SamsungServerProfile pins an
        # identity from inside the verify callback. Either one turns an
        # appliance's alert into a local verify failure, which is the single
        # thing a diagnostic must not do, so accept-any is re-asserted last.
        # A PSK provider's cipher list survives that, because VERIFY_PEER is
        # never consulted for a ciphersuite carrying no certificate.
        ctx.set_verify(SSL.VERIFY_PEER, _accept_any_peer_chain)
    elif cert_pem is not None:
        _load_pem_chain(ctx, cert_pem, key_pem)
    elif cert_path is not None:
        ctx.use_certificate_chain_file(cert_path)
        ctx.use_privatekey_file(key_path)
        ctx.check_privatekey()
    return ctx


def diagnose_dtls_handshake(
        host, port, *, auth=None, cert_pem=None, key_pem=None,
        cert_path=None, key_path=None,
        retries=2, timeout=3.0, mtu=1200,
        family=socket.AF_UNSPEC):
    """Opt in to a stateful DTLS handshake for protocol diagnosis.

    Unlike :func:`probe_dtls_port`, this function feeds the server flight back
    into OpenSSL. It can therefore emit a cookie-bearing second ClientHello and
    allocate appliance-side association state. Keep it out of discovery,
    reconnect, and other production liveness paths.

    ``auth`` takes any :mod:`~smartthings_local.protocol.auth` authentication
    provider, so a PSK carrier can be diagnosed on the same footing as a
    certificate one. It is mutually exclusive with the
    ``cert_pem``/``key_pem``/``cert_path``/``key_path`` inputs, which remain
    supported for certificate credentials.

    A diagnostic never enforces trust, whichever credential reaches it. A
    provider's own verification, including a ``SamsungServerProfile``'s pinned
    server identity, is deliberately not honoured here: the result has to
    report what the appliance did, so an untrusted chain is classified rather
    than rejected locally. Use :class:`DtlsCoapSession` for a session that
    does gate on trust.
    """
    _validate_liveness_options(port, retries, timeout, mtu)
    _validate_probe_family(family)
    _validate_diagnostic_auth(auth, cert_pem, key_pem, cert_path, key_path)
    result = ProbeResult(host, port)

    ctx = _diagnostic_context(
        auth=auth,
        cert_pem=cert_pem,
        key_pem=key_pem,
        cert_path=cert_path,
        key_path=key_path,
    )

    conn = SSL.Connection(ctx, None)
    conn.set_connect_state()
    conn.set_ciphertext_mtu(mtu)

    try:
        sock, _endpoint = open_host_filtered_udp_socket(
            host,
            port,
            family=family,
            timeout=min(0.5, timeout),
        )
    except OSError:
        result.error = ProbeError()
        return result

    started = time.monotonic()
    deadline = started + timeout
    seen = set()
    encrypted = False

    def record_datagram(datagram):
        nonlocal encrypted
        if result.rtt_s is None:
            result.rtt_s = time.monotonic() - started
        result.datagrams.append(datagram)
        for content_type, detail in classify_datagram(datagram):
            if content_type == _CT_CHANGE_CIPHER_SPEC:
                # Handshake records after this one are encrypted, so their
                # first byte is ciphertext and not a message type. Reading it
                # as one invents a message: roughly one ciphertext byte in
                # 256 collides with a name in _HS_NAMES, which is frequent
                # enough to have produced a phantom 'Finished' in testing.
                encrypted = True
            elif content_type == _CT_HANDSHAKE and not encrypted:
                if detail not in seen:
                    seen.add(detail)
                    result.handshake_msgs.append(detail)
                if result.outcome == DEAD:
                    result.outcome = LIVE
            elif content_type == _CT_ALERT and detail is not None:
                level, name = detail
                result.alert = (level, name)
                if level == 2:  # fatal
                    result.outcome = REJECTED

    try:
        completed = _drive_dtls_handshake(
            conn,
            sock,
            deadline=deadline,
            retries=retries,
            on_datagram=record_datagram,
        )
        if completed:
            result.outcome = COMPLETED
            if result.rtt_s is None:
                result.rtt_s = time.monotonic() - started
    except SSL.Error:
        # A fatal Alert lands here; record_datagram() has already classified
        # the alert record before it is fed back into OpenSSL.
        result.error = ProbeError()
    except OSError:
        result.error = ProbeError()
    finally:
        sock.close()

    return result


def _main(argv):
    import concurrent.futures as cf

    if len(argv) < 2:
        print('usage: python -m smartthings_local.protocol.dtls_probe '
              'HOST PORT [PORT...] [--diagnostic]\n'
              '         [--cert FILE --key FILE]\n'
              '         [--psk-identity HEX --psk-key HEX]\n'
              'A PSK passed here is visible to every process on the host; '
              'use a throwaway value.')
        return 2
    host = argv[0]
    cert_path = key_path = None
    psk_identity = psk_key = None
    diagnostic = False
    ports = []
    it = iter(argv[1:])
    for a in it:
        if a == '--cert':
            cert_path = next(it)
        elif a == '--key':
            key_path = next(it)
        elif a == '--psk-identity':
            psk_identity = next(it)
        elif a == '--psk-key':
            psk_key = next(it)
        elif a == '--diagnostic':
            diagnostic = True
        elif a == '--stateless':
            # Compatibility no-op: stateless is now the fail-safe default.
            pass
        else:
            ports.append(int(a))
    if not ports:
        print('at least one PORT is required')
        return 2
    ports = list(dict.fromkeys(ports))
    if len(ports) > 32:
        print('at most 32 PORT values may be probed')
        return 2
    if (cert_path is None) != (key_path is None):
        print('--cert and --key must be supplied together')
        return 2
    if (psk_identity is None) != (psk_key is None):
        print('--psk-identity and --psk-key must be supplied together')
        return 2
    if cert_path is not None and psk_identity is not None:
        print('pass either --cert/--key or --psk-identity/--psk-key, '
              'not both')
        return 2
    credential_supplied = cert_path is not None or psk_identity is not None
    if not diagnostic and credential_supplied:
        print('a credential requires the explicit --diagnostic mode')
        return 2

    auth = None
    if psk_identity is not None:
        try:
            auth = PskAuth(
                identity=bytes.fromhex(psk_identity),
                key=bytes.fromhex(psk_key),
            )
        except ValueError as exc:
            print(f'invalid PSK credential: {exc}')
            return 2

    credential_kwargs = (
        {'auth': auth}
        if auth is not None
        else {'cert_path': cert_path, 'key_path': key_path}
    )
    target = diagnose_dtls_handshake if diagnostic else probe
    with cf.ThreadPoolExecutor(max_workers=max(1, len(ports))) as ex:
        futs = {ex.submit(target, host, p, **credential_kwargs): p
                for p in ports}
        results = [f.result() for f in cf.as_completed(futs)]

    for r in sorted(results, key=lambda r: r.port):
        print(r)
    return 0


if __name__ == '__main__':
    import sys
    raise SystemExit(_main(sys.argv[1:]))
