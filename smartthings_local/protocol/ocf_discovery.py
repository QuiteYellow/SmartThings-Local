"""Bounded discovery of OCF-advertised secure UDP ports.

Samsung appliances normally receive public CoAP discovery on UDP 5683, but
some firmware sends the response from a different source port. This module
therefore uses unconnected UDP sockets, validates the resolved target address
and CoAP token, then pins the first valid response endpoint for the remainder
of each bounded Block2 transfer.

Discovery first reads the unfiltered ``/oic/res`` directory and accepts only
secure ``eps`` entries bound to that response source. If the representation
contains no secure endpoint, a second, separately correlated
``/oic/res?rt=oic.r.doxm`` lookup supports legacy ``p.sec``/``port`` forms.
Both lookups share one monotonic socket-I/O deadline.

Directory discovery learns advertised candidates, including ports outside a
caller's conventional scan set. It does not prove that a DTLS service is
present: callers should pass the returned candidates to ``probe_dtls_ports``.
Neither operation authenticates a device, transfers ownership, or writes an
OCF security resource.
"""

from __future__ import annotations

import io
import math
import secrets
import selectors
import socket
import time
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

import cbor2

from ..errors import BlockwiseError, MalformedMessageError
from .coap import (
    BLOCK2_DUPLICATE,
    CF_CBOR,
    RESPONSE_MESSAGE,
    TYPE_CON,
    TYPE_NON,
    Block2Accumulator,
    build_get_request,
    classify_coap_response,
)
from .endpoint import ResolvedUdpEndpoint, resolve_udp_endpoints

__all__ = [
    'OcfSecurePortDiscoveryResult',
    'discover_ocf_secure_ports',
]

_DISCOVERY_PORT = 5683
_MAX_ENDPOINTS = 8
_MAX_PORTS = 8
_MAX_BLOCKS = 32
_MAX_DATAGRAM_BYTES = 8192
_MAX_PAYLOAD_BYTES = 65536
_MAX_LINKS = 256
_MAX_ENDPOINT_URIS_PER_LINK = 32
_OCF_CBOR_CONTENT_FORMAT = 10000
_CONTENT = 0x45
_PRIMARY_QUERY = ()
_FALLBACK_QUERY = (b'rt=oic.r.doxm',)
_UNSET = object()

_TRANSFER_COMPLETE = 'complete'
_TRANSFER_ENDPOINT_UNAVAILABLE = 'endpoint_unavailable'
_TRANSFER_MALFORMED = 'malformed'
_TRANSFER_NO_RESPONSE = 'no_response'

_PORTS_FOUND = 'ports'
_PORTS_ABSENT = 'absent'
_PORTS_MALFORMED = 'malformed'
_PORTS_UNTRUSTED = 'untrusted'

_ENDPOINT_IGNORE = 'ignore'
_ENDPOINT_MATCH = 'match'
_ENDPOINT_UNTRUSTED = 'untrusted'


@dataclass(frozen=True, slots=True, repr=False)
class OcfSecurePortDiscoveryResult:
    """Redacted outcome of one bounded secure-port discovery operation.

    ``attempts`` counts logical request attempts across the primary and, when
    needed, fallback lookup rather than destination addresses.
    ``response_received`` is true when either lookup accepted at least one
    correlated response. The custom representation deliberately omits
    discovered ports, addresses, and wire data.
    """

    ports: tuple[int, ...]
    attempts: int
    response_received: bool
    error_code: str | None = None

    @property
    def found(self):
        """Return whether at least one validated secure port was advertised."""
        return bool(self.ports)

    def __repr__(self):
        return (
            'OcfSecurePortDiscoveryResult('
            f'found={self.found!r}, port_count={len(self.ports)}, '
            f'attempts={self.attempts}, '
            f'response_received={self.response_received!r}, '
            f'error_code={self.error_code!r})'
        )


@dataclass(slots=True, repr=False)
class _Route:
    sock: socket.socket
    endpoint: ResolvedUdpEndpoint
    host_key: tuple[bytes, int]


@dataclass(frozen=True, slots=True, repr=False)
class _TransferResult:
    status: str
    payload: bytes
    code: int | None
    family: int | None
    source_key: tuple[bytes, int] | None
    attempts: int
    response_received: bool


def _validate_options(discovery_port, timeout, retries, family):
    if isinstance(discovery_port, bool) or not isinstance(discovery_port, int):
        raise TypeError('discovery_port must be an integer')
    if not 1 <= discovery_port <= 65535:
        raise ValueError('discovery_port must be between 1 and 65535')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError('timeout must be a number')
    if not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError('timeout must be greater than zero and at most 30')
    if isinstance(retries, bool) or not isinstance(retries, int):
        raise TypeError('retries must be an integer')
    if not 0 <= retries <= 4:
        raise ValueError('retries must be between zero and four')
    if isinstance(family, bool) or not isinstance(family, int):
        raise TypeError('family must be an address-family integer')
    if family not in (socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6):
        raise ValueError('family must be AF_UNSPEC, AF_INET, or AF_INET6')


def _host_key(family, sockaddr):
    """Return canonical address bytes plus an IPv6 scope ID."""
    expected_length = 2 if family == socket.AF_INET else 4
    if not isinstance(sockaddr, tuple) or len(sockaddr) != expected_length:
        return None
    host = sockaddr[0]
    if not isinstance(host, str):
        return None
    if family == socket.AF_INET6:
        host = host.split('%', 1)[0]
    try:
        packed = socket.inet_pton(family, host)
    except OSError:
        return None
    scope_id = sockaddr[3] if family == socket.AF_INET6 else 0
    if isinstance(scope_id, bool) or not isinstance(scope_id, int):
        return None
    return packed, scope_id


def _peer_key(family, sockaddr):
    host_key = _host_key(family, sockaddr)
    if host_key is None:
        return None
    port = sockaddr[1]
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    if not 1 <= port <= 65535:
        return None
    return family, host_key[0], port, host_key[1]


def _open_routes(endpoints, selector):
    routes = []
    for endpoint in endpoints[:_MAX_ENDPOINTS]:
        key = _host_key(endpoint.family, endpoint.sockaddr)
        if key is None:
            continue
        sock = None
        try:
            sock = socket.socket(
                endpoint.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.bind(endpoint.bind_address(0))
            sock.setblocking(False)
            route = _Route(sock, endpoint, key)
            selector.register(sock, selectors.EVENT_READ, route)
            routes.append(route)
        except (OSError, ValueError):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return routes


def _decode_cbor(payload):
    stream = io.BytesIO(payload)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception:  # noqa: BLE001 - untrusted CBOR must fail closed
        return _UNSET
    if stream.tell() != len(payload):
        return _UNSET
    return value


def _resource_links(value):
    """Return a shallow, bounded OCF link sequence or ``None``."""
    containers = value if isinstance(value, list) else [value]
    if not all(isinstance(container, dict) for container in containers):
        return None

    links = []
    for container in containers:
        if 'links' in container:
            nested = container.get('links')
            if not isinstance(nested, list):
                return None
            candidates = nested
        elif 'href' in container:
            candidates = [container]
        else:
            candidates = []
        for link in candidates:
            if not isinstance(link, dict):
                return None
            links.append(link)
            if len(links) > _MAX_LINKS:
                return None
    return links


def _uri_scope_id(zone):
    if not zone:
        return None
    if zone.isdecimal():
        value = int(zone, 10)
        return value if value <= 0xFFFFFFFF else None
    try:
        return socket.if_nametoindex(zone)
    except (OSError, ValueError):
        return None


def _secure_endpoint_for_source(value, family, source_key):
    """Classify one endpoint URI without resolving untrusted hostnames."""
    if not isinstance(value, str):
        return _ENDPOINT_IGNORE, None
    secure_hint = value.lower().startswith('coaps:')
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError:
        return (_ENDPOINT_UNTRUSTED if secure_hint else _ENDPOINT_IGNORE), None

    if parsed.scheme.lower() != 'coaps':
        return _ENDPOINT_IGNORE, None
    if (not hostname or username is not None or password is not None
            or parsed.path or parsed.query or parsed.fragment
            or parsed.netloc.endswith(':')):
        return _ENDPOINT_UNTRUSTED, None

    hostname = unquote(hostname)
    scope_id = 0
    if family == socket.AF_INET6:
        if '%' in hostname:
            address, zone = hostname.rsplit('%', 1)
            scope_id = _uri_scope_id(zone)
            if scope_id is None:
                return _ENDPOINT_UNTRUSTED, None
        else:
            address = hostname
            # A zone identifier is local to the receiver. An omitted zone in
            # an advertised link-local URI is interpreted in the exact scope
            # on which the correlated datagram arrived.
            scope_id = source_key[1]
    else:
        if '%' in hostname:
            return _ENDPOINT_UNTRUSTED, None
        address = hostname

    try:
        packed = socket.inet_pton(family, address)
    except OSError:
        # Do not perform DNS for a hostname supplied by an unauthenticated
        # directory response.
        return _ENDPOINT_UNTRUSTED, None
    if (packed, scope_id) != source_key:
        return _ENDPOINT_UNTRUSTED, None

    if port is None:
        port = 5684
    if not 1 <= port <= 65535:
        return _ENDPOINT_UNTRUSTED, None
    return _ENDPOINT_MATCH, port


def _add_port(ports, seen, port):
    if (isinstance(port, bool) or not isinstance(port, int)
            or not 1 <= port <= 65535 or port in seen):
        return
    seen.add(port)
    if len(ports) < _MAX_PORTS:
        ports.append(port)


def _ports_from_links(links, family, source_key, *, fallback):
    ports = []
    seen = set()
    saw_untrusted = False

    for link in links:
        if fallback:
            if link.get('href') != '/oic/sec/doxm':
                continue
            resource_types = link.get('rt')
            if isinstance(resource_types, str):
                resource_types = [resource_types]
            if (not isinstance(resource_types, list)
                    or 'oic.r.doxm' not in resource_types):
                continue

            policy = link.get('p')
            if isinstance(policy, dict) and policy.get('sec') is True:
                _add_port(ports, seen, policy.get('port'))

        endpoints = link.get('eps')
        if not isinstance(endpoints, list):
            continue
        for endpoint in endpoints[:_MAX_ENDPOINT_URIS_PER_LINK]:
            if not isinstance(endpoint, dict):
                continue
            status, port = _secure_endpoint_for_source(
                endpoint.get('ep'), family, source_key)
            if status == _ENDPOINT_MATCH:
                _add_port(ports, seen, port)
            elif status == _ENDPOINT_UNTRUSTED:
                saw_untrusted = True

    if ports:
        return _PORTS_FOUND, tuple(ports)
    if saw_untrusted:
        return _PORTS_UNTRUSTED, ()
    return _PORTS_ABSENT, ()


def _primary_secure_ports_from_payload(payload, family, source_key):
    value = _decode_cbor(payload)
    if value is _UNSET:
        return _PORTS_MALFORMED, ()
    links = _resource_links(value)
    if links is None:
        return _PORTS_MALFORMED, ()
    return _ports_from_links(links, family, source_key, fallback=False)


def _fallback_secure_ports_from_payload(payload, family, source_key):
    value = _decode_cbor(payload)
    if value is _UNSET:
        return _PORTS_MALFORMED, ()
    links = _resource_links(value)
    if links is None:
        return _PORTS_MALFORMED, ()
    return _ports_from_links(links, family, source_key, fallback=True)


def _transfer_result(
        status, *, attempts, response_received, accumulator=None, route=None):
    complete = accumulator is not None and accumulator.complete
    return _TransferResult(
        status=status,
        payload=accumulator.payload if complete else b'',
        code=accumulator.code if complete else None,
        family=route.endpoint.family if complete and route is not None else None,
        source_key=route.host_key if complete and route is not None else None,
        attempts=attempts,
        response_received=response_received,
    )


def _fetch_directory(
        routes, selector, *, query, cutoff, retries, used_mids):
    """Fetch one representation without retaining an address in its repr."""
    token = secrets.token_bytes(8)
    accumulator = Block2Accumulator(
        token,
        max_blocks=_MAX_BLOCKS,
        max_payload_bytes=_MAX_PAYLOAD_BYTES,
        accepted_content_formats={
            int.from_bytes(CF_CBOR, 'big'),
            _OCF_CBOR_CONTENT_FORMAT,
        },
    )
    wait_slice = max(
        0.0,
        min(1.0, (cutoff - time.monotonic()) / (retries + 1)),
    )
    attempts = 0
    response_received = False
    saw_malformed = False
    pinned_route = None
    pinned_peer = None
    pinned_destination = None

    while not accumulator.complete:
        accepted = False
        sent_for_block = False
        for block_attempt in range(retries + 1):
            if time.monotonic() >= cutoff:
                break
            mid = secrets.randbits(16)
            while mid in used_mids:
                mid = (mid + 1) & 0xFFFF
            used_mids.add(mid)
            request = build_get_request(
                TYPE_NON,
                mid,
                token,
                (b'oic', b'res'),
                query,
                block_number=(
                    accumulator.expected_number
                    if accumulator.expected_number > 0 else None
                ),
                block_szx=accumulator.szx,
            )
            send_routes = [pinned_route] if pinned_route else routes
            sent = False
            for route in send_routes:
                try:
                    destination = (
                        pinned_destination
                        if route is pinned_route and pinned_destination
                        else route.endpoint.sockaddr
                    )
                    sent_length = route.sock.sendto(request, destination)
                    sent = sent or sent_length == len(request)
                except OSError:
                    continue
            attempts += 1
            if not sent:
                continue
            sent_for_block = True

            now = time.monotonic()
            attempt_deadline = (
                cutoff if block_attempt == retries
                else min(cutoff, now + wait_slice)
            )
            while True:
                remaining = attempt_deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    events = selector.select(remaining)
                except (OSError, ValueError):
                    events = []
                if not events:
                    break
                for key, _mask in events:
                    route = key.data
                    try:
                        datagram, source = route.sock.recvfrom(
                            _MAX_DATAGRAM_BYTES + 1)
                    except (BlockingIOError, OSError):
                        continue
                    source_host_key = _host_key(
                        route.endpoint.family, source)
                    peer_key = _peer_key(route.endpoint.family, source)
                    if source_host_key != route.host_key or peer_key is None:
                        continue
                    if pinned_peer is not None and (
                            route is not pinned_route
                            or peer_key != pinned_peer):
                        continue
                    if len(datagram) > _MAX_DATAGRAM_BYTES:
                        saw_malformed = True
                        continue

                    try:
                        classification = classify_coap_response(
                            datagram, token=token, request_mid=mid)
                    except MalformedMessageError:
                        saw_malformed = True
                        continue
                    message = classification.message
                    if (classification.kind != RESPONSE_MESSAGE
                            or message is None
                            or message.mtype not in (TYPE_CON, TYPE_NON)):
                        continue

                    try:
                        block_status = accumulator.add_response(message)
                    except BlockwiseError:
                        saw_malformed = True
                        continue

                    # ACK only an accepted, correlated CON. The shared
                    # classifier may offer an ACK for an ignored CON to
                    # preserve connected-session behavior.
                    if (message.mtype == TYPE_CON
                            and classification.acknowledgement is not None):
                        try:
                            route.sock.sendto(
                                classification.acknowledgement, source)
                        except OSError:
                            pass

                    response_received = True
                    if pinned_peer is None:
                        pinned_route = route
                        pinned_peer = peer_key
                        pinned_destination = tuple(source)
                    if block_status == BLOCK2_DUPLICATE:
                        continue
                    accepted = True
                    break
                if accepted:
                    break
            if accepted:
                break

        if accumulator.complete:
            return _transfer_result(
                _TRANSFER_COMPLETE,
                attempts=attempts,
                response_received=response_received,
                accumulator=accumulator,
                route=pinned_route,
            )
        if not accepted:
            if response_received or saw_malformed:
                status = _TRANSFER_MALFORMED
            elif not sent_for_block and attempts:
                status = _TRANSFER_ENDPOINT_UNAVAILABLE
            else:
                status = _TRANSFER_NO_RESPONSE
            return _transfer_result(
                status,
                attempts=attempts,
                response_received=response_received,
            )

    return _transfer_result(
        _TRANSFER_MALFORMED,
        attempts=attempts,
        response_received=response_received,
    )


def _result(ports, attempts, response_received, error_code=None):
    return OcfSecurePortDiscoveryResult(
        ports=ports,
        attempts=attempts,
        response_received=response_received,
        error_code=error_code,
    )


def _extraction_for_transfer(transfer, *, fallback):
    if transfer.status != _TRANSFER_COMPLETE:
        return None
    if transfer.code != _CONTENT:
        return _PORTS_ABSENT, ()
    extractor = (
        _fallback_secure_ports_from_payload
        if fallback else _primary_secure_ports_from_payload
    )
    return extractor(transfer.payload, transfer.family, transfer.source_key)


def discover_ocf_secure_ports(
        host, *, discovery_port=_DISCOVERY_PORT, timeout=3.0, retries=1,
        family=socket.AF_UNSPEC):
    """Discover secure ports advertised by a target's public OCF directory.

    Name resolution happens synchronously first. ``timeout`` then bounds both
    explicit directory lookups and every Block2 continuation. An advertisement
    is only a candidate; callers should prove it with
    :func:`smartthings_local.protocol.dtls_probe.probe_dtls_ports` before a
    DTLS handshake.
    """
    _validate_options(discovery_port, timeout, retries, family)
    try:
        endpoints = resolve_udp_endpoints(
            host, discovery_port, family=family)
    except OSError:
        return _result((), 0, False, 'endpoint_unavailable')

    selector = selectors.DefaultSelector()
    routes = _open_routes(endpoints, selector)
    if not routes:
        selector.close()
        return _result((), 0, False, 'endpoint_unavailable')

    started = time.monotonic()
    deadline = started + float(timeout)
    # Reserve half of short timeouts, capped at one second, so a filtered-only
    # legacy target can still answer inside the same total deadline.
    primary_cutoff = deadline - min(1.0, float(timeout) / 2)
    attempts = 0
    response_received = False
    used_mids = set()

    try:
        primary = _fetch_directory(
            routes,
            selector,
            query=_PRIMARY_QUERY,
            cutoff=primary_cutoff,
            retries=retries,
            used_mids=used_mids,
        )
        attempts += primary.attempts
        response_received = response_received or primary.response_received

        if primary.status == _TRANSFER_ENDPOINT_UNAVAILABLE:
            return _result(
                (), attempts, response_received, 'endpoint_unavailable')
        if primary.status == _TRANSFER_MALFORMED:
            return _result(
                (), attempts, response_received, 'malformed_ocf_response')
        if primary.status == _TRANSFER_COMPLETE:
            extraction = _extraction_for_transfer(primary, fallback=False)
            status, ports = extraction
            if status == _PORTS_FOUND:
                return _result(ports, attempts, response_received)
            if status in (_PORTS_MALFORMED, _PORTS_UNTRUSTED):
                return _result(
                    (), attempts, response_received,
                    'malformed_ocf_response')

        # A completely unanswered primary request and a valid representation
        # with no usable secure eps are the only fallback conditions. The
        # fallback gets a fresh token, accumulator, and peer pin and starts at
        # the original public discovery routes.
        fallback_result = _fetch_directory(
            routes,
            selector,
            query=_FALLBACK_QUERY,
            cutoff=deadline,
            retries=retries,
            used_mids=used_mids,
        )
        attempts += fallback_result.attempts
        response_received = (
            response_received or fallback_result.response_received)

        if fallback_result.status == _TRANSFER_ENDPOINT_UNAVAILABLE:
            return _result(
                (), attempts, response_received, 'endpoint_unavailable')
        if fallback_result.status == _TRANSFER_MALFORMED:
            return _result(
                (), attempts, response_received, 'malformed_ocf_response')
        if fallback_result.status == _TRANSFER_NO_RESPONSE:
            return _result(
                (), attempts, response_received, 'no_ocf_response')

        status, ports = _extraction_for_transfer(
            fallback_result, fallback=True)
        if status == _PORTS_FOUND:
            return _result(ports, attempts, response_received)
        if status in (_PORTS_MALFORMED, _PORTS_UNTRUSTED):
            return _result(
                (), attempts, response_received, 'malformed_ocf_response')
        return _result((), attempts, response_received, 'no_secure_ports')
    finally:
        for route in routes:
            try:
                selector.unregister(route.sock)
            except (KeyError, OSError, ValueError):
                pass
            try:
                route.sock.close()
            except OSError:
                pass
        selector.close()
