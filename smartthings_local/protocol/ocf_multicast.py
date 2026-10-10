"""Bounded discovery of a known host's plaintext OCF response port.

Some OCF devices receive multicast discovery on UDP 5683 but reply from an
ephemeral port. This module records only token-correlated response ports from
the caller's expected IPv4 address. The results are candidates: callers still
need directory parsing, a DTLS probe, and authenticated identity validation.
"""

from __future__ import annotations

import ipaddress
import math
import secrets
import selectors
import socket
import time
from dataclasses import dataclass

import cbor2

from ..errors import MalformedMessageError
from .coap import (
    ACCEPT,
    CF_CBOR,
    METHOD_GET,
    TYPE_ACK,
    TYPE_CON,
    TYPE_NON,
    URI_PATH,
    URI_QUERY,
    build_coap,
    parse_coap,
)
from .ocf_discovery import (
    discover_ocf_secure_ports,
    read_plaintext_ocf_resource,
)

__all__ = [
    "OcfResponder",
    "OcfResponderDiscovery",
    "OcfResponderPortDiscoveryResult",
    "discover_ocf_responder_ports",
    "discover_ocf_responders",
    "read_ocf_responder",
    "secure_ports_for_di",
]

_OCF_MULTICAST_GROUP = socket.inet_ntoa(bytes((224, 0, 1, 187)))
_OCF_DISCOVERY_PORT = 5683
_OCF_CBOR = (10_000).to_bytes(2, "big")
_OCF_CONTENT_FORMAT_VERSION = 2049
_OCF_VERSION_1_0 = (2048).to_bytes(2, "big")
_CONTENT = 0x45
_MAX_DATAGRAM_BYTES = 8192
# The least of a round's nominal window that still makes sending its requests
# worthwhile. Each round puts three datagrams on the multicast group, so every
# device on the segment pays for a round sent with no window to read a reply
# in. The floor is a share of the caller's own budget rather than a fixed
# number of milliseconds; the same fraction guards the DTLS probe's
# retransmissions, for the same reason.
_MIN_WINDOW_SHARE = 0.5

_MAX_DATAGRAMS_PER_ROUND = 64
_MAX_PORTS = 8


@dataclass(frozen=True, slots=True, repr=False)
class OcfResponderPortDiscoveryResult:
    """Redacted result of one known-host multicast discovery operation."""

    ports: tuple[int, ...]
    attempts: int
    responses: int
    error_code: str | None = None

    @property
    def found(self) -> bool:
        """Return whether at least one response port was discovered."""
        return bool(self.ports)

    def __repr__(self) -> str:
        return (
            "OcfResponderPortDiscoveryResult("
            f"found={self.found!r}, port_count={len(self.ports)}, "
            f"attempts={self.attempts}, responses={self.responses}, "
            f"error_code={self.error_code!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OcfResponder:
    """One OCF responder at a host: its identity and advertised secure ports.

    ``rt`` and ``di`` come from a plaintext ``/oic/d`` read and ``secure_ports``
    from ``/oic/res``. ``di`` is the unauthenticated Device UUID, suitable for
    choosing which responder to dial; it does not replace an authenticated
    ``/oic/d.di`` check made after a DTLS handshake. ``error_code`` is set when
    the identity read did not complete. The representation redacts ``di`` and the
    device name, which can identify a specific unit.
    """

    plaintext_port: int
    rt: tuple[str, ...]
    di: str | None
    name: str | None
    secure_ports: tuple[int, ...]
    error_code: str | None = None

    @property
    def has_identity(self) -> bool:
        """Return whether a Device UUID was read for this responder."""
        return self.di is not None

    def __repr__(self) -> str:
        return (
            "OcfResponder("
            f"plaintext_port={self.plaintext_port}, rt={list(self.rt)!r}, "
            f"has_di={self.di is not None!r}, has_name={self.name is not None!r}, "
            f"secure_port_count={len(self.secure_ports)}, "
            f"error_code={self.error_code!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OcfResponderDiscovery:
    """Redacted result of enumerating the OCF responders at one host.

    ``error_code`` carries the multicast discovery failure when no responder was
    found; it is ``None`` once at least one responder is enumerated, even if an
    individual responder's identity read failed (see ``OcfResponder.error_code``).
    """

    responders: tuple[OcfResponder, ...]
    error_code: str | None = None

    @property
    def found(self) -> bool:
        """Return whether at least one responder was enumerated."""
        return bool(self.responders)

    def __repr__(self) -> str:
        return (
            "OcfResponderDiscovery("
            f"found={self.found!r}, responder_count={len(self.responders)}, "
            f"error_code={self.error_code!r})"
        )


def _validate_address(value: object, name: str) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be an IPv4 address string")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{name} must be a valid IPv4 address") from exc
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ValueError(f"{name} must be a unicast IPv4 address")
    return str(address), address.packed


def _validate_options(
    *,
    discovery_port: object,
    timeout: object,
    rounds: object,
) -> tuple[int, float, int]:
    if isinstance(discovery_port, bool) or not isinstance(discovery_port, int):
        raise TypeError("discovery_port must be an integer")
    if not 1 <= discovery_port <= 65535:
        raise ValueError("discovery_port must be between 1 and 65535")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number")
    timeout_value = float(timeout)
    if not math.isfinite(timeout_value) or not 0 < timeout_value <= 30:
        raise ValueError("timeout must be greater than zero and at most 30")
    if isinstance(rounds, bool) or not isinstance(rounds, int):
        raise TypeError("rounds must be an integer")
    if not 1 <= rounds <= 4:
        raise ValueError("rounds must be between one and four")
    return discovery_port, timeout_value, rounds


def _request(
    token: bytes,
    message_id: int,
    *,
    versioned: bool,
    filtered: bool,
) -> bytes:
    options = [
        (URI_PATH, b"oic"),
        (URI_PATH, b"res"),
        (ACCEPT, _OCF_CBOR if versioned else CF_CBOR),
    ]
    if filtered:
        options.append((URI_QUERY, b"rt=oic.r.doxm"))
    if versioned:
        options.append((_OCF_CONTENT_FORMAT_VERSION, _OCF_VERSION_1_0))
    return build_coap(TYPE_NON, METHOD_GET, message_id, token, options)


def _result(
    ports: tuple[int, ...],
    attempts: int,
    responses: int,
    error_code: str | None = None,
) -> OcfResponderPortDiscoveryResult:
    return OcfResponderPortDiscoveryResult(
        ports=ports,
        attempts=attempts,
        responses=responses,
        error_code=error_code,
    )


def discover_ocf_responder_ports(
    target_address: str,
    *,
    interface_address: str,
    discovery_port: int = _OCF_DISCOVERY_PORT,
    timeout: float = 3.0,
    rounds: int = 2,
) -> OcfResponderPortDiscoveryResult:
    """Find plaintext OCF response ports for one known IPv4 host.

    These ports carry plain CoAP. A DTLS handshake needs the *secure* port,
    which the appliance advertises separately and which
    :func:`smartthings_local.protocol.ocf_discovery.discover_ocf_secure_ports`
    reads. Dialling a port from this result with DTLS times out.

    Each round sends modern OCF and legacy IoTivity NON requests to the
    link-local multicast group. Only a 2.05 response with a request token and
    the exact target source address contributes a candidate. One monotonic
    deadline bounds all rounds, and every socket is closed before return.

    ``rounds`` is a ceiling. Each round takes a share of what is left of the
    budget, and a round whose share is under half a nominal window is skipped
    instead of putting its requests on the group with no window left to read
    an answer in.
    """

    _target_address, target_key = _validate_address(target_address, "target_address")
    interface_address, interface_key = _validate_address(
        interface_address, "interface_address"
    )
    discovery_port, timeout, rounds = _validate_options(
        discovery_port=discovery_port,
        timeout=timeout,
        rounds=rounds,
    )

    try:
        selector = selectors.DefaultSelector()
    except (OSError, ValueError):
        return _result((), 0, 0, "interface_unavailable")
    active = None
    try:
        active = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        active.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface_key)
        active.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        active.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        active.bind((interface_address, 0))
        active.setblocking(False)
        selector.register(active, selectors.EVENT_READ)
    except (OSError, ValueError):
        if active is not None:
            try:
                active.close()
            except OSError:
                pass
        selector.close()
        return _result((), 0, 0, "interface_unavailable")

    started = time.monotonic()
    deadline = started + timeout
    accepted_tokens: set[bytes] = set()
    observations: set[tuple[bytes, int]] = set()
    ports: list[int] = []
    seen_ports: set[int] = set()
    attempts = 0
    responses = 0
    too_many_ports = False

    try:
        nominal_window = timeout / rounds
        for round_number in range(rounds):
            if time.monotonic() >= deadline:
                break
            # Share what is left of the budget across the rounds that are
            # left, rather than giving this round the fixed slice ending at
            # `started + timeout * (round_number + 1) / rounds`. A select
            # returns somewhat past the timeout it was given, and under fixed
            # slices that overrun came out of the next round's window: with a
            # short `timeout`, or `rounds` near its limit of four, one overrun
            # consumes a whole slice, and the round then sent all three of its
            # requests to the multicast group with no window left to read a
            # reply in. Measured at a 30 ms slice and a 40 ms overrun, one
            # round in three went out unread. The `deadline` check above still
            # bounds the whole call, so redistributing never extends it.
            now = time.monotonic()
            round_window = (deadline - now) / (rounds - round_number)
            if (round_number
                    and round_window < nominal_window * _MIN_WINDOW_SHARE):
                # Too little of the window survives to carry a reply, so these
                # requests would cost every device on the segment a datagram
                # for an answer that could not arrive in time.
                break
            round_deadline = now + round_window
            # Preserve the unfiltered modern and legacy requests used by the
            # installed appliance generations. Older media firmware can omit
            # usable endpoint policy from its large unfiltered directory but
            # answer the smaller legacy DOXM-filtered lookup, so send that as
            # a third bounded fallback rather than narrowing every request.
            for versioned, filtered in (
                (True, False),
                (False, False),
                (False, True),
            ):
                token = secrets.token_bytes(8)
                while token in accepted_tokens:
                    token = secrets.token_bytes(8)
                accepted_tokens.add(token)
                request = _request(
                    token,
                    secrets.randbits(16),
                    versioned=versioned,
                    filtered=filtered,
                )
                try:
                    sent = active.sendto(
                        request,
                        (_OCF_MULTICAST_GROUP, discovery_port),
                    )
                except OSError:
                    continue
                attempts += 1
                if sent != len(request):
                    continue

            datagrams = 0
            while datagrams < _MAX_DATAGRAMS_PER_ROUND:
                remaining = round_deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    events = selector.select(remaining)
                except (OSError, ValueError):
                    break
                if not events:
                    break
                try:
                    datagram, source = active.recvfrom(_MAX_DATAGRAM_BYTES + 1)
                except (BlockingIOError, OSError):
                    continue
                datagrams += 1
                if len(datagram) > _MAX_DATAGRAM_BYTES:
                    continue
                if (
                    len(datagram) < 4
                    or datagram[0] >> 6 != 1
                    or datagram[0] & 0x0F > 8
                    or 4 + (datagram[0] & 0x0F) > len(datagram)
                ):
                    continue
                if not isinstance(source, tuple) or len(source) != 2:
                    continue
                source_host, source_port = source
                if not isinstance(source_host, str):
                    continue
                try:
                    source_key = socket.inet_pton(socket.AF_INET, source_host)
                except OSError:
                    continue
                if source_key != target_key:
                    continue
                if (
                    isinstance(source_port, bool)
                    or not isinstance(source_port, int)
                    or not 1 <= source_port <= 65535
                ):
                    continue
                try:
                    message_type, code, mid, token, _options, payload = parse_coap(
                        datagram
                    )
                except (IndexError, ValueError, MalformedMessageError):
                    continue
                if (
                    token not in accepted_tokens
                    or code != _CONTENT
                    or message_type not in (TYPE_NON, TYPE_CON)
                    or not payload
                ):
                    continue
                if message_type == TYPE_CON:
                    try:
                        active.sendto(build_coap(TYPE_ACK, 0, mid, b"", []), source)
                    except OSError:
                        pass
                observation = (token, source_port)
                if observation in observations:
                    continue
                observations.add(observation)
                responses += 1
                if source_port in seen_ports:
                    continue
                if len(ports) >= _MAX_PORTS:
                    too_many_ports = True
                    continue
                seen_ports.add(source_port)
                ports.append(source_port)

        if too_many_ports:
            return _result((), attempts, responses, "ambiguous_response")
        if ports:
            return _result(tuple(ports), attempts, responses)
        if attempts == 0:
            return _result((), attempts, responses, "interface_unavailable")
        return _result((), attempts, responses, "no_response")
    finally:
        try:
            selector.unregister(active)
        except (KeyError, OSError, ValueError):
            pass
        try:
            active.close()
        except OSError:
            pass
        selector.close()


def _validate_responder_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("port must be an integer")
    if not 1 <= value <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return value


def _identity_from_oic_d(payload: bytes) -> tuple[tuple[str, ...], str | None, str | None]:
    try:
        value = cbor2.loads(payload)
    except Exception:  # noqa: BLE001 - untrusted CBOR must fail closed
        return (), None, None
    if not isinstance(value, dict):
        return (), None, None
    rt_raw = value.get("rt")
    rt = (
        tuple(item for item in rt_raw if isinstance(item, str))
        if isinstance(rt_raw, list)
        else ()
    )
    di = value.get("di")
    di = di if isinstance(di, str) and di else None
    name = value.get("n")
    name = name if isinstance(name, str) else None
    return rt, di, name


def read_ocf_responder(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
    retries: int = 1,
) -> OcfResponder:
    """Read one responder's identity and advertised secure ports at a known port.

    Two unicast reads run in sequence on ``host``:``port``: ``/oic/d`` for the
    responder's ``rt``, ``di`` and name, then ``/oic/res`` for its advertised
    secure ports. ``/oic/d`` is read at its default OCF Interface, which exposes
    the ``rt``/``if`` Common Properties; a non-baseline view may omit them.

    The ``di`` returned is the plaintext, unauthenticated Device UUID. It is for
    choosing which responder to dial and does not replace an authenticated
    ``/oic/d.di`` check made after a DTLS handshake. When the ``/oic/d`` read does
    not complete, ``rt`` is empty, ``di``/``name`` are ``None``, and
    ``error_code`` is set; the secure-port read is still attempted.
    """

    port = _validate_responder_port(port)
    identity = read_plaintext_ocf_resource(
        host, "/oic/d", port=port, timeout=timeout, retries=retries
    )
    if identity.successful:
        rt, di, name = _identity_from_oic_d(identity.payload)
        error_code = None
    else:
        rt, di, name = (), None, None
        error_code = identity.error_code or "identity_unavailable"

    secure = discover_ocf_secure_ports(
        host, discovery_port=port, timeout=timeout, retries=retries
    )
    return OcfResponder(
        plaintext_port=port,
        rt=rt,
        di=di,
        name=name,
        secure_ports=secure.ports,
        error_code=error_code,
    )


def discover_ocf_responders(
    target_address: str,
    *,
    interface_address: str,
    discovery_port: int = _OCF_DISCOVERY_PORT,
    timeout: float = 3.0,
    rounds: int = 2,
    per_read_timeout: float = 3.0,
    retries: int = 1,
) -> OcfResponderDiscovery:
    """Enumerate the OCF responders at one IPv4 host, with identity and ports.

    Multicast discovery first finds each responder's plaintext port; then, one
    responder at a time, :func:`read_ocf_responder` reads its identity
    (``/oic/d``) and advertised secure ports (``/oic/res``). Reads are sequential,
    not parallel, so a host that answers discovery from several ports is not
    flooded.

    Choosing which responder is the wanted appliance is left to the caller: filter
    :attr:`OcfResponder.rt` (an appliance declares a functional ``oic.d.*`` type
    beyond the mandatory ``oic.wk.d``), or match a stored :attr:`OcfResponder.di`
    with :func:`secure_ports_for_di`. When no responder answers, the result's
    ``error_code`` carries the multicast discovery reason, which lets a caller
    distinguish "nothing here" from "multicast could not cross the network".
    """

    discovery = discover_ocf_responder_ports(
        target_address,
        interface_address=interface_address,
        discovery_port=discovery_port,
        timeout=timeout,
        rounds=rounds,
    )
    if not discovery.ports:
        return OcfResponderDiscovery((), error_code=discovery.error_code)
    responders = tuple(
        read_ocf_responder(
            target_address, port, timeout=per_read_timeout, retries=retries
        )
        for port in discovery.ports
    )
    return OcfResponderDiscovery(responders)


def secure_ports_for_di(responders: object, di: str) -> tuple[int, ...]:
    """Return the advertised secure ports of the responder whose ``di`` matches.

    ``responders`` is any iterable of :class:`OcfResponder`, typically
    ``discover_ocf_responders(...).responders``. ``di`` is the plaintext
    ``/oic/d`` Device UUID stored at onboarding, which is stable across the
    reboots that move the secure port. Returns an empty tuple when no responder
    carries that ``di``.
    """

    if not isinstance(di, str) or not di:
        raise ValueError("di must be a non-empty string")
    for responder in responders:
        if responder.di == di:
            return responder.secure_ports
    return ()
