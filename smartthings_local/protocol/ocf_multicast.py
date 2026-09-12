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

__all__ = [
    "OcfResponderPortDiscoveryResult",
    "discover_ocf_responder_ports",
]

_OCF_MULTICAST_GROUP = socket.inet_ntoa(bytes((224, 0, 1, 187)))
_OCF_DISCOVERY_PORT = 5683
_OCF_CBOR = (10_000).to_bytes(2, "big")
_OCF_CONTENT_FORMAT_VERSION = 2049
_OCF_VERSION_1_0 = (2048).to_bytes(2, "big")
_CONTENT = 0x45
_MAX_DATAGRAM_BYTES = 8192
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
        for round_number in range(rounds):
            if time.monotonic() >= deadline:
                break
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

            round_deadline = started + timeout * (round_number + 1) / rounds
            datagrams = 0
            while datagrams < _MAX_DATAGRAMS_PER_ROUND:
                remaining = min(deadline, round_deadline) - time.monotonic()
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
