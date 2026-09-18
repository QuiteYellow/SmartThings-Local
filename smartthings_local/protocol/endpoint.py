"""Deterministic UDP endpoint resolution and connected socket setup."""

import math
import socket
import time
from dataclasses import dataclass

from ..errors import EndpointError

__all__ = [
    'HostFilteredUdpSocket',
    'ResolvedUdpEndpoint',
    'open_connected_udp_socket',
    'open_host_filtered_udp_socket',
    'resolve_udp_endpoint',
    'resolve_udp_endpoints',
]

_SUPPORTED_FAMILIES = (socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6)


def _validate_port(port, *, allow_zero=False):
    lower_bound = 0 if allow_zero else 1
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError('port must be an integer')
    if not lower_bound <= port <= 65535:
        raise ValueError(f'port must be between {lower_bound} and 65535')


def _validate_family(family):
    if isinstance(family, bool) or not isinstance(family, int):
        raise TypeError('family must be an address-family integer')
    if family not in _SUPPORTED_FAMILIES:
        raise ValueError('family must be AF_UNSPEC, AF_INET, or AF_INET6')


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedUdpEndpoint:
    """One concrete IPv4 or IPv6 UDP destination.

    ``sockaddr`` is the exact tuple returned by ``getaddrinfo`` and therefore
    retains IPv6 flow and scope IDs. The custom representation omits the
    address, port, and scope so exception and diagnostic output does not leak
    a remote endpoint accidentally.
    """

    family: int
    sockaddr: tuple

    def __post_init__(self):
        if self.family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError('resolved family must be AF_INET or AF_INET6')
        expected_length = 2 if self.family == socket.AF_INET else 4
        if not isinstance(self.sockaddr, tuple) or \
                len(self.sockaddr) != expected_length:
            raise ValueError('sockaddr does not match its address family')
        _validate_port(self.sockaddr[1])

    @property
    def host(self):
        return self.sockaddr[0]

    @property
    def port(self):
        return self.sockaddr[1]

    @property
    def scope_id(self):
        return self.sockaddr[3] if self.family == socket.AF_INET6 else 0

    @property
    def family_name(self):
        return socket.AddressFamily(self.family).name

    def bind_address(self, local_port):
        """Return the wildcard bind tuple matching this endpoint's family."""
        _validate_port(local_port, allow_zero=True)
        if self.family == socket.AF_INET6:
            return ('::', local_port, 0, 0)
        return ('', local_port)

    def __repr__(self):
        return f'ResolvedUdpEndpoint(family={self.family_name})'


def resolve_udp_endpoints(host, port, *, family=socket.AF_UNSPEC):
    """Resolve all unique IPv4/IPv6 UDP candidates in resolver order."""
    if not isinstance(host, (str, bytes)):
        raise TypeError('host must be a string or bytes value')
    if not host:
        raise ValueError('host must be a non-empty string or bytes value')
    _validate_port(port)
    _validate_family(family)

    infos = None
    try:
        infos = socket.getaddrinfo(
            host, port, family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except (OSError, UnicodeError):
        pass
    if infos is None:
        raise EndpointError() from OSError('UDP endpoint resolution failed')

    endpoints = []
    seen = set()
    for resolved_family, socktype, protocol, _canonname, sockaddr in infos:
        if resolved_family not in (socket.AF_INET, socket.AF_INET6):
            continue
        if socktype not in (0, socket.SOCK_DGRAM):
            continue
        if protocol not in (0, socket.IPPROTO_UDP):
            continue
        expected_length = 2 if resolved_family == socket.AF_INET else 4
        if not isinstance(sockaddr, tuple) or len(sockaddr) != expected_length:
            continue
        key = (resolved_family, sockaddr)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(ResolvedUdpEndpoint(resolved_family, sockaddr))

    if not endpoints:
        raise EndpointError()
    return tuple(endpoints)


def resolve_udp_endpoint(host, port, *, family=socket.AF_UNSPEC):
    """Resolve the first usable UDP candidate."""
    return resolve_udp_endpoints(host, port, family=family)[0]


def open_connected_udp_socket(
        host, port, *, family=socket.AF_UNSPEC, local_port=None, timeout=None):
    """Create, optionally bind, and connect a UDP socket.

    Candidates are tried in resolver order. A connected UDP socket accepts
    datagrams only from its exact remote peer and lets the caller use
    ``send``/``recv`` instead of passing an address on every operation.
    """
    if local_port is not None:
        _validate_port(local_port, allow_zero=True)
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError('timeout must be a number or None')
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError('timeout must be a non-negative number or None')

    endpoints = resolve_udp_endpoints(host, port, family=family)
    for endpoint in endpoints:
        sock = None
        try:
            sock = socket.socket(
                endpoint.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if local_port is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(endpoint.bind_address(local_port))
            sock.connect(endpoint.sockaddr)
            sock.settimeout(timeout)
            return sock, endpoint
        except OSError:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    raise EndpointError() from OSError('UDP socket setup failed')


def _host_key(family, sockaddr):
    """Return a comparable host identity, ignoring port and flow label."""
    try:
        packed = socket.inet_pton(family, sockaddr[0])
    except (OSError, UnicodeError, TypeError, ValueError):
        return None
    # Retain the IPv6 scope so a link-local reply from another interface is
    # not mistaken for the target.
    scope = sockaddr[3] if family == socket.AF_INET6 and len(sockaddr) > 3 else 0
    return (family, packed, scope)


class HostFilteredUdpSocket:
    """UDP socket that accepts replies from any port on one target host.

    A connected UDP socket accepts datagrams only from the exact port it
    dialled. An appliance's DTLS socket is bound to a kernel-assigned port,
    so it answers from a port that need not match the one addressed, and a
    connected socket makes a live appliance look silent. This wrapper keeps
    sending to the resolved destination and filters inbound datagrams on host
    alone, which is what ``ocf_discovery`` already does.

    The exposed surface is the subset of the socket API the DTLS callers use.
    Off-path spoofing resistance drops from address-and-port to address only;
    the DTLS cookie exchange and handshake authentication remain the real
    protection, as they already are for a connected socket.
    """

    __slots__ = (
        '_dest',
        '_endpoint',
        '_host_key',
        '_sock',
        '_timeout',
        'observed_reply_port',
    )

    def __init__(self, sock, endpoint):
        self._sock = sock
        self._endpoint = endpoint
        self._dest = endpoint.sockaddr
        self._host_key = _host_key(endpoint.family, endpoint.sockaddr)
        self._timeout = None
        #: Source port of the most recent accepted datagram. Diagnostic only;
        #: replies keep going to the port originally dialled.
        self.observed_reply_port = None

    @property
    def endpoint(self):
        return self._endpoint

    def send(self, data):
        """Send to the resolved destination, mirroring ``socket.send``."""
        return self._sock.sendto(data, self._dest)

    def recv(self, bufsize):
        """Return the next datagram from the target host.

        Datagrams from any other host are discarded without extending the
        caller's timeout, so a flood from elsewhere cannot hold the call open
        past its deadline.
        """
        timeout = self._timeout
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('timed out')
                self._sock.settimeout(remaining)
            datagram, address = self._sock.recvfrom(bufsize)
            if self._host_key is None or \
                    _host_key(self._endpoint.family, address) == self._host_key:
                if len(address) > 1:
                    self.observed_reply_port = address[1]
                return datagram

    def settimeout(self, timeout):
        self._timeout = timeout
        self._sock.settimeout(timeout)

    def gettimeout(self):
        return self._timeout

    def fileno(self):
        return self._sock.fileno()

    def getsockname(self):
        return self._sock.getsockname()

    def close(self):
        self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def __repr__(self):
        return f'HostFilteredUdpSocket(family={self._endpoint.family_name})'


def open_host_filtered_udp_socket(
        host, port, *, family=socket.AF_UNSPEC, local_port=None, timeout=None):
    """Open an unconnected UDP socket bound to one target host.

    Mirrors :func:`open_connected_udp_socket`, but the returned socket accepts
    a reply from any port on the target rather than only the port dialled. See
    :class:`HostFilteredUdpSocket` for why an OCF appliance needs that.
    """
    if local_port is not None:
        _validate_port(local_port, allow_zero=True)
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError('timeout must be a number or None')
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError('timeout must be a non-negative number or None')

    endpoints = resolve_udp_endpoints(host, port, family=family)
    for endpoint in endpoints:
        sock = None
        try:
            sock = socket.socket(
                endpoint.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if local_port is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind unconditionally so the local port is fixed before the first
            # send, matching the connected path's source-port stability.
            sock.bind(endpoint.bind_address(local_port or 0))
            wrapper = HostFilteredUdpSocket(sock, endpoint)
            wrapper.settimeout(timeout)
            return wrapper, endpoint
        except OSError:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    raise EndpointError() from OSError('UDP socket setup failed')
