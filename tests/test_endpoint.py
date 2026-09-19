import socket
import traceback

import pytest
from OpenSSL import SSL

from smartthings_local.errors import EndpointError
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.endpoint import (
    HostFilteredUdpSocket,
    ResolvedUdpEndpoint,
    open_connected_udp_socket,
    open_host_filtered_udp_socket,
    resolve_udp_endpoint,
    resolve_udp_endpoints,
)


def _addrinfo(family, sockaddr, *, socktype=socket.SOCK_DGRAM,
              protocol=socket.IPPROTO_UDP):
    return family, socktype, protocol, '', sockaddr


class FakeSocket:
    def __init__(self, family, *, fail_bind=False, fail_connect=False):
        self.family = family
        self.fail_bind = fail_bind
        self.fail_connect = fail_connect
        self.options = []
        self.bound = None
        self.peer = None
        self.timeout = None
        self.closed = False
        self.sent = []
        self.inbound = []

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, address):
        if self.fail_bind:
            raise OSError('synthetic bind failure')
        self.bound = address

    def connect(self, address):
        if self.fail_connect:
            raise OSError('synthetic connect failure')
        self.peer = address

    def settimeout(self, timeout):
        self.timeout = timeout

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def recv(self, _size):
        return self.inbound.pop(0)

    def close(self):
        self.closed = True


def _socket_factory(monkeypatch, failures=()):
    created = []
    remaining = list(failures)

    def factory(family, _socktype, _protocol):
        failure = remaining.pop(0) if remaining else None
        sock = FakeSocket(
            family,
            fail_bind=failure == 'bind',
            fail_connect=failure == 'connect',
        )
        created.append(sock)
        return sock

    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.socket', factory)
    return created


def test_resolve_ipv4_endpoint_and_redacted_repr(monkeypatch):
    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo',
        lambda *args: [_addrinfo(socket.AF_INET, ('192.0.2.10', 5684))],
    )

    endpoint = resolve_udp_endpoint('device.example', 5684)

    assert endpoint.family == socket.AF_INET
    assert endpoint.host == '192.0.2.10'
    assert endpoint.port == 5684
    assert endpoint.scope_id == 0
    assert repr(endpoint) == 'ResolvedUdpEndpoint(family=AF_INET)'
    assert '192.0.2.10' not in repr(endpoint)
    assert '5684' not in repr(endpoint)


def test_resolve_scoped_ipv6_preserves_flow_and_scope(monkeypatch):
    sockaddr = ('2001:db8::1', 5684, 3, 7)
    calls = []

    def resolve(*args):
        calls.append(args)
        return [_addrinfo(socket.AF_INET6, sockaddr)]

    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo',
        resolve,
    )

    endpoint = resolve_udp_endpoint(
        'device.example', 5684, family=socket.AF_INET6)

    assert endpoint.sockaddr == sockaddr
    assert endpoint.scope_id == 7
    assert endpoint.bind_address(55000) == ('::', 55000, 0, 0)
    assert '2001:db8::1' not in repr(endpoint)
    assert '7' not in repr(endpoint)
    assert calls == [(
        'device.example', 5684, socket.AF_INET6,
        socket.SOCK_DGRAM, socket.IPPROTO_UDP)]


def test_resolver_order_is_stable_and_duplicates_are_removed(monkeypatch):
    first = _addrinfo(socket.AF_INET6, ('2001:db8::10', 5684, 0, 0))
    second = _addrinfo(socket.AF_INET, ('198.51.100.20', 5684))
    ignored = _addrinfo(
        socket.AF_INET, ('203.0.113.30', 5684), socktype=socket.SOCK_STREAM)
    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo',
        lambda *args: [first, first, ignored, second],
    )

    endpoints = resolve_udp_endpoints('device.example', 5684)

    assert [endpoint.sockaddr for endpoint in endpoints] == [
        first[-1], second[-1]]


def test_resolver_failure_raises_redacted_endpoint_error(monkeypatch):
    def fail(*args):
        raise socket.gaierror('credential-value at device.example')

    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo', fail)
    remote_host = 'device.example'

    with pytest.raises(EndpointError) as exc:
        resolve_udp_endpoint(remote_host, 5684)

    formatted = ''.join(traceback.format_exception(exc.value))
    assert isinstance(exc.value, OSError)
    assert exc.value.__context__ is None
    assert 'UDP endpoint resolution failed' in formatted
    assert 'credential-value' not in formatted
    assert 'device.example' not in formatted


def test_socket_setup_tries_next_candidate_after_bind_failure(monkeypatch):
    candidates = [
        _addrinfo(socket.AF_INET6, ('2001:db8::10', 5684, 0, 0)),
        _addrinfo(socket.AF_INET, ('192.0.2.10', 5684)),
    ]
    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo',
        lambda *args: candidates,
    )
    created = _socket_factory(monkeypatch, failures=('bind', None))

    sock, endpoint = open_connected_udp_socket(
        'device.example', 5684, local_port=55000, timeout=1.5)

    assert created[0].closed
    assert sock is created[1]
    assert endpoint.family == socket.AF_INET
    assert sock.bound == ('', 55000)
    assert sock.peer == ('192.0.2.10', 5684)
    assert sock.timeout == 1.5
    assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in sock.options


def test_socket_setup_failure_is_redacted_and_closes_candidates(monkeypatch):
    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo',
        lambda *args: [
            _addrinfo(socket.AF_INET, ('192.0.2.10', 5684)),
            _addrinfo(socket.AF_INET, ('198.51.100.20', 5684)),
        ],
    )
    created = _socket_factory(monkeypatch, failures=('connect', 'connect'))

    with pytest.raises(EndpointError) as exc:
        open_connected_udp_socket('device.example', 5684)

    formatted = ''.join(traceback.format_exception(exc.value))
    assert all(sock.closed for sock in created)
    assert exc.value.__context__ is None
    assert 'UDP socket setup failed' in formatted
    assert 'synthetic connect failure' not in formatted
    assert '192.0.2.10' not in formatted
    assert '198.51.100.20' not in formatted


def test_same_port_different_hosts_remain_distinct_with_source_reuse(
        monkeypatch):
    addresses = {
        'first.example': '192.0.2.10',
        'second.example': '198.51.100.20',
    }

    def resolve(host, port, *_args):
        return [_addrinfo(socket.AF_INET, (addresses[host], port))]

    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo', resolve)
    created = _socket_factory(monkeypatch)

    first, _ = open_connected_udp_socket(
        'first.example', 5684, local_port=55000)
    second, _ = open_connected_udp_socket(
        'second.example', 5684, local_port=55000)

    assert first.peer == ('192.0.2.10', 5684)
    assert second.peer == ('198.51.100.20', 5684)
    assert first.peer != second.peer
    assert [sock.bound for sock in created] == [('', 55000), ('', 55000)]


def test_connected_udp_socket_filters_datagrams_from_another_peer():
    expected_peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other_peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = None
    try:
        expected_peer.bind(('127.0.0.1', 0))
        other_peer.bind(('127.0.0.1', 0))
        expected_peer.settimeout(0.5)
        client, endpoint = open_connected_udp_socket(
            '127.0.0.1',
            expected_peer.getsockname()[1],
            family=socket.AF_INET,
            timeout=0.5,
        )

        assert endpoint.sockaddr == expected_peer.getsockname()
        assert client.send(b'client datagram') == len(b'client datagram')
        payload, source = expected_peer.recvfrom(64)
        assert payload == b'client datagram'
        assert source == client.getsockname()

        other_peer.sendto(b'unrelated', client.getsockname())
        expected_peer.sendto(b'expected', client.getsockname())
        assert client.recv(64) == b'expected'
    finally:
        if client is not None:
            client.close()
        expected_peer.close()
        other_peer.close()


@pytest.mark.parametrize(
    ('host', 'port', 'family'),
    (
        ('', 5684, socket.AF_UNSPEC),
        ('device.example', 0, socket.AF_UNSPEC),
        ('device.example', 65536, socket.AF_UNSPEC),
        ('device.example', 5684, 9999),
    ),
)
def test_invalid_endpoint_inputs_fail_before_resolution(host, port, family):
    with pytest.raises(ValueError):
        resolve_udp_endpoint(host, port, family=family)


@pytest.mark.parametrize(
    ('host', 'port', 'family'),
    (
        (None, 5684, socket.AF_UNSPEC),
        ('device.example', '5684', socket.AF_UNSPEC),
        ('device.example', 5684, 'AF_INET'),
    ),
)
def test_endpoint_input_types_are_explicit(host, port, family):
    with pytest.raises(TypeError):
        resolve_udp_endpoint(host, port, family=family)


@pytest.mark.parametrize('timeout', (-1, float('nan'), float('inf')))
def test_socket_timeout_must_be_finite_and_non_negative(timeout):
    with pytest.raises(ValueError):
        open_connected_udp_socket('device.example', 5684, timeout=timeout)


def test_session_uses_host_filtered_socket_send_and_recv(monkeypatch):
    endpoint = ResolvedUdpEndpoint(
        socket.AF_INET6, ('2001:db8::10', 5684, 0, 0))
    sock = FakeSocket(socket.AF_INET6)
    sock.peer = endpoint.sockaddr
    sock.inbound.append(b'synthetic server flight')
    outbound_record = (
        b'\x16\xfe\xfd' + b'\x00' * 8 + b'\x00\x01' + b'x')

    class FakeContext:
        def load_verify_locations(self, *args):
            pass

        def set_verify(self, *args):
            pass

        def set_cipher_list(self, *args):
            pass

        def use_certificate_chain_file(self, *args):
            pass

        def use_privatekey_file(self, *args):
            pass

        def check_privatekey(self):
            pass

    class FakeConnection:
        def __init__(self):
            self.handshake_calls = 0
            self.bio_reads = 0
            self.bio_writes = []

        def set_connect_state(self):
            pass

        def set_ciphertext_mtu(self, *args):
            pass

        def do_handshake(self):
            self.handshake_calls += 1
            if self.handshake_calls == 1:
                raise SSL.WantReadError()

        def bio_read(self, _size):
            self.bio_reads += 1
            if self.bio_reads == 1:
                return outbound_record
            raise SSL.WantReadError()

        def bio_write(self, data):
            self.bio_writes.append(data)

    connection = FakeConnection()
    open_calls = []

    def open_socket(*args, **kwargs):
        open_calls.append((args, kwargs))
        return sock, endpoint

    monkeypatch.setattr(dtls_session.SSL, 'Context', lambda *args: FakeContext())
    monkeypatch.setattr(
        dtls_session.SSL, 'Connection', lambda *args: connection)
    monkeypatch.setattr(
        dtls_session,
        'open_host_filtered_udp_socket',
        open_socket,
    )
    monkeypatch.setattr(dtls_session.time, 'sleep', lambda _delay: None)

    session = dtls_session.DtlsCoapSession(
        'device.example', 5684,
        cert_path='/synthetic/client.pem',
        key_path='/synthetic/client.key',
        family=socket.AF_INET6,
    )
    session.connect()

    assert sock.sent == [outbound_record]
    assert connection.bio_writes == [b'synthetic server flight']
    assert session.endpoint is endpoint
    assert session.dest == endpoint.sockaddr
    assert open_calls == [(('device.example', 5684), {
        'family': socket.AF_INET6,
        'local_port': None,
        'timeout': 0.5,
    })]

    session.close()
    assert session.endpoint is None
    assert session.dest is None


def test_session_send_failure_has_no_raw_exception_context():
    outbound_record = (
        b'\x16\xfe\xfd' + b'\x00' * 8 + b'\x00\x01' + b'x')

    class FakeConnection:
        def __init__(self):
            self.bio_reads = 0

        def send(self, _data):
            pass

        def bio_read(self, _size):
            self.bio_reads += 1
            if self.bio_reads == 1:
                return outbound_record
            raise SSL.WantReadError()

    class FailingSocket:
        def send(self, _data):
            raise OSError('credential-value at device.example')

    session = dtls_session.DtlsCoapSession(
        'device.example', 5684,
        cert_path='/synthetic/client.pem',
        key_path='/synthetic/client.key',
    )
    session.conn = FakeConnection()
    session.sock = FailingSocket()

    with pytest.raises(EndpointError) as exc:
        session._send_dgram(b'payload')

    formatted = ''.join(traceback.format_exception(exc.value))
    assert exc.value.__context__ is None
    assert 'UDP send failed' in formatted
    assert 'credential-value' not in formatted
    assert 'device.example' not in formatted


# --- issue #66: an appliance answering from a port it was not dialled on ----
#
# An appliance's secure port is kernel-assigned, so a reply legitimately
# arrives from a source port other than the one addressed. A connected UDP
# socket drops those, which made a live appliance report as dead. The two
# appliances here run IoTivity classic, which initialises its unicast secure
# socket's port to 0 (caipadapter.c:219) and learns the assignment back from
# getsockname (caipserver.c:826) — see docs/firmware-families.md for the tree
# and pin those lines are from.


class _RecordingUdpSocket:
    """Underlying socket stub that replays a scripted inbound sequence."""

    def __init__(self, family, inbound=()):
        self.family = family
        self.inbound = list(inbound)
        self.sent = []
        self.timeouts = []
        self.bound = None
        self.closed = False
        self.options = []

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, address):
        self.bound = address

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendto(self, data, address):
        self.sent.append((data, address))
        return len(data)

    def recvfrom(self, _size):
        if not self.inbound:
            raise TimeoutError('timed out')
        return self.inbound.pop(0)

    def getsockname(self):
        return self.bound

    def fileno(self):
        return 7

    def close(self):
        self.closed = True


def _v4_endpoint(port=5684):
    return ResolvedUdpEndpoint(socket.AF_INET, ('192.0.2.10', port))


def test_reply_from_another_source_port_is_accepted():
    endpoint = _v4_endpoint()
    inner = _RecordingUdpSocket(
        socket.AF_INET,
        inbound=[(b'\x16reply', ('192.0.2.10', 59768))],
    )
    sock = HostFilteredUdpSocket(inner, endpoint)

    assert sock.recv(4096) == b'\x16reply'
    # The port the appliance answered from is recorded for diagnostics only.
    assert sock.observed_reply_port == 59768


def test_send_still_targets_the_dialled_port():
    endpoint = _v4_endpoint()
    inner = _RecordingUdpSocket(
        socket.AF_INET,
        inbound=[(b'\x16reply', ('192.0.2.10', 59768))],
    )
    sock = HostFilteredUdpSocket(inner, endpoint)
    sock.recv(4096)
    sock.send(b'\x16request')

    # Following the reply port would be an unevidenced behaviour change; #66's
    # capture shows the appliance still accepting on the port originally used.
    assert inner.sent == [(b'\x16request', ('192.0.2.10', 5684))]


def test_datagram_from_another_host_is_discarded():
    endpoint = _v4_endpoint()
    inner = _RecordingUdpSocket(
        socket.AF_INET,
        inbound=[
            (b'\x16spoof', ('198.51.100.7', 5684)),
            (b'\x16real', ('192.0.2.10', 41234)),
        ],
    )
    sock = HostFilteredUdpSocket(inner, endpoint)

    assert sock.recv(4096) == b'\x16real'
    assert sock.observed_reply_port == 41234


def test_foreign_datagrams_do_not_extend_the_deadline(monkeypatch):
    endpoint = _v4_endpoint()
    inner = _RecordingUdpSocket(
        socket.AF_INET,
        inbound=[(b'\x16spoof', ('198.51.100.7', 5684))] * 50,
    )
    sock = HostFilteredUdpSocket(inner, endpoint)
    sock.settimeout(1.0)

    clock = iter([0.0] + [0.3, 0.6, 0.9, 1.2] + [9.0] * 50)
    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.time.monotonic',
        lambda: next(clock))

    with pytest.raises(TimeoutError):
        sock.recv(4096)

    # Each discarded datagram shortens the remaining budget rather than
    # restarting it, so a flood cannot hold recv open past its deadline.
    assert inner.timeouts[-1] < 1.0
    assert inner.inbound, 'recv consumed the whole flood instead of timing out'


def test_ipv6_scope_is_part_of_host_identity():
    endpoint = ResolvedUdpEndpoint(
        socket.AF_INET6, ('2001:db8::10', 5684, 0, 2))
    inner = _RecordingUdpSocket(
        socket.AF_INET6,
        inbound=[
            (b'\x16wrong-if', ('2001:db8::10', 5684, 0, 3)),
            (b'\x16right-if', ('2001:db8::10', 59768, 0, 2)),
        ],
    )
    sock = HostFilteredUdpSocket(inner, endpoint)

    # The same address arriving with a different scope is a different peer,
    # which is what keeps a link-local reply from another interface out.
    assert sock.recv(4096) == b'\x16right-if'


def test_open_host_filtered_udp_socket_binds_without_connecting(monkeypatch):
    created = []

    def factory(family, _socktype, _protocol):
        sock = _RecordingUdpSocket(family)
        created.append(sock)
        return sock

    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.socket', factory)
    monkeypatch.setattr(
        'smartthings_local.protocol.endpoint.socket.getaddrinfo',
        lambda *_a, **_k: [_addrinfo(socket.AF_INET, ('192.0.2.10', 5684))])

    sock, endpoint = open_host_filtered_udp_socket(
        '192.0.2.10', 5684, timeout=2.0)

    assert isinstance(sock, HostFilteredUdpSocket)
    assert endpoint.port == 5684
    assert created[0].bound == ('', 0)
    assert not hasattr(created[0], 'peer')
    assert sock.gettimeout() == 2.0
    sock.close()
    assert created[0].closed
