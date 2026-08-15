"""Public OCF secure-port discovery stays bounded and source-correlated."""

import socket
import threading
import time
import traceback
from dataclasses import FrozenInstanceError

import cbor2
import pytest

from smartthings_local.errors import EndpointError
from smartthings_local.protocol import ocf_discovery as discovery
from smartthings_local.protocol.coap import (
    ACCEPT,
    BLOCK2,
    CF_CBOR,
    CONTENT_FORMAT,
    ETAG,
    METHOD_GET,
    SIZE2,
    TYPE_ACK,
    TYPE_CON,
    TYPE_NON,
    URI_PATH,
    URI_QUERY,
    block_value,
    build_coap,
    parse_coap,
)

# Synthetic private-use UDP fixtures; none are captured appliance endpoints.


def _doxm_link(port=61002, *, endpoints=None):
    link = {
        'href': '/oic/sec/doxm',
        'rt': ['oic.r.doxm'],
        'p': {'sec': True, 'port': port},
    }
    if endpoints is not None:
        link['eps'] = [{'ep': endpoint} for endpoint in endpoints]
    return link


def _eps_link(*endpoints, href='/oic/d'):
    return {
        'href': href,
        'rt': ['oic.wk.d'],
        'eps': [{'ep': endpoint} for endpoint in endpoints],
    }


def _payload(*links, padding=''):
    value = {'links': list(links)}
    if padding:
        value['padding'] = padding
    return cbor2.dumps(value)


def _option_map(options):
    result = {}
    for number, value in options:
        result.setdefault(number, []).append(value)
    return result


def _uint_bytes(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, 'big')


def _ipv4_key(address='192.0.2.20'):
    return socket.inet_pton(socket.AF_INET, address), 0


def test_primary_uses_source_bound_eps_from_all_links_and_ignores_legacy():
    payload = _payload(
        _doxm_link(61002),
        _eps_link(
            'coaps://192.0.2.20:61003',
            'coaps://192.0.2.20',
            'coap://192.0.2.20:61004',
            'coaps+tcp://192.0.2.20:61005',
            'coaps://192.0.2.21:61006',
        ),
    )

    status, ports = discovery._primary_secure_ports_from_payload(
        payload, socket.AF_INET, _ipv4_key())

    assert status == discovery._PORTS_FOUND
    assert ports == (61003, 5684)


def test_fallback_uses_only_doxm_eps_and_legacy_ports_and_stays_bounded():
    links = [
        {'href': '/oic/d', 'rt': ['oic.wk.d'],
         'p': {'sec': True, 'port': 49000}},
        _doxm_link(
            61000,
            endpoints=[
                'coaps://192.0.2.20:61001',
                'coaps://192.0.2.21:61999',
            ],
        ),
        *[_doxm_link(port) for port in range(61002, 61012)],
    ]

    status, ports = discovery._fallback_secure_ports_from_payload(
        cbor2.dumps(links), socket.AF_INET, _ipv4_key())

    assert status == discovery._PORTS_FOUND
    assert ports == tuple(range(61000, 61008))


@pytest.mark.parametrize(
    'payload',
    (
        b'not-cbor',
        cbor2.dumps({'links': 'not-a-list'}),
        cbor2.dumps([{'links': [None]}]),
        cbor2.dumps({'links': []}) + cbor2.dumps(1),
    ),
)
@pytest.mark.parametrize(
    'extractor',
    (
        discovery._primary_secure_ports_from_payload,
        discovery._fallback_secure_ports_from_payload,
    ),
)
def test_malformed_or_trailing_cbor_is_rejected(payload, extractor):
    assert extractor(
        payload, socket.AF_INET, _ipv4_key()) == (
            discovery._PORTS_MALFORMED, ())


def test_primary_distinguishes_absence_from_untrusted_secure_eps():
    absent = _payload(_doxm_link(), _eps_link('coap://192.0.2.20:61003'))
    untrusted_values = (
        'coaps://192.0.2.21:61003',
        'coaps://appliance.invalid:61003',
        'coaps://192.0.2.20:',
        'coaps://user:secret@192.0.2.20:61003',
        'coaps://192.0.2.20:61003/path',
    )

    assert discovery._primary_secure_ports_from_payload(
        absent, socket.AF_INET, _ipv4_key()) == (
            discovery._PORTS_ABSENT, ())
    for endpoint in untrusted_values:
        assert discovery._primary_secure_ports_from_payload(
            _payload(_eps_link(endpoint)),
            socket.AF_INET,
            _ipv4_key(),
        ) == (discovery._PORTS_UNTRUSTED, ())


def test_ipv6_eps_binding_inherits_or_exactly_matches_response_scope():
    source_key = (
        socket.inet_pton(socket.AF_INET6, '2001:db8::20'),
        7,
    )
    matching = _payload(_eps_link(
        'coaps://[2001:db8::20]:62000',
        'coaps://[2001:db8::20%257]:62001',
        'coaps://[2001:db8::20%258]:62002',
    ))

    status, ports = discovery._primary_secure_ports_from_payload(
        matching, socket.AF_INET6, source_key)

    assert status == discovery._PORTS_FOUND
    assert ports == (62000, 62001)
    assert discovery._primary_secure_ports_from_payload(
        _payload(_eps_link('coaps://[2001:db8::20%258]:62002')),
        socket.AF_INET6,
        source_key,
    ) == (discovery._PORTS_UNTRUSTED, ())
    assert discovery._primary_secure_ports_from_payload(
        _payload(_eps_link('coaps://[2001:db8::21]:62003')),
        socket.AF_INET6,
        source_key,
    ) == (discovery._PORTS_UNTRUSTED, ())


def test_unfiltered_dynamic_source_and_two_block_response_are_supported():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    responder.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    responder.settimeout(2.0)
    assert listener.getsockname()[1] != responder.getsockname()[1]

    body = _payload(
        _eps_link('coaps://127.0.0.1:61002'),
        padding='x' * 300,
    )
    block_size = 256
    assert block_size < len(body) <= block_size * 2
    errors = []

    def respond():
        try:
            first_request, client = listener.recvfrom(8192)
            mtype, code, first_mid, token, options, request_payload = \
                parse_coap(first_request)
            option_map = _option_map(options)
            assert (mtype, code) == (TYPE_NON, METHOD_GET)
            assert len(token) == 8 and request_payload == b''
            assert option_map[URI_PATH] == [b'oic', b'res']
            assert URI_QUERY not in option_map
            assert option_map[ACCEPT] == [CF_CBOR]
            assert BLOCK2 not in option_map

            common = [
                (CONTENT_FORMAT, CF_CBOR),
                (ETAG, b'test'),
                (SIZE2, _uint_bytes(len(body))),
            ]
            responder.sendto(
                build_coap(
                    TYPE_CON,
                    0x45,
                    0x7001,
                    token,
                    [*common, (BLOCK2, block_value(0, 1, 4))],
                    body[:block_size],
                ),
                client,
            )
            first_ack, ack_peer = responder.recvfrom(8192)
            assert ack_peer == client
            assert parse_coap(first_ack)[:4] == (
                TYPE_ACK, 0, 0x7001, b'')

            second_request, second_client = responder.recvfrom(8192)
            mtype, code, second_mid, second_token, options, request_payload = \
                parse_coap(second_request)
            option_map = _option_map(options)
            assert second_client == client
            assert (mtype, code) == (TYPE_NON, METHOD_GET)
            assert second_token == token and second_mid != first_mid
            assert request_payload == b'' and URI_QUERY not in option_map
            assert option_map[BLOCK2] == [block_value(1, 0, 4)]

            responder.sendto(
                build_coap(
                    TYPE_CON,
                    0x45,
                    0x7002,
                    token,
                    [*common, (BLOCK2, block_value(1, 0, 4))],
                    body[block_size:],
                ),
                client,
            )
            second_ack, _ack_peer = responder.recvfrom(8192)
            assert parse_coap(second_ack)[:4] == (
                TYPE_ACK, 0, 0x7002, b'')
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=1.5,
            retries=1,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=3.0)
        listener.close()
        responder.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (61002,)
    assert result.response_received
    assert result.error_code is None
    assert result.attempts == 2


def test_absent_primary_falls_back_with_fresh_token_on_original_route():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    responder.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    responder.settimeout(2.0)
    errors = []

    def respond():
        try:
            primary, client = listener.recvfrom(8192)
            primary_parsed = parse_coap(primary)
            assert URI_QUERY not in _option_map(primary_parsed[4])
            responder.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7101,
                    primary_parsed[3],
                    [],
                    _payload({'href': '/oic/d', 'rt': ['oic.wk.d']}),
                ),
                client,
            )

            # A new logical GET starts from the original discovery socket,
            # rather than the primary response's dynamic source port.
            fallback, fallback_client = listener.recvfrom(8192)
            fallback_parsed = parse_coap(fallback)
            option_map = _option_map(fallback_parsed[4])
            assert fallback_client == client
            assert option_map[URI_QUERY] == [b'rt=oic.r.doxm']
            assert fallback_parsed[3] != primary_parsed[3]
            assert fallback_parsed[2] != primary_parsed[2]
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7102,
                    fallback_parsed[3],
                    [],
                    _payload(_doxm_link()),
                ),
                fallback_client,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=1.5,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=3.0)
        listener.close()
        responder.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (61002,)
    assert result.attempts == 2
    assert result.response_received


def test_unanswered_primary_reserves_time_for_filtered_fallback():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    errors = []

    def respond():
        try:
            primary, client = listener.recvfrom(8192)
            primary_parsed = parse_coap(primary)
            assert URI_QUERY not in _option_map(primary_parsed[4])
            fallback, fallback_client = listener.recvfrom(8192)
            fallback_parsed = parse_coap(fallback)
            assert fallback_client == client
            assert _option_map(fallback_parsed[4])[URI_QUERY] == [
                b'rt=oic.r.doxm']
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7201,
                    fallback_parsed[3],
                    [],
                    _payload(_doxm_link(61003)),
                ),
                fallback_client,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    started = time.monotonic()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.8,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        elapsed = time.monotonic() - started
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (61003,)
    assert result.attempts == 2
    assert elapsed < 1.0


@pytest.mark.parametrize(
    'primary_payload',
    (
        b'not-cbor',
        _payload(_eps_link('coaps://127.0.0.2:61002')),
    ),
)
def test_malformed_or_cross_source_primary_never_starts_fallback(
        primary_payload):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(0.4)
    errors = []
    saw_fallback = []

    def respond():
        try:
            request, client = listener.recvfrom(8192)
            parsed = parse_coap(request)
            listener.sendto(
                build_coap(
                    TYPE_NON, 0x45, 0x7301, parsed[3], [], primary_payload),
                client,
            )
            try:
                listener.recvfrom(8192)
            except TimeoutError:
                return
            saw_fallback.append(True)
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.6,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert saw_fallback == []
    assert result.ports == ()
    assert result.response_received
    assert result.error_code == 'malformed_ocf_response'


def test_stale_primary_token_is_ignored_during_fallback():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    errors = []

    def respond():
        try:
            primary, client = listener.recvfrom(8192)
            primary_token = parse_coap(primary)[3]
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7401,
                    primary_token,
                    [],
                    _payload({'href': '/oic/d'}),
                ),
                client,
            )
            fallback, fallback_client = listener.recvfrom(8192)
            fallback_token = parse_coap(fallback)[3]
            assert fallback_token != primary_token
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7402,
                    primary_token,
                    [],
                    _payload(_doxm_link(61999)),
                ),
                fallback_client,
            )
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7403,
                    fallback_token,
                    [],
                    _payload(_doxm_link(61004)),
                ),
                fallback_client,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=1.0,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (61004,)
    assert result.attempts == 2


def test_non_request_rejects_piggyback_ack_and_uses_fallback():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    errors = []

    def respond():
        try:
            primary, client = listener.recvfrom(8192)
            primary_parsed = parse_coap(primary)
            listener.sendto(
                build_coap(
                    TYPE_ACK,
                    0x45,
                    primary_parsed[2],
                    primary_parsed[3],
                    [],
                    _payload(_eps_link('coaps://127.0.0.1:61999')),
                ),
                client,
            )
            fallback, fallback_client = listener.recvfrom(8192)
            fallback_parsed = parse_coap(fallback)
            assert _option_map(fallback_parsed[4])[URI_QUERY] == [
                b'rt=oic.r.doxm']
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7501,
                    fallback_parsed[3],
                    [],
                    _payload(_doxm_link(61005)),
                ),
                fallback_client,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.8,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (61005,)
    assert result.attempts == 2


def test_wrong_token_con_is_not_acknowledged():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(0.4)
    errors = []
    unexpected_datagrams = []

    def respond():
        try:
            request, client = listener.recvfrom(8192)
            token = parse_coap(request)[3]
            listener.sendto(
                build_coap(
                    TYPE_CON,
                    0x45,
                    0x7601,
                    b'badtoken',
                    [],
                    _payload(_eps_link('coaps://127.0.0.1:61999')),
                ),
                client,
            )
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7602,
                    token,
                    [],
                    _payload(_eps_link('coaps://127.0.0.1:61006')),
                ),
                client,
            )
            try:
                unexpected_datagrams.append(listener.recvfrom(8192))
            except TimeoutError:
                pass
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.8,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert unexpected_datagrams == []
    assert result.ports == (61006,)


def test_partial_block_transfer_stays_pinned_and_fails_closed():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    first_responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other_responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    first_responder.bind(('127.0.0.1', 0))
    other_responder.bind(('127.0.0.1', 0))
    listener.settimeout(1.0)
    first_responder.settimeout(1.0)
    body = _payload(
        _eps_link('coaps://127.0.0.1:61007'), padding='x' * 10)
    assert 64 < len(body) <= 128
    errors = []

    def respond():
        try:
            request, client = listener.recvfrom(8192)
            token = parse_coap(request)[3]
            first_responder.sendto(
                build_coap(
                    TYPE_NON, 0x45, 0x7701, token,
                    [(BLOCK2, block_value(0, 1, 2))], body[:64]),
                client,
            )
            _request, second_client = first_responder.recvfrom(8192)
            assert second_client == client
            other_responder.sendto(
                build_coap(
                    TYPE_NON, 0x45, 0x7702, token,
                    [(BLOCK2, block_value(1, 0, 2))], body[64:]),
                client,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=0.6,
            retries=0,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()
        first_responder.close()
        other_responder.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == ()
    assert result.response_received
    assert result.error_code == 'malformed_ocf_response'


def test_primary_retry_keeps_token_and_changes_message_id():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    listener.settimeout(2.0)
    errors = []

    def respond():
        try:
            first, client = listener.recvfrom(8192)
            second, second_client = listener.recvfrom(8192)
            first_parsed = parse_coap(first)
            second_parsed = parse_coap(second)
            assert second_client == client
            assert first_parsed[0] == second_parsed[0] == TYPE_NON
            assert first_parsed[3] == second_parsed[3]
            assert first_parsed[2] != second_parsed[2]
            assert URI_QUERY not in _option_map(second_parsed[4])
            listener.sendto(
                build_coap(
                    TYPE_NON,
                    0x45,
                    0x7801,
                    second_parsed[3],
                    [],
                    _payload(_eps_link('coaps://127.0.0.1:61008')),
                ),
                client,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced through errors below
            errors.append(exc)

    thread = threading.Thread(target=respond)
    thread.start()
    try:
        result = discovery.discover_ocf_secure_ports(
            '127.0.0.1',
            discovery_port=listener.getsockname()[1],
            timeout=1.0,
            retries=1,
            family=socket.AF_INET,
        )
    finally:
        thread.join(timeout=2.0)
        listener.close()

    assert not thread.is_alive()
    assert errors == []
    assert result.ports == (61008,)
    assert result.attempts == 2


def test_resolution_failure_and_result_repr_are_redacted(monkeypatch):
    remote_host = 'private-appliance.invalid'

    def fail(host, port, *, family):
        assert host == remote_host
        assert port == 5683
        assert family == socket.AF_INET6
        raise EndpointError()

    monkeypatch.setattr(discovery, 'resolve_udp_endpoints', fail)

    result = discovery.discover_ocf_secure_ports(
        remote_host, family=socket.AF_INET6)
    rendered = repr(result) + ''.join(
        traceback.format_exception(EndpointError()))

    assert result.error_code == 'endpoint_unavailable'
    assert result.attempts == 0
    assert remote_host not in rendered
    assert '61002' not in repr(
        discovery.OcfSecurePortDiscoveryResult((61002,), 1, True))


def test_result_is_immutable_and_ipv6_scope_is_part_of_source_identity():
    result = discovery.OcfSecurePortDiscoveryResult((61002,), 1, True)

    with pytest.raises(FrozenInstanceError):
        result.attempts = 2
    assert discovery._host_key(
        socket.AF_INET, ('192.0.2.20', 5683)) != discovery._host_key(
            socket.AF_INET, ('192.0.2.21', 5683))
    assert discovery._host_key(
        socket.AF_INET6, ('2001:db8::20', 5683, 0, 7)) != \
        discovery._host_key(
            socket.AF_INET6, ('2001:db8::20', 5683, 0, 8))


@pytest.mark.parametrize(
    ('keyword', 'value', 'error_type'),
    (
        ('discovery_port', 0, ValueError),
        ('discovery_port', True, TypeError),
        ('timeout', 0, ValueError),
        ('timeout', float('nan'), ValueError),
        ('timeout', True, TypeError),
        ('retries', 5, ValueError),
        ('retries', True, TypeError),
        ('family', 9999, ValueError),
        ('family', 'AF_INET', TypeError),
    ),
)
def test_invalid_options_fail_before_network(keyword, value, error_type):
    with pytest.raises(error_type):
        discovery.discover_ocf_secure_ports(
            '192.0.2.20', **{keyword: value})
