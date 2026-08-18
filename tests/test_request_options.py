"""Validated URI query and additional CoAP request option tests."""

from __future__ import annotations

import pytest

from smartthings_local.errors import (
    BlockwiseError,
    SessionClosedError,
    SessionTimeoutError,
)
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.coap import (
    ACCEPT,
    BLOCK1,
    BLOCK2,
    CONTENT_FORMAT,
    METHOD_DELETE,
    METHOD_GET,
    METHOD_POST,
    OBSERVE,
    SIZE1,
    SIZE2,
    TYPE_ACK,
    URI_PATH,
    URI_QUERY,
    block_value,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_ROUTING_OPTION = (65524, b"\xc0")
_VERSION_OPTION = (2049, b"\x08\x00")


class _NullAuth:
    def configure_context(self, _context):
        return None


def _session(responder):
    session = DtlsCoapSession(
        "device.example",
        5684,
        auth=_NullAuth(),
        rate_limit_rps=1_000_000,
    )
    session.conn = object()
    requests = []

    def send(datagram):
        request = parse_coap(datagram)
        requests.append(request)
        response = responder(request, len(requests) - 1)
        if response is None:
            return
        responses = response if isinstance(response, (list, tuple)) else (response,)
        for item in responses:
            session._dispatch_coap(item)

    session._send_dgram = send
    return session, requests


def _response(request, payload=b"ok", *, code=0x45, options=()):
    _mtype, _code, mid, token, _options, _payload = request
    return build_coap(TYPE_ACK, code, mid, token, options, payload)


def _block1_response(request, *, block=None, code=None, payload=b""):
    request_block = next(value for number, value in request[4] if number == BLOCK1)
    _num, more, _szx = dtls_session.block_fields(request_block)
    if block is None:
        block = request_block
    if code is None:
        code = 0x5F if more else 0x44
    return _response(
        request,
        payload,
        code=code,
        options=((BLOCK1, block),),
    )


def test_get_keeps_query_and_extra_options_on_every_block():
    def respond(request, request_number):
        if request_number == 0:
            return _response(
                request,
                b"a" * 1024,
                options=((BLOCK2, block_value(0, 1, 6)),),
            )
        return _response(
            request,
            b"done",
            options=((BLOCK2, block_value(1, 0, 6)),),
        )

    session, requests = _session(respond)
    code, payload = session.get(
        ["oic", "res"],
        query=("rt=oic.r.doxm", "if=oic.if.baseline"),
        extra_options=(_VERSION_OPTION, _ROUTING_OPTION),
    )

    assert code == 0x45
    assert payload == b"a" * 1024 + b"done"
    assert len(requests) == 2
    assert all(request[1] == METHOD_GET for request in requests)
    for request in requests:
        options = request[4]
        assert [value for number, value in options if number == URI_PATH] == [
            b"oic",
            b"res",
        ]
        assert [value for number, value in options if number == URI_QUERY] == [
            b"rt=oic.r.doxm",
            b"if=oic.if.baseline",
        ]
        assert _VERSION_OPTION in options
        assert _ROUTING_OPTION in options
    assert not [value for number, value in requests[0][4] if number == BLOCK2]
    assert [value for number, value in requests[1][4] if number == BLOCK2] == [
        block_value(1, 0, 6)
    ]


def test_post_encodes_repeated_queries_and_ordered_extra_options():
    session, requests = _session(lambda request, _number: _response(request))

    assert session.post(
        ["mode", "vs", "0"],
        b"payload",
        query=("if=oic.if.a", "x.example=value"),
        extra_options=(_VERSION_OPTION, _ROUTING_OPTION),
    ) == (0x45, b"ok")

    assert len(requests) == 1
    _mtype, code, _mid, _token, options, payload = requests[0]
    assert code == METHOD_POST
    assert payload == b"payload"
    assert [value for number, value in options if number == URI_QUERY] == [
        b"if=oic.if.a",
        b"x.example=value",
    ]
    assert _VERSION_OPTION in options
    assert _ROUTING_OPTION in options


@pytest.mark.parametrize(
    ("body_size", "chunk_sizes"),
    (
        (1024, [1024]),
        (1025, [1024, 1]),
        (2048, [1024, 1024]),
        (2049, [1024, 1024, 1]),
    ),
)
def test_post_uses_block1_only_above_one_ocf_block(body_size, chunk_sizes):
    body = bytes(range(256)) * (body_size // 256) + bytes(range(body_size % 256))

    def respond(request, _number):
        if any(number == BLOCK1 for number, _value in request[4]):
            return _block1_response(request)
        return _response(request, b"final", code=0x44)

    session, requests = _session(respond)
    expected_payload = b"final" if body_size <= 1024 else b""
    assert session.post(["resource"], body) == (0x44, expected_payload)

    assert [len(request[5]) for request in requests] == chunk_sizes
    assert b"".join(request[5] for request in requests) == body
    if body_size <= 1024:
        assert not any(number == BLOCK1 for number, _value in requests[0][4])
        assert not any(number == SIZE1 for number, _value in requests[0][4])
        return
    assert len({request[3] for request in requests}) == 1
    assert len({request[2] for request in requests}) == len(requests)
    first_size = next(value for number, value in requests[0][4] if number == SIZE1)
    assert int.from_bytes(first_size, "big") == body_size
    assert all(
        not any(number == SIZE1 for number, _value in request[4])
        for request in requests[1:]
    )


def test_block1_keeps_queries_and_extensions_on_every_request():
    session, requests = _session(lambda request, _number: _block1_response(request))
    body = b"x" * 2050

    assert session.post(
        ["oic", "sec", "cred"],
        body,
        query=("if=oic.if.b",),
        extra_options=(_VERSION_OPTION, _ROUTING_OPTION),
    ) == (0x44, b"")

    assert len(requests) == 3
    for request in requests:
        assert (URI_QUERY, b"if=oic.if.b") in request[4]
        assert _VERSION_OPTION in request[4]
        assert _ROUTING_OPTION in request[4]


def test_block1_honours_a_smaller_server_block_size():
    body = b"x" * 1600

    def respond(request, request_number):
        request_block = next(value for number, value in request[4] if number == BLOCK1)
        if request_number == 0:
            return _block1_response(request, block=block_value(1, 1, 5))
        return _block1_response(request, block=request_block)

    session, requests = _session(respond)
    assert session.post(["oic", "sec", "cred"], body) == (0x44, b"")

    assert [len(request[5]) for request in requests] == [1024, 512, 64]
    assert [
        next(value for number, value in request[4] if number == BLOCK1)
        for request in requests
    ] == [
        block_value(0, 1, 6),
        block_value(2, 1, 5),
        block_value(3, 0, 5),
    ]


def test_block1_ignores_a_late_acknowledgement_for_the_previous_chunk():
    first_response = None

    def respond(request, request_number):
        nonlocal first_response
        response = _block1_response(request)
        if request_number == 0:
            first_response = response
            return response
        if request_number == 1:
            return [first_response, response]
        return response

    session, requests = _session(respond)
    assert session.post(["resource"], b"x" * 2049) == (0x44, b"")
    assert len(requests) == 3


def test_block1_retransmits_the_identical_request(monkeypatch):
    monkeypatch.setattr(dtls_session, "_BLOCK_ACK_TIMEOUT", 0.01)

    def respond(request, request_number):
        if request_number == 0:
            return None
        return _block1_response(request)

    session, requests = _session(respond)
    assert session.post(["resource"], b"x" * 1025, timeout=1.0) == (0x44, b"")

    assert requests[0] == requests[1]
    assert requests[0][2] == requests[1][2]
    assert requests[0][3] == requests[1][3]


@pytest.mark.parametrize(
    ("response", "error_type"),
    (
        (lambda request: _response(request, code=0x44), BlockwiseError),
        (lambda request: _response(request, code=0x5F), BlockwiseError),
        (
            lambda request: _block1_response(
                request, block=block_value(0, 0, 6), code=0x5F
            ),
            BlockwiseError,
        ),
        (
            lambda request: _block1_response(
                request, block=block_value(0, 1, 7), code=0x5F
            ),
            SessionTimeoutError,
        ),
    ),
)
def test_block1_rejects_non_atomic_intermediate_success(response, error_type):
    session, _requests = _session(lambda request, _number: response(request))

    with pytest.raises(error_type):
        session.post(["resource"], b"x" * 1025, timeout=0.05)


def test_block1_returns_an_intermediate_error_without_sending_more():
    session, requests = _session(
        lambda request, _number: _response(request, b"rejected", code=0x80)
    )

    assert session.post(["resource"], b"x" * 1025) == (0x80, b"rejected")
    assert len(requests) == 1


def test_block1_rejects_continue_as_the_final_response():
    def respond(request, _number):
        block = next(value for number, value in request[4] if number == BLOCK1)
        _num, more, _szx = dtls_session.block_fields(block)
        return _block1_response(request, code=0x5F if not more else None)

    session, _requests = _session(respond)
    with pytest.raises(BlockwiseError):
        session.post(["resource"], b"x" * 1025)


def test_block1_refuses_oversized_bodies_before_send():
    session, requests = _session(lambda request, _number: _block1_response(request))

    with pytest.raises(ValueError, match="524288"):
        session.post(["resource"], b"x" * (512 * 1024 + 1))

    assert requests == []


def test_block1_request_cap_fails_closed_before_the_next_send(monkeypatch):
    monkeypatch.setattr(dtls_session, "_MAX_BLOCK1_REQUESTS", 1)
    session, requests = _session(lambda request, _number: _block1_response(request))

    with pytest.raises(BlockwiseError):
        session.post(["resource"], b"x" * 1025)

    assert len(requests) == 1


def test_block1_timeout_and_reader_death_retire_pending_tokens(monkeypatch):
    monkeypatch.setattr(dtls_session, "_BLOCK_ACK_TIMEOUT", 0.01)
    session, requests = _session(lambda _request, _number: None)
    with pytest.raises(SessionTimeoutError):
        session.post(["resource"], b"x" * 1025, timeout=0.02)
    assert requests
    assert session._pending == {}

    def stop_reader(_request, _number):
        session._reader_thread = object()
        session._reader_running.clear()

    session, _requests = _session(stop_reader)
    with pytest.raises(SessionClosedError):
        session.post(["resource"], b"x" * 1025, timeout=1.0)
    assert session._pending == {}


def test_delete_encodes_queries_and_extensions_without_a_payload():
    session, requests = _session(lambda request, _number: _response(request))

    assert session.delete(
        ["oic", "sec", "cred"],
        query=("subjectuuid=peer",),
        extra_options=(_ROUTING_OPTION,),
    ) == (0x45, b"ok")

    assert len(requests) == 1
    _mtype, code, _mid, _token, options, payload = requests[0]
    assert code == METHOD_DELETE
    assert payload == b""
    assert [value for number, value in options if number == URI_QUERY] == [
        b"subjectuuid=peer"
    ]
    assert not [value for number, value in options if number == CONTENT_FORMAT]
    assert _ROUTING_OPTION in options


def test_delete_is_paced_before_send():
    session, requests = _session(lambda request, _number: _response(request))
    order = []

    session.pace = lambda: order.append("pace")
    original_send = session._send_dgram

    def send(datagram):
        order.append("send")
        original_send(datagram)

    session._send_dgram = send

    assert session.delete(["resource"]) == (0x45, b"ok")
    assert order == ["pace", "send"]
    assert len(requests) == 1


def test_delete_timeout_retires_its_pending_token():
    session, requests = _session(lambda _request, _number: None)

    with pytest.raises(SessionTimeoutError):
        session.delete(["resource"], timeout=0)

    assert len(requests) == 1
    assert session._pending == {}


@pytest.mark.parametrize(
    ("operation", "error_type"),
    (
        (lambda session: session.get("oic"), TypeError),
        (lambda session: session.get([1]), TypeError),
        (lambda session: session.get(["x" * 1025]), ValueError),
        (lambda session: session.get(["\ud800"]), ValueError),
        (lambda session: session.get(["oic"], query="x=y"), TypeError),
        (lambda session: session.get(["oic"], query=(1,)), TypeError),
        (lambda session: session.get(["oic"], query=("",)), ValueError),
        (lambda session: session.get(["oic"], query=("x" * 1025,)), ValueError),
        (
            lambda session: session.get(["oic"], query=("x=y",) * 33),
            ValueError,
        ),
        (lambda session: session.post(["oic"], bytearray(b"x")), TypeError),
        (
            lambda session: session.get(["oic"], extra_options=(("2049", b"x"),)),
            TypeError,
        ),
        (
            lambda session: session.get(
                ["oic"], extra_options=((2049, bytearray(b"x")),)
            ),
            TypeError,
        ),
        (
            lambda session: session.get(["oic"], extra_options=((2049, b"x" * 1025),)),
            ValueError,
        ),
        (
            lambda session: session.get(
                ["oic"], extra_options=((65524, b"x"), (2049, b"y"))
            ),
            ValueError,
        ),
        (
            lambda session: session.get(["oic"], extra_options=((0, b"x"),)),
            ValueError,
        ),
        (
            lambda session: session.get(["oic"], extra_options=((65536, b"x"),)),
            ValueError,
        ),
        (
            lambda session: session.get(
                ["oic"], extra_options=tuple((2049, b"x") for _ in range(33))
            ),
            ValueError,
        ),
    ),
)
def test_invalid_request_options_fail_before_send(operation, error_type):
    session, requests = _session(lambda request, _number: _response(request))

    with pytest.raises(error_type):
        operation(session)

    assert requests == []


@pytest.mark.parametrize(
    "option_number",
    (
        URI_PATH,
        URI_QUERY,
        OBSERVE,
        CONTENT_FORMAT,
        ACCEPT,
        BLOCK2,
        BLOCK1,
        SIZE2,
        SIZE1,
    ),
)
def test_transport_managed_options_cannot_be_overridden(option_number):
    session, requests = _session(lambda request, _number: _response(request))

    with pytest.raises(ValueError, match="managed"):
        session.get(["oic"], extra_options=((option_number, b"x"),))

    assert requests == []


def test_repeated_additional_option_numbers_preserve_order():
    session, requests = _session(lambda request, _number: _response(request))
    repeated = ((2049, b"a"), (2049, b"b"))

    session.get(["oic"], extra_options=repeated)

    assert [item for item in requests[0][4] if item[0] == 2049] == list(repeated)


def test_validation_errors_do_not_echo_option_values():
    session, _requests = _session(lambda request, _number: _response(request))
    private_value = b"credential-value"

    with pytest.raises(ValueError) as error:
        session.get(
            ["oic"],
            extra_options=((65524, private_value), (2049, b"out-of-order")),
        )

    assert private_value.decode() not in str(error.value)
