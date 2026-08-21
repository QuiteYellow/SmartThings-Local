"""Validated URI query and additional CoAP request option tests."""

from __future__ import annotations

import pytest

from smartthings_local.errors import SessionTimeoutError
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
        if response is not None:
            session._dispatch_coap(response)

    session._send_dgram = send
    return session, requests


def _response(request, payload=b"ok", *, options=()):
    _mtype, _code, mid, token, _options, _payload = request
    return build_coap(TYPE_ACK, 0x45, mid, token, options, payload)


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
