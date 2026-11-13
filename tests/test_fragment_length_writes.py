"""Writes under a negotiated fragment length.

A negotiated `max_fragment_length` bounds every record, application records
included, and one CoAP message is one record on this transport. So each
message `post()` sends has to fit whole, header and options with it. Before
this, `post()` chose Block1 only above 1024 bytes of body and always started
it at 1024-byte blocks, so at a limit of 512 or 1024 a body near either size
went out over the limit and the engine refused it with a bare `SSL.Error`.

These tests hold down three things: every message fits, the body still
arrives whole and in order, and a write that cannot fit is refused with a
`ValueError` before anything is sent.
"""

from __future__ import annotations

import pytest

import smartthings_local.protocol.dtls_session as dtls_session
from smartthings_local.protocol.coap import (
    BLOCK1,
    TYPE_ACK,
    block_fields,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_ROUTING_OPTION = (65524, b"\xc0")


class _NullAuth:
    def configure_context(self, _context):
        return None


class _Connection:
    def __init__(self, fragment_length):
        self.negotiated_fragment_length = fragment_length


def _session(fragment_length):
    """A session whose sends are answered in-process, with each size kept."""
    session = DtlsCoapSession(
        "device.example", 5684, auth=_NullAuth(), rate_limit_rps=1_000_000,
    )
    session.conn = _Connection(fragment_length)
    sizes = []
    requests = []

    def send(datagram):
        sizes.append(len(datagram))
        request = parse_coap(datagram)
        requests.append(request)
        _mtype, _code, mid, token, options, _payload = request
        blocks = [value for number, value in options if number == BLOCK1]
        if blocks:
            _num, more, _szx = block_fields(blocks[0])
            code = 0x5F if more else 0x44
            reply = build_coap(TYPE_ACK, code, mid, token, [(BLOCK1, blocks[0])])
        else:
            reply = build_coap(TYPE_ACK, 0x44, mid, token, [], b"done")
        session._dispatch_coap(reply)

    session._send_dgram = send
    return session, sizes, requests


@pytest.mark.parametrize("limit", [512, 1024])
@pytest.mark.parametrize("body_size", [1, 400, 500, 900, 1000, 1024, 1025, 3000])
def test_every_message_fits_and_the_body_arrives_whole(limit, body_size):
    session, sizes, requests = _session(limit)
    body = bytes(index % 251 for index in range(body_size))

    session.post(["oic", "sec", "cred"], body, query=("if=oic.if.b",))

    assert max(sizes) <= limit
    assert b"".join(request[5] for request in requests) == body


def test_a_body_that_fits_one_message_stays_single_frame():
    session, _sizes, requests = _session(1024)
    assert session.post(["resource"], b"x" * 900) == (0x44, b"done")
    assert len(requests) == 1
    assert not any(number == BLOCK1 for number, _value in requests[0][4])


def test_a_body_under_1024_that_does_not_fit_uses_block1():
    """The old rule kept this single-frame: 1010 bytes of body plus 22 of header."""
    session, sizes, requests = _session(1024)
    session.post(["resource"], b"x" * 1010)
    assert len(requests) > 1
    assert max(sizes) <= 1024


def test_the_block_size_is_the_largest_that_fits():
    session, _sizes, requests = _session(512)
    session.post(["resource"], b"x" * 1000)
    first = next(value for number, value in requests[0][4] if number == BLOCK1)
    # 512-byte blocks cannot fit a 512-byte record with a header, so 256.
    assert block_fields(first)[2] == 4


def test_extra_options_count_against_the_limit():
    session, sizes, _requests = _session(512)
    session.post(
        ["resource"], b"x" * 600,
        extra_options=((2049, b"\x08\x00" * 100), _ROUTING_OPTION),
    )
    assert max(sizes) <= 512


def test_without_a_limit_nothing_changes():
    session, sizes, requests = _session(None)
    session.post(["resource"], b"x" * 1024)
    assert len(requests) == 1
    session.post(["resource"], b"x" * 1025)
    assert [len(request[5]) for request in requests[1:]] == [1024, 1]


def test_options_that_leave_no_room_are_refused_before_send():
    session, _sizes, requests = _session(512)
    with pytest.raises(ValueError, match="negotiated fragment length of 512"):
        session.post(
            ["resource"], b"x" * 600,
            extra_options=((2049, b"\x00" * 500),),
        )
    assert requests == []


def test_a_body_that_needs_too_many_blocks_is_refused_before_send(monkeypatch):
    monkeypatch.setattr(dtls_session, "_MAX_BLOCK1_REQUESTS", 3)
    session, _sizes, requests = _session(512)
    with pytest.raises(ValueError, match="more Block1 requests"):
        session.post(["resource"], b"x" * 1000)
    assert requests == []


def test_send_refuses_an_over_length_message_with_a_typed_error():
    """The engine's own refusal is a bare SSL.Error that no caller handles."""

    class _Refusing:
        negotiated_fragment_length = 512

        def send(self, _data):
            raise AssertionError("an over-length message reached the engine")

    session = DtlsCoapSession("device.example", 5684, auth=_NullAuth())
    session.conn = _Refusing()
    with pytest.raises(ValueError, match="exceeds the negotiated fragment"):
        session._send_dgram(b"x" * 513)


def test_the_size_helper_matches_a_real_token():
    session = DtlsCoapSession("device.example", 5684, auth=_NullAuth())
    token = session._next_tok()
    options = [(11, b"resource")]
    assert dtls_session._request_size(options, b"body") == len(
        build_coap(0, 2, 0, token, options, b"body"))
