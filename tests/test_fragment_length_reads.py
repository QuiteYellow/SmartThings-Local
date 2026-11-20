"""Reads under a negotiated fragment length.

The appliance firmware sends block 0 of a read at 1024 bytes, which does not
fit a record at a negotiated length of 512 or 1024, and the session is lost.
A GET that asks for a smaller block 0 gets no reply, but it stores the size
under the token, and a plain GET on the same token is then answered at that
size. Measured on a dryer on 2026-11-19: /device/0, 4607 bytes, came back in
512-byte blocks at a length of 1024.

The fake appliance below models exactly that, plus a server that answers the
primer itself, as RFC 7959 lets it. A reply over the length is dropped, which
is what the session sees when the appliance cannot write it.
"""

from __future__ import annotations

import pytest

import smartthings_local.protocol.dtls_session as dtls_session
from smartthings_local.errors import FragmentLimitTimeoutError
from smartthings_local.protocol.coap import (
    BLOCK2,
    SIZE2,
    TYPE_ACK,
    TYPE_CON,
    TYPE_NON,
    block_fields,
    block_value,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.dtls_session import (
    DtlsCoapSession,
    _block2_szx,
)

_BODY = bytes(index % 251 for index in range(4607))


class _NullAuth:
    def configure_context(self, _context):
        return None


class _Connection:
    def __init__(self, fragment_length):
        self.negotiated_fragment_length = fragment_length


class _Appliance:
    """Answers GETs the way the measured firmware does.

    ``answers_primer`` switches to a server that answers a Block2 NUM 0
    request directly, as RFC 7959 §2.4 describes.
    """

    def __init__(self, session, limit, body=_BODY, *, answers_primer=False):
        self.session = session
        self.limit = limit
        self.body = body
        self.answers_primer = answers_primer
        self.stored_szx = {}
        self.requests = []
        self.dropped = []

    def __call__(self, datagram):
        mtype, _code, mid, token, options, _payload = parse_coap(datagram)
        self.requests.append((mtype, options))
        blocks = [value for number, value in options if number == BLOCK2]
        reply_type = TYPE_ACK if mtype == TYPE_CON else TYPE_NON
        if blocks:
            num, _more, szx = block_fields(blocks[0])
            if num == 0 and not self.answers_primer:
                # The first-block branch stores the size and sends nothing.
                self.stored_szx[token] = szx
                return
        else:
            num, szx = 0, self.stored_szx.get(token, 6)
        if len(self.body) <= 1024 and num == 0:
            reply = build_coap(reply_type, 0x45, mid, token, [], self.body)
        else:
            size = 1 << (szx + 4)
            chunk = self.body[num * size:(num + 1) * size]
            more = (num + 1) * size < len(self.body)
            reply_options = [(BLOCK2, block_value(num, more, szx))]
            if num == 0:
                reply_options.append((SIZE2, len(self.body).to_bytes(2, "big")))
            reply = build_coap(reply_type, 0x45, mid, token, reply_options, chunk)
        if self.limit is not None and len(reply) > self.limit:
            self.dropped.append(len(reply))
            return
        self.session._dispatch_coap(reply)


@pytest.fixture(autouse=True)
def _short_settle(monkeypatch):
    monkeypatch.setattr(dtls_session, "_PRIMER_SETTLE_S", 0.01)


def _session(limit, **appliance_kwargs):
    session = DtlsCoapSession(
        "device.example", 5684, auth=_NullAuth(), rate_limit_rps=1_000_000,
    )
    session.conn = _Connection(limit)
    appliance = _Appliance(session, limit, **appliance_kwargs)
    session._send_dgram = appliance
    return session, appliance


def _block2(options):
    values = [value for number, value in options if number == BLOCK2]
    return block_fields(values[0]) if values else None


@pytest.mark.parametrize("limit, szx", [(512, 4), (1024, 5)])
def test_a_primed_read_returns_the_whole_body(limit, szx):
    session, appliance = _session(limit)

    assert session.get(["device", "0"]) == (0x45, _BODY)

    assert appliance.dropped == []
    primer, plain = appliance.requests[:2]
    assert primer[0] == TYPE_NON and _block2(primer[1]) == (0, False, szx)
    assert plain[0] == TYPE_CON and _block2(plain[1]) is None
    assert {_block2(options)[2] for _type, options in appliance.requests[2:]} == {szx}


def test_without_the_primer_block_0_cannot_arrive(monkeypatch):
    """The reason for the primer: unprimed, block 0 is over the length."""
    monkeypatch.setattr(dtls_session, "_block2_szx", lambda _limit: None)
    session, appliance = _session(1024)

    with pytest.raises(FragmentLimitTimeoutError):
        session.get(["device", "0"], timeout=0.3)
    assert appliance.dropped and min(appliance.dropped) > 1024


def test_a_server_that_answers_the_primer_needs_no_plain_get():
    session, appliance = _session(1024, answers_primer=True)

    assert session.get(["device", "0"]) == (0x45, _BODY)

    assert appliance.dropped == []
    assert all(_block2(options) is not None
               for _type, options in appliance.requests)


def test_without_a_limit_no_primer_is_sent():
    session, appliance = _session(None)

    assert session.get(["device", "0"]) == (0x45, _BODY)

    first_type, first_options = appliance.requests[0]
    assert first_type == TYPE_CON and _block2(first_options) is None
    assert {_block2(options)[2] for _type, options in appliance.requests[1:]} == {6}


def test_a_small_body_still_reads_after_a_primer():
    """The firmware sends a body of 1024 bytes or less whole, primer or not."""
    session, appliance = _session(1024, body=b"x" * 300)

    assert session.get(["oic", "d"]) == (0x45, b"x" * 300)
    assert appliance.dropped == []


@pytest.mark.parametrize(
    "limit, expected",
    [(None, None), (128, 2), (512, 4), (1024, 5), (2048, None), (4096, None)],
)
def test_the_primed_size_is_the_largest_that_fits(limit, expected):
    assert _block2_szx(limit) == expected


def test_a_length_too_small_for_any_block_is_refused():
    with pytest.raises(ValueError, match="no Block2 size fits"):
        _block2_szx(30)
