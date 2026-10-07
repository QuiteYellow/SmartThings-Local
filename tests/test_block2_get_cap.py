"""Block2 GET block cap versus the assembled-payload cap."""

from __future__ import annotations

import pytest

from smartthings_local.errors import BlockwiseError
from smartthings_local.protocol.coap import (
    BLOCK2,
    BLOCK_SZX,
    MAX_BLOCK2_PAYLOAD_BYTES,
    TYPE_ACK,
    block_fields,
    block_value,
    build_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_BLOCK = 1 << (BLOCK_SZX + 4)


class _NullAuth:
    def configure_context(self, _context):
        return None


def _serve(body):
    """A session whose fake device serves `body` in SZX-6 Block2 blocks."""
    session = DtlsCoapSession(
        "device.example", 5684, auth=_NullAuth(), rate_limit_rps=1_000_000
    )
    session.conn = object()
    sent = []

    def send(datagram):
        from smartthings_local.protocol.coap import parse_coap

        _mtype, _code, mid, token, options, _payload = request = parse_coap(datagram)
        sent.append(request)
        asked = [value for number, value in options if number == BLOCK2]
        num = block_fields(asked[0])[0] if asked else 0
        chunk = body[num * _BLOCK:(num + 1) * _BLOCK]
        more = (num + 1) * _BLOCK < len(body)
        session._dispatch_coap(build_coap(
            TYPE_ACK, 0x45, mid, token,
            ((BLOCK2, block_value(num, int(more), BLOCK_SZX)),), chunk,
        ))

    session._send_dgram = send
    return session, sent


def test_block_cap_covers_the_payload_cap():
    assert DtlsCoapSession.MAX_BLOCKS * _BLOCK == MAX_BLOCK2_PAYLOAD_BYTES


def test_get_reassembles_a_34_block_response():
    # 33,884 bytes is the measured /device/0?if=oic.if.b size of one
    # LCD_A311D_OV_QMD_EU_22K oven; it needs 34 blocks at SZX 6.
    body = bytes(range(256)) * (33_884 // 256) + b"x" * (33_884 % 256)
    session, sent = _serve(body)

    code, payload = session.get(["device", "0"], query=("if=oic.if.b",))

    assert code == 0x45
    assert payload == body
    assert len(sent) == 34


def test_get_still_refuses_a_response_past_the_payload_cap():
    session, _sent = _serve(b"y" * (MAX_BLOCK2_PAYLOAD_BYTES + 1))

    with pytest.raises(BlockwiseError):
        session.get(["device", "0"], query=("if=oic.if.b",))
