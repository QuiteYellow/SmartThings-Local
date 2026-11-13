"""Per-call Block2 caps on DtlsCoapSession.get().

get() takes ``max_payload_bytes`` and ``max_blocks`` for a single large read
the caller asked for. ``None`` keeps the caps every other read gets, and the
two are independent: either one ends a transfer on its own.

The small-block cases model a server that answers block 0 at the 1024 bytes
requested while advertising a smaller SZX, then serves the rest at that size.
At 64-byte blocks the default block count is reached at about 5 KB, far
inside the default byte cap, which is why the block count is a parameter too.
"""

from __future__ import annotations

import pytest

from smartthings_local.errors import BlockwiseError
from smartthings_local.protocol.coap import (
    BLOCK2,
    BLOCK_SZX,
    ETAG,
    MAX_BLOCK2_BLOCKS,
    MAX_BLOCK2_PAYLOAD_BYTES,
    TYPE_ACK,
    block_fields,
    block_value,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_LARGE = 1 << (BLOCK_SZX + 4)
_SMALL_SZX = 2
_SMALL = 1 << (_SMALL_SZX + 4)


class _NullAuth:
    def configure_context(self, _context):
        return None


def _body(length):
    return bytes(range(256)) * (length // 256) + b"x" * (length % 256)


def _small_block_body(blocks):
    """One 1024-byte block 0, then `blocks - 1` full 64-byte blocks."""
    return _body(_LARGE + (blocks - 1) * _SMALL)


def _serve(body, *, szx=BLOCK_SZX, etag_change_on_first_token=False,
           session_cls=DtlsCoapSession):
    """A session whose fake device serves `body`.

    Block 0 is always 1024 bytes. Every later block is served at `szx`, so
    an `szx` below BLOCK_SZX is a downshift after the first block. With
    `etag_change_on_first_token`, the first transfer's ETag changes after
    block 0, which makes get() restart once under a fresh token.
    """
    session = session_cls(
        "device.example", 5684, auth=_NullAuth(), rate_limit_rps=1_000_000
    )
    session.conn = object()
    session.pace = lambda: None
    sent = []
    tokens = []

    def send(datagram):
        request = parse_coap(datagram)
        sent.append(request)
        _mtype, _code, mid, token, options, _payload = request
        if token not in tokens:
            tokens.append(token)
        asked = [value for number, value in options if number == BLOCK2]
        if asked:
            num, _more, asked_szx = block_fields(asked[0])
            offset = num * (1 << (asked_szx + 4))
        else:
            offset = 0
        size = _LARGE if offset == 0 else 1 << (szx + 4)
        chunk = body[offset:offset + size]
        more = offset + len(chunk) < len(body)
        response_options = []
        if etag_change_on_first_token:
            first_transfer = token == tokens[0]
            etag = b"\x02" if first_transfer and offset else b"\x01"
            response_options.append((ETAG, etag))
        response_options.append(
            (BLOCK2, block_value(offset // (1 << (szx + 4)), int(more), szx))
        )
        session._dispatch_coap(build_coap(
            TYPE_ACK, 0x45, mid, token, tuple(response_options), chunk,
        ))

    session._send_dgram = send
    return session, sent, tokens


def _get(session, **kwargs):
    return session.get(["file", "transfer", "vs", "0"], **kwargs)


# ---- defaults are unchanged ------------------------------------------------


def test_default_caps_still_refuse_a_transfer_just_over_64_kib():
    session, sent, _tokens = _serve(_body(MAX_BLOCK2_PAYLOAD_BYTES + 1))

    with pytest.raises(BlockwiseError):
        _get(session)
    # The cap fires on the 64th block, which still says more is coming.
    assert len(sent) == MAX_BLOCK2_BLOCKS


def test_default_caps_still_accept_exactly_64_kib():
    body = _body(MAX_BLOCK2_PAYLOAD_BYTES)
    session, sent, _tokens = _serve(body)

    assert _get(session) == (0x45, body)
    assert len(sent) == MAX_BLOCK2_BLOCKS


def test_default_caps_still_refuse_more_than_64_small_blocks():
    body = _small_block_body(MAX_BLOCK2_BLOCKS + 1)
    assert len(body) < MAX_BLOCK2_PAYLOAD_BYTES // 8
    session, sent, _tokens = _serve(body, szx=_SMALL_SZX)

    with pytest.raises(BlockwiseError):
        _get(session)
    assert len(sent) == MAX_BLOCK2_BLOCKS


def test_explicit_none_is_the_default():
    session, sent, _tokens = _serve(_body(MAX_BLOCK2_PAYLOAD_BYTES + 1))

    with pytest.raises(BlockwiseError):
        _get(session, max_payload_bytes=None, max_blocks=None)
    assert len(sent) == MAX_BLOCK2_BLOCKS


# ---- each cap on its own ---------------------------------------------------


class _ManyBlockSession(DtlsCoapSession):
    # A subclass raising the block count is the existing hook; with it,
    # max_payload_bytes is the only cap left at its default.
    MAX_BLOCKS = 4 * MAX_BLOCK2_BLOCKS


def test_max_payload_bytes_alone_completes_a_large_block_transfer():
    # 100 blocks of 1024: under this session's block cap, over the byte cap.
    body = _body(100 * _LARGE)
    session, _sent, _tokens = _serve(body, session_cls=_ManyBlockSession)
    with pytest.raises(BlockwiseError):
        _get(session)

    session, sent, _tokens = _serve(body, session_cls=_ManyBlockSession)
    assert _get(session, max_payload_bytes=len(body)) == (0x45, body)
    assert len(sent) == 100


def test_max_payload_bytes_alone_stops_at_the_default_block_cap():
    # At 1024-byte blocks the default block count is the default byte cap,
    # so raising bytes alone cannot carry a transfer past 64 KiB.
    body = _body(MAX_BLOCK2_PAYLOAD_BYTES + _LARGE)
    session, sent, _tokens = _serve(body)

    with pytest.raises(BlockwiseError):
        _get(session, max_payload_bytes=2 * MAX_BLOCK2_PAYLOAD_BYTES)
    assert len(sent) == MAX_BLOCK2_BLOCKS


def test_max_blocks_alone_completes_a_small_block_transfer():
    blocks = 4 * MAX_BLOCK2_BLOCKS
    body = _small_block_body(blocks)
    assert len(body) < MAX_BLOCK2_PAYLOAD_BYTES
    session, sent, _tokens = _serve(body, szx=_SMALL_SZX)

    assert _get(session, max_blocks=blocks) == (0x45, body)
    assert len(sent) == blocks


def test_max_blocks_alone_leaves_the_default_byte_cap_in_place():
    # Enough blocks allowed, but the body is over 64 KiB.
    body = _body(MAX_BLOCK2_PAYLOAD_BYTES + _LARGE)
    session, _sent, _tokens = _serve(body)

    with pytest.raises(BlockwiseError):
        _get(session, max_blocks=4 * MAX_BLOCK2_BLOCKS)


# ---- both raised -----------------------------------------------------------


def test_both_raised_complete_a_transfer_over_both_default_caps():
    blocks = 2 * MAX_BLOCK2_BLOCKS
    body = _body(blocks * _LARGE)
    assert len(body) > MAX_BLOCK2_PAYLOAD_BYTES
    session, sent, _tokens = _serve(body)

    assert _get(
        session, max_payload_bytes=len(body), max_blocks=blocks,
    ) == (0x45, body)
    assert len(sent) == blocks


def test_both_raised_complete_a_large_small_block_transfer():
    blocks = (MAX_BLOCK2_PAYLOAD_BYTES * 2 - _LARGE) // _SMALL + 1
    body = _small_block_body(blocks)
    assert len(body) == 2 * MAX_BLOCK2_PAYLOAD_BYTES
    session, sent, _tokens = _serve(body, szx=_SMALL_SZX)

    assert _get(
        session, max_payload_bytes=len(body), max_blocks=blocks,
    ) == (0x45, body)
    assert len(sent) == blocks


# ---- caps set below what the transfer needs --------------------------------


def test_max_payload_bytes_below_the_transfer_fails_like_the_default():
    body = _body(3 * _LARGE)
    session, sent, _tokens = _serve(body)

    with pytest.raises(BlockwiseError):
        _get(session, max_payload_bytes=len(body) - 1)
    assert len(sent) == 3


def test_max_blocks_below_the_transfer_fails_like_the_default():
    body = _small_block_body(10)
    session, sent, _tokens = _serve(body, szx=_SMALL_SZX)

    with pytest.raises(BlockwiseError):
        _get(session, max_blocks=9)
    assert len(sent) == 9


def test_max_blocks_equal_to_the_transfer_is_enough():
    body = _small_block_body(10)
    session, _sent, _tokens = _serve(body, szx=_SMALL_SZX)

    assert _get(session, max_blocks=10) == (0x45, body)


# ---- subclass override -----------------------------------------------------


class _EightBlockSession(DtlsCoapSession):
    MAX_BLOCKS = 8


def test_subclass_max_blocks_applies_by_default():
    session, sent, _tokens = _serve(
        _body(9 * _LARGE), session_cls=_EightBlockSession)

    with pytest.raises(BlockwiseError):
        _get(session)
    assert len(sent) == 8


def test_subclass_max_blocks_applies_when_only_bytes_are_raised():
    session, sent, _tokens = _serve(
        _body(9 * _LARGE), session_cls=_EightBlockSession)

    with pytest.raises(BlockwiseError):
        _get(session, max_payload_bytes=2 * MAX_BLOCK2_PAYLOAD_BYTES)
    assert len(sent) == 8


def test_explicit_max_blocks_overrides_the_subclass():
    body = _body(9 * _LARGE)
    session, _sent, _tokens = _serve(body, session_cls=_EightBlockSession)

    assert _get(session, max_blocks=9) == (0x45, body)


# ---- validation ------------------------------------------------------------


_INVALID = [
    pytest.param(True, TypeError, id="bool"),
    pytest.param(0, ValueError, id="zero"),
    pytest.param(-1, ValueError, id="negative"),
    pytest.param("1024", TypeError, id="str"),
    pytest.param(1.5, TypeError, id="float"),
]


@pytest.mark.parametrize("name", ["max_payload_bytes", "max_blocks"])
@pytest.mark.parametrize("value, error", _INVALID)
def test_invalid_cap_raises_before_anything_is_sent(name, value, error):
    body = _body(2 * _LARGE)
    session, sent, _tokens = _serve(body)
    token_before = session._tok_counter

    with pytest.raises(error, match=name):
        _get(session, **{name: value})
    assert sent == []

    # The rejected call left nothing behind: the next read is an ordinary
    # one under the default caps.
    assert session._tok_counter == token_before
    assert _get(session) == (0x45, body)


def test_raised_caps_do_not_outlive_the_call():
    body = _body(100 * _LARGE)
    session, _sent, _tokens = _serve(body, session_cls=_ManyBlockSession)

    assert _get(session, max_payload_bytes=len(body)) == (0x45, body)
    with pytest.raises(BlockwiseError):
        _get(session)


# ---- ETag restart ----------------------------------------------------------


def test_etag_restart_uses_the_callers_block_cap():
    blocks = 2 * MAX_BLOCK2_BLOCKS
    body = _small_block_body(blocks)
    session, sent, tokens = _serve(
        body, szx=_SMALL_SZX, etag_change_on_first_token=True)

    assert _get(session, max_blocks=blocks) == (0x45, body)
    # The first transfer stopped at block 1 on the ETag change; the second
    # ran to the end under a fresh token, past the default block cap.
    assert len(tokens) == 2
    assert len(sent) == 2 + blocks


def test_etag_restart_with_default_caps_still_hits_the_block_cap():
    body = _small_block_body(2 * MAX_BLOCK2_BLOCKS)
    session, sent, tokens = _serve(
        body, szx=_SMALL_SZX, etag_change_on_first_token=True)

    with pytest.raises(BlockwiseError):
        _get(session)
    assert len(tokens) == 2
    assert len(sent) == 2 + MAX_BLOCK2_BLOCKS


def test_etag_restart_uses_the_callers_byte_cap():
    body = _body(100 * _LARGE)
    session, sent, tokens = _serve(
        body, etag_change_on_first_token=True, session_cls=_ManyBlockSession)

    assert _get(session, max_payload_bytes=len(body)) == (0x45, body)
    assert len(tokens) == 2
    assert len(sent) == 2 + 100
