"""One derivation for the Block2 block count, used at every bound.

#122 raised the session's count after a 34-block `/device/0?if=oic.if.b`
batch was refused by a count of 32 that sat well inside the 64 KiB payload
cap enforced beside it. Two more copies of that disagreement were left: the
module default every external caller gets, and the plaintext discovery read.
These pin that all three now come from one place.
"""

from __future__ import annotations

import secrets

import pytest

from smartthings_local.errors import BlockwiseError
from smartthings_local.protocol import ocf_discovery
from smartthings_local.protocol.coap import (
    BLOCK2,
    BLOCK2_COMPLETE,
    BLOCK_SZX,
    CF_CBOR,
    CONTENT_FORMAT,
    MAX_BLOCK2_BLOCKS,
    MAX_BLOCK2_PAYLOAD_BYTES,
    TYPE_ACK,
    Block2Accumulator,
    block_value,
    build_coap,
    parse_coap_message,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_BLOCK = 1 << (BLOCK_SZX + 4)


def test_the_block_count_is_the_payload_cap_in_blocks():
    assert MAX_BLOCK2_BLOCKS * _BLOCK == MAX_BLOCK2_PAYLOAD_BYTES


@pytest.mark.parametrize(
    'blocks, payload_bytes',
    [
        (DtlsCoapSession.MAX_BLOCKS, MAX_BLOCK2_PAYLOAD_BYTES),
        (ocf_discovery._MAX_BLOCKS, ocf_discovery._MAX_PAYLOAD_BYTES),
        (MAX_BLOCK2_BLOCKS, MAX_BLOCK2_PAYLOAD_BYTES),
    ],
    ids=['dtls-session', 'plaintext-discovery', 'module-default'],
)
def test_every_bound_in_the_tree_agrees(blocks, payload_bytes):
    # A bound that disagrees with its neighbour is the #122 defect, wherever
    # it sits: the smaller one refuses transfers the larger one permits, and
    # the error names the wrong cause.
    assert blocks == MAX_BLOCK2_BLOCKS
    assert payload_bytes == MAX_BLOCK2_PAYLOAD_BYTES


def _feed(accumulator, body, *, token):
    """Drive one whole Block2 transfer into `accumulator`, SZX 6 throughout."""
    status = None
    for number in range(-(-len(body) // _BLOCK)):
        chunk = body[number * _BLOCK:(number + 1) * _BLOCK]
        more = (number + 1) * _BLOCK < len(body)
        status = accumulator.add_response(parse_coap_message(
            build_coap(
                TYPE_ACK, 0x45, 0x1234 + number, token,
                ((CONTENT_FORMAT, CF_CBOR),
                 (BLOCK2, block_value(number, int(more), BLOCK_SZX))),
                chunk,
            )
        ))
    return status


def test_the_discovery_bounds_accept_a_transfer_past_the_old_count():
    # 33 blocks is one past the count both of these carried before. The
    # plaintext directory has not been measured this large on any appliance
    # here, so this is the bound being asserted, not an observation.
    token = secrets.token_bytes(8)
    accumulator = Block2Accumulator(
        token,
        max_blocks=ocf_discovery._MAX_BLOCKS,
        max_payload_bytes=ocf_discovery._MAX_PAYLOAD_BYTES,
        accepted_content_formats={int.from_bytes(CF_CBOR, 'big')},
    )

    body = bytes(range(256)) * (33 * _BLOCK // 256)
    assert _feed(accumulator, body, token=token) == BLOCK2_COMPLETE
    assert accumulator.payload == body
    assert accumulator.blocks_received == 33


def test_the_shared_bounds_still_refuse_the_block_after_the_last():
    # Both bounds land on the same block, so the one that fires first is
    # unspecified and either error is the same answer: the body is too big.
    token = secrets.token_bytes(8)
    accumulator = Block2Accumulator(token)

    with pytest.raises(BlockwiseError):
        _feed(accumulator, b'y' * ((MAX_BLOCK2_BLOCKS + 1) * _BLOCK),
              token=token)


def test_a_transfer_filling_the_bounds_exactly_is_accepted():
    token = secrets.token_bytes(8)
    accumulator = Block2Accumulator(token)

    body = b'z' * MAX_BLOCK2_PAYLOAD_BYTES
    assert _feed(accumulator, body, token=token) == BLOCK2_COMPLETE
    assert accumulator.blocks_received == MAX_BLOCK2_BLOCKS
