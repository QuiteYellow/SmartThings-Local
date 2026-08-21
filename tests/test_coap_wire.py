import pytest

from smartthings_local.errors import BlockwiseError, MalformedMessageError
from smartthings_local.protocol.coap import (
    ACCEPT,
    BLOCK2,
    BLOCK2_COMPLETE,
    BLOCK2_CONTINUE,
    BLOCK2_DUPLICATE,
    CF_CBOR,
    CONTENT_FORMAT,
    ETAG,
    METHOD_GET,
    RESPONSE_EMPTY_ACK,
    RESPONSE_IGNORE,
    RESPONSE_MESSAGE,
    SIZE2,
    TYPE_ACK,
    TYPE_CON,
    TYPE_NON,
    URI_PATH,
    URI_QUERY,
    Block2Accumulator,
    CoapMessage,
    block_fields,
    block_value,
    build_coap,
    build_empty_ack,
    build_get_request,
    classify_coap_response,
    decode_uint_option,
    encode_options,
    fmt_code,
    option_values,
    parse_coap,
)


def test_build_then_parse_roundtrip_no_payload():
    opts = [(URI_PATH, b'device'), (URI_PATH, b'0'), (ACCEPT, CF_CBOR)]
    datagram = build_coap(TYPE_CON, METHOD_GET, 0xABCD, b'\x01\x02', opts)
    mtype, code, mid, tok, parsed_opts, payload = parse_coap(datagram)
    assert mtype == TYPE_CON
    assert code == METHOD_GET
    assert mid == 0xABCD
    assert tok == b'\x01\x02'
    assert payload == b''
    assert sorted(parsed_opts) == sorted(opts)


def test_build_then_parse_roundtrip_with_payload():
    datagram = build_coap(TYPE_CON, 0x45, 1, b'\xff', [], payload=b'\xa1\x01\x02')
    _, code, _, _, _, payload = parse_coap(datagram)
    assert code == 0x45
    assert payload == b'\xa1\x01\x02'


def test_encode_options_orders_by_option_number():
    # ACCEPT (17) must be encoded after URI_PATH (11) regardless of input order
    encoded_in_order = encode_options([(URI_PATH, b'x'), (ACCEPT, CF_CBOR)])
    encoded_reversed = encode_options([(ACCEPT, CF_CBOR), (URI_PATH, b'x')])
    assert encoded_in_order == encoded_reversed


def test_block_value_encodes_num_more_szx():
    # num=2, more=1, szx=6 -> (2<<4)|(1<<3)|6 = 0x2E
    assert block_value(2, 1, 6) == bytes([0x2E])


def test_block_value_promotes_to_two_bytes_when_num_is_large():
    v = block_value(num=0xFFF, more=0, szx=0)
    assert len(v) == 2


@pytest.mark.parametrize('num, more, szx', [
    (0, 0, 0),
    (0, 1, 6),
    (2, 1, 6),
    (1, 0, 4),
    (0xFFF, 0, 0),
    (0xFFFFF, 1, 7),
])
def test_block_fields_inverts_block_value(num, more, szx):
    assert block_fields(block_value(num, more, szx)) == (num, more, szx)


def test_block_fields_treats_empty_value_as_block_zero():
    # RFC 7959 §2.2: a zero-length Block option means num=0, m=0, szx=0.
    assert block_fields(b'') == (0, 0, 0)


def test_fmt_code_formats_class_dot_detail():
    assert fmt_code(0x45) == '2.05'
    assert fmt_code(0x84) == '4.04'


@pytest.mark.parametrize('option_header', (b'\xf0', b'\x0f'))
def test_reserved_option_nibbles_raise_classified_value_error(option_header):
    datagram = b'\x40\x01\x00\x01' + option_header

    with pytest.raises(MalformedMessageError) as exc:
        parse_coap(datagram)

    assert isinstance(exc.value, ValueError)


@pytest.mark.parametrize(
    'datagram',
    (
        b'',
        b'\x40\x01\x00',
        b'\x80\x01\x00\x01',       # unsupported CoAP version
        b'\x49\x01\x00\x01' + b'x' * 9,  # reserved token length
        b'\x44\x01\x00\x01abc',    # truncated token
        b'\x40\x01\x00\x01\xd0', # truncated extended delta
        b'\x40\x01\x00\x01\xe0\x00',
        b'\x40\x01\x00\x01\x0d', # truncated extended length
        b'\x40\x01\x00\x01\x0e\x00',
        b'\x40\x01\x00\x01\x03ab',  # truncated option value
        b'\x40\x01\x00\x01\xff', # empty payload marker
    ),
)
def test_truncated_or_structurally_invalid_datagrams_are_classified(datagram):
    with pytest.raises(MalformedMessageError):
        parse_coap(datagram)


def test_non_bytes_coap_input_is_classified():
    with pytest.raises(MalformedMessageError):
        parse_coap('not wire bytes')


def test_build_get_request_adds_query_and_only_requested_block2():
    initial = build_get_request(
        TYPE_NON,
        0x1234,
        b'token',
        ('oic', b'res'),
        ('rt=oic.r.doxm',),
    )
    _, code, _, _, initial_options, _ = parse_coap(initial)
    assert code == METHOD_GET
    assert option_values(initial_options, URI_PATH) == (b'oic', b'res')
    assert option_values(initial_options, URI_QUERY) == (b'rt=oic.r.doxm',)
    assert option_values(initial_options, ACCEPT) == (CF_CBOR,)
    assert option_values(initial_options, BLOCK2) == ()

    continuation = build_get_request(
        TYPE_NON,
        0x1235,
        b'token',
        ('oic', 'res'),
        block_number=2,
        block_szx=4,
    )
    *_, continuation_options, _ = parse_coap(continuation)
    assert option_values(continuation_options, BLOCK2) == (
        block_value(2, 0, 4),
    )


def test_decode_uint_option_is_optional_unique_and_bounded():
    assert decode_uint_option([], SIZE2, max_length=4) is None
    assert decode_uint_option([(SIZE2, b'')], SIZE2, max_length=4) == 0
    assert decode_uint_option(
        [(SIZE2, b'\x01\x00')], SIZE2, max_length=4) == 256
    with pytest.raises(MalformedMessageError):
        decode_uint_option(
            [(SIZE2, b'\x01'), (SIZE2, b'\x02')],
            SIZE2,
            max_length=4,
        )
    with pytest.raises(MalformedMessageError):
        decode_uint_option([(SIZE2, b'12345')], SIZE2, max_length=4)


def test_response_classification_handles_empty_ack_then_separate_con():
    empty_ack = classify_coap_response(
        build_empty_ack(0x1234),
        token=b'token',
        request_mid=0x1234,
    )
    assert empty_ack.kind == RESPONSE_EMPTY_ACK
    assert empty_ack.acknowledgement is None

    separate = classify_coap_response(
        build_coap(
            TYPE_CON,
            0x45,
            0xBEEF,
            b'token',
            [(CONTENT_FORMAT, CF_CBOR)],
            b'body',
        ),
        token=b'token',
        request_mid=0x1234,
    )
    assert separate.kind == RESPONSE_MESSAGE
    assert separate.message.payload == b'body'
    assert parse_coap(separate.acknowledgement) == (
        TYPE_ACK,
        0,
        0xBEEF,
        b'',
        [],
        b'',
    )


def test_response_classification_accepts_matching_piggyback_ack():
    response = classify_coap_response(
        build_coap(TYPE_ACK, 0x45, 0x1234, b'token', [], b'body'),
        token=b'token',
        request_mid=0x1234,
    )
    assert response.kind == RESPONSE_MESSAGE
    assert response.acknowledgement is None

    stale = classify_coap_response(
        build_coap(TYPE_ACK, 0x45, 0x1235, b'token', [], b'body'),
        token=b'token',
        request_mid=0x1234,
    )
    assert stale.kind == RESPONSE_IGNORE


def test_nonempty_empty_ack_is_malformed():
    with pytest.raises(MalformedMessageError):
        classify_coap_response(
            build_coap(TYPE_ACK, 0, 0x1234, b'x', []),
            token=b'x',
            request_mid=0x1234,
        )


def _message(
        *, number=0, more=False, szx=0, token=b'token', payload=b'',
        etag=b'etag', content_format=60, size2=None, code=0x45,
        mtype=TYPE_NON, include_block=True):
    options = []
    if include_block:
        options.append((BLOCK2, block_value(number, more, szx)))
    if etag is not None:
        options.append((ETAG, etag))
    if content_format is not None:
        options.append((
            CONTENT_FORMAT,
            content_format.to_bytes(max(1, (content_format.bit_length() + 7) // 8),
                                    'big'),
        ))
    if size2 is not None:
        options.append((
            SIZE2,
            size2.to_bytes(max(1, (size2.bit_length() + 7) // 8), 'big'),
        ))
    return CoapMessage(
        mtype=mtype,
        code=code,
        mid=number,
        token=token,
        options=tuple(options),
        payload=payload,
    )


def test_block2_accumulator_is_token_stable_and_assembles_exact_body():
    accumulator = Block2Accumulator(
        b'token',
        accepted_content_formats={60, 10000},
    )
    first = _message(
        number=0,
        more=True,
        payload=b'a' * 16,
        size2=20,
    )
    assert accumulator.add_response(first) == BLOCK2_CONTINUE
    assert accumulator.expected_number == 1
    assert accumulator.szx == 0
    assert accumulator.blocks_received == 1

    # A retransmitted earlier block is ignored without duplicating its bytes.
    assert accumulator.add_response(first) == BLOCK2_DUPLICATE
    assert accumulator.payload == b'a' * 16

    final = _message(number=1, payload=b'done', size2=20)
    assert accumulator.add_response(final) == BLOCK2_COMPLETE
    assert accumulator.complete
    assert accumulator.code == 0x45
    assert accumulator.payload == b'a' * 16 + b'done'
    assert accumulator.etag == b'etag'
    assert accumulator.content_format == 60
    assert accumulator.size2 == 20


def test_block2_accumulator_strict_default_rejects_szx_change():
    accumulator = Block2Accumulator(b'token')
    accumulator.add_response(_message(
        number=0,
        more=True,
        szx=6,
        payload=b'a' * 1024,
    ))

    with pytest.raises(BlockwiseError):
        accumulator.add_response(_message(
            number=4,
            szx=4,
            payload=b'done',
        ))


def test_block2_accumulator_compat_downshift_uses_byte_offset():
    accumulator = Block2Accumulator(
        b'token',
        allow_szx_downshift=True,
    )

    # Samsung may return the full 1024 bytes requested for block zero while
    # advertising SZX=4 (256 bytes) for continuation requests.
    assert accumulator.add_response(_message(
        number=0,
        more=True,
        szx=4,
        payload=b'a' * 1024,
    )) == BLOCK2_CONTINUE
    assert accumulator.expected_number == 4
    assert accumulator.szx == 4

    assert accumulator.add_response(_message(
        number=4,
        szx=4,
        payload=b'done',
    )) == BLOCK2_COMPLETE
    assert accumulator.payload == b'a' * 1024 + b'done'


def test_block2_accumulator_compat_rejects_upshift_and_unaligned_downshift():
    upshift = Block2Accumulator(
        b'token',
        allow_szx_downshift=True,
    )
    upshift.add_response(_message(
        number=0,
        more=True,
        szx=4,
        payload=b'a' * 1024,
    ))
    with pytest.raises(BlockwiseError):
        upshift.add_response(_message(
            number=1,
            szx=6,
            payload=b'done',
        ))

    unaligned = Block2Accumulator(
        b'token',
        allow_szx_downshift=True,
    )
    with pytest.raises(BlockwiseError):
        unaligned.add_response(_message(
            number=0,
            more=True,
            szx=4,
            payload=b'a' * 300,
        ))


@pytest.mark.parametrize(
    'second',
    (
        _message(number=2, payload=b'done'),
        _message(number=1, szx=1, payload=b'done'),
        _message(number=1, token=b'other', payload=b'done'),
        _message(number=1, etag=b'other', payload=b'done'),
        _message(number=1, content_format=10000, payload=b'done'),
    ),
)
def test_block2_accumulator_rejects_transfer_identity_changes(second):
    accumulator = Block2Accumulator(b'token')
    accumulator.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
        size2=20,
    ))
    with pytest.raises(BlockwiseError):
        accumulator.add_response(second)


def test_block2_advisory_metadata_mode_preserves_legacy_peer_compatibility():
    accumulator = Block2Accumulator(b'token', strict_metadata=False)
    accumulator.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
        etag=b'first',
        content_format=60,
        size2=20,
    ))
    assert accumulator.add_response(_message(
        number=1,
        payload=b'done',
        etag=None,
        content_format=None,
        size2=None,
    )) == BLOCK2_COMPLETE
    assert accumulator.payload == b'a' * 16 + b'done'
    assert accumulator.etag is None
    assert accumulator.content_format is None
    assert accumulator.size2 is None


def test_block2_size2_is_an_informational_estimate_only():
    accumulator = Block2Accumulator(
        b'token',
        max_payload_bytes=32,
    )
    accumulator.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
        size2=1,
    ))
    assert accumulator.add_response(_message(
        number=1,
        payload=b'done',
        size2=1_000_000,
    )) == BLOCK2_COMPLETE
    assert accumulator.payload == b'a' * 16 + b'done'
    assert accumulator.size2 == 1_000_000


def test_block2_continuation_requires_an_explicit_block2_option():
    accumulator = Block2Accumulator(b'token')
    accumulator.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
    ))
    with pytest.raises(BlockwiseError):
        accumulator.add_response(_message(
            payload=b'done',
            include_block=False,
        ))


def test_mid_transfer_error_is_opt_in_for_connected_session_compatibility():
    strict = Block2Accumulator(b'token')
    strict.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
    ))
    error = _message(
        code=0x80,
        payload=b'error',
        include_block=False,
        etag=None,
        content_format=None,
    )
    with pytest.raises(BlockwiseError):
        strict.add_response(error)

    compatible = Block2Accumulator(
        b'token',
        allow_mid_transfer_error=True,
    )
    compatible.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
    ))
    assert compatible.add_response(error) == BLOCK2_COMPLETE
    assert compatible.code == 0x80
    assert compatible.payload == b'a' * 16 + b'error'


def test_block2_accumulator_enforces_exact_block_and_payload_bounds():
    two_blocks = Block2Accumulator(
        b'token',
        max_blocks=2,
        max_payload_bytes=32,
    )
    assert two_blocks.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
        size2=32,
    )) == BLOCK2_CONTINUE
    assert two_blocks.add_response(_message(
        number=1,
        payload=b'b' * 16,
        size2=32,
    )) == BLOCK2_COMPLETE

    needs_third = Block2Accumulator(
        b'token',
        max_blocks=2,
        max_payload_bytes=48,
    )
    needs_third.add_response(_message(
        number=0,
        more=True,
        payload=b'a' * 16,
        size2=48,
    ))
    with pytest.raises(BlockwiseError):
        needs_third.add_response(_message(
            number=1,
            more=True,
            payload=b'b' * 16,
            size2=48,
        ))

    too_large = Block2Accumulator(b'token', max_payload_bytes=16)
    with pytest.raises(BlockwiseError):
        too_large.add_response(_message(
            payload=b'x' * 17,
            include_block=False,
            etag=None,
            content_format=None,
        ))


def test_block2_accumulator_default_payload_bound_is_exactly_64_kib():
    exact = Block2Accumulator(b'token')
    response = _message(
        payload=b'x' * 65536,
        include_block=False,
        etag=None,
        content_format=None,
    )
    assert exact.add_response(response) == BLOCK2_COMPLETE

    oversized = Block2Accumulator(b'token')
    with pytest.raises(BlockwiseError):
        oversized.add_response(CoapMessage(
            mtype=TYPE_NON,
            code=0x80,
            mid=1,
            token=b'token',
            options=(),
            payload=b'x' * 65537,
        ))


def test_internal_response_reprs_redact_token_payload_and_ack_bytes():
    sensitive_value = b'synthetic-sensitive-device-value'
    classification = classify_coap_response(
        build_coap(TYPE_CON, 0x45, 1, b'token', [], sensitive_value),
        token=b'token',
    )
    assert 'token' not in repr(classification.message)
    assert sensitive_value.decode() not in repr(classification.message)
    assert 'acknowledgement=b' not in repr(classification)
