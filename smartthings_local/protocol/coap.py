"""CoAP wire encoding/decoding (RFC 7252 + 7641 + 7959).

Pure functions — no sockets, no DTLS. Split out of the original
coap_dtls.py so protocol/dtls_session.py (the stateful session) and
this module (stateless wire format) can be reasoned about and tested
independently.
"""
import struct
from dataclasses import dataclass

from ..errors import BlockwiseError, MalformedMessageError

# CoAP option numbers (RFC 7252 + 7641 + 7959)
URI_PATH       = 11
URI_QUERY      = 15
OBSERVE        =  6
ETAG           =  4
CONTENT_FORMAT = 12
ACCEPT         = 17
BLOCK2         = 23
SIZE2          = 28

# CoAP message types
TYPE_CON = 0
TYPE_NON = 1
TYPE_ACK = 2
TYPE_RST = 3

# CoAP method codes
METHOD_GET  = 0x01
METHOD_POST = 0x02

# CoAP content-format value for application/cbor
CF_CBOR = b'\x3c'

# OBSERVE option values (RFC 7641 §2)
OBSERVE_REGISTER   = b''           # register / refresh
OBSERVE_DEREGISTER = bytes([1])    # deregister

# Block2 SZX=6 → 1024-byte blocks. The largest size Samsung's RT-OCF
# will honour and the only one the probes have validated end-to-end.
BLOCK_SZX = 6

# Shared bounds for callers that assemble untrusted Block2 responses.  Thirty-
# two means exactly blocks 0..31; a response that advertises another block from
# block 31 is rejected.  The payload cap applies to the fully assembled body.
MAX_BLOCK2_BLOCKS = 32
MAX_BLOCK2_PAYLOAD_BYTES = 64 * 1024

# ``classify_coap_response`` outcomes.  Strings keep the helper lightweight for
# transports that already use their own event/state machinery.
RESPONSE_IGNORE = 'ignore'
RESPONSE_EMPTY_ACK = 'empty_ack'
RESPONSE_RESET = 'reset'
RESPONSE_MESSAGE = 'response'

BLOCK2_DUPLICATE = 'duplicate'
BLOCK2_CONTINUE = 'continue'
BLOCK2_COMPLETE = 'complete'


@dataclass(frozen=True, slots=True, repr=False)
class CoapMessage:
    """One decoded CoAP datagram.

    The representation is deliberately metadata-only: tokens and payloads can
    contain device data and must not leak through exception/debug reprs.
    """

    mtype: int
    code: int
    mid: int
    token: bytes
    options: tuple[tuple[int, bytes], ...]
    payload: bytes

    def __repr__(self):
        return (
            'CoapMessage('
            f'mtype={self.mtype!r}, code={self.code!r}, '
            f'option_count={len(self.options)}, '
            f'payload_length={len(self.payload)})'
        )


@dataclass(frozen=True, slots=True, repr=False)
class CoapResponseClassification:
    """Transport-independent classification of a possible response."""

    kind: str
    message: CoapMessage | None = None
    acknowledgement: bytes | None = None

    def __repr__(self):
        return (
            'CoapResponseClassification('
            f'kind={self.kind!r}, has_message={self.message is not None!r}, '
            f'has_acknowledgement={self.acknowledgement is not None!r})'
        )


def _vlen(v):
    """Variable-length integer encoder used in option deltas + lengths."""
    if v < 13:
        return v, b''
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack('>H', v - 269)


def encode_options(opts):
    """Encode a list of (option_number, value_bytes) tuples."""
    out = b''
    prev = 0
    for n, val in sorted(opts, key=lambda x: x[0]):
        d, dx = _vlen(n - prev)
        length, lx = _vlen(len(val))
        out += bytes([(d << 4) | length]) + dx + lx + val
        prev = n
    return out


def parse_coap(data):
    """Decode a CoAP datagram. Returns (mtype, code, mid, token,
    options, payload). options is a list of (num, value_bytes).

    The decoder is intentionally strict because some callers use it on
    unauthenticated UDP datagrams. Truncated headers, tokens, extended option
    fields, option values, and empty payload markers are classified rather
    than leaking ``IndexError`` or being accepted as partial messages.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise MalformedMessageError()
    data = bytes(data)
    if len(data) < 4 or data[0] >> 6 != 1:
        raise MalformedMessageError()
    mt = (data[0] >> 4) & 0x03
    tkl = data[0] & 0x0F
    if tkl > 8 or len(data) < 4 + tkl:
        raise MalformedMessageError()
    code = data[1]
    mid = int.from_bytes(data[2:4], 'big')
    tok = data[4:4 + tkl]
    i = 4 + tkl
    opts = []
    prev = 0
    payload = b''
    while i < len(data):
        b = data[i]
        if b == 0xFF:
            if i + 1 >= len(data):
                raise MalformedMessageError()
            payload = data[i + 1:]
            break
        d_nib, l_nib = b >> 4, b & 0x0F
        i += 1
        if d_nib == 13:
            if i >= len(data):
                raise MalformedMessageError()
            delta = 13 + data[i]
            i += 1
        elif d_nib == 14:
            if i + 2 > len(data):
                raise MalformedMessageError()
            delta = 269 + int.from_bytes(data[i:i + 2], 'big')
            i += 2
        elif d_nib == 15:
            raise MalformedMessageError()
        else:
            delta = d_nib
        if l_nib == 13:
            if i >= len(data):
                raise MalformedMessageError()
            length = 13 + data[i]
            i += 1
        elif l_nib == 14:
            if i + 2 > len(data):
                raise MalformedMessageError()
            length = 269 + int.from_bytes(data[i:i + 2], 'big')
            i += 2
        elif l_nib == 15:
            raise MalformedMessageError()
        else:
            length = l_nib
        num = prev + delta
        if i + length > len(data):
            raise MalformedMessageError()
        opts.append((num, data[i:i + length]))
        i += length
        prev = num
    return mt, code, mid, tok, opts, payload


def parse_coap_message(data):
    """Decode ``data`` into an immutable :class:`CoapMessage`."""
    mtype, code, mid, token, options, payload = parse_coap(data)
    return CoapMessage(
        mtype=mtype,
        code=code,
        mid=mid,
        token=token,
        options=tuple(options),
        payload=payload,
    )


def build_coap(mtype, code, mid, token, options, payload=b''):
    """Build a CoAP datagram. mtype: CON/NON/ACK/RST. token: bytes (may
    be empty for ACK). options: list of (num, value_bytes)."""
    tkl = len(token)
    hdr = bytes([(1 << 6) | (mtype << 4) | tkl, code,
                 (mid >> 8) & 0xFF, mid & 0xFF])
    body = hdr + token + encode_options(options)
    if payload:
        body += b'\xFF' + payload
    return body


def build_empty_ack(mid):
    """Build the bare ACK required for a confirmable CoAP response."""
    return build_coap(TYPE_ACK, 0, mid, b'', [])


def block_value(num, more, szx):
    """Encode a CoAP Block-N option value."""
    v = (num << 4) | ((more & 1) << 3) | (szx & 7)
    if v <= 0xFF:
        return bytes([v])
    if v <= 0xFFFF:
        return struct.pack('>H', v)
    return struct.pack('>I', v)[1:]


def block_fields(value):
    """Decode a CoAP Block-N option value. Inverse of block_value().
    Returns (num, more, szx). An empty value means block 0, no more,
    SZX=0 — RFC 7959 §2.2 allows a zero-length option to elide it."""
    v = int.from_bytes(value, 'big')
    return v >> 4, (v >> 3) & 1, v & 0x07


def _option_bytes(value, *, name):
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f'{name} values must be strings or bytes')


def build_get_request(
        mtype, mid, token, path_segs, query=(), *, accept=CF_CBOR,
        block_number=None, block_szx=BLOCK_SZX):
    """Build a GET with optional Uri-Query, Accept, and Block2 options.

    ``block_number=None`` omits Block2 for the initial request.  Continuation
    requests pass the accumulator's ``expected_number`` and ``szx``.  Path and
    query values may be either text or already encoded bytes.
    """
    options = [
        (URI_PATH, _option_bytes(segment, name='path segment'))
        for segment in path_segs
    ]
    options.extend(
        (URI_QUERY, _option_bytes(value, name='query'))
        for value in query
    )
    if accept is not None:
        if not isinstance(accept, (bytes, bytearray, memoryview)):
            raise TypeError('accept must be bytes or None')
        options.append((ACCEPT, bytes(accept)))
    if block_number is not None:
        if (isinstance(block_number, bool)
                or not isinstance(block_number, int)
                or block_number < 0):
            raise ValueError('block_number must be a non-negative integer')
        if (isinstance(block_szx, bool)
                or not isinstance(block_szx, int)
                or not 0 <= block_szx <= BLOCK_SZX):
            raise ValueError('block_szx must be between 0 and 6')
        options.append((BLOCK2, block_value(block_number, 0, block_szx)))
    return build_coap(mtype, METHOD_GET, mid, token, options)


def option_values(options, number):
    """Return all values for one option number, preserving wire order."""
    return tuple(value for option_number, value in options
                 if option_number == number)


def decode_uint_option(options, number, *, max_length):
    """Decode one optional CoAP uint option.

    Returns ``None`` when absent.  Repeated options and values longer than the
    caller's bound are malformed; an empty value is the canonical integer 0.
    """
    values = option_values(options, number)
    if len(values) > 1:
        raise MalformedMessageError()
    if not values:
        return None
    value = values[0]
    if len(value) > max_length:
        raise MalformedMessageError()
    return int.from_bytes(value, 'big')


def classify_coap_response(datagram, *, token=None, request_mid=None):
    """Classify a response without coupling it to a socket implementation.

    Empty ACK and RST frames correlate by ``request_mid`` because RFC 7252
    requires them to carry no token.  Piggyback ACK responses correlate by
    both MID (when supplied) and token.  Separate CON/NON responses correlate
    by token; a CON classification includes the bare ACK bytes the transport
    should send to the response source.

    ``token=None`` disables token filtering and is useful to a connected
    session that performs its own token dispatch.  Structurally valid but
    unrelated messages return ``RESPONSE_IGNORE``.  Invalid ACK/RST semantics
    raise :class:`MalformedMessageError`.
    """
    message = parse_coap_message(datagram)

    if message.mtype in (TYPE_ACK, TYPE_RST) and message.code == 0:
        if message.token or message.options or message.payload:
            raise MalformedMessageError()
        if request_mid is not None and message.mid != request_mid:
            return CoapResponseClassification(RESPONSE_IGNORE, message)
        kind = (RESPONSE_EMPTY_ACK
                if message.mtype == TYPE_ACK else RESPONSE_RESET)
        return CoapResponseClassification(kind, message)

    if message.mtype == TYPE_RST:
        # A Reset is always empty.  A non-empty/code-bearing RST is malformed,
        # rather than an unrelated response that callers may silently accept.
        raise MalformedMessageError()

    acknowledgement = (
        build_empty_ack(message.mid) if message.mtype == TYPE_CON else None
    )
    if message.mtype not in (TYPE_CON, TYPE_NON, TYPE_ACK):
        return CoapResponseClassification(
            RESPONSE_IGNORE, message, acknowledgement)
    if message.code == 0:
        return CoapResponseClassification(
            RESPONSE_IGNORE, message, acknowledgement)
    if token is not None and message.token != token:
        return CoapResponseClassification(
            RESPONSE_IGNORE, message, acknowledgement)
    if (message.mtype == TYPE_ACK and request_mid is not None
            and message.mid != request_mid):
        return CoapResponseClassification(RESPONSE_IGNORE, message)
    return CoapResponseClassification(
        RESPONSE_MESSAGE, message, acknowledgement)


class Block2Accumulator:
    """Strict, bounded, token-stable Block2 representation accumulator.

    At most ``max_blocks`` response blocks (32 by default) and
    ``max_payload_bytes`` assembled bytes (64 KiB by default) are accepted.
    Block offsets must remain contiguous.  SZX is stable by default; a
    connected legacy session can opt into downward renegotiation while the
    discovery path remains strict.  In the default strict-metadata mode, ETag
    and Content-Format presence/value must be identical across every block.
    Size2 is decoded only as an informational RFC 7959 estimate: it may change,
    may differ from the final length, and never affects allocation or
    acceptance.  A connected legacy session can disable metadata inspection
    to preserve interoperability with peers that only send representation
    metadata on block zero; the block/token/size bounds remain enforced.

    ``add_response`` returns ``BLOCK2_DUPLICATE`` without changing state for a
    retransmitted earlier block, ``BLOCK2_CONTINUE`` when the next block is
    required, and ``BLOCK2_COMPLETE`` when ``code`` and ``payload`` are ready.
    Any correlated transfer-contract violation raises ``BlockwiseError``.
    """

    def __init__(
            self, token, *, max_blocks=MAX_BLOCK2_BLOCKS,
            max_payload_bytes=MAX_BLOCK2_PAYLOAD_BYTES,
            accepted_content_formats=None, strict_metadata=True,
            allow_mid_transfer_error=False, allow_szx_downshift=False):
        if not isinstance(token, (bytes, bytearray, memoryview)):
            raise TypeError('token must be bytes')
        token = bytes(token)
        if len(token) > 8:
            raise ValueError('token must contain at most 8 bytes')
        if (isinstance(max_blocks, bool) or not isinstance(max_blocks, int)
                or max_blocks <= 0):
            raise ValueError('max_blocks must be a positive integer')
        if (isinstance(max_payload_bytes, bool)
                or not isinstance(max_payload_bytes, int)
                or max_payload_bytes <= 0):
            raise ValueError(
                'max_payload_bytes must be a positive integer')
        if not isinstance(strict_metadata, bool):
            raise TypeError('strict_metadata must be a boolean')
        if not isinstance(allow_mid_transfer_error, bool):
            raise TypeError('allow_mid_transfer_error must be a boolean')
        if not isinstance(allow_szx_downshift, bool):
            raise TypeError('allow_szx_downshift must be a boolean')

        if accepted_content_formats is None:
            formats = None
        else:
            try:
                formats = frozenset(accepted_content_formats)
            except TypeError as exc:
                raise TypeError(
                    'accepted_content_formats must be an iterable') from exc
            if any(isinstance(value, bool) or not isinstance(value, int)
                   or value < 0 for value in formats):
                raise ValueError(
                    'accepted_content_formats must contain non-negative '
                    'integers')

        self._token = token
        self._max_blocks = max_blocks
        self._max_payload_bytes = max_payload_bytes
        self._accepted_content_formats = formats
        self._strict_metadata = strict_metadata
        self._allow_mid_transfer_error = allow_mid_transfer_error
        self._allow_szx_downshift = allow_szx_downshift
        self._expected_number = 0
        self._negotiated_szx = None
        self._etag = None
        self._content_format = None
        self._size2 = None
        self._payload = bytearray()
        self._blocks_received = 0
        self._code = None
        self._complete = False

    @property
    def expected_number(self):
        """Block number required next at the currently negotiated SZX."""
        return self._expected_number

    @property
    def szx(self):
        """SZX for the next request (1024-byte blocks until negotiated)."""
        if self._negotiated_szx is None:
            return BLOCK_SZX
        return self._negotiated_szx

    @property
    def complete(self):
        return self._complete

    @property
    def code(self):
        return self._code

    @property
    def payload(self):
        return bytes(self._payload)

    @property
    def blocks_received(self):
        return self._blocks_received

    @property
    def etag(self):
        return self._etag

    @property
    def content_format(self):
        return self._content_format

    @property
    def size2(self):
        return self._size2

    @staticmethod
    def _single_etag(options):
        values = option_values(options, ETAG)
        if len(values) > 1:
            raise BlockwiseError()
        if not values:
            return None
        value = values[0]
        if not 1 <= len(value) <= 8:
            raise BlockwiseError()
        return value

    @staticmethod
    def _uint_option(options, number, *, max_length):
        try:
            return decode_uint_option(
                options, number, max_length=max_length)
        except MalformedMessageError:
            raise BlockwiseError() from None

    def add_response(self, message):
        if not isinstance(message, CoapMessage):
            raise TypeError('message must be a CoapMessage')
        if self._complete:
            raise BlockwiseError()
        if message.token != self._token:
            raise BlockwiseError()
        if message.mtype not in (TYPE_CON, TYPE_NON, TYPE_ACK):
            raise BlockwiseError()
        if message.code == 0:
            raise BlockwiseError()

        # A non-success response terminates the logical GET immediately.  The
        # strict default rejects one after a representation has started; the
        # connected session opts into its historical contract of returning the
        # error code plus all bytes accumulated before and in the error.
        if message.code >> 5 != 2:
            if (self._blocks_received and not self._allow_mid_transfer_error):
                raise BlockwiseError()
            if len(self._payload) + len(message.payload) > \
                    self._max_payload_bytes:
                raise BlockwiseError()
            self._code = message.code
            self._payload.extend(message.payload)
            self._blocks_received += 1
            self._complete = True
            return BLOCK2_COMPLETE

        block_values = option_values(message.options, BLOCK2)
        if len(block_values) > 1:
            raise BlockwiseError()
        if self._expected_number > 0 and not block_values:
            raise BlockwiseError()
        if block_values:
            encoded = block_values[0]
            if len(encoded) > 3:
                raise BlockwiseError()
            number, more, response_szx = block_fields(encoded)
            more = bool(more)
            if response_szx > BLOCK_SZX:
                raise BlockwiseError()
        else:
            number = 0
            more = False
            response_szx = None

        if self._expected_number > 0 and response_szx is None:
            raise BlockwiseError()

        if response_szx is not None:
            block_size = 1 << (response_szx + 4)
            response_offset = number * block_size
            expected_offset = len(self._payload)
            if response_offset < expected_offset:
                return BLOCK2_DUPLICATE
            if response_offset != expected_offset:
                raise BlockwiseError()

            request_szx = self.szx
            if self._negotiated_szx is not None \
                    and response_szx != self._negotiated_szx:
                if (not self._allow_szx_downshift
                        or response_szx > self._negotiated_szx):
                    raise BlockwiseError()

            # Some Samsung RT-OCF versions answer a request at the previous
            # SZX-sized payload while advertising a smaller SZX for the next
            # request.  Compatibility mode accepts only this bounded downward
            # transition.  The byte offset below still has to land exactly on
            # a block boundary at the newly advertised size.
            downshifted = response_szx < request_szx
            payload_limit_szx = (
                request_szx
                if self._allow_szx_downshift and downshifted
                else response_szx
            )
            payload_limit = 1 << (payload_limit_szx + 4)
            if len(message.payload) > payload_limit:
                raise BlockwiseError()
            next_offset = expected_offset + len(message.payload)
            if more and (
                    not message.payload
                    or next_offset % block_size
                    or (not (self._allow_szx_downshift and downshifted)
                        and len(message.payload) != block_size)):
                raise BlockwiseError()
        else:
            next_offset = len(message.payload)

        if self._strict_metadata:
            etag = self._single_etag(message.options)
            content_format = self._uint_option(
                message.options, CONTENT_FORMAT, max_length=2)
            size2 = self._uint_option(message.options, SIZE2, max_length=4)
            if (self._accepted_content_formats is not None
                    and content_format is not None
                    and content_format not in self._accepted_content_formats):
                raise BlockwiseError()
        else:
            # RFC 7959 peers are allowed to vary which representation metadata
            # options accompany continuation blocks.  The historical connected
            # session ignored these options, so advisory mode does likewise.
            etag = None
            content_format = None
            size2 = None

        if self._blocks_received == 0:
            next_etag = etag
            next_content_format = content_format
            next_size2 = size2
            next_szx = response_szx
            next_code = message.code
        else:
            if message.code != self._code:
                raise BlockwiseError()
            if etag != self._etag or content_format != self._content_format:
                raise BlockwiseError()
            next_etag = self._etag
            next_content_format = self._content_format
            next_size2 = self._size2 if size2 is None else size2
            next_szx = response_szx
            next_code = self._code

        next_length = len(self._payload) + len(message.payload)
        if next_length > self._max_payload_bytes:
            raise BlockwiseError()
        if self._blocks_received >= self._max_blocks:
            raise BlockwiseError()
        if more and self._blocks_received + 1 >= self._max_blocks:
            raise BlockwiseError()

        self._etag = next_etag
        self._content_format = next_content_format
        self._size2 = next_size2
        self._negotiated_szx = next_szx
        self._code = next_code
        self._payload.extend(message.payload)
        self._blocks_received += 1
        if more:
            self._expected_number = next_offset // (1 << (next_szx + 4))
            return BLOCK2_CONTINUE
        self._complete = True
        return BLOCK2_COMPLETE


def fmt_code(c):
    """0x45 → '2.05', 0x84 → '4.04'. Used in log lines."""
    return f"{c >> 5}.{c & 0x1F:02d}"


def split_dtls(buf):
    """Split a UDP datagram that contains one-or-more DTLS records.
    OpenSSL sometimes hands the BIO multiple records back-to-back; we
    must send each as its own UDP datagram or TizenRT drops them."""
    o, out = 0, []
    while o + 13 <= len(buf):
        L = int.from_bytes(buf[o + 11:o + 13], 'big')
        end = o + 13 + L
        if end > len(buf):
            break
        out.append(buf[o:end])
        o = end
    return out
