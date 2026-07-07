"""CoAP wire encoding/decoding (RFC 7252 + 7641 + 7959).

Pure functions — no sockets, no DTLS. Split out of the original
coap_dtls.py so protocol/dtls_session.py (the stateful session) and
this module (stateless wire format) can be reasoned about and tested
independently.
"""
import struct

# CoAP option numbers (RFC 7252 + 7641 + 7959)
URI_PATH       = 11
URI_QUERY      = 15
OBSERVE        =  6
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


def _vlen(v):
    """Variable-length integer encoder used in option deltas + lengths."""
    if v < 13:    return v, b''
    if v < 269:   return 13, bytes([v - 13])
    return 14, struct.pack('>H', v - 269)


def encode_options(opts):
    """Encode a list of (option_number, value_bytes) tuples."""
    out = b''
    prev = 0
    for n, val in sorted(opts, key=lambda x: x[0]):
        d, dx = _vlen(n - prev)
        l, lx = _vlen(len(val))
        out += bytes([(d << 4) | l]) + dx + lx + val
        prev = n
    return out


def parse_coap(data):
    """Decode a CoAP datagram. Returns (mtype, code, mid, token,
    options, payload). options is a list of (num, value_bytes)."""
    mt = (data[0] >> 4) & 0x03
    tkl = data[0] & 0x0F
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
            payload = data[i + 1:]
            break
        d_nib, l_nib = b >> 4, b & 0x0F
        i += 1
        if d_nib == 13:
            delta = 13 + data[i]; i += 1
        elif d_nib == 14:
            delta = 269 + int.from_bytes(data[i:i + 2], 'big'); i += 2
        elif d_nib == 15:
            raise ValueError("reserved option delta nibble 15")
        else:
            delta = d_nib
        if l_nib == 13:
            length = 13 + data[i]; i += 1
        elif l_nib == 14:
            length = 269 + int.from_bytes(data[i:i + 2], 'big'); i += 2
        elif l_nib == 15:
            raise ValueError("reserved option length nibble 15")
        else:
            length = l_nib
        num = prev + delta
        opts.append((num, data[i:i + length]))
        i += length
        prev = num
    return mt, code, mid, tok, opts, payload


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


def block_value(num, more, szx):
    """Encode a CoAP Block-N option value."""
    v = (num << 4) | ((more & 1) << 3) | (szx & 7)
    if v <= 0xFF:    return bytes([v])
    if v <= 0xFFFF:  return struct.pack('>H', v)
    return struct.pack('>I', v)[1:]


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
