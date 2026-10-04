#!/usr/bin/env python3
"""Authenticate to an appliance with a binary PSK identity, then GET /oic/d.

Written for https://github.com/QuiteYellow/SmartThings-Local/pull/115 to test
a pure-Python DTLS 1.2 ECDHE-PSK client against real hardware. It replaces the
compiled Mbed TLS backend in that PR with `dtls_psk.py` next to this file, so
there is nothing to build.

What it does, and nothing else:

1. one DTLS 1.2 ECDHE-PSK handshake, sending the identity you give it with an
   explicit length, so a zero byte inside it survives
2. one CoAP GET of /oic/d over that session
3. a close_notify, then exit

It never writes to the appliance, never touches a security resource, and never
starts another session or retries the GET. DTLS flights can retransmit.
Stop the bridge or integration first if one is running, since the
appliance will already have a session with it.

Usage:

    # Runtime dependencies: cryptography and cbor2. Use a virtual environment.
    python3 -m pip install cryptography cbor2
    export PSK_HOST=192.0.2.100
    export PSK_PORT=49154
    export PSK_IDENTITY_HEX=0102...        # 32 hex chars, the 16-byte UUID
    export PSK_KEY_HEX=...                 # 32 or 64 hex chars
    export PSK_EXPECTED_DI=...             # required, the di you expect
    export PSK_LOCAL_PORT=...              # optional, stable local UDP port
    python3 oven_psk_test.py

Output omits addresses, credentials, device identifiers, and their fingerprints.
"""
from __future__ import annotations

import io

import cbor2
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dtls_psk import DtlsPskClient, WantRead, ZeroReturn
except ImportError:
    sys.exit("dtls_psk.py must sit next to this script")


def _env(name: str, *, required: bool = True) -> str | None:
    value = os.environ.get(name)
    if required and not value:
        sys.exit(f"{name} is not set; see the docstring at the top of this file")
    return value


def _hexbytes(name: str, lengths: tuple[int, ...]) -> bytes:
    raw = _env(name)
    try:
        value = bytes.fromhex(raw.strip())
    except ValueError:
        sys.exit(f"{name} must be hex")
    if len(value) not in lengths:
        sys.exit(f"{name} must decode to {' or '.join(map(str, lengths))} bytes, "
                 f"got {len(value)}")
    return value


def _coap_get(path: tuple[str, ...], token: bytes, message_id: int) -> bytes:
    """Encode a CON GET. Uri-Path is option 11; deltas are 11 then 0."""
    out = bytearray()
    out.append(0x40 | len(token))          # ver 1, CON, token length
    out.append(1)                          # 0.01 GET
    out += struct.pack("!H", message_id)
    out += token
    delta = 11
    for segment in path:
        encoded = segment.encode()
        if len(encoded) > 12:
            out.append((delta << 4) | 13)
            out.append(len(encoded) - 13)
        else:
            out.append((delta << 4) | len(encoded))
        out += encoded
        delta = 0
    return bytes(out)


def _coap_parse(datagram: bytes) -> tuple[int, int, int, bytes, bytes]:
    """Validate framing and return type, code, message ID, token, and payload."""
    if len(datagram) < 4 or datagram[0] >> 6 != 1:
        raise ValueError("invalid CoAP header")
    token_length = datagram[0] & 0x0F
    if token_length > 8 or len(datagram) < 4 + token_length:
        raise ValueError("invalid CoAP token")
    kind = (datagram[0] >> 4) & 3
    code = datagram[1]
    message_id = int.from_bytes(datagram[2:4], "big")
    token = datagram[4:4 + token_length]
    offset = 4 + token_length
    payload = b""
    while offset < len(datagram):
        header = datagram[offset]
        offset += 1
        if header == 0xFF:
            if offset == len(datagram):
                raise ValueError("empty CoAP payload")
            payload = datagram[offset:]
            break
        values = []
        for nibble in (header >> 4, header & 15):
            if nibble == 15:
                raise ValueError("reserved CoAP option nibble")
            width = 1 if nibble == 13 else 2 if nibble == 14 else 0
            if offset + width > len(datagram):
                raise ValueError("truncated CoAP option")
            value = int.from_bytes(datagram[offset:offset + width], "big")
            values.append(nibble if not width else value + (13 if width == 1 else 269))
            offset += width
        offset += values[1]
        if offset > len(datagram):
            raise ValueError("truncated CoAP option value")
    if code == 0 and (token or len(datagram) != 4):
        raise ValueError("invalid empty CoAP message")
    return kind, code, message_id, token, payload


def _split_records(buf: bytes) -> list[bytes]:
    """One DTLS record per datagram; the appliance drops packed records."""
    out, offset = [], 0
    while offset < len(buf):
        if offset + 13 > len(buf):
            raise ValueError("truncated DTLS record")
        length = int.from_bytes(buf[offset + 11:offset + 13], "big")
        end = offset + 13 + length
        if end > len(buf):
            raise ValueError("truncated DTLS record")
        out.append(buf[offset:end])
        offset = end
    return out


def _flush(client, sock, target: tuple[str, int]) -> bool:
    try:
        pending = client.bio_read(65535)
    except WantRead:
        return False
    records = _split_records(pending)
    for record in records:
        sock.sendto(record, target)
    return bool(records)


def _receive(client, sock, target: tuple[str, int]) -> None:
    datagram, source = sock.recvfrom(65535)
    if source[0] == target[0]:
        client.bio_write(datagram)


class ProbeFailure(Exception):
    """A fixed diagnostic that contains no peer data or configuration values."""


HANDSHAKE_TIMEOUT = 20
REPLY_TIMEOUT = 10


def _probe(client, sock, target: tuple[str, int], expected_di: str) -> None:
    started = time.monotonic()
    deadline = started + HANDSHAKE_TIMEOUT
    while time.monotonic() < deadline:
        try:
            client.do_handshake()
            break
        except WantRead:
            pass
        except Exception as exc:
            raise ProbeFailure(f"handshake failed ({type(exc).__name__})") from None
        _flush(client, sock, target)
        try:
            _receive(client, sock, target)
        except socket.timeout:
            remaining = client.DTLSv1_get_timeout()
            if remaining is not None and remaining <= 0:
                client.DTLSv1_handle_timeout()
    else:
        raise ProbeFailure("handshake timed out")
    _flush(client, sock, target)
    print(f"handshake     : OK in {time.monotonic() - started:.1f}s "
          "(DTLS 1.2, ECDHE-PSK-AES128-CBC-SHA256)")

    token = os.urandom(4)
    message_id = int.from_bytes(os.urandom(2), "big")
    client.send(_coap_get(("oic", "d"), token, message_id))
    _flush(client, sock, target)
    deadline = time.monotonic() + REPLY_TIMEOUT
    while time.monotonic() < deadline:
        try:
            kind, code, reply_id, reply_token, payload = _coap_parse(client.recv(65535))
        except ZeroReturn:
            raise ProbeFailure("peer closed before GET response") from None
        except ValueError:
            raise ProbeFailure("GET response had invalid CoAP framing") from None
        except WantRead:
            try:
                _receive(client, sock, target)
            except socket.timeout:
                pass
            continue
        if kind == 3 and reply_id == message_id:
            raise ProbeFailure("GET request was reset")
        if code == 0:
            continue  # An empty ACK is not the response.
        if reply_token != token or kind == 3 or (kind == 2 and reply_id != message_id):
            continue
        if kind == 0:
            client.send(struct.pack("!BBH", 0x60, 0, reply_id))
            _flush(client, sock, target)
        if code != 69:
            raise ProbeFailure("GET did not return 2.05")
        stream = io.BytesIO(payload)
        try:
            document = cbor2.CBORDecoder(stream).decode()
        except Exception:
            raise ProbeFailure("GET payload was invalid CBOR") from None
        if stream.read(1) or not isinstance(document, dict):
            raise ProbeFailure("GET payload was not one CBOR map")
        if document.get("di") != expected_di:
            raise ProbeFailure("GET device ID did not match")
        print("GET /oic/d    : OK (2.05, CBOR map, expected device ID matched)")
        return
    raise ProbeFailure("GET timed out")


def main() -> int:
    client = sock = None
    result = 1
    stage = "configuration"
    completed = False
    try:
        host = _env("PSK_HOST")
        port = int(_env("PSK_PORT"))
        local_port = int(_env("PSK_LOCAL_PORT", required=False) or 0)
        if not 1 <= port <= 65535 or not 0 <= local_port <= 65535:
            raise ValueError("invalid UDP port")
        identity = _hexbytes("PSK_IDENTITY_HEX", (16,))
        key = _hexbytes("PSK_KEY_HEX", (16, 32))
        expected_di = _env("PSK_EXPECTED_DI")
        target = (socket.gethostbyname(host), port)
        client = DtlsPskClient(identity, key, mtu=1400)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", local_port))
        sock.settimeout(0.5)
        print(f"identity      : 16 bytes, contains a zero byte: {'yes' if 0 in identity else 'no'}")
        stage = "probe"
        _probe(client, sock, target, expected_di)
        completed = True
        result = 0
    except ProbeFailure as exc:
        print(f"{stage:<14}: FAILED ({exc})")
    except Exception as exc:
        # Exception text can contain credentials, addresses, or appliance data.
        print(f"{stage:<14}: FAILED ({type(exc).__name__})")
    finally:
        try:
            if client is not None:
                client.shutdown()
                sent = sock is not None and _flush(client, sock, target)
                print(f"close_notify  : {'sent' if sent else 'not queued'}")
                if completed and not sent:
                    result = 1
        except Exception as exc:
            print(f"close_notify  : FAILED ({type(exc).__name__})")
            result = 1
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception as exc:
                    print(f"socket cleanup: FAILED ({type(exc).__name__})")
                    result = 1
    return result


def _cap_memory(limit_mb: int = 512) -> None:
    """Abort rather than exhaust the machine if something goes wrong.

    A backstop, not a hard cap: macOS refuses to lower RLIMIT_AS/RLIMIT_DATA,
    so on that platform this is a polling watchdog that turns a runaway
    allocation into a dead process instead of a dead laptop.
    """
    import os
    import resource
    import sys
    import threading
    import time

    ceiling = limit_mb * 1024 * 1024
    for name in ("RLIMIT_AS", "RLIMIT_DATA"):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            resource.setrlimit(limit, (ceiling, resource.getrlimit(limit)[1]))
            return
        except (ValueError, OSError):
            continue
    scale = 1 if sys.platform == "darwin" else 1024

    def watch() -> None:
        while True:
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale
            if rss > ceiling:
                print(f"aborting: {rss // 1048576} MB exceeds the "
                      f"{limit_mb} MB cap", flush=True)
                os._exit(97)
            time.sleep(0.05)

    threading.Thread(target=watch, daemon=True).start()


if __name__ == "__main__":
    _cap_memory()
    sys.exit(main())
