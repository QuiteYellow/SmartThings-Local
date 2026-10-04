"""Real DTLS interoperability with synthetic credentials and memory BIOs."""
import struct

import pytest
from OpenSSL import SSL, _util

from dtls_psk import DtlsPskClient


@pytest.mark.parametrize("use_cookie", [False, True])
def test_openssl_psk_interoperability(use_cookie):
    identity, key = bytes(range(16)), b"k" * 16
    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(b"ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0")

    @_util.ffi.callback(
        "unsigned int(*)(SSL *, const char *, unsigned char *, unsigned int)"
    )
    def psk_callback(ssl, received_identity, output, capacity):
        if capacity < len(key):
            return 0
        _util.ffi.memmove(output, key, len(key))
        return len(key)

    _util.lib.SSL_CTX_set_psk_server_callback(context._context, psk_callback)
    if use_cookie:
        context.set_cookie_generate_callback(lambda connection: b"offline-cookie")
        context.set_cookie_verify_callback(
            lambda connection, cookie: cookie == b"offline-cookie"
        )
        context.set_options(SSL.OP_COOKIE_EXCHANGE)
    client = DtlsPskClient(identity, key)
    server = SSL.Connection(context, None)
    server.set_accept_state()
    completed = [False, False]
    saw_identity = False
    first_server = None
    for turn in range(80):
        for index, sender, receiver in ((0, client, server), (1, server, client)):
            try:
                sender.do_handshake()
                completed[index] = True
            except SSL.WantReadError:
                pass
            try:
                data = sender.bio_read(65535)
            except SSL.WantReadError:
                continue
            offset = 0
            while offset + 13 <= len(data):
                length = int.from_bytes(data[offset + 11:offset + 13], "big")
                record = data[offset:offset + 13 + length]
                offset += 13 + length
                if index == 1 and first_server is None and record[0] == 22:
                    first_server = (record[1:3], record[13])
                if (index == 0 and record[0] == 22
                        and record[3:5] == b"\0\0" and record[13] == 16):
                    assert record[25:27] == b"\0\x10"
                    assert record[27:43] == identity
                    saw_identity = True
            receiver.bio_write(data)
        if all(completed):
            break
    assert all(completed), (use_cookie, completed)
    assert saw_identity
    assert first_server == (
        (b"\xfe\xff", 3) if use_cookie else (b"\xfe\xfd", 2)
    )
    client.send(b"client payload")
    server.bio_write(client.bio_read(65535))
    assert server.recv(65535) == b"client payload"
    server.send(b"server payload")
    client.bio_write(server.bio_read(65535))
    assert client.recv(65535) == b"server payload"
    client.shutdown()
    server.bio_write(client.bio_read(65535))
    with pytest.raises(SSL.ZeroReturnError):
        server.recv(65535)


@pytest.mark.parametrize("record_version, accepted", [(b"\xfe\xff", False), (b"\xfe\xfd", True)])
def test_server_hello_requires_dtls12_record_header(record_version, accepted):
    client = DtlsPskClient(bytes(range(16)), b"k" * 16)
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    client.bio_read(65535)
    body = b"\xfe\xfd" + bytes(range(32)) + b"\0\xc0\x37\0"
    length = len(body).to_bytes(3, "big")
    handshake = b"\x02" + length + b"\0" * 5 + length + body
    record = b"\x16" + record_version + b"\0" * 8 + struct.pack("!H", len(handshake)) + handshake
    client.bio_write(record)
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    assert client._state == ("got_server_hello" if accepted else "sent_hello")
