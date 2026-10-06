"""A PSK credential driven end to end through DtlsCoapSession.

The seam, the handshake driver and the pure-Python engine together, against
a real OpenSSL DTLS PSK server. No appliance and no credential of our own:
OpenSSL plays the server over memory BIOs behind a fake socket, which is how
the rest of this suite avoids real sockets, so these run in CI.

The identity used throughout contains a zero byte. That is the whole point
of the engine -- OpenSSL's client callback would truncate it -- so a test
that proves the wiring has to carry one.
"""

from __future__ import annotations

import socket

import pytest
from OpenSSL import SSL, _util

from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.auth import PskAuth
from smartthings_local.protocol.coap import split_dtls as _split_dtls
from smartthings_local.protocol.dtls_session import DtlsCoapSession
from smartthings_local.protocol.endpoint import ResolvedUdpEndpoint

IDENTITY = bytes(range(16))  # leads with 0x00
KEY = b"k" * 16


def _psk_server(*, cookies: bool):
    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(b"ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0")
    seen = []

    @_util.ffi.callback(
        "unsigned int(*)(SSL *, const char *, unsigned char *, unsigned int)"
    )
    def psk_callback(_ssl, _identity, output, capacity):
        if capacity < len(KEY):
            return 0
        _util.ffi.memmove(output, KEY, len(KEY))
        return len(KEY)

    _util.lib.SSL_CTX_set_psk_server_callback(context._context, psk_callback)
    if cookies:
        context.set_cookie_generate_callback(lambda _c: b"offline-cookie")
        context.set_cookie_verify_callback(
            lambda _c, cookie: cookie == b"offline-cookie"
        )
        context.set_options(SSL.OP_COOKIE_EXCHANGE)
    server = SSL.Connection(context, None)
    server.set_accept_state()
    # The callbacks must outlive the context, as they do on a provider.
    server._test_keepalive = (psk_callback, context)
    return server, seen


class _ServerSocket:
    """A socket whose peer is an in-process OpenSSL DTLS server."""

    def __init__(self, server):
        self.server = server
        self.inbound: list[bytes] = []
        self.sent: list[bytes] = []
        self.closed = False
        self.completed = False

    def send(self, record):
        self.sent.append(record)
        self.server.bio_write(record)
        try:
            self.server.do_handshake()
            self.completed = True
        except SSL.WantReadError:
            pass
        try:
            self.inbound.extend(_split_dtls(self.server.bio_read(65535)))
        except SSL.WantReadError:
            pass
        return len(record)

    def recv(self, _size=65535):
        if not self.inbound:
            raise socket.timeout()
        return self.inbound.pop(0)

    def settimeout(self, _timeout):
        return None

    def close(self):
        self.closed = True

    # Deliberately no fileno(): connect() documents the timeout-driven path
    # for "structural socket adapters that intentionally expose no file
    # descriptor", and taking it keeps the handshake off select().


def _install(monkeypatch, data_socket):
    endpoint = ResolvedUdpEndpoint(socket.AF_INET, ("192.0.2.10", 49154))
    monkeypatch.setattr(
        dtls_session,
        "open_host_filtered_udp_socket",
        lambda *_a, **_k: (data_socket, endpoint),
    )
    return endpoint


@pytest.mark.parametrize("cookies", [False, True])
def test_session_completes_a_psk_handshake_with_a_nul_identity(
    monkeypatch, cookies
):
    server, _ = _psk_server(cookies=cookies)
    data_socket = _ServerSocket(server)
    _install(monkeypatch, data_socket)
    session = DtlsCoapSession("appliance.invalid", 49154,
                              auth=PskAuth(identity=IDENTITY, key=KEY))

    session.connect(timeout=5.0)

    assert data_socket.completed, "the OpenSSL server never finished"
    assert session.conn is not None
    assert session.server_certificate_identity is None
    assert not data_socket.closed

    # The credential really crossed the wire whole, in the clear, ahead of
    # ChangeCipherSpec: a 16-byte identity whose first byte is a NUL.
    client_key_exchanges = [
        record for record in data_socket.sent
        if record[0] == 22 and record[3:5] == b"\0\0" and record[13] == 16
    ]
    assert len(client_key_exchanges) == 1
    body = client_key_exchanges[0][13 + 12:]
    assert body[:2] == b"\0\x10"
    assert body[2:18] == IDENTITY

    # Each record went out as its own datagram, which TizenRT requires.
    for record in data_socket.sent:
        assert len(_split_dtls(record)) == 1


def test_application_data_round_trips_over_the_session(monkeypatch):
    server, _ = _psk_server(cookies=False)
    data_socket = _ServerSocket(server)
    _install(monkeypatch, data_socket)
    session = DtlsCoapSession("appliance.invalid", 49154,
                              auth=PskAuth(identity=IDENTITY, key=KEY))
    session.connect(timeout=5.0)

    session.conn.send(b"coap request")
    data_socket.server.bio_write(session.conn.bio_read(65535))
    assert data_socket.server.recv(65535) == b"coap request"

    data_socket.server.send(b"coap response")
    session.conn.bio_write(data_socket.server.bio_read(65535))
    assert session.conn.recv(65535) == b"coap response"


def test_a_session_still_refuses_to_configure_an_openssl_context():
    """The engine lifting the restriction must not lift it for OpenSSL."""
    provider = PskAuth(identity=IDENTITY, key=KEY)
    with pytest.raises(ValueError, match="truncates"):
        provider.configure_context(SSL.Context(SSL.DTLS_METHOD))


def test_close_releases_the_peer_through_the_engine(monkeypatch):
    """close() must still emit an encrypted close_notify, as its own datagram.

    This is the machinery that has to stay above the seam, and it matters
    more on this path than on the certificate one. The appliance frees a
    peer entry on close_notify, and its CAdecryptSsl only runs SetupCipher
    for an endpoint with no existing peer entry
    (ca_adapter_net_ssl.c:2177-2191), so a reused peer entry keeps whatever
    the shared g_cipherSuitesList (:323, rebuilt in place at :1542 and
    handed to mbedtls_ssl_conf_ciphersuites at :1586) last held. Our
    ClientHello offers exactly one suite, so a stale entry without
    ECDHE-PSK in that list is a handshake_failure with nothing naming the
    cause. A clean close is what prevents it.
    """
    server, _ = _psk_server(cookies=True)
    data_socket = _ServerSocket(server)
    _install(monkeypatch, data_socket)
    session = DtlsCoapSession("appliance.invalid", 49154,
                              auth=PskAuth(identity=IDENTITY, key=KEY))
    session.connect(timeout=5.0)
    before = len(data_socket.sent)

    session.close()

    closing = data_socket.sent[before:]
    records = [record for datagram in closing
               for record in _split_dtls(datagram)]
    alerts = [record for record in records if record[0] == 21]
    assert len(alerts) == 1, records
    # Epoch 1: encrypted under the session keys, which is the only form the
    # appliance can authenticate.
    assert int.from_bytes(alerts[0][3:5], "big") == 1
    # One record per datagram, all the way through the close path.
    for datagram in closing:
        assert len(_split_dtls(datagram)) == 1
    assert data_socket.closed

    # The server's own verdict, not just our byte inspection.
    with pytest.raises(SSL.ZeroReturnError):
        server.recv(65535)
