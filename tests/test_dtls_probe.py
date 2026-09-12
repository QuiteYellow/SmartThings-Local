import socket
import threading
import time

import pytest

from smartthings_local.protocol import dtls_probe as p


def _rec(content_type, frag, *, epoch=0):
    """Build one DTLS record: 13-byte header + fragment."""
    return (bytes([content_type])
            + b'\xfe\xfd'                 # DTLS 1.2
            + epoch.to_bytes(2, 'big')    # epoch
            + b'\x00\x00\x00\x00\x00\x00' # sequence number
            + len(frag).to_bytes(2, 'big')
            + frag)


def _hs(msg_type, body=b''):
    header = (
        bytes([msg_type])
        + len(body).to_bytes(3, 'big')
        + b'\x00\x00'                    # message sequence
        + b'\x00\x00\x00'              # fragment offset
        + len(body).to_bytes(3, 'big')
    )
    return _rec(p._CT_HANDSHAKE, header + body)


def _hvr(cookie=b'cookie'):
    return _hs(3, b'\xfe\xfd' + bytes([len(cookie)]) + cookie)


def _server_hello():
    body = (
        b'\xfe\xfd'
        + b'\x00' * 32
        + b'\x00'                    # session ID length
        + b'\xc0\x2b'                # ECDHE-ECDSA-AES128-GCM-SHA256
        + b'\x00'                    # null compression
    )
    return _hs(2, body)


def _alert(level, desc, *, epoch=0):
    return _rec(p._CT_ALERT, bytes([level, desc]), epoch=epoch)


def test_classify_hello_verify_request():
    assert p.classify_datagram(_hvr()) == [
        (p._CT_HANDSHAKE, 'HelloVerifyRequest')]


def test_classify_coalesced_server_flight():
    # OpenSSL commonly hands back ServerHello+Certificate back-to-back.
    dgram = _server_hello() + _hs(11, b'\x00' * 40)
    assert p.classify_datagram(dgram) == [
        (p._CT_HANDSHAKE, 'ServerHello'),
        (p._CT_HANDSHAKE, 'Certificate')]


def test_classify_fatal_alert_names_description():
    # The OCF-PKI-wall signature: fatal unsupported_certificate (43).
    assert p.classify_datagram(_alert(2, 43)) == [
        (p._CT_ALERT, (2, 'unsupported_certificate'))]


def test_classify_unknown_handshake_type_is_not_lost():
    assert p.classify_datagram(_hs(99)) == [(p._CT_HANDSHAKE, 'hs99')]


def test_dead_port_probe_is_dead_and_never_raises():
    # Nothing listens here; the probe must fold the silence into a DEAD
    # result within the timeout rather than raise.
    r = p.probe('127.0.0.1', 5684, timeout=0.1)
    assert r.outcome == p.DEAD
    assert not r.is_dtls_server
    assert r.datagrams == []


def test_is_dtls_server_reflects_outcome():
    r = p.ProbeResult('h', 1)
    r.outcome = p.LIVE
    assert r.is_dtls_server
    r.outcome = p.REJECTED
    assert r.is_dtls_server
    r.outcome = p.DEAD
    assert not r.is_dtls_server


# --- probe() behavioural tests over a scripted fake UDP socket ----------
#
# OpenSSL runs for real against a memory BIO, so the ClientHello on the
# wire is genuine; only the datagram transport is faked. `responder(fake)`
# is called on every recvfrom and returns the bytes to deliver, or None to
# simulate a lost/silent flight (which sleeps the socket timeout so
# OpenSSL's DTLS retransmit clock advances in real time).

class _FakeSock:
    def __init__(self, responder):
        self._responder = responder
        self._timeout = 0.5
        self.sends = []
        self.recv_calls = 0
        self.closed = False
        self.destination = None

    def settimeout(self, t):
        self._timeout = t

    def setsockopt(self, *a):
        pass

    def bind(self, *a):
        pass

    def connect(self, destination):
        self.destination = destination

    def send(self, data):
        self.sends.append(data)
        return len(data)

    def sendto(self, data, dest):
        self.sends.append(data)
        return len(data)

    def recv(self, n):
        self.recv_calls += 1
        resp = self._responder(self)
        if resp is None:
            time.sleep(self._timeout)
            raise TimeoutError()
        return resp

    def recvfrom(self, n):
        self.recv_calls += 1
        resp = self._responder(self)
        if resp is None:
            time.sleep(self._timeout)
            raise TimeoutError()
        return resp, ('127.0.0.1', 5684)

    def close(self):
        self.closed = True


def _patch_sock(monkeypatch, fake):
    monkeypatch.setattr(p.socket, 'socket', lambda *a, **k: fake)


def test_stateless_probe_sends_exactly_one_clienthello(monkeypatch):
    # The §4.2.8 regression guard: a HelloVerifyRequest proves liveness,
    # and the stateless gate must stop there — never emitting the cookie'd
    # second ClientHello that would commit association state on the device.
    fake = _FakeSock(lambda _fake: _hvr())
    _patch_sock(monkeypatch, fake)
    r = p.probe('127.0.0.1', 5684, stateless=True, timeout=0.2)
    assert r.outcome == p.LIVE
    assert len(fake.sends) == 1          # only the initial ClientHello
    assert fake.recv_calls == 1          # stopped on the first flight
    assert fake.closed


def test_stateless_probe_preserves_first_flight_alert(monkeypatch):
    fake = _FakeSock(lambda _fake: _alert(2, 48))
    _patch_sock(monkeypatch, fake)

    result = p.probe('127.0.0.1', 5684, stateless=True, timeout=0.2)

    assert result.outcome == p.REJECTED
    assert result.alert == (2, 'unknown_ca')
    assert len(fake.sends) == 1


def test_stateless_warning_alert_proves_liveness_without_fatal_rejection(
        monkeypatch):
    fake = _FakeSock(lambda _fake: _alert(1, 90))
    _patch_sock(monkeypatch, fake)

    result = p.probe('127.0.0.1', 5684, stateless=True, timeout=0.2)

    assert result.outcome == p.LIVE
    assert result.is_dtls_server
    assert result.alert == (1, 'user_canceled')


def test_retransmit_recovers_from_dropped_first_flight(monkeypatch):
    # The first ClientHello is "lost" (recvfrom times out) until OpenSSL's
    # retransmit timer fires a second flight; only then does the server
    # answer. A single dropped datagram must NOT read as DEAD.
    fake = _FakeSock(lambda f: _hvr() if len(f.sends) >= 2
                     else None)
    _patch_sock(monkeypatch, fake)
    r = p.probe('127.0.0.1', 5684, stateless=True, retries=2, timeout=0.3)
    assert r.outcome == p.LIVE
    assert len(fake.sends) == 2          # initial + one retransmit
    assert fake.sends[0] == fake.sends[1]


def test_silent_port_is_dead_only_after_flight_budget(monkeypatch):
    # A truly silent port: DEAD, but only after the initial flight plus
    # `retries` retransmits — not on the first unanswered datagram.
    fake = _FakeSock(lambda f: None)
    _patch_sock(monkeypatch, fake)
    r = p.probe('127.0.0.1', 5684, stateless=True, retries=1, timeout=0.2)
    assert r.outcome == p.DEAD
    assert not r.is_dtls_server
    assert len(fake.sends) == 2          # initial + retries(1) retransmit


def test_explicit_diagnostic_feeds_server_flight_back(monkeypatch):
    # The explicitly named diagnostic must NOT stop at the
    # HelloVerifyRequest: it feeds the flight back into OpenSSL to drive the
    # handshake onward (the #16 characterization path). The
    # fed-back record makes OpenSSL emit a cookie-bearing second ClientHello,
    # which is precisely what proves the diagnostic did not short-circuit.
    fake = _FakeSock(
        lambda f: _hvr() if f.recv_calls == 1 else None)
    _patch_sock(monkeypatch, fake)
    r = p.diagnose_dtls_handshake('127.0.0.1', 5684, timeout=0.3)
    assert r.outcome == p.LIVE           # HVR still proved liveness
    assert len(fake.sends) >= 2          # OpenSSL processed the flight


def test_stateless_probe_ignores_unrelated_datagram_without_retransmit(
        monkeypatch):
    responses = iter((
        _rec(p._CT_APP_DATA, b'unrelated'),
        _hvr(),
    ))
    fake = _FakeSock(lambda _fake: next(responses))
    _patch_sock(monkeypatch, fake)

    result = p.probe_dtls_port(
        '127.0.0.1', 5684, retries=1, timeout=0.2)

    assert result.response_kind == p.HELLO_VERIFY_REQUEST
    assert result.attempts == 1
    assert len(fake.sends) == 1
    assert fake.recv_calls == 2


def test_stateless_probe_forwards_explicit_address_family(monkeypatch):
    fake = _FakeSock(lambda _fake: _hvr())
    calls = []

    def open_socket(host, port, *, family, timeout):
        calls.append((host, port, family, timeout))
        fake.settimeout(timeout)
        return fake, object()

    monkeypatch.setattr(p, 'open_host_filtered_udp_socket', open_socket)

    result = p.probe_dtls_port(
        'appliance.invalid', 5684, family=socket.AF_INET6, timeout=0.2)

    assert result.is_dtls_server
    assert calls == [('appliance.invalid', 5684, socket.AF_INET6, 0.2 / 3)]


def test_client_hello_flight_is_complete_epoch_zero_dtls():
    flight = p._client_hello_flight(mtu=1200)

    assert flight
    assert all(len(record) <= 1200 for record in flight)
    assert all(record[1:3] in p._DTLS_VERSIONS for record in flight)
    assert all(record[3:5] == b'\x00\x00' for record in flight)
    assert any(
        record[0] == p._CT_HANDSHAKE and record[13] == 1
        for record in flight
    )


def test_liveness_classifier_accepts_first_flight_response_classes():
    assert p._classify_liveness_response(_hvr()) == \
        p.HELLO_VERIFY_REQUEST
    assert p._classify_liveness_response(_server_hello()) == \
        p.SERVER_HELLO
    assert p._classify_liveness_response(_alert(2, 48)) == p.ALERT


def test_liveness_classifier_rejects_truncated_or_nonzero_epoch():
    assert p._classify_liveness_response(_hvr()[:-1]) is None
    assert p._classify_liveness_response(_hs(3)) is None
    assert p._classify_liveness_response(_hs(2, b'\x00' * 20)) is None
    nonzero_epoch = bytearray(_hvr())
    nonzero_epoch[4] = 1
    assert p._classify_liveness_response(bytes(nonzero_epoch)) is None


def test_liveness_alert_detail_comes_from_valid_epoch_zero_record(monkeypatch):
    datagram = _alert(2, 40, epoch=1) + _alert(2, 48)
    fake = _FakeSock(lambda _fake: datagram)
    _patch_sock(monkeypatch, fake)

    result = p.probe_dtls_port('127.0.0.1', 5684, timeout=0.2)

    assert result.response_kind == p.ALERT
    assert result.alert == (2, 'unknown_ca')


def _liveness(port, *, live=True, error_code=None):
    return p.DtlsLivenessResult(
        port=port,
        response_kind=p.HELLO_VERIFY_REQUEST if live else None,
        attempts=1,
        error_code=error_code,
    )


def test_multi_port_probe_runs_concurrently_and_preserves_order(monkeypatch):
    ports = (5684, 49154, 49155)
    barrier = threading.Barrier(len(ports))

    def fake_probe(_host, port, **_kwargs):
        barrier.wait(timeout=2.0)
        return _liveness(port, live=port == 5684)

    monkeypatch.setattr(p, '_client_hello_flight', lambda **_kwargs: (b'hello',))
    monkeypatch.setattr(p, '_probe_dtls_port_with_flight', fake_probe)

    result = p.probe_dtls_ports('appliance.invalid', ports)

    assert result.outcome == p.SELECTED
    assert result.selected_port == 5684
    assert tuple(item.port for item in result.results) == ports
    assert not any(
        thread.name.startswith('smartthings-dtls-probe')
        for thread in threading.enumerate()
    )


def test_multi_port_probe_reports_ambiguity_without_guessing(monkeypatch):
    monkeypatch.setattr(p, '_client_hello_flight', lambda **_kwargs: (b'hello',))
    monkeypatch.setattr(
        p,
        '_probe_dtls_port_with_flight',
        lambda _host, port, **_kwargs: _liveness(port),
    )

    result = p.probe_dtls_ports('appliance.invalid', (5684, 49154))

    assert result.outcome == p.AMBIGUOUS
    assert result.selected_port is None
    assert result.live_ports == (5684, 49154)


def test_multi_port_probe_prefers_previously_proven_listener(monkeypatch):
    monkeypatch.setattr(p, '_client_hello_flight', lambda **_kwargs: (b'hello',))
    monkeypatch.setattr(
        p,
        '_probe_dtls_port_with_flight',
        lambda _host, port, **_kwargs: _liveness(port),
    )

    result = p.probe_dtls_ports(
        'appliance.invalid',
        (5684, 49154),
        preferred_port=49154,
    )

    assert result.outcome == p.SELECTED
    assert result.selected_port == 49154


def test_multi_port_probe_folds_worker_failure_into_redacted_result(monkeypatch):
    monkeypatch.setattr(p, '_client_hello_flight', lambda **_kwargs: (b'hello',))
    monkeypatch.setattr(
        p,
        '_probe_dtls_port_with_flight',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError('private')),
    )

    result = p.probe_dtls_ports('private-host.invalid', (5684,))

    assert result.outcome == p.UNREACHABLE
    assert result.results[0].error_code == 'probe_worker_failed'
    assert 'private-host' not in repr(result)
    assert 'private' not in repr(result)


def test_multi_port_probe_bounds_candidate_count():
    with pytest.raises(ValueError, match='at most 32'):
        p.probe_dtls_ports('appliance.invalid', tuple(range(1, 34)))


def test_multi_port_probe_rejects_invalid_family_before_starting_workers():
    with pytest.raises(ValueError, match='family'):
        p.probe_dtls_ports(
            'appliance.invalid',
            (5684, 49154),
            family=9999,
        )


def test_diagnostic_honors_timeout_below_half_second(monkeypatch):
    now = [10.0]

    class BudgetSocket:
        def __init__(self):
            self.timeout = None
            self.timeouts = []

        def settimeout(self, timeout):
            self.timeout = timeout
            self.timeouts.append(timeout)

        def send(self, data):
            return len(data)

        def recv(self, _size):
            now[0] += self.timeout
            raise TimeoutError()

        def close(self):
            pass

    sock = BudgetSocket()
    open_timeouts = []

    def open_socket(_host, _port, *, family, timeout):
        assert family == socket.AF_UNSPEC
        open_timeouts.append(timeout)
        sock.settimeout(timeout)
        return sock, object()

    monkeypatch.setattr(p, 'open_host_filtered_udp_socket', open_socket)
    monkeypatch.setattr(p.time, 'monotonic', lambda: now[0])

    result = p.diagnose_dtls_handshake(
        'appliance.invalid',
        5684,
        timeout=0.1,
        retries=0,
    )

    assert result.outcome == p.DEAD
    assert open_timeouts == [0.1]
    assert sock.timeouts and max(sock.timeouts) <= 0.1
    assert now[0] <= 10.1


def test_cli_bounds_port_fanout(capsys):
    result = p._main([
        'appliance.invalid',
        *(str(port) for port in range(1, 34)),
    ])

    assert result == 2
    assert 'at most 32 PORT values' in capsys.readouterr().out


# --- auth= providers, against a real loopback DTLS server ----------------
#
# `_FakeSock` fakes only the datagram transport, so an OpenSSL server driven
# through its responder produces genuine server flights: a real certificate
# chain to verify, and a real `unknown_psk_identity` alert from OpenSSL's own
# PSK path. That is what makes these tests evidence about the handshake
# rather than about a hand-built record.

_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xC02B
_ECDHE_PSK_AES128_CBC_SHA256 = 0xC037


def _synthetic_ec_server_credentials():
    """An ECDSA self-signed server cert unrelated to Samsung's hierarchy."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic test server')]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


class _LoopbackDtlsServer:
    """Drive a real OpenSSL DTLS server from `_FakeSock`'s responder."""

    def __init__(self, context):
        from OpenSSL import SSL

        self._ssl = SSL
        self._conn = SSL.Connection(context, None)
        self._conn.set_accept_state()
        self._consumed = 0

    def __call__(self, fake):
        for datagram in fake.sends[self._consumed:]:
            self._conn.bio_write(datagram)
        self._consumed = len(fake.sends)
        try:
            self._conn.do_handshake()
        except (self._ssl.WantReadError, self._ssl.Error):
            # A rejection is emitted into the BIO as an alert record, which
            # is the flight under test; nothing here should raise onward.
            pass
        try:
            return self._conn.bio_read(65536)
        except self._ssl.WantReadError:
            return None


def _server_context(*, cipher, cert_pem=None, key_pem=None, psk=False):
    from OpenSSL import SSL, _util, crypto

    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(cipher)
    if cert_pem is not None:
        # pyOpenSSL's own types: the floor binding in CI rejects a
        # cryptography certificate here, and the library loads chains the
        # same way.
        context.use_certificate(
            crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
        )
        context.use_privatekey(
            crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem.encode())
        )
    if psk:
        ffi = _util.ffi

        @ffi.callback(
            'unsigned int(*)(SSL *, const char *, unsigned char *, '
            'unsigned int)'
        )
        def server_callback(_ssl, _identity, _key_buffer, _max_key_length):
            # Every identity is unknown, so OpenSSL raises the RFC 4279
            # unknown_psk_identity(115) alert itself.
            return 0

        # Retained on the context object: the callback must outlive this call.
        context._test_psk_callback = server_callback
        _util.lib.SSL_CTX_set_psk_server_callback(
            context._context, server_callback
        )
    return context


# RFC 5746 §3.3. Advertised alongside the real suites by some OpenSSL
# builds, and it names no cipher, so it is dropped before comparing.
_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF


def _client_hello_cipher_suites(datagram):
    """Read the offered cipher suites out of a DTLS ClientHello datagram.

    Signalling suite values are excluded, leaving only real ciphers.
    """
    fragment = datagram[13:13 + int.from_bytes(datagram[11:13], 'big')]
    body = fragment[12:]                      # past the handshake header
    offset = 2 + 32                           # client_version + random
    offset += 1 + body[offset]                # session_id
    offset += 1 + body[offset]                # cookie
    length = int.from_bytes(body[offset:offset + 2], 'big')
    suites = body[offset + 2:offset + 2 + length]
    return {
        int.from_bytes(suites[i:i + 2], 'big')
        for i in range(0, len(suites), 2)
    } - {_EMPTY_RENEGOTIATION_INFO_SCSV}


def test_diagnostic_psk_provider_reaches_an_unknown_psk_identity_alert(
        monkeypatch):
    # The point of auth=: a PSK carrier is diagnosable on the same footing as
    # a certificate one, and the alert it fails with is named rather than
    # reported as a bare 115.
    from smartthings_local.protocol.auth import PskAuth

    server = _LoopbackDtlsServer(
        _server_context(cipher=b'ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0',
                        psk=True)
    )
    fake = _FakeSock(server)
    _patch_sock(monkeypatch, fake)

    result = p.diagnose_dtls_handshake(
        '127.0.0.1',
        5684,
        auth=PskAuth(identity=bytes(range(1, 17)), key=b'k' * 16),
        timeout=2.0,
    )

    assert result.alert == (2, 'unknown_psk_identity')
    assert result.outcome == p.REJECTED
    assert 'ServerHello' in result.handshake_msgs


def test_diagnostic_psk_provider_replaces_the_certificate_cipher_list(
        monkeypatch):
    # Ordering guarantee: the provider is applied after the probe's own
    # baseline, so PskAuth's suite replaces ECDHE-ECDSA rather than being
    # overwritten by it.
    from smartthings_local.protocol.auth import PskAuth

    fake = _FakeSock(lambda _f: None)
    _patch_sock(monkeypatch, fake)
    p.diagnose_dtls_handshake(
        '127.0.0.1', 5684,
        auth=PskAuth(identity=bytes(range(1, 17)), key=b'k' * 16),
        timeout=0.2, retries=0,
    )
    psk_suites = _client_hello_cipher_suites(fake.sends[0])

    certificate_fake = _FakeSock(lambda _f: None)
    _patch_sock(monkeypatch, certificate_fake)
    p.diagnose_dtls_handshake('127.0.0.1', 5684, timeout=0.2, retries=0)
    certificate_suites = _client_hello_cipher_suites(
        certificate_fake.sends[0]
    )

    assert psk_suites == {_ECDHE_PSK_AES128_CBC_SHA256}
    assert certificate_suites == {_ECDHE_ECDSA_AES128_GCM_SHA256}


def test_diagnostic_certificate_provider_matches_inline_pem_credentials(
        monkeypatch):
    # auth=CertificateAuth has to be a pure re-spelling of cert_pem/key_pem,
    # since an existing caller's behaviour must not shift under the new
    # parameter.
    from smartthings_local.protocol.auth import CertificateAuth

    cert_pem, key_pem = _synthetic_ec_server_credentials()
    outcomes = []
    for credentials in (
        {'cert_pem': cert_pem, 'key_pem': key_pem},
        {'auth': CertificateAuth.from_memory(cert_pem, key_pem)},
    ):
        server_cert, server_key = _synthetic_ec_server_credentials()
        fake = _FakeSock(
            _LoopbackDtlsServer(
                _server_context(
                    cipher=b'ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0',
                    cert_pem=server_cert,
                    key_pem=server_key,
                )
            )
        )
        _patch_sock(monkeypatch, fake)
        result = p.diagnose_dtls_handshake(
            '127.0.0.1', 5684, timeout=2.0, **credentials
        )
        outcomes.append(
            (result.outcome, tuple(result.handshake_msgs), result.alert)
        )

    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == p.COMPLETED
    assert outcomes[0][1] == (
        'ServerHello',
        'Certificate',
        'ServerKeyExchange',
        'ServerHelloDone',
        'NewSessionTicket',
    )


def test_diagnostic_never_gates_on_a_pinned_server_identity(monkeypatch):
    # A SamsungServerProfile pins an identity from inside the verify
    # callback, which would turn this synthetic server's chain into a local
    # verify failure. A diagnostic must report what the appliance did, so the
    # probe re-asserts accept-any last and the handshake still completes.
    from smartthings_local.protocol.auth import (
        CertificateAuth,
        SamsungServerProfile,
    )

    cert_pem, key_pem = _synthetic_ec_server_credentials()
    server_cert, server_key = _synthetic_ec_server_credentials()
    fake = _FakeSock(
        _LoopbackDtlsServer(
            _server_context(
                cipher=b'ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0',
                cert_pem=server_cert,
                key_pem=server_key,
            )
        )
    )
    _patch_sock(monkeypatch, fake)

    result = p.diagnose_dtls_handshake(
        '127.0.0.1',
        5684,
        auth=CertificateAuth.from_memory(
            cert_pem,
            key_pem,
            server_profile=SamsungServerProfile(
                # tools/check_share_safety.py's allowlisted placeholder.
                expected_certificate_identity=(
                    '11111111-2222-3333-4444-555555555555'
                ),
            ),
        ),
        timeout=2.0,
    )

    assert result.outcome == p.COMPLETED
    assert result.error is None


def test_diagnostic_rejects_auth_beside_certificate_inputs():
    from smartthings_local.protocol.auth import PskAuth

    auth = PskAuth(identity=bytes(range(1, 17)), key=b'k' * 16)
    for credentials in (
        {'cert_pem': 'pem', 'key_pem': 'key'},
        {'cert_path': '/dev/null', 'key_path': '/dev/null'},
    ):
        with pytest.raises(ValueError, match='not both'):
            p.diagnose_dtls_handshake(
                '127.0.0.1', 5684, auth=auth, **credentials
            )


def test_diagnostic_rejects_an_object_that_is_not_a_provider():
    with pytest.raises(TypeError, match='AuthenticationProvider'):
        p.diagnose_dtls_handshake('127.0.0.1', 5684, auth=object())


def test_cli_psk_credential_requires_the_diagnostic_mode(capsys):
    result = p._main([
        '127.0.0.1', '5684',
        '--psk-identity', '000102030405060708090a0b0c0d0e0f',
        '--psk-key', '00' * 16,
    ])

    assert result == 2
    assert 'requires the explicit --diagnostic mode' in capsys.readouterr().out


def test_cli_psk_credential_needs_both_halves(capsys):
    result = p._main([
        '127.0.0.1', '5684', '--diagnostic',
        '--psk-identity', '000102030405060708090a0b0c0d0e0f',
    ])

    assert result == 2
    assert 'must be supplied together' in capsys.readouterr().out


def test_cli_refuses_a_certificate_and_a_psk_together(capsys):
    result = p._main([
        '127.0.0.1', '5684', '--diagnostic',
        '--cert', 'c.pem', '--key', 'k.pem',
        '--psk-identity', '000102030405060708090a0b0c0d0e0f',
        '--psk-key', '00' * 16,
    ])

    assert result == 2
    assert 'not both' in capsys.readouterr().out


def test_cli_reports_an_unusable_psk_credential_without_a_traceback(capsys):
    # A NUL in the identity is rejected by PskAuth, and the CLI has to render
    # that as a usage error rather than an exception.
    result = p._main([
        '127.0.0.1', '5684', '--diagnostic',
        '--psk-identity', '0102030405060708000a0b0c0d0e0f10',
        '--psk-key', '00' * 16,
    ])

    assert result == 2
    assert 'invalid PSK credential' in capsys.readouterr().out


def test_encrypted_records_do_not_invent_handshake_messages(monkeypatch):
    # A handshake record after ChangeCipherSpec is encrypted, so its first
    # byte is ciphertext. Read as a message type it names whatever it
    # collides with, and roughly one byte in 256 collides with a name in
    # _HS_NAMES: this fabricated a 'Finished' once in 30 real handshakes
    # before the suppression went in. 20 is Finished's type value.
    responses = iter((
        _hvr(),
        _rec(p._CT_CHANGE_CIPHER_SPEC, b'\x01')
        + _rec(p._CT_HANDSHAKE, bytes([20]) + b'ciphertext'),
    ))
    fake = _FakeSock(lambda _f: next(responses, None))
    _patch_sock(monkeypatch, fake)

    result = p.diagnose_dtls_handshake('127.0.0.1', 5684, timeout=0.3)

    assert result.handshake_msgs == ['HelloVerifyRequest']
    assert 'Finished' not in result.handshake_msgs
