"""Where the certificate engine meets trust: diagnostics, refusals, purpose.

Four rules, each from the review of #129 at 8aaa251:

- `diagnose_dtls_handshake` never enforces trust, whichever credential it
  gets. `FragmentingCertificateAuth` used to reach it through its public
  factory, whose connection always verifies the chain, so an untrusted chain
  failed locally before our flight, and the caller got a local error in place
  of the appliance's alert.
- When the engine refuses the peer before its own flight, it sends an
  epoch-zero fatal `handshake_failure`, so the peer does not keep a half-open
  handshake for this client. The driver sends it; a pyOpenSSL connection has
  no such alert to give and is unchanged.
- The engine verifies the server chain for the SSL-server purpose, as the
  pyOpenSSL path does, so a leaf whose EKU lacks serverAuth fails on both.
- A bad `max_fragment_length` raises where it is supplied, not at connect.

Everything runs against OpenSSL over memory BIOs with throwaway chains.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
import test_certificate_profiles as profiles
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import SSL, crypto
from test_dtls_cert_interop import _pump

from smartthings_local.protocol import dtls_probe
from smartthings_local.protocol._dtls_cert import DtlsCertClient, DtlsError
from smartthings_local.protocol.auth import (
    CertificateAuth,
    FragmentingCertificateAuth,
    SamsungServerProfile,
    _PEM_CERT_RE,
)
from smartthings_local.protocol.dtls_handshake import _drive_dtls_handshake

_IDENTITY = UUID("11111111-2222-3333-4444-555555555555")


@pytest.fixture(scope="module")
def chain():
    return profiles._make_generated_chain(_IDENTITY)


def _server(chain):
    server = SSL.Connection(
        profiles._configured_certificate_server_context(chain), None
    )
    server.set_accept_state()
    return server


def _provider(chain, profile=None, **kwargs):
    return FragmentingCertificateAuth(
        server_profile=profile,
        certificate_pem=chain.certificate_pem,
        private_key_pem=chain.private_key_pem,
        **kwargs,
    )


def _chain_der(chain):
    return [
        crypto.dump_certificate(
            crypto.FILETYPE_ASN1, crypto.load_certificate(crypto.FILETYPE_PEM, block)
        )
        for block in _PEM_CERT_RE.findall(chain.certificate_pem.encode())
    ]


# -- the diagnostic does not gate on trust ---------------------------------


def test_the_session_connection_refuses_a_chain_outside_the_ocf_root(chain):
    """The control: the synthetic root is not the bundled OCF root."""
    client = _provider(chain).create_dtls_connection(mtu=1400)
    with pytest.raises(DtlsError, match="peer certificate rejected"):
        _pump(client, _server(chain))


def test_the_diagnostic_connection_completes_on_the_same_chain(chain):
    client = dtls_probe._diagnostic_connection(
        auth=_provider(chain), cert_pem=None, key_pem=None,
        cert_path=None, key_path=None, mtu=1200,
    )
    _pump(client, _server(chain))
    assert client._state == "established"


def test_the_diagnostic_ignores_a_profile_pin_too(chain):
    profile = SamsungServerProfile(
        expected_certificate_identity=UUID("99999999-2222-3333-4444-555555555555"),
        additional_ca_pem=chain.root_pem,
    )
    client = dtls_probe._diagnostic_connection(
        auth=_provider(chain, profile), cert_pem=None, key_pem=None,
        cert_path=None, key_path=None, mtu=1200,
    )
    _pump(client, _server(chain))
    assert client._state == "established"


def test_the_public_factory_still_verifies(chain):
    """The diagnostic hook is a second door, not a change to the first."""
    client = _provider(chain).create_dtls_connection(mtu=1400)
    assert client._verify_peer_chain is not None


# -- a refusal frees the peer ----------------------------------------------


def test_a_refusal_keeps_one_epoch_zero_fatal_handshake_failure(chain):
    client = _provider(chain).create_dtls_connection(mtu=1400)
    with pytest.raises(DtlsError):
        _pump(client, _server(chain))

    alert = client._take_abandon_alert()
    assert len(alert) == 15
    assert alert[0] == 21                      # alert
    assert alert[1:3] == b"\xfe\xfd"           # DTLS 1.2
    assert alert[3:5] == b"\x00\x00"           # epoch zero
    assert alert[11:13] == b"\x00\x02"
    assert alert[13:] == bytes([2, 40])        # fatal handshake_failure
    assert client._take_abandon_alert() == b""


def test_openssl_reads_that_alert_as_the_end_of_the_handshake(chain):
    client = _provider(chain).create_dtls_connection(mtu=1400)
    server = _server(chain)
    with pytest.raises(DtlsError):
        _pump(client, server)

    server.bio_write(client._take_abandon_alert())
    with pytest.raises(SSL.Error) as raised:
        server.do_handshake()
    assert not isinstance(raised.value, SSL.WantReadError)


def test_a_failure_the_peer_caused_keeps_no_alert():
    engine = DtlsCertClient([b"\x30"], ec.generate_private_key(ec.SECP256R1()))
    engine._fail("peer sent fatal alert 40")
    assert engine._take_abandon_alert() == b""


class _Socket:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, data):
        if self.fail:
            raise OSError("down")
        self.sent.append(bytes(data))
        return len(data)


class _Failing:
    def __init__(self, alert=None):
        self.alert = alert

    def do_handshake(self):
        raise SSL.Error("refused")

    def __getattr__(self, name):
        if name == "_take_abandon_alert" and self.alert is not None:
            return lambda: self.alert
        raise AttributeError(name)


def _drive(connection, sock):
    recorded = []
    with pytest.raises(SSL.Error, match="refused"):
        _drive_dtls_handshake(
            connection, sock, deadline=float("inf"),
            on_record_sent=recorded.append,
        )
    return recorded


def test_the_driver_sends_the_kept_alert_and_still_raises():
    sock = _Socket()
    recorded = _drive(_Failing(alert=b"ALERT"), sock)
    assert sock.sent == [b"ALERT"]
    assert recorded == [b"ALERT"]


def test_the_driver_sends_nothing_for_a_connection_without_the_hook():
    sock = _Socket()
    assert _drive(_Failing(), sock) == []
    assert sock.sent == []


def test_a_failed_alert_send_does_not_replace_the_handshake_error():
    _drive(_Failing(alert=b"ALERT"), _Socket(fail=True))


# -- the server purpose ----------------------------------------------------


@pytest.mark.parametrize(
    ("eku", "accepted"),
    [
        (ExtendedKeyUsageOID.SERVER_AUTH, True),
        (ExtendedKeyUsageOID.CLIENT_AUTH, False),
    ],
)
def test_the_engine_and_pyopenssl_agree_on_the_server_purpose(
    monkeypatch, eku, accepted
):
    monkeypatch.setattr(
        profiles, "ExtendedKeyUsageOID", SimpleNamespace(SERVER_AUTH=eku)
    )
    chain = profiles._make_generated_chain(_IDENTITY)
    profile = SamsungServerProfile(
        expected_certificate_identity=_IDENTITY,
        additional_ca_pem=chain.root_pem,
    )

    context = SSL.Context(SSL.DTLS_METHOD)
    CertificateAuth.from_memory(
        chain.certificate_pem, chain.private_key_pem, server_profile=profile
    ).configure_context(context)
    try:
        profiles._drive_memory_bio_handshake(
            context, profiles._configured_certificate_server_context(chain)
        )
        pyopenssl_accepted = True
    except SSL.Error:
        pyopenssl_accepted = False

    try:
        _provider(chain, profile)._verify_peer_chain(_chain_der(chain))
        engine_accepted = True
    except crypto.X509StoreContextError:
        engine_accepted = False

    assert pyopenssl_accepted is accepted
    assert engine_accepted is accepted


# -- the fragment length is checked where it is supplied -------------------


@pytest.mark.parametrize("value", [700, "1024", True, 0])
def test_a_bad_fragment_length_raises_at_construction(chain, value):
    with pytest.raises(ValueError, match="max_fragment_length"):
        _provider(chain, max_fragment_length=value)


@pytest.mark.parametrize("value", [None, 512, 4096])
def test_a_valid_fragment_length_is_kept(chain, value):
    client = _provider(chain, max_fragment_length=value).create_dtls_connection(
        mtu=1400
    )
    assert client._mfl == value
