import pytest
from OpenSSL import SSL, crypto

from smartthings_local.protocol.dtls_session import DtlsCoapSession, _load_pem_chain


def _make_self_signed_pem_pair():
    """A throwaway self-signed cert + key, just to exercise PEM loading —
    not meant to resemble a real Samsung client cert."""
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = "test"
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode()
    return cert_pem, key_pem


def test_load_pem_chain_loads_cert_and_key_in_memory():
    cert_pem, key_pem = _make_self_signed_pem_pair()
    ctx = SSL.Context(SSL.DTLS_METHOD)
    _load_pem_chain(ctx, cert_pem, key_pem)
    ctx.check_privatekey()  # raises if cert/key don't match


def test_load_pem_chain_rejects_cert_pem_with_no_certificates():
    with pytest.raises(ValueError):
        _load_pem_chain(SSL.Context(SSL.DTLS_METHOD), "not a cert", "not a key")


def test_session_requires_exactly_one_cert_source():
    cert_pem, key_pem = _make_self_signed_pem_pair()

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234)  # neither pair given

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234, cert_path="/a", key_path="/b",
                         cert_pem=cert_pem, key_pem=key_pem)  # both given

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234, cert_pem=cert_pem)  # key_pem missing


def test_session_accepts_pem_pair():
    cert_pem, key_pem = _make_self_signed_pem_pair()
    sess = DtlsCoapSession("host", 1234, cert_pem=cert_pem, key_pem=key_pem)
    assert sess.cert_path is None
    assert sess.key_path is None
    assert sess.cert_pem == cert_pem
