import gc
import traceback
import weakref
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL, crypto

from smartthings_local.protocol.auth import CertificateAuth
from smartthings_local.protocol.dtls_session import DtlsCoapSession, _load_pem_chain


def _make_generated_pem_chain():
    """Create a throwaway leaf + root chain unrelated to Samsung devices."""
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test root")]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test client")]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(root_key, hashes.SHA256())
    )

    cert_pem = (
        leaf_cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM)
    ).decode()
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def test_load_pem_chain_loads_cert_and_key_in_memory():
    cert_pem, key_pem = _make_generated_pem_chain()
    ctx = SSL.Context(SSL.DTLS_METHOD)
    _load_pem_chain(ctx, cert_pem, key_pem)
    ctx.check_privatekey()  # raises if cert/key don't match


def test_load_pem_chain_rejects_cert_pem_with_no_certificates():
    with pytest.raises(ValueError):
        _load_pem_chain(SSL.Context(SSL.DTLS_METHOD), "not a cert", "not a key")


def test_session_requires_exactly_one_cert_source():
    cert_pem, key_pem = _make_generated_pem_chain()

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234)  # neither pair given

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234, cert_path="/a", key_path="/b",
                         cert_pem=cert_pem, key_pem=key_pem)  # both given

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234, cert_pem=cert_pem)  # key_pem missing

    with pytest.raises(ValueError):
        DtlsCoapSession("host", 1234, cert_path="/a")  # key_path missing


def test_session_rejects_provider_with_legacy_certificate_arguments():
    cert_pem, key_pem = _make_generated_pem_chain()
    auth = CertificateAuth.from_memory(cert_pem, key_pem)

    with pytest.raises(ValueError, match="auth or legacy certificate"):
        DtlsCoapSession(
            "host",
            1234,
            cert_pem=cert_pem,
            key_pem=key_pem,
            auth=auth,
        )


def test_session_rejects_object_that_is_not_an_authentication_provider():
    with pytest.raises(TypeError, match="AuthenticationProvider"):
        DtlsCoapSession("host", 1234, auth=object())


def test_session_accepts_explicit_certificate_provider():
    cert_pem, key_pem = _make_generated_pem_chain()
    auth = CertificateAuth.from_memory(cert_pem, key_pem)
    session = DtlsCoapSession("host", 1234, auth=auth)

    assert session.auth is auth
    assert session.cert_path is None
    assert session.key_path is None
    assert session.cert_pem is None
    assert session.key_pem is None


def test_session_retains_authentication_provider_for_its_lifetime():
    class RetainedProvider:
        def configure_context(self, _context):
            return None

    auth = RetainedProvider()
    reference = weakref.ref(auth)
    session = DtlsCoapSession("host", 1234, auth=auth)

    del auth
    gc.collect()
    assert reference() is session.auth


def test_session_accepts_pem_pair():
    cert_pem, key_pem = _make_generated_pem_chain()
    sess = DtlsCoapSession("host", 1234, cert_pem=cert_pem, key_pem=key_pem)
    assert sess.cert_path is None
    assert sess.key_path is None
    assert sess.cert_pem == cert_pem
    assert isinstance(sess.auth, CertificateAuth)


def test_session_routes_legacy_file_pair_through_certificate_auth(tmp_path):
    cert_path = tmp_path / "client.pem"
    key_path = tmp_path / "client-key.pem"
    session = DtlsCoapSession(
        "host",
        1234,
        cert_path=cert_path,
        key_path=key_path,
    )

    assert isinstance(session.auth, CertificateAuth)
    assert session.cert_path == str(cert_path)
    assert session.key_path == str(key_path)


def test_certificate_auth_loads_generated_chain_from_memory_and_files(tmp_path):
    cert_pem, key_pem = _make_generated_pem_chain()

    memory_context = SSL.Context(SSL.DTLS_METHOD)
    CertificateAuth.from_memory(cert_pem, key_pem).configure_context(
        memory_context
    )
    memory_context.check_privatekey()

    cert_path = tmp_path / "client.pem"
    key_path = tmp_path / "client-key.pem"
    cert_path.write_text(cert_pem)
    key_path.write_text(key_pem)
    file_context = SSL.Context(SSL.DTLS_METHOD)
    CertificateAuth.from_files(cert_path, key_path).configure_context(file_context)
    file_context.check_privatekey()


def test_certificate_auth_rejects_invalid_memory_material():
    auth = CertificateAuth.from_memory("not a certificate", "not a key")
    with pytest.raises(ValueError, match="No certificates found"):
        auth.configure_context(SSL.Context(SSL.DTLS_METHOD))


def test_invalid_certificate_error_does_not_include_credential_material():
    marker = "credential" + "-marker"
    certificate_blob = (
        "-----BEGIN CERTIFICATE-----\n"
        f"{marker}\n"
        "-----END CERTIFICATE-----\n"
    )
    key_blob = "invalid-" + marker
    auth = CertificateAuth.from_memory(certificate_blob, key_blob)

    with pytest.raises(crypto.Error) as captured:
        auth.configure_context(SSL.Context(SSL.DTLS_METHOD))
    rendered = (
        str(captured.value)
        + repr(captured.value)
        + "".join(traceback.format_exception(captured.value))
    )
    assert marker not in rendered


def test_certificate_auth_rejects_invalid_file_material(tmp_path):
    cert_path = tmp_path / "invalid.pem"
    key_path = tmp_path / "invalid-key.pem"
    cert_path.write_text("invalid")
    key_path.write_text("invalid")

    with pytest.raises(SSL.Error):
        CertificateAuth.from_files(cert_path, key_path).configure_context(
            SSL.Context(SSL.DTLS_METHOD)
        )


def test_certificate_auth_rejects_incomplete_or_mixed_sources():
    with pytest.raises(ValueError):
        CertificateAuth()
    with pytest.raises(ValueError):
        CertificateAuth(certificate_path="/synthetic/client.pem")
    with pytest.raises(ValueError):
        CertificateAuth(certificate_pem="certificate")

    certificate_path = "/synthetic/client.pem"
    key_path = "/synthetic/client-key.pem"
    certificate_data = "certificate"
    key_data = "key"
    with pytest.raises(ValueError):
        CertificateAuth(
            certificate_path=certificate_path,
            private_key_path=key_path,
            certificate_pem=certificate_data,
            private_key_pem=key_data,
        )


def test_certificate_auth_is_immutable_and_has_secret_safe_repr():
    cert_pem, key_pem = _make_generated_pem_chain()
    auth = CertificateAuth.from_memory(cert_pem, key_pem)

    rendered = repr(auth)
    assert rendered == "CertificateAuth()"
    assert cert_pem not in rendered
    assert key_pem not in rendered
    with pytest.raises(AttributeError, match="immutable"):
        auth.certificate_pem = None
    with pytest.raises(AttributeError, match="immutable"):
        del auth._certificate_pem


def test_certificate_auth_has_no_public_or_dataclass_credential_surface():
    cert_pem, key_pem = _make_generated_pem_chain()
    auth = CertificateAuth.from_memory(cert_pem, key_pem)

    assert not hasattr(auth, "certificate_pem")
    assert not hasattr(auth, "private_key_pem")
    with pytest.raises(TypeError):
        vars(auth)
    with pytest.raises(TypeError):
        asdict(auth)


def test_certificate_auth_context_setup_matches_legacy_happy_path():
    class RecordingContext:
        def __init__(self):
            self.calls = []
            self.verify_callback = None

        def load_verify_locations(self, path):
            self.calls.append(("load_verify_locations", path))

        def set_verify(self, mode, callback):
            self.calls.append(("set_verify", mode))
            self.verify_callback = callback

        def set_cipher_list(self, ciphers):
            self.calls.append(("set_cipher_list", ciphers))

        def set_options(self, options):
            self.calls.append(("set_options", options))

        def use_certificate_chain_file(self, path):
            self.calls.append(("use_certificate_chain_file", path))

        def use_privatekey_file(self, path):
            self.calls.append(("use_privatekey_file", path))

        def check_privatekey(self):
            self.calls.append(("check_privatekey",))

    context = RecordingContext()
    CertificateAuth.from_files(
        "/synthetic/client.pem",
        "/synthetic/client-key.pem",
    ).configure_context(context)

    assert [call[0] for call in context.calls] == [
        "load_verify_locations",
        "set_verify",
        "set_cipher_list",
        "set_options",
        "use_certificate_chain_file",
        "use_privatekey_file",
        "check_privatekey",
    ]
    assert context.calls[1] == ("set_verify", SSL.VERIFY_PEER)
    assert context.calls[2] == (
        "set_cipher_list",
        b"ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0",
    )
    assert context.calls[3] == (
        "set_options",
        SSL.OP_NO_TICKET,
    )
    callback = context.verify_callback
    assert callback(None, None, 0, 0, True) is True
    assert callback(None, None, 1, 0, False) is False
