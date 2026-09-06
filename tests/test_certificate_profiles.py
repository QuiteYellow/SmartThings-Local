"""Synthetic security and wire-contract tests for certificate profiles."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from OpenSSL import SSL, crypto

import smartthings_local.protocol.auth as auth_module
from smartthings_local.protocol.auth import (
    CertificateAuth,
    SamsungServerProfile,
    SamsungServerRole,
    ServerCertificateAuth,
)

_IDENTITY = UUID(bytes=b"\xab" * 16)
_OTHER_IDENTITY = UUID(bytes=b"\xcd" * 16)


def _build_certificate(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    issuer_key,
    serial_number: int,
    is_ca: bool | None,
) -> x509.Certificate:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
    )
    if is_ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    if is_ca is False:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_der_element(tag: int, contents: bytes) -> bytes:
    return bytes([tag]) + _encode_der_length(len(contents)) + contents


def _read_der_element(
    encoded: bytes,
    offset: int,
) -> tuple[int, int, int, int]:
    tag = encoded[offset]
    first_length_octet = encoded[offset + 1]
    if first_length_octet < 0x80:
        length_octets = 0
        length = first_length_octet
    else:
        length_octets = first_length_octet & 0x7F
        assert 0 < length_octets <= 4
        length = int.from_bytes(
            encoded[offset + 2 : offset + 2 + length_octets],
            "big",
        )
    contents_start = offset + 2 + length_octets
    contents_end = contents_start + length
    assert contents_end <= len(encoded)
    return tag, contents_start, contents_end, contents_end


def _add_tbs_signature_algorithm_trailing_null(
    certificate: x509.Certificate,
    issuer_key,
) -> bytes:
    """Make a signed synthetic leaf with Samsung-style algorithm extra data."""
    encoded = certificate.public_bytes(serialization.Encoding.DER)
    outer_tag, outer_start, _outer_end, certificate_end = _read_der_element(
        encoded,
        0,
    )
    assert outer_tag == 0x30
    assert certificate_end == len(encoded)

    tbs_tag, tbs_start, tbs_end, tbs_next = _read_der_element(
        encoded,
        outer_start,
    )
    assert tbs_tag == 0x30
    signature_algorithm_offset = tbs_start
    for _ in range(2):
        _, _, _, signature_algorithm_offset = _read_der_element(
            encoded,
            signature_algorithm_offset,
        )
    (
        signature_algorithm_tag,
        signature_algorithm_start,
        signature_algorithm_end,
        _,
    ) = _read_der_element(encoded, signature_algorithm_offset)
    assert signature_algorithm_tag == 0x30

    malformed_signature_algorithm = _encode_der_element(
        0x30,
        encoded[signature_algorithm_start:signature_algorithm_end]
        + b"\x05\x00",
    )
    malformed_tbs = _encode_der_element(
        0x30,
        encoded[tbs_start:signature_algorithm_offset]
        + malformed_signature_algorithm
        + encoded[signature_algorithm_end:tbs_end],
    )

    (
        outer_signature_tag,
        outer_signature_start,
        outer_signature_end,
        _,
    ) = _read_der_element(
        encoded,
        tbs_next,
    )
    assert outer_signature_tag == 0x30
    malformed_outer_signature_algorithm = _encode_der_element(
        0x30,
        encoded[outer_signature_start:outer_signature_end] + b"\x05\x00",
    )
    signature = issuer_key.sign(malformed_tbs, ec.ECDSA(hashes.SHA256()))
    return _encode_der_element(
        0x30,
        malformed_tbs
        + malformed_outer_signature_algorithm
        + _encode_der_element(0x03, b"\x00" + signature),
    )


def _make_generated_chain(
    identity: UUID,
    *,
    organizational_unit: str = "OCF HA Device",
    intermediate_has_constraints: bool = True,
    leaf_signature_algorithm_trailing_null: bool = False,
):
    """Create a throwaway three-level chain unrelated to real devices."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic profile root")]
    )
    root = _build_certificate(
        subject=root_name,
        issuer=root_name,
        public_key=root_key.public_key(),
        issuer_key=root_key,
        serial_number=101,
        is_ca=True,
    )

    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Synthetic profile intermediate",
            )
        ]
    )
    intermediate = _build_certificate(
        subject=intermediate_name,
        issuer=root_name,
        public_key=intermediate_key.public_key(),
        issuer_key=root_key,
        serial_number=102,
        is_ca=True if intermediate_has_constraints else None,
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "Samsung Electronics",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                organizational_unit,
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                f"OCF Device: Test ({identity})",
            ),
        ]
    )
    leaf = _build_certificate(
        subject=leaf_name,
        issuer=intermediate_name,
        public_key=leaf_key.public_key(),
        issuer_key=intermediate_key,
        serial_number=103,
        is_ca=False,
    )

    root_pem = root.public_bytes(serialization.Encoding.PEM).decode()
    intermediate_pem = intermediate.public_bytes(serialization.Encoding.PEM).decode()
    if leaf_signature_algorithm_trailing_null:
        leaf_der = _add_tbs_signature_algorithm_trailing_null(
            leaf,
            intermediate_key,
        )
        openssl_leaf = crypto.load_certificate(crypto.FILETYPE_ASN1, leaf_der)
        leaf_pem = crypto.dump_certificate(
            crypto.FILETYPE_PEM,
            openssl_leaf,
        ).decode()
    else:
        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        openssl_leaf = crypto.load_certificate(crypto.FILETYPE_PEM, leaf_pem)
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return SimpleNamespace(
        root_pem=root_pem,
        certificate_pem=leaf_pem + intermediate_pem,
        private_key_pem=key_pem,
        leaf=openssl_leaf,
        intermediate=crypto.load_certificate(
            crypto.FILETYPE_PEM,
            intermediate_pem,
        ),
    )


@pytest.fixture(scope="module")
def generated_chain():
    return _make_generated_chain(_IDENTITY)


def _configured_context(chain, profile=None, *, server_only=False) -> SSL.Context:
    context = SSL.Context(SSL.DTLS_METHOD)
    if server_only:
        ServerCertificateAuth(server_profile=profile).configure_context(context)
    else:
        CertificateAuth.from_memory(
            chain.certificate_pem,
            chain.private_key_pem,
            server_profile=profile,
        ).configure_context(context)
    return context


def _configured_certificate_server_context(chain) -> SSL.Context:
    context = SSL.Context(SSL.DTLS_METHOD)
    certificates = auth_module._PEM_CERT_RE.findall(
        chain.certificate_pem.encode()
    )
    context.use_certificate(
        crypto.load_certificate(crypto.FILETYPE_PEM, certificates[0])
    )
    for certificate in certificates[1:]:
        context.add_extra_chain_cert(
            crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        )
    context.use_privatekey(
        crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            chain.private_key_pem.encode(),
        )
    )
    context.check_privatekey()
    # Request a client certificate but permit an empty certificate message,
    # matching a server-authenticated manufacturer-certificate OTM carrier.
    context.set_verify(SSL.VERIFY_PEER, lambda *_args: True)
    return context


def _first_client_hello(context: SSL.Context) -> bytes:
    connection = SSL.Connection(context, None)
    connection.set_connect_state()
    with pytest.raises(SSL.WantReadError):
        connection.do_handshake()
    chunks = []
    while True:
        try:
            chunks.append(connection.bio_read(65535))
        except SSL.WantReadError:
            break
    assert len(chunks) == 1
    return chunks[0]


def _parse_client_hello(datagram: bytes):
    """Return cipher suites and extensions from one DTLS ClientHello."""
    assert datagram[0] == 22
    record_length = int.from_bytes(datagram[11:13], "big")
    handshake = datagram[13 : 13 + record_length]
    assert handshake[0] == 1
    body = handshake[12:]

    offset = 2 + 32
    session_id_length = body[offset]
    offset += 1 + session_id_length
    cookie_length = body[offset]
    offset += 1 + cookie_length

    cipher_length = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    ciphers = [
        int.from_bytes(body[index : index + 2], "big")
        for index in range(offset, offset + cipher_length, 2)
    ]
    offset += cipher_length

    compression_length = body[offset]
    offset += 1 + compression_length
    extensions_length = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extensions_end = offset + extensions_length
    extensions = {}
    while offset < extensions_end:
        extension_type = int.from_bytes(body[offset : offset + 2], "big")
        extension_length = int.from_bytes(
            body[offset + 2 : offset + 4],
            "big",
        )
        offset += 4
        assert extension_type not in extensions
        extensions[extension_type] = body[offset : offset + extension_length]
        offset += extension_length
    assert offset == extensions_end == len(body)
    return ciphers, extensions


def _vector_values(extension: bytes) -> list[int]:
    vector_length = int.from_bytes(extension[:2], "big")
    assert vector_length == len(extension) - 2
    return [
        int.from_bytes(extension[index : index + 2], "big")
        for index in range(2, len(extension), 2)
    ]


def _drive_memory_bio_handshake(
    client_context: SSL.Context,
    server_context: SSL.Context,
) -> tuple[SSL.Connection, SSL.Connection]:
    client = SSL.Connection(client_context, None)
    client.set_connect_state()
    client.set_ciphertext_mtu(1200)
    server = SSL.Connection(server_context, None)
    server.set_accept_state()
    server.set_ciphertext_mtu(1200)
    client_done = False
    server_done = False

    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
        while True:
            try:
                server.bio_write(client.bio_read(65535))
            except SSL.WantReadError:
                break

        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
        while True:
            try:
                client.bio_write(server.bio_read(65535))
            except SSL.WantReadError:
                break

        if client_done and server_done:
            return client, server

    raise AssertionError("synthetic DTLS handshake did not complete")


def _verify_chain(context: SSL.Context, chain) -> None:
    crypto.X509StoreContext(
        context.get_cert_store(),
        chain.leaf,
        [chain.intermediate],
    ).verify_certificate()


def test_profile_accepts_only_canonical_nonzero_identity():
    assert repr(SamsungServerProfile.bound_device(_IDENTITY)) == (
        "SamsungServerProfile()"
    )
    assert repr(SamsungServerProfile.bound_device(str(_IDENTITY))) == (
        "SamsungServerProfile()"
    )

    for invalid in (
        UUID(int=0),
        str(UUID(int=0)),
        str(_IDENTITY).upper(),
        "{" + str(_IDENTITY) + "}",
        "not-an-identity",
    ):
        with pytest.raises(ValueError, match="canonical non-zero UUID"):
            SamsungServerProfile.bound_device(invalid)
    for invalid in (True, 1, b"not-an-identity"):
        with pytest.raises(TypeError, match="UUID or string"):
            SamsungServerProfile.bound_device(invalid)


def test_discovery_profile_verifies_role_before_exposing_identity():
    first_chain = _make_generated_chain(_IDENTITY)
    second_chain = _make_generated_chain(_OTHER_IDENTITY)
    zero_chain = _make_generated_chain(UUID(int=0))
    wrong_role = _make_generated_chain(
        _IDENTITY,
        organizational_unit="OCF VD Device",
    )
    profile = SamsungServerProfile.discover_device()

    assert repr(profile) == "SamsungServerProfile()"
    assert profile._verify_peer(None, first_chain.leaf, 0, 0, True) is True
    assert profile._verify_peer(None, second_chain.leaf, 0, 0, True) is True
    assert profile._verify_peer(None, zero_chain.leaf, 0, 0, True) is False
    assert profile._verify_peer(None, wrong_role.leaf, 0, 0, True) is False

    for invalid in ("OCF HA Device", None, object()):
        with pytest.raises(TypeError, match="SamsungServerRole"):
            SamsungServerProfile.discover_device(role=invalid)


def test_discovery_profile_is_reusable_and_does_not_retain_peer_identity():
    first_chain = _make_generated_chain(_IDENTITY)
    second_chain = _make_generated_chain(_OTHER_IDENTITY)
    profile = SamsungServerProfile.discover_device()
    provider = ServerCertificateAuth(server_profile=profile)

    first = provider._authenticated_server_identity(
        SimpleNamespace(get_peer_certificate=lambda: first_chain.leaf)
    )
    second = provider._authenticated_server_identity(
        SimpleNamespace(get_peer_certificate=lambda: second_chain.leaf)
    )

    assert first == _IDENTITY
    assert second == _OTHER_IDENTITY
    assert not hasattr(profile, "certificate_identity")
    assert str(_IDENTITY) not in repr(profile)
    assert str(_OTHER_IDENTITY) not in repr(profile)

    certificate_provider = CertificateAuth.from_memory(
        first_chain.certificate_pem,
        first_chain.private_key_pem,
        server_profile=profile,
    )
    assert certificate_provider._authenticated_server_identity(
        SimpleNamespace(get_peer_certificate=lambda: second_chain.leaf)
    ) == _OTHER_IDENTITY


def test_profile_roles_are_explicit_and_fail_closed():
    home_chain = _make_generated_chain(_IDENTITY)
    video_chain = _make_generated_chain(
        _IDENTITY,
        organizational_unit="OCF VD Device",
    )
    mismatched_video_chain = _make_generated_chain(
        _OTHER_IDENTITY,
        organizational_unit="OCF VD Device",
    )
    home_profile = SamsungServerProfile.bound_device(_IDENTITY)
    video_profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        role=SamsungServerRole.VD_DEVICE,
    )

    assert home_profile._verify_peer(None, home_chain.leaf, 0, 0, True) is True
    assert home_profile._verify_peer(None, video_chain.leaf, 0, 0, True) is False
    assert video_profile._verify_peer(None, video_chain.leaf, 0, 0, True) is True
    assert video_profile._verify_peer(None, home_chain.leaf, 0, 0, True) is False
    assert (
        video_profile._verify_peer(
            None,
            mismatched_video_chain.leaf,
            0,
            0,
            True,
        )
        is False
    )

    for invalid in ("OCF VD Device", "video_device", None, object()):
        with pytest.raises(TypeError, match="SamsungServerRole"):
            SamsungServerProfile.bound_device(_IDENTITY, role=invalid)


def test_profile_additional_ca_input_is_bounded_and_parsed(generated_chain):
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=generated_chain.root_pem,
    )
    assert repr(profile) == "SamsungServerProfile()"

    with pytest.raises(TypeError, match="must be a string"):
        SamsungServerProfile.bound_device(
            _IDENTITY,
            additional_ca_pem=generated_chain.root_pem.encode(),
        )
    for invalid in (
        "",
        generated_chain.root_pem + "unexpected trailing material",
        generated_chain.root_pem * 5,
        generated_chain.root_pem * 2,
        generated_chain.root_pem + (" " * (32 * 1024)),
        generated_chain.certificate_pem,
        "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
        "non-ascii-\N{SNOWMAN}",
    ):
        with pytest.raises(ValueError):
            SamsungServerProfile.bound_device(
                _IDENTITY,
                additional_ca_pem=invalid,
            )


def test_profile_is_immutable_and_has_no_public_identity_or_ca_surface(
    generated_chain,
):
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=generated_chain.root_pem,
    )
    rendered = repr(profile)
    assert str(_IDENTITY) not in rendered
    assert "BEGIN CERTIFICATE" not in rendered
    assert not hasattr(profile, "expected_certificate_identity")
    assert not hasattr(profile, "additional_ca_pem")
    with pytest.raises(TypeError):
        vars(profile)
    with pytest.raises(TypeError):
        asdict(profile)
    with pytest.raises(AttributeError, match="immutable"):
        profile.expected_certificate_identity = _OTHER_IDENTITY
    with pytest.raises(AttributeError, match="immutable"):
        del profile._expected_certificate_identity


def test_server_certificate_auth_is_explicit_immutable_and_redacted(
    generated_chain,
):
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        role=SamsungServerRole.VD_DEVICE,
        additional_ca_pem=generated_chain.root_pem,
    )
    provider = ServerCertificateAuth(server_profile=profile)

    assert repr(provider) == "ServerCertificateAuth()"
    assert str(_IDENTITY) not in repr(provider)
    assert generated_chain.root_pem not in repr(provider)
    with pytest.raises(TypeError):
        vars(provider)
    with pytest.raises(TypeError):
        asdict(provider)
    with pytest.raises(AttributeError, match="immutable"):
        provider.server_profile = profile
    with pytest.raises(AttributeError, match="immutable"):
        del provider._server_profile
    for invalid in (None, object()):
        with pytest.raises(TypeError, match="SamsungServerProfile"):
            ServerCertificateAuth(server_profile=invalid)


def test_certificate_auth_requires_the_exact_profile_type(generated_chain):
    with pytest.raises(TypeError, match="SamsungServerProfile"):
        CertificateAuth.from_memory(
            generated_chain.certificate_pem,
            generated_chain.private_key_pem,
            server_profile=object(),
        )


def test_profile_emits_the_exact_client_hello_and_reuses_cold(
    generated_chain,
):
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=generated_chain.root_pem,
    )

    first = _parse_client_hello(
        _first_client_hello(_configured_context(generated_chain, profile))
    )
    second = _parse_client_hello(
        _first_client_hello(_configured_context(generated_chain, profile))
    )
    assert first == second

    ciphers, extensions = first
    # Older OpenSSL appends the non-negotiable renegotiation SCSV (0x00ff).
    # No other negotiable cipher may enter the profile.
    assert ciphers[0] == 0xC02B
    assert set(ciphers) <= {0xC02B, 0x00FF}
    assert _vector_values(extensions[10]) == [23]
    assert _vector_values(extensions[13]) == [
        0x0401,
        0x0403,
        0x0201,
        0x0203,
    ]
    assert 35 not in extensions


def test_server_only_profile_emits_the_same_client_hello_without_credentials(
    generated_chain,
):
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        role=SamsungServerRole.VD_DEVICE,
        additional_ca_pem=generated_chain.root_pem,
    )

    certificate_hello = _parse_client_hello(
        _first_client_hello(_configured_context(generated_chain, profile))
    )
    server_only_hello = _parse_client_hello(
        _first_client_hello(
            _configured_context(
                generated_chain,
                profile,
                server_only=True,
            )
        )
    )

    assert server_only_hello == certificate_hello


def test_server_only_profile_completes_without_a_client_certificate():
    video_chain = _make_generated_chain(
        _IDENTITY,
        organizational_unit="OCF VD Device",
    )
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        role=SamsungServerRole.VD_DEVICE,
        additional_ca_pem=video_chain.root_pem,
    )
    client_context = _configured_context(
        video_chain,
        profile,
        server_only=True,
    )

    client, server = _drive_memory_bio_handshake(
        client_context,
        _configured_certificate_server_context(video_chain),
    )

    assert client.get_peer_certificate() is not None
    assert server.get_peer_certificate() is None


def test_profile_verifies_openssl_accepted_non_der_vd_leaf():
    video_chain = _make_generated_chain(
        _IDENTITY,
        organizational_unit="OCF VD Device",
        leaf_signature_algorithm_trailing_null=True,
    )
    try:
        video_chain.leaf.to_cryptography()
    except ValueError as error:
        # cryptography 50 rejects this shape; the dependency floor accepts it.
        assert "TbsCertificate" in str(error)
        assert "signature_alg" in str(error)

    video_profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        role=SamsungServerRole.VD_DEVICE,
        additional_ca_pem=video_chain.root_pem,
    )
    client_context = _configured_context(
        video_chain,
        video_profile,
        server_only=True,
    )
    _verify_chain(client_context, video_chain)

    client, server = _drive_memory_bio_handshake(
        client_context,
        _configured_certificate_server_context(video_chain),
    )

    assert client.get_peer_certificate() is not None
    assert server.get_peer_certificate() is None
    assert (
        SamsungServerProfile.bound_device(
            _OTHER_IDENTITY,
            role=SamsungServerRole.VD_DEVICE,
        )._verify_peer(None, video_chain.leaf, 0, 0, True)
        is False
    )
    assert (
        SamsungServerProfile.bound_device(_IDENTITY)._verify_peer(
            None,
            video_chain.leaf,
            0,
            0,
            True,
        )
        is False
    )


def test_python_floor_curve_fallback_has_the_same_wire_contract(
    monkeypatch,
    generated_chain,
):
    signature_setter = auth_module._util.lib.SSL_CTX_set1_sigalgs_list
    monkeypatch.setattr(
        auth_module,
        "_util",
        SimpleNamespace(
            lib=SimpleNamespace(
                SSL_CTX_set1_sigalgs_list=signature_setter,
            )
        ),
    )
    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=generated_chain.root_pem,
    )

    ciphers, extensions = _parse_client_hello(
        _first_client_hello(_configured_context(generated_chain, profile))
    )

    assert ciphers[0] == 0xC02B
    assert set(ciphers) <= {0xC02B, 0x00FF}
    assert _vector_values(extensions[10]) == [23]
    assert _vector_values(extensions[13]) == [
        0x0401,
        0x0403,
        0x0201,
        0x0203,
    ]
    assert 35 not in extensions


def test_profile_fails_closed_when_exact_openssl_support_is_unavailable(
    monkeypatch,
):
    class FallbackContext:
        _context = object()

        def set_tmp_ecdh(self, _curve):
            return None

    monkeypatch.setattr(
        auth_module,
        "_util",
        SimpleNamespace(lib=SimpleNamespace()),
    )
    profile = SamsungServerProfile.bound_device(_IDENTITY)

    with pytest.raises(RuntimeError, match="rejected"):
        profile._configure_context(FallbackContext())


def test_default_and_profile_verification_are_selected_per_provider(
    monkeypatch,
):
    valid_chain = _make_generated_chain(_IDENTITY)
    mismatch_chain = _make_generated_chain(_OTHER_IDENTITY)

    class RecordingContext:
        def __init__(self):
            self._context = object()
            self.calls = []
            self.verify_callback = None

        def load_verify_locations(self, path):
            self.calls.append(("load_verify_locations", path))

        def set_verify(self, mode, callback):
            self.calls.append(("set_verify", mode))
            self.verify_callback = callback

        def set_cipher_list(self, ciphers):
            self.calls.append(("set_cipher_list", ciphers))

        def use_certificate_chain_file(self, path):
            self.calls.append(("use_certificate_chain_file", path))

        def use_privatekey_file(self, path):
            self.calls.append(("use_privatekey_file", path))

        def check_privatekey(self):
            self.calls.append(("check_privatekey",))

        def set_options(self, options):
            self.calls.append(("set_options", options))

    profile_calls = []
    monkeypatch.setattr(
        auth_module,
        "_util",
        SimpleNamespace(
            lib=SimpleNamespace(
                SSL_CTX_set1_curves_list=(
                    lambda handle, value: (
                        profile_calls.append(("curves", handle, value)) or 1
                    )
                ),
                SSL_CTX_set1_sigalgs_list=(
                    lambda handle, value: (
                        profile_calls.append(("signature_algorithms", handle, value))
                        or 1
                    )
                ),
            )
        ),
    )

    default_context = RecordingContext()
    CertificateAuth.from_files("/synthetic/cert", "/synthetic/key").configure_context(
        default_context
    )
    assert default_context.verify_callback(None, None, 0, 0, True) is True
    assert default_context.verify_callback(None, None, 0, 0, False) is False
    assert not profile_calls
    assert all(call[0] != "set_options" for call in default_context.calls)

    profiled_context = RecordingContext()
    profile = SamsungServerProfile.bound_device(_IDENTITY)
    CertificateAuth.from_files(
        "/synthetic/cert",
        "/synthetic/key",
        server_profile=profile,
    ).configure_context(profiled_context)

    assert [call[0] for call in profile_calls] == [
        "curves",
        "signature_algorithms",
    ]
    assert ("set_options", SSL.OP_NO_TICKET) in profiled_context.calls
    callback = profiled_context.verify_callback
    assert callback(None, valid_chain.leaf, 0, 0, True) is True
    assert callback(None, mismatch_chain.leaf, 0, 0, True) is False
    assert callback(None, valid_chain.leaf, 0, 0, False) is False

    profile_calls.clear()
    video_chain = _make_generated_chain(
        _IDENTITY,
        organizational_unit="OCF VD Device",
    )
    server_only_context = RecordingContext()
    video_profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        role=SamsungServerRole.VD_DEVICE,
    )
    ServerCertificateAuth(server_profile=video_profile).configure_context(
        server_only_context
    )
    assert [call[0] for call in profile_calls] == [
        "curves",
        "signature_algorithms",
    ]
    assert all(
        call[0]
        not in {
            "use_certificate_chain_file",
            "use_privatekey_file",
            "check_privatekey",
        }
        for call in server_only_context.calls
    )
    assert (
        server_only_context.verify_callback(
            None,
            video_chain.leaf,
            0,
            0,
            True,
        )
        is True
    )
    assert (
        server_only_context.verify_callback(
            None,
            valid_chain.leaf,
            0,
            0,
            True,
        )
        is False
    )


def test_profile_identity_verification_rejects_malformed_subjects(caplog):
    profile = SamsungServerProfile.bound_device(_IDENTITY)
    discovery_profile = SamsungServerProfile.discover_device()
    wrong_role = _make_generated_chain(
        _IDENTITY,
        organizational_unit="Unexpected Device",
    )

    assert profile._verify_peer(None, wrong_role.leaf, 0, 0, True) is False
    assert profile._verify_peer(None, None, 0, 0, True) is False
    assert profile._verify_peer(None, wrong_role.leaf, 0, -1, True) is False
    assert profile._verify_peer(None, object(), 0, 1, True) is True

    duplicate_common_name = SimpleNamespace(
        get_subject=lambda: SimpleNamespace(
            get_components=lambda: [
                (b"CN", f"OCF Device: First ({_IDENTITY})".encode()),
                (b"CN", f"OCF Device: Other ({_IDENTITY})".encode()),
                (b"OU", b"OCF HA Device"),
                (b"O", b"Samsung Electronics"),
                (b"C", b"KR"),
            ]
        )
    )
    assert (
        profile._verify_peer(
            None,
            duplicate_common_name,
            0,
            0,
            True,
        )
        is False
    )

    invalid_encoding = SimpleNamespace(
        get_subject=lambda: SimpleNamespace(
            get_components=lambda: [(b"CN", b"\xff")]
        )
    )
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=auth_module.__name__):
        assert profile._verify_peer(None, object(), 0, 0, True) is False
        assert (
            discovery_profile._verify_peer(None, object(), 0, 0, True)
            is False
        )
        assert (
            profile._verify_peer(
                None,
                invalid_encoding,
                0,
                0,
                True,
            )
            is False
        )
    assert caplog.messages == [
        "Unable to parse Samsung server certificate subject",
        "Unable to parse Samsung server certificate subject",
        "Unable to parse Samsung server certificate subject",
    ]

    caplog.clear()
    assert profile._verify_peer(None, wrong_role.leaf, 0, 0, True) is False
    assert not caplog.records


def test_additional_ca_is_scoped_and_invalid_intermediate_is_rejected(
    generated_chain,
):
    default_context = _configured_context(generated_chain)
    with pytest.raises(crypto.X509StoreContextError):
        _verify_chain(default_context, generated_chain)

    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=generated_chain.root_pem,
    )
    profiled_context = _configured_context(generated_chain, profile)
    _verify_chain(profiled_context, generated_chain)

    missing_constraints = _make_generated_chain(
        _IDENTITY,
        intermediate_has_constraints=False,
    )
    missing_constraints_profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=missing_constraints.root_pem,
    )
    missing_constraints_context = _configured_context(
        missing_constraints,
        missing_constraints_profile,
    )
    with pytest.raises(crypto.X509StoreContextError):
        _verify_chain(missing_constraints_context, missing_constraints)


def test_profile_errors_and_provider_repr_do_not_echo_inputs(generated_chain):
    marker = "private" + "-profile-marker"
    with pytest.raises(ValueError) as captured:
        SamsungServerProfile.bound_device(marker)
    assert marker not in str(captured.value)

    profile = SamsungServerProfile.bound_device(
        _IDENTITY,
        additional_ca_pem=generated_chain.root_pem,
    )
    provider = CertificateAuth.from_memory(
        generated_chain.certificate_pem,
        generated_chain.private_key_pem,
        server_profile=profile,
    )
    rendered = repr(provider) + repr(profile)
    assert str(_IDENTITY) not in rendered
    assert generated_chain.root_pem not in rendered
    assert generated_chain.private_key_pem not in rendered
