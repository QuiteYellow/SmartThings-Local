"""The opt-in provider that puts a client certificate on our own DTLS engine.

`FragmentingCertificateAuth` exists for one extension. What these tests hold
down is that choosing it does not weaken anything: the chain is still verified
against the profile's own anchors, the profile's role and UUID rules still
decide, and a session with no profile verifies the chain and pins nothing,
as `CertificateAuth` does.

The synthetic three-level chain comes from `test_certificate_profiles.py`, so
the subject shape under test is the one the profile rules were written for.
"""
from uuid import UUID, uuid4

import pytest
from OpenSSL import SSL, crypto
from test_certificate_profiles import _make_generated_chain

from smartthings_local.protocol._dtls_cert import DtlsCertClient
from smartthings_local.protocol.auth import (
    FragmentingCertificateAuth,
    SamsungServerProfile,
    SamsungServerRole,
)

_IDENTITY = UUID("11111111-2222-3333-4444-555555555555")


@pytest.fixture(scope="module")
def chain():
    return _make_generated_chain(_IDENTITY)


def _profile(chain, identity=_IDENTITY, role=SamsungServerRole.HOME_APPLIANCE):
    return SamsungServerProfile(
        expected_certificate_identity=identity,
        role=role,
        additional_ca_pem=chain.root_pem,
    )


def _auth(chain, profile=None, **kwargs):
    return FragmentingCertificateAuth(
        server_profile=profile if profile is not None else _profile(chain),
        certificate_pem=chain.certificate_pem,
        private_key_pem=chain.private_key_pem,
        **kwargs,
    )


# -- the provider is fail-closed -----------------------------------------


def test_a_profile_is_optional_and_means_what_it_does_elsewhere(chain):
    """Optional, exactly as on CertificateAuth, and for the same reason.

    Without a profile the pyOpenSSL path verifies the chain against the
    bundled OCF root and pins nothing further; this provider does the same.
    Nothing per-appliance is required to use it: the client certificate's own
    subject UUID is a constant, and a profile pins the appliance's hardware
    leaf UUID, which is a different identity.
    """
    auth = FragmentingCertificateAuth(
        certificate_pem=chain.certificate_pem,
        private_key_pem=chain.private_key_pem,
    )
    assert auth.create_dtls_connection(mtu=1400)._mfl == 1024


def test_without_a_profile_the_chain_is_still_verified(chain):
    """The synthetic root is not the bundled OCF root, so this must refuse.

    This is the test that would have caught the design this replaced: the
    claim was that a profileless session verifies nothing, and the fix is that
    it verifies the chain.
    """
    auth = FragmentingCertificateAuth(
        certificate_pem=chain.certificate_pem,
        private_key_pem=chain.private_key_pem,
    )
    leaf = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.leaf)
    intermediate = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.intermediate)
    with pytest.raises(crypto.X509StoreContextError):
        auth._verify_peer_chain([leaf, intermediate])


def test_without_a_profile_there_is_no_server_identity(chain):
    """None, which is what CertificateAuth returns in the same case."""
    auth = FragmentingCertificateAuth(
        certificate_pem=chain.certificate_pem,
        private_key_pem=chain.private_key_pem,
    )
    connection = auth.create_dtls_connection(mtu=1400)
    connection._peer_chain = [
        crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.leaf)
    ]
    assert auth._authenticated_server_identity(connection) is None


@pytest.mark.parametrize("bad", ["profile", object(), 1])
def test_a_profile_that_is_not_one_is_refused(chain, bad):
    """None is allowed; anything else that is not a profile is not.

    The check is inherited from CertificateAuth, so this pins that the
    subclass did not loosen it.
    """
    with pytest.raises(TypeError, match="server_profile"):
        FragmentingCertificateAuth(
            server_profile=bad,
            certificate_pem=chain.certificate_pem,
            private_key_pem=chain.private_key_pem,
        )


def test_the_provider_is_immutable_and_redacted(chain):
    auth = _auth(chain)
    rendered = repr(auth)
    assert rendered == "FragmentingCertificateAuth()"
    assert "BEGIN CERTIFICATE" not in rendered
    assert "BEGIN PRIVATE KEY" not in rendered
    # Credential sources stay private, which is CertificateAuth's convention.
    assert not hasattr(auth, "certificate_pem")
    assert not hasattr(auth, "private_key_pem")
    assert not hasattr(auth, "max_fragment_length")
    with pytest.raises(TypeError):
        vars(auth)
    with pytest.raises(AttributeError, match="immutable"):
        auth._max_fragment_length = 1024
    with pytest.raises(AttributeError, match="immutable"):
        del auth._max_fragment_length


# -- the hook ------------------------------------------------------------


def test_the_hook_builds_our_engine_with_the_chosen_fragment_length(chain):
    auth = _auth(chain, max_fragment_length=1024)
    connection = auth.create_dtls_connection(mtu=1400)
    assert isinstance(connection, DtlsCertClient)
    assert connection._mfl == 1024
    assert connection._mtu == 1400
    # Our own chain reached the engine, leaf first.
    assert len(connection._chain_der) == 2


def test_the_hook_defaults_to_the_largest_workable_fragment_length(chain):
    # 1024, not 512: the ceiling is whatever leaves the appliance's flight
    # inside one frame, and the same figure caps every response it can send,
    # so a smaller default only costs reads. Measured by @fredrikbae on
    # mbillow/localthings#504.
    connection = _auth(chain).create_dtls_connection(mtu=1400)
    assert connection._mfl == 1024


def test_each_attempt_gets_a_fresh_connection(chain):
    auth = _auth(chain)
    first = auth.create_dtls_connection(mtu=1400)
    second = auth.create_dtls_connection(mtu=1400)
    assert first is not second


# -- trust ---------------------------------------------------------------


def test_the_profiles_chain_is_accepted(chain):
    auth = _auth(chain)
    leaf = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.leaf)
    intermediate = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.intermediate)
    auth._verify_peer_chain([leaf, intermediate])


def test_a_chain_outside_the_profiles_anchors_is_refused(chain):
    """With no additional CA the synthetic root is not trusted."""
    profile = SamsungServerProfile(expected_certificate_identity=_IDENTITY)
    auth = _auth(chain, profile=profile)
    leaf = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.leaf)
    intermediate = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.intermediate)
    with pytest.raises(crypto.X509StoreContextError):
        auth._verify_peer_chain([leaf, intermediate])


def test_a_pinned_identity_that_does_not_match_is_refused(chain):
    auth = _auth(chain, profile=_profile(chain, identity=uuid4()))
    leaf = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.leaf)
    intermediate = crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.intermediate)
    with pytest.raises(ValueError, match="server profile"):
        auth._verify_peer_chain([leaf, intermediate])


def test_the_wrong_role_is_refused(chain):
    """The profile pins the whole subject, and there is no role fallback."""
    vd = _make_generated_chain(_IDENTITY, organizational_unit="OCF VD Device")
    auth = _auth(
        chain,
        profile=SamsungServerProfile(
            expected_certificate_identity=_IDENTITY,
            role=SamsungServerRole.HOME_APPLIANCE,
            additional_ca_pem=vd.root_pem,
        ),
    )
    leaf = crypto.dump_certificate(crypto.FILETYPE_ASN1, vd.leaf)
    intermediate = crypto.dump_certificate(crypto.FILETYPE_ASN1, vd.intermediate)
    with pytest.raises(ValueError, match="server profile"):
        auth._verify_peer_chain([leaf, intermediate])


def test_an_empty_chain_is_refused(chain):
    with pytest.raises(ValueError, match="no certificate"):
        _auth(chain)._verify_peer_chain([])


# -- the verified identity -----------------------------------------------


def test_the_verified_identity_comes_from_the_engines_chain(chain):
    auth = _auth(chain)
    connection = auth.create_dtls_connection(mtu=1400)
    connection._peer_chain = [
        crypto.dump_certificate(crypto.FILETYPE_ASN1, chain.leaf)
    ]
    assert auth._authenticated_server_identity(connection) == _IDENTITY


def test_no_chain_means_no_identity_rather_than_a_guess(chain):
    auth = _auth(chain)
    connection = auth.create_dtls_connection(mtu=1400)
    with pytest.raises(ValueError, match="unavailable"):
        auth._authenticated_server_identity(connection)


# -- end to end ----------------------------------------------------------


def test_the_provider_completes_a_handshake_and_verifies_the_peer(chain):
    """The whole path: our engine, our credential, the profile's trust rules.

    OpenSSL plays the appliance, presenting the same synthetic leaf the profile
    is pinned to. A refusal anywhere in `_verify_peer_chain` stops the client
    flight, so completing the handshake is also evidence the chain verified.
    """
    auth = _auth(chain)
    client = auth.create_dtls_connection(mtu=1400)

    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(b"ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0")
    context.use_certificate(chain.leaf)
    context.add_extra_chain_cert(chain.intermediate)
    context.use_privatekey(
        crypto.load_privatekey(crypto.FILETYPE_PEM, chain.private_key_pem)
    )
    context.set_verify(SSL.VERIFY_PEER, lambda *_: True)
    server = SSL.Connection(context, None)
    server.set_accept_state()

    done = [False, False]
    for _turn in range(120):
        for index, sender, receiver in ((0, client, server), (1, server, client)):
            try:
                sender.do_handshake()
                done[index] = True
            except SSL.WantReadError:
                pass
            try:
                data = sender.bio_read(65535)
            except SSL.WantReadError:
                continue
            offset = 0
            while offset + 13 <= len(data):
                length = int.from_bytes(data[offset + 11:offset + 13], "big")
                receiver.bio_write(data[offset:offset + 13 + length])
                offset += 13 + length
        if all(done):
            break
    assert all(done), done
    assert client.negotiated_fragment_length == 1024
    assert auth._authenticated_server_identity(client) == _IDENTITY


def test_the_factories_carry_the_fragment_length_and_keep_the_profile_optional(
    chain,
):
    """Overridden only to carry max_fragment_length, which the parent lacks."""
    import inspect

    for factory in (
        FragmentingCertificateAuth.from_files,
        FragmentingCertificateAuth.from_memory,
    ):
        parameters = inspect.signature(factory).parameters
        profile = parameters["server_profile"]
        assert profile.kind is inspect.Parameter.KEYWORD_ONLY
        assert profile.default is None
        assert parameters["max_fragment_length"].default == 1024

    auth = FragmentingCertificateAuth.from_memory(
        chain.certificate_pem,
        chain.private_key_pem,
        server_profile=_profile(chain),
        max_fragment_length=1024,
    )
    assert auth.create_dtls_connection(mtu=1400)._mfl == 1024
