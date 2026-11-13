"""The connection seam as supported API, and what it reports.

`_create_dtls_connection` was private, and both downstream consumers of it
said the same thing: a private hook tells an integration it has broken only
after a release. mbillow declined to ship LocalThings on it
(mbillow/localthings#504), and @fredrikbae declined to open a PR for a working
MFL fork for the same reason. So the seam is now
`DtlsConnectionProvider.create_dtls_connection`, returning a
`DtlsConnection`, and both are in the published contract.

The private name is still consulted, with a `FutureWarning`. A fork
running in production shipped against it, and breaking that in the release
that fixes the fragility would be a strange way to fix it.

Also covered here: the two things a caller needs once a fragment length is in
force. The negotiated limit is readable from the session, and a read that
drew nothing on its first block raises a distinct error rather than a bare
timeout.
"""

from __future__ import annotations

import pytest

from smartthings_local.errors import (
    FragmentLimitTimeoutError,
    SessionTimeoutError,
)
from smartthings_local.protocol.auth import (
    AuthenticationProvider,
    DtlsConnection,
    DtlsConnectionProvider,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession


class _Connection:
    """Every method the published `DtlsConnection` contract names."""

    def __init__(self, fragment_length=None):
        self.negotiated_fragment_length = fragment_length

    def bio_write(self, datagram):
        return len(datagram)

    def bio_read(self, capacity=65535):
        return b""

    def do_handshake(self):
        return None

    def send(self, data):
        return len(data)

    def recv(self, capacity=65535):
        return b""

    def shutdown(self):
        return None

    def DTLSv1_get_timeout(self):  # noqa: N802
        return None

    def DTLSv1_handle_timeout(self):  # noqa: N802
        return None


class _PublicProvider:
    """A provider on the supported seam."""

    def __init__(self, connection):
        self.connection = connection
        self.mtus = []

    def configure_context(self, context):
        return None

    def create_dtls_connection(self, *, mtu):
        self.mtus.append(mtu)
        return self.connection


class _LegacyProvider:
    """A provider shipped against the private hook, as one fork has."""

    def __init__(self, connection):
        self.connection = connection
        self.mtus = []

    def configure_context(self, context):
        return None

    def _create_dtls_connection(self, *, mtu):
        self.mtus.append(mtu)
        return self.connection


class _BothProvider(_PublicProvider):
    """A provider mid-migration, carrying each name."""

    def __init__(self, public, private):
        super().__init__(public)
        self.private = private

    def _create_dtls_connection(self, *, mtu):
        return self.private


def _session(auth, **kwargs):
    return DtlsCoapSession("192.0.2.10", 49154, auth=auth, **kwargs)


# -- the published types -------------------------------------------------


def test_the_engines_satisfy_the_published_connection_contract():
    from smartthings_local.protocol._dtls_cert import DtlsCertClient
    from smartthings_local.protocol._dtls_psk import DtlsPskClient

    for engine in (DtlsCertClient, DtlsPskClient):
        assert issubclass(engine, DtlsConnection), engine

    # And the local double, so a drift in the contract fails here rather than
    # only against a real engine.
    assert isinstance(_Connection(), DtlsConnection)


def test_a_connection_missing_one_verb_is_not_a_DtlsConnection():
    """Built standalone: subclassing _Connection would inherit the method."""

    class _Partial:
        def bio_write(self, datagram):
            return len(datagram)

        def bio_read(self, capacity=65535):
            return b""

        def do_handshake(self):
            return None

        def send(self, data):
            return len(data)

        def recv(self, capacity=65535):
            return b""

        def DTLSv1_get_timeout(self):  # noqa: N802
            return None

        def DTLSv1_handle_timeout(self):  # noqa: N802
            return None

    # shutdown is the one left out, and it is the verb that frees the
    # appliance's peer entry, so its absence matters more than most.
    assert not hasattr(_Partial(), "shutdown")
    assert not isinstance(_Partial(), DtlsConnection)


def test_our_providers_satisfy_the_published_provider_contract():
    from smartthings_local.protocol.auth import (
        FragmentingCertificateAuth,
        PskAuth,
    )

    for provider in (FragmentingCertificateAuth, PskAuth):
        assert issubclass(provider, DtlsConnectionProvider), provider


def test_a_provider_is_still_an_AuthenticationProvider():
    """The new contract includes configure_context on purpose.

    The session's isinstance gate stays meaningful, and the context path
    stays available, rather than the new seam becoming a way around both.
    """
    provider = _PublicProvider(_Connection())
    assert isinstance(provider, AuthenticationProvider)
    assert isinstance(provider, DtlsConnectionProvider)


def test_a_context_only_provider_is_not_a_connection_provider():
    class _ContextOnly:
        def configure_context(self, context):
            return None

    assert isinstance(_ContextOnly(), AuthenticationProvider)
    assert not isinstance(_ContextOnly(), DtlsConnectionProvider)


# -- dispatch ------------------------------------------------------------


def test_the_public_hook_is_used_and_gets_the_session_mtu():
    connection = _Connection()
    provider = _PublicProvider(connection)
    session = _session(provider, mtu=1300)
    assert session._new_dtls_connection(None) is connection
    assert provider.mtus == [1300]


def test_the_private_hook_still_works_and_warns():
    connection = _Connection()
    provider = _LegacyProvider(connection)
    session = _session(provider)
    with pytest.warns(FutureWarning, match="create_dtls_connection"):
        assert session._new_dtls_connection(None) is connection
    assert provider.mtus == [session.mtu]


def test_the_public_hook_wins_when_a_provider_carries_both():
    public, private = _Connection(), _Connection()
    provider = _BothProvider(public, private)
    session = _session(provider)
    assert session._new_dtls_connection(None) is public


def test_a_provider_with_neither_hook_still_builds_a_context():
    class _ContextOnly:
        def __init__(self):
            self.contexts = []

        def configure_context(self, context):
            self.contexts.append(context)

    provider = _ContextOnly()
    connection = _session(provider)._new_dtls_connection(None)
    assert connection is not None
    assert len(provider.contexts) == 1


def test_the_diagnostic_uses_the_public_hook_too():
    """The diagnostic has its own construction site, so it needs its own test.

    #120 put the factory ahead of the context path there deliberately: the
    order decides which engine sees the credential.
    """
    from smartthings_local.protocol import dtls_probe

    connection = _Connection()
    provider = _PublicProvider(connection)
    assert dtls_probe._diagnostic_connection(
        auth=provider, cert_pem=None, key_pem=None,
        cert_path=None, key_path=None, mtu=1200,
    ) is connection
    assert provider.mtus == [1200]


def test_the_diagnostic_still_honours_the_private_hook_and_warns():
    from smartthings_local.protocol import dtls_probe

    connection = _Connection()
    provider = _LegacyProvider(connection)
    with pytest.warns(FutureWarning, match="create_dtls_connection"):
        assert dtls_probe._diagnostic_connection(
            auth=provider, cert_pem=None, key_pem=None,
            cert_path=None, key_path=None, mtu=1200,
        ) is connection
