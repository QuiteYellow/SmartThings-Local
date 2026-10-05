"""One construction site per caller for a session's DTLS connection.

A provider may carry a private ``_create_dtls_connection`` factory and own
its own engine, which is how the pure-Python PSK client is reached without
an ``isinstance`` fork spreading through ``connect()``, the reader loop and
the diagnostic. The factory is deliberately not a verb on
``AuthenticationProvider``: that Protocol is ``runtime_checkable`` and
``DtlsCoapSession.__init__`` gates on ``isinstance``, so requiring a method
would reject every third-party provider that has not grown one.

These tests pin that the factory is honoured where a connection is built,
that a provider without one is unaffected, and that the ordering the
diagnostic depends on cannot be silently reversed.
"""

from __future__ import annotations

import pytest
from OpenSSL import SSL

from smartthings_local.errors import SessionClosedError
from smartthings_local.protocol import dtls_probe, dtls_session
from smartthings_local.protocol.auth import AuthenticationProvider
from smartthings_local.protocol.dtls_session import (
    ConnectCancellation,
    DtlsCoapSession,
)


class _ContextAuth:
    """A provider of the shape every third party already ships."""

    def __init__(self):
        self.contexts = []

    def configure_context(self, context):
        self.contexts.append(context)


class _EngineAuth:
    """A provider that brings its own connection, as PskAuth will."""

    def __init__(self, connection):
        self.connection = connection
        self.mtus = []
        self.contexts = []

    def configure_context(self, context):
        # Kept, so direct callers and the Protocol check both still work.
        self.contexts.append(context)

    def _create_dtls_connection(self, *, mtu):
        self.mtus.append(mtu)
        return self.connection


class _Connection:
    """The memory-BIO subset the handshake driver actually touches."""

    def __init__(self):
        self.handshakes = 0

    def do_handshake(self):
        self.handshakes += 1
        raise SSL.WantReadError()

    def bio_read(self, _size=65535):
        raise SSL.WantReadError()

    def bio_write(self, _datagram):
        return None

    def DTLSv1_get_timeout(self):  # noqa: N802 - mirrors pyOpenSSL
        return None

    def shutdown(self):
        return None


def _no_openssl(monkeypatch, module):
    """Fail loudly if a context or connection is built behind the factory."""
    monkeypatch.setattr(
        module.SSL,
        "Context",
        lambda *_a, **_k: pytest.fail("built an SSL.Context for an engine provider"),
    )
    monkeypatch.setattr(
        module.SSL,
        "Connection",
        lambda *_a, **_k: pytest.fail("built an SSL.Connection for an engine provider"),
    )


def test_engine_provider_is_still_an_authentication_provider():
    """The factory must not be what makes a provider acceptable."""
    assert isinstance(_EngineAuth(_Connection()), AuthenticationProvider)
    assert isinstance(_ContextAuth(), AuthenticationProvider)


def test_session_uses_the_provider_factory_and_builds_no_context(monkeypatch):
    connection = _Connection()
    auth = _EngineAuth(connection)
    session = DtlsCoapSession("device.example", 5684, auth=auth, mtu=900)
    _no_openssl(monkeypatch, dtls_session)
    monkeypatch.setattr(
        dtls_session,
        "open_host_filtered_udp_socket",
        lambda *_a, **_k: pytest.fail("reached the socket"),
    )

    assert session._new_dtls_connection(None) is connection
    assert auth.mtus == [900]
    assert auth.contexts == []


def test_session_without_a_factory_takes_the_context_path(monkeypatch):
    """The certificate path has to stay exactly where it was."""
    auth = _ContextAuth()
    session = DtlsCoapSession("device.example", 5684, auth=auth, mtu=1100)
    context = object()
    connection = _Connection()
    mtus = []
    monkeypatch.setattr(dtls_session.SSL, "Context", lambda *_a: context)
    monkeypatch.setattr(dtls_session.SSL, "Connection", lambda *_a: connection)
    monkeypatch.setattr(
        _Connection, "set_connect_state", lambda self: None, raising=False)
    monkeypatch.setattr(
        _Connection, "set_ciphertext_mtu", lambda self, mtu: mtus.append(mtu),
        raising=False)

    assert session._new_dtls_connection(None) is connection
    assert auth.contexts == [context]
    assert mtus == [1100]


def test_cancellation_after_the_factory_is_honoured():
    """A provider's own engine must not skip the cancellation window."""
    connection = _Connection()
    auth = _EngineAuth(connection)
    session = DtlsCoapSession("device.example", 5684, auth=auth)
    cancel = ConnectCancellation()

    def create(*, mtu):
        auth.mtus.append(mtu)
        cancel.set()
        return connection

    auth._create_dtls_connection = create
    with pytest.raises(SessionClosedError):
        session._new_dtls_connection(cancel)


def test_lifecycle_cancellation_after_the_factory_is_honoured():
    connection = _Connection()
    auth = _EngineAuth(connection)
    session = DtlsCoapSession("device.example", 5684, auth=auth)
    session._lifecycle_cancel.set()

    with pytest.raises(SessionClosedError):
        session._new_dtls_connection(None)


def test_diagnostic_uses_the_provider_factory(monkeypatch):
    """A credential that works in a session must not fail in the diagnostic.

    diagnose_dtls_handshake grew auth= so LocalThings could route a PSK
    entry through the same alert diagnosis (47e09b3). If the factory stopped
    here, that credential would reach the context path instead.
    """
    connection = _Connection()
    auth = _EngineAuth(connection)
    _no_openssl(monkeypatch, dtls_probe)

    built = dtls_probe._diagnostic_connection(
        auth=auth,
        cert_pem=None,
        key_pem=None,
        cert_path=None,
        key_path=None,
        mtu=1200,
    )
    assert built is connection
    assert auth.mtus == [1200]
    assert auth.contexts == []


def test_diagnostic_factory_is_asked_before_the_context_path(monkeypatch):
    """Ordering, not presence, is what routes the credential.

    _validate_diagnostic_auth only duck-checks configure_context, and an
    engine provider keeps that method, so it passes the gate either way.
    Asking the context path first would hand the credential to OpenSSL with
    nothing reporting the mistake.
    """
    auth = _EngineAuth(_Connection())
    assert callable(getattr(auth, "configure_context", None))
    dtls_probe._validate_diagnostic_auth(auth, None, None, None, None)

    calls = []
    monkeypatch.setattr(
        dtls_probe,
        "_diagnostic_context",
        lambda **_k: calls.append("context") or object(),
    )
    dtls_probe._diagnostic_connection(
        auth=auth,
        cert_pem=None,
        key_pem=None,
        cert_path=None,
        key_path=None,
        mtu=1200,
    )
    assert calls == []


def test_diagnostic_without_a_factory_still_builds_a_context(monkeypatch):
    auth = _ContextAuth()
    context = object()
    connection = _Connection()
    mtus = []
    monkeypatch.setattr(dtls_probe, "_diagnostic_context", lambda **_k: context)
    monkeypatch.setattr(dtls_probe.SSL, "Connection", lambda *_a: connection)
    monkeypatch.setattr(
        _Connection, "set_connect_state", lambda self: None, raising=False)
    monkeypatch.setattr(
        _Connection, "set_ciphertext_mtu", lambda self, mtu: mtus.append(mtu),
        raising=False)

    assert dtls_probe._diagnostic_connection(
        auth=auth,
        cert_pem=None,
        key_pem=None,
        cert_path=None,
        key_path=None,
        mtu=1200,
    ) is connection
    assert mtus == [1200]


def test_port_probe_flight_stays_on_openssl():
    """The credential-free ClientHello is not part of the seam.

    _client_hello_flight takes no provider: it is the stateless liveness
    probe, and a connection from a credential's engine would make it a
    handshake attempt against the appliance instead.
    """
    import inspect

    parameters = inspect.signature(dtls_probe._client_hello_flight).parameters
    assert set(parameters) == {"mtu"}


# -- one mtu rule, so a number cannot mean different things per provider ----


@pytest.mark.parametrize("mtu", [100, 575, 16385, 70000])
def test_out_of_range_mtu_is_refused_for_every_provider(mtu):
    """The divergence this closes: the session never validated mtu.

    DtlsPskClient requires 256-65535 and OpenSSL silently accepts anything,
    consulting it only when it has to fragment. So mtu=100 used to construct,
    then raise from connect() on a PSK provider while a certificate provider
    carried on. Now both are refused where the argument was supplied, under
    the range dtls_probe has validated since it was written.
    """
    for auth in (_ContextAuth(), _EngineAuth(_Connection())):
        with pytest.raises(ValueError, match="safe UDP range"):
            DtlsCoapSession("device.example", 5684, auth=auth, mtu=mtu)


@pytest.mark.parametrize("mtu", [576, 1200, 16384])
def test_in_range_mtu_is_accepted_for_every_provider(mtu):
    for auth in (_ContextAuth(), _EngineAuth(_Connection())):
        assert DtlsCoapSession(
            "device.example", 5684, auth=auth, mtu=mtu).mtu == mtu


@pytest.mark.parametrize("mtu", [True, 1200.0, "1200", None])
def test_mtu_must_be_an_integer(mtu):
    with pytest.raises(TypeError, match="mtu must be an integer"):
        DtlsCoapSession("device.example", 5684, auth=_ContextAuth(), mtu=mtu)


def test_the_session_and_the_probe_share_one_mtu_rule():
    """Two copies of a range drift. The probe's message is the shared one."""
    from smartthings_local.protocol.dtls_handshake import _validate_mtu

    for module_validator in (dtls_probe._validate_mtu,
                             dtls_session._validate_mtu):
        assert module_validator is _validate_mtu
