import traceback

import pytest
from OpenSSL import SSL

from smartthings_local.errors import (
    AuthenticationError,
    AuthorizationError,
    BlockwiseError,
    EndpointError,
    MalformedMessageError,
    ObserveError,
    ProbeError,
    SessionClosedError,
    SessionError,
    SessionTimeoutError,
    SmartThingsLocalError,
)
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.dtls_session import DtlsCoapSession
from smartthings_local.protocol.endpoint import ResolvedUdpEndpoint

ERROR_TYPES = (
    EndpointError,
    ProbeError,
    SessionError,
    AuthenticationError,
    AuthorizationError,
    SessionTimeoutError,
    SessionClosedError,
    MalformedMessageError,
    BlockwiseError,
    ObserveError,
)


@pytest.mark.parametrize(
    ('error_type', 'legacy_type'),
    (
        (EndpointError, OSError),
        (ProbeError, ConnectionError),
        (SessionError, ConnectionError),
        (AuthenticationError, ConnectionError),
        (AuthorizationError, PermissionError),
        (SessionTimeoutError, TimeoutError),
        (SessionClosedError, ConnectionError),
        (MalformedMessageError, ValueError),
        (BlockwiseError, ConnectionError),
        (ObserveError, ConnectionError),
    ),
)
def test_errors_preserve_legacy_builtin_catches(error_type, legacy_type):
    error = error_type()
    assert isinstance(error, SmartThingsLocalError)
    assert isinstance(error, legacy_type)


@pytest.mark.parametrize('error_type', ERROR_TYPES)
def test_error_text_is_fixed_and_redacted(error_type):
    error = error_type()
    text = f'{error!s} {error!r}'
    assert error.code
    assert str(error) == error.message
    assert repr(error) == f'{error_type.__name__}(code={error.code!r})'
    assert 'device.example' not in text
    assert '/synthetic/client.key' not in text
    assert 'credential-value' not in text
    with pytest.raises(TypeError):
        error_type('credential-value')


def test_chained_backend_error_is_not_copied_into_public_text():
    backend = ConnectionError('DTLS backend failed')

    try:
        raise SessionError() from backend
    except SessionError as error:
        assert error.__cause__ is backend
        formatted = ''.join(traceback.format_exception(error))
        assert 'DTLS backend failed' in formatted
        assert 'device.example' not in formatted
        assert 'credential-value' not in formatted


def test_handshake_error_is_classified_without_backend_text(monkeypatch):
    class FakeContext:
        def load_verify_locations(self, *args):
            pass

        def set_verify(self, *args):
            pass

        def set_cipher_list(self, *args):
            pass

        def use_certificate_chain_file(self, *args):
            pass

        def use_privatekey_file(self, *args):
            pass

        def check_privatekey(self):
            pass

    class FakeConnection:
        def set_connect_state(self):
            pass

        def set_ciphertext_mtu(self, *args):
            pass

        def do_handshake(self):
            raise SSL.Error('credential-value at device.example')

    class FakeSocket:
        closed = False

        def settimeout(self, *args):
            pass

        def close(self):
            self.closed = True

    fake_socket = FakeSocket()
    monkeypatch.setattr(dtls_session.SSL, 'Context', lambda *args: FakeContext())
    monkeypatch.setattr(
        dtls_session.SSL, 'Connection', lambda *args: FakeConnection())
    endpoint = ResolvedUdpEndpoint(
        dtls_session.socket.AF_INET, ('192.0.2.10', 5684))
    monkeypatch.setattr(
        dtls_session,
        'open_connected_udp_socket',
        lambda *args, **kwargs: (fake_socket, endpoint),
    )

    session = DtlsCoapSession(
        'device.example', 5684,
        cert_path='/synthetic/client.pem',
        key_path='/synthetic/client.key',
    )
    with pytest.raises(SessionError) as exc:
        session.connect()

    assert fake_socket.closed
    assert isinstance(exc.value, ConnectionError)
    assert isinstance(exc.value.__cause__, ConnectionError)
    assert exc.value.__context__ is None
    formatted = ''.join(traceback.format_exception(exc.value))
    assert 'DTLS backend failed' in formatted
    assert 'device.example' not in formatted
    assert 'credential-value' not in formatted


@pytest.mark.parametrize(
    'operation',
    (
        lambda session: session.get(['resource']),
        lambda session: session.post(['resource'], b'payload'),
        lambda session: session.delete(['resource']),
        lambda session: session.ping(),
        lambda session: session.refresh_observes([]),
        lambda session: session.subscribe(['resource']),
    ),
)
def test_closed_session_operations_raise_classified_error(operation):
    session = DtlsCoapSession(
        'device.example', 5684,
        cert_path='/synthetic/client.pem',
        key_path='/synthetic/client.key',
    )

    with pytest.raises(SessionClosedError):
        operation(session)
