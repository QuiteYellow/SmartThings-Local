"""DTLS_FRAGMENT_LENGTH plumbing: env var -> SharedConfig -> the session.

The extension exists for appliances that drop off the network while sending
an over-MTU handshake flight (#20). Offering it needs the package's own
certificate engine, because no Python binding of OpenSSL can send it, so the
bridge has to be able to choose that engine.

Far more importantly, it has to keep defaulting to the pyOpenSSL path. The
appliances this bridge runs against complete a handshake without the
extension, and the engine has so far only met appliances that already worked.
"""
import types

import pytest

import mqtt_demo.bridge as bridge
from mqtt_demo.config import SharedConfig
from smartthings_local.protocol.auth import FragmentingCertificateAuth


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv('DTLS_FRAGMENT_LENGTH', raising=False)


class _StopAfterConstruction(Exception):
    pass


def _drive(monkeypatch, shared):
    """Construct one session and capture the credential kwargs."""
    captured = {}

    class _FakeSession:
        def __init__(self, host, port, **kw):
            captured.update(kw)

        def connect(self):
            raise _StopAfterConstruction()

    monkeypatch.setattr(bridge, 'DtlsCoapSession', _FakeSession)
    b = bridge.PushBridge.__new__(bridge.PushBridge)
    b.app = types.SimpleNamespace(ip='192.0.2.9', ocf_port=49155, index=0)
    b.shared = shared
    b.log = types.SimpleNamespace(
        debug=lambda *a, **k: None, info=lambda *a, **k: None,
        warning=lambda *a, **k: None, error=lambda *a, **k: None)
    b._on_notification = lambda *a: None
    b._on_observe_delivery = lambda *a: None
    b._resolve_port = lambda: 49155
    with pytest.raises(_StopAfterConstruction):
        b.session_once()
    return captured


def _shared(fragment_length):
    return types.SimpleNamespace(
        CERT_PATH='/tmp/cert.pem', KEY_PATH='/tmp/key.pem',
        WRITE_MAX_ATTEMPTS=1, DTLS_FRAGMENT_LENGTH=fragment_length)


def test_the_default_leaves_the_pyopenssl_path_alone():
    assert SharedConfig.from_env().DTLS_FRAGMENT_LENGTH == 0


def test_the_env_var_is_read(monkeypatch):
    monkeypatch.setenv('DTLS_FRAGMENT_LENGTH', '512')
    assert SharedConfig.from_env().DTLS_FRAGMENT_LENGTH == 512


@pytest.mark.parametrize("value", ['yes', '', '500', '511', '8192', '-512'])
def test_a_value_that_cannot_be_offered_stops_startup(monkeypatch, value):
    # Same contract as the other knobs: a typo stops the process rather than
    # silently reverting to a default nobody asked for. 500 parses and is
    # still a typo, because RFC 6066 offers four sizes and that is not one.
    monkeypatch.setenv('DTLS_FRAGMENT_LENGTH', value)
    with pytest.raises(ValueError):
        SharedConfig.from_env()


def test_zero_sends_certificate_paths_and_no_provider(monkeypatch):
    captured = _drive(monkeypatch, _shared(0))
    assert captured['cert_path'] == '/tmp/cert.pem'
    assert captured['key_path'] == '/tmp/key.pem'
    assert 'auth' not in captured


def test_a_fragment_length_sends_the_provider_and_no_paths(monkeypatch):
    captured = _drive(monkeypatch, _shared(512))
    assert 'cert_path' not in captured
    assert 'key_path' not in captured
    auth = captured['auth']
    assert isinstance(auth, FragmentingCertificateAuth)
    assert auth._max_fragment_length == 512


def test_the_chosen_length_is_carried_verbatim(monkeypatch):
    # Only the plumbing is asserted here. That the value reaches the engine
    # is test_fragmenting_certificate_auth's job, and building a connection
    # needs a real PEM on disk, which this test has no business minting.
    for length in (512, 1024, 2048, 4096):
        captured = _drive(monkeypatch, _shared(length))
        assert captured['auth']._max_fragment_length == length


def test_the_two_credential_forms_are_never_mixed(monkeypatch):
    # DtlsCoapSession raises when both are passed, so a bridge that sent
    # both would fail at connect rather than at review.
    for length in (0, 512):
        captured = _drive(monkeypatch, _shared(length))
        assert ('auth' in captured) != ('cert_path' in captured)
