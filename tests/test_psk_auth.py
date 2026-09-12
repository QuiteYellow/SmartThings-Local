from __future__ import annotations

import gc
import traceback
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from OpenSSL import SSL

from smartthings_local.errors import SessionError
from smartthings_local.protocol import auth as auth_module
from smartthings_local.protocol import dtls_session as session_module
from smartthings_local.protocol.auth import PskAuth
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_IDENTITY = b"i" * 16
_KEY = b"k" * 16
_OTHER_IDENTITY = b"j" * 16
_OTHER_KEY = b"l" * 32


class _BytesSubclass(bytes):
    pass


def _fake_openssl_util(setter):
    return SimpleNamespace(
        ffi=auth_module._util.ffi,
        lib=SimpleNamespace(SSL_CTX_set_psk_client_callback=setter),
    )


def _invoke_callback(callback, identity_size: int, key_size: int):
    ffi = auth_module._util.ffi
    identity_buffer = ffi.new("char[]", max(identity_size, 1))
    key_buffer = ffi.new("unsigned char[]", max(key_size, 1))
    copied = callback(
        ffi.NULL,
        ffi.NULL,
        identity_buffer,
        identity_size,
        key_buffer,
        key_size,
    )
    return (
        copied,
        bytes(ffi.buffer(identity_buffer, max(identity_size, 1))),
        bytes(ffi.buffer(key_buffer, max(key_size, 1))),
    )


@pytest.mark.parametrize("key_length", [16, 32])
def test_psk_auth_accepts_exact_supported_credential_lengths(key_length):
    provider = PskAuth(identity=_IDENTITY, key=b"k" * key_length)

    assert repr(provider) == "PskAuth()"


@pytest.mark.parametrize(
    ("identity", "key"),
    [
        ("i" * 16, _KEY),
        (bytearray(_IDENTITY), _KEY),
        (memoryview(_IDENTITY), _KEY),
        (_BytesSubclass(_IDENTITY), _KEY),
        (_IDENTITY, "k" * 16),
        (_IDENTITY, bytearray(_KEY)),
        (_IDENTITY, memoryview(_KEY)),
        (_IDENTITY, _BytesSubclass(_KEY)),
    ],
)
def test_psk_auth_rejects_non_bytes_credentials(identity, key):
    with pytest.raises(TypeError, match="identity and key must be bytes"):
        PskAuth(identity=identity, key=key)


@pytest.mark.parametrize("identity_length", [0, 15, 17])
def test_psk_auth_rejects_invalid_identity_lengths(identity_length):
    with pytest.raises(ValueError, match="raw 16-byte OCF UUID"):
        PskAuth(identity=b"i" * identity_length, key=_KEY)


def test_psk_auth_rejects_identity_with_nul_byte():
    with pytest.raises(ValueError, match="cannot contain a NUL"):
        PskAuth(identity=b"i" * 15 + b"\x00", key=_KEY)


def test_nul_rejection_explains_the_truncation_it_prevents():
    # Measured against OpenSSL 4.0.0: a 16-byte identity with a NUL at byte 8
    # goes on the wire as 8 bytes and the handshake raises nothing locally, so
    # the guard is the only thing standing between a caller and a silently
    # wrong identity. The message has to carry that, because an appliance
    # answers the truncated value with unknown_psk_identity and nothing else
    # points back here.
    with pytest.raises(ValueError) as raised:
        PskAuth(identity=b"i" * 15 + b"\x00", key=_KEY)

    message = str(raised.value)
    assert "C string" in message
    assert "truncates" in message
    assert "shorter identity" in message


def test_validate_identity_checks_a_credential_before_one_is_assembled():
    # An import flow holds an identity before it has a provider to build, and
    # needs the reason to show a user, so the check is reachable on its own
    # and raises what the constructor raises.
    assert PskAuth.validate_identity(_IDENTITY) is None

    with pytest.raises(ValueError, match="cannot contain a NUL"):
        PskAuth.validate_identity(b"i" * 15 + b"\x00")


@pytest.mark.parametrize(
    "identity",
    [b"i" * 15 + b"\x00", b"i" * 15, b"i" * 17, b""],
)
def test_validate_identity_rejects_what_the_constructor_rejects(identity):
    # One code path, so the reason a caller can show a user is the same
    # reason the constructor would have raised.
    with pytest.raises(ValueError) as from_check:
        PskAuth.validate_identity(identity)
    with pytest.raises(ValueError) as from_constructor:
        PskAuth(identity=identity, key=_KEY)

    assert str(from_check.value) == str(from_constructor.value)


@pytest.mark.parametrize("identity", ["i" * 16, bytearray(_IDENTITY)])
def test_validate_identity_names_only_the_argument_it_takes(identity):
    # The constructor checks both credentials together, so its message names
    # both. This check takes no key and must not mention one.
    with pytest.raises(TypeError, match="^identity must be bytes$"):
        PskAuth.validate_identity(identity)
    with pytest.raises(TypeError, match="identity and key must be bytes"):
        PskAuth(identity=identity, key=_KEY)


@pytest.mark.parametrize("key_length", [0, 15, 17, 31, 33])
def test_psk_auth_rejects_invalid_key_lengths(key_length):
    with pytest.raises(ValueError, match="16 or 32 bytes"):
        PskAuth(identity=_IDENTITY, key=b"k" * key_length)


def test_psk_auth_is_immutable_and_has_no_public_credential_surface():
    provider = PskAuth(identity=_IDENTITY, key=_KEY)

    rendered = repr(provider)
    assert rendered == "PskAuth()"
    assert str(provider) == rendered
    assert _IDENTITY.decode() not in rendered
    assert _KEY.decode() not in rendered
    assert not hasattr(provider, "identity")
    assert not hasattr(provider, "key")
    assert not hasattr(provider, "_identity")
    assert not hasattr(provider, "_key")
    with pytest.raises(TypeError):
        vars(provider)
    with pytest.raises(TypeError):
        asdict(provider)
    with pytest.raises(AttributeError, match="immutable"):
        provider.identity = _OTHER_IDENTITY
    with pytest.raises(AttributeError, match="immutable"):
        del provider._callback


def test_psk_auth_identity_equality_does_not_compare_credentials():
    first = PskAuth(identity=_IDENTITY, key=_KEY)
    second = PskAuth(identity=_IDENTITY, key=_KEY)

    assert first != second
    assert len({first, second}) == 2


def test_psk_callback_copies_exact_identity_and_key():
    installed = {}

    def setter(context_handle, callback):
        installed["context"] = context_handle
        installed["callback"] = callback

    context_handle = object()
    context = MagicMock()
    context._context = context_handle
    provider = PskAuth(identity=_IDENTITY, key=_KEY)

    with patch.object(auth_module, "_util", _fake_openssl_util(setter)):
        provider.configure_context(context)

    assert installed["context"] is context_handle
    callback = installed["callback"]
    copied, identity_bytes, key_bytes = _invoke_callback(callback, 17, 16)
    assert copied == 16
    assert identity_bytes == _IDENTITY + b"\x00"
    assert key_bytes == _KEY
    context.set_cipher_list.assert_called_once_with(
        b"ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0"
    )
    context.load_verify_locations.assert_not_called()
    context.set_verify.assert_not_called()


@pytest.mark.parametrize(
    ("identity_size", "key_size"),
    [(16, 16), (17, 15)],
)
def test_psk_callback_rejects_short_buffers_without_partial_copy(
    identity_size,
    key_size,
):
    installed = {}
    provider = PskAuth(identity=_IDENTITY, key=_KEY)
    context = MagicMock()
    context._context = object()

    with patch.object(
        auth_module,
        "_util",
        _fake_openssl_util(
            lambda _context, callback: installed.setdefault(
                "callback", callback
            )
        ),
    ):
        provider.configure_context(context)

    ffi = auth_module._util.ffi
    identity_buffer = ffi.new("char[]", 17)
    key_buffer = ffi.new("unsigned char[]", 16)
    ffi.memmove(identity_buffer, b"I" * 17, 17)
    ffi.memmove(key_buffer, b"K" * 16, 16)
    copied = installed["callback"](
        ffi.NULL,
        ffi.NULL,
        identity_buffer,
        identity_size,
        key_buffer,
        key_size,
    )

    assert copied == 0
    assert bytes(ffi.buffer(identity_buffer, 17)) == b"I" * 17
    assert bytes(ffi.buffer(key_buffer, 16)) == b"K" * 16


@pytest.mark.parametrize("null_buffer", ["identity", "key"])
def test_psk_callback_rejects_null_buffers(null_buffer):
    installed = {}
    provider = PskAuth(identity=_IDENTITY, key=_KEY)
    context = MagicMock()
    context._context = object()

    with patch.object(
        auth_module,
        "_util",
        _fake_openssl_util(
            lambda _context, callback: installed.setdefault(
                "callback", callback
            )
        ),
    ):
        provider.configure_context(context)

    ffi = auth_module._util.ffi
    identity_buffer = ffi.new("char[]", 17)
    key_buffer = ffi.new("unsigned char[]", 16)
    ffi.memmove(identity_buffer, b"I" * 17, 17)
    ffi.memmove(key_buffer, b"K" * 16, 16)
    if null_buffer == "identity":
        identity_buffer = ffi.NULL
    else:
        key_buffer = ffi.NULL

    copied = installed["callback"](
        ffi.NULL,
        ffi.NULL,
        identity_buffer,
        17,
        key_buffer,
        16,
    )
    assert copied == 0
    if null_buffer == "identity":
        assert bytes(ffi.buffer(key_buffer, 16)) == b"K" * 16
    else:
        assert bytes(ffi.buffer(identity_buffer, 17)) == b"I" * 17


def test_psk_auth_unsupported_binding_error_contains_no_credentials():
    provider = PskAuth(identity=_IDENTITY, key=_KEY)
    context = MagicMock()
    context._context = object()
    unsupported_util = SimpleNamespace(
        ffi=auth_module._util.ffi,
        lib=SimpleNamespace(),
    )

    with (
        patch.object(auth_module, "_util", unsupported_util),
        pytest.raises(RuntimeError) as captured,
    ):
        provider.configure_context(context)

    rendered = (
        str(captured.value)
        + repr(captured.value)
        + "".join(traceback.format_exception(captured.value))
    )
    assert _IDENTITY.decode() not in rendered
    assert _KEY.decode() not in rendered
    context.set_cipher_list.assert_not_called()


def test_psk_auth_configures_real_openssl_context():
    context = SSL.Context(SSL.DTLS_METHOD)
    provider = PskAuth(identity=_IDENTITY, key=_KEY)

    assert provider.configure_context(context) is None


def test_distinct_psk_providers_do_not_share_callback_credentials():
    callbacks = []

    def setter(_context, callback):
        callbacks.append(callback)

    first = PskAuth(identity=_IDENTITY, key=_KEY)
    second = PskAuth(identity=_OTHER_IDENTITY, key=_OTHER_KEY)
    first_context = MagicMock()
    first_context._context = object()
    second_context = MagicMock()
    second_context._context = object()

    with patch.object(auth_module, "_util", _fake_openssl_util(setter)):
        first.configure_context(first_context)
        second.configure_context(second_context)

    assert callbacks[0] is not callbacks[1]
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(_invoke_callback, callbacks[0], 17, 16)
        second_future = executor.submit(
            _invoke_callback,
            callbacks[1],
            17,
            32,
        )
        first_result = first_future.result()
        second_result = second_future.result()
    assert first_result == (16, _IDENTITY + b"\x00", _KEY)
    assert second_result == (32, _OTHER_IDENTITY + b"\x00", _OTHER_KEY)


def test_session_retains_psk_callback_only_with_provider_lifetime():
    callback_reference = None

    def setter(_context, callback):
        nonlocal callback_reference
        callback_reference = weakref.ref(callback)

    provider = PskAuth(identity=_IDENTITY, key=_KEY)
    session = DtlsCoapSession(
        "appliance.invalid",
        49154,
        auth=provider,
    )
    context = MagicMock()
    context._context = object()
    with patch.object(auth_module, "_util", _fake_openssl_util(setter)):
        session.auth.configure_context(context)

    del provider
    gc.collect()
    assert callback_reference is not None
    assert callback_reference() is not None
    assert _invoke_callback(callback_reference(), 17, 16) == (
        16,
        _IDENTITY + b"\x00",
        _KEY,
    )

    del session
    gc.collect()
    assert callback_reference() is None


def test_session_accepts_psk_provider_without_legacy_certificate_material():
    provider = PskAuth(identity=_IDENTITY, key=_KEY)
    session = DtlsCoapSession("appliance.invalid", 49154, auth=provider)

    assert session.auth is provider
    assert session.cert_path is None
    assert session.key_path is None
    assert session.cert_pem is None
    assert session.key_pem is None


def test_psk_handshake_rejection_does_not_expose_credentials():
    provider = PskAuth(identity=_IDENTITY, key=_KEY)
    session = DtlsCoapSession("appliance.invalid", 49154, auth=provider)
    context = MagicMock()
    context._context = object()
    connection = MagicMock()
    connection.do_handshake.side_effect = SSL.Error()
    udp_socket = MagicMock()
    endpoint = SimpleNamespace(sockaddr=("192.0.2.100", 49154))

    with (
        patch.object(auth_module, "_util", _fake_openssl_util(lambda *_: None)),
        patch.object(session_module.SSL, "Context", return_value=context),
        patch.object(session_module.SSL, "Connection", return_value=connection),
        patch.object(
            session_module,
            "open_host_filtered_udp_socket",
            return_value=(udp_socket, endpoint),
        ),
        pytest.raises(SessionError) as captured,
    ):
        session.connect()

    rendered = (
        str(captured.value)
        + repr(captured.value)
        + "".join(traceback.format_exception(captured.value))
    )
    assert _IDENTITY.decode() not in rendered
    assert _KEY.decode() not in rendered
    udp_socket.close.assert_called_once_with()


# --- why the NUL guard exists, characterized against OpenSSL -------------

_PSK_CIPHER = b"ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0"
_CLIENT_CALLBACK_CDEF = (
    "unsigned int(*)(SSL *, const char *, char *, unsigned int, "
    "unsigned char *, unsigned int)"
)
_SERVER_CALLBACK_CDEF = (
    "unsigned int(*)(SSL *, const char *, unsigned char *, unsigned int)"
)


def _psk_identity_on_the_wire(identity):
    """Return the psk_identity length and bytes a real DTLS client sends.

    Both endpoints are OpenSSL over memory BIOs, relayed by hand so the
    client's records can be read. The ClientKeyExchange carrying
    psk_identity precedes ChangeCipherSpec, so it is in the clear.
    """
    ffi, lib = auth_module._util.ffi, auth_module._util.lib

    @ffi.callback(_CLIENT_CALLBACK_CDEF)
    def client_callback(_ssl, _hint, identity_buffer, max_identity_length,
                        key_buffer, max_key_length):
        # Byte for byte what PskAuth's own callback does, so this measures
        # OpenSSL rather than a straw man.
        if len(identity) + 1 > max_identity_length or len(_KEY) > max_key_length:
            return 0
        ffi.memmove(identity_buffer, identity + b"\x00", len(identity) + 1)
        ffi.memmove(key_buffer, _KEY, len(_KEY))
        return len(_KEY)

    @ffi.callback(_SERVER_CALLBACK_CDEF)
    def server_callback(_ssl, _identity, key_buffer, max_key_length):
        if len(_KEY) > max_key_length:
            return 0
        ffi.memmove(key_buffer, _KEY, len(_KEY))
        return len(_KEY)

    client_context = SSL.Context(SSL.DTLS_METHOD)
    client_context.set_cipher_list(_PSK_CIPHER)
    lib.SSL_CTX_set_psk_client_callback(
        client_context._context, client_callback
    )
    server_context = SSL.Context(SSL.DTLS_METHOD)
    server_context.set_cipher_list(_PSK_CIPHER)
    lib.SSL_CTX_set_psk_server_callback(
        server_context._context, server_callback
    )

    client = SSL.Connection(client_context, None)
    server = SSL.Connection(server_context, None)
    client.set_connect_state()
    server.set_accept_state()

    sent = bytearray()
    for _ in range(30):
        for source, destination, record in (
            (client, server, sent),
            (server, client, None),
        ):
            try:
                source.do_handshake()
            except (SSL.WantReadError, SSL.Error):
                pass
            try:
                data = source.bio_read(65536)
            except SSL.WantReadError:
                continue
            if record is not None:
                record += data
            destination.bio_write(data)

    stream = bytes(sent)
    offset = 0
    while offset + 13 <= len(stream):
        length = int.from_bytes(stream[offset + 11:offset + 13], "big")
        fragment = stream[offset + 13:offset + 13 + length]
        offset += 13 + length
        if len(fragment) >= 14 and fragment[0] == 16:   # ClientKeyExchange
            body = fragment[12:]
            declared = int.from_bytes(body[:2], "big")
            return declared, body[2:2 + declared]
    raise AssertionError("no ClientKeyExchange reached the wire")


def test_openssl_sends_a_clean_identity_whole():
    # The control: without a NUL, the full 16 bytes arrive.
    identity = bytes(range(1, 17))

    declared, wire = _psk_identity_on_the_wire(identity)

    assert declared == 16
    assert wire == identity


def test_a_nul_identity_would_reach_the_wire_truncated():
    # The reason PskAuth refuses this rather than passing it through.
    # OpenSSL's DTLS 1.2 PSK client callback returns the identity as a
    # C string and takes its strlen, so everything from the NUL onward is
    # dropped and nothing raises. An appliance would be asked to
    # authenticate an identity it has never held, and answer
    # unknown_psk_identity, with no local error pointing back here.
    #
    # If this test ever fails because the full 16 bytes arrive, OpenSSL has
    # gained a length-carrying path and the guard below can be revisited.
    identity = bytes(range(1, 9)) + b"\x00" + bytes(range(10, 17))

    declared, wire = _psk_identity_on_the_wire(identity)

    assert declared == 8
    assert wire == identity[:8]

    with pytest.raises(ValueError, match="cannot contain a NUL"):
        PskAuth(identity=identity, key=_KEY)
