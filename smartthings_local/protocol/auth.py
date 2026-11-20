"""Immutable authentication providers for DTLS sessions."""

from __future__ import annotations

import logging
import re
import warnings
from enum import Enum
from os import PathLike
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from OpenSSL import SSL, _util, crypto

from ._dtls_cert import DtlsCertClient, _validate_max_fragment_length
from ._dtls_psk import DtlsPskClient

logger = logging.getLogger(__name__)

_OCF_ROOT_CA = str(Path(__file__).with_name("ocf_root_ca.pem"))
_DTLS_CIPHERS = b"ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0"
_DTLS_PSK_CIPHERS = b"ECDHE-PSK-AES128-CBC-SHA256:@SECLEVEL=0"
_SAMSUNG_SERVER_CURVES = b"prime256v1"
_SAMSUNG_SERVER_SIGNATURE_ALGORITHMS = (
    b"RSA+SHA256:ECDSA+SHA256:RSA+SHA1:ECDSA+SHA1"
)
_SAMSUNG_SERVER_CN_RE = re.compile(
    r"\AOCF Device: [^()\r\n]{1,96} "
    r"\((?P<device_identity>[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)\Z",
    re.IGNORECASE,
)
_PSK_CLIENT_CALLBACK_CDEF = (
    "unsigned int (*)(SSL *, char *, char *, unsigned int, "
    "unsigned char *, unsigned int)"
)
_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _verify_peer(_connection, _certificate, _error, _depth, ok):
    """Keep pyOpenSSL's existing verification result unchanged."""
    return ok


def _load_pem_chain(ctx: SSL.Context, cert_pem: str, key_pem: str) -> None:
    """Load a PEM certificate chain and private key into a context in memory."""
    certificates = _PEM_CERT_RE.findall(cert_pem.encode())
    if not certificates:
        raise ValueError("No certificates found in cert_pem")
    ctx.use_certificate(
        crypto.load_certificate(crypto.FILETYPE_PEM, certificates[0])
    )
    for extra in certificates[1:]:
        ctx.add_extra_chain_cert(
            crypto.load_certificate(crypto.FILETYPE_PEM, extra)
        )
    ctx.use_privatekey(
        crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem.encode())
    )
    ctx.check_privatekey()


@runtime_checkable
class AuthenticationProvider(Protocol):
    """Configure authentication for a newly created DTLS context."""

    def configure_context(self, context: SSL.Context) -> None:
        """Configure a context while this provider remains session-owned."""


_LEGACY_CONNECTION_HOOK = "_create_dtls_connection"


def _connection_factory(auth):
    """Return a provider's connection factory, or None.

    Prefers the supported :meth:`DtlsConnectionProvider.create_dtls_connection`
    and falls back to the private name this package used before it, with a
    ``FutureWarning``. That category, unlike ``DeprecationWarning``, is shown
    by the default filters whatever frame it is attributed to, and the frame
    here is package code. The default filters also show it once per call
    site, not once per provider class. The fallback exists because a downstream
    integration shipped against the private hook and runs in production; that
    is exactly the fragility making it public is meant to end, so breaking it
    in the same release would be a strange way to fix it.
    """
    factory = getattr(auth, "create_dtls_connection", None)
    if factory is not None:
        return factory
    legacy = getattr(auth, _LEGACY_CONNECTION_HOOK, None)
    if legacy is None:
        return None
    warnings.warn(
        f"{type(auth).__name__} supplies {_LEGACY_CONNECTION_HOOK}, which was "
        "never supported API. Rename it to create_dtls_connection and declare "
        "DtlsConnectionProvider; the private name will stop being consulted.",
        FutureWarning,
        stacklevel=3,
    )
    return legacy


@runtime_checkable
class DtlsConnection(Protocol):
    """The connection surface this package drives, as a supported contract.

    A provider that supplies its own engine returns something shaped like
    this. The eight methods are the whole surface: `dtls_handshake` drives
    `bio_write`, `bio_read`, `do_handshake` and the two timeout verbs,
    `DtlsCoapSession` adds `send` and `recv`, and both the session and the
    diagnostic call `shutdown` to release the appliance's peer entry.

    `set_connect_state` and `set_ciphertext_mtu` are deliberately absent. They
    belong to the context path, and a factory returns a connection already in
    client state with its MTU applied, so there is nothing left for a caller
    to set.

    The two `DTLSv1_` names carry pyOpenSSL's capitalisation because the same
    handshake driver drives pyOpenSSL and this package's own engines, and one
    driver cannot hold two spellings. Renaming them would be a breaking change
    for no behaviour.

    Required behaviour, which the type cannot express:

    - `bio_read` raises `WantRead` when no datagram is pending, rather than
      returning empty bytes.
    - `do_handshake` raises `WantRead` until the handshake completes.
    - `recv` returns buffered application data before reporting a failure or a
      close, and raises `ZeroReturn` on an orderly close.
    - The connection owns no socket and starts no network I/O. The caller owns
      the socket, the deadline, cancellation and publishing the session.
    """

    def bio_write(self, datagram: bytes) -> int:
        """Hand one inbound datagram to the engine."""

    def bio_read(self, capacity: int = 65535) -> bytes:
        """Return pending outbound bytes, or raise `WantRead`."""

    def do_handshake(self) -> None:
        """Advance the handshake, raising `WantRead` until it completes."""

    def send(self, data: bytes) -> int:
        """Encrypt and queue one application record."""

    def recv(self, capacity: int = 65535) -> bytes:
        """Return one decrypted application record."""

    def shutdown(self) -> None:
        """Queue a close_notify, which frees the appliance's peer entry."""

    def DTLSv1_get_timeout(self):  # noqa: N802 - see the class docstring
        """Seconds until the current flight should be retransmitted."""

    def DTLSv1_handle_timeout(self):  # noqa: N802 - see the class docstring
        """Requeue the current flight and back off."""


@runtime_checkable
class DtlsConnectionProvider(Protocol):
    """An :class:`AuthenticationProvider` that also builds its own connection.

    Supported public API. A credential whose carrier is not pyOpenSSL answers
    `create_dtls_connection`, and `DtlsCoapSession` and
    `diagnose_dtls_handshake` use it in place of building a context. This is
    the interface #120 left open when it put the construction behind one
    private hook per caller, and both consumers of that hook asked for it to
    become supported rather than private: a private name tells a downstream
    integration it has broken only after a release.

    `configure_context` stays in the contract, so a provider still satisfies
    :class:`AuthenticationProvider` and the context path remains available to
    a caller that wants it. That also keeps the session's existing `isinstance`
    gate meaningful rather than something to be worked around.

    A provider is free to implement this and nothing in this package requires
    it, so a third-party :class:`AuthenticationProvider` that has not grown the
    method is unaffected.
    """

    def configure_context(self, context: SSL.Context) -> None:
        """Configure a context while this provider remains session-owned."""

    def create_dtls_connection(self, *, mtu: int) -> DtlsConnection:
        """Return a fresh connection for one attempt, in client state."""


class SamsungServerRole(Enum):
    """Known Samsung OCF hardware-certificate subject roles."""

    HOME_APPLIANCE = "OCF HA Device"
    VD_DEVICE = "OCF VD Device"


class SamsungServerProfile:
    """Opt-in Samsung hardware-certificate verification profile."""

    __slots__ = (
        "_additional_ca_certificates",
        "_expected_certificate_identity",
        "_role",
    )

    def __init__(
        self,
        *,
        expected_certificate_identity: UUID | str,
        role: SamsungServerRole = SamsungServerRole.HOME_APPLIANCE,
        additional_ca_pem: str | None = None,
    ) -> None:
        parsed_identity = self._parse_expected_identity(
            expected_certificate_identity
        )
        self._initialize(
            expected_certificate_identity=parsed_identity,
            role=role,
            additional_ca_pem=additional_ca_pem,
        )

    @staticmethod
    def _parse_expected_identity(
        expected_certificate_identity: UUID | str,
    ) -> UUID:
        if type(expected_certificate_identity) is UUID:
            parsed_identity = expected_certificate_identity
        elif type(expected_certificate_identity) is str:
            try:
                parsed_identity = UUID(expected_certificate_identity)
            except ValueError:
                raise ValueError(
                    "expected_certificate_identity must be a canonical "
                    "non-zero UUID"
                ) from None
            if expected_certificate_identity != str(parsed_identity):
                raise ValueError(
                    "expected_certificate_identity must be a canonical "
                    "non-zero UUID"
                )
        else:
            raise TypeError(
                "expected_certificate_identity must be a UUID or string"
            )
        if parsed_identity.int == 0:
            raise ValueError(
                "expected_certificate_identity must be a canonical "
                "non-zero UUID"
            )
        return parsed_identity

    def _initialize(
        self,
        *,
        expected_certificate_identity: UUID | None,
        role: SamsungServerRole,
        additional_ca_pem: str | None,
    ) -> None:
        if type(role) is not SamsungServerRole:
            raise TypeError("role must be a SamsungServerRole")

        certificates: tuple[bytes, ...] = ()
        if additional_ca_pem is not None:
            if type(additional_ca_pem) is not str:
                raise TypeError("additional_ca_pem must be a string")
            try:
                raw_ca_pem = additional_ca_pem.encode("ascii")
            except UnicodeEncodeError:
                raise ValueError(
                    "additional_ca_pem must contain ASCII PEM certificates"
                ) from None
            parsed_certificates = tuple(_PEM_CERT_RE.findall(raw_ca_pem))
            if (
                not 1 <= len(parsed_certificates) <= 4
                or len(raw_ca_pem) > 32 * 1024
                or _PEM_CERT_RE.sub(b"", raw_ca_pem).strip()
            ):
                raise ValueError(
                    "additional_ca_pem must contain one to four PEM certificates"
                )
            try:
                loaded_certificates = [
                    crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
                    for certificate in parsed_certificates
                ]
                basic_constraints = [
                    [
                        extension
                        for extension in certificate.to_cryptography().extensions
                        if extension.oid == ExtensionOID.BASIC_CONSTRAINTS
                    ]
                    for certificate in loaded_certificates
                ]
            except (crypto.Error, ValueError):
                raise ValueError(
                    "additional_ca_pem contains an invalid certificate"
                ) from None
            if any(
                len(constraints) != 1 or not constraints[0].value.ca
                for constraints in basic_constraints
            ):
                raise ValueError(
                    "additional_ca_pem must contain only CA certificates"
                )
            fingerprints = {
                crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
                for certificate in loaded_certificates
            }
            if len(fingerprints) != len(loaded_certificates):
                raise ValueError(
                    "additional_ca_pem must not contain duplicate certificates"
                )
            certificates = parsed_certificates

        object.__setattr__(
            self,
            "_expected_certificate_identity",
            expected_certificate_identity,
        )
        object.__setattr__(self, "_role", role)
        object.__setattr__(self, "_additional_ca_certificates", certificates)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("SamsungServerProfile is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("SamsungServerProfile is immutable")

    @classmethod
    def bound_device(
        cls,
        expected_certificate_identity: UUID | str,
        *,
        role: SamsungServerRole = SamsungServerRole.HOME_APPLIANCE,
        additional_ca_pem: str | None = None,
    ) -> SamsungServerProfile:
        """Bind a verified Samsung hardware leaf to its certificate UUID."""
        return cls(
            expected_certificate_identity=expected_certificate_identity,
            role=role,
            additional_ca_pem=additional_ca_pem,
        )

    @classmethod
    def discover_device(
        cls,
        *,
        role: SamsungServerRole = SamsungServerRole.HOME_APPLIANCE,
        additional_ca_pem: str | None = None,
    ) -> SamsungServerProfile:
        """Verify a Samsung hardware leaf before learning its certificate UUID.

        This profile is intended only for an explicit first-use workflow. The
        caller must bind the returned session identity to independently
        authenticated device evidence before persisting it.
        """
        profile = object.__new__(cls)
        profile._initialize(
            expected_certificate_identity=None,
            role=role,
            additional_ca_pem=additional_ca_pem,
        )
        return profile

    def __repr__(self) -> str:
        """Return a representation without device or trust-chain details."""
        return "SamsungServerProfile()"

    def _configure_context(self, context: SSL.Context) -> None:
        curve_setter = getattr(_util.lib, "SSL_CTX_set1_curves_list", None)
        if curve_setter is not None:
            if curve_setter(context._context, _SAMSUNG_SERVER_CURVES) != 1:
                raise RuntimeError(
                    "OpenSSL rejected the Samsung server certificate profile"
                )
        else:
            # pyOpenSSL 23.1 does not expose SSL_CTX_set1_curves_list. Its
            # public set_tmp_ecdh fallback produces the same single P-256
            # supported-groups ClientHello extension; wire-level tests protect
            # that compatibility path. Newer pyOpenSSL uses the exact setter.
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    curve = crypto.get_elliptic_curve("prime256v1")
                    context.set_tmp_ecdh(curve)
            except (AttributeError, TypeError, ValueError, SSL.Error):
                raise RuntimeError(
                    "OpenSSL rejected the Samsung server certificate profile"
                ) from None

        signature_setter = getattr(
            _util.lib,
            "SSL_CTX_set1_sigalgs_list",
            None,
        )
        if (
            signature_setter is None
            or signature_setter(
                context._context,
                _SAMSUNG_SERVER_SIGNATURE_ALGORITHMS,
            )
            != 1
        ):
            raise RuntimeError(
                "OpenSSL rejected the Samsung server certificate profile"
            )
        context.set_options(SSL.OP_NO_TICKET)

        if self._additional_ca_certificates:
            store = context.get_cert_store()
            try:
                for certificate in self._additional_ca_certificates:
                    store.add_cert(
                        crypto.load_certificate(
                            crypto.FILETYPE_PEM,
                            certificate,
                        )
                    )
            except crypto.Error:
                raise RuntimeError(
                    "OpenSSL rejected the Samsung server trust profile"
                ) from None

    def _verify_peer(
        self,
        _connection,
        certificate,
        _error,
        depth,
        ok,
    ) -> bool:
        if not ok or certificate is None or depth < 0:
            return False
        if depth > 0:
            return True
        identity = self._certificate_identity(certificate)
        return identity is not None and (
            self._expected_certificate_identity is None
            or identity == self._expected_certificate_identity
        )

    def _certificate_identity(self, certificate) -> UUID | None:
        """Extract a UUID only from the selected Samsung subject role."""
        try:
            with warnings.catch_warnings():
                # pyOpenSSL deprecates this API in favor of cryptography, but
                # reparsing Samsung's non-DER factory leaves with cryptography
                # rejects certificates that OpenSSL has already verified.
                warnings.simplefilter("ignore", DeprecationWarning)
                components = [
                    (name.decode("ascii"), value.decode("ascii"))
                    for name, value in certificate.get_subject().get_components()
                ]
        except (
            AttributeError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            crypto.Error,
        ):
            logger.warning("Unable to parse Samsung server certificate subject")
            return None

        common_names = [value for name, value in components if name == "CN"]
        organizational_units = [
            value for name, value in components if name == "OU"
        ]
        organizations = [value for name, value in components if name == "O"]
        countries = [value for name, value in components if name == "C"]
        # This deliberately pins the complete Samsung subject role. The OCF
        # reference implementation reads only the UUID-bearing CN, but
        # relaxing C/O/OU here could accept a different certificate cohort.
        if (
            len(common_names) != 1
            or organizational_units != [self._role.value]
            or organizations != ["Samsung Electronics"]
            or countries != ["KR"]
        ):
            return None
        match = _SAMSUNG_SERVER_CN_RE.fullmatch(common_names[0])
        if match is None:
            return None
        identity = UUID(match.group("device_identity"))
        return identity if identity.int != 0 else None


def _configure_certificate_server(
    context: SSL.Context,
    server_profile: SamsungServerProfile | None,
) -> None:
    """Configure certificate-server verification for one DTLS context."""
    context.load_verify_locations(_OCF_ROOT_CA)
    if server_profile is None:
        context.set_verify(SSL.VERIFY_PEER, _verify_peer)
    else:
        server_profile._configure_context(context)
        context.set_verify(
            SSL.VERIFY_PEER,
            server_profile._verify_peer,
        )
    # @SECLEVEL=0 permits SHA-1 in Samsung's server cert chain (AC14K_M
    # intermediate is SHA-1 signed). This is the only channel that reaches
    # the OpenSSL instance cryptography bundles; ctypes and cffi bindings
    # do not expose SSL_CTX_set_security_level on this build.
    context.set_cipher_list(_DTLS_CIPHERS)


class ServerCertificateAuth:
    """Verify a pinned Samsung server without a client certificate."""

    __slots__ = ("_server_profile",)

    def __init__(self, *, server_profile: SamsungServerProfile) -> None:
        if type(server_profile) is not SamsungServerProfile:
            raise TypeError("server_profile must be a SamsungServerProfile")
        object.__setattr__(self, "_server_profile", server_profile)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("ServerCertificateAuth is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("ServerCertificateAuth is immutable")

    def __repr__(self) -> str:
        """Return a representation without server identity or trust details."""
        return "ServerCertificateAuth()"

    def configure_context(self, context: SSL.Context) -> None:
        """Verify the selected server profile without loading client material."""
        _configure_certificate_server(context, self._server_profile)

    def _authenticated_server_identity(self, connection) -> UUID | None:
        certificate = connection.get_peer_certificate()
        identity = self._server_profile._certificate_identity(certificate)
        if identity is None:
            raise ValueError("verified server identity was unavailable")
        return identity


class CertificateAuth:
    """Certificate authentication loaded from files or in-memory PEM data.

    Use :meth:`from_files` or :meth:`from_memory` to create an instance.
    Credential sources are intentionally not exposed as public attributes.
    """

    __slots__ = (
        "_certificate_path",
        "_certificate_pem",
        "_private_key_path",
        "_private_key_pem",
        "_server_profile",
    )

    def __init__(
        self,
        *,
        certificate_path: str | PathLike[str] | None = None,
        private_key_path: str | PathLike[str] | None = None,
        certificate_pem: str | None = None,
        private_key_pem: str | None = None,
        server_profile: SamsungServerProfile | None = None,
    ) -> None:
        file_supplied = (
            certificate_path is not None or private_key_path is not None
        )
        memory_supplied = (
            certificate_pem is not None or private_key_pem is not None
        )
        if file_supplied and memory_supplied:
            raise ValueError(
                "pass either certificate_path/private_key_path or "
                "certificate_pem/private_key_pem, not both"
            )
        if file_supplied:
            if certificate_path is None or private_key_path is None:
                raise ValueError(
                    "certificate_path and private_key_path must be passed together"
                )
        elif memory_supplied:
            if certificate_pem is None or private_key_pem is None:
                raise ValueError(
                    "certificate_pem and private_key_pem must be passed together"
                )
        else:
            raise ValueError(
                "must pass either certificate_path/private_key_path or "
                "certificate_pem/private_key_pem"
            )
        if (
            server_profile is not None
            and type(server_profile) is not SamsungServerProfile
        ):
            raise TypeError("server_profile must be a SamsungServerProfile")
        object.__setattr__(
            self,
            "_certificate_path",
            str(certificate_path) if certificate_path is not None else None,
        )
        object.__setattr__(
            self,
            "_private_key_path",
            str(private_key_path) if private_key_path is not None else None,
        )
        object.__setattr__(self, "_certificate_pem", certificate_pem)
        object.__setattr__(self, "_private_key_pem", private_key_pem)
        object.__setattr__(self, "_server_profile", server_profile)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("CertificateAuth is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("CertificateAuth is immutable")

    @classmethod
    def from_files(
        cls,
        certificate_path: str | PathLike[str],
        private_key_path: str | PathLike[str],
        *,
        server_profile: SamsungServerProfile | None = None,
    ) -> CertificateAuth:
        """Create a provider backed by certificate-chain and key files."""
        return cls(
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            server_profile=server_profile,
        )

    @classmethod
    def from_memory(
        cls,
        certificate_pem: str,
        private_key_pem: str,
        *,
        server_profile: SamsungServerProfile | None = None,
    ) -> CertificateAuth:
        """Create a provider backed by an in-memory PEM chain and key."""
        return cls(
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            server_profile=server_profile,
        )

    def __repr__(self) -> str:
        """Return a representation that never includes credential material."""
        return "CertificateAuth()"

    def configure_context(self, context: SSL.Context) -> None:
        """Apply the existing certificate authentication profile to a context."""
        _configure_certificate_server(context, self._server_profile)
        if self._certificate_pem is not None:
            _load_pem_chain(
                context,
                self._certificate_pem,
                self._private_key_pem,
            )
        else:
            context.use_certificate_chain_file(self._certificate_path)
            context.use_privatekey_file(self._private_key_path)
            context.check_privatekey()

    def _authenticated_server_identity(self, connection) -> UUID | None:
        if self._server_profile is None:
            return None
        certificate = connection.get_peer_certificate()
        identity = self._server_profile._certificate_identity(certificate)
        if identity is None:
            raise ValueError("verified server identity was unavailable")
        return identity


def _set_server_purpose(store) -> None:
    """Verify `store`'s chains for the SSL-server purpose, or raise.

    The binding is looked up, as the curve setter's is, so a `cryptography`
    build without it raises a RuntimeError that names the cause.
    """
    set_purpose = getattr(_util.lib, "X509_STORE_set_purpose", None)
    purpose = getattr(_util.lib, "X509_PURPOSE_SSL_SERVER", None)
    if set_purpose is None or purpose is None:
        raise RuntimeError(
            "this OpenSSL binding cannot set the server certificate purpose"
        )
    if set_purpose(store._store, purpose) != 1:
        raise RuntimeError("OpenSSL rejected the server certificate purpose")


class FragmentingCertificateAuth(CertificateAuth):
    """Client-certificate authentication on this package's own DTLS engine.

    Same credentials, same server profile, same trust rules as
    :class:`CertificateAuth`. The difference is the carrier: the handshake runs
    on `_dtls_cert.DtlsCertClient` rather than pyOpenSSL, so the ClientHello
    can offer `max_fragment_length`.

    That extension is the only reason to choose this provider. The washer and
    dryer on issue #20 leave the network for about ten seconds whenever they
    have to put a handshake flight on the wire that will not fit one frame, and
    theirs will not. Measured on both units on 2026-10-25: four of four
    probes without the extension took the unit off the network, and both
    probes with it drew the appliance's whole flight and dropped nothing.
    pyOpenSSL cannot send it, and neither can any other Python binding of
    OpenSSL, because `cryptography` exposes no
    `SSL_CTX_set_tlsext_max_fragment_length` and no `SSL_CTX_ctrl` to reach the
    macro through.

    `server_profile` is optional, exactly as on :class:`CertificateAuth`, and
    means the same thing on both. Without one, the peer's chain is verified
    against the bundled OCF root and nothing further is pinned, which is what
    the pyOpenSSL path does when its context carries no profile. With one, the
    profile's role, subject and UUID checks apply on top.

    Nothing per-appliance is needed either way. The client certificate's own
    subject UUID is a constant that does not rotate (`setup_cert.py`), and a
    profile pins the *appliance's* hardware leaf UUID, which is a different
    identity and differs between units, so it belongs to a caller that has one
    to pin rather than to this constructor.

    Nothing in this package selects this provider. A caller opts in, which is
    deliberate. On 2026-10-26 the engine completed handshakes on a Samsung
    dryer and oven, with and without a fragment length. Both of those
    appliances already work on pyOpenSSL, so the units that stall, which are
    the reason for this provider, are still untested with it.
    """

    __slots__ = ("_max_fragment_length",)

    def __init__(
        self,
        *,
        server_profile: SamsungServerProfile | None = None,
        max_fragment_length: int = 1024,
        certificate_path: str | PathLike[str] | None = None,
        private_key_path: str | PathLike[str] | None = None,
        certificate_pem: str | None = None,
        private_key_pem: str | None = None,
    ) -> None:
        super().__init__(
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            server_profile=server_profile,
        )
        # The engine's own rule, applied here so that a bad value raises at
        # this call and not at the first connect.
        _validate_max_fragment_length(max_fragment_length)
        # The same for the purpose binding. Inside a handshake the engine
        # reports only the exception type, so a missing binding has to
        # surface here, where its reason reaches the caller.
        _set_server_purpose(crypto.X509Store())
        object.__setattr__(self, "_max_fragment_length", max_fragment_length)

    @classmethod
    def from_files(
        cls,
        certificate_path: str | PathLike[str],
        private_key_path: str | PathLike[str],
        *,
        server_profile: SamsungServerProfile | None = None,
        max_fragment_length: int = 1024,
    ) -> FragmentingCertificateAuth:
        """Create a provider backed by certificate-chain and key files.

        Overridden only to carry `max_fragment_length`; the inherited factory
        has no parameter for it.
        """
        return cls(
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            server_profile=server_profile,
            max_fragment_length=max_fragment_length,
        )

    @classmethod
    def from_memory(
        cls,
        certificate_pem: str,
        private_key_pem: str,
        *,
        server_profile: SamsungServerProfile | None = None,
        max_fragment_length: int = 1024,
    ) -> FragmentingCertificateAuth:
        """Create a provider backed by an in-memory PEM chain and key."""
        return cls(
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            server_profile=server_profile,
            max_fragment_length=max_fragment_length,
        )

    def __repr__(self) -> str:
        """Return a representation that never includes credential material."""
        return "FragmentingCertificateAuth()"

    def create_dtls_connection(self, *, mtu: int):
        """Return a DTLS connection carrying this credential.

        Satisfies :class:`DtlsConnectionProvider`.
        """
        return self._new_client(mtu, self._verify_peer_chain)

    def _create_diagnostic_connection(self, *, mtu: int):
        """Return a connection that leaves the trust decision to the peer.

        For `diagnose_dtls_handshake` only. A diagnostic reports the
        appliance's own alert, so it must not refuse the chain locally. The
        engine skips the chain check when it gets no callback
        (`DtlsCertClient._send_client_flight`). It still checks the
        ServerKeyExchange signature against the leaf.
        """
        return self._new_client(mtu, None)

    def _new_client(self, mtu, verify_peer_chain):
        chain_der, key = self._load_client_credential()
        return DtlsCertClient(
            chain_der,
            key,
            mtu=mtu,
            max_fragment_length=self._max_fragment_length,
            verify_peer_chain=verify_peer_chain,
        )

    def _load_client_credential(self):
        """Return our chain as DER, leaf first, and the private key."""
        if self._certificate_pem is not None:
            chain_pem = self._certificate_pem.encode()
            key_pem = self._private_key_pem.encode()
        else:
            chain_pem = Path(self._certificate_path).read_bytes()
            key_pem = Path(self._private_key_path).read_bytes()
        certificates = _PEM_CERT_RE.findall(chain_pem)
        if not certificates:
            raise ValueError("no certificate found in the client chain")
        chain_der = [
            crypto.load_certificate(crypto.FILETYPE_PEM, block)
            .to_cryptography()
            .public_bytes(serialization.Encoding.DER)
            for block in certificates
        ]
        key = serialization.load_pem_private_key(key_pem, password=None)
        return chain_der, key

    def _verify_peer_chain(self, chain_der: list[bytes]) -> None:
        """Verify the peer's chain, then apply any profile's identity rules.

        Raises to refuse, which is what the engine's callback contract asks
        for. The chain is always verified, against the bundled OCF root plus
        any additional CA a profile carries. A profile then adds its leaf
        check, `SamsungServerProfile._verify_peer`, so the role, subject and
        UUID rules are not restated here. With no profile this matches what
        the pyOpenSSL path does: OpenSSL's chain verdict and no pin.

        Certificates are parsed by OpenSSL rather than by `cryptography`,
        because Samsung's factory leaves are not accepted by a `cryptography`
        reparse that OpenSSL has already verified (#33).
        """
        if not chain_der:
            raise ValueError("peer sent no certificate")
        parsed = [
            crypto.load_certificate(crypto.FILETYPE_ASN1, der) for der in chain_der
        ]
        store = crypto.X509Store()
        for block in _PEM_CERT_RE.findall(Path(_OCF_ROOT_CA).read_bytes()):
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, block))
        if self._server_profile is not None:
            for certificate in (
                self._server_profile._additional_ca_certificates or ()
            ):
                store.add_cert(
                    crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
                )
        # The pyOpenSSL path refuses a server leaf whose extended key usage
        # lacks serverAuth. Measured 2026-11-13 with a synthetic chain, on the
        # dependency floor and on current: only the leaf's EKU differed, and
        # serverAuth completed while clientAuth alone failed verification.
        # X509StoreContext sets no purpose, so set the SSL-server one here.
        _set_server_purpose(store)
        crypto.X509StoreContext(
            store, parsed[0], chain=parsed[1:] or None
        ).verify_certificate()
        if self._server_profile is None:
            return
        if not self._server_profile._verify_peer(None, parsed[0], 0, 0, True):
            raise ValueError("peer certificate did not match the server profile")

    def _authenticated_server_identity(self, connection) -> UUID | None:
        """Read the verified leaf's UUID from the engine's own chain.

        None without a profile, which is what :class:`CertificateAuth` returns
        in the same case: there is no verified role to read an identity from.
        """
        if self._server_profile is None:
            return None
        chain = getattr(connection, "peer_chain_der", None)
        if not chain:
            raise ValueError("verified server identity was unavailable")
        leaf = crypto.load_certificate(crypto.FILETYPE_ASN1, chain[0])
        identity = self._server_profile._certificate_identity(leaf)
        if identity is None:
            raise ValueError("verified server identity was unavailable")
        return identity


class PskAuth:
    """DTLS authentication using an existing OCF PSK credential.

    The identity must be a raw 16-byte OCF UUID; the key must contain 16 or
    32 bytes. Credential material is intentionally not exposed as public
    attributes and is never included in this provider's representation. A
    configured context must not outlive this provider; ``DtlsCoapSession``
    enforces that lifetime by retaining its provider.

    A session reaches this credential through the library's own DTLS 1.2
    ECDHE-PSK client, which carries the identity with an explicit length and
    so takes any 16 bytes. :meth:`configure_context` is the OpenSSL path,
    kept for direct callers, and it cannot carry an identity containing a
    zero byte -- see :meth:`validate_identity`.
    """

    __slots__ = ("_callback", "_engine")

    @staticmethod
    def validate_identity(identity: bytes) -> None:
        """Raise unless ``identity`` is one a session can put on the wire.

        A caller holding a credential can check it here, and report the
        reason, before building a provider or storing anything. This is a
        pure check: it depends on the identity and nothing else.

        A zero byte is accepted. An OCF appliance takes the identity as
        bytes with an explicit length, so a zero byte is unremarkable to the
        device, and the library's own DTLS client frames it the same way.
        What cannot carry it is OpenSSL: its DTLS 1.2 PSK client callback
        returns the identity as a C string, so a NUL truncates it on the
        wire and the handshake fails against the truncated value with no
        local error to point at the cause. That constraint belongs to one
        backend rather than to the credential, so :meth:`configure_context`
        refuses such an identity explicitly and a session does not.

        The size of that difference, measured: roughly 6% of uniformly
        random 16-byte identities carry a zero byte, and about 5% of
        UUIDv4s, whose version and variant bytes can never be zero.
        """
        if type(identity) is not bytes:
            raise TypeError("identity must be bytes")
        if len(identity) != 16:
            raise ValueError("identity must be a raw 16-byte OCF UUID")

    def __init__(self, *, identity: bytes, key: bytes) -> None:
        if type(identity) is not bytes or type(key) is not bytes:
            raise TypeError("identity and key must be bytes")
        self.validate_identity(identity)
        if len(key) not in (16, 32):
            raise ValueError("key must be 16 or 32 bytes")

        def engine(*, mtu: int) -> DtlsPskClient:
            return DtlsPskClient(identity, key, mtu)

        # Held in a closure rather than an attribute, the same way the
        # OpenSSL callback below is: no attribute, public or private, holds
        # credential material, and test_psk_auth pins that.
        object.__setattr__(self, "_engine", engine)

        if b"\x00" in identity:
            # OpenSSL would truncate this identity at the zero byte, so no
            # callback is built for it at all and configure_context refuses.
            # The engine a session uses carries an explicit length and is
            # unaffected; see validate_identity.
            object.__setattr__(self, "_callback", None)
            return

        ffi = _util.ffi

        @ffi.callback(_PSK_CLIENT_CALLBACK_CDEF)
        def client_callback(
            _ssl,
            _identity_hint,
            identity_buffer,
            max_identity_length,
            key_buffer,
            max_key_length,
        ):
            # OpenSSL callbacks cannot propagate Python exceptions. Fail
            # before touching either destination when a buffer is unavailable
            # or too small for the complete credential.
            if (
                identity_buffer == ffi.NULL
                or key_buffer == ffi.NULL
                or len(identity) + 1 > max_identity_length
                or len(key) > max_key_length
            ):
                return 0
            ffi.memmove(
                identity_buffer,
                identity + b"\x00",
                len(identity) + 1,
            )
            ffi.memmove(key_buffer, key, len(key))
            return len(key)

        object.__setattr__(self, "_callback", client_callback)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("PskAuth is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("PskAuth is immutable")

    def __repr__(self) -> str:
        """Return a representation that never includes credential material."""
        return "PskAuth()"

    def create_dtls_connection(self, *, mtu: int):
        """Return a DTLS connection carrying this credential.

        Satisfies :class:`DtlsConnectionProvider`. The engine speaks one
        ciphersuite and no X.509, and it frames the identity with an explicit
        length, which is the whole reason this path exists alongside
        :meth:`configure_context`.
        """
        return self._engine(mtu=mtu)

    def configure_context(self, context: SSL.Context) -> None:
        """Configure one context for the narrow Samsung OCF PSK profile.

        Raises when the identity contains a zero byte. OpenSSL presents a
        DTLS 1.2 PSK identity as a C string, so it would send a shorter
        identity than the one supplied and nothing local would say so. A
        session does not come through here and has no such limit.
        """
        if self._callback is None:
            raise ValueError(
                "this identity contains a NUL byte and cannot be presented "
                "through OpenSSL, which carries a DTLS 1.2 PSK identity as a "
                "C string: it truncates there, and the appliance would be "
                "sent a shorter identity than the one supplied. A "
                "DtlsCoapSession carries this credential without OpenSSL"
            )
        setter = getattr(_util.lib, "SSL_CTX_set_psk_client_callback", None)
        if setter is None:
            raise RuntimeError(
                "the installed OpenSSL binding does not support DTLS PSK"
            )
        context.set_cipher_list(_DTLS_PSK_CIPHERS)
        setter(context._context, self._callback)


__all__ = [
    "AuthenticationProvider",
    "CertificateAuth",
    "PskAuth",
    "SamsungServerProfile",
    "SamsungServerRole",
    "ServerCertificateAuth",
]
