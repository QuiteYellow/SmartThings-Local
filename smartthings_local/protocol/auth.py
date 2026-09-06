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

from cryptography.x509.oid import ExtensionOID
from OpenSSL import SSL, _util, crypto

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


class PskAuth:
    """DTLS authentication using an existing OCF PSK credential.

    The identity must be a raw 16-byte OCF UUID. The key must contain 16 or
    32 bytes. Credential material is intentionally not exposed as public
    attributes and is never included in this provider's representation. A
    configured context must not outlive this provider; ``DtlsCoapSession``
    enforces that lifetime by retaining its provider.
    """

    __slots__ = ("_callback",)

    def __init__(self, *, identity: bytes, key: bytes) -> None:
        if type(identity) is not bytes or type(key) is not bytes:
            raise TypeError("identity and key must be bytes")
        if len(identity) != 16:
            raise ValueError("identity must be a raw 16-byte OCF UUID")
        if b"\x00" in identity:
            raise ValueError("identity cannot contain a NUL byte")
        if len(key) not in (16, 32):
            raise ValueError("key must be 16 or 32 bytes")

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

    def configure_context(self, context: SSL.Context) -> None:
        """Configure one context for the narrow Samsung OCF PSK profile."""
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
