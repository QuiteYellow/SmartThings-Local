"""Immutable authentication providers for DTLS sessions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Protocol, runtime_checkable

from OpenSSL import SSL, crypto

_OCF_ROOT_CA = str(Path(__file__).with_name("ocf_root_ca.pem"))
_DTLS_CIPHERS = b"ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0"
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
        """Configure trust, verification, ciphers, and client credentials."""


@dataclass(frozen=True, slots=True, repr=False)
class CertificateAuth:
    """Certificate authentication loaded from files or in-memory PEM data."""

    certificate_path: str | PathLike[str] | None = None
    private_key_path: str | PathLike[str] | None = None
    certificate_pem: str | None = None
    private_key_pem: str | None = None

    def __post_init__(self) -> None:
        file_supplied = (
            self.certificate_path is not None or self.private_key_path is not None
        )
        memory_supplied = (
            self.certificate_pem is not None or self.private_key_pem is not None
        )
        if file_supplied and memory_supplied:
            raise ValueError(
                "pass either certificate_path/private_key_path or "
                "certificate_pem/private_key_pem, not both"
            )
        if file_supplied:
            if self.certificate_path is None or self.private_key_path is None:
                raise ValueError(
                    "certificate_path and private_key_path must be passed together"
                )
            object.__setattr__(self, "certificate_path", str(self.certificate_path))
            object.__setattr__(self, "private_key_path", str(self.private_key_path))
        elif memory_supplied:
            if self.certificate_pem is None or self.private_key_pem is None:
                raise ValueError(
                    "certificate_pem and private_key_pem must be passed together"
                )
        else:
            raise ValueError(
                "must pass either certificate_path/private_key_path or "
                "certificate_pem/private_key_pem"
            )

    @classmethod
    def from_files(
        cls,
        certificate_path: str | PathLike[str],
        private_key_path: str | PathLike[str],
    ) -> CertificateAuth:
        """Create a provider backed by certificate-chain and key files."""
        return cls(
            certificate_path=certificate_path,
            private_key_path=private_key_path,
        )

    @classmethod
    def from_memory(
        cls,
        certificate_pem: str,
        private_key_pem: str,
    ) -> CertificateAuth:
        """Create a provider backed by an in-memory PEM chain and key."""
        return cls(
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
        )

    def __repr__(self) -> str:
        """Return a representation that never includes credential material."""
        return "CertificateAuth()"

    def configure_context(self, context: SSL.Context) -> None:
        """Apply the existing certificate authentication profile to a context."""
        context.load_verify_locations(_OCF_ROOT_CA)
        context.set_verify(SSL.VERIFY_PEER, _verify_peer)
        # @SECLEVEL=0 permits SHA-1 in Samsung's server cert chain (AC14K_M
        # intermediate is SHA-1 signed). This is the only channel that reaches
        # the OpenSSL instance cryptography bundles; ctypes and cffi bindings
        # do not expose SSL_CTX_set_security_level on this build.
        context.set_cipher_list(_DTLS_CIPHERS)
        if self.certificate_pem is not None:
            _load_pem_chain(
                context,
                self.certificate_pem,
                self.private_key_pem,
            )
        else:
            context.use_certificate_chain_file(self.certificate_path)
            context.use_privatekey_file(self.private_key_path)
            context.check_privatekey()


__all__ = ["AuthenticationProvider", "CertificateAuth"]
