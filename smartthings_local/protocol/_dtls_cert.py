"""Pure-Python DTLS 1.2 client for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.

Exists because of one extension. The washer and dryer on #20 leave the network
for about ten seconds whenever they have to put a handshake flight on the wire
that does not fit one Ethernet frame, and their flight does not. Offering
`max_fragment_length` makes them fragment it at the DTLS layer instead, and
measured on both units on 2026-10-25 that stops the drop: four of four
no-extension probes took the unit off the network and both extension probes
drew the whole flight with no loss.

No Python binding of OpenSSL can send that extension. `openssl s_client` can
(`-maxfraglen`), so the library is not the limit: `cryptography` 50.0.1 exposes
neither `SSL_CTX_set_tlsext_max_fragment_length` nor the `SSL_CTX_ctrl` the
macro goes through, its OpenSSL is linked statically into `_rust.abi3.so` with
the symbols hidden, and the only `SSL_CTX_ctrl` that resolves in-process
belongs to a different OpenSSL that does not own our context. Hence an engine
of our own, on the same shared base as the PSK one.

The wire profile is the one measured for this cohort in #33 and confirmed
against #20's two appliances on 2026-10-25:

- P-256 only, and one ciphersuite, `0xC02B`.
- The ordered signature offer RSA+SHA256, ECDSA+SHA256, RSA+SHA1, ECDSA+SHA1.
  Both appliances' CertificateRequest accepts ECDSA+SHA256 and RSA+SHA256.
- No session ticket.

Trust is not decided here. The engine verifies that the server's
ServerKeyExchange signature was made by the key in the leaf it presented, which
is what binds the ECDHE parameters to that certificate, and hands the chain to
a caller-supplied callback for everything else. The role, UUID and CA-chain
rules belong to `SamsungServerProfile` in `auth.py`, which already holds them
and must not be reimplemented here (#33, #76).

Outbound handshake fragmentation lives here rather than in the base because
the PSK flight is a few hundred bytes and never needs it. A negotiated fragment
length binds us as well as the peer, so our own Certificate goes out split to
fit, and `split_dtls` then puts each record in its own datagram, which this
firmware requires.

Security posture: we are the client, on a LAN, against one appliance. The
record layer is AEAD, so the padding-oracle surface the PSK engine documents
does not arise here.
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from OpenSSL import crypto

from ._dtls_base import (
    _CT_CHANGE_CIPHER_SPEC,
    _CT_HANDSHAKE,
    _ECCURVETYPE_NAMED,
    _HANDSHAKE_HEADER,
    _HT_CERTIFICATE,
    _HT_CERTIFICATE_REQUEST,
    _HT_CERTIFICATE_VERIFY,
    _HT_CLIENT_KEY_EXCHANGE,
    _HT_FINISHED,
    _HT_SERVER_KEY_EXCHANGE,
    _NAMED_CURVE_SECP256R1,
    _VERIFY_DATA_LEN,
    DtlsError,
    WantRead,
    ZeroReturn,
    _DtlsClientBase,
    _prf,
    logger,
)

__all__ = ["DtlsCertClient", "DtlsError", "WantRead", "ZeroReturn"]

# ssl_ciphersuites.h: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
_SUITE = 0xC02B

# RFC 5288 section 3: 4-byte implicit salt, 8-byte explicit nonce, 16-byte tag.
_GCM_KEY_LEN = 16
_GCM_SALT_LEN = 4
_GCM_EXPLICIT_LEN = 8
_GCM_TAG_LEN = 16

# The ordered offer measured in #33. Codepoints are (hash, signature) pairs
# from RFC 5246 section 7.4.1.4.1: SHA-256 is 4, SHA-1 is 2, RSA is 1,
# ECDSA is 3.
_SIG_RSA_SHA256 = (4, 1)
_SIG_ECDSA_SHA256 = (4, 3)
_SIG_RSA_SHA1 = (2, 1)
_SIG_ECDSA_SHA1 = (2, 3)
_SIGNATURE_OFFER = (
    _SIG_RSA_SHA256,
    _SIG_ECDSA_SHA256,
    _SIG_RSA_SHA1,
    _SIG_ECDSA_SHA1,
)

_HASHES = {2: hashes.SHA1, 4: hashes.SHA256, 5: hashes.SHA384, 6: hashes.SHA512}
_SIG_RSA = 1
_SIG_ECDSA = 3

# RFC 6066 section 4. 512 is the smallest offer and the one measured to move
# these appliances' flight under the MTU.
_MFL_CODES = {512: 1, 1024: 2, 2048: 3, 4096: 4}

# A chain longer than this is a peer wasting our memory, not an appliance.
# The two units measured on 2026-10-25 both send two certificates.
_MAX_CHAIN_CERTS = 8


class _GcmTransform:
    """AES-128-GCM records, RFC 5288 with DTLS 1.2 sequence numbering."""

    __slots__ = ("_dec", "_dec_salt", "_enc", "_enc_salt")

    def __init__(self, key_block: bytes) -> None:
        # RFC 5246 section 6.3 with no MAC keys: client key, server key,
        # client salt, server salt.
        offset = 0
        enc_key = key_block[offset:offset + _GCM_KEY_LEN]
        offset += _GCM_KEY_LEN
        dec_key = key_block[offset:offset + _GCM_KEY_LEN]
        offset += _GCM_KEY_LEN
        self._enc_salt = key_block[offset:offset + _GCM_SALT_LEN]
        offset += _GCM_SALT_LEN
        self._dec_salt = key_block[offset:offset + _GCM_SALT_LEN]
        self._enc = AESGCM(enc_key)
        self._dec = AESGCM(dec_key)

    @staticmethod
    def _aad(epoch: int, seq: int, content_type: int, length: int) -> bytes:
        # The DTLS 1.2 additional data is the 64-bit epoch-and-sequence,
        # then the record header's type, version and plaintext length.
        return (
            struct.pack("!H", epoch)
            + seq.to_bytes(6, "big")
            + struct.pack("!BHH", content_type, 0xFEFD, length)
        )

    def protect(self, epoch: int, seq: int, content_type: int, payload: bytes) -> bytes:
        explicit = struct.pack("!H", epoch) + seq.to_bytes(6, "big")
        nonce = self._enc_salt + explicit
        aad = self._aad(epoch, seq, content_type, len(payload))
        return explicit + self._enc.encrypt(nonce, payload, aad)

    def unprotect(
        self, epoch: int, seq: int, content_type: int, fragment: bytes
    ) -> bytes | None:
        """Return the plaintext payload, or None when the record is not authentic.

        The explicit nonce is read from the record rather than recomputed, so a
        peer that numbers its nonces differently from its sequence numbers still
        decrypts. AEAD gives one combined failure, so there is no padding path
        to time here.
        """
        if len(fragment) < _GCM_EXPLICIT_LEN + _GCM_TAG_LEN:
            return None
        explicit = fragment[:_GCM_EXPLICIT_LEN]
        sealed = fragment[_GCM_EXPLICIT_LEN:]
        nonce = self._dec_salt + explicit
        length = len(sealed) - _GCM_TAG_LEN
        aad = self._aad(epoch, seq, content_type, length)
        try:
            return self._dec.decrypt(nonce, sealed, aad)
        except Exception:  # noqa: BLE001 - AEAD gives one combined failure
            return None


class DtlsCertClient(_DtlsClientBase):
    """One DTLS 1.2 ECDHE-ECDSA session with a client certificate.

    `chain_der` is the client certificate first, then any intermediates, each
    DER-encoded. `private_key` is the matching `cryptography` private key.

    `verify_peer_chain` is called with the peer's chain as a list of DER
    certificates once it has arrived and before the client flight is sent. It
    decides trust and raises to refuse; the engine itself checks only that the
    ServerKeyExchange signature was made by the leaf's key. Passing None skips
    the callback, which authenticates the carrier and nothing about who is on
    the other end -- a diagnostic's position, never a session's (#84, v0.1.17).

    `max_fragment_length` is the whole reason this engine exists. None omits
    the extension, which is the behaviour that drops #20's appliances off the
    network.
    """

    def __init__(
        self,
        chain_der: list[bytes],
        private_key,
        *,
        mtu: int = 1400,
        max_fragment_length: int | None = 512,
        verify_peer_chain=None,
    ) -> None:
        if not isinstance(chain_der, (list, tuple)) or not chain_der:
            raise ValueError("chain_der must be a non-empty list of DER certificates")
        if any(type(entry) is not bytes or not entry for entry in chain_der):
            raise TypeError("every chain_der entry must be non-empty bytes")
        if len(chain_der) > _MAX_CHAIN_CERTS:
            raise ValueError(f"chain_der must hold at most {_MAX_CHAIN_CERTS} entries")
        if max_fragment_length is not None and (
            type(max_fragment_length) is not int
            or max_fragment_length not in _MFL_CODES
        ):
            raise ValueError(
                "max_fragment_length must be one of "
                f"{sorted(_MFL_CODES)} or None"
            )
        if not hasattr(private_key, "sign"):
            raise TypeError("private_key must be a cryptography private key")
        super().__init__(mtu=mtu)
        self._chain_der = list(chain_der)
        self._key = private_key
        self._mfl = max_fragment_length
        self._verify_peer_chain = verify_peer_chain

        self._peer_chain: list[bytes] = []
        self._peer_public_key = None
        self._certificate_requested = False
        self._request_sig_algs: tuple[tuple[int, int], ...] = ()
        self._mfl_agreed = False

    # -- what the peer presented -----------------------------------------

    @property
    def peer_chain_der(self) -> list[bytes]:
        """The peer's certificate chain, leaf first, as DER."""
        return list(self._peer_chain)

    @property
    def negotiated_fragment_length(self) -> int | None:
        """The fragment length the server echoed, or None if it did not."""
        return self._mfl if self._mfl_agreed else None

    # -- hooks -----------------------------------------------------------

    def _offered_suites(self) -> tuple[int, ...]:
        return (_SUITE,)

    def _hello_extensions(self) -> bytes:
        groups = struct.pack("!HHHH", 0x000A, 4, 2, _NAMED_CURVE_SECP256R1)
        point_formats = struct.pack("!HH", 0x000B, 2) + bytes([1, 0])
        offer = b"".join(bytes(pair) for pair in _SIGNATURE_OFFER)
        sig_algs = struct.pack("!HHH", 0x000D, len(offer) + 2, len(offer)) + offer
        # No session ticket extension: #33 measured this cohort with tickets
        # disabled, and an absent extension is how that is expressed.
        extensions = groups + point_formats + sig_algs
        if self._mfl is not None:
            extensions += struct.pack("!HHB", 0x0001, 1, _MFL_CODES[self._mfl])
        return extensions

    def _on_server_hello(self, body: bytes, offset: int) -> None:
        """Read the extensions the server echoed, and hold it to the MFL."""
        echoed = _parse_hello_extensions(body, offset)
        if echoed is None:
            self._fail("malformed ServerHello extensions")
            return
        if 0x0001 in echoed:
            value = echoed[0x0001]
            if self._mfl is None:
                self._fail("server echoed a fragment length that was not offered")
                return
            if value != bytes([_MFL_CODES[self._mfl]]):
                self._fail("server echoed a different fragment length")
                return
            self._mfl_agreed = True

    def _handle_other_handshake(
        self, msg_type: int, message: bytes, body: bytes
    ) -> None:
        if msg_type == _HT_CERTIFICATE:
            self._transcript += message
            self._handle_certificate(body)
        elif msg_type == _HT_SERVER_KEY_EXCHANGE:
            self._transcript += message
            self._handle_server_key_exchange(body)
        elif msg_type == _HT_CERTIFICATE_REQUEST:
            self._transcript += message
            self._handle_certificate_request(body)

    # -- inbound handshake messages --------------------------------------

    def _handle_certificate(self, body: bytes) -> None:
        if self._state != "got_server_hello":
            return
        if self._peer_chain:
            self._fail("server sent more than one Certificate")
            return
        chain = _parse_certificate_list(body)
        if chain is None:
            self._fail("malformed Certificate message")
            return
        if not chain:
            self._fail("server sent an empty certificate chain")
            return
        if len(chain) > _MAX_CHAIN_CERTS:
            self._fail("server certificate chain is too long")
            return
        public_key = _leaf_public_key(chain[0])
        if public_key is None:
            self._fail("server leaf certificate did not parse")
            return
        self._peer_chain = chain
        self._peer_public_key = public_key

    def _handle_server_key_exchange(self, body: bytes) -> None:
        """Read and verify the signed ECDHE parameters.

        Unlike the PSK exchange there is a signature here, and verifying it is
        what ties these ephemeral parameters to the certificate the peer just
        presented. Without that check an off-path peer can substitute its own
        key share.
        """
        if self._state != "got_server_hello":
            return
        if self._peer_public_key is None:
            self._fail("ServerKeyExchange arrived before the certificate")
            return
        if len(body) < 4:
            self._fail("short ServerKeyExchange")
            return
        if body[0] != _ECCURVETYPE_NAMED:
            self._fail("server offered a non-named curve")
            return
        curve = int.from_bytes(body[1:3], "big")
        if curve != _NAMED_CURVE_SECP256R1:
            self._fail(f"server offered unexpected curve 0x{curve:04x}")
            return
        point_len = body[3]
        point = body[4:4 + point_len]
        if len(point) != point_len or point_len == 0:
            self._fail("malformed server ECDH point")
            return
        params = body[:4 + point_len]
        rest = body[4 + point_len:]
        if len(rest) < 4:
            self._fail("ServerKeyExchange carries no signature")
            return
        hash_id, sig_id = rest[0], rest[1]
        sig_len = int.from_bytes(rest[2:4], "big")
        signature = rest[4:4 + sig_len]
        if len(signature) != sig_len or not signature:
            self._fail("malformed ServerKeyExchange signature")
            return
        if (hash_id, sig_id) not in _SIGNATURE_OFFER:
            self._fail(
                f"server signed with an algorithm that was not offered "
                f"({hash_id},{sig_id})"
            )
            return
        signed = self._client_random + self._server_random + params
        if not _verify_signature(
            self._peer_public_key, hash_id, sig_id, signature, signed
        ):
            self._fail("ServerKeyExchange signature did not verify")
            return
        try:
            # Rejects points that are malformed or not on the curve.
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError:
            self._fail("server ECDH point is not on secp256r1")
            return
        self._peer_point = point
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._state = "got_server_params"

    def _handle_certificate_request(self, body: bytes) -> None:
        """Record that a client certificate is wanted, and with what algorithms."""
        if self._state not in ("got_server_hello", "got_server_params"):
            return
        parsed = _parse_certificate_request(body)
        if parsed is None:
            self._fail("malformed CertificateRequest")
            return
        self._certificate_requested = True
        self._request_sig_algs = parsed

    # -- the client flight -----------------------------------------------

    def _send_client_flight(self) -> None:
        """Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished."""
        if self._verify_peer_chain is not None:
            if not self._peer_chain:
                self._fail("peer presented no certificate to verify")
                return
            try:
                self._verify_peer_chain(list(self._peer_chain))
            except Exception as exc:  # noqa: BLE001 - the callback owns the reason
                self._fail(f"peer certificate rejected: {type(exc).__name__}")
                return
        signature_algorithm = None
        if self._certificate_requested:
            signature_algorithm = self._client_signature_algorithm()
            if signature_algorithm is None:
                self._fail("no offered signature algorithm matches our key")
                return

        self._start_flight()
        # Certificate and CertificateVerify go out only when the server asked
        # for one. Both appliances measured on #20 do ask, so this is the
        # normal path; sending them unrequested would be an invalid flight.
        if self._certificate_requested:
            self._emit_handshake(
                _HT_CERTIFICATE,
                _encode_certificate_list(self._chain_der),
                transcript=True,
            )

        public = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self._emit_handshake(
            _HT_CLIENT_KEY_EXCHANGE,
            bytes([len(public)]) + public,
            transcript=True,
        )

        if signature_algorithm is not None:
            # CertificateVerify signs every handshake message so far, this
            # message excluded, so the transcript is read before it is
            # appended to.
            signed = bytes(self._transcript)
            hash_id, sig_id = signature_algorithm
            signature = _make_signature(self._key, hash_id, sig_id, signed)
            self._emit_handshake(
                _HT_CERTIFICATE_VERIFY,
                bytes([hash_id, sig_id])
                + struct.pack("!H", len(signature))
                + signature,
                transcript=True,
            )

        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), self._peer_point
        )
        # The ECDHE premaster is the shared secret alone, where the PSK
        # exchange composes it with the key (ssl_tls.c:1136).
        premaster = self._private_key.exchange(ec.ECDH(), peer)
        self._master_secret = _prf(
            premaster,
            b"master secret",
            self._client_random + self._server_random,
            48,
        )
        key_block = _prf(
            self._master_secret,
            b"key expansion",
            self._server_random + self._client_random,
            _GCM_KEY_LEN * 2 + _GCM_SALT_LEN * 2,
        )

        self._emit_record(_CT_CHANGE_CIPHER_SPEC, b"\x01")
        self._transform = _GcmTransform(key_block)
        self._send_epoch = 1
        self._send_seq = 0

        verify = _prf(
            self._master_secret,
            b"client finished",
            hashlib.sha256(self._transcript).digest(),
            _VERIFY_DATA_LEN,
        )
        self._emit_handshake(_HT_FINISHED, verify, transcript=True)

    def _client_signature_algorithm(self) -> tuple[int, int] | None:
        """Pick a signature algorithm both sides will accept for our key.

        The server's CertificateRequest narrows the offer when it carries one;
        an absent or empty list means it stated no preference, so our own offer
        order stands.
        """
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            kind = _SIG_ECDSA
        else:
            kind = _SIG_RSA
        allowed = self._request_sig_algs or _SIGNATURE_OFFER
        for pair in _SIGNATURE_OFFER:
            if pair[1] == kind and pair in allowed:
                return pair
        return None

    def send(self, data: bytes) -> int:
        """Encrypt and queue one application record.

        A negotiated fragment length bounds every record, not only handshake
        ones (RFC 6066 section 4), and an over-length record is what a peer
        answers with `record_overflow`. Splitting here is not available: one
        CoAP message is one record on this transport, so a split would hand
        the appliance two half-messages. The caller is told the limit instead,
        and `post()` already has Block1 for a body that needs it.
        """
        limit = self.negotiated_fragment_length
        if limit is not None and len(data) > limit:
            raise DtlsError(
                f"application record of {len(data)} bytes exceeds the "
                f"negotiated fragment length of {limit}"
            )
        return super().send(data)

    # -- outbound fragmentation ------------------------------------------

    def _fragment_limit(self) -> int:
        """Largest handshake-message body one record may carry.

        A negotiated fragment length binds both directions, so our own
        Certificate has to fit it. With no negotiated length the MTU stands in,
        less the IP, UDP, record and handshake headers.
        """
        if self._mfl_agreed and self._mfl is not None:
            budget = self._mfl
        else:
            budget = self._mtu - 28 - 13
        return max(64, budget - _HANDSHAKE_HEADER)

    def _emit_handshake(self, msg_type: int, body: bytes, *, transcript: bool) -> None:
        """Emit one handshake message, fragmented to the negotiated length.

        The transcript always carries the unfragmented message (RFC 6347
        section 4.2.6), so a flight that fragments hashes the same as one that
        does not. `message_seq` advances once per message, not per fragment.
        """
        limit = self._fragment_limit()
        msg_seq = self._next_msg_seq
        self._next_msg_seq += 1
        total = len(body)
        if transcript:
            self._transcript += _handshake_header(
                msg_type, total, msg_seq, 0, total
            ) + body
        offset = 0
        while True:
            chunk = body[offset:offset + limit]
            self._emit_record(
                _CT_HANDSHAKE,
                _handshake_header(msg_type, total, msg_seq, offset, len(chunk))
                + chunk,
            )
            offset += len(chunk)
            if offset >= total:
                break


# -- encoding and parsing helpers ------------------------------------------


def _leaf_public_key(der: bytes):
    """Return the leaf's public key, or None when it cannot be read.

    MEASURED 2026-10-26, on a Samsung dryer and oven: `cryptography`'s
    `load_der_x509_certificate` refuses both appliances' factory leaves, so
    every handshake failed at "server leaf certificate did not parse" while the
    pyOpenSSL path completed against the same certificate. #33 recorded the
    same asymmetry on an HW-S61B and a TU7x and reads the subject through
    OpenSSL for that reason; this is the same hazard reached from a different
    direction, because an engine that parses the chain itself has to parse it
    with something.

    So OpenSSL parses the certificate and `cryptography` only receives the key
    it yields. Nothing here is a trust decision: the key is used to check the
    ServerKeyExchange signature, and the chain goes to the caller's callback,
    which hands it to OpenSSL as well.
    """
    try:
        return crypto.load_certificate(
            crypto.FILETYPE_ASN1, der
        ).get_pubkey().to_cryptography_key()
    except Exception:  # noqa: BLE001 - any parse failure is the same refusal
        return None



def _handshake_header(
    msg_type: int, total: int, msg_seq: int, frag_offset: int, frag_len: int
) -> bytes:
    return (
        bytes([msg_type])
        + total.to_bytes(3, "big")
        + struct.pack("!H", msg_seq)
        + frag_offset.to_bytes(3, "big")
        + frag_len.to_bytes(3, "big")
    )


def _encode_certificate_list(chain: list[bytes]) -> bytes:
    body = b"".join(len(entry).to_bytes(3, "big") + entry for entry in chain)
    return len(body).to_bytes(3, "big") + body


def _parse_certificate_list(body: bytes) -> list[bytes] | None:
    if len(body) < 3:
        return None
    total = int.from_bytes(body[:3], "big")
    if total != len(body) - 3:
        return None
    out: list[bytes] = []
    offset = 3
    end = 3 + total
    while offset < end:
        if offset + 3 > end:
            return None
        size = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        if size == 0 or offset + size > end:
            return None
        out.append(body[offset:offset + size])
        offset += size
        if len(out) > _MAX_CHAIN_CERTS:
            return None
    return out


def _parse_certificate_request(body: bytes) -> tuple[tuple[int, int], ...] | None:
    """Return the signature algorithms the server will accept from us.

    The certificate-authority list is deliberately not returned. Which chain to
    present is the caller's decision and it holds exactly one, so reading the
    list here would only invite the engine to make a trust decision that
    belongs to `SamsungServerProfile`.
    """
    try:
        offset = 0
        type_count = body[offset]
        offset += 1 + type_count
        sig_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if sig_len % 2 or offset + sig_len > len(body):
            return None
        algs = tuple(
            (body[offset + index], body[offset + index + 1])
            for index in range(0, sig_len, 2)
        )
        offset += sig_len
        ca_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if offset + ca_len > len(body):
            return None
    except IndexError:
        return None
    return algs


def _parse_hello_extensions(body: bytes, offset: int) -> dict[int, bytes] | None:
    if offset == len(body):
        return {}
    if offset + 2 > len(body):
        return None
    total = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    end = offset + total
    # The block ends the message, so a declared length that stops short of the
    # body leaves trailing bytes, and dropping those quietly would accept a
    # ServerHello nobody wrote.
    if end != len(body):
        return None
    out: dict[int, bytes] = {}
    while offset + 4 <= end:
        kind = int.from_bytes(body[offset:offset + 2], "big")
        size = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        if offset + size > end:
            return None
        out[kind] = body[offset:offset + size]
        offset += size
    if offset != end:
        return None
    return out


def _verify_signature(public_key, hash_id, sig_id, signature, signed) -> bool:
    algorithm = _HASHES.get(hash_id)
    if algorithm is None:
        return False
    try:
        if sig_id == _SIG_ECDSA:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            public_key.verify(signature, signed, ec.ECDSA(algorithm()))
        elif sig_id == _SIG_RSA:
            public_key.verify(
                signature, signed, padding.PKCS1v15(), algorithm()
            )
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _make_signature(private_key, hash_id, sig_id, signed) -> bytes:
    algorithm = _HASHES[hash_id]()
    if sig_id == _SIG_ECDSA:
        return private_key.sign(signed, ec.ECDSA(algorithm))
    return private_key.sign(signed, padding.PKCS1v15(), algorithm)


_ = (logger,)
