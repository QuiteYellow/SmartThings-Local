"""Hostile and malformed input against the certificate engine's own parsers.

The PSK engine's thirteen defects were found this way rather than on hardware,
so the new parsing surface gets the same treatment before it meets an
appliance. Everything here is offline.

What is deliberately NOT asserted: that a refusal is constant-time, or that any
of this is a defence against an on-path attacker who holds a trusted key. The
engine's job is to refuse malformed input without crashing or silently
continuing, and to make a trust decision nowhere.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from smartthings_local.protocol._dtls_cert import (
    _MAX_CHAIN_CERTS,
    _SIGNATURE_OFFER,
    DtlsCertClient,
    _encode_certificate_list,
    _parse_certificate_list,
    _parse_certificate_request,
    _parse_hello_extensions,
)


def _leaf():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hostile")])
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.DER)


def _client(**kwargs):
    key, der = _leaf()
    return DtlsCertClient([der], key, **kwargs)


# -- constructor ----------------------------------------------------------


@pytest.mark.parametrize(
    "chain",
    [[], (), b"not-a-list", [b""], ["not-bytes"], [bytearray(b"x")]],
)
def test_constructor_refuses_a_bad_chain(chain):
    key, _der = _leaf()
    with pytest.raises((TypeError, ValueError)):
        DtlsCertClient(chain, key)


def test_constructor_refuses_an_overlong_chain():
    key, der = _leaf()
    with pytest.raises(ValueError, match="at most"):
        DtlsCertClient([der] * (_MAX_CHAIN_CERTS + 1), key)


@pytest.mark.parametrize("value", [0, 1, 511, 513, 8192, "512", 512.0])
def test_constructor_refuses_a_fragment_length_off_the_list(value):
    key, der = _leaf()
    with pytest.raises(ValueError, match="max_fragment_length"):
        DtlsCertClient([der], key, max_fragment_length=value)


def test_constructor_accepts_no_fragment_length():
    client = _client(max_fragment_length=None)
    assert client.negotiated_fragment_length is None


def test_constructor_refuses_something_that_cannot_sign():
    _key, der = _leaf()
    with pytest.raises(TypeError, match="private key"):
        DtlsCertClient([der], object())


@pytest.mark.parametrize("value", [255, 65536, -1, "1400", 1400.0])
def test_constructor_keeps_the_one_mtu_rule(value):
    key, der = _leaf()
    with pytest.raises(ValueError, match="mtu"):
        DtlsCertClient([der], key, mtu=value)


# -- the ClientHello profile ---------------------------------------------


def test_hello_offers_the_measured_profile_and_no_session_ticket():
    extensions = _client()._hello_extensions()
    kinds = []
    offset = 0
    while offset + 4 <= len(extensions):
        kind = int.from_bytes(extensions[offset:offset + 2], "big")
        size = int.from_bytes(extensions[offset + 2:offset + 4], "big")
        kinds.append(kind)
        offset += 4 + size
    assert offset == len(extensions)
    assert kinds == [0x000A, 0x000B, 0x000D, 0x0001]
    # 0x0023 is the session ticket; #33 measured this cohort with it disabled.
    assert 0x0023 not in kinds
    # The ordered offer from #33, in that order.
    assert _SIGNATURE_OFFER == ((4, 1), (4, 3), (2, 1), (2, 3))


def test_hello_omits_the_fragment_length_when_it_was_not_asked_for():
    extensions = _client(max_fragment_length=None)._hello_extensions()
    assert b"\x00\x01\x00\x01" not in extensions


# -- ServerHello extension handling --------------------------------------


def _server_hello_tail(extensions: bytes) -> bytes:
    """A ServerHello body ending in the given extensions block."""
    body = b"\xfe\xfd" + b"r" * 32 + b"\x00" + b"\xc0\x2b" + b"\x00"
    if extensions is None:
        return body
    return body + len(extensions).to_bytes(2, "big") + extensions


def test_an_unsolicited_fragment_length_echo_is_refused():
    client = _client(max_fragment_length=None)
    client._state = "sent_hello"
    client._handle_server_hello(_server_hello_tail(b"\x00\x01\x00\x01\x01"))
    assert "not offered" in (client._failed or "")


def test_a_different_fragment_length_echo_is_refused():
    client = _client(max_fragment_length=512)
    client._state = "sent_hello"
    # Code 2 is 1024, not the 512 that was offered.
    client._handle_server_hello(_server_hello_tail(b"\x00\x01\x00\x01\x02"))
    assert "different fragment length" in (client._failed or "")


def test_a_matching_echo_is_accepted_and_recorded():
    client = _client(max_fragment_length=512)
    client._state = "sent_hello"
    client._handle_server_hello(_server_hello_tail(b"\x00\x01\x00\x01\x01"))
    assert client._failed is None
    assert client.negotiated_fragment_length == 512
    assert client._state == "got_server_hello"


def test_no_echo_leaves_the_length_unnegotiated():
    client = _client(max_fragment_length=512)
    client._state = "sent_hello"
    client._handle_server_hello(_server_hello_tail(b""))
    assert client._failed is None
    assert client.negotiated_fragment_length is None


def test_a_server_hello_with_no_extension_block_is_accepted():
    client = _client(max_fragment_length=512)
    client._state = "sent_hello"
    client._handle_server_hello(_server_hello_tail(None))
    assert client._failed is None


def test_a_malformed_extension_block_is_refused():
    client = _client()
    client._state = "sent_hello"
    body = _server_hello_tail(b"\x00\x01\x00\x01\x01")[:-1]
    client._handle_server_hello(body)
    assert "malformed ServerHello extensions" in (client._failed or "")


def test_an_unoffered_suite_is_refused():
    client = _client()
    client._state = "sent_hello"
    body = b"\xfe\xfd" + b"r" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
    client._handle_server_hello(body)
    assert "unexpected ciphersuite" in (client._failed or "")


# -- extension parser ----------------------------------------------------


@pytest.mark.parametrize(
    "blob",
    [
        b"\x00",                          # truncated length
        b"\x00\x08\x00\x01\x00\x01\x01",  # declared longer than present
        b"\x00\x05\x00\x01\x00\x01\x01\xff",  # trailing byte inside the block
        b"\x00\x04\x00\x01\x00\x09\x01",  # extension longer than its block
    ],
)
def test_hello_extension_parser_refuses_malformed_blocks(blob):
    assert _parse_hello_extensions(blob, 0) is None


def test_hello_extension_parser_reads_an_empty_block():
    assert _parse_hello_extensions(b"\x00\x00", 0) == {}
    assert _parse_hello_extensions(b"", 0) == {}


# -- certificate list parser ---------------------------------------------


def test_certificate_list_round_trips():
    chain = [b"a" * 10, b"b" * 20]
    assert _parse_certificate_list(_encode_certificate_list(chain)) == chain


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x00\x00",                                  # too short for a length
        b"\x00\x00\x09",                              # total disagrees
        b"\x00\x00\x03\x00\x00\x00",                  # zero-length certificate
        b"\x00\x00\x04\x00\x00\x09\xff",              # entry overruns the list
        b"\x00\x00\x02\x00\x00",                      # entry header truncated
    ],
)
def test_certificate_list_parser_refuses_malformed_input(blob):
    assert _parse_certificate_list(blob) is None


def test_certificate_list_parser_refuses_too_many_entries():
    chain = [b"x"] * (_MAX_CHAIN_CERTS + 1)
    assert _parse_certificate_list(_encode_certificate_list(chain)) is None


def test_an_empty_certificate_list_is_refused_by_the_handler():
    client = _client()
    client._state = "got_server_hello"
    client._handle_certificate(b"\x00\x00\x00")
    assert "empty certificate chain" in (client._failed or "")


def test_an_unparseable_leaf_is_refused():
    client = _client()
    client._state = "got_server_hello"
    client._handle_certificate(_encode_certificate_list([b"not-a-certificate"]))
    assert "did not parse" in (client._failed or "")
    assert client.peer_chain_der == []


# -- CertificateRequest parser -------------------------------------------


def test_certificate_request_reads_the_signature_algorithms():
    body = bytes([2, 1, 64]) + b"\x00\x04\x04\x03\x04\x01" + b"\x00\x00"
    assert _parse_certificate_request(body) == ((4, 3), (4, 1))


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        bytes([1, 64]) + b"\x00\x03\x04\x03\x04",      # odd algorithm length
        bytes([1, 64]) + b"\x00\x08\x04\x03",          # declared past the end
        bytes([1, 64]) + b"\x00\x02\x04\x03" + b"\x00\x09",  # CA list overruns
    ],
)
def test_certificate_request_parser_refuses_malformed_input(blob):
    assert _parse_certificate_request(blob) is None


def test_certificate_request_does_not_surface_the_authority_list():
    """The engine must not be handed material it could make a trust call on.

    Which chain to present belongs to the caller, and the role, UUID and CA
    rules belong to SamsungServerProfile (#33, #76).
    """
    body = bytes([1, 64]) + b"\x00\x02\x04\x03" + b"\x00\x04" + b"\x30\x02\x05\x00"
    assert _parse_certificate_request(body) == ((4, 3),)


# -- ordering and the client flight --------------------------------------


def test_server_key_exchange_before_the_certificate_is_refused():
    client = _client()
    client._state = "got_server_hello"
    client._handle_server_key_exchange(b"\x03\x00\x17\x01\x04")
    assert "before the certificate" in (client._failed or "")


def test_an_unoffered_signature_algorithm_is_refused():
    client = _client()
    client._state = "got_server_hello"
    _key, der = _leaf()
    client._handle_certificate(_encode_certificate_list([der]))
    client._client_random = b"c" * 32
    client._server_random = b"s" * 32
    point = b"\x04" + b"\x01" * 64
    # Hash 1 is MD5, which is not in the offer.
    body = (
        b"\x03\x00\x17" + bytes([len(point)]) + point
        + bytes([1, 3]) + b"\x00\x01\xff"
    )
    client._handle_server_key_exchange(body)
    assert "not offered" in (client._failed or "")


def test_a_rejecting_verify_callback_stops_the_flight():
    def refuse(_chain):
        raise ValueError("no")

    client = _client(verify_peer_chain=refuse)
    _key, der = _leaf()
    client._peer_chain = [der]
    client._state = "got_server_params"
    before = len(client._outbox)
    client._send_client_flight()
    assert "peer certificate rejected" in (client._failed or "")
    # Nothing went out: the credential must not reach a peer we refused.
    assert len(client._outbox) == before


def test_an_rsa_key_picks_an_rsa_signature_algorithm():
    _key, der = _leaf()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = DtlsCertClient([der], rsa_key)
    assert client._client_signature_algorithm() == (4, 1)


def test_a_server_narrowing_to_ecdsa_rules_out_our_rsa_key():
    _key, der = _leaf()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = DtlsCertClient([der], rsa_key)
    client._request_sig_algs = ((4, 3),)
    assert client._client_signature_algorithm() is None


def test_the_fragment_limit_falls_back_to_the_mtu():
    client = _client(mtu=600, max_fragment_length=None)
    # 600 less the IP, UDP, record and handshake headers.
    assert client._fragment_limit() == 600 - 28 - 13 - 12


def test_the_fragment_limit_follows_a_negotiated_length():
    client = _client(max_fragment_length=512)
    client._mfl_agreed = True
    assert client._fragment_limit() == 512 - 12


# -- found by the self-audit pass of 2026-10-26 --------------------------


def test_an_application_record_over_the_negotiated_length_is_refused():
    """RFC 6066 section 4 bounds every record, not only handshake ones.

    `post()` carries bodies up to 1024 bytes on its single-frame path, so an
    unchecked `send()` would put an over-length record on the wire and draw a
    `record_overflow`. Splitting is not available here: one CoAP message is
    one record, so a split hands the appliance two half-messages.
    """
    from smartthings_local.protocol._dtls_cert import DtlsError as CertDtlsError

    client = _client(max_fragment_length=512)
    client._mfl_agreed = True
    client._state = "established"
    with pytest.raises(CertDtlsError, match="exceeds the negotiated fragment"):
        client.send(b"x" * 513)


def test_an_application_record_at_the_negotiated_length_is_allowed():
    client = _client(max_fragment_length=512)
    client._mfl_agreed = True
    client._state = "established"

    class _Transform:
        def protect(self, epoch, seq, content_type, payload):
            return payload

    client._transform = _Transform()
    client._send_epoch = 1
    assert client.send(b"x" * 512) == 512


def test_an_unnegotiated_length_leaves_application_records_unbounded():
    client = _client(max_fragment_length=512)
    assert client.negotiated_fragment_length is None
    client._state = "established"

    class _Transform:
        def protect(self, epoch, seq, content_type, payload):
            return payload

    client._transform = _Transform()
    client._send_epoch = 1
    assert client.send(b"x" * 2000) == 2000


def test_a_second_certificate_is_refused():
    """The first leaf is the one the ServerKeyExchange is checked against.

    Letting a later Certificate overwrite it would mean verifying the key
    share against whichever leaf arrived last.
    """
    client = _client()
    client._state = "got_server_hello"
    _key, der = _leaf()
    client._handle_certificate(_encode_certificate_list([der]))
    assert client._failed is None
    first = client.peer_chain_der
    _key2, other = _leaf()
    client._handle_certificate(_encode_certificate_list([other]))
    assert "more than one Certificate" in (client._failed or "")
    assert client.peer_chain_der == first


def test_no_certificate_request_means_no_certificate_in_our_flight():
    """A client must not send Certificate or CertificateVerify unrequested.

    Both appliances measured on #20 do send a CertificateRequest, so this is
    not the path they take; an unrequested flight carrying them would simply
    be invalid.
    """
    client = _client(verify_peer_chain=None)
    _key, der = _leaf()
    client._peer_chain = [der]
    client._private_key = ec.generate_private_key(ec.SECP256R1())
    client._peer_point = (
        client._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    client._client_random = b"c" * 32
    client._server_random = b"s" * 32
    client._state = "got_server_params"
    assert client._certificate_requested is False
    client._send_client_flight()
    assert client._failed is None
    kinds = _handshake_kinds(client._outbox)
    assert 11 not in kinds, "Certificate went out unrequested"
    assert 15 not in kinds, "CertificateVerify went out unrequested"
    assert 16 in kinds, "ClientKeyExchange is still required"


def test_a_certificate_request_puts_both_messages_in_our_flight():
    client = _client(verify_peer_chain=None)
    _key, der = _leaf()
    client._peer_chain = [der]
    client._private_key = ec.generate_private_key(ec.SECP256R1())
    client._peer_point = (
        client._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    client._client_random = b"c" * 32
    client._server_random = b"s" * 32
    client._certificate_requested = True
    client._state = "got_server_params"
    client._send_client_flight()
    assert client._failed is None
    kinds = _handshake_kinds(client._outbox)
    assert 11 in kinds and 16 in kinds and 15 in kinds


def test_a_verify_callback_with_no_peer_chain_refuses_rather_than_skips():
    client = _client(verify_peer_chain=lambda _chain: None)
    client._state = "got_server_params"
    client._send_client_flight()
    assert "no certificate to verify" in (client._failed or "")


def _handshake_kinds(outbox: bytes) -> set[int]:
    """Handshake message types in an epoch-0 outbox, one record at a time."""
    kinds = set()
    offset = 0
    while offset + 13 <= len(outbox):
        length = int.from_bytes(outbox[offset + 11:offset + 13], "big")
        record = outbox[offset:offset + 13 + length]
        offset += 13 + length
        if record[0] == 22 and record[3:5] == b"\x00\x00":
            kinds.add(record[13])
    return kinds


# -- found on hardware 2026-10-26 ----------------------------------------


def test_the_leaf_public_key_is_read_through_openssl():
    """Register item E4, and the one defect hardware found.

    `cryptography`'s `load_der_x509_certificate` refuses both appliances'
    factory leaves while the pyOpenSSL path completes against the same
    certificate, so every arm failed at "server leaf certificate did not
    parse" until OpenSSL took over the parse. Nothing offline catches this:
    these tests mint their own chains with `cryptography`, so both ends agree.
    What is asserted here is the route, since the encoding that breaks it is
    not reproducible without a Samsung leaf.
    """
    import inspect

    from smartthings_local.protocol import _dtls_cert

    source = inspect.getsource(_dtls_cert._leaf_public_key)
    assert "crypto.load_certificate" in source
    assert "FILETYPE_ASN1" in source
    # The cryptography parser must not be the one reading a peer leaf. Its
    # name still appears in the docstring above, which is why this looks for
    # the call and the import rather than the bare name.
    module_source = inspect.getsource(_dtls_cert)
    assert "load_der_x509_certificate(" not in module_source
    assert "from cryptography.x509 import" not in module_source


def test_the_leaf_public_key_reads_a_valid_certificate():
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    from smartthings_local.protocol._dtls_cert import _leaf_public_key

    _key, der = _leaf()
    public_key = _leaf_public_key(der)
    assert isinstance(public_key, _ec.EllipticCurvePublicKey)


@pytest.mark.parametrize("junk", [b"", b"\x00", b"not-a-certificate", b"\x30\x82\xff\xff"])
def test_the_leaf_public_key_refuses_junk(junk):
    from smartthings_local.protocol._dtls_cert import _leaf_public_key

    assert _leaf_public_key(junk) is None
