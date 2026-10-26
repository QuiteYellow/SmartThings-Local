"""Real DTLS interoperability for the certificate engine, against OpenSSL.

Needs no appliance and no Samsung credential: OpenSSL acts as the DTLS server
over a memory BIO with a locally minted P-256 chain, so these run in CI. The
pattern follows `test_dtls_psk_interop.py`, which @KRZ303 wrote for #116.

What each test pins down:

- the handshake completes and application data crosses both ways, which
  exercises the ClientHello profile, the server chain parse, the
  ServerKeyExchange signature check, our Certificate and CertificateVerify,
  and the AES-GCM record layer;
- `max_fragment_length` is offered, echoed, and then honoured on our own
  outbound records, which is the only reason this engine exists;
- a server whose ServerKeyExchange signature does not match the certificate it
  presented is refused, because that signature is what binds the ephemeral key
  share to the peer's identity.
"""
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from OpenSSL import SSL, crypto

from smartthings_local.protocol._dtls_cert import DtlsCertClient, DtlsError

_CIPHERS = b"ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0"


def _certificate(
    common_name, *, ca_key=None, ca_subject=None, is_ca=False, padding_bytes=0
):
    """Mint one P-256 certificate, self-signed unless a CA key is supplied."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signer_key = ca_key or key
    signer_subject = ca_subject or subject
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signer_subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=36500))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if padding_bytes:
        # Grow the certificate past a fragment length without inventing an
        # invalid name: a common name is capped at 64 characters.
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"),
                b"\x04" + bytes([0x82, padding_bytes >> 8, padding_bytes & 0xFF])
                + b"p" * padding_bytes,
            ),
            critical=False,
        )
    return key, builder.sign(signer_key, hashes.SHA256())


def _server_context(key, certificate):
    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(_CIPHERS)
    context.use_privatekey(
        crypto.PKey.from_cryptography_key(key)
    )
    context.use_certificate(crypto.X509.from_cryptography(certificate))
    # Ask for a client certificate without judging it: what is under test here
    # is our flight, not OpenSSL's trust decision.
    context.set_verify(SSL.VERIFY_PEER, lambda *_: True)
    return context


def _pump(client, server, turns=120):
    """Run both ends to completion over memory BIOs, one record per datagram."""
    done = [False, False]
    client_records = []
    for _turn in range(turns):
        for index, sender, receiver in ((0, client, server), (1, server, client)):
            try:
                sender.do_handshake()
                done[index] = True
            except SSL.WantReadError:
                # pyOpenSSL's WantReadError subclasses SSL.Error, which is what
                # DtlsError aliases, so it has to be caught first or a plain
                # want-read reads as a session failure.
                pass
            try:
                data = sender.bio_read(65535)
            except SSL.WantReadError:
                continue
            offset = 0
            while offset + 13 <= len(data):
                length = int.from_bytes(data[offset + 11:offset + 13], "big")
                record = data[offset:offset + 13 + length]
                offset += 13 + length
                if index == 0:
                    client_records.append(record)
                receiver.bio_write(record)
        if all(done):
            return client_records
    raise AssertionError(f"handshake did not complete: {done}")


@pytest.mark.parametrize("fragment_length", [None, 512])
def test_openssl_certificate_interoperability(fragment_length):
    ca_key, ca_cert = _certificate("interop-ca", is_ca=True)
    server_key, server_cert = _certificate(
        "interop-server", ca_key=ca_key, ca_subject=ca_cert.subject
    )
    client_key, client_cert = _certificate(
        "interop-client", ca_key=ca_key, ca_subject=ca_cert.subject
    )

    seen = []
    client = DtlsCertClient(
        [client_cert.public_bytes(serialization.Encoding.DER)],
        client_key,
        max_fragment_length=fragment_length,
        verify_peer_chain=seen.append,
    )
    server = SSL.Connection(_server_context(server_key, server_cert), None)
    server.set_accept_state()

    _pump(client, server)

    # The callback saw the chain the server actually presented.
    assert len(seen) == 1
    assert seen[0][0] == server_cert.public_bytes(serialization.Encoding.DER)
    assert client.peer_chain_der[0] == seen[0][0]

    # Application data both ways over the AES-GCM records.
    client.send(b"GET /oic/d")
    server.bio_write(client.bio_read(65535))
    assert server.recv(65535) == b"GET /oic/d"
    server.send(b"2.05 content")
    client.bio_write(server.bio_read(65535))
    assert client.recv(65535) == b"2.05 content"


def test_offered_fragment_length_is_echoed_and_honoured():
    """The whole point: the server agrees, and our own records then fit.

    Our client certificate is padded past the fragment length with a long
    subject so the Certificate message has to span several records. Without
    outbound fragmentation one record would carry all of it.
    """
    ca_key, ca_cert = _certificate("interop-ca", is_ca=True)
    server_key, server_cert = _certificate(
        "interop-server", ca_key=ca_key, ca_subject=ca_cert.subject
    )
    client_key, client_cert = _certificate(
        "interop-client-large",
        ca_key=ca_key,
        ca_subject=ca_cert.subject,
        padding_bytes=900,
    )
    chain = [
        client_cert.public_bytes(serialization.Encoding.DER),
        ca_cert.public_bytes(serialization.Encoding.DER),
    ]

    client = DtlsCertClient(chain, client_key, max_fragment_length=512)
    server = SSL.Connection(_server_context(server_key, server_cert), None)
    server.set_accept_state()
    records = _pump(client, server)

    assert client.negotiated_fragment_length == 512

    # Every record we sent fits the negotiated length, headers included.
    oversized = [record for record in records if len(record) - 13 > 512]
    assert not oversized, [len(record) for record in oversized]

    # And the Certificate really did span more than one record.
    certificate_fragments = [
        record for record in records
        if record[0] == 22 and record[3:5] == b"\x00\x00" and record[13] == 11
    ]
    assert len(certificate_fragments) > 1
    offsets = [
        int.from_bytes(record[19:22], "big") for record in certificate_fragments
    ]
    assert offsets == sorted(offsets)
    assert offsets[0] == 0


def test_server_key_exchange_signature_is_verified():
    """A key share signed by a key other than the presented leaf is refused.

    OpenSSL will not produce that, so the server's ServerKeyExchange signature
    is corrupted on the wire instead, which is the same thing from our side.
    """
    ca_key, ca_cert = _certificate("interop-ca", is_ca=True)
    server_key, server_cert = _certificate(
        "interop-server", ca_key=ca_key, ca_subject=ca_cert.subject
    )
    client_key, client_cert = _certificate(
        "interop-client", ca_key=ca_key, ca_subject=ca_cert.subject
    )
    client = DtlsCertClient(
        [client_cert.public_bytes(serialization.Encoding.DER)], client_key
    )
    server = SSL.Connection(_server_context(server_key, server_cert), None)
    server.set_accept_state()

    with pytest.raises(DtlsError, match="signature did not verify"):
        for _turn in range(120):
            for index, sender, receiver in ((0, client, server), (1, server, client)):
                try:
                    sender.do_handshake()
                except SSL.WantReadError:
                    pass
                try:
                    data = sender.bio_read(65535)
                except SSL.WantReadError:
                    continue
                offset = 0
                while offset + 13 <= len(data):
                    length = int.from_bytes(data[offset + 11:offset + 13], "big")
                    record = bytearray(data[offset:offset + 13 + length])
                    offset += 13 + length
                    if (index == 1 and record[0] == 22
                            and record[3:5] == b"\x00\x00" and record[13] == 12):
                        # Flip the last byte of the signature.
                        record[-1] ^= 0xFF
                    receiver.bio_write(bytes(record))


def test_a_server_that_asks_for_no_certificate_still_completes():
    """OpenSSL without `set_verify` sends no CertificateRequest.

    Our flight must then carry neither Certificate nor CertificateVerify, and
    the handshake must still complete. Both appliances on #20 do ask, so this
    pins the other branch rather than the one they take.
    """
    ca_key, ca_cert = _certificate("interop-ca", is_ca=True)
    server_key, server_cert = _certificate(
        "interop-server", ca_key=ca_key, ca_subject=ca_cert.subject
    )
    client_key, client_cert = _certificate(
        "interop-client", ca_key=ca_key, ca_subject=ca_cert.subject
    )
    client = DtlsCertClient(
        [client_cert.public_bytes(serialization.Encoding.DER)], client_key
    )

    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(_CIPHERS)
    context.use_privatekey(crypto.PKey.from_cryptography_key(server_key))
    context.use_certificate(crypto.X509.from_cryptography(server_cert))
    server = SSL.Connection(context, None)
    server.set_accept_state()

    records = _pump(client, server)
    kinds = {
        record[13] for record in records
        if record[0] == 22 and record[3:5] == b"\x00\x00"
    }
    assert 11 not in kinds and 15 not in kinds
    assert 16 in kinds

    client.send(b"ping")
    server.bio_write(client.bio_read(65535))
    assert server.recv(65535) == b"ping"
