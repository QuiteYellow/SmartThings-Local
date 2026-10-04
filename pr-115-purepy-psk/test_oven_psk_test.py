"""Local transport and acceptance tests; no appliance or credentials required."""
import errno
import socket
import struct
import threading

import cbor2
import pytest

import oven_psk_test as probe
from dtls_psk import DtlsPskClient


def record(payload):
    return b"\x17\xfe\xfd" + b"\0" * 8 + len(payload).to_bytes(2, "big") + payload


class FixtureClient:
    """Plaintext records isolate the probe from the DTLS engine."""
    instances = []
    shutdown_fails = False

    def __init__(self, *args, **kwargs):
        self.outbox = b""
        self.inbox = []
        self.state = "start"
        self.closed = False
        self.instances.append(self)

    def do_handshake(self):
        if self.state == "start":
            self.outbox += record(b"hello")
            self.state = "waiting"
        if self.inbox:
            assert self.inbox.pop(0) == b"hello"
            self.state = "established"
        if self.state != "established":
            raise probe.WantRead()

    def bio_read(self, capacity):
        if not self.outbox:
            raise probe.WantRead()
        value, self.outbox = self.outbox, b""
        return value

    def bio_write(self, data):
        self.inbox.append(data[13:])

    def send(self, data):
        self.outbox += record(data)

    def recv(self, capacity):
        if not self.inbox:
            raise probe.WantRead()
        return self.inbox.pop(0)

    def shutdown(self):
        self.closed = True
        if self.shutdown_fails:
            raise RuntimeError("secret key or host must not reach output")
        self.outbox += record(b"close_notify")

    def DTLSv1_get_timeout(self):
        return None


@pytest.fixture
def setup(monkeypatch):
    FixtureClient.instances = []
    monkeypatch.setattr(FixtureClient, "shutdown_fails", False)
    monkeypatch.setattr(probe, "DtlsPskClient", FixtureClient)
    monkeypatch.setattr(probe, "REPLY_TIMEOUT", 0.02)
    monkeypatch.setenv("PSK_HOST", "127.0.0.1")
    monkeypatch.setenv("PSK_IDENTITY_HEX", "00" * 16)
    monkeypatch.setenv("PSK_KEY_HEX", "11" * 16)
    monkeypatch.setenv("PSK_EXPECTED_DI", "fixture-device")
    monkeypatch.delenv("PSK_LOCAL_PORT", raising=False)
    return monkeypatch


def response(kind, code, mid, token, document):
    payload = document if isinstance(document, bytes) else cbor2.dumps(document)
    return bytes([(1 << 6) | (kind << 4) | len(token), code]) + struct.pack("!H", mid) + token + b"\xff" + payload


def run_peer(monkeypatch, mode):
    """Reply from another socket, as the appliance changes UDP source port."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    sender.bind(("127.0.0.1", 0))
    listener.settimeout(2)
    monkeypatch.setenv("PSK_PORT", str(listener.getsockname()[1]))
    received, errors = [], []

    def serve():
        try:
            hello, target = listener.recvfrom(65535)
            assert hello[13:] == b"hello"
            sender.sendto(record(b"hello"), target)
            request, source = listener.recvfrom(65535)
            assert source == target
            kind, code, mid, token, payload = probe._coap_parse(request[13:])
            assert (kind, code, payload) == (0, 1, b"")
            received.append(("source", source))
            if mode == "timeout":
                pass
            elif mode == "separate":
                response_mid = (mid + 1) & 0xFFFF
                sender.sendto(record(struct.pack("!BBH", 0x60, 0, mid)), target)
                sender.sendto(record(response(0, 69, response_mid, token, {"di": "fixture-device"})), target)
                ack, _ = listener.recvfrom(65535)
                assert ack[13:] == struct.pack("!BBH", 0x60, 0, response_mid)
                received.append("ACK")
            else:
                code = 128 if mode == "error" else 69
                body = {"di": "another-device"} if mode == "mismatch" else {"di": "fixture-device"}
                if mode == "missing_di":
                    body = {}
                if mode == "invalid_cbor":
                    body = b"\xff"
                if mode == "unrelated":
                    sender.sendto(record(response(2, 69, mid, b"bad", body)), target)
                sender.sendto(record(response(2, code, mid, token, body)), target)
            close, _ = listener.recvfrom(65535)
            assert close[13:] == b"close_notify"
            received.append("close_notify")
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()
            sender.close()

    thread = threading.Thread(target=serve)
    thread.start()
    result = probe.main()
    thread.join(3)
    assert not thread.is_alive()
    assert not errors
    return result, received


@pytest.mark.parametrize("mode", ["success", "separate", "unrelated"])
def test_udp_reply_from_different_port_and_correlated_response(setup, mode, capsys):
    result, received = run_peer(setup, mode)
    assert result == 0
    assert received[-1] == "close_notify"
    if mode == "separate":
        assert "ACK" in received
    output = capsys.readouterr().out
    assert "127.0.0.1" not in output
    assert "fixture-device" not in output
    assert "111111" not in output
    assert "sha256" not in output


@pytest.mark.parametrize("mode", ["timeout", "error", "mismatch", "missing_di", "invalid_cbor"])
def test_failed_read_returns_nonzero_and_closes(setup, mode):
    result, received = run_peer(setup, mode)
    assert result == 1
    assert received[-1] == "close_notify"
    assert FixtureClient.instances[-1].closed


def test_discards_datagrams_from_foreign_host():
    class Socket:
        def recvfrom(self, capacity):
            return b"foreign", ("127.0.0.2", 4567)

    class Client:
        def bio_write(self, data):
            pytest.fail("foreign host entered DTLS engine")

    probe._receive(Client(), Socket(), ("127.0.0.1", 1234))


def test_local_port_is_bound(setup):
    reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()
    setup.setenv("PSK_LOCAL_PORT", str(port))
    result, received = run_peer(setup, "success")
    assert result == 0
    assert received[0][1][1] == port


def test_local_port_bind_failure_cleans_up_without_sending(setup, capsys):
    class Socket:
        closed = False
        sent = []

        def bind(self, address):
            raise OSError(errno.EADDRINUSE, "private bind address")

        def sendto(self, data, address):
            self.sent.append(data)

        def close(self):
            self.closed = True

    class Client(DtlsPskClient):
        shutdown_attempted = False

        def shutdown(self):
            self.shutdown_attempted = True
            super().shutdown()

    sock = Socket()
    client = Client(bytes(range(16)), b"k" * 16)
    setup.setenv("PSK_PORT", "1234")
    setup.setenv("PSK_LOCAL_PORT", "4321")
    setup.setattr(probe.socket, "socket", lambda *args: sock)
    setup.setattr(probe, "DtlsPskClient", lambda *args, **kwargs: client)
    setup.setattr(probe, "_probe", lambda *args: pytest.fail("probe ran after bind failure"))
    assert probe.main() == 1
    assert sock.closed and client.shutdown_attempted
    assert not sock.sent
    assert "private bind address" not in capsys.readouterr().out


def test_shutdown_failure_still_closes_socket_and_fails(setup, capsys):
    class Socket:
        closed = False
        def bind(self, address):
            pass
        def settimeout(self, value):
            pass
        def close(self):
            self.closed = True

    sock = Socket()
    setup.setenv("PSK_PORT", "1234")
    setup.setattr(probe.socket, "socket", lambda *args: sock)
    setup.setattr(probe, "_probe", lambda *args: None)
    setup.setattr(FixtureClient, "shutdown_fails", True)
    assert probe.main() == 1
    assert sock.closed
    assert "secret key" not in capsys.readouterr().out


def test_handshake_error_still_attempts_shutdown_and_closes(setup, capsys):
    class Socket:
        closed = False
        def bind(self, address):
            pass
        def settimeout(self, value):
            pass
        def sendto(self, data, address):
            return len(data)
        def close(self):
            self.closed = True

    sock = Socket()
    setup.setenv("PSK_PORT", "1234")
    setup.setattr(probe.socket, "socket", lambda *args: sock)
    def fail(*args):
        raise RuntimeError("private device ID or PSK")
    setup.setattr(FixtureClient, "do_handshake", fail)
    assert probe.main() == 1
    assert sock.closed and FixtureClient.instances[-1].closed
    assert "private device" not in capsys.readouterr().out


@pytest.mark.parametrize("datagram", [b"", b"\x40\x45\0\0\xfd", b"\x40\x45\0\0\xff", b"\x49\x45\0\0", b"\x40\x45\0\0\x01"])
def test_rejects_invalid_coap(datagram):
    with pytest.raises(ValueError):
        probe._coap_parse(datagram)


@pytest.mark.parametrize("datagram", [
    b"\x60\0\x12\x34\xffpayload",
    b"\x60\0\x12\x34\0",
    b"\x61\0\x12\x34x",
])
def test_rejects_empty_coap_with_payload_option_or_token(datagram):
    with pytest.raises(ValueError, match="invalid empty CoAP message"):
        probe._coap_parse(datagram)


def test_parses_extended_option_length():
    datagram = b"\x60\x45\x12\x34\x0e\0\0" + b"x" * 269 + b"\xffpayload"
    assert probe._coap_parse(datagram) == (2, 69, 0x1234, b"", b"payload")
