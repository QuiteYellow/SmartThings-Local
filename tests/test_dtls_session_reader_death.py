"""Reader-thread death visibility (QuiteYellow/SmartThings-Local#37).

A connected UDP socket surfaces ICMP errors on recv; before this the
reader exited silently on the first one and every later request waited
out its full timeout against a session nobody was reading. These tests
pin the three behaviours that fixed it: advisory ICMP errnos keep the
reader alive, a real socket error exits with a WARNING and clears
_reader_running, and callers then fail fast with SessionClosedError.
"""
import errno
import logging
import threading
import time

import pytest
from OpenSSL import SSL

from smartthings_local.errors import SessionClosedError
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.coap import (
    BLOCK2,
    BLOCK2_DUPLICATE,
    CF_CBOR,
    CONTENT_FORMAT,
    TYPE_ACK,
    TYPE_CON,
    block_value,
    build_coap,
    build_empty_ack,
    option_values,
    parse_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

_LOGGER_NAME = "smartthings_local.protocol.dtls_session"


class _NullAuth:
    """Structural AuthenticationProvider — never configured, we skip connect()."""

    def configure_context(self, _context):
        return None


class _FakeConn:
    """Minimal stand-in for SSL.Connection: each datagram written to the
    BIO surfaces as one decrypted packet on the next recv(), then
    WantReadError like a drained DTLS record buffer."""

    def __init__(self):
        self._decrypted = []
        self.sent = []

    def bio_write(self, datagram):
        self._decrypted.append(datagram)

    def recv(self, _n):
        if self._decrypted:
            return self._decrypted.pop(0)
        raise SSL.WantReadError()

    def bio_read(self, _n):
        return b""

    def send(self, datagram):
        self.sent.append(datagram)

    def shutdown(self):
        return None


class _FakeSock:
    """Scripted UDP socket. Each step is bytes to return, an exception to
    raise, or a callable to run (then a timeout, so the loop re-checks
    _stop). An exhausted script blocks like a real recv timeout; once
    close()d it raises EBADF the way a closed fd does."""

    def __init__(self, steps=()):
        self._steps = list(steps)
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def recv(self, _n):
        if self.closed:
            raise OSError(errno.EBADF, "bad file descriptor")
        if self._steps:
            step = self._steps.pop(0)
            if callable(step):
                step()
                raise TimeoutError()
            if isinstance(step, BaseException):
                raise step
            return step
        time.sleep(0.01)
        raise TimeoutError()

    def send(self, data):
        return len(data)

    def close(self):
        self.closed = True


def _make_session():
    sess = DtlsCoapSession("host", 1234, auth=_NullAuth())
    sess.conn = _FakeConn()
    return sess


def _run_reader(sess, steps, timeout=2.0):
    sess.sock = _FakeSock(steps)
    sess.start_reader()
    sess._reader_thread.join(timeout)
    assert not sess._reader_thread.is_alive(), "reader thread did not exit"


def test_advisory_icmp_error_does_not_kill_reader(caplog):
    sess = _make_session()
    dispatched = []
    sess._dispatch_coap = dispatched.append

    with caplog.at_level(logging.DEBUG, logger=_LOGGER_NAME):
        _run_reader(sess, [
            OSError(errno.ECONNREFUSED, "connection refused"),
            b"\x60\x00\x00\x00",              # survives, gets dispatched
            lambda: sess._stop.set(),         # end the loop cleanly
        ])

    assert dispatched == [b"\x60\x00\x00\x00"]
    assert not sess._reader_running.is_set()
    assert any(r.levelno == logging.DEBUG and "advisory" in r.getMessage()
               for r in caplog.records)
    # An advisory errno is not a real exit — no WARNING.
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


def test_fatal_socket_error_exits_with_warning(caplog):
    sess = _make_session()

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        _run_reader(sess, [OSError(errno.EBADF, "bad file descriptor")])

    assert not sess._reader_running.is_set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "reader exiting" in warnings[0].getMessage()


def test_request_fails_fast_after_reader_death():
    sess = _make_session()
    _run_reader(sess, [OSError(errno.EBADF, "bad file descriptor")])
    assert not sess._reader_running.is_set()

    start = time.monotonic()
    with pytest.raises(SessionClosedError):
        sess.get(["oic", "d"], timeout=10.0)
    elapsed = time.monotonic() - start
    # The whole point: no waiting out the request timeout.
    assert elapsed < 1.0, f"get() waited {elapsed:.2f}s instead of failing fast"


def test_close_does_not_log_warning_on_teardown(caplog):
    sess = _make_session()
    sess.sock = _FakeSock()          # empty script: blocks on recv
    sess.start_reader()
    time.sleep(0.05)                 # let the reader reach recv

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        sess.close()
        sess._reader_thread.join(2.0)

    assert not sess._reader_thread.is_alive()
    assert not sess._reader_running.is_set()
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


def test_check_live_without_reader_matches_old_conn_guard():
    sess = _make_session()          # conn set, reader never started
    assert sess._reader_thread is None
    sess._check_live()              # must not raise — config-flow behaviour

    sess.conn = None
    with pytest.raises(SessionClosedError):
        sess._check_live()


def test_dispatch_empty_ack_then_separate_con_resolves_and_acks_response():
    sess = _make_session()
    token = b'token'
    event = threading.Event()
    container = {}
    sess._pending[token] = (event, container)
    sess._pending_get_mids[0x1234] = (event, container)

    sess._dispatch_coap(build_empty_ack(0x1235))
    assert not event.is_set()

    sess._dispatch_coap(build_empty_ack(0x1234))
    assert event.is_set()
    assert container['acknowledged'] is True
    assert sess.conn.sent == []
    event.clear()

    sess._dispatch_coap(build_coap(
        TYPE_CON,
        0x45,
        0xBEEF,
        token,
        [(CONTENT_FORMAT, CF_CBOR)],
        b'body',
    ))
    assert event.is_set()
    assert container['payload'] == b'body'
    assert parse_coap(sess.conn.sent[-1]) == (
        TYPE_ACK,
        0,
        0xBEEF,
        b'',
        [],
        b'',
    )


def test_dispatch_piggyback_ack_resolves_without_sending_another_ack():
    sess = _make_session()
    token = b'token'
    event = threading.Event()
    container = {}
    sess._pending[token] = (event, container)

    sess._dispatch_coap(build_coap(
        TYPE_ACK,
        0x45,
        0x1234,
        token,
        [(CONTENT_FORMAT, CF_CBOR)],
        b'body',
    ))
    assert event.is_set()
    assert container['payload'] == b'body'
    assert sess.conn.sent == []


def test_get_uses_one_token_and_shared_block2_continuation_builder():
    sess = _make_session()
    requests = []

    def respond(datagram):
        request = parse_coap(datagram)
        requests.append(request)
        _mtype, _code, mid, token, options, _payload = request
        requested_block = option_values(options, BLOCK2)
        number = 0 if not requested_block else \
            int.from_bytes(requested_block[0], 'big') >> 4
        response_payload = b'a' * 16 if number == 0 else b'done'
        response_options = [
            (BLOCK2, block_value(number, number == 0, 0)),
        ]
        # Some RFC 7959 peers only repeat representation metadata on block 0.
        # The connected session historically accepted that shape.
        if number == 0:
            response_options.append((CONTENT_FORMAT, CF_CBOR))
        sess._dispatch_coap(build_coap(
            TYPE_ACK,
            0x45,
            mid,
            token,
            response_options,
            response_payload,
        ))

    sess._send_dgram = respond
    sess.pace = lambda: None

    code, payload = sess.get(['oic', 'res'], query=('if=oic.if.baseline',))
    assert code == 0x45
    assert payload == b'a' * 16 + b'done'
    assert len(requests) == 2
    assert requests[0][3] == requests[1][3]
    assert option_values(requests[0][4], BLOCK2) == ()
    assert option_values(requests[1][4], BLOCK2) == (
        block_value(1, 0, 0),
    )


def test_stale_block_does_not_clear_interleaved_current_block(monkeypatch):
    sess = _make_session()
    requests = []
    state = {
        'injected_current': False,
        'mid': None,
        'token': None,
    }

    def respond(datagram):
        _mtype, _code, mid, token, options, _payload = parse_coap(datagram)
        requested = option_values(options, BLOCK2)
        number = 0 if not requested else \
            int.from_bytes(requested[0], 'big') >> 4
        requests.append(number)
        state['mid'] = mid
        state['token'] = token

        if number == 0:
            sess._dispatch_coap(build_coap(
                TYPE_ACK,
                0x45,
                mid,
                token,
                [(BLOCK2, block_value(0, 1, 0))],
                b'a' * 16,
            ))
        elif number == 1 and requests.count(1) == 1:
            # The first answer to block 1 is a delayed duplicate of block 0.
            sess._dispatch_coap(build_coap(
                TYPE_ACK,
                0x45,
                mid,
                token,
                [(BLOCK2, block_value(0, 1, 0))],
                b'a' * 16,
            ))

    original_add_response = dtls_session.Block2Accumulator.add_response

    def add_response_with_interleaved_current(accumulator, message):
        status = original_add_response(accumulator, message)
        if status == BLOCK2_DUPLICATE and not state['injected_current']:
            state['injected_current'] = True
            # Simulate the reader dispatching the requested block after the GET
            # thread took its stale snapshot but before it clears the slot.
            sess._dispatch_coap(build_coap(
                TYPE_ACK,
                0x45,
                state['mid'],
                state['token'],
                [(BLOCK2, block_value(1, 0, 0))],
                b'done',
            ))
        return status

    monkeypatch.setattr(
        dtls_session.Block2Accumulator,
        'add_response',
        add_response_with_interleaved_current,
    )
    sess._send_dgram = respond
    sess.pace = lambda: None

    assert sess.get(['oic', 'res'], timeout=0.2) == (
        0x45,
        b'a' * 16 + b'done',
    )
    assert requests == [0, 1]


def test_empty_ack_stops_get_retransmit_until_separate_response(
        monkeypatch):
    monkeypatch.setattr(dtls_session, '_BLOCK_ACK_TIMEOUT', 0.01)
    sess = _make_session()
    requests = []
    timers = []

    def respond(datagram):
        mtype, code, mid, token, _options, _payload = parse_coap(datagram)
        if mtype == TYPE_ACK and code == 0:
            return
        requests.append(datagram)
        sess._dispatch_coap(build_empty_ack(mid))
        timer = threading.Timer(
            0.04,
            lambda: sess._dispatch_coap(build_coap(
                TYPE_CON,
                0x45,
                0xBEEF,
                token,
                [],
                b'body',
            )),
        )
        timers.append(timer)
        timer.start()

    sess._send_dgram = respond
    try:
        assert sess.get(['oic', 'res'], timeout=0.2) == (0x45, b'body')
    finally:
        for timer in timers:
            timer.join(1.0)
    assert len(requests) == 1


def test_get_preserves_mid_transfer_error_payload_contract():
    sess = _make_session()

    def respond(datagram):
        _mtype, _code, mid, token, options, _payload = parse_coap(datagram)
        requested_block = option_values(options, BLOCK2)
        number = 0 if not requested_block else \
            int.from_bytes(requested_block[0], 'big') >> 4
        if number == 0:
            code = 0x45
            response_options = [(BLOCK2, block_value(0, 1, 0))]
            payload = b'a' * 16
        else:
            code = 0x80
            response_options = []
            payload = b'error'
        sess._dispatch_coap(build_coap(
            TYPE_ACK,
            code,
            mid,
            token,
            response_options,
            payload,
        ))

    sess._send_dgram = respond
    sess.pace = lambda: None
    assert sess.get(['oic', 'res']) == (0x80, b'a' * 16 + b'error')


@pytest.mark.parametrize('method', ('get', 'post'))
def test_request_rechecks_reader_after_pending_registration(method):
    sess = _make_session()
    sess._reader_thread = object()
    sess._reader_running.set()
    original_check_live = sess._check_live
    checks = 0
    sent = []

    def fail_on_post_registration_snapshot():
        nonlocal checks
        checks += 1
        if checks == 2:
            sess._reader_running.clear()
        original_check_live()

    sess._check_live = fail_on_post_registration_snapshot
    sess._send_dgram = sent.append
    with pytest.raises(SessionClosedError):
        if method == 'get':
            sess.get(['oic', 'res'])
        else:
            sess.post(['mode', 'vs', '0'], b'body')

    assert checks == 2
    assert sent == []
    assert sess._pending == {}
