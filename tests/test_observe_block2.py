"""Blockwise OBSERVE notifications (QuiteYellow/SmartThings-Local#39).

A notification carries only the first block of the representation
(RFC 7959 §2.6). Before this, _dispatch_coap handed that first block
straight to on_notification and the consumer decoded a truncated CBOR
buffer. These tests pin the replacement: a truncated notification is
withheld, the resource is re-read from block 0 under a fresh one-shot
token, and only the reassembled representation reaches the callback.

The re-read starts at block 0 rather than continuing at NUM=1 for two
reasons, both recorded on #39: RFC 7959 §3.4 forbids continuing on the
observation's token, and the appliance tested there dropped a transfer
that opened at NUM>0 under a token it had not seen.
"""
import logging
import socket
import threading
import time

import pytest
from OpenSSL import SSL

from smartthings_local.errors import BlockwiseError
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.coap import (
    BLOCK2, ETAG, METHOD_GET, OBSERVE, TYPE_ACK, TYPE_NON,
    block_fields, block_value, build_coap, parse_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession

SZX = 6  # 1024-byte blocks, the only size these appliances honour
_LOGGER_NAME = "smartthings_local.protocol.dtls_session"


class _NullAuth:
    """Structural AuthenticationProvider — never configured, we skip connect()."""

    def configure_context(self, _context):
        return None


class _LoopbackConn:
    """SSL.Connection stand-in that answers requests from a script.

    `responder` is called with each parsed request and returns a list of
    CoAP datagrams to hand back (possibly empty, to model a silent
    device). Responses surface on recv() the way decrypted records do.
    """

    def __init__(self, responder):
        self._responder = responder
        self._inbox = []
        self._lock = threading.Lock()
        self.sent = []

    # -- client -> device
    def send(self, datagram):
        self.sent.append(parse_coap(datagram))
        for reply in self._responder(parse_coap(datagram)):
            with self._lock:
                self._inbox.append(reply)
        return len(datagram)

    def bio_read(self, _n):
        return b""

    # -- device -> client
    def inject(self, datagram):
        """Push a device-initiated frame (an OBSERVE notification)."""
        with self._lock:
            self._inbox.append(datagram)

    def bio_write(self, _datagram):
        return None

    def recv(self, _n):
        with self._lock:
            if self._inbox:
                return self._inbox.pop(0)
        raise SSL.WantReadError()

    def shutdown(self):
        return None

    def pending(self):
        with self._lock:
            return len(self._inbox)


class _PumpSock:
    """UDP socket stand-in. recv() returns a dummy datagram whenever the
    connection has something decrypted waiting, so the reader loop keeps
    pumping; otherwise it times out like a real socket."""

    def __init__(self, conn):
        self._conn = conn
        self.closed = False

    def settimeout(self, _value):
        return None

    def recv(self, _n):
        for _ in range(20):
            if self.closed:
                raise OSError("closed")
            if self._conn.pending():
                return b"\x00"
            time.sleep(0.005)
        raise socket.timeout()

    def send(self, data):
        return len(data)

    def close(self):
        self.closed = True


def _make_session(responder, **kwargs):
    calls = []
    sess = DtlsCoapSession(
        "host", 1234, auth=_NullAuth(),
        on_notification=lambda href, payload: calls.append((href, payload)),
        **kwargs)
    sess.conn = _LoopbackConn(responder)
    sess.sock = _PumpSock(sess.conn)
    sess.start_reader()
    return sess, calls


def _notification(tok, payload, *, block2=None, mtype=TYPE_NON, obs=1):
    opts = [(OBSERVE, bytes([obs]))]
    if block2 is not None:
        opts.append((BLOCK2, block2))
    return build_coap(mtype, 0x45, 0x1234, tok, opts, payload)


def _content(tok, mid, payload, *, block2=None, etag=None):
    opts = []
    if etag is not None:
        opts.append((ETAG, etag))
    if block2 is not None:
        opts.append((BLOCK2, block2))
    return build_coap(TYPE_ACK, 0x45, mid, tok, opts, payload)


def _requested_block(request):
    """(num, szx) the request asked for, or (0, None) with no Block2."""
    _, _, _, _, opts, _ = request
    b2 = [v for n, v in opts if n == BLOCK2]
    if not b2:
        return 0, None
    num, _, szx = block_fields(b2[0])
    return num, szx


def _wait_for(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _close(sess):
    sess.close()
    sess.join()


# --------------------------------------------------------------------
# The no-regression case


def test_single_block_notification_is_delivered_inline():
    sess, calls = _make_session(lambda request: [])
    try:
        tok = sess.subscribe(["oven", "vs", "0"])
        sess.conn.inject(_notification(tok, b"\xa1\x01\x02"))

        assert _wait_for(lambda: calls)
        assert calls == [("/oven/vs/0", b"\xa1\x01\x02")]
        # The subscribe GET is the only thing we sent — no refetch.
        assert len(sess.conn.sent) == 1
    finally:
        _close(sess)


def test_complete_block_zero_notification_is_delivered_inline():
    """Block2 present but M=0 and NUM=0 means the whole representation
    fit in one block. Nothing to fetch back."""
    sess, calls = _make_session(lambda request: [])
    try:
        tok = sess.subscribe(["oven", "vs", "0"])
        sess.conn.inject(
            _notification(tok, b"\xa1\x01\x02",
                          block2=block_value(0, 0, SZX)))

        assert _wait_for(lambda: calls)
        assert calls == [("/oven/vs/0", b"\xa1\x01\x02")]
        assert len(sess.conn.sent) == 1
    finally:
        _close(sess)


# --------------------------------------------------------------------
# The fix


def test_truncated_notification_is_refetched_and_reassembled():
    blocks = [b"A" * 1024, b"B" * 40]

    def responder(request):
        _mtype, code, mid, tok, opts, _ = request
        if code != METHOD_GET or any(n == OBSERVE for n, _ in opts):
            return []           # the subscribe registration itself
        num, _ = _requested_block(request)
        more = 1 if num + 1 < len(blocks) else 0
        return [_content(tok, mid, blocks[num],
                         block2=block_value(num, more, SZX))]

    sess, calls = _make_session(responder)
    try:
        tok = sess.subscribe(["mode", "vs", "0"])
        sess.conn.inject(
            _notification(tok, blocks[0],
                          block2=block_value(0, 1, SZX)))

        assert _wait_for(lambda: calls), "callback never fired"
        assert calls == [("/mode/vs/0", b"".join(blocks))]
    finally:
        _close(sess)


def test_refetch_uses_a_fresh_one_shot_token_not_the_observe_token():
    """RFC 7959 §3.4: the requests for additional blocks cannot use the
    token of the observation relationship."""
    blocks = [b"A" * 1024, b"B" * 40]

    def responder(request):
        _mtype, _code, mid, tok, opts, _ = request
        if any(n == OBSERVE for n, _ in opts):
            return []
        num, _ = _requested_block(request)
        more = 1 if num + 1 < len(blocks) else 0
        return [_content(tok, mid, blocks[num],
                         block2=block_value(num, more, SZX))]

    sess, calls = _make_session(responder)
    try:
        observe_tok = sess.subscribe(["mode", "vs", "0"])
        assert len(observe_tok) == 8, (
            "OBSERVE registrations use 8-byte tokens: the observer lookup "
            "matches on the incoming token's length, so a short token "
            "collides with a held one's prefix")
        sess.conn.inject(
            _notification(observe_tok, blocks[0],
                          block2=block_value(0, 1, SZX)))
        assert _wait_for(lambda: calls)

        refetch = [r for r in sess.conn.sent
                   if not any(n == OBSERVE for n, _ in r[4])]
        assert refetch, "no refetch request was sent"
        tokens = {r[3] for r in refetch}
        assert observe_tok not in tokens
        assert all(len(t) == 4 for t in tokens), "one-shot tokens are 4-byte"
        assert len(tokens) == 1, "the transfer must hold one token throughout"

        # And the transfer restarts at block 0 rather than continuing at 1.
        assert _requested_block(refetch[0])[0] == 0
        assert [_requested_block(r)[0] for r in refetch] == [0, 1]
        # No Observe option on a continuation request.
        assert not any(n == OBSERVE for r in refetch for n, _ in r[4])
    finally:
        _close(sess)


def test_silent_device_drops_the_notification_without_delivering_a_partial():
    sess, calls = _make_session(lambda request: [])
    try:
        tok = sess.subscribe(["mode", "vs", "0"])
        sess.conn.inject(
            _notification(tok, b"A" * 1024,
                          block2=block_value(0, 1, SZX)))
        # Give the worker a chance to try and fail. _BLOCK_ACK_TIMEOUT is
        # 4s per attempt, so we only need to see that nothing partial got
        # through in the meantime.
        assert not _wait_for(lambda: calls, timeout=0.6)
        assert sess._reader_thread.is_alive(), "reader must survive"
    finally:
        _close(sess)


def test_non_2xx_refetch_is_dropped_rather_than_delivered():
    def responder(request):
        _mtype, _code, mid, tok, opts, _ = request
        if any(n == OBSERVE for n, _ in opts):
            return []
        return [build_coap(TYPE_ACK, 0x84, mid, tok, [], b"")]

    sess, calls = _make_session(responder)
    try:
        tok = sess.subscribe(["mode", "vs", "0"])
        sess.conn.inject(
            _notification(tok, b"A" * 1024,
                          block2=block_value(0, 1, SZX)))
        assert not _wait_for(lambda: calls, timeout=0.6)
    finally:
        _close(sess)


def test_notification_burst_collapses_to_one_refetch_per_resource():
    blocks = [b"A" * 1024, b"B" * 40]
    gate = threading.Event()

    def responder(request):
        _mtype, _code, mid, tok, opts, _ = request
        if any(n == OBSERVE for n, _ in opts):
            return []
        gate.wait(2.0)          # hold the first transfer open
        num, _ = _requested_block(request)
        more = 1 if num + 1 < len(blocks) else 0
        return [_content(tok, mid, blocks[num],
                         block2=block_value(num, more, SZX))]

    sess, calls = _make_session(responder)
    try:
        tok = sess.subscribe(["mode", "vs", "0"])
        for seq in range(5):
            sess.conn.inject(
                _notification(tok, blocks[0], obs=seq + 1,
                              block2=block_value(0, 1, SZX)))
        # Five notifications, one queue entry: latest wins per href.
        assert _wait_for(lambda: sess._refetch_pending or sess.conn.sent[1:])
        assert len(sess._refetch_pending) <= 1
        gate.set()

        assert _wait_for(lambda: calls)
        assert _wait_for(
            lambda: not sess._refetch_pending and len(calls) >= 1)
        time.sleep(0.2)
        # Two transfers at most: the one in flight when the burst landed,
        # plus one for the final state.
        starts = [r for r in sess.conn.sent
                  if not any(n == OBSERVE for n, _ in r[4])
                  and _requested_block(r)[0] == 0]
        assert len(starts) <= 2, f"{len(starts)} refetches for one burst"
        assert calls[-1] == ("/mode/vs/0", b"".join(blocks))
    finally:
        gate.set()
        _close(sess)


def test_close_during_a_queued_refetch_stops_the_worker():
    sess, _calls = _make_session(lambda request: [])
    tok = sess.subscribe(["mode", "vs", "0"])
    sess.conn.inject(
        _notification(tok, b"A" * 1024, block2=block_value(0, 1, SZX)))
    assert _wait_for(lambda: sess._refetch_thread is not None)

    sess.close()
    sess.join()     # hangs if the worker outlives the session
    assert not sess._refetch_thread.is_alive()


def test_refetch_worker_exits_when_the_reader_dies():
    sess, _calls = _make_session(lambda request: [])
    tok = sess.subscribe(["mode", "vs", "0"])
    sess.conn.inject(
        _notification(tok, b"A" * 1024, block2=block_value(0, 1, SZX)))
    assert _wait_for(lambda: sess._refetch_thread is not None)

    # Kill the reader the way a socket error does, without close().
    sess.sock.closed = True
    assert _wait_for(lambda: not sess._reader_running.is_set(), timeout=5.0)
    sess._refetch_thread.join(6.0)
    assert not sess._refetch_thread.is_alive()
    sess.close()


def test_debug_bridge_promotes_the_refetch_outcome_to_info(monkeypatch, caplog):
    """The hardware validation for #39 reads this line to confirm which
    token the re-read used, so it has to survive the bridge's INFO
    default. Without DEBUG_BRIDGE it stays at debug."""
    monkeypatch.setattr(dtls_session, "DEBUG_BRIDGE", True)
    blocks = [b"A" * 1024, b"B" * 40]

    def responder(request):
        _mtype, _code, mid, tok, opts, _ = request
        if any(n == OBSERVE for n, _ in opts):
            return []
        num, _ = _requested_block(request)
        more = 1 if num + 1 < len(blocks) else 0
        return [_content(tok, mid, blocks[num],
                         block2=block_value(num, more, SZX))]

    sess, calls = _make_session(responder)
    try:
        with caplog.at_level(logging.INFO, logger=_LOGGER_NAME):
            tok = sess.subscribe(["mode", "vs", "0"])
            sess.conn.inject(
                _notification(tok, blocks[0], block2=block_value(0, 1, SZX)))
            assert _wait_for(lambda: calls)

        line = next((r.getMessage() for r in caplog.records
                     if r.getMessage().startswith("refetch /mode/vs/0")), None)
        assert line is not None, "no refetch line at INFO"
        assert "blocks=2" in line
        assert f"bytes={sum(len(b) for b in blocks)}" in line
        assert line.endswith("ok")
        # The token in the line is the one-shot token, not the observe one.
        assert f"tok={tok.hex()} " not in line
    finally:
        _close(sess)


# --------------------------------------------------------------------
# Shared Block2 loop hardening


def test_stale_block_number_is_not_concatenated():
    """A retransmit of block 0 arriving while we wait for block 1 must
    not be appended as if it were block 1."""
    served = []

    def responder(request):
        _mtype, _code, mid, tok, _opts, _ = request
        num, _ = _requested_block(request)
        served.append(num)
        if num == 0:
            return [_content(tok, mid, b"A" * 1024,
                             block2=block_value(0, 1, SZX))]
        # Answer the block-1 request with a duplicate of block 0 first.
        return [
            _content(tok, mid, b"A" * 1024, block2=block_value(0, 1, SZX)),
            _content(tok, mid, b"B" * 40, block2=block_value(1, 0, SZX)),
        ]

    sess, _calls = _make_session(responder)
    try:
        code, payload = sess.get(["mode", "vs", "0"], timeout=5.0)
        assert code == 0x45
        assert payload == b"A" * 1024 + b"B" * 40
    finally:
        _close(sess)


def test_etag_change_mid_transfer_restarts_then_fails():
    etags = [b"\x01", b"\x02", b"\x03", b"\x04"]

    def responder(request):
        _mtype, _code, mid, tok, _opts, _ = request
        num, _ = _requested_block(request)
        # A different ETag on every single response: the representation
        # never settles, so reassembly can never be consistent.
        etag = etags.pop(0) if etags else b"\xff"
        payload = b"A" * 1024 if num == 0 else b"B" * 40
        more = 1 if num == 0 else 0
        return [_content(tok, mid, payload, etag=etag,
                         block2=block_value(num, more, SZX))]

    sess, _calls = _make_session(responder)
    try:
        with pytest.raises(BlockwiseError):
            sess.get(["mode", "vs", "0"], timeout=5.0)
    finally:
        _close(sess)


def test_stable_etag_across_blocks_reassembles():
    def responder(request):
        _mtype, _code, mid, tok, _opts, _ = request
        num, _ = _requested_block(request)
        payload = b"A" * 1024 if num == 0 else b"B" * 40
        more = 1 if num == 0 else 0
        return [_content(tok, mid, payload, etag=b"\x77",
                         block2=block_value(num, more, SZX))]

    sess, _calls = _make_session(responder)
    try:
        code, payload = sess.get(["mode", "vs", "0"], timeout=5.0)
        assert code == 0x45
        assert payload == b"A" * 1024 + b"B" * 40
    finally:
        _close(sess)


def test_szx_downshift_asks_for_the_block_after_what_we_have():
    """Server answers block 0 at SZX=6 (1024B) then drops to SZX=4
    (256B). Block numbers index the new size, so the next request is
    block 4, not block 1."""
    requested = []

    def responder(request):
        _mtype, _code, mid, tok, _opts, _ = request
        num, szx = _requested_block(request)
        requested.append((num, szx))
        if num == 0:
            return [_content(tok, mid, b"A" * 1024,
                             block2=block_value(0, 1, 4))]
        return [_content(tok, mid, b"B" * 100,
                         block2=block_value(num, 0, 4))]

    sess, _calls = _make_session(responder)
    try:
        code, payload = sess.get(["mode", "vs", "0"], timeout=5.0)
        assert code == 0x45
        assert payload == b"A" * 1024 + b"B" * 100
        # 1024 bytes in hand at 256B blocks = blocks 0..3 done, ask for 4.
        assert requested[1] == (4, 4)
    finally:
        _close(sess)
