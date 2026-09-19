"""Write-path retransmission and liveness (LocalThings#384, #396).

`post()` sent its datagram exactly once and then waited on a bare
`ev.wait(timeout)`, while `get()` retransmitted every block through
`_exchange_block`. One lost datagram was therefore an unrecoverable write
and a silent no-op for a read — three unrelated resources on one AC all
failing with `SessionTimeoutError` is what surfaced it.

Retransmission ships off by default (`write_max_attempts=1`): a device
already dropping under load turns one lost write into several, and MID
dedupe is unverified on the appliances here. These tests pin both the
default's unchanged single send and the behaviour the flag buys when it
is on.

The MID registry these lean on is #57's, shared with the read path; #58
gave `_exchange_block` the same one-datagram-per-exchange shape. What is
specific to writes is the attempt loop: its backoff, its pacing, and the
frames that must stop it.
"""
import threading
import time

import pytest

from smartthings_local.errors import (
    EndpointError,
    SessionClosedError,
    SessionResetError,
    SessionTimeoutError,
)
from smartthings_local.protocol import dtls_session as ds
from smartthings_local.protocol.coap import TYPE_ACK, TYPE_RST, parse_coap
from smartthings_local.protocol.dtls_session import DtlsCoapSession


class _NullAuth:
    """Structural AuthenticationProvider — never configured, we skip connect()."""

    def configure_context(self, _context):
        return None


def _session(**kwargs):
    """Session with the wire stubbed out: every datagram post() hands to
    _send_dgram is recorded instead of sent, so a test can decide which
    ones the 'device' answers.

    The stub stamps _last_send_ts exactly as the real _send_dgram does --
    without it pace() reads a zero timestamp, decides the interval elapsed
    long ago, and never sleeps, which silently voids any test of pacing."""
    sess = DtlsCoapSession("host", 1234, auth=_NullAuth(), **kwargs)
    sess.conn = object()            # satisfies _check_live's conn guard
    sess.sent = []

    def _record(datagram):
        sess.sent.append(datagram)
        sess._last_send_ts = time.monotonic()

    sess._send_dgram = _record
    return sess


def _answer(sess, tok, *, code=0x44, payload=b"", delay=0.0):
    """Resolve `tok` the way the reader thread would, optionally late.

    Waits for post() to register the token first — the real reader can
    only ever see a token that is already pending."""

    def _deliver():
        entry = None
        give_up = time.monotonic() + 5.0
        while entry is None and time.monotonic() < give_up:
            with sess._state_lock:
                entry = sess._pending.get(tok)
            if entry is None:
                time.sleep(0.005)
        if entry is None:
            return
        if delay:
            time.sleep(delay)
        ev, container = entry
        container.update(code=code, payload=payload)
        ev.set()

    t = threading.Thread(target=_deliver, daemon=True)
    t.start()
    return t


def _reply_on_second_pace(sess, tok, *, then=None):
    """Stub pace() so the *retry's* pace is the window an answer lands in.

    post() paces before its first send too (#51), so a stub that answers on
    every call would resolve the exchange before anything reached the wire
    and prove nothing about the retransmit."""
    paces = []

    def _paced():
        paces.append(None)
        if len(paces) < 2:
            return
        with sess._state_lock:
            entry = sess._pending.get(tok)
        if entry is not None:
            ev, container = entry
            container.update(code=0x44, payload=b"")
            ev.set()
        if then is not None:
            then()

    sess.pace = _paced
    return paces


def _control_frame_once_sent(sess, mtype, mid):
    """Dispatch a bare ACK/RST for `mid` once the request is on the wire.

    Keyed off `sent` rather than the registry: the exchange is registered
    before the send, but a device cannot answer a datagram it has not
    received, and firing early would test a case the wire cannot produce."""

    def _fire():
        give_up = time.monotonic() + 5.0
        while time.monotonic() < give_up:
            if sess.sent:
                sess._dispatch_coap(ds.build_coap(mtype, 0, mid, b"", []))
                return
            time.sleep(0.005)

    threading.Thread(target=_fire, daemon=True).start()


def _token_of(sess):
    """The token post() will mint next, so a test can answer it."""
    return (sess._tok_counter + 1).to_bytes(4, "big")


def _mid_of(sess):
    """The MID post() will mint next — what a bare frame is matched on."""
    return (sess._mid + 1) & 0xFFFF


def test_default_sends_exactly_once():
    sess = _session()
    _answer(sess, _token_of(sess))

    code, _ = sess.post(["power", "vs", "0"], b"\xa0", timeout=1.0)

    assert code == 0x44
    # The default must stay byte-for-byte the old behaviour: no extra load
    # on a device nobody has yet measured as safe to retransmit into.
    assert len(sess.sent) == 1


def test_retransmit_recovers_a_dropped_datagram(monkeypatch):
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.1)
    sess = _session(write_max_attempts=2, rate_limit_rps=20.0)
    # Answers well after the second attempt is on the wire (~0.15s in: a
    # 0.1s first attempt plus the 0.05s pace before the retransmit). The
    # margin is wide because a loaded CI runner may stall anywhere in there,
    # and the assertion is about which attempt gets answered, not when.
    _answer(sess, _token_of(sess), delay=1.0)

    code, _ = sess.post(["power", "vs", "0"], b"\xa0", timeout=4.0)

    assert code == 0x44
    assert len(sess.sent) == 2


def test_retransmit_reuses_the_same_message_id_and_token(monkeypatch):
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.1)
    sess = _session(write_max_attempts=3)

    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=2.0)

    assert len(sess.sent) > 1
    # The whole point of retransmitting rather than re-posting: a server
    # implementing RFC 7252 §4.5 can only recognise the duplicate — and skip
    # re-running the write — if the frame is the one it already saw.
    assert len(set(sess.sent)) == 1, "retransmissions must be byte-identical"
    frames = [parse_coap(d) for d in sess.sent]
    assert len({f[2] for f in frames}) == 1, "retransmit minted a new MID"
    assert len({f[3] for f in frames}) == 1, "retransmit minted a new token"
    assert {f[:2] for f in frames} == {(ds.TYPE_CON, ds.METHOD_POST)}


def test_attempts_stop_at_the_callers_deadline(monkeypatch):
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.05)
    sess = _session(write_max_attempts=10)

    start = time.monotonic()
    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=0.4)
    elapsed = time.monotonic() - start

    # Retransmission lives inside the caller's timeout, never on top of it.
    assert elapsed < 1.0, f"post() overran its 0.4s deadline by {elapsed:.2f}s"


def test_a_retry_is_skipped_when_its_pace_would_outrun_the_deadline(monkeypatch):
    """pace() sleeps up to a whole rate-limit interval, so a retry decided on
    "is there any budget left" returns well past the caller's timeout — 1s on
    a 0.5s call at 1 rps."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.1)
    sess = _session(write_max_attempts=5, rate_limit_rps=1.0)

    start = time.monotonic()
    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=0.5)
    elapsed = time.monotonic() - start

    assert elapsed < 0.5, f"post() overran its 0.5s deadline by {elapsed:.2f}s"
    assert len(sess.sent) == 1


def test_a_reply_during_the_pace_window_is_not_resent(monkeypatch):
    """The retry's pace is a window the answer can land in. Resending then
    puts a second copy of a non-idempotent write on the wire for nothing."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.05)
    sess = _session(write_max_attempts=3)
    paces = _reply_on_second_pace(sess, _token_of(sess))

    code, _ = sess.post(["power", "vs", "0"], b"\xa0", timeout=2.0)

    assert code == 0x44
    assert len(paces) == 2, "the reply has to land in the retry's pace window"
    assert len(sess.sent) == 1


def test_an_answer_that_beat_a_dying_reader_is_still_returned(monkeypatch):
    """That same pace window is one in which both can happen: the response
    lands and the reader exits. Checking liveness first throws away a write
    the device confirmed and reports the session as closed."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.05)
    sess = _session(write_max_attempts=3)
    sess._reader_thread = threading.Thread(target=lambda: None)
    sess._reader_running.set()
    paces = _reply_on_second_pace(
        sess, _token_of(sess), then=sess._reader_running.clear
    )

    code, _ = sess.post(["power", "vs", "0"], b"\xa0", timeout=2.0)

    assert code == 0x44
    assert len(paces) == 2
    assert len(sess.sent) == 1


def test_separate_ack_stops_retransmission(monkeypatch):
    """An empty ACK means "response coming on its own CON" (RFC 7252 §5.2.2)
    and stops the retransmit timer. #57 matches it by MID; what is tested
    here is that the write loop then holds instead of resending."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.05)
    sess = _session(write_max_attempts=10)
    _control_frame_once_sent(sess, TYPE_ACK, _mid_of(sess))

    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=0.5)

    # Without honouring the ACK this retransmits for the whole 0.5s budget.
    assert len(sess.sent) == 1


def test_rst_surfaces_as_a_rejection_and_stops_retransmission(monkeypatch):
    """RST rejects the request and likewise stops retransmission (§4.2).
    Resending through one would push copies of a write the device has
    already refused, and then report it as a timeout."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.05)
    sess = _session(write_max_attempts=10)
    _control_frame_once_sent(sess, TYPE_RST, _mid_of(sess))

    with pytest.raises(SessionResetError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=1.0)

    assert len(sess.sent) == 1


def test_reader_death_mid_write_fails_fast():
    sess = _session()
    sess._reader_thread = threading.Thread(target=lambda: None)
    sess._reader_running.set()      # alive at entry, so _check_live passes

    def _kill():
        time.sleep(0.05)
        sess._reader_running.clear()

    threading.Thread(target=_kill, daemon=True).start()

    start = time.monotonic()
    with pytest.raises(SessionClosedError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=10.0)
    elapsed = time.monotonic() - start
    # Previously this waited out the full timeout on a bare ev.wait() and
    # reported it as a device timeout, hiding a dead session behind the
    # write's symptom.
    assert elapsed < 2.0, f"post() waited {elapsed:.2f}s instead of failing fast"


def test_a_response_delivered_as_the_reader_tore_down_is_not_lost():
    """The liveness guard above covers the reader exiting during a pace. The
    other half is the reader's own teardown: _reader_loop's finally calls
    _close_pending_requests(), which stamped a closed-session error onto
    every pending container — including one already holding the response it
    had just dispatched. Both callers read 'err' before 'code', so a write
    the device confirmed came back as SessionClosedError."""
    sess = _session()
    sess._reader_thread = threading.Thread(target=lambda: None)
    sess._reader_running.set()
    tok = _token_of(sess)

    def _deliver_then_tear_down(_datagram):
        sess.sent.append(_datagram)

        def _reader_exit():
            with sess._state_lock:
                ev, container = sess._pending[tok]
                container.update(code=0x44, payload=b"ok")
            ev.set()
            # _reader_loop's finally, in order.
            sess._reader_running.clear()
            sess._close_pending_requests()

        thread = threading.Thread(target=_reader_exit)
        thread.start()
        thread.join()           # teardown wins the race, deterministically

    sess._send_dgram = _deliver_then_tear_down

    assert sess.post(["power", "vs", "0"], b"\xa0", timeout=5.0) == (0x44, b"ok")


def test_teardown_does_not_overwrite_an_answered_exchange():
    """The same guard, at its source: shared by post() and _exchange_block,
    so the read path gets it too — a final block dispatched as the reader
    exits is an answer, not a closed session."""
    sess = _session()
    answered_ev, answered = threading.Event(), {"code": 0x45, "payload": b"ok"}
    silent_ev, silent = threading.Event(), {}
    sess._register_pending_request(b"answered", answered_ev, answered)
    sess._register_pending_request(b"silent", silent_ev, silent)

    sess._close_pending_requests()

    assert "err" not in answered, "teardown discarded a dispatched response"
    assert isinstance(silent["err"], SessionClosedError)
    assert answered_ev.is_set() and silent_ev.is_set()


def test_a_failed_retransmit_does_not_abort_the_exchange(monkeypatch):
    """A connected UDP socket reports the ICMP error queued by an earlier
    send on the *next* one, and the reader treats those errnos as advisory.
    If a retransmit's EndpointError killed the exchange, turning
    retransmission on would be less robust than leaving it off."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.1)
    sess = _session(write_max_attempts=3, rate_limit_rps=20.0)
    tok = _token_of(sess)
    attempts = []

    def _send(datagram):
        attempts.append(datagram)
        sess._last_send_ts = time.monotonic()
        if len(attempts) == 2:
            raise EndpointError()       # ICMP from attempt 1, surfaced here

    sess._send_dgram = _send
    _answer(sess, tok, delay=1.0)       # lands well after the failed retry

    assert sess.post(["power", "vs", "0"], b"\xa0", timeout=4.0) == (0x44, b"")
    assert len(attempts) >= 2


def test_a_failed_first_send_still_reaches_the_caller():
    """The other side of that: attempt 0 is the caller's only datagram, so
    its failure is theirs to see, not something to swallow and time out on."""
    sess = _session(write_max_attempts=3)

    def _send(_datagram):
        raise EndpointError()

    sess._send_dgram = _send

    with pytest.raises(EndpointError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=2.0)


def test_the_caller_timeout_bounds_the_pace_too():
    """post() paces before its first send (#51). The deadline is armed
    before that pace, so a caller that asked for 0.5s gets an answer or an
    error inside 0.5s — not 0.5s plus whatever the rate limiter withheld."""
    sess = _session(rate_limit_rps=2.0)         # 500ms interval
    sess._last_send_ts = time.monotonic()       # a send just went out

    start = time.monotonic()
    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=0.5)
    elapsed = time.monotonic() - start

    assert elapsed < 0.9, f"post() took {elapsed:.2f}s for a 0.5s timeout"


def test_refresh_observes_paces_the_dereg_sweep():
    sess = _session()
    sess._observe_tokens = {b"\x41": "/power/vs/0", b"\x42": "/oven/vs/0"}
    calls = []
    sess.pace = lambda: calls.append("pace")
    sess._send_observe_dereg = lambda *_a: calls.append("dereg")
    sess.subscribe = lambda *_a, **_k: calls.append("subscribe")

    sess.refresh_observes([("power", "vs", "0"), ("oven", "vs", "0")])

    # This dereg runs against a session that has to keep working afterwards,
    # so the burst is paced (LocalThings#396). The subscribe sweep is not
    # paced here on purpose — subscribe() is where that belongs, and #51 put
    # it there; the sleep that used to stand in for it is gone with #59's.
    assert calls == ["pace", "dereg", "pace", "dereg", "subscribe", "subscribe"]
