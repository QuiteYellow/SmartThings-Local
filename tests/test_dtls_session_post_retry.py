"""Write-path retransmission and liveness (LocalThings#384, #396).

`post()` used to send its datagram exactly once and wait on a bare
`ev.wait(timeout)`, while `get()` retransmitted every block through
`_exchange_block`. One lost datagram was therefore an unrecoverable write
and a silent no-op for a read — three unrelated resources on one AC all
failing with `SessionTimeoutError` is what surfaced it.

Retransmission ships off by default (`write_max_attempts=1`): a device
already dropping under load turns one lost write into several, and MID
dedupe is unverified on RT-OCF. These tests pin both the default's
unchanged single send and the behaviour the flag buys when it is on.
"""
import threading
import time

import pytest

from smartthings_local.errors import SessionClosedError, SessionTimeoutError
from smartthings_local.protocol import dtls_session as ds
from smartthings_local.protocol.coap import parse_coap
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


def _token_of(sess):
    """The token post() will mint next, so a test can answer it."""
    return (sess._tok_counter + 1).to_bytes(4, "big")


def _mid_of(sess):
    """The MID post() will mint next — what an empty ACK is matched on."""
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
    sess = _session(write_max_attempts=2)
    # Answers only after the first attempt has already given up.
    _answer(sess, _token_of(sess), delay=0.2)

    code, _ = sess.post(["power", "vs", "0"], b"\xa0", timeout=2.0)

    assert code == 0x44
    assert len(sess.sent) == 2


def test_retransmit_reuses_the_same_message_id_and_token(monkeypatch):
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.1)
    sess = _session(write_max_attempts=3)

    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=0.5)

    assert len(sess.sent) > 1
    frames = [parse_coap(d) for d in sess.sent]
    mids = {f[2] for f in frames}
    toks = {f[3] for f in frames}
    # The whole point of retransmitting rather than re-posting: a server
    # implementing RFC 7252 4.5 can only recognise the duplicate — and skip
    # re-running the write — if the MID is the one it already saw.
    assert len(mids) == 1, f"retransmit minted a new MID: {mids}"
    assert len(toks) == 1, f"retransmit minted a new token: {toks}"
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
    tok = _token_of(sess)

    def _answer_while_pacing():
        with sess._state_lock:
            entry = sess._pending.get(tok)
        if entry is not None:
            ev, container = entry
            container.update(code=0x44, payload=b"")
            ev.set()

    sess.pace = _answer_while_pacing

    code, _ = sess.post(["power", "vs", "0"], b"\xa0", timeout=2.0)

    assert code == 0x44
    assert len(sess.sent) == 1


def test_separate_ack_stops_retransmission(monkeypatch):
    """An empty ACK means "response coming on its own CON" (RFC 7252 5.2.2)
    and stops the retransmit timer. It carries no token, so the session has
    to match it on MID or it looks like nothing arrived at all."""
    monkeypatch.setattr(ds, "_WRITE_ACK_TIMEOUT", 0.05)
    sess = _session(write_max_attempts=10)
    mid = _mid_of(sess)

    def _ack_once_registered():
        give_up = time.monotonic() + 5.0
        while time.monotonic() < give_up:
            with sess._state_lock:
                registered = mid in sess._separate_acks
            if registered:
                sess._dispatch_coap(ds.build_coap(ds.TYPE_ACK, 0, mid, b"", []))
                return
            time.sleep(0.005)

    threading.Thread(target=_ack_once_registered, daemon=True).start()

    with pytest.raises(SessionTimeoutError):
        sess.post(["power", "vs", "0"], b"\xa0", timeout=0.5)

    # Without MID matching this retransmits for the whole 0.5s budget.
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
    # Previously this waited out the full timeout and reported it as a
    # device timeout, hiding a dead session behind the write's symptom.
    assert elapsed < 2.0, f"post() waited {elapsed:.2f}s instead of failing fast"


def test_refresh_observes_paces_the_dereg_sweep():
    sess = _session()
    sess._observe_tokens = {b"\x41": "/power/vs/0", b"\x42": "/oven/vs/0"}
    calls = []
    sess.pace = lambda: calls.append("pace")
    sess._send_observe_dereg = lambda *_a: calls.append("dereg")
    sess.subscribe = lambda *_a: calls.append("subscribe")

    sess.refresh_observes([("power", "vs", "0"), ("oven", "vs", "0")])

    # This dereg runs against a session that has to keep working afterwards,
    # so the burst is paced (LocalThings#396). The subscribe sweep is not
    # paced here on purpose — that belongs inside subscribe().
    assert calls == ["pace", "dereg", "pace", "dereg", "subscribe", "subscribe"]
