"""Full relation context on each Observe delivery.

`on_notification(href, payload)` cannot express two things the session
already knows. Which delivery answered the register CON -- RFC 7641
§3.2 makes it the first response on the token, and a consumer that
treats it as a push reports a device as pushing when it has only
replied to being asked (#41). And which query-qualified relation it
belongs to, since one href can carry several, each registering on its
own token.

`on_observe_delivery` carries both, so a consumer reads a fact instead
of reconstructing one from arrival order.
"""

from __future__ import annotations

from smartthings_local.protocol.coap import (
    BLOCK2,
    OBSERVE,
    TYPE_NON,
    block_value,
    build_coap,
)
from smartthings_local.protocol.dtls_session import (
    DtlsCoapSession,
    ObserveDelivery,
)


class _NullAuth:
    def configure_context(self, _context):
        return None


def _session(**callbacks):
    session = DtlsCoapSession(
        "device.example",
        5684,
        auth=_NullAuth(),
        rate_limit_rps=1_000_000,
        **callbacks,
    )
    session.conn = object()
    session._send_dgram = lambda _datagram: None
    return session


def _observe_value(value):
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _notify(session, token, mid, payload, *, sequence=None, options=()):
    observe_options = (
        () if sequence is None else ((OBSERVE, _observe_value(sequence)),)
    )
    session._dispatch_coap(
        build_coap(TYPE_NON, 0x45, mid, token,
                   (*observe_options, *options), payload)
    )


def test_the_first_response_on_a_token_is_the_registration_answer():
    seen: list[ObserveDelivery] = []
    session = _session(on_observe_delivery=seen.append)
    token = session.subscribe(["operational", "state", "vs", "0"])

    _notify(session, token, 10, b"first", sequence=1)
    _notify(session, token, 11, b"second", sequence=2)

    assert [d.registration for d in seen] == [True, False]
    assert [d.sequence for d in seen] == [1, 2]
    assert [d.payload for d in seen] == [b"first", b"second"]
    assert all(d.href == "/operational/state/vs/0" for d in seen)


def test_each_query_variant_registers_on_its_own_token():
    """The case arrival order cannot resolve: two relations on one href,
    so the second registration answer looks like the first relation's
    second notification unless the query is carried through."""
    seen: list[ObserveDelivery] = []
    session = _session(on_observe_delivery=seen.append)
    actuator = session.subscribe(["mode", "vs", "0"], query=("if=oic.if.a",))
    sensor = session.subscribe(["mode", "vs", "0"], query=("if=oic.if.s",))

    _notify(session, actuator, 10, b"a", sequence=1)
    _notify(session, sensor, 11, b"s", sequence=1)

    assert [d.registration for d in seen] == [True, True]
    assert [d.query for d in seen] == [("if=oic.if.a",), ("if=oic.if.s",)]


def test_re_subscribing_marks_the_new_answer_as_a_registration():
    """Retiring a token clears its recorded sequence, so a reconnect or
    the periodic refresh is recognised with no caller bookkeeping."""
    seen: list[ObserveDelivery] = []
    session = _session(on_observe_delivery=seen.append)
    first = session.subscribe(["power", "vs", "0"])
    _notify(session, first, 10, b"on", sequence=1)
    _notify(session, first, 11, b"off", sequence=2)

    session.unsubscribe(["power", "vs", "0"])
    second = session.subscribe(["power", "vs", "0"])
    _notify(session, second, 12, b"on", sequence=1)

    assert [d.registration for d in seen] == [True, False, True]


def test_an_optionless_initial_response_is_also_a_registration():
    """Firmware that omits the Observe option still answers the register
    CON, and that answer is no more a push than a compliant one."""
    seen: list[ObserveDelivery] = []
    pending: list[str] = []
    session = _session(on_observe_delivery=seen.append,
                       on_observe_pending=pending.append)
    token = session.subscribe(["alarms", "vs", "0"])

    _notify(session, token, 10, b"first")
    _notify(session, token, 11, b"second")

    assert pending == ["/alarms/vs/0"]
    assert [d.registration for d in seen] == [True, False]
    assert [d.sequence for d in seen] == [None, None]
    assert [d.legacy for d in seen] == [False, True]


def test_a_blockwise_registration_answer_survives_the_refetch():
    """The re-read is what reaches the caller, so the flag has to travel
    with the queued relation rather than with the first block."""
    seen: list[ObserveDelivery] = []
    session = _session(on_observe_delivery=seen.append)
    token = session.subscribe(["mode", "vs", "0"])
    queued = []
    session._queue_refetch = (
        lambda href, query=(), *, legacy=False, registration=False:
        queued.append((href, query, legacy, registration)))

    _notify(session, token, 10, b"partial", sequence=1,
            options=((BLOCK2, block_value(0, 1, 6)),))

    assert queued == [("/mode/vs/0", (), False, True)]
    assert seen == []


def test_the_rich_callback_replaces_the_plain_one():
    """Both firing would double-apply every representation."""
    rich: list[ObserveDelivery] = []
    plain = []
    session = _session(on_observe_delivery=rich.append,
                       on_notification=lambda h, p: plain.append((h, p)))
    token = session.subscribe(["power", "vs", "0"])

    _notify(session, token, 10, b"on", sequence=1)

    assert len(rich) == 1
    assert plain == []


def test_existing_callers_are_untouched():
    """The default stays exactly what it was: no delivery callback set,
    so on_notification keeps receiving every representation."""
    plain = []
    session = _session(on_notification=lambda h, p: plain.append((h, p)))
    token = session.subscribe(["power", "vs", "0"])

    _notify(session, token, 10, b"on", sequence=1)
    _notify(session, token, 11, b"off", sequence=2)

    assert plain == [("/power/vs/0", b"on"), ("/power/vs/0", b"off")]


def test_a_raising_callback_does_not_kill_the_reader():
    def explode(_delivery):
        raise RuntimeError("consumer bug")

    session = _session(on_observe_delivery=explode)
    token = session.subscribe(["power", "vs", "0"])

    _notify(session, token, 10, b"on", sequence=1)
    _notify(session, token, 11, b"off", sequence=2)
