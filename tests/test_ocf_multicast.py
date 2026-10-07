"""Known-host OCF multicast responder-port discovery tests."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from smartthings_local.protocol.coap import (
    ACCEPT,
    TYPE_CON,
    TYPE_NON,
    URI_PATH,
    URI_QUERY,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.ocf_multicast import (
    _OCF_MULTICAST_GROUP,
    OcfResponderPortDiscoveryResult,
    discover_ocf_responder_ports,
)

_TARGET = "192.0.2.20"
_OTHER = "192.0.2.21"
_INTERFACE = "192.0.2.10"


class _FakeSocket:
    def __init__(self, responder=None):
        self.responder = responder
        self.incoming = []
        self.sent = []
        self.options = []
        self.bound = None
        self.blocking = None
        self.closed = False

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def bind(self, address):
        self.bound = address

    def setblocking(self, enabled):
        self.blocking = enabled

    def sendto(self, datagram, destination):
        self.sent.append((datagram, destination))
        if self.responder is not None:
            self.incoming.extend(self.responder(datagram, destination))
        return len(datagram)

    def recvfrom(self, _size):
        return self.incoming.pop(0)

    def close(self):
        self.closed = True


class _FakeSelector:
    def __init__(self, active):
        self.active = active
        self.closed = False

    def register(self, *_args):
        return None

    def unregister(self, *_args):
        return None

    def select(self, _timeout):
        if not self.active.incoming:
            return []
        return [(SimpleNamespace(fileobj=self.active), selectors_event_read())]

    def close(self):
        self.closed = True


def selectors_event_read():
    return 1


class _VirtualClock:
    """A monotonic clock the test advances itself.

    The round budget is wall-clock arithmetic, and `_FakeSelector.select`
    returns instantly, so the existing tests spend no time at all and cannot
    see how the budget is divided. Virtual time makes that observable without
    sleeping and without depending on the host's scheduler.
    """

    def __init__(self, now=1000.0):
        self.now = float(now)

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class _TimedSelector(_FakeSelector):
    """A selector whose waits spend virtual time and overshoot, as a poll does.

    `overshoot` is the scheduler delay to simulate: the seconds `select`
    takes beyond the timeout it was given. `windows` records the timeout each
    wait was actually given, so a test can tell which rounds got one at all.
    """

    def __init__(self, active, clock, *, overshoot=0.0):
        super().__init__(active)
        self._clock = clock
        self._overshoot = overshoot
        self.windows = []

    def select(self, timeout):
        self.windows.append(timeout)
        self._clock.advance((timeout or 0.0) + self._overshoot)
        return super().select(timeout)


@pytest.fixture
def patch_timed_socket(monkeypatch):
    """Install a silent socket whose selector waits spend virtual time."""

    def install(*, overshoot):
        clock = _VirtualClock()
        active = _FakeSocket()
        selector = _TimedSelector(active, clock, overshoot=overshoot)
        monkeypatch.setattr(
            "smartthings_local.protocol.ocf_multicast.socket.socket",
            lambda *_args: active,
        )
        monkeypatch.setattr(
            "smartthings_local.protocol.ocf_multicast.selectors.DefaultSelector",
            lambda: selector,
        )
        monkeypatch.setattr(
            "smartthings_local.protocol.ocf_multicast.time", clock
        )
        return active, selector

    return install


def test_every_round_sent_gets_a_window_to_read_a_reply_in(patch_timed_socket):
    # `rounds` is allowed up to four, so a 120 ms budget gives 30 ms rounds,
    # and a wait overshooting by 40 ms -- the worst a UDP read was measured
    # to overshoot a 100 ms timeout on 2026-10-07 -- outlives its own round.
    # Under the fixed slice `started + timeout * (round + 1) / rounds` every
    # later round's deadline was then already in the past, and a round still
    # sent all three of its requests to the multicast group before finding
    # that out: three datagrams every device on the segment pays for, with
    # nothing waiting for an answer.
    active, selector = patch_timed_socket(overshoot=0.04)

    result = discover_ocf_responder_ports(
        _TARGET, interface_address=_INTERFACE, timeout=0.12, rounds=4)

    assert result.ports == ()
    rounds_sent, remainder = divmod(len(active.sent), 3)
    assert remainder == 0
    assert rounds_sent == 2                      # not the three it used to
    assert len(selector.windows) == rounds_sent  # each one was waited for
    assert all(w > 0.015 for w in selector.windows)


def test_an_unhurried_run_divides_the_budget_as_before(patch_timed_socket):
    # The guard must not cost a round when nothing overruns: at the library's
    # own defaults every round keeps its full nominal window.
    _active, selector = patch_timed_socket(overshoot=0.0)

    discover_ocf_responder_ports(
        _TARGET, interface_address=_INTERFACE, timeout=0.12, rounds=4)

    assert selector.windows == [pytest.approx(0.03, abs=1e-6)] * 4


def _response(
    datagram, _destination=None, *, host=_TARGET, port=43123, message_type=TYPE_NON
):
    _mtype, _code, mid, token, _options, _payload = parse_coap(datagram)
    response_mid = mid if message_type != TYPE_CON else (mid + 1) & 0xFFFF
    return [
        (
            build_coap(message_type, 0x45, response_mid, token, [], b"directory"),
            (host, port),
        )
    ]


@pytest.fixture
def patch_socket(monkeypatch):
    created = []

    def install(responder=None):
        active = _FakeSocket(responder)
        selector = _FakeSelector(active)
        created.append((active, selector))
        monkeypatch.setattr(
            "smartthings_local.protocol.ocf_multicast.socket.socket",
            lambda *_args: active,
        )
        monkeypatch.setattr(
            "smartthings_local.protocol.ocf_multicast.selectors.DefaultSelector",
            lambda: selector,
        )
        return active, selector

    return install


def test_sends_proven_directory_requests_and_filtered_fallback_on_interface(
    patch_socket,
):
    active, selector = patch_socket(_response)

    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=1,
    )

    assert result.ports == (43123,)
    assert result.attempts == 3
    assert result.responses == 3
    assert active.bound == (_INTERFACE, 0)
    assert active.blocking is False
    assert active.closed
    assert selector.closed
    assert all(
        destination == (_OCF_MULTICAST_GROUP, 5683) for _, destination in active.sent
    )

    requests = [parse_coap(datagram) for datagram, _ in active.sent]
    assert all(
        [value for number, value in item[4] if number == URI_PATH] == [b"oic", b"res"]
        for item in requests
    )
    queries = [
        [value for number, value in item[4] if number == URI_QUERY] for item in requests
    ]
    assert queries == [[], [], [b"rt=oic.r.doxm"]]
    accepts = [
        [value for number, value in item[4] if number == ACCEPT] for item in requests
    ]
    assert accepts == [[b"\x27\x10"], [b"\x3c"], [b"\x3c"]]
    assert [value for number, value in requests[0][4] if number == 2049] == [
        b"\x08\x00"
    ]
    assert [value for number, value in requests[1][4] if number == 2049] == []
    assert [value for number, value in requests[2][4] if number == 2049] == []


@pytest.mark.parametrize(
    ("accepted_accept", "accepted_query"),
    (
        (b"\x27\x10", ()),
        (b"\x3c", ()),
        (b"\x3c", (b"rt=oic.r.doxm",)),
    ),
)
def test_each_directory_request_profile_can_find_the_responder(
    patch_socket, accepted_accept, accepted_query
):
    def responder(datagram, destination):
        _mtype, _code, _mid, _token, options, _payload = parse_coap(datagram)
        accept = next(value for number, value in options if number == ACCEPT)
        query = tuple(value for number, value in options if number == URI_QUERY)
        if (accept, query) != (accepted_accept, accepted_query):
            return []
        return _response(datagram, destination)

    patch_socket(responder)
    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=1,
    )

    assert result.ports == (43123,)
    assert result.responses == 1


def test_accepts_only_token_correlated_content_from_the_target(patch_socket):
    def responder(datagram, _destination):
        responses = _response(datagram)
        _mtype, _code, mid, token, _options, _payload = parse_coap(datagram)
        responses.extend(
            [
                (build_coap(TYPE_NON, 0x45, mid, b"wrong", [], b"x"), (_TARGET, 49999)),
                (build_coap(TYPE_NON, 0x44, mid, token, [], b"x"), (_TARGET, 49998)),
                (build_coap(TYPE_NON, 0x45, mid, token, [], b"x"), (_OTHER, 49997)),
                (build_coap(TYPE_NON, 0x45, mid, token, [], b""), (_TARGET, 49996)),
            ]
        )
        return responses

    patch_socket(responder)
    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=1,
    )

    assert result.ports == (43123,)
    assert result.responses == 3


def test_ignores_malformed_and_oversized_datagrams(patch_socket):
    def responder(datagram, _destination):
        valid = _response(datagram)
        invalid_version = bytes([valid[0][0][0] & 0x3F]) + valid[0][0][1:]
        invalid_token_length = bytes([0x49]) + valid[0][0][1:]
        return [
            (b"\x40", (_TARGET, 49999)),
            (invalid_version, (_TARGET, 49998)),
            (invalid_token_length, (_TARGET, 49997)),
            (b"x" * 8193, (_TARGET, 49996)),
            *valid,
        ]

    patch_socket(responder)
    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=1,
    )

    assert result.ports == (43123,)
    assert result.responses == 3


def test_acknowledges_confirmable_responses(patch_socket):
    active, _selector = patch_socket(
        lambda datagram, _destination: _response(datagram, message_type=TYPE_CON)
    )

    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=1,
    )

    assert result.found
    acknowledgements = [
        (parse_coap(datagram), destination)
        for datagram, destination in active.sent
        if parse_coap(datagram)[0] == 2
    ]
    assert len(acknowledgements) == 3
    assert all(item[0][1] == 0 and item[0][3] == b"" for item in acknowledgements)
    assert all(
        destination == (_TARGET, 43123) for _item, destination in acknowledgements
    )


def test_collects_a_small_bounded_candidate_set(patch_socket):
    response_number = 0

    def responder(datagram, _destination):
        nonlocal response_number
        port = 40000 + response_number % 8
        response_number += 1
        return _response(datagram, port=port)

    patch_socket(responder)
    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=4,
    )

    assert result.ports == tuple(range(40000, 40008))
    assert result.error_code is None


def test_fails_closed_when_too_many_distinct_ports_answer(patch_socket):
    next_port = 40000

    def responder(datagram, _destination):
        nonlocal next_port
        responses = [
            *_response(datagram, port=next_port),
            *_response(datagram, port=next_port + 1),
        ]
        next_port += 2
        return responses

    patch_socket(responder)
    result = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=4,
    )

    assert result.ports == ()
    assert result.responses == 24
    assert result.error_code == "ambiguous_response"


def test_no_response_and_interface_failures_are_fixed_results(
    patch_socket, monkeypatch
):
    active, _selector = patch_socket()
    no_response = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
        rounds=1,
    )
    assert no_response == OcfResponderPortDiscoveryResult(
        ports=(),
        attempts=3,
        responses=0,
        error_code="no_response",
    )
    assert active.closed

    class BrokenSocket:
        def setsockopt(self, *_args):
            raise OSError("synthetic")

        def close(self):
            return None

    monkeypatch.setattr(
        "smartthings_local.protocol.ocf_multicast.socket.socket",
        lambda *_args: BrokenSocket(),
    )
    unavailable = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
    )
    assert unavailable.error_code == "interface_unavailable"
    assert unavailable.attempts == 0

    monkeypatch.setattr(
        "smartthings_local.protocol.ocf_multicast.selectors.DefaultSelector",
        lambda: (_ for _ in ()).throw(OSError("synthetic")),
    )
    unavailable = discover_ocf_responder_ports(
        _TARGET,
        interface_address=_INTERFACE,
    )
    assert unavailable.error_code == "interface_unavailable"
    assert unavailable.attempts == 0


@pytest.mark.parametrize(
    ("kwargs", "exception"),
    [
        ({"target_address": 123}, TypeError),
        ({"target_address": "not-an-address"}, ValueError),
        ({"target_address": _OCF_MULTICAST_GROUP}, ValueError),
        ({"interface_address": "0.0.0.0"}, ValueError),
        ({"discovery_port": True}, TypeError),
        ({"discovery_port": 0}, ValueError),
        ({"timeout": float("nan")}, ValueError),
        ({"rounds": 0}, ValueError),
        ({"rounds": 5}, ValueError),
    ],
)
def test_rejects_invalid_options_without_opening_a_socket(
    monkeypatch, kwargs, exception
):
    values = {
        "target_address": _TARGET,
        "interface_address": _INTERFACE,
        **kwargs,
    }
    socket_factory = pytest.fail
    monkeypatch.setattr(
        "smartthings_local.protocol.ocf_multicast.socket.socket",
        socket_factory,
    )
    with pytest.raises(exception):
        discover_ocf_responder_ports(**values)


def test_result_repr_omits_ports_and_addresses():
    result = OcfResponderPortDiscoveryResult(ports=(43123,), attempts=2, responses=1)

    rendered = repr(result)
    assert "43123" not in rendered
    assert _TARGET not in rendered
    assert "port_count=1" in rendered
