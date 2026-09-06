"""Observe relation identity, confirmation, and sequence handling."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from smartthings_local.errors import SessionIdentifierError
from smartthings_local.protocol import dtls_session
from smartthings_local.protocol.coap import (
    BLOCK2,
    OBSERVE,
    TYPE_ACK,
    TYPE_NON,
    URI_QUERY,
    block_value,
    build_coap,
    parse_coap,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession


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
        build_coap(
            TYPE_NON,
            0x45,
            mid,
            token,
            (*observe_options, *options),
            payload,
        )
    )


def test_subscribe_registers_path_and_query_before_immediate_response():
    delivered = []
    session = _session(
        on_notification=lambda href, payload: delivered.append((href, payload))
    )
    requests = []

    def send(datagram):
        request = parse_coap(datagram)
        requests.append(request)
        _mtype, _code, mid, token, _options, _payload = request
        assert session._observe_tokens[token] == "/mode/vs/0"
        assert session._observe_queries[token] == (
            "if=oic.if.a",
            "rt=x.test",
        )
        session._dispatch_coap(
            build_coap(
                TYPE_ACK,
                0x45,
                mid,
                token,
                [(OBSERVE, b"")],
                b"initial",
            )
        )

    session._send_dgram = send

    token = session.subscribe(
        ["mode", "vs", "0"],
        query=("if=oic.if.a", "rt=x.test"),
    )

    assert len(token) == 1
    assert delivered == [("/mode/vs/0", b"initial")]
    assert [value for number, value in requests[0][4] if number == URI_QUERY] == [
        b"if=oic.if.a",
        b"rt=x.test",
    ]


def test_plain_initial_response_needs_different_mid_to_confirm_legacy():
    delivered = []
    pending = []
    session = _session(
        on_notification=lambda href, payload: delivered.append(
            ("standard", href, payload)
        ),
        on_legacy_notification=lambda href, payload: delivered.append(
            ("legacy", href, payload)
        ),
        on_observe_pending=pending.append,
    )
    session._send_dgram = Mock()
    token = session.subscribe(["doors", "vs", "0"])

    _notify(session, token, 10, b"initial")
    _notify(session, token, 10, b"initial-retransmit")

    assert pending == ["/doors/vs/0"]
    assert delivered == [
        ("standard", "/doors/vs/0", b"initial"),
    ]
    assert session._observe_plain_response_mids[token] == 10
    assert token not in session._legacy_observe_tokens
    assert token not in session._observe_sequences

    _notify(session, token, 11, b"changed")
    _notify(session, token, 11, b"changed-retransmit")
    _notify(session, token, 12, b"changed-again")

    assert token in session._legacy_observe_tokens
    assert delivered == [
        ("standard", "/doors/vs/0", b"initial"),
        ("legacy", "/doors/vs/0", b"changed"),
        ("legacy", "/doors/vs/0", b"changed-again"),
    ]


def test_legacy_notification_falls_back_to_main_callback():
    delivered = []
    session = _session(
        on_notification=lambda href, payload: delivered.append((href, payload))
    )
    session._send_dgram = Mock()
    token = session.subscribe(["doors", "vs", "0"])

    _notify(session, token, 20, b"initial")
    _notify(session, token, 21, b"changed")

    assert delivered == [
        ("/doors/vs/0", b"initial"),
        ("/doors/vs/0", b"changed"),
    ]


def test_probationary_blockwise_initial_queues_refetch_without_partial_delivery():
    delivered = []
    pending = []
    session = _session(
        on_notification=lambda href, payload: delivered.append((href, payload)),
        on_observe_pending=pending.append,
    )
    session._send_dgram = Mock()
    session._queue_refetch = Mock()
    token = session.subscribe(
        ["mode", "vs", "0"], query=("if=oic.if.a",)
    )

    _notify(
        session,
        token,
        10,
        b"partial",
        options=((BLOCK2, block_value(0, 1, 6)),),
    )

    assert pending == ["/mode/vs/0"]
    assert delivered == []
    session._queue_refetch.assert_called_once_with(
        "/mode/vs/0",
        ("if=oic.if.a",),
        legacy=False,
        registration=True,
    )


def test_pending_callback_can_retire_relation_before_initial_delivery():
    delivered = []
    holder = {}

    def retire(_href):
        with holder["session"]._state_lock:
            holder["session"]._retire_observe_token_locked(holder["token"])

    session = _session(
        on_notification=lambda href, payload: delivered.append((href, payload)),
        on_observe_pending=retire,
    )
    holder["session"] = session
    session._send_dgram = Mock()
    holder["token"] = session.subscribe(["mode", "vs", "0"])

    _notify(session, holder["token"], 10, b"initial")

    assert delivered == []
    assert holder["token"] not in session._observe_tokens


def test_probationary_blockwise_representation_is_refetched_before_delivery():
    delivered = []
    session = _session(
        on_notification=lambda href, payload: delivered.append((href, payload))
    )
    session._blockwise_get = Mock(
        return_value=(0x45, b"complete", 2, b"fresh")
    )
    token = b"\x41"
    href = "/mode/vs/0"
    query = ("if=oic.if.a",)
    session._observe_tokens[token] = href
    session._observe_queries[token] = query
    session._observe_plain_response_mids[token] = 10

    session._refetch_one((href, query, False), 1)

    session._blockwise_get.assert_called_once_with(
        ["mode", "vs", "0"],
        query,
        dtls_session._REFETCH_TIMEOUT_S,
    )
    assert delivered == [(href, b"complete")]


def test_rejected_observe_retires_every_relation_index():
    errors = []
    session = _session(
        on_observe_error=lambda href, code: errors.append((href, code))
    )
    session._send_dgram = Mock()
    token = session.subscribe(
        ["mode", "vs", "0"], query=("if=oic.if.a",)
    )
    session._observe_plain_response_mids[token] = 1
    session._legacy_observe_tokens.add(token)
    session._legacy_observe_mids[token] = 2
    session._observe_sequences[token] = (3, 4.0)

    session._dispatch_coap(
        build_coap(TYPE_ACK, 0x80, 10, token, [], b"rejected")
    )

    assert errors == [("/mode/vs/0", 0x80)]
    assert token not in session._observe_tokens
    assert token not in session._observe_queries
    assert token not in session._observe_plain_response_mids
    assert token not in session._legacy_observe_tokens
    assert token not in session._legacy_observe_mids
    assert token not in session._observe_sequences


def test_rfc_observe_sequence_drops_duplicate_and_stale_values():
    delivered = []
    session = _session(
        on_notification=lambda _href, payload: delivered.append(payload)
    )
    session._send_dgram = Mock()
    token = session.subscribe(["mode", "vs", "0"])

    _notify(session, token, 1, b"zero", sequence=0)
    _notify(session, token, 2, b"one", sequence=1)
    _notify(session, token, 3, b"duplicate", sequence=1)
    _notify(session, token, 4, b"stale", sequence=0)

    assert delivered == [b"zero", b"one"]


def test_rfc_observe_sequence_accepts_24_bit_wrap():
    delivered = []
    session = _session(
        on_notification=lambda _href, payload: delivered.append(payload)
    )
    session._send_dgram = Mock()
    token = session.subscribe(["mode", "vs", "0"])

    _notify(session, token, 1, b"before-wrap", sequence=0xFFFFFE)
    _notify(session, token, 2, b"after-wrap", sequence=1)

    assert delivered == [b"before-wrap", b"after-wrap"]


def test_receipt_time_can_reestablish_sequence_after_128_seconds(monkeypatch):
    now = [100.0]
    delivered = []
    monkeypatch.setattr(dtls_session.time, "monotonic", lambda: now[0])
    session = _session(
        on_notification=lambda _href, payload: delivered.append(payload)
    )
    session._send_dgram = Mock()
    token = session.subscribe(["mode", "vs", "0"])

    _notify(session, token, 1, b"newer", sequence=100)
    now[0] += 128.001
    _notify(session, token, 2, b"server-restarted", sequence=1)

    assert delivered == [b"newer", b"server-restarted"]


@pytest.mark.parametrize(
    "options",
    (
        ((OBSERVE, b""), (OBSERVE, b"\x01")),
        ((OBSERVE, b"\x00\x00\x00\x01"),),
        ((OBSERVE, b""), (BLOCK2, b""), (BLOCK2, b"")),
        ((OBSERVE, b""), (BLOCK2, b"\x00\x00\x00\x00")),
    ),
)
def test_malformed_observe_transport_options_do_not_advance_relation(options):
    delivered = []
    session = _session(
        on_notification=lambda _href, payload: delivered.append(payload)
    )
    session._send_dgram = Mock()
    token = session.subscribe(["mode", "vs", "0"])

    session._dispatch_coap(
        build_coap(TYPE_NON, 0x45, 1, token, options, b"invalid")
    )

    assert delivered == []
    assert token not in session._observe_sequences


def test_blockwise_refetch_keeps_query_and_callback_kind():
    standard = []
    legacy = []
    session = _session(
        on_notification=lambda href, payload: standard.append((href, payload)),
        on_legacy_notification=lambda href, payload: legacy.append((href, payload)),
    )
    session._blockwise_get = Mock(
        return_value=(0x45, b"complete", 2, b"fresh")
    )

    key = ("/mode/vs/0", ("if=oic.if.a",), True)
    token = b"\x41"
    session._observe_tokens[token] = key[0]
    session._observe_queries[token] = key[1]
    session._legacy_observe_tokens.add(token)
    session._refetch_one(key, 1)

    session._blockwise_get.assert_called_once_with(
        ["mode", "vs", "0"],
        ("if=oic.if.a",),
        dtls_session._REFETCH_TIMEOUT_S,
    )
    assert standard == []
    assert legacy == [("/mode/vs/0", b"complete")]


def test_refresh_preserves_each_query_separated_relation():
    session = _session()
    session.pace = Mock()
    requests = []
    session._send_dgram = requests.append
    path = ["mode", "vs", "0"]
    session.subscribe(path, query=("if=oic.if.a",))
    session.subscribe(path, query=("if=oic.if.s",))
    requests.clear()

    session.refresh_observes([path])

    parsed = [parse_coap(request) for request in requests]
    deregisters = [
        message for message in parsed
        if (OBSERVE, b"\x01") in message[4]
    ]
    registers = [
        message for message in parsed
        if (OBSERVE, b"") in message[4]
    ]
    assert {
        tuple(value for number, value in message[4] if number == URI_QUERY)
        for message in deregisters
    } == {(b"if=oic.if.a",), (b"if=oic.if.s",)}
    assert {
        tuple(value for number, value in message[4] if number == URI_QUERY)
        for message in registers
    } == {(b"if=oic.if.a",), (b"if=oic.if.s",)}


def test_observe_token_space_fails_closed_without_overwriting_relation():
    session = _session()
    session._send_dgram = Mock()
    session._observe_tokens = {
        bytes([value]): f"/resource/{value}" for value in range(1, 256)
    }
    session._observe_queries = {
        token: () for token in session._observe_tokens
    }

    with pytest.raises(SessionIdentifierError):
        session.subscribe(["mode", "vs", "0"])

    assert len(session._observe_tokens) == 255
    session._send_dgram.assert_not_called()
