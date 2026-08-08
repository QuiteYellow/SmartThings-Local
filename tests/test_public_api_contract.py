"""Compatibility baseline for the published API and LocalThings consumer."""

from __future__ import annotations

import inspect

from smartthings_local.ocf.observe_refresh import ObserveRefreshTask
from smartthings_local.ocf.state_cache import StateCache
from smartthings_local.protocol.auth import AuthenticationProvider, CertificateAuth
from smartthings_local.protocol.dtls_session import DtlsCoapSession


def _assert_compatible_signature(callable_object, expected: list[str]) -> None:
    """Require the existing call surface while allowing safe extensions."""
    parameters = list(inspect.signature(callable_object).parameters.values())
    assert [parameter.name for parameter in parameters[: len(expected)]] == expected
    for parameter in parameters[len(expected) :]:
        assert (
            parameter.kind
            in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
            or parameter.default is not inspect.Parameter.empty
        )


def test_dtls_session_constructor_keeps_file_memory_and_local_port_inputs():
    _assert_compatible_signature(
        DtlsCoapSession,
        [
            "host",
            "port",
            "cert_path",
            "key_path",
            "cert_pem",
            "key_pem",
            "on_notification",
            "mtu",
            "rate_limit_rps",
            "local_port",
        ],
    )
    auth_parameter = inspect.signature(DtlsCoapSession).parameters["auth"]
    assert auth_parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert auth_parameter.default is None


def test_certificate_auth_is_a_public_authentication_provider():
    provider = CertificateAuth.from_files("/synthetic/cert.pem", "/synthetic/key")
    assert isinstance(provider, AuthenticationProvider)


def test_dtls_session_keeps_current_consumer_methods():
    expected = {
        "close",
        "connect",
        "get",
        "join",
        "pace",
        "ping",
        "post",
        "refresh_observes",
        "start_reader",
        "subscribe",
    }
    assert expected <= set(dir(DtlsCoapSession))
    _assert_compatible_signature(
        DtlsCoapSession.get,
        [
            "self",
            "path_segs",
            "query",
            "timeout",
        ],
    )
    _assert_compatible_signature(
        DtlsCoapSession.post,
        [
            "self",
            "path_segs",
            "body_cbor",
            "timeout",
        ],
    )
    _assert_compatible_signature(
        DtlsCoapSession.subscribe,
        ["self", "path_segs"],
    )


def test_state_cache_keeps_current_consumer_surface():
    _assert_compatible_signature(StateCache, ["descriptor"])
    expected = {
        "apply_optimistic",
        "apply_rep",
        "freshness_s",
        "get",
        "index_device_tree",
        "set_on_change",
        "snapshot",
        "stalest",
    }
    assert expected <= set(dir(StateCache))


def test_observe_refresh_task_keeps_current_consumer_surface():
    _assert_compatible_signature(
        ObserveRefreshTask,
        [
            "session",
            "paths",
            "interval_s",
            "logger",
        ],
    )
    _assert_compatible_signature(
        ObserveRefreshTask.run_forever,
        ["self", "stop"],
    )
