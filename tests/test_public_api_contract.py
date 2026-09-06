"""Compatibility baseline for the published API and LocalThings consumer."""

from __future__ import annotations

import importlib
import inspect
import re
from pathlib import Path

from smartthings_local.ocf.observe_refresh import ObserveRefreshTask
from smartthings_local.ocf.state_cache import StateCache
from smartthings_local.protocol.auth import (
    AuthenticationProvider,
    CertificateAuth,
    PskAuth,
    SamsungServerProfile,
    SamsungServerRole,
    ServerCertificateAuth,
)
from smartthings_local.protocol.dtls_session import (
    ConnectCancellation,
    DtlsCoapSession,
)
from smartthings_local.protocol.ocf_discovery import (
    OcfSecurePortDiscoveryResult,
    discover_ocf_secure_ports,
)
from smartthings_local.protocol.ocf_multicast import (
    OcfResponderPortDiscoveryResult,
    discover_ocf_responder_ports,
)
from smartthings_local.protocol.owner_psk import derive_mfg_certificate_owner_psk


_REPO_ROOT = Path(__file__).resolve().parent.parent

# Explicit imports exercised by LocalThings, the reference bridge, and the
# downstream Home Assistant integration. Keep the module boundaries visible;
# this is intentionally not a root-level re-export list.
SUPPORTED_DOWNSTREAM_IMPORTS = {
    "smartthings_local.errors": (
        "AuthenticationError",
        "AuthorizationError",
        "BlockwiseError",
        "EndpointError",
        "HandshakePeerCleanupError",
        "MalformedMessageError",
        "ObserveError",
        "ProbeError",
        "SessionClosedError",
        "SessionError",
        "SessionIdentifierError",
        "SessionResetError",
        "SessionTimeoutError",
        "SmartThingsLocalError",
    ),
    "smartthings_local.protocol.auth": (
        "AuthenticationProvider",
        "CertificateAuth",
        "PskAuth",
        "SamsungServerProfile",
        "SamsungServerRole",
        "ServerCertificateAuth",
    ),
    "smartthings_local.protocol.dtls_session": (
        "ConnectCancellation",
        "DtlsCoapSession",
    ),
    "smartthings_local.protocol.dtls_probe": (
        "ALERT",
        "AMBIGUOUS",
        "COMPLETED",
        "DEAD",
        "DtlsLivenessResult",
        "DtlsPortProbeResult",
        "HELLO_VERIFY_REQUEST",
        "LIVE",
        "REJECTED",
        "SELECTED",
        "SERVER_HELLO",
        "UNREACHABLE",
        "probe_dtls_port",
        "probe_dtls_ports",
    ),
    "smartthings_local.protocol.endpoint": (
        "HostFilteredUdpSocket",
        "ResolvedUdpEndpoint",
        "open_connected_udp_socket",
        "open_host_filtered_udp_socket",
        "resolve_udp_endpoint",
        "resolve_udp_endpoints",
    ),
    "smartthings_local.protocol.ocf_discovery": (
        "OcfSecurePortDiscoveryResult",
        "PlaintextOcfResourceResult",
        "discover_ocf_secure_ports",
        "read_plaintext_ocf_resource",
    ),
    "smartthings_local.protocol.ocf_multicast": (
        "OcfResponderPortDiscoveryResult",
        "discover_ocf_responder_ports",
    ),
    "smartthings_local.protocol.coap": (
        "ACCEPT",
        "BLOCK1",
        "BLOCK2",
        "CF_CBOR",
        "CONTENT_FORMAT",
        "METHOD_DELETE",
        "METHOD_GET",
        "METHOD_POST",
        "TYPE_ACK",
        "TYPE_CON",
        "TYPE_NON",
        "URI_PATH",
        "URI_QUERY",
        "Block2Accumulator",
        "CoapMessage",
        "CoapResponseClassification",
        "block_fields",
        "block_value",
        "build_coap",
        "build_empty_ack",
        "build_get_request",
        "classify_coap_response",
        "decode_uint_option",
        "fmt_code",
        "option_values",
        "parse_coap",
        "parse_coap_message",
        "split_dtls",
    ),
    "smartthings_local.protocol.coap_tcp": (
        "CoapTcpCodecError",
        "CoapTcpMessage",
        "CoapTcpStreamDecoder",
        "build_coap_tcp_csm",
        "build_coap_tcp_delete",
        "build_coap_tcp_get",
        "build_coap_tcp_message",
        "build_coap_tcp_post",
        "encode_uint_option",
        "parse_coap_tcp_message",
    ),
    "smartthings_local.protocol.ble_ocf": (
        "AdaptiveBleOcfReassembler",
        "BleOcfCodecError",
        "BleOcfHeader",
        "BleOcfInterleavedFrameError",
        "BleOcfReassembler",
        "ReassembledBleOcfPdu",
        "decode_header",
        "encode_header",
        "fragment_pdu",
    ),
    "smartthings_local.protocol.owner_psk": (
        "CONFIRMED_MFG_CERTIFICATE_OXM_LABEL",
        "MFG_CERTIFICATE_KEY_BLOCK_LENGTHS",
        "STANDARD_MFG_CERTIFICATE_OXM_LABEL",
        "derive_mfg_certificate_owner_psk",
    ),
    "smartthings_local.ocf.state_cache": ("StateCache",),
    "smartthings_local.ocf.poll_scheduler": ("PollScheduler", "PollTier"),
    "smartthings_local.ocf.keepalive": ("KeepaliveTask",),
    "smartthings_local.ocf.observe_refresh": ("ObserveRefreshTask",),
}


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


def test_supported_downstream_import_contract_resolves_explicitly():
    for module_name, names in SUPPORTED_DOWNSTREAM_IMPORTS.items():
        module = importlib.import_module(module_name)
        for name in names:
            assert getattr(module, name) is not None, f"{module_name}.{name}"


def test_root_packages_do_not_duplicate_the_explicit_module_facade():
    package = importlib.import_module("smartthings_local")
    protocol = importlib.import_module("smartthings_local.protocol")

    assert not hasattr(package, "DtlsCoapSession")
    assert not hasattr(package, "CertificateAuth")
    assert not hasattr(protocol, "DtlsCoapSession")
    assert not hasattr(protocol, "CertificateAuth")


def test_readme_python_examples_are_syntax_checked():
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    examples = re.findall(r"```python\n(.*?)```", readme, flags=re.DOTALL)

    assert len(examples) >= 10
    for index, example in enumerate(examples, start=1):
        compile(example, f"README.md python example {index}", "exec")


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
    for callback in (
        "on_legacy_notification",
        "on_observe_pending",
        "on_observe_error",
    ):
        parameter = inspect.signature(DtlsCoapSession).parameters[callback]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is None


def test_known_host_multicast_discovery_has_a_bounded_explicit_interface_api():
    parameters = inspect.signature(discover_ocf_responder_ports).parameters
    assert list(parameters) == [
        "target_address",
        "interface_address",
        "discovery_port",
        "timeout",
        "rounds",
    ]
    assert parameters["target_address"].default is inspect.Parameter.empty
    for name in ("interface_address", "discovery_port", "timeout", "rounds"):
        assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["interface_address"].default is inspect.Parameter.empty
    assert parameters["discovery_port"].default == 5683
    assert parameters["timeout"].default == 3.0
    assert parameters["rounds"].default == 2

    result = OcfResponderPortDiscoveryResult(
        ports=(43123,),
        attempts=2,
        responses=1,
    )
    assert result.found is True
    assert result.ports == (43123,)


def test_certificate_auth_is_a_public_authentication_provider():
    provider = CertificateAuth.from_files("/synthetic/cert.pem", "/synthetic/key")
    assert isinstance(provider, AuthenticationProvider)

    for factory in (CertificateAuth.from_files, CertificateAuth.from_memory):
        profile_parameter = inspect.signature(factory).parameters["server_profile"]
        assert profile_parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert profile_parameter.default is None


def test_samsung_server_profile_is_public_and_explicitly_bound():
    parameters = inspect.signature(SamsungServerProfile.bound_device).parameters
    assert list(parameters) == [
        "expected_certificate_identity",
        "role",
        "additional_ca_pem",
    ]
    assert (
        parameters["expected_certificate_identity"].default
        is inspect.Parameter.empty
    )
    assert parameters["role"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["role"].default is SamsungServerRole.HOME_APPLIANCE
    assert parameters["additional_ca_pem"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["additional_ca_pem"].default is None

    discovery_parameters = inspect.signature(
        SamsungServerProfile.discover_device
    ).parameters
    assert list(discovery_parameters) == ["role", "additional_ca_pem"]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in discovery_parameters.values()
    )
    assert (
        discovery_parameters["role"].default
        is SamsungServerRole.HOME_APPLIANCE
    )
    assert discovery_parameters["additional_ca_pem"].default is None


def test_server_certificate_auth_is_a_public_authentication_provider():
    profile = SamsungServerProfile.bound_device(
        "abababab-abab-abab-abab-abababababab",
        role=SamsungServerRole.VD_DEVICE,
    )
    provider = ServerCertificateAuth(server_profile=profile)
    assert isinstance(provider, AuthenticationProvider)
    session = DtlsCoapSession("device.example", 5684, auth=provider)
    assert session.auth is provider
    assert session.cert_path is None
    assert session.key_path is None
    assert session.cert_pem is None
    assert session.key_pem is None
    assert session.server_certificate_identity is None
    parameters = inspect.signature(ServerCertificateAuth).parameters
    assert list(parameters) == ["server_profile"]
    assert parameters["server_profile"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["server_profile"].default is inspect.Parameter.empty


def test_psk_auth_is_a_public_authentication_provider():
    provider = PskAuth(identity=b"i" * 16, key=b"k" * 16)
    assert isinstance(provider, AuthenticationProvider)
    parameters = inspect.signature(PskAuth).parameters
    assert list(parameters) == ["identity", "key"]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        and parameter.default is inspect.Parameter.empty
        for parameter in parameters.values()
    )


def test_owner_psk_derivation_keeps_every_security_input_explicit():
    parameters = inspect.signature(
        derive_mfg_certificate_owner_psk
    ).parameters
    assert list(parameters) == [
        "master_secret",
        "client_random",
        "server_random",
        "owner_uuid",
        "device_uuid",
        "cipher_name",
        "oxm_label",
    ]
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        and parameter.default is inspect.Parameter.empty
        for parameter in parameters.values()
    )


def test_dtls_session_keeps_current_consumer_methods():
    expected = {
        "close",
        "connect",
        "delete",
        "get",
        "join",
        "abort",
        "pace",
        "ping",
        "post",
        "quiesce_for_close",
        "refresh_observes",
        "start_reader",
        "subscribe",
        "unsubscribe",
    }
    assert expected <= set(dir(DtlsCoapSession))
    _assert_compatible_signature(DtlsCoapSession.connect, ["self"])
    connect_timeout = inspect.signature(DtlsCoapSession.connect).parameters[
        "timeout"
    ]
    assert connect_timeout.kind is inspect.Parameter.KEYWORD_ONLY
    assert connect_timeout.default is None
    connect_cancel = inspect.signature(DtlsCoapSession.connect).parameters[
        "cancel"
    ]
    assert connect_cancel.kind is inspect.Parameter.KEYWORD_ONLY
    assert connect_cancel.default is None
    connect_cleanup = inspect.signature(DtlsCoapSession.connect).parameters[
        "cleanup_hvr_peer"
    ]
    assert connect_cleanup.kind is inspect.Parameter.KEYWORD_ONLY
    assert connect_cleanup.default is False
    assert callable(ConnectCancellation().set)
    _assert_compatible_signature(
        DtlsCoapSession.quiesce_for_close,
        ["self"],
    )
    _assert_compatible_signature(DtlsCoapSession.abort, ["self"])
    _assert_compatible_signature(
        DtlsCoapSession.get,
        [
            "self",
            "path_segs",
            "query",
            "timeout",
        ],
    )
    subscribe_query = inspect.signature(DtlsCoapSession.subscribe).parameters[
        "query"
    ]
    assert subscribe_query.kind is inspect.Parameter.KEYWORD_ONLY
    assert subscribe_query.default == ()
    _assert_compatible_signature(
        DtlsCoapSession.unsubscribe,
        ["self", "path_segs"],
    )
    refresh_queries = inspect.signature(
        DtlsCoapSession.refresh_observes
    ).parameters["queries_by_href"]
    assert refresh_queries.kind is inspect.Parameter.KEYWORD_ONLY
    assert refresh_queries.default is None
    get_extra_options = inspect.signature(DtlsCoapSession.get).parameters[
        "extra_options"
    ]
    assert get_extra_options.kind is inspect.Parameter.KEYWORD_ONLY
    assert get_extra_options.default == ()
    _assert_compatible_signature(
        DtlsCoapSession.post,
        [
            "self",
            "path_segs",
            "body_cbor",
            "timeout",
        ],
    )
    post_parameters = inspect.signature(DtlsCoapSession.post).parameters
    for name in ("query", "extra_options"):
        assert post_parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert post_parameters[name].default == ()
    _assert_compatible_signature(
        DtlsCoapSession.delete,
        [
            "self",
            "path_segs",
            "timeout",
        ],
    )
    delete_parameters = inspect.signature(DtlsCoapSession.delete).parameters
    for name in ("query", "extra_options"):
        assert delete_parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert delete_parameters[name].default == ()
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


def test_ocf_secure_port_discovery_has_a_small_composable_surface():
    _assert_compatible_signature(discover_ocf_secure_ports, ["host"])
    result = OcfSecurePortDiscoveryResult(
        ports=(5684,),
        attempts=1,
        response_received=True,
    )

    assert result.found
    assert result.ports == (5684,)
