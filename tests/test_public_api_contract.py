"""Compatibility baseline for the published API and LocalThings consumer."""

from __future__ import annotations

import importlib
import inspect
import re
from pathlib import Path

import pytest

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
from smartthings_local.protocol.dtls_probe import diagnose_dtls_handshake
from smartthings_local.protocol.dtls_session import (
    ConnectCancellation,
    DtlsCoapSession,
    ObserveDelivery,
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
from tools import generate_api_docs
from tools.api_contract import API_LAYERS, SUPPORTED_DOWNSTREAM_IMPORTS


_REPO_ROOT = Path(__file__).resolve().parent.parent



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
        "on_observe_delivery",
    ):
        parameter = inspect.signature(DtlsCoapSession).parameters[callback]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is None


def test_observe_delivery_carries_the_full_relation_context():
    """Consumers key on (href, query) and act on `registration`, so both
    have to stay on the record even as fields are added."""
    delivery = ObserveDelivery(href="/power/vs/0", payload=b"on")
    assert delivery.query == ()
    assert delivery.registration is False
    assert delivery.sequence is None
    assert delivery.legacy is False
    assert {"href", "payload", "query", "registration", "sequence",
            "legacy"} <= set(ObserveDelivery.__dataclass_fields__)


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


def test_diagnostic_handshake_accepts_any_authentication_provider():
    parameters = inspect.signature(diagnose_dtls_handshake).parameters
    assert list(parameters) == [
        "host",
        "port",
        "auth",
        "cert_pem",
        "key_pem",
        "cert_path",
        "key_path",
        "retries",
        "timeout",
        "mtu",
        "family",
    ]
    for name in ("auth", "cert_pem", "key_pem", "cert_path", "key_path"):
        assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert parameters[name].default is None

    # A carrier and a raw certificate are alternatives, never a merge.
    with pytest.raises(ValueError):
        diagnose_dtls_handshake(
            "127.0.0.1",
            5684,
            auth=PskAuth(identity=bytes(range(1, 17)), key=b"k" * 16),
            cert_pem="pem",
            key_pem="key",
        )


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


def test_psk_identity_validation_is_reachable_without_a_key():
    # An import flow validates a stored identity before it has a key to pair
    # with it, so this is part of the supported surface rather than an
    # internal guard.
    parameters = inspect.signature(PskAuth.validate_identity).parameters
    assert list(parameters) == ["identity"]
    assert PskAuth.validate_identity(b"i" * 16) is None

    with pytest.raises(ValueError):
        PskAuth.validate_identity(b"i" * 15 + b"\x00")


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


def test_published_api_reference_matches_the_code():
    # docs/api.md is what a downstream maintainer reads instead of unzipping
    # a wheel, which is what happened before it existed. Generated, so a
    # renamed argument or a new supported name fails here rather than
    # quietly leaving the page wrong.
    assert generate_api_docs.main(["--check"]) == 0, (
        "docs/api.md is stale; run python tools/generate_api_docs.py"
    )


def test_every_declared_name_reaches_the_published_reference():
    # A callable gets its own heading; a constant is a row in its module's
    # table. Either way the name has to be findable on the page.
    reference = generate_api_docs.DOC_PATH.read_text()
    for module_name, names in SUPPORTED_DOWNSTREAM_IMPORTS.items():
        assert f"### `{module_name}`" in reference, module_name
        for name in names:
            heading = f"#### `{name}`" in reference
            table_row = f"| `{name}` |" in reference
            assert heading or table_row, f"{module_name}.{name}"


def test_every_supported_module_is_laid_out_exactly_once():
    # The page groups modules by layer. A module added to the contract and
    # forgotten here would be documented nowhere, so the omission fails
    # rather than shipping a page with a hole in it.
    laid_out = [module for _, modules in API_LAYERS for module in modules]

    assert sorted(laid_out) == sorted(SUPPORTED_DOWNSTREAM_IMPORTS)
    assert len(laid_out) == len(set(laid_out))


def test_contents_links_resolve_to_a_heading_on_the_page():
    reference = generate_api_docs.DOC_PATH.read_text()
    anchors = re.findall(r"\]\(#([a-z0-9_-]+)\)", reference)
    headings = {
        generate_api_docs._slug(line)
        for line in reference.splitlines()
        if line.startswith("#")
    }

    assert anchors, "the page should carry a table of contents"
    for anchor in anchors:
        assert anchor in headings, anchor
