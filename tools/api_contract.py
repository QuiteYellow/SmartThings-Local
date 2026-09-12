"""The published module-level API contract.

`SUPPORTED_DOWNSTREAM_IMPORTS` is the surface downstream code may import by
name. It sits here rather than in the test that enforces it, or in the
package itself, because two things read it: `tests/test_public_api_contract.py`
proves every name resolves, and `tools/generate_api_docs.py` renders
`docs/api.md` from it. A name absent from this mapping is reachable but
incidental, and may move.
"""

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
        "ObserveDelivery",
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
        "diagnose_dtls_handshake",
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


# Reading order for `docs/api.md`. Grouped by layer because the module list
# alone gives a reader no way in: fifteen flat names do not say which one a
# session comes from and which one is a codec. Every module in
# SUPPORTED_DOWNSTREAM_IMPORTS must appear in exactly one layer, which
# tests/test_public_api_contract.py enforces, so adding a module cannot
# silently drop it from the page.
API_LAYERS = (
    (
        "Errors",
        ("smartthings_local.errors",),
    ),
    (
        "Authentication",
        ("smartthings_local.protocol.auth",),
    ),
    (
        "Sessions",
        ("smartthings_local.protocol.dtls_session",),
    ),
    (
        "Discovery and probing",
        (
            "smartthings_local.protocol.dtls_probe",
            "smartthings_local.protocol.ocf_discovery",
            "smartthings_local.protocol.ocf_multicast",
            "smartthings_local.protocol.endpoint",
        ),
    ),
    (
        "Wire formats",
        (
            "smartthings_local.protocol.coap",
            "smartthings_local.protocol.coap_tcp",
            "smartthings_local.protocol.ble_ocf",
            "smartthings_local.protocol.owner_psk",
        ),
    ),
    (
        "Reference-bridge helpers",
        (
            "smartthings_local.ocf.state_cache",
            "smartthings_local.ocf.poll_scheduler",
            "smartthings_local.ocf.keepalive",
            "smartthings_local.ocf.observe_refresh",
        ),
    ),
)
