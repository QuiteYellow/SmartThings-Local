# SmartThings-Local

**`smartthings-local` is a Python library for local, cloud-free control of Samsung connected appliances over authenticated CoAP-DTLS.** It gives you the DTLS-CoAP transport, a tiered polling + OBSERVE state layer, and identity-cert tooling for AC14K_M-compatible firmware. Newer OCF-PKI appliances require a different authentication profile; see [the laundry compatibility findings](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-pki-laundry.md). Supported profiles can read state and write commands on the LAN with no SmartThings cloud round-trip.

The repo also ships a self-contained **reference bridge demo** (`mqtt_demo/`) that turns the library into auto-discovered Home Assistant entities over MQTT. One process supervises multiple appliances, each on its own DTLS session. Configuration, deployment and per-appliance coverage are in [`docs/bridge-demo.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/bridge-demo.md).

<img width="1600" height="882" alt="image" src="https://github.com/user-attachments/assets/3b0e2646-66c7-4950-aee3-93086a6ed1e4" />

> **Just want to control your Samsung appliance from Home Assistant?**
> Use [localthings](https://github.com/mbillow/localthings), a Home
> Assistant custom component built on the `smartthings-local` package.
> This repo is the protocol research project, the library itself, and a
> self-contained MQTT bridge demo; new appliance support (capability
> mappings, HA entities) should go to localthings, not here.

## Documentation

- **[`docs/api.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/api.md)** — the supported API: every name downstream code may import, with its signature. Generated from the code, so it cannot drift.
- **[`docs/bridge-demo.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/bridge-demo.md)** — the MQTT bridge demo: what it exposes, how to configure and deploy it, per-appliance coverage, config keys and topics.
- **[`docs/appliance-compatibility.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md)** — which appliances answer a local session, how to check, and the firmware-family caveat.
- **[`docs/certificates.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/certificates.md)** — obtaining the client certificate compatible firmware accepts.
- [`docs/ocf-pki-laundry.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-pki-laundry.md) — the newer OCF-PKI appliance generation, and why an AC14K_M certificate is refused there.
- [`docs/ocf-vd-devices.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-vd-devices.md) — server-authenticated findings from Samsung VD hardware.
- [`docs/use-of-ai.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/use-of-ai.md) — how an AI assistant is used here, and the review the output goes through.

## Quick start (library)

`smartthings-local` is on PyPI:

```sh
pip install smartthings-local
```

For compatible firmware, mint a client cert once (see
[Getting a certificate](#getting-a-certificate)), then drive a
session directly:

```python
import cbor2
from smartthings_local.protocol.auth import CertificateAuth
from smartthings_local.protocol.dtls_session import DtlsCoapSession

auth = CertificateAuth.from_files(
    "certs/client_fullchain.pem",
    "certs/client.key",
)
sess = DtlsCoapSession(
    "192.0.2.100", 49154,
    auth=auth,
    on_notification=lambda href, payload: ...,
)
sess.connect()
sess.start_reader()

code, body = sess.get(["device", "0"])                       # Block2-aware read
code, _    = sess.post(["mode", "vs", "0"], cbor2.dumps({}))  # write
sess.subscribe(["operational", "state", "vs", "0"])          # OBSERVE
sess.close()
```

`get()` and `post()` accept repeated URI-query strings. They also accept
ordered `(number, bytes)` options for reviewed OCF extensions while retaining
ownership of path, query, content-format, Accept, Observe, and blockwise
options:

```python
code, body = sess.get(
    ["oic", "res"],
    query=("rt=oic.r.doxm",),
    extra_options=((2049, b"\x08\x00"),),
)
```

Path and query text is UTF-8 encoded, and every value is size bounded before
anything is sent. Additional options remain arbitrary bytes, must already be
ordered by option number, and may repeat a number when the option is
repeatable.

`delete()` uses the same path, query, extension-option, timeout, and response
contract without sending a request payload.

Observe relations may also include repeated URI-query strings. The same query
is retained for a blockwise notification refetch and for best-effort
deregistration:

```python
sess.subscribe(["mode", "vs", "0"], query=("if=oic.if.b",))
```

An RFC 7641 relation is confirmed only by a valid Observe response option;
duplicate and stale 24-bit sequence values are not delivered. Some older
Samsung firmware omits that option. For those devices, a plain initial `2.05`
is probationary until a later packet arrives on the same token with a different
Message ID. Its complete representation is still delivered through
`on_notification`; a blockwise representation is re-read before delivery.
Optional `on_observe_pending`, `on_legacy_notification`, and `on_observe_error`
constructor callbacks let consumers keep that compatibility path distinct from
confirmed RFC notifications and ordinary polling.

`on_observe_delivery` replaces `on_notification` for consumers that need the
whole relation context rather than `(href, payload)`. It receives one
`ObserveDelivery`, whose `registration` field separates the server's answer to
the register CON from a change the server chose to send, and whose `query`
completes the relation identity when one href carries several query-qualified
relations. `sequence` is the Observe option value, or `None` on the optionless
responses some firmware sends. Setting it suppresses `on_notification` and
`on_legacy_notification`, so representations are delivered once:

```python
def on_delivery(delivery):
    if delivery.registration:
        seed(delivery.href, delivery.payload)   # answered because we asked
    else:
        record_push(delivery.href, delivery.payload)

sess = DtlsCoapSession(..., on_observe_delivery=on_delivery)
```

Periodic renewal can target only the relations that need it; unrelated
observations remain active. Existing query variants are preserved unless the
caller supplies an explicit replacement:

```python
successful, failures = sess.refresh_observes(
    (("mode", "vs", "0"),),
    queries_by_href={"/mode/vs/0": ("if=oic.if.b",)},
)
removed = sess.unsubscribe(("mode", "vs", "0"))
```

`successful` reports hrefs whose replacement registration datagram was sent;
confirmation still comes from the Observe callbacks. `unsubscribe()` retires
every query-qualified relation for that exact path without disturbing sibling
paths. Refresh, unsubscribe, and orderly close pace every deregistration just
as `subscribe()` paces each registration, avoiding request bursts during
relation maintenance.

POST bodies through 1024 bytes retain the single-request behavior. Larger
bodies use token-stable Block1 requests under one monotonic timeout, include
Size1 on the first request, honor a server-requested smaller block size, and
return only the final response. Upload bodies are limited to 512 KiB and 1024
block requests; incomplete or contradictory success acknowledgements fail as
`BlockwiseError`.

`connect()` uses a 12-second monotonic DTLS handshake deadline by default. A
caller that needs a shorter bounded attempt can pass a positive finite value
without changing later reader timeouts. OpenSSL's DTLS timer schedules flight
retransmissions within that same deadline:

```python
sess.connect(timeout=4.0)
```

The deadline stops further setup, retries, and network waits. If OpenSSL
reports that the handshake completed at the deadline boundary, the completed
session is retained rather than torn down as a timeout.

Connection attempts can also use a one-way cancellation signal. The signal is
backed by a socketpair, so setting it wakes the network wait immediately while
OpenSSL retains control of DTLS retransmission timing:

```python
from smartthings_local.protocol.dtls_session import ConnectCancellation

cancel_connect = ConnectCancellation()
# Another thread may call cancel_connect.set().
sess.connect(timeout=8.0, cancel=cancel_connect)
```

Setting the signal stops subscribed connection attempts and closes their
temporary UDP sockets. It does not alter an already established session.
Interrupted attempts raise `SessionClosedError`.

Some Samsung OCF-PKI firmware can retain a half-open DTLS peer when a
handshake stops immediately after the cookie exchange. A caller using a
`SamsungServerProfile` and a fixed non-zero local UDP port can opt in to the
narrow cleanup path:

```python
from smartthings_local.errors import HandshakePeerCleanupError

try:
    sess.connect(timeout=8.0, cleanup_hvr_peer=True)
except HandshakePeerCleanupError:
    # Apply the device-specific settle delay, then retry under caller policy.
    schedule_connection_retry()
```

Cleanup is sent only after the bounded transcript contains at least two
complete epoch-zero ClientHello messages and every received record is a
complete epoch-zero HelloVerifyRequest. A malformed, fragmented, mixed, or
oversized transcript remains an ordinary `SessionTimeoutError`. On the exact
HVR-only shape, the session sends one epoch-zero fatal `handshake_failure`
alert, closes the temporary socket, and raises `HandshakePeerCleanupError`.
The package never sleeps or retries automatically, so the caller retains the
overall recovery budget and can use the settle interval validated for its
device. Cancellation and backend failures never trigger the alert.

Hosts that stop network work before their blocking executor drains can use the
session's two-phase shutdown. `quiesce_for_close()` is terminal: it interrupts
an in-progress handshake, wakes pending requests and notification refetches,
and rejects new work while retaining an established DTLS socket and active
Observe relation metadata. A subsequent `close()` paces explicit Observe
deregistrations, flushes the authenticated close-notify record, and then closes
that socket:

```python
sess.quiesce_for_close()  # safe from the host's early shutdown phase
# Later, after session workers have joined:
sess.close()
```

Use `abort()` when orderly shutdown is impossible. It performs the same
terminal wakeup but closes the established socket immediately, without waiting
for close-notify. All three methods are idempotent; a quiesced or aborted
session cannot be connected again.

## Writes and retransmission

Reads retransmit each Block2 request; writes send once. Where a lost write is
the proven cause, and not a device refusing load, `write_max_attempts` lets
`post()` retransmit inside the caller's timeout, backing off per RFC 7252 §4.2
and pacing each retransmit:

```python
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth, write_max_attempts=3)
```

Each attempt resends the byte-identical datagram, so a §4.5 server answers the
duplicate from its dedupe cache. Retrying from the caller cannot do that — a second
`post()` mints a fresh Message ID, which is a new request. It defaults to `1`
(send once) because retransmitting into an appliance that is already dropping
under load turns one lost write into several, and §4.5 dedupe is unverified on
RT-OCF.

Note that `post()`'s `timeout` bounds the whole call, rate-limit pacing
included, rather than only the wait that follows the send. Every attempt has to
share one budget, and a caller that asked for 8 seconds should not wait 8
seconds plus however long the limiter withheld the request. At the default 5
req/s that costs at most 200 ms of it; at `rate_limit_rps=1.0` it costs a full
second, so pair a low rate limit with a longer timeout.

## Authentication

Every session needs a credential. A certificate provider covers the
AC14K_M-compatible firmware families; the newer OCF-PKI generation needs a
pinned server profile or a PSK, and
[docs/ocf-pki-laundry.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-pki-laundry.md)
covers which is which.

### Getting a certificate

A compatible appliance accepts a client certificate whose Subject DN carries a UUID those appliances' on-device ACLs grant access to. On the appliances tested the signer is not checked, so `setup_cert.py` self-signs by default, extracting the UUID live from the cloud gateway's certificate. Pass `--fallback` to sign with `AC14K_M` instead, for a device that validates the chain:

```sh
python setup_cert.py
```

That writes `certs/client_fullchain.pem` and `certs/client.key`. Why it works, how durable it is, and how to read the UUID yourself are in [docs/certificates.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/certificates.md). Whether a given appliance accepts this credential at all is in [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md).

### Credentials from memory

If the cert/key are minted at runtime and never written to disk (e.g. inside
an HA config flow), create the provider from memory instead:

```python
auth = CertificateAuth.from_memory(cert_pem, key_pem)
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth)
```

### Samsung server-certificate profiles

Some newer OCF-PKI devices require an exact Samsung DTLS offer and present a
hardware certificate whose subject contains a certificate UUID. That UUID can
be distinct from the runtime OCF device UUID reported by `/oic/d`, so callers
must obtain and verify the certificate identity independently. When the caller
already has an authorized client certificate and a previously verified
hardware-certificate UUID, opt in to both requirements explicitly:

```python
from smartthings_local.protocol.auth import (
    CertificateAuth,
    SamsungServerProfile,
)

server_profile = SamsungServerProfile.bound_device(
    expected_certificate_uuid,
    additional_ca_pem=additional_samsung_ca_pem,
)
auth = CertificateAuth.from_memory(
    cert_pem,
    key_pem,
    server_profile=server_profile,
)
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth)
```

The default profile is restricted to Samsung home-appliance leaves with
`OU=OCF HA Device`. The profile limits the ClientHello to P-256,
`ECDHE-ECDSA-AES128-GCM-SHA256`, and the observed SHA-256/SHA-1 RSA/ECDSA
signature set, disables session tickets, preserves certificate-chain
verification, and requires the exact subject role
`C=KR, O=Samsung Electronics, OU=OCF HA Device` with a common name ending in
the expected certificate UUID. `additional_ca_pem` is optional and accepts
only a bounded PEM CA-certificate chain; it is applied only to this profiled
context. Without a profile, `CertificateAuth` retains its existing verification
behavior.

Samsung VD-family devices can present the same wire profile with the distinct
`OU=OCF VD Device` role. Select that role explicitly; profiles never fall back
between device classes:

```python
from smartthings_local.protocol.auth import (
    SamsungServerProfile,
    SamsungServerRole,
    ServerCertificateAuth,
)

server_profile = SamsungServerProfile.bound_device(
    expected_certificate_uuid,
    role=SamsungServerRole.VD_DEVICE,
)
auth = ServerCertificateAuth(server_profile=server_profile)
sess = DtlsCoapSession("192.0.2.100", 5684, auth=auth)
```

`ServerCertificateAuth` is for a server-authenticated channel that does not
send a client certificate, such as the initial DTLS carrier used by
manufacturer-certificate OTM. It still verifies the CA chain, exact selected
subject role, and pinned certificate UUID. It cannot be combined with client
credentials.

An explicit first-use workflow may need to authenticate the Samsung hardware
certificate before its subject UUID is known. Use the discovery profile only
for that bounded step:

```python
server_profile = SamsungServerProfile.discover_device(
    additional_ca_pem=additional_samsung_ca_pem,
)
auth = ServerCertificateAuth(server_profile=server_profile)
sess = DtlsCoapSession("192.0.2.100", 5684, auth=auth)
sess.connect()
certificate_uuid = sess.server_certificate_identity
```

The discovery profile still verifies the CA chain and the complete selected
Samsung subject role before `connect()` exposes the non-zero certificate UUID.
It does not trust an arbitrary first certificate, and neither the immutable
profile nor its provider retains the learned identity. The caller must bind
that UUID to independently authenticated device evidence, such as `/oic/d`
read over the same authenticated session, before persisting it. Subsequent
connections should use `bound_device()` with that verified binding. The
certificate UUID and the OCF device UUID are separate identities and must not
be assumed equal.

This API deliberately does not discover, mint, authorize, provision, rotate,
or persist credentials, and it performs no ownership transfer or OCF security
resource writes. In particular, the server-only provider can authenticate the
initial manufacturer-certificate channel, but it does not implement the OTM
that follows. The already-owned new-PKI case in
[issue #16](https://github.com/QuiteYellow/SmartThings-Local/issues/16) still
requires an authorized client identity before ordinary protected resources
can be used.

For compatibility, the existing `cert_path` / `key_path` and `cert_pem` /
`key_pem` session arguments remain supported without a deprecation warning.
They are routed through `CertificateAuth` internally. Do not combine `auth`
with those legacy arguments.

### PSK credentials

An existing OCF PSK credential can be supplied through `PskAuth`:

```python
from smartthings_local.protocol.auth import PskAuth

auth = PskAuth(identity=psk_identity, key=psk_key)
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth)
```

The identity must be the raw 16-byte OCF UUID and the key exactly 16 or 32 bytes. `PskAuth` selects only `ECDHE-PSK-AES128-CBC-SHA256` and does not acquire, derive, provision, rotate, or persist credentials. Ownership transfer and credential discovery are outside this package.

An identity containing a zero byte is rejected, and that limit is OpenSSL's rather than the appliance's. An OCF device takes the identity as bytes with an explicit length, so a zero byte means nothing to it, but OpenSSL's DTLS 1.2 PSK client callback returns the identity as a C string. Measured against OpenSSL 4.0.0, a 16-byte identity with a NUL at byte 8 reaches the wire as 8 bytes and the handshake raises nothing locally, so the appliance answers a truncated identity it has never seen. DTLS 1.2 offers no length-carrying PSK callback, so such a credential is unusable here: roughly 6% of uniformly random 16-byte identities, and about 5% of UUIDv4s, which have two fixed bytes.

Code holding a credential can check it, and report why, before building a provider or storing anything:

```python
try:
    PskAuth.validate_identity(psk_identity)
except (TypeError, ValueError) as exc:
    print(f"unusable PSK identity: {exc}")
```

### OwnerPSK derivation

Code that has already completed an authenticated manufacturer-certificate
session can derive IoTivity's 128-bit OwnerPSK from the resulting TLS state:

```python
from smartthings_local.protocol.owner_psk import derive_mfg_certificate_owner_psk

owner_psk = derive_mfg_certificate_owner_psk(
    master_secret=master_secret,
    client_random=client_random,
    server_random=server_random,
    owner_uuid=owner_uuid,
    device_uuid=device_uuid,
    cipher_name=cipher_name,
    oxm_label=selected_oxm_label,
)
```

The caller must supply the exact authenticated TLS values, non-nil raw OCF
UUIDs, negotiated cipher name, and label for the selected OXM. Use
`STANDARD_MFG_CERTIFICATE_OXM_LABEL` for `oic.sec.doxm.mfgcert` and
`CONFIRMED_MFG_CERTIFICATE_OXM_LABEL` for
`x.org.iotivity.conmfgcert`; do not infer the label from the appliance model.
The helper performs deterministic key derivation only: it does not access a
session, discover credentials, choose an ownership method, write security
resources, run OTM, or persist the result.

## Supported library imports

**[`docs/api.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/api.md) is the reference**: every supported name, grouped by
layer, with its signature read off the code. It is generated, so it cannot
drift.

Import from the owning module, as the examples here do. `smartthings_local`
and `smartthings_local.protocol` deliberately do not re-export those names: a
root facade would hide which wire layer an application depends on, and would
collide across the datagram, TCP and BLE codecs. Names beginning with `_`,
modules absent from `docs/api.md`, and `mqtt_demo` are outside the contract.

`0.1.x` keeps the `DtlsCoapSession` constructor and method signatures
additive. The `cert_path`/`key_path` and `cert_pem`/`key_pem` pairs stay
supported without warnings, though new code should prefer a `CertificateAuth`
or `PskAuth` provider so the authentication requirement is explicit. Expect
additive keyword-only options and new classified error subclasses in
compatible releases; a broad catch stays valid, since every classified error
keeps its documented built-in base.

The session lifecycle is caller-owned: finish `connect()` before
`start_reader()`, one reader per session, then `quiesce_for_close()`/`close()`
or `abort()`. Notification callbacks run on the reader path, so hand work off
instead of blocking it.

## CoAP over TCP framing

`smartthings_local.protocol.coap_tcp` provides the pure reliable-transport
wire codec used by Samsung's IoTivity stack. It follows the variable-length
header defined by [RFC 8323](https://www.rfc-editor.org/rfc/rfc8323.html) and
corroborated by Samsung's public IoTivity 1.2 sources for
[`CAGeneratePDUImpl`](https://github.com/Samsung/TizenRT/blob/0df9b54dfd35d9aaba2c16eb2ef9f4b4b6a5f545/external/iotivity/iotivity_1.2-rel/resource/csdk/connectivity/src/caprotocolmessage.c)
and
[`coap_get_total_message_length`](https://github.com/Samsung/TizenRT/blob/0df9b54dfd35d9aaba2c16eb2ef9f4b4b6a5f545/external/iotivity/iotivity_1.2-rel/resource/csdk/connectivity/lib/libcoap-4.1.1/pdu.c).

Builders cover the opening CSM, raw messages, and GET, POST, and DELETE
convenience forms. The CSM builder can advertise Max-Message-Size and
Block-Wise-Transfer without owning connection policy.
`CoapTcpStreamDecoder` accepts partial or concatenated byte-stream chunks,
emits only complete parsed messages, and rejects an oversized declaration as
soon as its length prefix is available:

```python
from smartthings_local.protocol.coap_tcp import (
    CoapTcpStreamDecoder,
    build_coap_tcp_get,
)

request = build_coap_tcp_get("/oic/res", token=b"\x01")
decoder = CoapTcpStreamDecoder(max_message_size=64 * 1024)
messages = decoder.feed(received_chunk)
```

The module opens no TCP/TLS/Bluetooth connection, chooses
no carrier, and performs no setup or ownership work. Those remain caller policy.

## BLE OCF framing

`smartthings_local.protocol.ble_ocf` provides the pure fragmentation layer
used by IoTivity's GATT transport. The two-byte header carries a start flag,
source and destination virtual ports, and a secure flag. A start frame also
carries the PDU's four-byte big-endian total length. The format and full-frame
fragmentation behavior are documented in Samsung's public IoTivity sources:
[`cafragmentation.h`](https://github.com/Samsung/TizenRT/blob/0df9b54dfd35d9aaba2c16eb2ef9f4b4b6a5f545/external/iotivity/iotivity_1.2-rel/resource/csdk/connectivity/inc/cafragmentation.h),
[`cafragmentation.c`](https://github.com/Samsung/TizenRT/blob/0df9b54dfd35d9aaba2c16eb2ef9f4b4b6a5f545/external/iotivity/iotivity_1.2-rel/resource/csdk/connectivity/src/adapter_util/cafragmentation.c),
and the adapter's
[`caleadapter.c`](https://github.com/Samsung/TizenRT/blob/0df9b54dfd35d9aaba2c16eb2ef9f4b4b6a5f545/external/iotivity/iotivity_1.2-rel/resource/csdk/connectivity/src/bt_le_adapter/caleadapter.c).

The BLE payload is the same reliable-transport CoAP message described above.
For example, a caller that already owns GATT connection policy can wrap a
plaintext discovery request and strictly reassemble response characteristic
values:

```python
from smartthings_local.protocol.ble_ocf import (
    AdaptiveBleOcfReassembler,
    fragment_pdu,
)
from smartthings_local.protocol.coap_tcp import build_coap_tcp_get

request_pdu = build_coap_tcp_get("/oic/res", token=b"\x01")
request_frames = fragment_pdu(
    request_pdu,
    mtu=20,
    source_port=1,
    destination_port=0,
    secure=False,
)

decoder = AdaptiveBleOcfReassembler(max_pdu_size=64 * 1024)
response = decoder.feed(received_characteristic_value)
if response is not None:
    response_pdu = response.pdu
```

Here `mtu` means IoTivity's maximum complete characteristic-value frame size,
not the raw ATT MTU. The default ATT MTU of 23 normally leaves 20 bytes for a
characteristic value. The adaptive reassembler infers a peer's usable frame
size from each first frame, rejects inconsistent continuation metadata and
lengths, and discards partial state after an error.

The two-byte IoTivity header has no fragment sequence number. A duplicated or
reordered full-size continuation with otherwise identical metadata is
therefore indistinguishable at this layer; IoTivity relies on GATT's ordered
delivery. The codec does reject duplicate starts, orphan continuations,
detectable missing or shortened fragments, and changed port or secure flags.

The secure bit is transport metadata; this codec does not encrypt or
authenticate the PDU. It also does not connect to Bluetooth, select GATT
characteristics, discover credentials, or perform setup or ownership work.

## Library reference

The sections below cover the rest of the library surface: the error types a
call can raise, endpoint resolution, and the two bounded plaintext reads used
to find an appliance before authenticating to it.

### Classified errors

Runtime transport failures use the public types in

```python
from smartthings_local.errors import SessionClosedError, SmartThingsLocalError
```

All classified errors inherit from `SmartThingsLocalError` and expose a stable
`code`. Their messages are fixed and deliberately omit remote endpoints, local
paths, credential metadata, raw packets, and backend exception text. Existing
callers can keep catching the built-in types used by earlier releases:

| Error | Stable code | Compatible built-in |
| --- | --- | --- |
| `EndpointError` | `endpoint` | `OSError` |
| `ProbeError` | `probe` | `ConnectionError` |
| `SessionError` | `session` | `ConnectionError` |
| `AuthenticationError` | `authentication` | `ConnectionError` |
| `AuthorizationError` | `authorization` | `PermissionError` |
| `SessionTimeoutError` | `timeout` | `TimeoutError` |
| `HandshakePeerCleanupError` | `handshake_peer_cleanup` | `TimeoutError` |
| `SessionClosedError` | `session_closed` | `ConnectionError` |
| `MalformedMessageError` | `malformed_message` | `ValueError` |
| `BlockwiseError` | `blockwise` | `ConnectionError` |
| `ObserveError` | `observe` | `ConnectionError` |

Constructor argument validation remains a normal `ValueError`. When a backend
failure is chained for debugging, the cause is replaced with a fixed redacted
marker; raw backend text is not copied into the public error or its formatted
traceback.

### Resolved UDP endpoints

Sessions resolve a host to a first-class `ResolvedUdpEndpoint` and use a
connected UDP socket for the DTLS transport. Connecting the datagram socket
pins it to the exact resolved peer, so unrelated datagrams from another host
using the same port are discarded by the operating system. IPv4, IPv6, and
scoped IPv6 tuples are preserved without putting the address or scope in the
endpoint's `repr`.

Address family and fixed source-port behavior are explicit and optional:

```python
import socket

sess = DtlsCoapSession(
    "device.example",
    49154,
    cert_pem=cert_pem,
    key_pem=key_pem,
    family=socket.AF_INET6,
    local_port=56830,
)
sess.connect()
assert sess.endpoint.family == socket.AF_INET6
```

The resolver retains candidate order and the socket setup tries the next
candidate after a family, bind, or connect failure. Resolution and socket
setup failures raise the redacted `EndpointError` documented above.

### Dynamic plaintext OCF response ports

Some OCF devices listen for multicast discovery on UDP 5683 but send their
response from a different port that changes after a power cycle. A caller that
already knows the device's IPv4 address can discover those plaintext response
port candidates on one explicit LAN interface:

```python
from smartthings_local.protocol.ocf_multicast import (
    discover_ocf_responder_ports,
)

result = discover_ocf_responder_ports(
    "192.0.2.20",
    interface_address="192.0.2.10",
)
for discovery_port in result.ports:
    pass  # use for a bounded, source-bound /oic/res lookup
```

The call sends unfiltered current OCF and legacy IoTivity directory requests,
plus a legacy DOXM-filtered fallback, under one deadline. It accepts only
token-correlated replies from the expected host, closes its multicast socket
before returning, and omits addresses and ports from its result representation.
Returned ports are unauthenticated candidates, not DTLS endpoints; directory
parsing, DTLS liveness, and authenticated device identity remain separate
checks.

### Bounded plaintext OCF resource reads

Once the public request port is known, callers can read an absolute OCF href
without reimplementing the source-port and Block2 handling used by directory
discovery:

```python
import cbor2

from smartthings_local.protocol.ocf_discovery import (
    read_plaintext_ocf_resource,
)

resource = read_plaintext_ocf_resource(
    "192.0.2.20",
    "/oic/d",
    port=5683,
)
if resource.successful:
    device = cbor2.loads(resource.payload)
elif resource.complete:
    print(f"appliance returned CoAP code {resource.code:#04x}")
else:
    print(resource.error_code)
```

The reader sends a read-only NON GET and returns the raw body instead of
assuming one representation shape. It keeps one token across Block2, pins a
different response source port after the first correlated reply, uses a fresh
message ID for each request attempt, and applies one deadline plus the same
32-block, 64-KiB, and datagram bounds as directory discovery. Successful
representations must either omit Content-Format or identify OCF/CoAP CBOR.

A complete 4.xx or 5.xx response is returned with its code and body rather
than converted into a transport failure. Public resources vary by firmware:
reaching a plaintext endpoint does not authenticate the appliance or grant
access to protected appliance data. `content_format` and `size2` describe
successful representations; they are `None` for a non-success diagnostic body.

For a full worked integration, the higher-level `smartthings_local.ocf` layer (`StateCache`, `PollScheduler`, `KeepaliveTask`, `ObserveRefreshTask`) coordinates tiered polling and OBSERVE on top of a session. The MQTT bridge demo below wires all of it together.

## Repo layout

```
smartthings_local/                   The installable library — `pip install smartthings-local`
  __init__.py
  protocol/                          DTLS-CoAP transport (reusable by any consumer, not just MQTT)
    __init__.py
    auth.py                          Immutable DTLS authentication providers
    coap.py                          CoAP wire protocol: message encode/decode, token handling
    dtls_session.py                  DTLS session: handshake, client-cert auth (file or in-memory PEM), Block2, liveness
    dtls_probe.py                    Stateless DTLS liveness + opt-in stateful diagnostic
    dtls_handshake.py                Shared memory-BIO handshake driver, bounded by a monotonic deadline (used by session + probe)
    owner_psk.py                     Pure manufacturer-certificate OwnerPSK derivation
    ocf_discovery.py                 Bounded public OCF secure-port discovery
    ocf_root_ca.pem                  Samsung OCF root CA, bundled for handshake verification
  ocf/                               OCF resource + state layer (reusable)
    __init__.py
    state_cache.py                   StateCache — single source of truth for appliance state
    poll_scheduler.py                Tiered adaptive polling (hot/warm/cold + sweep)
    keepalive.py                     CoAP liveness checks (empty-CON pings)
    observe_refresh.py               OBSERVE registration management
mqtt_demo/                           MQTT bridge demo (consumes smartthings_local)
  __init__.py
  __main__.py                        Entry point — loads config, spawns one bridge per appliance
  config.py                          SharedConfig + ApplianceConfig dataclasses
  logger.py                          Tagged logger helpers
  bridge.py                          Bridge — one DTLS session per appliance, descriptor-driven
  descriptor.py                      ApplianceDescriptor dataclass + HA discovery helpers
  clock_sync.py                      Periodic appliance clock write (write-only resource, host-clock gated)
  samples/
    __init__.py                      Sample DESCRIPTORS registry (frozen reference implementations)
    dryer.py                         Dryer descriptor (paths, flatten, discovery, commands)
    oven.py                          Oven descriptor
    fridge.py                        Fridge descriptor (ARTIK051 firmware family)
  Dockerfile                         Container build (python:3.11-slim + 3 deps)
  docker-compose.yml                 One service: smartthings-local
  deploy.sh                          tar + ssh + docker compose up --build
  requirements.txt                   Python dependencies for the bridge
  .env.example                       Template — copy to .env, fill in
setup_cert.py                        One-shot cert minting script (live-fetches AC14K_M + UUID)
pyproject.toml                       Packaging — PyPI dist `smartthings-local`, hatch-vcs versioning
tests/                               pytest suite (CoAP wire, state cache, import isolation, cert loading, DTLS probe, bridge port resolution, cert signing, certificate profiles, OwnerPSK derivation, connect deadline, session interruption)
.github/workflows/publish.yml        Build + PyPI Trusted Publishing on `v*` tags
```

`certs/` is gitignored. Drop the privileged client cert + key there; the container mounts that directory read-only at `/config`. See [`localthings`](https://github.com/mbillow/localthings) for production HA integration.

---

## Adding appliance support

The three descriptors in `mqtt_demo/samples/` (dryer, oven, fridge) are
frozen reference implementations: enough to exercise both the newer
Tizen RT 3.x family and the older ARTIK051 family, proving the
`smartthings_local` library layers generalize across firmware generations.
They are not updated for new appliance models.

**To add support for a new appliance, submit it to
[localthings](https://github.com/mbillow/localthings)**, which owns
the capability registry and Home Assistant integration.

---

## Traps to avoid

These each looked like obvious improvements at some point. Each one broke something.

- **Don't add OBSERVE subscriptions on OCF-standard `/<x>/0` paths.** They register successfully but never push. Use the Samsung `/<x>/vs/0` siblings (which do).
- **Don't assume OBSERVE silence means the appliance is broken.** With no route to Samsung's cloud, OBSERVE dispatch goes quiet while the local DTLS session, GETs, POSTs and cache keep working. Measured firewalled: `~14 req/s` dryer, `~8 req/s` oven, 200/200 GETs. The polling tiers are the structural answer to this; treat OBSERVE strictly as an optional accelerator.
- **Don't touch `/oic/sec/*` (doxm, pstat, cred, acl).** The bridge doesn't, and you shouldn't from helper scripts either. Those resources have wedge/brick risk on Samsung's RT-OCF security stack. The bridge surfaces are strictly `/<x>/vs/0` and `/device/0`.
- **Don't run two clients against the same appliance simultaneously.** Samsung's RT-OCF DTLS allows one active session per peer; a second handshake will get the device to drop the new socket. If HA seems to flap, check whether you've got `python -m mqtt_demo` running locally AND the Docker container up.
- **Expect gaps in write coverage, but few are hard limits.** The local DTLS surface appears to expose every write Samsung's own app uses, so a control that isn't wired yet usually just hasn't been mapped: the ceiling is per-surface reverse-engineering, meaning the resource, field and encoding. Oven cavity remote-start is the open example. Samsung's cloud does it; locally the write is accepted (`2.04`) and the cavity never engages, which is a problem I haven't cracked rather than a dead end. The real limits are the few surfaces gated in hardware or firmware (power, child lock, remote-control enable), which accept a write and snap back to the physical switch. The SmartThings app cannot flip those remotely either, since Remote Control is a button on the appliance.

---

## Known DTLS flakiness

Samsung's RT-OCF DTLS stack occasionally closes sessions actively, usually right after a Block2 GET or in the seconds after a POST. The bridge handles this with exponential reconnect (1s → 30s) and a re-seed on each new session. From HA's perspective the entity briefly goes offline then comes back; from the bridge's perspective you'll see lines like:

```
oven.…  DTLS recv: Unexpected EOF
oven.…  reconnect in 1s
oven.…  DTLS connected — subscribing 11 paths
oven.…  seeded → 16 links; sensors live
```

If reconnects become persistent (e.g. >10 in a minute) something's wrong: check the appliance's Wi-Fi link first, then look for a competing DTLS client on the LAN.

---

## Contributing

If you submit a PR, please don't include real device UUIDs, MACs, serials, IPs, or bearer tokens. Use the placeholders from `.env.example`.

If you drafted any of it with an AI assistant, [`docs/use-of-ai.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/use-of-ai.md) covers what is expected: measured claims, no device identifiers, and a human reading the wording before it goes out.

---

## Trademarks & disclaimer

This is an independent, unofficial project. It is **not affiliated with, authorised, endorsed, or sponsored by Samsung Electronics Co., Ltd.** or any of its subsidiaries.

"Samsung", "SmartThings", and any related names, marks, and logos are trademarks of Samsung Electronics Co., Ltd. They are used in this project **only nominatively** — to identify the hardware and protocols this software interoperates with — and no claim is made to any right in them. Use of these marks does not imply any affiliation with or endorsement by their owner.

The software is provided under the [MIT License](https://github.com/QuiteYellow/SmartThings-Local/blob/main/LICENSE) for interoperability with hardware you own, without warranty of any kind.
