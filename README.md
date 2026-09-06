# SmartThings-Local

**`smartthings-local` is a Python library for local, cloud-free control of Samsung connected appliances over authenticated CoAP-DTLS.** It gives you the DTLS-CoAP transport, a tiered polling + OBSERVE state layer, and identity-cert tooling for AC14K_M-compatible firmware. Newer OCF-PKI appliances require a different authentication profile; see [the laundry compatibility findings](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-pki-laundry.md). Supported profiles can read state and write commands on the LAN with no SmartThings cloud round-trip.

The repo also ships a self-contained **reference bridge demo** (`mqtt_demo/`) that turns the library into auto-discovered Home Assistant entities over MQTT. One process supervises multiple appliances, each on its own DTLS session.

<img width="778" height="367" alt="image" src="https://github.com/user-attachments/assets/cc1dca15-f272-4625-a13c-2dc82283ff95" />

> **Just want to control your Samsung appliance from Home Assistant?**
> Use [localthings](https://github.com/mbillow/localthings), a Home
> Assistant custom component built on the `smartthings-local` package.
> This repo is the protocol research project, the library itself, and a
> self-contained MQTT bridge demo; new appliance support (capability
> mappings, HA entities) should go to localthings, not here.

## Quick start (library)

`smartthings-local` is on PyPI:

```sh
pip install smartthings-local
```

For compatible firmware, mint a client cert once (see
[Part 2](#part-2--auth-for-ac14k_m-compatible-firmware)), then drive a
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

The module deliberately does not open a TCP/TLS/Bluetooth connection, choose a
carrier, or perform setup and ownership operations. Those remain caller policy.

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

Reads retransmit each Block2 request; writes send once. Where a lost write
has been shown to be the cause rather than a device that is simply refusing
load, `write_max_attempts` lets `post()` retransmit inside the caller's own
timeout, backing off per RFC 7252 §4.2 and pacing every retransmit:

```python
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth, write_max_attempts=3)
```

Each attempt resends the byte-identical datagram, so a server implementing
§4.5 can recognise the duplicate and answer from its dedupe cache instead of
re-running the write. Retrying from the caller cannot do that — a second
`post()` mints a fresh Message ID, which is a new request. It defaults to `1`
(send once) because retransmitting into an appliance that is already dropping
under load turns one lost write into several, and §4.5 dedupe is unverified on
RT-OCF.

Note that `post()`'s `timeout` bounds the whole call, rate-limit pacing
included, rather than only the wait that follows the send. Every attempt has to
share one budget, and a caller that asked for 8 seconds should not wait 8
seconds plus however long the limiter withheld the request. At the default 5
req/s that is at most 200 ms of the budget; at a hand-tuned `rate_limit_rps=1.0`
it is a full second, so a caller pairing a low rate limit with a short timeout
should raise the timeout to match.

If the cert/key are minted at runtime and never written to disk (e.g. inside
an HA config flow), create the provider from memory instead:

```python
auth = CertificateAuth.from_memory(cert_pem, key_pem)
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth)
```

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

An existing OCF PSK credential can be supplied through `PskAuth`:

```python
from smartthings_local.protocol.auth import PskAuth

auth = PskAuth(identity=psk_identity, key=psk_key)
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth)
```

The identity must be the raw 16-byte OCF UUID and cannot contain a NUL byte;
the key must be exactly 16 or 32 bytes. `PskAuth` selects only
`ECDHE-PSK-AES128-CBC-SHA256` and does not acquire, derive, provision, rotate,
or persist credentials. Ownership transfer and credential discovery are
outside this package.

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

### What the demo bridge gives you

- **Multi-appliance, one container:** single Docker service holds N DTLS sessions in parallel, one per appliance, sharing one MQTT client. Adding an appliance class is ~150 lines and one descriptor file.
- **Bounded state latency:** hot-tier resources (job state, door, operational state) refresh on a sub-second cadence regardless of whether the appliance has internet. Worst-case lag is the tier interval (≤1s idle, ≤500ms during an active cycle on the dryer).
- **Writes that work:** dryer Start/Pause/Stop, course selection, wrinkle prevent; oven lamp (light entity), sound, fast preheat, setpoint slider, mode select, stop.
- **Optimistic publish + verify:** HA sees the new value the instant the device 2.04-confirms the write; the PollScheduler verifies on its next tier tick (after a 4s defer past Samsung's fetchback-revert window).
- **HA Energy Dashboard ready** (dryer): live watts + cumulative kWh as `total_increasing`.
- **Bridge logs tagged per-appliance** with `<class>.<serial>` once each device's serial is read on connect: `dryer.<serial>` and `oven.<serial>` interleave in the same log stream, easy to grep.
- **Zero HA YAML:** every entity is auto-discovered via MQTT discovery.
- **Your state stays on your LAN:** bridge → broker → HA. Samsung's cloud sees nothing from HA. *(The appliance still maintains its own TLS session to Samsung. That's the appliance's design, not ours.)*
- **A few controls the cloud HA integration doesn't offer.** Talking to the appliance directly surfaces some writes the official SmartThings integration doesn't currently expose for these models: dryer course selection ([HA core #162501](https://github.com/home-assistant/core/issues/162501)) and the oven temperature setpoint (where the cloud integration provides a read-only sensor). It's not a strict superset (the cloud integration still covers surfaces this doesn't), but the reverse-engineered write set is broad.

### Under the hood

Each appliance runs an independent bridge built around three coordinated pieces over one persistent DTLS session: a `StateCache` (single source of truth for all reps), a `PollScheduler` (tiered adaptive polling: hot/warm/cold plus a periodic `/device/0` sweep), and a `KeepaliveTask` (CoAP empty-CON ping for DTLS-layer liveness, with consecutive-failure detection for MQTT availability). Tier cadences are descriptor-declared and were calibrated against the empirically-measured per-firmware ceilings: dryer ~14 req/s, oven ~8 req/s. OBSERVE registrations (RFC 7641) are kept as an opportunistic freshness accelerator: when the appliance has internet and emits notifications, the cache absorbs them and the next-poll timer is reset for that resource; when it's air-gapped, polling alone carries the UX with no other code change. Token-stable Block2 (RFC 7959) handles multi-block reads. Writes are optimistically merged into the cache the moment the device 2.04-confirms, with the scheduler deferring that resource's next poll past the fetchback-revert window. Reconnect with exponential backoff on session errors, gated by a stateless DTLS ClientHello pre-flight (`smartthings_local/protocol/dtls_probe.py`) so a silent/rebooting device or wrong port drops into backoff in ~1 RTT instead of eating the full handshake timeout; when `OCF_PORT` is unset the same probe auto-discovers the live port across the OCF band.

On the currently supported firmware families, authentication uses a client cert keyed to the UUID published in Samsung's own wildcard cloud TLS cert. Their factory ACL grants that UUID `perm=31` (full CRUDN) on `href=*`. That certificate path is not universal: the WD53 profile in issue #16 and the washer in issue #20 reject it. For those newer OCF-PKI devices, the `SamsungServerProfile` and `ServerCertificateAuth` providers (see Quick start) pin and verify the device's hardware certificate, but getting an authorized client credential to reach protected resources is still an open problem.

---

## Part 1 — Is your appliance compatible?

Check before anything else; if it's older firmware, this project doesn't target it.

```sh
# UDP scan for public/secure standard OCF plus the dynamic appliance band
nmap -Pn -sU -p 5683,5684,49152-49160 "$APPLIANCE_IP"
```

Read the result:

- **`5684/udp` or a 4915x port with a DTLS first-flight response** → an OCF DTLS listener. Standard-port OCF-PKI firmware needs the Samsung server-certificate profile (`SamsungServerProfile` / `ServerCertificateAuth`, see Quick start), and no working client credential for it exists yet.
- **`5683/udp` responds to public OCF security/resource GETs** → use `/oic/res` to learn the device's advertised secure endpoint; do not assume that endpoint is fixed.
- **Only `8888/tcp` open (token-based HTTPS)** → older firmware (~2018–2022). **Not supported here.**

nmap's `open|filtered` can't tell a real DTLS server from a silent UDP port. Confirm which of the candidate ports actually speaks DTLS with the ClientHello probe, which sends one ClientHello and reports back per port:

```sh
# Stateless liveness check: one ClientHello round trip, leaves no state on the device
python -m smartthings_local.protocol.dtls_probe "$APPLIANCE_IP" 5684 49153 49154 49155 49156 --stateless
```

`live` means a DTLS server answered its first flight; `dead` means silent or not DTLS. Once you have the client cert (Part 2), add the explicit `--diagnostic` flag to run the stateful diagnostic drive, which reports `completed` (cert accepted) or `rejected` with the server's fatal alert. Diagnostic mode can allocate appliance-side DTLS state and is never used by discovery or reconnect. An `unsupported_certificate` / `unknown_ca` alert means the endpoint is reachable but this certificate profile was rejected. It is not a reason to disable verification or keep retrying. The same bounded stateless API gates the bridge's reconnect loop and, when `OCF_PORT` is unset, probes both standard 5684 and ports 49152–49160.

Consumers can discover ports outside that fallback range through the public,
read-only OCF resource directory before probing them:

```python
from smartthings_local.protocol.dtls_probe import probe_dtls_ports
from smartthings_local.protocol.ocf_discovery import discover_ocf_secure_ports

fallback_ports = (5684, *range(49152, 49161))
advertisement = discover_ocf_secure_ports(appliance_host)
candidates = advertisement.ports or fallback_ports
probe = probe_dtls_ports(appliance_host, candidates)
```

`discovery_port` is the target's already-known public CoAP request port. Its
5683 default is only a convenience: this function does not scan or use
multicast to locate a different public port. If the appliance does not listen
on 5683, locate that public port separately and pass it explicitly as
`discovery_port=...`.

`discover_ocf_secure_ports()` first reads the public `/oic/res` directory and
uses only `coaps://` endpoints whose literal host matches the correlated
response source. If that first lookup yields no correlated response or no
usable secure endpoint, the same overall deadline also bounds a filtered
`/oic/res?rt=oic.r.doxm` fallback for Samsung's legacy secure-port policy. It
accepts a different dynamic response source port after the request reaches the
known public port, while still requiring the resolved target address and CoAP
token, and assembles Block2 responses within fixed time, block-count, and
payload limits.

Directory discovery and the DTLS probe have separate jobs: discovery can learn
a device-advertised port outside the caller's fixed fallback set, while
`probe_dtls_ports()` only checks the candidates it receives for a stateless
DTLS first-flight response. Neither step authenticates the appliance. An
advertised port therefore remains only a candidate: require a successful
stateless DTLS probe before attempting authentication.

### Tested combinations

| Appliance class | Model family | Confirmed |
|---|---|---|
| Washer | WW11DG (`DA_WM_TP2_20_COMMON`, `mnid=0AJT`) | All entities. Contributed by [@indykoning](https://github.com/indykoning) (PR #13); tested via [`mbillow/localthings`](https://github.com/mbillow/localthings) |
| Dryer | DV5000T (`DA_WM_TP2_20_COMMON`, `mnid=0AJT`); DV90T (same `mnid=0AJT`) | All entities, ≤1s hot-tier poll (OBSERVE accelerates when online) |
| Oven | NV7000BS-class (`TP1X_DA-KS-OVEN-0107X`, `mnid=0AJT`) | All entities; hot-tier poll covers door + operational state regardless of cloud reachability |
| Fridge | ARTIK051_REF_17K (`DA-REF-ART-COMMON-1_20201124`) | Contributed by [@aminorjourney](https://github.com/aminorjourney) (PR #1). Older firmware family; port 49155, minimal `/oic/res` with full tree under `/device/0` |

Other appliances on the same firmware family (dishwashers, AC units) almost certainly speak the same protocol: the auth path and read primitives are common, and a washer on the shared `DA_WM_TP2_20_COMMON` controller is already confirmed above. You'd write one new descriptor for the `localthings` registry.

The Bespoke AI Laundry Combo `WD53DBA900HZ[A1]` on Tizen 7 software
`20260416.215549` is a known OCF-PKI profile, but is not yet supported by the
public authentication path. Its endpoint and manufacturer-OTM/OwnerPSK findings
are documented [here](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/ocf-pki-laundry.md), including the exact relationship
to issues [#16](https://github.com/QuiteYellow/SmartThings-Local/issues/16) and
[#20](https://github.com/QuiteYellow/SmartThings-Local/issues/20).

### Firmware families: a limitation

Descriptors are firmware-family-specific. Each descriptor hardcodes the resource layout of one firmware family: which hrefs it polls, which fields it reads, which write surfaces it exposes. There's no runtime feature detection. The three sample descriptors here (`mqtt_demo/samples/`) are frozen references.

**What this means in practice:** if you set `APPLIANCE_<n>_CLASS=fridge` on a fridge that speaks a different firmware family than the one this descriptor was built for, the bridge will start and connect fine, but many sensors will publish as unknown and some controls won't work. Nothing catastrophic. You just get a half-broken HA device card.

If your appliance model doesn't match a row in the tested table above, it may still work if it's on the same firmware family; otherwise you'd write a new descriptor (see "Adding a new appliance class" below). The ARTIK051 fridge and the newer RF9000B-class fridge, for example, expose different resource models (collection-resource vs per-instance-resource) and can't share a descriptor even though they're both "fridges".

---

## How the app keeps in sync with the appliance

There are two parallel paths between the appliance and the app over the local CoAP-DTLS socket:

- **Push (OBSERVE).** When the appliance can reach Samsung's cloud, it emits a CoAP OBSERVE notification on the LAN socket within ~100ms of any state change: cycle start, door open, mode flip. The notification travels over the LAN; nothing about the push itself routes via Samsung. **But** the appliance's decision to emit it at all is gated inside its cloud-publish thread. Block the appliance from the internet and the LAN OBSERVE pushes stop, even though the LAN path itself is unaffected and the appliance still answers reads + accepts writes normally.
- **Polling.** The app always polls a small tier of hot resources (operational state, door, etc.) on a sub-second cadence, a warmer tier (mode, kidslock, alarms, …) every 15–30 s, and a full `/device/0` sweep every 5 minutes. This carries the UX regardless of whether OBSERVE is firing.

In normal operation both happen at once: an OBSERVE notification arrives first, the cache absorbs it, and the next-poll timer for that resource is reset. In an air-gapped LAN the app keeps working. Only the worst-case freshness changes (from ~100 ms with push to ≤1 s on hot-tier resources via polling). Reads, writes, and HA entities behave identically.

Which path is doing the work is visible in Home Assistant. The bridge publishes per-appliance diagnostic entities including **Push Active** (on while OBSERVE is firing), **Last Update Source** (`observe` / `poll` / `sweep` / `optimistic`), **Last OBSERVE Age**, **Poll Max RTT**, **Slow Polls (window)**, **Poll Errors (window)**, and **Stalest Resource Age**, all under each device's Diagnostic section.

---

## Part 2 — Auth for AC14K_M-compatible firmware

For a compatible firmware family, the bridge authenticates with a **client
cert** signed by `AC14K_M`, an intermediate CA that has been public for years.
The cert's Subject DN carries a UUID that those appliances' on-device ACLs
grant full access to.

You can read the UUID yourself out of the relevant server cert:

```sh
openssl s_client -connect <samsung-host>:443 -servername <samsung-host> \
                 -showcerts < /dev/null 2>/dev/null \
  | openssl x509 -noout -subject
# subject=C=KR, O=Samsung Electronics, OU=uuid:<UUID>, CN=*.samsungiotcloud.com
```

The UUID lives in `OU=uuid:<UUID>`. The server cert is currently valid through **2035-04-09**.

This README doesn't pin the literal UUID: the setup script extracts it live each run, so it self-updates if upstream rotates.

### Why this works

- Each currently supported Tizen/RT-OCF firmware family has a **factory-baked ACE** in `/oic/sec/acl` granting this UUID `perm=31` on `href=*`.
- TizenRT iotivity derives peerId from `memmem(subject_dn, "uuid:")`, which is RDN-agnostic. A cert with the UUID in CN authenticates the same as one with it in OU.
- We don't need the matching private key from the original keyholder. We mint our own key and have `AC14K_M` sign our leaf. Different key, same identity, same access.

### One-command setup

```sh
pip install -r requirements-bootstrap.txt
TARGET_IP=$APPLIANCE_IP python setup_cert.py --test
```

What it does:

1. Fetches the AC14K_M signing CA + private key + upstream chain (RemoteAccessCA → CECA → ROOTCA) from a public mirror.
2. Fetches the relevant server cert and extracts the current UUID from its subject DN.
3. Sanity-checks that the AC14K_M cert and key actually pair (modulus match) before signing anything.
4. Generates a fresh RSA-2048 key pair you own.
5. Builds a CSR with the UUID in OU + CN + SAN and signs it with `AC14K_M` (SHA-1, matching the on-device trust hierarchy).
6. Concatenates `leaf + AC14K_M + 3 upstream CAs` into the fullchain PEM.
7. With `--test`: opens a DTLS handshake against `$TARGET_IP:$TARGET_PORT` (default `49154`) and GETs `/oic/sec/acl`; a `2.05` reply proves the cert authenticated (anonymous peers get `4.01`).

Output in `./certs/`: `client_fullchain.pem` + `client.key`.

Neither the UUID nor the AC14K_M bundle is hardcoded in this repo; both are fetched live each run, so the script self-updates if upstream rotates. If either fetch fails, the script prints an inline workaround: supply the UUID via `UUID=<uuid>` env, or supply the AC14K_M bundle via `AC14K_M_CERT_BUNDLE=/path/to/cert.pem`. `BRAYSTORM_URL=<mirror>` points at a different bundle source.

On Fedora/RHEL (and other hardened OpenSSL 3.x builds) the default crypto policy blocks SHA-1 signing, which step 5 needs. The script detects this, retries the signing step once with SHA-1 force-enabled for just that command, and only fails if the retry also fails. If it does, it prints the remedy: `sudo update-crypto-policies --set DEFAULT:SHA1` (undo afterward with `sudo update-crypto-policies --set DEFAULT`).

### How durable is this on the compatible firmware families?

Rotating the published UUID would require coordinated cloud certificate, ACL,
and device identity changes across the compatible firmware families.
`AC14K_M` has been public for years and remains accepted by the tested rows
above, but it is already rejected by other 2026 appliance profiles. Do not
extrapolate this certificate path to an untested model.

> **Legacy path:** earlier versions used a per-hub-UUID cert via an anonymous `/oic/sec/doxm` read escalation. That still works on the dryer-family firmware but isn't necessary: the cert minted here authenticates against every appliance and survives device resets. The old `bootstrap.py` for the legacy flow was removed when the package was renamed; see git history if you need it.

---

## Part 3 — Configure your appliances

Copy `.env.example` to `.env` and fill in.

### Layered envs

The bridge config splits into:

- **Shared keys** (one per process): MQTT broker + creds, HA discovery prefix, cert paths, timer intervals.
- **Per-appliance keys** (one block per appliance) under `APPLIANCE_<n>_*` (1-indexed).

`APPLIANCE_COUNT` tells the bridge how many indexed blocks to read. Bump it as you add appliances.

```bash
APPLIANCE_COUNT=2

# Appliance 1 — dryer
APPLIANCE_1_CLASS=dryer
APPLIANCE_1_IP=192.0.2.100
APPLIANCE_1_OCF_PORT=             # blank → auto-discover across the OCF band (dryer=49155)
APPLIANCE_1_TOPIC=samsung_dryer
APPLIANCE_1_NAME=Samsung Dryer

# Appliance 2 — oven
APPLIANCE_2_CLASS=oven
APPLIANCE_2_IP=192.0.2.101
APPLIANCE_2_OCF_PORT=             # blank → auto-discover across the OCF band (oven=49154)
APPLIANCE_2_TOPIC=samsung_oven
APPLIANCE_2_NAME=Samsung Oven
```

Each `APPLIANCE_<n>_CLASS` must match a key in
`mqtt_demo.samples.DESCRIPTORS`: currently `dryer`, `oven`, and `fridge`.

---

## Part 4 — Run it

### Docker (the real deployment)

```sh
docker compose up -d --build
docker compose logs -f
```

Container name `smartthings-local`. Outbound-only; no ports exposed. Needs egress to each appliance's IP/port (UDP) and to your MQTT broker. The certs in `./certs/` (or whatever `APPDATA_DIR` points to via the volume mount) are read-only mounted at `/config`.

### Deploying to a remote Linux host (Unraid, etc.)

```sh
# Once: upload the cert + key onto the remote.
ssh "$SSH_HOST" mkdir -p "$APPDATA_DIR"
scp certs/client_fullchain.pem certs/client.key "$SSH_HOST:$APPDATA_DIR/"

# Each deploy: ship source + .env, rebuild container on the host.
./deploy.sh
```

Set `SSH_HOST`, `REMOTE_DIR`, `APPDATA_DIR` in `.env`. `deploy.sh` extracts those three keys via `grep` rather than `source .env`, so values containing spaces (like `APPLIANCE_1_NAME=Samsung Dryer`) don't break it.

### Bare metal (first test / debugging)

```sh
python3 -m venv .venv
.venv/bin/pip install -r mqtt_demo/requirements.txt
.venv/bin/python -m mqtt_demo
```

### Expected first-run logs

```
14:08:42  INFO   mqtt_demo                SmartThings-Local Bridge starting (2 appliances)
14:08:42  INFO   mqtt_demo                  broker = <broker-ip>:1883 (user=<mqtt-user>)
14:08:42  INFO   mqtt_demo                  [1] dryer @ <dryer-ip>:49155? (DTLS, auto-discover) → topic samsung_dryer/*
14:08:42  INFO   mqtt_demo                  [2] oven  @ <oven-ip>:49154? (DTLS, auto-discover) → topic samsung_oven/*
14:08:42  INFO   mqtt_demo                MQTT connected → <broker-ip>:1883
14:08:43  INFO   dryer                    discovered DTLS port 49155
14:08:43  INFO   oven                     discovered DTLS port 49154
14:08:43  INFO   dryer                    DTLS connected — subscribing 11 paths
14:08:44  INFO   dryer.<dryer-serial>     identified — serial=…
14:08:44  INFO   dryer.<dryer-serial>     seeded → 25 links; sensors live
14:08:44  INFO   oven                     DTLS connected — subscribing 11 paths
14:08:46  INFO   oven.<oven-serial>       identified — serial=…
14:08:46  INFO   oven.<oven-serial>       seeded → 16 links; sensors live
```

In HA: **Settings → Devices & Services → MQTT** should show both devices populated.

---

## Per-appliance notes

### Dryer

| Capability | Works? | Notes |
|---|---|---|
| Read all state | ✅ | Machine state, job state, energy (W + kWh), course, dry level, completion time, remote control, child lock, alarms |
| Wrinkle Prevent toggle | ✅ | Persists |
| Start / Pause / Stop | ✅ | Via `/operational/state/vs/0`; needs Remote Control on |
| Change course | ✅ | Via `/st/dryercourse/vs/0`; needs Remote Control on. **Not exposed by the SmartThings cloud HA integration.** |
| Power on/off | ❌ | Accepted (2.04) but reverts within seconds; hardware-mirrored |
| Child Lock / Remote Control toggle | ❌ | Same; hardware-mirrored physical buttons |

The dryer's `/operational/state/vs/0` is on the bridge's hot poll tier (1s idle / 0.5s while a cycle is active) and also accepts OBSERVE registration. When the appliance has internet it pushes notifications within ~100ms of any state change and the cache absorbs them as fast freshness; when air-gapped the hot-tier poll carries the same UX with worst-case lag of one tier interval.

### Oven

| Capability | Works? | Notes |
|---|---|---|
| Read state | ✅ | Cavity state, current/target temp, door, mode, alarms, firmware-update-available |
| Lamp (light entity) | ✅ | Binary On/Off only; High/Low/Dim values are accepted (2.04) but silently coerced back. Works regardless of Remote Control. |
| Sound, Fast preheat | ⚠️ | Wired but untested RC-gated. |
| Setpoint slider | ⚠️ | Wired but untested RC-gated. |
| Mode select | ⚠️ | Wired but untested RC-gated. |
| Stop button | ✅ |  |
| **Kitchen timer (`⏲` icon)** | ❌ | **The oven's panel kitchen timer is not exposed via CoAP at all.** Confirmed by full `/device/0` dump: `UpperTimer*` fields in `/mode/vs/0` only populate when set via the API, not from the panel. |

**The oven doesn't push OBSERVE on `/mode/vs/0` writes** (the dryer does). The bridge handles this transparently because state freshness comes from polling rather than from OBSERVE:
1. **Optimistic publish** — the moment a POST returns 2.04, the bridge merges the write body into the cache and publishes to MQTT. HA reflects the new value instantly.
2. **Scheduler reconciliation** — the PollScheduler defers polling the just-written resource for ~4s (past Samsung's fetchback-revert window), then refreshes it on its tier cadence. If the device silently coerced the value, the corrected state is republished and HA reverts.
3. **Periodic `/device/0` sweep** — every 5 minutes the scheduler's sweep tier re-fetches the whole device tree, bounding worst-case drift on any resource the per-tier polls don't cover.

### Fridge (ARTIK051)

Contributed by [@aminorjourney](https://github.com/aminorjourney) in PR #1, verified against an `ARTIK051_REF_17K` fridge-freezer on firmware `DA-REF-ART-COMMON-1_20201124`. First public documentation of this firmware's local resource layout.

| Capability | Works? | Notes |
|---|---|---|
| Read temperatures | ✅ | Fridge + freezer current + setpoint via `/temperatures/vs/0` |
| Read doors | ✅ | Fridge, freezer, convertible zone via `/doors/vs/0` items array; plus an "any door open" binary sensor |
| Energy monitoring | ✅ | Instantaneous W + cumulative Wh via `/energy/consumption/vs/0` |
| Water filter | ✅ | Usage % + status via `/filter/waterfilter/vs/0` |
| Ice maker | ✅ | State + ice-making status via `/icemaker/one/vs/0` |
| Setpoint slider (fridge / freezer) | ✅ | Fridge 1–7°C, freezer -23 to -15°C |
| Power Cool, Power Freeze, Sabbath, Ice Maker switches | ✅ | |
| Active modes | ✅ | Read-only sensor of the fridge's mode list |

Notes specific to this firmware family:
- **Port 49155**, not the 49154 the oven defaults to.
- `/oic/res` only advertises 15 paths; the full resource tree lives at `/device/0` (32 links). The bridge's periodic `/device/0` sweep handles this transparently; no descriptor change needed.
- `/hass/state/vs/0` and `/hass/command/vs/0` return `4.04`. They're vestigial paths from an earlier firmware and are ignored.
- Doors are exposed as a Samsung-plural collection resource (`/doors/vs/0` with an `items[]` array keyed by `x.com.samsung.da.description`), not as per-room OCF resources like the newer RF9000B-class fridges use. This is one of the concrete divergences behind the "Firmware families" caveat in Part 1.

---

## Reference

### Config keys

| Key | Meaning |
|---|---|
| `APPLIANCE_COUNT` | Number of `APPLIANCE_<n>_*` blocks to read (1-indexed) |
| `APPLIANCE_<n>_CLASS` | Descriptor name: `dryer`, `oven`, `fridge` |
| `APPLIANCE_<n>_IP` | LAN IP of the appliance |
| `APPLIANCE_<n>_OCF_PORT` | Optional. Blank → probe standard port 5684 and the dynamic range 49152–49160 with a stateless ClientHello; set it to pin and gate one specific port (dryer=49155, oven=49154, fridge=49155) |
| `APPLIANCE_<n>_TOPIC` | MQTT topic prefix (also the HA device identifier; changing it re-keys the device) |
| `APPLIANCE_<n>_NAME` | Friendly name on the HA device card |
| `MQTT_BROKER` / `MQTT_PORT` / `MQTT_USER` / `MQTT_PASS` | Broker config |
| `HA_DISCOVERY_PREFIX` | HA discovery topic root (default `homeassistant`) |
| `CERT_PATH` / `KEY_PATH` | Override cert lookup (auto-detects `/config/` then `./certs/`) |
| `HEALTH_INTERVAL_S` | Seconds between `<prefix>/bridge/health` publishes (default 60) |
| `PING_INTERVAL_S` | CoAP empty-CON ping cadence; three consecutive failures publish `availability=offline` (default 25). Tier polling cadences are descriptor-declared, not env-tunable. |
| `SSH_HOST` / `REMOTE_DIR` / `APPDATA_DIR` | Used by `deploy.sh` only |

### MQTT topics — outgoing (bridge → broker)

Per appliance, where `<prefix>` is its `APPLIANCE_<n>_TOPIC`.

| Topic | Retain | When |
|---|---|---|
| `<prefix>/availability` | ✓ | `online` after seed; `offline` on disconnect (LWT for appliance #1) |
| `<prefix>/remote_available` | ✓ | `online` iff bridge is up AND Remote Control on the appliance is on. Gates the control entities. |
| `<prefix>/state` | ✓ | JSON sensor dict; published only when sensors actually diff |
| `<prefix>/bridge/health` | ✓ | Every `HEALTH_INTERVAL_S`: connect_count, error_count, notif_count, poll_count, poll_error_count, ping_count, ping_fail_count, reachable, last_change_age_s, last_seed_age_s, session_age_s, stalest_href, stalest_age_s, serial |
| `<ha_prefix>/{sensor,binary_sensor,switch,light,number,select,button}/<prefix>/.../config` | ✓ | HA MQTT discovery, republished on every MQTT (re)connect |

### MQTT topics — incoming (bridge subscribes)

`<prefix>/cmd/#`. **The MQTT user must have READ permission on this subtree.** Without it the broker silently drops the TCP connection shortly after SUBSCRIBE. Check broker logs if writes never land.

Dryer:

| Suffix | Payloads | Effect |
|---|---|---|
| `cmd/wrinkle_prevent` | `On`, `Off` | POST `/washer/vs/0` |
| `cmd/operational_state` | `Run`, `Pause`, `Ready` | POST `/operational/state/vs/0`; requires RC |
| `cmd/dryer_mode` | Course name (e.g. `Cotton`) | Translated to `Course_HH` then POST `/st/dryercourse/vs/0`; requires RC |

Oven:

| Suffix | Payloads | Effect |
|---|---|---|
| `cmd/lamp` | `On`, `Off` | RMW of `/mode/vs/0 .options[UpperLamp_*]` |
| `cmd/sound` | `On`, `Off` | RMW of `/mode/vs/0 .options[Sound_*]` |
| `cmd/fastpreheat` | `On`, `Off` | RMW of `/mode/vs/0 .options[fastpreheat_*]` |
| `cmd/setpoint` | Integer °C (30–270, step 5) | RMW of `/temperatures/vs/0 .items[0].desired`; requires RC |
| `cmd/mode` | Mode name (e.g. `Convection`, `LargeGrill`) | POST `/mode/vs/0 {modes: [<name>]}`; requires RC |
| `cmd/stop` | (button press) | POST `/operational/state/vs/0 {state: Ready}` |

### Entity counts (approximate, per appliance)

| Type | Dryer | Oven |
|---|---|---|
| `sensor` | 17 | 17 |
| `binary_sensor` | 4 | 7 |
| `switch` | 1 (wrinkle) | 2 (sound, fastpreheat) |
| `light` | — | 1 (lamp) |
| `number` | — | 1 (setpoint slider) |
| `select` | 1 (course) | 1 (mode) |
| `button` | 3 (start/pause/stop) | 1 (stop) |

Gated control entities use HA's `availability_mode: all` against `<prefix>/availability` AND `<prefix>/remote_available`. Flip Remote Control on the appliance's front panel and those entities un-grey in HA.

### Repo layout

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
- **Don't assume OBSERVE silence means the appliance is broken.** When the appliance can't reach Samsung's cloud, its OBSERVE notify dispatch goes quiet even though the local DTLS session, GETs, POSTs, and the cache continue to work normally (measured at `~14 req/s` dryer / `~8 req/s` oven with 200/200 GETs successful while firewalled). The polling tiers are the structural answer to this; treat OBSERVE strictly as an optional accelerator.
- **Don't touch `/oic/sec/*` (doxm, pstat, cred, acl).** The bridge doesn't, and you shouldn't from helper scripts either. Those resources have wedge/brick risk on Samsung's RT-OCF security stack. The bridge surfaces are strictly `/<x>/vs/0` and `/device/0`.
- **Don't run two clients against the same appliance simultaneously.** Samsung's RT-OCF DTLS allows one active session per peer; a second handshake will get the device to drop the new socket. If HA seems to flap, check whether you've got `python -m mqtt_demo` running locally AND the Docker container up.
- **Expect gaps in write coverage, but few are hard limits.** The local DTLS surface appears to expose every write Samsung's own app uses; the ceiling is per-surface reverse-engineering (finding the resource, field, and encoding), not an API boundary. A control that isn't wired yet usually just hasn't been mapped. Oven cavity remote-start is the marquee open example: it works today through Samsung's cloud, and locally the write is accepted (`2.04`) but the cavity never engages. That's a reverse-engineering problem we haven't cracked yet, not a dead end. The hard limits are the few surfaces Samsung gates in hardware/firmware (power, child lock, remote-control enable), which accept the write then snap back to the physical switch. That mirrors Samsung's own behaviour, not a shortfall of the local path: the SmartThings app can't flip those remotely either (Remote Control is a button you press on the appliance). The optimistic-publish-then-verify pattern absorbs the reverts transparently: HA briefly shows the new value, then the PollScheduler's next tier poll (deferred ~4s past Samsung's revert window) re-reads and republishes the actual state. (The bridge deliberately does **not** fetch-back right after a write; that GET is itself what triggers the revert.)

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

---

## Trademarks & disclaimer

This is an independent, unofficial project. It is **not affiliated with, authorised, endorsed, or sponsored by Samsung Electronics Co., Ltd.** or any of its subsidiaries.

"Samsung", "SmartThings", and any related names, marks, and logos are trademarks of Samsung Electronics Co., Ltd. They are used in this project **only nominatively** — to identify the hardware and protocols this software interoperates with — and no claim is made to any right in them. Use of these marks does not imply any affiliation with or endorsement by their owner.

The software is provided under the [MIT License](LICENSE) for interoperability with hardware you own, without warranty of any kind.
