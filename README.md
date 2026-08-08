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
)
sess.connect()
sess.start_reader()

code, body = sess.get(["device", "0"])                       # Block2-aware read
code, _    = sess.post(["mode", "vs", "0"], cbor2.dumps({}))  # write
sess.subscribe(["operational", "state", "vs", "0"],          # OBSERVE
               on_notification=lambda href, payload: ...)
sess.close()
```

If the cert/key are minted at runtime and never written to disk (e.g. inside
an HA config flow), create the provider from memory instead:

```python
auth = CertificateAuth.from_memory(cert_pem, key_pem)
sess = DtlsCoapSession("192.0.2.100", 49154, auth=auth)
```

For compatibility, the existing `cert_path` / `key_path` and `cert_pem` /
`key_pem` session arguments remain supported without a deprecation warning.
They are routed through `CertificateAuth` internally. Do not combine `auth`
with those legacy arguments.

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

On the currently supported firmware families, authentication uses a client cert keyed to the UUID published in Samsung's own wildcard cloud TLS cert. Their factory ACL grants that UUID `perm=31` (full CRUDN) on `href=*`. That certificate path is not universal: the WD53 profile in issue #16 and the washer in issue #20 reject it and need separate authentication work.

---

## Part 1 — Is your appliance compatible?

Check before anything else; if it's older firmware, this project doesn't target it.

```sh
# UDP scan for public/secure standard OCF plus the dynamic appliance band
nmap -Pn -sU -p 5683,5684,49152-49160 "$APPLIANCE_IP"
```

Read the result:

- **`5684/udp` or a 4915x port with a DTLS first-flight response** → an OCF DTLS listener. Standard-port OCF-PKI firmware may still require an unsupported authentication profile.
- **`5683/udp` responds to public OCF security/resource GETs** → use `/oic/res` to learn the device's advertised secure endpoint; do not assume that endpoint is fixed.
- **Only `8888/tcp` open (token-based HTTPS)** → older firmware (~2018–2022). **Not supported here.**

nmap's `open|filtered` can't tell a real DTLS server from a silent UDP port. Confirm which of the candidate ports actually speaks DTLS with the ClientHello probe, which sends one ClientHello and reports back per port:

```sh
# Stateless liveness check: one ClientHello round trip, leaves no state on the device
python -m smartthings_local.protocol.dtls_probe "$APPLIANCE_IP" 5684 49153 49154 49155 49156 --stateless
```

`live` means a DTLS server answered its first flight; `dead` means silent or not DTLS. Once you have the client cert (Part 2), add the explicit `--diagnostic` flag to run the stateful diagnostic drive, which reports `completed` (cert accepted) or `rejected` with the server's fatal alert. Diagnostic mode can allocate appliance-side DTLS state and is never used by discovery or reconnect. An `unsupported_certificate` / `unknown_ca` alert means the endpoint is reachable but this certificate profile was rejected. It is not a reason to disable verification or keep retrying. The same bounded stateless API gates the bridge's reconnect loop and, when `OCF_PORT` is unset, probes both standard 5684 and ports 49152–49160.

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
tests/                               pytest suite (CoAP wire, state cache, import isolation, cert loading, DTLS probe, bridge port resolution, cert signing)
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
