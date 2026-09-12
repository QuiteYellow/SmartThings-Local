# Reference bridge demo

`mqtt_demo/` is a self-contained MQTT bridge built on `smartthings-local`. It
turns the library into auto-discovered Home Assistant entities, supervising
several appliances from one process with a DTLS session each.

It is a demonstration of the library rather than the recommended way to run
Samsung appliances in Home Assistant. For that, use
[localthings](https://github.com/mbillow/localthings), a custom component
built on this package.

You need a client certificate before any of this works. See
[Certificates](https://github.com/QuiteYellow/SmartThings-Local/blob/main/README.md#auth-for-ac14k_m-compatible-firmware)
in the README.

## What the demo bridge gives you

- **Multi-appliance, one container:** single Docker service holds N DTLS sessions in parallel, one per appliance, sharing one MQTT client. Adding an appliance class is ~150 lines and one descriptor file.
- **Bounded state latency:** hot-tier resources (job state, door, operational state) refresh on a sub-second cadence regardless of whether the appliance has internet. Worst-case lag is the tier interval (≤1s idle, ≤500ms during an active cycle on the dryer).
- **Writes that work:** dryer Start/Pause/Stop, course selection, wrinkle prevent; oven lamp (light entity), sound, fast preheat, setpoint slider, mode select, stop.
- **Optimistic publish + verify:** HA sees the new value the instant the device 2.04-confirms the write; the PollScheduler verifies on its next tier tick (after a 4s defer past Samsung's fetchback-revert window).
- **HA Energy Dashboard ready** (dryer): live watts + cumulative kWh as `total_increasing`.
- **Bridge logs tagged per-appliance** with `<class>.<serial>` once each device's serial is read on connect: `dryer.<serial>` and `oven.<serial>` interleave in the same log stream, easy to grep.
- **Zero HA YAML:** every entity is auto-discovered via MQTT discovery.
- **Your state stays on your LAN:** bridge → broker → HA. Samsung's cloud sees nothing from HA. *(The appliance still maintains its own TLS session to Samsung. That's the appliance's design, not ours.)*
- **A few controls the cloud HA integration doesn't offer.** Talking to the appliance directly surfaces some writes the official SmartThings integration doesn't currently expose for these models: dryer course selection ([HA core #162501](https://github.com/home-assistant/core/issues/162501)) and the oven temperature setpoint (where the cloud integration provides a read-only sensor). It's not a strict superset (the cloud integration still covers surfaces this doesn't), but the reverse-engineered write set is broad.

## Under the hood

Each appliance runs an independent bridge built around three coordinated pieces over one persistent DTLS session: a `StateCache` (single source of truth for all reps), a `PollScheduler` (tiered adaptive polling: hot/warm/cold plus a periodic `/device/0` sweep), and a `KeepaliveTask` (CoAP empty-CON ping for DTLS-layer liveness, with consecutive-failure detection for MQTT availability). Tier cadences are descriptor-declared and were calibrated against the empirically-measured per-firmware ceilings: dryer ~14 req/s, oven ~8 req/s. OBSERVE registrations (RFC 7641) are kept as an opportunistic freshness accelerator: when the appliance has internet and emits notifications, the cache absorbs them and the next-poll timer is reset for that resource; when it's air-gapped, polling alone carries the UX with no other code change. Token-stable Block2 (RFC 7959) handles multi-block reads. Writes are optimistically merged into the cache the moment the device 2.04-confirms, with the scheduler deferring that resource's next poll past the fetchback-revert window. Reconnect with exponential backoff on session errors, gated by a stateless DTLS ClientHello pre-flight (`smartthings_local/protocol/dtls_probe.py`) so a silent/rebooting device or wrong port drops into backoff in ~1 RTT instead of eating the full handshake timeout; when `OCF_PORT` is unset the same probe auto-discovers the live port across the OCF band.

On the currently supported firmware families, authentication uses a client cert keyed to the UUID published in Samsung's own wildcard cloud TLS cert. Their factory ACL grants that UUID `perm=31` (full CRUDN) on `href=*`. That certificate path is not universal: the WD53 profile in issue #16 and the washer in issue #20 reject it. For those newer OCF-PKI devices, the `SamsungServerProfile` and `ServerCertificateAuth` providers (see Quick start) pin and verify the device's hardware certificate, but getting an authorized client credential to reach protected resources is still an open problem.

---

## Configure your appliances

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

## Run it

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
- Doors are exposed as a Samsung-plural collection resource (`/doors/vs/0` with an `items[]` array keyed by `x.com.samsung.da.description`), not as per-room OCF resources like the newer RF9000B-class fridges use. This is one of the concrete divergences behind the ["Firmware families" caveat](https://github.com/QuiteYellow/SmartThings-Local/blob/main/README.md#firmware-families-a-limitation) in the README.

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
| `CLOCK_SYNC_INTERVAL_H` | Hours between appliance clock writes, for descriptors that declare one (default 24; `0` disables the sync and its button) |
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
| `cmd/sync_clock` | (button press) | POST `/configuration/vs/0 {x.com.samsung.da.currentTime: <host local time>}` |

#### Clock sync

An appliance kept off the internet has no way to correct its own clock, so the display drifts. Where a descriptor declares a `ClockSync` spec (today the oven), the bridge writes the host's local wall clock to `/configuration/vs/0` as `x.com.samsung.da.currentTime` every `CLOCK_SYNC_INTERVAL_H` hours, and exposes a Sync clock button for an immediate write. Set `CLOCK_SYNC_INTERVAL_H=0` to switch off both.

The field is write-only: a GET of that resource returns the metadata without it, so the value never enters the state cache and no sensor reports it. Timestamps land in the container's `TZ`.

The write came from LocalThings [#404](https://github.com/mbillow/localthings/issues/404) / [#428](https://github.com/mbillow/localthings/pull/428), verified there on a TP1X range and originally documented on [the SmartThings forum](https://community.smartthings.com/t/samsung-oven-range-and-cooktop-sync-time-api/251391). Both the periodic write and the button answer 2.04 on the oven this repo's sample descriptor targets. Other appliance classes are untested — a rejection shows up as a 4.xx in the bridge log, and nothing else is written to the resource.

One limit is worth knowing whatever the appliance. A timestamp far outside its certificate validity window can break certificate verification and leave it unresponsive, so the bridge refuses to write a host clock reading outside `PLAUSIBLE_FROM`/`PLAUSIBLE_UNTIL` in `mqtt_demo/clock_sync.py`. A host that boots without NTP skips the sync rather than writing 1970.

### Entity counts (approximate, per appliance)

| Type | Dryer | Oven |
|---|---|---|
| `sensor` | 17 | 17 |
| `binary_sensor` | 4 | 7 |
| `switch` | 1 (wrinkle) | 2 (sound, fastpreheat) |
| `light` | — | 1 (lamp) |
| `number` | — | 1 (setpoint slider) |
| `select` | 1 (course) | 1 (mode) |
| `button` | 3 (start/pause/stop) | 2 (stop, sync clock) |

Gated control entities use HA's `availability_mode: all` against `<prefix>/availability` AND `<prefix>/remote_available`. Flip Remote Control on the appliance's front panel and those entities un-grey in HA.\n