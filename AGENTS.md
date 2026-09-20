# Working in this repository

Mechanics that are easy to get wrong, for a contributor or a coding assistant. The judgement calls live in [`docs/use-of-ai.md`](docs/use-of-ai.md) and are not repeated here.

## Generated and gated files

- **`docs/api.md` is generated.** Run `python tools/generate_api_docs.py` after any change to a public docstring or signature. `tests/test_public_api_contract.py` fails when it is stale, so a forgotten regenerate surfaces as a test failure.
- **The public API surface is an allowlist.** `tools/api_contract.py` enumerates every exported name. Adding one is a deliberate edit there, which is the point: a name that leaves this package is a promise to callers who catch or import it.
- **`tools/check_share_safety.py` runs in CI as "Share safety".** It fails on UUIDs, serials, MACs and similar identifiers in introduced content. A value that is already public goes in its `SAFE_UUIDS` set, with the reason.

## Tests and the version matrix

`requires-python` is `>=3.11`, and CI runs 3.11 through 3.14 plus a dependency-floor job that installs the minimum pinned versions with `--no-deps`.

A local virtualenv drifts from both of those. When output depends on the interpreter or on a dependency version — reprs, exception rendering, annotations — pin it explicitly:

```sh
uv run --with pytest --with cbor2 --with pyOpenSSL --python 3.12 pytest tests/ -q
```

The floor job is the one that catches a new call into a newer dependency's API.

## Claims about appliance behaviour

Two rules, both with reasons on the pages that carry them:

- A statement about what an appliance does comes from a measurement. See [`docs/use-of-ai.md`](docs/use-of-ai.md).
- A statement about *why* it does it needs a citation from the stack that appliance actually runs, which is rarely obvious. See [`docs/firmware-families.md`](docs/firmware-families.md) for how to identify it, and for what the stacks do differently.

Those reference stacks are public. None is checked into this repository, and none is a substitute for hardware:

| Stack | Source | Pin used here |
| --- | --- | --- |
| **TizenRT's `iotivity_1.2-rel` fork** | `github.com/Samsung/TizenRT`, path `external/iotivity/iotivity_1.2-rel/` | `e590f30ab` |
| mbedTLS, as that fork links it | `github.com/Samsung/TizenRT`, paths `external/mbedtls/` and `external/include/mbedtls/` | `e590f30ab` (2.7.8) |
| IoTivity classic, upstream | `github.com/iotivity/iotivity` | `1.2.1`, with `1.3.1`, for contrast only |
| RT-OCF | `github.com/Samsung/RT-OCF` | `fd41fc4` |
| iotivity-lite | `github.com/iotivity/iotivity-lite` | `49441ba` |

The first row is the one to cite for the appliances here, and cite it by name: **TizenRT's `iotivity_1.2-rel` fork**, not "IoTivity classic". The family label reads as upstream, and upstream predicts handshake behaviour these appliances do not show, so a reader who follows the label reaches a tree that gives the wrong answer. The file this project reasons about most, `ca_adapter_net_ssl.c`, differs between fork and upstream by well over a thousand lines, enough that a line number from one lands somewhere unrelated in the other. Upstream earns its place by showing what Samsung changed, and that is the whole of its use here. Sparse-checkout the path; the repository is large:

```sh
git clone --filter=blob:none --no-checkout https://github.com/Samsung/TizenRT.git
cd TizenRT && git sparse-checkout set --no-cone external/iotivity external/mbedtls external/include/mbedtls
git checkout e590f30ab
```

Fetch mbedTLS alongside it: authmode, cookies and the reconnect path all live there, so the DTLS behaviour these appliances show has to be read across both trees. `build_iotivity.sh:34` symlinks the iotivity build's include path at TizenRT's own `external/include/mbedtls`, so **2.7.8** is what a TizenRT build compiles against; the 2.4.0 that `iotivity_1.2-rel/extlibs/mbedtls/prep.sh` pins is vestigial.

## Driving the library against hardware by hand

For one-off reads or writes against a real appliance, outside the bridge. Every point here cost a debugging session at least once.

- **Some appliances seem to only allow one DTLS session per peer, and the bridge holds it.** Stop the bridge before you open your own session and restart it after: `ssh <host> 'docker stop smartthings-local'` … `docker start smartthings-local`. Then confirm both appliances come back (`docker logs` shows `seeded` per class). Leaving two sessions contending is how a device gets wedged.
- **Run your script inside the bridge image, host-networked.** `docker run --rm --network host -v /mnt/user/appdata/smartthings-local:/config:ro -e PYTHONPATH=/app <image> python /tools/probe.py`. Host networking is not optional: Docker bridge NAT rewrites the source port, and these appliances answer from a different (ephemeral) port than the one addressed, so a NAT'd or *connected* socket drops every reply. `PYTHONPATH=/app` so `import smartthings_local` resolves against the installed tree.
- **The session lifecycle is `connect()` → `start_reader()` → `get()` / `post()` → `close()`.** Forgetting `start_reader()` is the classic mistake: the handshake completes, then every `get()`/`post()` times out because no thread is pumping the socket. A whole ladder of reads timing out *after* a clean handshake is this — not a dead device, not a bad port.
- **Reads are `get(path_segs)`; writes are `post(path_segs, cbor_body)`** (an OCF UPDATE, CBOR-encoded body). `close()` sends `close_notify` and frees the peer; skipping it orphans the peer on the device for minutes and the next connect looks dead.
- **A stall is usually the harness, not the hardware.** Before concluding a device is wedged, check `start_reader()`, that the bridge is stopped, and that you are host-networked. Re-handshaking on a loop to "retry" just accumulates peers and makes it worse — see [`docs/use-of-ai.md`](docs/use-of-ai.md) on pacing.

## Appliance safety

These devices cannot be replaced if a write bricks them. Nothing here writes to `/oic/sec/*`, and at least one appliance has gone silent for minutes after repeated handshakes in quick succession. The reasoning is in [`docs/use-of-ai.md`](docs/use-of-ai.md), and it binds.
