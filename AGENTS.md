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
- A statement about *why* it does it needs a citation from the stack that appliance actually runs, which is rarely obvious. See [`docs/firmware-families.md`](docs/firmware-families.md) for how to identify it, and for what the three stacks do differently.

Those three reference stacks are public. None is checked into this repository, and none is a substitute for hardware:

| Stack | Source | Pin used here |
| --- | --- | --- |
| IoTivity classic | `github.com/iotivity/iotivity` | `1.2.1`, with `1.3.1` for comparison |
| RT-OCF | `github.com/Samsung/RT-OCF` | `fd41fc4` |
| iotivity-lite | `github.com/iotivity/iotivity-lite` | `49441ba` |

## Appliance safety

These devices cannot be replaced if a write bricks them. Nothing here writes to `/oic/sec/*`, appliances hold one DTLS session per peer, and at least one wedges for minutes once its session table fills. The reasoning is in [`docs/use-of-ai.md`](docs/use-of-ai.md), and it binds.
