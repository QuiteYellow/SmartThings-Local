# Starting an oven cycle over a local session

Remote cycle start has been the marquee open question for local Samsung appliance control: the write is accepted with `2.04` and the cavity never engages. The reason is that the cook parameters and the run command go to the device collection in a single write, not to each resource separately. This page gives that payload, and the response an oven here returned to it on 2026-09-20.

## What was measured

One oven. A single-cavity built-in wall oven of the AC14K_M-era generation, `remoteControlEnabled: true`, reporting twelve modes its own firmware marks startable. The bridge container was stopped first, so the session below was the only one open.

```
POST /device/0        CoAP UPDATE, Content-Format 60 (CBOR)

[
  {"href": "/devices/0"},
  {"href": "/mode/vs/0",
   "rep": {"x.com.samsung.da.modes": ["Defrost"]}},
  {"href": "/temperatures/vs/0",
   "rep": {"x.com.samsung.da.items": [{"x.com.samsung.da.desired": "30",
                                       "x.com.samsung.da.id":      "0",
                                       "x.com.samsung.da.unit":    "Celsius"}]}},
  {"href": "/operational/state/vs/0",
   "rep": {"x.com.samsung.da.operationTime": "00:01:00",
           "x.com.samsung.da.state":         "Run"}}
]

  ->  2.04 Changed, empty body

t+4s    /mode/vs/0                modes   = ["Defrost"]
        /operational/state/vs/0   state   = "Run"
                                  opTime  = "00:01:00"
                                  remain  = "00:01:00"
        /oven/vs/0                state   = "Cooking"
        /temperatures/vs/0        desired = "30"    current = "28"
```

A few details of that payload are worth stating because they are easy to get wrong. The run command is not a separate step: `x.com.samsung.da.state: "Run"` rides inside the payload's own `/operational/state/vs/0` element alongside the cook time. And no option tokens were sent at all, because `Defrost` on this board supports neither fast preheat nor steam.

### The `/devices/0` element

The write goes to `/device/0`, singular. The first element of the payload is `{"href": "/devices/0"}`, plural. That is not a transcription error. It carries no `rep`, so it sets nothing by itself.

**This oven does not need it.** Measured 2026-09-20: the identical batch with the element deleted started the cook first time, reaching `Run` and `Cooking` within four seconds.

**Send it anyway.** That result is one oven, of one model, with one cavity. Nothing here establishes that another board is as relaxed about its absence, and it costs nothing to include, so the version that has been measured working is the one worth sending. The bridge sends it, and this page keeps it in the payload above for the same reason.

**Possibly a legacy name.** A publicly posted dump of the older HTTP API these machines exposed on port 8888, before OCF, has a top-level `Devices` array whose members link to their sub-resources at `/devices/0/information` and `/devices/0/configuration`. The OCF batch has that same shape, one element per sub-resource and all written together, so the marker reads like the older resource name carried across the generation change. Treat that as inference from the shape of two APIs: the evidence is someone else's capture of different hardware, and both firmwares are silent on the question. It bears on the paragraph above in one way. A name with a history behind it is likelier to still be wired to something on some board than a stray character would be.

It is untested on a multi-cavity board, where both the write target and this element would carry a cavity index.

Cancelling, by contrast, is an ordinary single-resource write, and it worked first time:

```
POST /operational/state/vs/0   {"x.com.samsung.da.state": "Ready"}
  ->  2.04, and four seconds later everything back to Ready / NoOperation /
      00:00:00 / desired 0
```

`Defrost` is the gentlest mode this board declares startable; 30 °C and one minute are that mode's own published floor for temperature and time. A run that starts ends by itself inside a minute.

## Ask the board before you send anything

`/mode/vs/0` carries `x.com.samsung.da.modeSpec`, a JSON string with one entry per mode, and each entry has a `control` field taking one of three values:

| `control` | Meaning |
| --- | --- |
| `Start&Setting` | the firmware will accept a remote start for this mode |
| `Setting` | adjustable while it runs, not startable |
| `NotSupported` | neither |

Read it first and pick a `Start&Setting` mode, using that mode's own `tempDefaultC`/`timeDefault` rather than a number from this page. A board that declares no startable mode is not worth hardware time.

The oven here declares `Start&Setting` on twelve modes, `Setting` on its autocook mode, and `NotSupported` on steam clean.

## Cavity index

Every href in the payload above ends in the same cavity index. This oven is single-cavity, and answers `4.04` on `/device/1`, `/oven/vs/1`, `/mode/vs/1` and `/doors/vs/1`, so only index 0 was exercised here.

Multi-cavity boards use the sibling indices: a flex range in the localthings fixture corpus carries `/connected/vs/1`, `/mode/vs/1`, `/operational/state/vs/1`, `/oven/vs/1` and `/temperatures/vs/1`. Address a second cavity by changing the index in every href of the payload.

## Guided-cooking recipes

`/oven/vs/0` carries an `x.com.samsung.da.recipe` field, which reads `00000000000000` on an idle oven. It was read, never written, and no recipe has been started from a local session here. On this board the autocook mode is `Setting` rather than `Start&Setting`.

## Scope

Measured on one single-cavity oven, one mode, on 2026-09-20. It has not been tried on a range, a microwave, a cooktop or a second oven model, and none of it should be assumed to transfer.

Follow each board's own declaration rather than offering start for every mode it lists. In the [localthings](https://github.com/mbillow/localthings) fixture corpus, a gas range declares no startable mode at all and its manual says a gas oven cannot be turned on remotely for safety; two further boards declare no `modeSpec` whatever. No microwave in the corpus declares a startable microwave mode, and the startable ones are convection, grill and air-fry.

## If you try this

A cycle start makes an appliance heat. Everything below is ordinary care rather than anything specific to this protocol:

- **Enable Remote Control at the panel, and check it before reading anything into a result.** `/remotectrl/vs/0` reports `x.com.samsung.da.remoteControlEnabled`; it must read `true`. With it off, the cook parameters are still accepted and held (mode, setpoint and cook time all stick) and only `state: "Run"` is silently dropped, so a batch that "does not start" tells you nothing about the payload. Measured here 2026-09-20, after a whole test run was wasted on it. It does not survive a power cycle. Necessary but not sufficient: one board in the corpus had it on and still would not start.
- Empty the cavity and stand in front of the appliance.
- Read `modeSpec` first and pick a `Start&Setting` mode. Choose the gentlest one the board offers, at its own minimum temperature and time. Not a preheat, not a broil.
- Stop any bridge or integration holding a session first. One session per appliance.
- Have the cancel write ready before you send the start, and check it took. It is a single-resource write of `{"x.com.samsung.da.state": "Ready"}`.
- The panel remains the real stop.
- A verification read is safe on this path: the run above read back four seconds after the write and the cycle held.

## Provenance

Everything quoted on this page is from a single live run against one oven on 2026-09-20: the payload as sent, the response codes, the values read back and the timings. `modeSpec` and the cavity `4.04`s are direct reads from that same unit. Cross-references to other boards come from the localthings fixture corpus, where a fixture is a capability dump from someone else's appliance and fixes no firmware version.

This is the standard path for these appliances rather than one payload that happened to work. How that was established is recorded in my own research notes and is not published here; the payload itself is stated in full above.

Appliance serial numbers, model numbers, UUIDs, MAC addresses and network addressing are deliberately absent. The property names are what a reader needs.
