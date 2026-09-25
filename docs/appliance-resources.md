# What an appliance exposes, and how each part was found

Every OCF resource these two appliances answer, what it carries, and — for each one — the probe or test that established it. The provenance column is the point of the page. A finding whose origin nobody can name gets rediscovered, and this project has now spent two sessions rediscovering facts that were written down in May.

## Fresh discoveries and open leads (2026-09-18/19)

New this session and the last, collected here for follow-up; provenance and detail for each is in the sections below. **Status** reads: *live* — answered 2.05 on my own hardware; *candidate* — named by a source outside these two units (a localthings fixture, or my own unpublished candidate list) but 4.04 or untested here; *parked (write)* — the next step needs a write, which is never done without an explicit go-ahead, because none of these has a known recovery path if it sticks.

| Lead | What it is | Status | Where to go next |
| --- | --- | --- | --- |
| `/cycleinterface/vs/0` (dryer) | live value `cycleInterfaceEnabled: "Off"`, actuator interface; sits in **neither** `/oic/res` nor `/device/0`, like the `/rm/*` family | live, read 2026-09-19 | read it across a wash/dry cycle to see what it tracks; a write is approval-gated |
| `/wm/setinfo/vs/0` (dryer) | model capability flags — `isModelSettingWithoutSC`, `aiCourse`, `isModelSettingPowerOnOff` | live, read 2026-09-19 | map each flag to observed behaviour; read-only, safe |
| `/buzzersound/vs/0`, `/wm/personalcourse/vs/0` (dryer) | both answer 2.05 but return an empty `{}`; both actuator interface | live, empty | read again after setting one through the phone app; a write is approval-gated |
| `/realtimenotiforclient/vs/0` (dryer) | observable, and the one lead on local push | live, parked (write) | the parked notify-subscription write experiment (approval-gated) |
| `/rm/micomdata/vs/0` | live micom-telemetry queue, empty at rest on both units | live, empty | read it during an active cycle or a fault, when the queue should be populated |
| `/rm/wifi/vs/0` | RSSI diagnostic, read by neither the bridge nor localthings | live, unused | surface it in the bridge — the oven at −80 dBm is the household's weak link |
| `/rm/control/vs/0` | observe-cadence throttle `{minPeriod: "9000"}` on a TP1X fridge | candidate (fixture) | 4.04 on both units here; test if a fridge is ever on hand |
| `/rm/framemems/vs/0` | raw micom sensor dump on a washer — `WMFrameMems`, RPM sensing | candidate (fixture) | 4.04 here; the deepest telemetry resource in the corpus, worth a washer read |
| `/rm/state/vs/0` `rmState` | service-diagnostics mode, reads `disable`. Writable over the LAN with **no PIN** — but enabling it beeps, shows `00`, **disables the appliance's front buttons**, and **reboots the unit** on exit | measured 2026-09-19 | nothing further without a reason: the write costs a reboot |
| `voice/*`, `bixby*`, `settings/sound/*`, `drlc`, `debug`, `location`, `dginformation` (dryer); `hood/*`, `cooktop/*`, `camera/streaming`, `energy/consumption`, `thermaldata`, `recipe/cook` (oven) | candidate paths, **all 4.04** on my units | candidate (other-model) | features of speaker/mic dryers and range-with-hood ovens in the same product classes; nothing to do on these two units |

## What the evidence here covers

Two appliances, a dryer and an oven, both AC14K_M-era boards running IoTivity classic of the 1.2.x era, in one household. Nothing on this page generalises to washers, fridges, air conditioners or the newer OCF-PKI generation; where a claim is corroborated by [localthings](https://github.com/mbillow/localthings)' fixture corpus that is said explicitly, and a fixture is a capability dump, so it fixes no spec version and no stack for the board it came from. See [docs/firmware-families.md](firmware-families.md) for how the stack was identified.

Values are omitted wherever they identify a unit or a household. Serial numbers, model numbers, OTN DUIDs, device UUIDs, MAC addresses, region and country codes all live on the appliance and none of them belong in a tracked file; the property *names* are what a reader needs.

## The two enumeration surfaces are disjoint

`/oic/res` and `/device/0` share no href on either appliance — 15 and 25 entries on the dryer, 14 and 17 on the oven, zero in common. Worth stating up front, because `/oic/res` looks like the resource directory and is not: it advertises the OCF-facing config and housekeeping surface, and no resource carrying appliance state appears in it.

That holds for a single-unit appliance, which is all this page measures. On a composite appliance `/oic/res` does carry a structural hook: localthings resolves a second indoor unit by reading its UUID out of a link prefix there, then reading that sibling's own collection. Neither appliance here is composite, so the hook has nothing to point at.

`/device/0` is where the state lives. It is an OCF collection whose own first batch entry declares `rt: ["x.com.samsung.devcol", "oic.wk.col"]`, and one blockwise GET returns `{href, rep}` for every member with current values. It is not discoverable and has to be asked for by name, which is why both this library and localthings hardcode the path. It answers to at least one other name: `/sec/devices` returns the identical payload on the dryer (see the master sweep below).

No generic route reaches it on a single-unit appliance. `?rt=oic.wk.col` and `?rt=x.com.samsung.devcol` both 4.04 while `?rt=oic.r.doxm` resolves to exactly one href, so the filter mechanism works and those are real negatives. The strongest form of that test uses a type string read off the device rather than one built from an href: `/power/vs/0` reports `rt: ["x.com.samsung.da.operation"]` when asked directly, and `/oic/res?rt=x.com.samsung.da.operation` is 4.04 on both appliances (2026-09-19). A member's own declared type does not resolve through `/oic/res`.

`/device/0` ignores `if=` entirely: on the oven, the default, `oic.if.ll` and `oic.if.baseline` views return byte-identical payloads, and every member carries `['href', 'rep']` and nothing else — no `rt`, no `if`, no `p`, under any interface. The type is not absent, it is unpublished: it surfaces only in a direct read of the leaf, and `x.com.samsung.da.operation` is a vendor string with no published semantics. Nothing on the device says `/power/vs/0` is a binary switch, and that is the structural reason a hand-maintained href-to-meaning registry cannot be replaced by more probing.

## `/oic/res`

`bm=3` is discoverable and observable, `bm=1` discoverable only. Both were checked against behaviour and `bm` is truthful for every resource it covers — 7/7 on each appliance.

| href | rt | dryer | oven |
| --- | --- | --- | --- |
| `/oic/d` | `oic.wk.d`, `oic.d.dryer` / `oic.d.oven` | bm=1 | bm=1 |
| `/oic/p` | `oic.wk.p` | bm=1 | bm=1 |
| `/oic/sec/doxm` | `oic.r.doxm` | bm=1, secure | bm=1, secure |
| `/oic/sec/pstat` | `oic.r.pstat` | bm=1, secure | bm=1, secure |
| `/EasySetupResURI` | `oic.r.easysetup` | bm=1, secure | **bm=3**, secure |
| `/WiFiConfResURI` | `oic.wk.wifi` | bm=1, secure | bm=1, secure |
| `/CoapCloudConfResURI` | `oic.wk.cloudserver` | bm=1, secure | bm=1, secure |
| `/DevConfResURI` | `oic.wk.devconf` | bm=1, secure | bm=1, secure |
| `/sec/provisioninginfo` | `x.com.samsung.provisioninginfo` | bm=1 | bm=1 |
| `/sec/accesspointlist` | `x.com.samsung.accesspointlist` | bm=1 | bm=1 |
| `/file/transfer/vs/0` | `x.com.samsung.file.transfer` | bm=3 | — |
| `/file/list/vs/0` | `x.com.samsung.file.list` | bm=1 | — |
| `/file/transfer/chunk/vs/0` | `x.com.samsung.file.chunk` | bm=1 | — |
| `/hass/state/vs/0` | `x.com.samsung.da.hass.state` | bm=3 | — |
| `/hass/command/vs/0` | `x.com.samsung.da.hass.command` | bm=3 | — |
| `/devicelog/connectioninfo` | `x.com.samsung.devicelog` | — | bm=1 |
| `/devicelog/file` | `x.com.samsung.devicelog.file` | — | bm=1 |
| `/autoreconnect/ap` | `x.com.samsung.autoreconnect.ap` | — | bm=1, secure |
| `/calmconnection/command` | `x.com.samsung.calmconnection.command` | — | bm=1, secure |

The secure links carry `p.sec` and `port`, which is the OIC 1.1 mechanism for advertising the DTLS endpoint; the port differs per appliance and drifts across reboots, so read it rather than assuming it.

`/hass/state/vs/0` and `/hass/command/vs/0` are advertised `bm=3` and return **4.04** to a query-less GET. Whatever addresses them needs something no probe here has supplied. An earlier pass recorded them as silent; they were not, and the error was in the instrumentation — see the method note at the end.

## `/device/0`

Property names as returned; `—` means the appliance does not carry that href in its batch. Both tables are read from the 2026-05-31 batch dumps (`local-tools/comparisons/*_device0.json`, `*_oic_res.json`), and the September test 10 inventory found the same membership on both appliances.

| href | dryer | oven | properties (`x.com.samsung.da.` prefix stripped) |
| --- | --- | --- | --- |
| `/alarms/vs/0` | yes | yes | dryer *(empty)*<br>oven `rt`, `if`, `items` — the one resource whose `rep` includes its own typing |
| `/configuration/vs/0` | yes | yes | *(identity-bearing; dryer carries region and country, oven empty)* |
| `/connected/vs/0` | — | yes | `connected` |
| `/connectionconfig/vs/0` | — | yes | `autoReconnectionMinVersion`, `autoReconnection`, `autoReconnectionProtocolType`, `supportedWiFiAuthType`, `supportedWiFiCryptoType`, `supportedWiFiFreq`, `calmConnectionCare` |
| `/course/vs/0` | yes | — | `supportedModes`, `options`, `supportedOptions` |
| `/cycleinterface/vs/0` | yes | — | `cycleInterfaceEnabled` |
| `/diagnosis/vs/0` | yes | — | `diagnosisStart` |
| `/doors/vs/0` | — | yes | `items` |
| `/energy/consumption/vs/0` | yes | — | `instantaneousPower`, `instantaneousPowerUnit`, `cumulativePower`, `cumulativeUnit`, `cumulativeDate`, `cumulativeDateUTC` — *(empty in the 31 May dump, populated two days earlier; varies between reads)* |
| `/energy/consumption/0` | yes | — | *(empty)* |
| `/file/information/vs/0` | yes | — | `timeoffset` |
| `/information/vs/0` | yes | yes | *(identity-bearing: model, description, serial, OTN DUID, diagnostics endpoint/IDs, firmware `items` list)* |
| `/kidslock/vs/0` | yes | yes | `kidsLock` |
| `/kidslock/0` | yes | — | `value` |
| `/mode/vs/0` | — | yes | `supportedModes`, `modes`, `options`, `defaultMode`, `modeSpec` |
| `/operational/state/vs/0` | yes | yes | dryer `state`, `remainingTime`, `progressPercentage`, `progress`, `delayEndTime`, `supportedProgress`<br>oven `state`, `operationTime`, `remainingTime`, `progressPercentage` |
| `/operational/state/0` | yes | — | `currentMachineState`, `machineStates`, `jobStates`, `currentJobState`, `remainingTime`, `progressPercentage` |
| `/otninformation/vs/0` | yes | yes | dryer `target`, `newVersionAvailable`<br>oven adds `flashingProgress`, `otnStatus`, `otnList` (per-component model ID and versions) |
| `/oven/vs/0` | — | yes | `state`, `recipe` |
| `/power/vs/0` | yes | yes | `power` |
| `/power/0` | yes | — | `value` |
| `/quickcontrol/info/vs/0` | — | yes | `supportedVersion` |
| `/realtimenotiforclient/vs/0` | yes | — | `timeforshortnoti`, `periodicnotisubscription` |
| `/remotectrl/vs/0` | yes | yes | `remoteControlEnabled` |
| `/remotectrl/0` | yes | — | `value` |
| `/setting/vs/0` | yes | — | *(empty)* |
| `/st/dryercourse/vs/0` | yes | — | `st.dryerMode`, `st.courseTable` |
| `/temperatures/vs/0` | — | yes | `items` |
| `/timezone/vs/0` | — | yes | `timezoneid`, `offset`, `DST` |
| `/washer/vs/0` | yes | — | `wrinklePrevent`, `dryLevel`, `supportedDryLevel`, `dryTime`, `supportedDryTime`, `dryerType` |
| `/wirelessinfo/vs/0` | — | yes | *(identity-bearing: WiFi and BLE MAC addresses)* |
| `/wm/editcourse/vs/0` | yes | — | `editCourseList`, `fixedCourseList` |
| `/wm/jobbeginingstatus/vs/0` | yes | — | `currentStatus` |
| `/wm/setinfo/vs/0` | yes | — | `isModelSettingWithoutSC`, `aiCourse`, `isModelSettingPowerOnOff` |

The dryer's default view carries a leading empty `{}` — the collection's own slot — which the baseline view omits, giving 26 items against 25.

Two of these are worth a second look and neither has been chased down. `/connectionconfig/vs/0` advertises `autoReconnectionProtocolType: ["helper_hotspot", "ble_ocf"]`, which is the appliance declaring a BLE OCF carrier for a codec this library already ships with no known carrier; `/wirelessinfo/vs/0` gives it a BLE MAC to go with that. And `/realtimenotiforclient/vs/0` reads like a push-notification subscription knob on an appliance that has never been seen to push, which makes it the only lead on that question — but testing it means a write, and no write to it has been made.

## Where the collection's shape comes from

The firmware generation before this one exposed the same object over HTTPS on port 8888, as `GET /devices`. A dump of that API — forum-posted, from a `TP6X_WW6500` washer, so neither of these appliances and not a generation either of them runs — lines up with `/device/0` almost key for key:

| old `Devices[0]` key | current href |
| --- | --- |
| `Mode` | `/mode/vs/0` (oven), `/course/vs/0` (laundry) |
| `Operation` | `/operational/state/vs/0` + `/kidslock/vs/0` + `/power/vs/0` |
| `Washer` | `/washer/vs/0` |
| `Information`, `Configuration`, `Alarms`, `Diagnosis` | `/information/vs/0`, `/configuration/vs/0`, `/alarms/vs/0`, `/diagnosis/vs/0` |
| `EnergyConsumption` | `/energy/consumption/vs/0` |

The flat objects became leaf resources, which is why `kidsLock` and `power` are separate hrefs that nonetheless arrive in one collection read. Three things follow, in descending order of confidence.

**The option vocabulary did not change.** That washer's `Mode.options` carries `TimeSync_NotSupported`, `UsagesDB_ok`, `LaundryOutTime_0`, `DeviceType_0167`, `Course_5B`, and a single opaque hex `supportedOptions` string. The dryer here carries `TimeSync_NotSupported`, `UsagesDB_ok`, `LaundryOutTime_0`, `DeviceType_0165`, `Course_16`, and the same opaque hex form. Same grammar, same encoding, one generation and one appliance class apart.

**`EnergyKW_396` appears verbatim in both.** Identical value, different appliance class, years apart. That is what a firmware constant looks like rather than a meter reading, and it is a reason not to derive an energy figure from that token — but nothing here settles it, and the field has never been watched across a cycle.

**It is where the plural `{"href": "/devices/0"}` element in a batch write probably comes from** — the old collection and its `/devices/0/information` sub-paths. That element is optional on this oven and the argument is set out in [starting a cycle](oven-cook-start.md); the old API is only the reason the plural spelling exists at all.

One dead end closes here. `EnergyConsumption.saveLocation` is `/files/usage.db` — the file the current `/file/transfer/vs/0` serves, hardcoded, the same bytes whatever `?id=` asks for. It is the energy-consumption store, not a general file route that happens to be stuck.

Neither appliance here runs that generation, and nobody has scanned them for port 8888 to check whether anything of it survives. Its use on this page is as a decoder for fields the current surface exposes raw, not as a route in.

### Course codes carry no names

`/course/vs/0` reports the running course as `Course_<HH>` and `/st/dryercourse/vs/0` as `Table_<TT>_Course_<HH>`, with no name attached; `/wm/editcourse/vs/0` lists the unit's whole dial as one hex string. Nothing the appliance serves carries a human-readable name for any of them. The 14 codes captured by hand in May (`mqtt_demo/samples/dryer.py`) are exactly the 14 the appliance itself lists in `EditCourseList_…`, so the code set is confirmed against the device even though the names are not.

## The OCF-standard `/x/0` twins

Five of the dryer's hrefs appear twice: once as Samsung's `/x/vs/0` and once as a bare `/x/0` carrying the OCF-standard representation. The oven has none.

| pair | `/x/vs/0` | `/x/0` | standard type |
| --- | --- | --- | --- |
| `/power` | `power: "Off"` | `value: false` | `oic.r.switch.binary` |
| `/kidslock` | `kidsLock: "Ready"` | `value: false` | `oic.r.switch.binary` |
| `/remotectrl` | `remoteControlEnabled: "false"` | `value: false` | `oic.r.switch.binary` |
| `/operational/state` | `state`, `remainingTime`, `progressPercentage`, `progress`, `delayEndTime` | `currentMachineState`, `machineStates`, `jobStates`, `currentJobState`, `remainingTime`, `progressPercentage` | `oic.r.operational.state` (§6.18) |
| `/energy/consumption` | as above | *(empty)* | — |

Checked against the OIC 1.1 Resource Type Specification rather than pattern-matched: `oic.r.switch.binary` defines exactly one required boolean `value`, and §6.18 defines exactly those six properties.

Neither of these is a friendlier surface to bind, for two measured reasons:

- **They accept an OBSERVE and never push.** Over a 60-second window on 2026-05-29, `/power/vs/0` fired twice and `/power/0` fired zero times, having registered successfully with `seq=0`. A poller would see typed values; a subscriber would see a value that never changes.
- **Their presence is not stable.** `/power/0` answered 2.05 consistently on 2026-05-28, then returned 4.04 for hours after a heavy probing session, survived a power cycle still 4.04, and reappeared the next day with nothing identifiable causing either transition. A single 4.04 is therefore not evidence a twin is absent, and a single 2.05 is not evidence it will be there tomorrow. It has now answered in five consecutive sessions, which weakens the intermittency without refuting it.

localthings reached a compatible position from a different direction: its `registry/capabilities/ignored.py` files `/mode/0`, `/energy/consumption/0` and `/drlc/0` as "a duplicate of state we already expose through a friendlier href".

The oven's absence was confirmed by direct GET in the master sweep below — 0 of 13 bare forms answered — so it is real rather than an artefact of reading the batch. It is also a family pattern rather than a quirk of this unit. Across localthings' 89 `*_device.json` fixtures, 54 carry at least one bare `/x/N` — `/power/0` in 39, `/energy/consumption/0` in 38, `/drlc/0` in 23 — and every oven, range, cooktop and microwave in the corpus carries none.

## How each fact was established

| what | how | when |
| --- | --- | --- |
| `/power/0` exists at all | `local-tools/probe_capability_index.py` — noticed a 4.06 Not Acceptable where a JSON Accept had been returning 4.04 | 2026-05-28 |
| `/power/0` Accept behaviour, observability, value stability | `local-tools/probe_power0.py` | 2026-05-29 |
| `/device/0` and the whole member list | `local-tools/probe_slash_zero.py` — 1569 `/word/0` candidates, 3 hits (`/power/0`, `/device/0`, `/remotectrl/0`), 1566 × 4.04. Output in `power0_sweep_hits.jsonl` | 2026-05-29 |
| The `/x/0` twins and their standard types | read out of that same sweep's `/device/0` payload | 2026-05-29 |
| `/x/0` registers an OBSERVE but never pushes | 60 s watch, `/power/0` against `/power/vs/0` | 2026-05-29 |
| `/power/0` presence is intermittent | observed across three sessions either side of a power cycle | 2026-05-28/29 |
| Oven's `/device/0`, `/oic/res` | `local-tools/probe_device0_oven.py`, `probe_oven_admin_enumerate.py` | 2026-05-31 |
| Endpoint × method × transport matrix | `local-tools/probe_matrix.py` → `ENDPOINT_MATRIX_RAW.md` | 2026-05-28 |
| `bm` is truthful where `/oic/res` covers a resource | hardware test 1, 7/7 each appliance | 2026-09-18 |
| `/oic/res` and `/device/0` are disjoint | hardware tests 6 and 7 | 2026-09-18 |
| `?rt=` and `?if=` filters cannot reach `/device/0`; `/device/0` ignores `if=` | hardware tests 7 and 9 | 2026-09-18 |
| `/oic/con`, `/oic/mnt`, `/oic/ad`, `/oic/rd`, `/introspection` all absent | hardware test 8 | 2026-09-18 |
| Property-level inventory of both appliances | hardware test 10 | 2026-09-18 |
| `/sec/devices` aliases `/device/0`; cross-probe scores zero; disabled capabilities split 3/2; `/device/<n>` absent; oven has no twins by direct GET | `local-tools/build_sweep_candidates.py` + `probe_master_sweep.py`, 687 candidates, logs in `master_sweep_{dryer,oven}.jsonl` | 2026-09-18 |
| HRM `/rm/*` resource types, interfaces, RSSI, and the three closed routes | `local-tools/probe_hrm.py`, plus the handler names in `local-tools/devicelog_*.log` | 2026-09-18 |
| `/devicelog/dump` and `/devicelog/command` absent from both appliances; the oven's logs come from `/devicelog/file` | `local-tools/probe_paths.py`, 8 GETs; retrieval path read off `fetch_devicelog.py` / `decode_devicelog.py` | 2026-09-19 |
| `/oic/res?rt=` misses a `/device/0` member under the member's *own* declared `rt`; `/power/vs/0` is `x.com.samsung.da.operation`, actuator on the dryer and sensor on the oven | `local-tools/probe_paths.py`, 3 sessions, 10 GETs | 2026-09-19 |
| `/oic/ping` 4.00 on both, reproduced against `/oic/res/types/d` as a control; stock classic cannot produce that code there | `local-tools/probe_paths.py`, 2 sessions, 6 GETs; stock behaviour read off iotivity 1.2.1/1.3.1 `oickeepalive.c` and `ocresource.c` | 2026-09-19 |
| `/rm/control` (fridge) and `/rm/framemems` (washer) are cross-class `/rm` members | localthings fixtures | 2026-09-19 |
| Of the candidate-list paths, four answer live on the dryer (`/cycleinterface`, `/wm/setinfo`, `/buzzersound`, `/wm/personalcourse`) and none on the oven; the rest are other-model 4.04 | `local-tools/probe_paths.py`, GET only, 29 dryer + 19 oven paths, bridge stopped, both healthy after | 2026-09-19 |

Full hardware-test write-ups are in `local-tools/iotivity-classic-audit/HARDWARE-RESULTS-2026-09-18.md`, which is not tracked.

That the May column and the September column overlap is the reason this page exists. Test 10 re-derived the `/x/0` twins, their standard resource types and `/realtimenotiforclient/vs/0` from a payload that had been captured, decoded and written up on 2026-05-29 — and it re-derived them minus the two qualifications above, because the write-up lived in a per-project memory directory belonging to a path the project no longer uses.

## What the earlier sweeps never asked for

Three sweeps had ever hunted for unadvertised resources before this one, and between them they asked for **1616 distinct first segments**. Their coverage had three holes, each a straightforward gap rather than a subtle one. The master sweep below was built to close them.

**None of them asked for a `/vs/` path.** `probe_capability_index.py` and `probe_hidden_sweep.py` contain no `/vs/` construction at all; `probe_slash_zero.py` has `vs` in its wordlist as a *first* segment, so it asked for `/vs/0` and never for `/<word>/vs/0`. Every sweep was hunting the `/power/0` shape, which is the rarest of the three shapes these appliances use and absent from the oven entirely.

**No multi-segment path was ever asked for.** `/operational/state/0`, `/energy/consumption/0`, `/wm/setinfo/vs/0`, `/st/dryercourse/vs/0` and `/quickcontrol/info/vs/0` are all known-live and all unreachable by a single-segment wordlist.

**The wordlists were curated from generic vocabulary, and missed words for resources already known to be present.** Of the 119 distinct first segments in the corpus of hrefs already on disk, 84 appear in no sweep wordlist — including `information`, `operational`, `temperatures`, `diagnosis`, `connected`, `oven` and `quickcontrol`, every one of which names a resource one of these two appliances answers today. `probe_hidden_sweep.py` mined an external vocabulary source for candidates, which was sound in principle; that source turns out to carry only the easysetup, cloud and devicelog vocabulary and not one `x.com.samsung.da.*` string, so the appliance-state namespace was never in it to begin with.

Only `probe_slash_zero.py` persisted its output. The other two printed to stdout in sessions whose transcripts no longer exist, so "already swept" cannot be checked for them beyond reading their wordlists.

### Where the candidates should come from instead

localthings' fixture corpus is 89 real `/device/0` dumps (`tests/fixtures/*_device.json`) across fridges, air conditioners, hoods, cooktops, coffee machines, vacuums, air dressers, dishwashers and heat pumps. Mining it together with this repository yields roughly 280 distinct `/x/vs/N` hrefs, 275 of which neither appliance here advertises. That is a candidate list built from names Samsung firmware actually serves, rather than from nouns someone thought sounded plausible.

Worth being clear about what that corpus is and is not. Those dumps were produced by the same mechanism used here — one batch read of `/device/0` — on appliances other people own, and contributed as Home Assistant diagnostics downloads. The breadth comes from the number of appliances, not from a better way of finding resources, and a fridge lists `/icemaker/status/vs/0` because it is a fridge. What the corpus supplies is names worth asking for; the asking still has to happen here.

That became the master sweep's tiering, cheapest and highest-prior first. What each tier was expected to show is below; what it did show is in the next section.

1. **`/device/<n>` siblings.** localthings probes `/device/1` and `/device/2` speculatively and resolves UUID-prefixed sibling trees three ways, one of which reads the sibling's UUID out of an `/oic/res` link prefix. Exactly one fixture is a verbatim capture of a real one — issue #177's two-indoor-unit air conditioner — while the other two `/device/1` fixtures are a reindexed reconstruction and a composite with a stand-in master. Neither appliance here carries `/subdevices/vs/0`, so 4.04 is the likely answer for both; four requests is cheap enough to find out, and a hit would hand over a whole membership list rather than one resource.
2. **In-household cross-probe.** Every href the oven advertises, asked of the dryer, and the reverse — 26 requests, every one a name known real on this generation and in this household. The dryer side includes `/quickcontrol/info/vs/0`, `/timezone/vs/0`, `/wirelessinfo/vs/0` and `/connectionconfig/vs/0`; the oven side includes `/power/0`, `/realtimenotiforclient/vs/0` and `/diagnosis/vs/0`.
3. **Same-family fixtures.** 33 laundry hrefs absent from the dryer's batch, 46 cooking hrefs absent from the oven's. The strongest single candidate is `/buzzersound/vs/0`, which three other dryer fixtures carry.
4. **The appliance's own device log**, added after the first run. Not a corpus tier at all — the firmware's registry, which is why it was the one source that named the HRM resources. It should have been first, and it is the tier to extend when a new log arrives.

The candidate list is rebuilt by running `local-tools/build_sweep_candidates.py`; it reads the fixtures, the comparison dumps and the device logs, and writes `sweep_candidates.json` for the sweep to consume. Current totals are 368 candidates per appliance.

Note what the cross-probe actually tests: whether batch membership and existence are the same thing. Nothing before this run established that they are, and `/hass/state/vs/0`, advertised and real and 4.04 to a plain GET, was a standing example of the two coming apart in the other direction.

## The master sweep, 2026-09-18

687 GET-only candidates across the two appliances, built by `local-tools/build_sweep_candidates.py` from every corpus on disk and run by `local-tools/probe_master_sweep.py` — one sustained session each, 1.5 s between requests, `/oic/d` sanity read every tenth candidate. **71 sanity reads, none failed**, and both appliances rejoined the bridge afterwards reporting `0 err, 0 ping-fail, 0 timeouts` on the first poll window. Per-line logs are in `local-tools/master_sweep_{dryer,oven}.jsonl`, untracked.

| | dryer | oven |
| --- | --- | --- |
| candidates probed | 348 | 339 |
| 2.05 | 28 | 15 |
| other non-4.04 | 1 × 4.05 | 1 × 5.00, 3 timeouts |
| 4.04 | 319 | 320 |

### `/sec/devices` returns the same payload as `/device/0`

On the dryer it returns **4607 B, 26 items, a byte-identical href list** — the same collection, under a name that appears nowhere in this repository, in localthings, in the fixture corpus or in the extracted app. On the oven it timed out at 10 s, exactly as `/device/0` did on the same run, which is what a second name for one 13 KB blockwise payload would do.

It is a registered resource in its own right, not an accident: the device log shows `sec_devices.c` running its own `init_sec_devices_resource()`, alongside `oven_device.c` registering `/device/0`. Two handlers, one payload. Nothing says which the firmware considers primary, and this is no reason to change what the library requests — but the collection answers to more than one name, and only one of those names is the one everybody hardcodes.

### Batch membership and existence are the same thing for vendor hrefs

The cross-probe scored **0 for 9 on the dryer and 0 for 17 on the oven**. Every `/x/vs/0` the other appliance in this household carries is a flat 4.04 here — `/quickcontrol/info/vs/0`, `/timezone/vs/0`, `/wirelessinfo/vs/0` and `/connectionconfig/vs/0` on the dryer; `/power/0`, `/realtimenotiforclient/vs/0` and `/diagnosis/vs/0` on the oven.

So for the vendor namespace, the batch is the resource list rather than a view over a larger one, and an href's absence from `/device/0` is real absence. `/hass/state/vs/0` remains the counter-example in the other direction: advertised in `/oic/res`, absent from the batch, and 4.04 to a plain GET.

### "Disabled" in the cloud record does not mean unbound locally

The dryer's SmartThings device record lists nine capabilities under `custom.disabledCapabilities`. Three of the five with a known href answered **2.05**:

| href | capability marked disabled | local answer |
| --- | --- | --- |
| `/buzzersound/vs/0` | `samsungce.audioVolumeLevel` | 2.05, 2 B — an empty CBOR map |
| `/wm/personalcourse/vs/0` | `samsungce.dryerCyclePreset` | 2.05, 2 B |
| `/wm/welcomemsg/vs/0` | `samsungce.welcomeMessage` | 2.05, 2 B |
| `/quickcontrol/info/vs/0` | `samsungce.quickControl` | 4.04 |
| `/drlc/vs/0` | `demandResponseLoadControl` | 4.04 |

The three that answer are bound and readable on an appliance whose own app hides them, and each returns an empty map rather than a value. The split is the useful part. A disabled capability predicts neither answer, so treat the cloud record as a source of candidate names and let the appliance supply the outcome.

### The `/x/0` twins, and `/device/<n>`

The oven's lack of standard twins is now measured directly rather than inferred from the batch: **0 of 13** bare `/x/0` forms answered. The dryer's five all answered again, including `/power/0` — one more datapoint that its documented intermittency is not currently biting, and the fifth consecutive session in which it has been present.

`/device/1`, `/device/2` and `/device/3` are **4.04 on both**. The oven's cloud record carries a `cavity-01` component with every value null, and that component has no local collection behind it.

### Smaller results worth keeping

- **`/multidevice/vs/0`** answers 2.05 on the dryer with `x.com.samsung.da.numofsubdevice` — a subdevice-count resource on a single-unit appliance, absent from its own batch.
- **`/rm/state/vs/0`** answers on both, carrying `rmPincode` and `rmState`. On the oven it also carries its own `rt` and `if`, which until now only `/alarms/vs/0` did.
- **`/file/transfer/chunk/vs/0`** returns **4.05 Method Not Allowed** on the dryer. The handler exists and declines a GET, which is a different fact from the 4.04 everything else returns.
- **`/autoreconnect/ap`** returns **5.00** on the oven. An internal error is not a read to repeat casually; it is on the list of paths to leave alone.
- Three oven candidates timed out at 10 s — `/device/0`, `/devicelog/file` and `/sec/devices` — and the sanity read immediately after each one passed. All three are large or blockwise; the timeout is the read, not the appliance.

### A labelling flaw in the candidate builder

Every same-family hit except one was a resource already advertised in `/oic/res` — `EasySetupResURI`, `/oic/sec/doxm`, `/sec/provisioninginfo` and the rest. The builder mines fixture `oic_res` blocks alongside `device0` blocks, so those arrived labelled "on a same-family fixture, absent from this unit" when they are advertised on this unit's own `/oic/res`. They are not discoveries, and the reason string attached to them is wrong. The one genuine same-family hit is `/water/consumption/vs/0` on the dryer.

## HRM — the `/rm/*` monitoring resources

A third category, and the only one found so far that sits in **neither** `/oic/res` nor `/device/0` while still answering. Read 2026-09-18 with `local-tools/probe_hrm.py`, GET only.

The appliance's own log names the subsystem and its handlers:

```
I RM hrm_state_handler.c:155         ... init rm/state/vs resource
I RM hrm_micom_handler.c:146         ... init rm/micomdata/vs resource
I RM hrm_wifi_handler.c:80           ... init rm/wifi/vs resource
I RM hrm_event_update_handler.c:177  ... init rm/eventupdate/vs resource
E RM hrm_manager.c:583 hrm_manager_pop_micom_data()  Queue may be empty
```

HRM pulls microcontroller telemetry off a message queue and republishes it as OCF resources, which the SmartThings cloud subscribes to over TCP — the log records `OBSERVE_GET /rm/state/vs/0?if=oic.if.baseline` and `/rm/wifi/vs/0?if=oic.if.baseline`, with 159 B and 117 B notifications going back.

One naming trap: IoTivity classic has its own unrelated `RM`, the Routing Manager behind `ROUTING_GATEWAY` (`RMHandleGatewayRequest` in `ocresource.c`). Samsung's `/rm/*` is their own `hrm_*.c` layer and has nothing to do with it.

| href | `rt` | `if` | dryer | oven |
| --- | --- | --- | --- | --- |
| `/rm/state/vs/0` | `x.com.samsung.da.rm.state` | baseline + **`oic.if.a`** | `rmState: "disable"`, `rmPincode` | same |
| `/rm/micomdata/vs/0` | `x.com.samsung.da.rm.micomdata` | baseline + **`oic.if.a`** | empty | empty |
| `/rm/wifi/vs/0` | `x.com.samsung.da.rm.wifi` | dryer `oic.if.s`, oven **`oic.if.a`** | `x.com.samsung.rm.rssi: [-61]` | `x.com.samsung.rm.rssi: -80` |
| `/rm/eventupdate/vs/0` | — | — | 4.04 | 2.05 with a zero-byte body |
| `/rm/control/vs/0` | — | — | 4.04 | 4.04 |

`oic.if.a` is the actuator interface, so `/rm/state` and `/rm/micomdata` are writable. `rmState` reads `disable` on both, with a one-character `rmPincode` beside it.

**Since measured on hardware (2026-09-19), and the caution was pointed the wrong way.** The write is *not* PIN-gated: `POST {rmState:"enable"}` returns 2.04 with no PIN sent, and `disable` reverts it. The PIN is a cloud-side artefact — Samsung's operator console uses it to *look up* a device and to force a refused transition, and the appliance never checks it. What the write does cost is real and was invisible to every read: the oven beeps and displays `00`, **its front buttons stop responding**, and it **reboots a few seconds after the session closes** (`Reboot reason : 112`, against `55` for a mains power-on). Whether the reboot is triggered by the disable, by the session dropping, or scheduled at enable is not established.

Enabling it changed nothing on the OCF surface: 39 hrefs swept before and after, every `oic.if.*` form, and OBSERVE registrations on all four `/rm` members — byte-identical except `rmState` itself, with `/rm/micomdata` still empty. That resource is a pop-from-queue (`hrm_manager_pop_micom_data()` logs `Queue may be empty`), and a public SmartThings payload shows it populated on a *dishwasher mid-cycle* with no service mode involved — so it fills when the appliance is **active**, and every reading here was taken on an idle one.

The probe redacts anything credential-shaped by key name, so no PIN value has been read into any file here.

`/rm/wifi/vs/0` is the one with obvious downstream value: signal strength in dBm, and the two units differ enough (−61 against −80) to be worth surfacing. Two inconsistencies for any consumer: the dryer declares it `oic.if.s` where the oven declares `oic.if.a`, and the dryer wraps the value in an array where the oven does not — identical resource type, different shape.

Two more `/rm/*` resources exist on other appliance classes but are 4.04 on both units here, found in the localthings fixture corpus rather than on hardware. `/rm/control/vs/0` appears on TP1X fridges carrying `{minPeriod: "9000"}` — an observe-cadence throttle (the minimum interval between notifications). `/rm/framemems/vs/0` appears on washers and washer-dryers carrying a raw micom sensor dump (`x.com.samsung.da.rawDataName: "WMFrameMems"`, `…rawDataDescription: "WM_FrameMems_Sensing_RPM_Control"`) — the deepest telemetry resource seen anywhere in the corpus. So the `/rm` namespace is a per-class monitoring set drawn from a shared pool: my two units register `state`, `micomdata`, `wifi` and `eventupdate` (the oven serves the last, the dryer 4.04s it), a fridge adds `control`, a washer adds `framemems`.

### Three routes that are now closed

**They are not discoverable by type.** `/oic/res?rt=x.com.samsung.da.rm.state`, `…rm.micomdata` and `…rm.wifi` are all **4.04** on both, asked using the exact `rt` each resource reports about itself. The `?rt=` filter works elsewhere (`?rt=oic.r.doxm` resolves to one link), so these are real negatives.

**There is no path-prefix listing.** Bare `/rm`, `/rm/state` and `/rm/state/vs` are 4.04 on both. OCF has no directory listing, and classic does not implement CoRE link-format at `/.well-known/core` — its `OC_RSRVD_WELL_KNOWN_URI` *is* `/oic/res`.

**`/oic/ping` answers 4.00, not 4.04** — reproduced on both appliances 2026-09-19, alongside `/oic/res/types/d` as a control in the same session. Every absent path on these units is 4.04, and 4.00 is what `HandleVirtualResource` sends when it reaches its tail with `OC_STACK_ERROR` (`discoveryResult == OC_STACK_NO_RESOURCE ? OC_EH_RESOURCE_NOT_FOUND : OC_EH_ERROR`). So the URI is recognised as virtual and then nothing answers it.

What it is *not* is stock behaviour. In classic 1.2.1 and 1.3.1 the keepalive branch returns before that tail: `HandleKeepAliveGETRequest` gives `OC_EH_OK` (2.05, payload `rt`/`if`/`in`) when the resource exists and `OC_EH_RESOURCE_NOT_FOUND` (4.04) when it does not, and `SendKeepAliveResponse` tolerates an endpoint with no keepalive-table entry by reporting `in: 0`. Neither transport nor table membership is checked anywhere on that path, and recognition and dispatch sit under the same `#ifdef TCP_ADAPTER`, so no stock build produces 4.00 here. Their firmware gates it somewhere stock does not; where exactly is not visible from outside. Two facts are solid: `/oic/ping` is special-cased in their stack, and it is not served over DTLS.

The firmware uses it as a **client**, toward the cloud, over TCP. The oven's device log shows `keepalive_apis.c` opening with one `GET /oic/ping` (`discover_keepalive_resource()`, "Keepalive interval set : 1") and then a `POST /oic/ping` every ~45 s for as long as the cloud session lasts, each answered in ~503 ms. Stock would also explain its absence from `/oic/res`: `CreateKeepAliveResource()` registers it with `OC_RES_PROP_NONE`, so it is undiscoverable by construction. The OCF definition is `oic.wk.ping` (`oic.if.rw` + baseline, one `in` property, POST resets the alive timer) — and a POST is a write that inserts the sender into the keepalive table, so it stays out of any read-only probe.

### The interface query changes the answer on one appliance only

The dryer returns **values only** to a query-less GET and adds `rt`/`if` when asked with `?if=oic.if.baseline`. The oven returns the baseline form either way and ignores the query — the same `if=`-ignoring behaviour already measured on its `/device/0`. That is why the master sweep saw `rt`/`if` on the oven and not the dryer: the difference is the appliance, not the resource. Ask both ways.

## The firmware's own resource registry

The device log beats every corpus as an href source, because the firmware announces each resource as it registers it and the log also records the CoAP traffic the SmartThings cloud generates against it. This is not other people's appliances — it is this generation's own registry.

These logs came off the oven (`local-tools/devicelog_*.log`, pulled 2026-09-10 by reading `/devicelog/file`, whose `x.com.samsung.devicelog.file.data` field is a zlib-segmented container — `local-tools/fetch_devicelog.py` retrieves it and `decode_devicelog.py` unpacks it). **The dryer has no equivalent**: `/devicelog/connectioninfo` and `/devicelog/file` are both 4.04 on it, and its `/file/list/vs/0` offers only `/opt/data/energy.db` and `/opt/data/hass.db`. So this route reaches one of the two appliances, and no dryer registry can be obtained through it.

`/devicelog/dump` and `/devicelog/command` are documented for Samsung VD hardware ([docs/ocf-vd-devices.md](ocf-vd-devices.md)) and are **4.04 on both appliances**, query-less and under `?if=oic.if.baseline` alike — 8 GETs, 8 negatives, 2026-09-19. Neither is an appliance resource, and an earlier draft of this page wrongly named `/devicelog/dump` as the route these logs came from. They came from `/devicelog/file`. What a log can and cannot tell you is below the table. Each line names the C module that owns the resource:

| registered resource | handler module | where it shows up |
| --- | --- | --- |
| `/power/vs/0` | `power_vs.c` | `/device/0` batch |
| `/kidslock/vs/0` | `kidslock_vs.c` | `/device/0` batch |
| `/remotectrl/vs/0` | `remotectrl_vs.c` | `/device/0` batch |
| `/operational/state/vs/0` | `operational_state_vs.c` | `/device/0` batch |
| `/doors/vs/0` | `doors_vs.c` | `/device/0` batch |
| `/temperatures/vs/0` | `temperatures_vs.c` | `/device/0` batch |
| `/mode/vs/0` | `mode_vs.c`, `mode_spec.c` | `/device/0` batch |
| `/oven/vs/0` | `oven_vs.c` | `/device/0` batch |
| `/alarms/vs/0` | `oven_alarms_vs.c` | `/device/0` batch |
| `/information/vs/0` | `information_vs.c` | `/device/0` batch |
| `/configuration/vs/0` | `configuration_vs.c` | `/device/0` batch |
| `/connected/vs/0` | `connected_vs.c` | `/device/0` batch |
| `/connectionconfig/vs/0` | `connectionconfig_vs.c` | `/device/0` batch |
| `/otninformation/vs/0` | `otninformation_vs.c` | `/device/0` batch |
| `/timezone/vs/0` | `timezone_vs.c` | `/device/0` batch |
| `/wirelessinfo/vs/0` | `wirelessinfo_vs.c` | `/device/0` batch |
| `/quickcontrol/info/vs/0` | `quickcontrol_info_vs.c` | `/device/0` batch |
| `/device/0` | `oven_device.c` | the collection itself |
| `/sec/devices` | `sec_devices.c` | **neither surface** — see below |
| `/rm/state/vs/0` | `hrm_state_handler.c` | **neither surface** |
| `/rm/micomdata/vs/0` | `hrm_micom_handler.c` | **neither surface** |
| `/rm/wifi/vs/0` | `hrm_wifi_handler.c` | **neither surface** |
| `/rm/eventupdate/vs/0` | `hrm_event_update_handler.c` | **neither surface** |
| `/sec/provisioninginfo` | `provisioning_info.c` | `/oic/res` |
| `/devicelog/file`, `/devicelog/connectioninfo` | `device_log.c` | `/oic/res` |
| `/calmconnection/command` | `calm_connection.c` | `/oic/res` |

The OCF and easy-setup resources in `/oic/res` (`/EasySetupResURI`, `/WiFiConfResURI`, `/oic/sec/*`) are registered by a different layer (`easysetup_manager.c`, `ocf_manager.c`) and do not appear in this table.

### How much of a registry a log actually holds

A log read is a bounded window of roughly three minutes, so what it contains depends on what the appliance was doing. That limits this table in three ways, and they are worth stating before anyone treats it as a device contract.

**Only a dump that catches a boot has a registry at all.** Of the five logs on disk, **two contain zero `init_*_resource()` lines** — `devicelog_2026-09-10.log` and `devicelog_dump.log`, 4419 and 4695 lines respectively, both full-length captures of a running appliance. Registration happens once at startup, so a runtime dump records none of it.

**The three that do are one boot, not three samples.** `devicelog_2026-09-10{b,c,d}.log` carry the same 29 registration lines from the same startup at 21:31:36, differing only in how much they captured afterwards. One observation, recorded three times.

**There is no dryer log at all.** Every log here is the oven's — no laundry module (`washer_vs.c`, `st/dryercourse`, `cycleinterface`) appears in any of them. So this table is the oven's registry, and the two appliances demonstrably differ: `/rm/eventupdate/vs/0` answers on the oven and is 4.04 on the dryer.

What does survive is narrower and still useful. The registration block runs from line 428 to line 513 of a 4354-line file, spanning 0.9 seconds, with ordinary boot activity either side — cloud token loading and BLE advertisement setup before it, `set_app_main.c` after. It is not clipped at either end, so **for that one boot, the block is complete**. Anything absent from it was not registered at startup.

That still leaves conditional registration unaccounted for. `rmState` reads `disable` on both appliances, and nothing here establishes whether enabling a mode registers further resources — if it does, a boot log taken with the mode off would never show them. Treat the table as a floor on what exists, never a ceiling.

The row that matters is `sec_devices.c`: `/sec/devices` has its own source file and its own `init_sec_devices_resource()`, so the duplicate payload is a registered second resource rather than an accidental alias.

To re-extract after pulling a fresh log:

```sh
cat local-tools/devicelog*.log | grep -aohE '_[a-z0-9_]+_resource\(\)' | sort -u
cat local-tools/devicelog*.log | grep -aohE '[a-z0-9_]+\.c:[0-9]+' | sed 's/:.*//' | sort -u
```

`build_sweep_candidates.py` parses these logs directly into a `t4b_devicelog` tier, so the tier is only ever as good as the dumps on disk — currently one oven boot plus whatever traffic the five windows happened to catch. Two filters clear the log's column truncation, which otherwise yields fragments like `/state/vs` from `/rm/state/vs/0` and `/operational/stat`: a resource must be an instance path or live under a known bare root, and any path that another path already ends with is a left-truncation of it. The tier also carries `/oic/ping` and `/oic/account/session`, neither of which any corpus contains.

## Probing a candidate path list

`/oic/res` is not a resource inventory on these units, so resources outside both enumeration surfaces have to be found by asking for them by name. Working from a candidate list of 44 dryer-class and 53 oven-class hrefs — assembled from my own research notes, which are not published here — each path was probed read-only against my two units (bridge stopped, GET only, 2026-09-19).

The list spans a whole product class rather than one model, so a path appearing on it means some appliance in that class serves the resource, not that these units do. The results bear that out: a handful of genuine live resources, and a majority of other-model 4.04s.

| resource (dryer) | GET result | note |
| --- | --- | --- |
| `/cycleinterface/vs/0` | 2.05 `{x.com.samsung.da.cycleInterfaceEnabled: "Off"}` | `rt x.com.samsung.da.operation`, `oic.if.a`; in neither `/oic/res` nor `/device/0` — a fourth resource in the same class as `/rm/*` |
| `/wm/setinfo/vs/0` | 2.05 `{isModelSettingWithoutSC:"true", aiCourse:"false", isModelSettingPowerOnOff:"false"}` | `rt x.com.samsung.da.wm.setinfo`, `oic.if.a`; model capability flags |
| `/buzzersound/vs/0` | 2.05 `{}` | `rt x.com.samsung.da.buzzersound`, `oic.if.a`; present but empty |
| `/wm/personalcourse/vs/0` | 2.05 `{}` | `rt x.com.samsung.da.personalcourse`, `oic.if.a`; present but empty |

The other 25 dryer candidate paths are **4.04**: every `bixby*`, `voice/*`, `settings/sound/*`, `accessibility`, `sec/networkaudio/audio` (this dryer has no speaker or mic), plus `debug`, `drlc`, `dginformation`, `location`, `power/vs/1`. On the oven, **every** candidate-only path is 4.04 — the `hood/*`, `cooktop/*`, `camera/streaming`, `bluetooth/hood/*` family belongs to a range-with-hood model, and `energy/consumption`, `recipe/cook`, `thermaldata`, `accessibility` are simply absent; `/oven/vs/1`, `/mode/vs/1`, `/doors/vs/1` are 4.04, confirming the oven is single-cavity. Both appliances stayed healthy across the probe (`/oic/d` 2.05 before and after each session, clean bridge reconnect). All four live dryer resources declare the actuator interface, i.e. they are writable; only reads were done.

## Discovery by resource type

Onboarding and diagnostics resources can be asked for by **type** rather than by path, which is what `/oic/res?rt=` is for. Asking that way, 2026-09-19:

| resource type | dryer | oven |
| --- | --- | --- |
| `x.com.samsung.provisioninginfo` | `/sec/provisioninginfo` | `/sec/provisioninginfo` |
| `oic.r.easysetup` | `/EasySetupResURI` | `/EasySetupResURI` |
| `x.com.samsung.accesspointlist` | `/sec/accesspointlist` | `/sec/accesspointlist` |
| `x.com.samsung.devicelog` | 4.04 | `/devicelog/connectioninfo` |
| `x.com.samsung.devicelog.file` | 4.04 | `/devicelog/file` |
| `x.com.samsung.autoreconnect.ap` | 4.04 | `/autoreconnect/ap` |
| `x.com.samsung.calmconnection.command` | 4.04 | `/calmconnection/command` |
| `x.com.samsung.devicelog.dump` | **4.04** | **4.04** |
| `x.com.samsung.devicelog.command` | **4.04** | **4.04** |

Seven of the nine resolve wherever the resource exists, so the filter is demonstrably working and the two `4.04` rows are real absences rather than an unsupported query.

**The filter reveals nothing hidden.** Every type that resolved returned exactly the href already listed in a bare `/oic/res`. IoTivity classic's `includeThisResourceInResponse` will surface an `OC_EXPLICIT_DISCOVERABLE` resource only when a type filter is supplied, so this was the mechanism most likely to be hiding something. On these two appliances it is not being used that way.

### Where the type vocabulary comes from

The resource types that resolve here all belong to the onboarding, easy-setup and diagnostics surface. **Every appliance-state resource type is absent from that vocabulary** — `x.com.samsung.da.rm.state`, `da.rm.wifi`, `da.hass.state`, `x.com.samsung.devcol` and `x.com.samsung.file.list` are not discoverable by type on either unit.

That has a simple explanation: appliance state reaches the phone from the cloud rather than over the LAN, so the LAN-side type vocabulary never needed it. **Type discovery is a good route to the onboarding and diagnostics surface and a poor one for appliance state.**

The app does carry a handful of genuine-looking appliance types (`x.com.samsung.da.power`, `da.mode`, `da.configuration`, `da.wm.jobbeginingstatus`), which is what made the test below possible.

### What the device's own type string settles

`/oic/res` does not reach a `/device/0` member, and as of 2026-09-19 that is measured rather than inferred. The earlier `?rt=` queries used type strings **built from hrefs rather than read from the device**, which proved nothing; this one asks the device first. `/power/vs/0` answers with `rt: ["x.com.samsung.da.operation"]` on both appliances, and `/oic/res?rt=x.com.samsung.da.operation` returns 4.04 on both.

`?rt=x.com.samsung.da.power` is 4.04 too, and the direct read explains why: on these appliances that string is the *property key* inside `/power/vs/0`, not the resource type. `x.com.samsung.languagelist` and `x.com.samsung.status.list`, the two other untested app strings, are 4.04 on the dryer as well.

The same read turned up a difference between the units. The dryer's `/power/vs/0` declares `if: ["oic.if.baseline", "oic.if.a"]`; the oven's declares `if: ["oic.if.baseline", "oic.if.s"]`. The dryer's power leaf presents itself as an actuator and the oven's as a sensor. Neither has been written to.

## What probing costs

Restarting the bridge after the HRM probe, the dryer answered nothing for **140 seconds** across five attempts — `no live DTLS server found`, and a `/oic/res` discovery on 5683 that drew no response — then reconnected and polled clean. The oven never dropped. That matches the silence wedge already recorded for this unit, and two probe sessions in one evening is the most likely trigger. Budget for it: after a probing run, the dryer may need a couple of minutes before it will accept a handshake.

## Rules for the next sweep

Each of these cost a session when it was ignored.

- **Ask for CBOR, never JSON.** A CBOR Accept (`0x3c`) and no Accept option behave identically here, both returning 2.05 with a body. A JSON Accept (`0x32`) returns 4.06 for handlers that answer CBOR happily, and earlier sweeps that used JSON produced false 4.04s that hid `/power/0` for weeks.
- **One sustained session, paced.** Roughly 100–150 ms between requests. Repeated fresh handshakes correlate with the appliance dropping its cloud connection, and the TLS service wedges after about 30 handshakes cumulative.
- **Correlate the response token against the request token.** CoAP-over-TCP interleaves responses, and queue desync has produced convincing "2.05 with content" readings for endpoints that actually return 4.01.
- **Sanity-read a known-good resource between probes and stop on the first failure.** `/oic/d` is the usual choice.
- **GET only.** A brute-forced path is not a place to send a write, and a resource that is not in `/oic/res` gets no write at all without the owner saying so first — recovery may mean re-pairing.
- **Read outcomes off the datagrams, not off an observe-delivery callback.** A callback never fires for a 4.04, so an error response and nothing arriving look identical. Both of the September results that turned on silence were re-run raw before they were believed.
- **Persist the output, one line at a time.** Two of the three early sweeps printed to stdout in sessions whose transcripts are gone. `probe_master_sweep.py` writes a JSON object per candidate and fsyncs before the next request, so a killed run loses nothing and resumes where it stopped.
- **Record why each candidate was asked for.** Every line in the master sweep's log carries its tier and a one-line reason. That is what surfaced the same-family labelling flaw in the results, where it could be read, instead of leaving it buried in the builder.
