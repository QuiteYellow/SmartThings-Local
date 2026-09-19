# Which firmware is your appliance running?

Two identifications decide whether a claim about an appliance is sound: which OCF stack it runs, and which directory dialect it speaks. Both are read-only, and getting either wrong has published a false finding here before.

This page exists because of one of those. The library's comments named RT-OCF as the appliances' stack throughout, a claim about port binding was then reasoned from RT-OCF's source, and it was wrong: the two appliances I own run IoTivity *classic*, which binds a port RT-OCF leaves alone. The observation behind the comment was fine. The mechanism attached to it came from a codebase those devices do not run.

## What the evidence here covers

My own hardware is two appliances, a dryer and an oven, both running IoTivity classic of the 1.2.x era. Every claim on this page that names a stack is sourced to that stack's code, and every claim about device behaviour comes from those two unless it says otherwise.

The library is also what [localthings](https://github.com/mbillow/localthings) runs against a far wider spread: its fixture corpus is 92 device dumps covering ARTIK051-, TP1x- and TP2x-era boards, and its users run newer generations still. So the wire behaviours this library encodes are exercised well beyond two appliances. Those dumps record device capabilities and carry no `/oic/d` or `/oic/p` block, so they fix no spec version and no stack for any of those boards. The breadth of testing is real; the attribution is not, and a comment should not invent one.

## Identifying the stack

The appliance's own log names its modules, and the three stacks have disjoint file names. Samsung exposes it as a read on `/devicelog/dump` (`x.com.samsung.devicelog.dump`, see [docs/ocf-vd-devices.md](ocf-vd-devices.md)); availability varies by model, and this repository ships no tool for it.

| Module names in the log | Stack |
| --- | --- |
| `ocstack.c`, `ocresource.c`, `caipadapter.c`, `caipserver.c`, `camessagehandler.c`, `ca_adapter_net_ssl.c`, `cablockwisetransfer.c` | **IoTivity classic** |
| `rt_udp.c`, `rt_ssl.c`, `rt_coap_transactions.c`, and anything else `rt_*` | **RT-OCF** (TizenRT) |
| `oc_ri.c`, `oc_endpoint.c`, `port/linux/ipadapter.c` | **iotivity-lite** |

Samsung's own layer sits alongside whichever one it is: `connectivity_apis.c`, `cloud_manager.c`, `auto_reconnection_manager.c`, `micom_manager.c`, `dawit_net_util.c`.

## Anchoring the version, and finding the fork

Once the stack is known, match `file:line` pairs from the log against the same file at each candidate revision. The line a given message sits on moves between revisions, so a handful of anchors narrows the era.

Anchor against the **vendor's** tree. Samsung vendors its own IoTivity fork inside TizenRT (`external/iotivity/`), and for the two appliances here it beats the upstream project on every anchor that discriminates. Upstream still sets the floor, since `ca_adapter_net_ssl.c` exists only from 1.2 onward, and it shows you *what the vendor changed*, which is often the interesting part. Cite the fork for what an appliance does.

The difference is not cosmetic. The log's `ocstack.c:537` "CASendRequest failed" sits 11 lines past upstream 1.2.1's 526, and 1 line before the fork's 538. Upstream 1.3.x and 2.0.0 put it past 670, so any of those readings gets the era right and only one gets the tree right.

Picking the revision is the same method run over the fork's own history. Take each `file:line function message` triple the log gives you, find the string in the tree, and record the drift. A vendor's integrator inserts extra log statements into the vendor source, so the appliance's line numbers should sit a little *after* the tree's, and within a file the gap should widen further down. Summing the absolute drift over a dozen anchors across the revisions that touch the path collapses a long history into a handful of distinct states, and the minimum is the era. For these appliances that is a plateau spanning 2019 to 2024, inside which a pin can be chosen for other reasons — the current one is the last revision before an mbedTLS API migration the appliances' much older mbedTLS cannot be carrying.

Two cautions the method earns. Read the result as an era: within a plateau many revisions are identical on every anchor, so a single commit is more precision than the evidence carries. And some messages in these logs are in **no** public revision of anything — checked with `git log -S` over the vendor tree's full history, not just its tip. Those are the appliance's own patch layer, which sits on top of the fork and is not published; at least one of them also turns up in a console capture from a different Samsung product, so that layer is shared across device families rather than specific to one model.

## Which directory dialect

Three separate facts, often conflated:

- **`icv` on `/oic/d`** reports the spec version the firmware claims. Both appliances here report `core.1.1.0`, which is also IoTivity classic's compiled-in default (`octypes.h:297`, served at `ocresource.c:1471` unless the integrator overrides it, in the fork at the pin; upstream 1.2.1 has the same value at `octypes.h:289` and `ocresource.c:1429`). So it is a decent hint about the build and a weak one about anything else.
- **The dialect served is chosen by the request.** Both stock stacks pick the `/oic/res` representation from the Accept option. Accept 60 selects the OIC 1.1 form; Accept 10000 asks for the OCF 1.0 form. Both appliances here answer 60 and return `4.06` to 10000, and a `4.06` after a clean parse says the board declines that format outright.
- **What the answer carries** follows from the dialect. OCF 1.0 and later carry a secure `eps` entry; an OIC 1.1 device carries `p.sec`/`port` on its `/oic/sec/doxm` link, and its directory has no `eps` key anywhere. A missing `eps` therefore identifies the generation, and anyone chasing it as a defect is chasing the wrong thing. `discover_ocf_secure_ports` reads both forms from whichever answer arrives.

## What each stack binds

Relevant because it decides which ports answer, and because two of these three disagree with the appliances here.

| | IoTivity classic, Samsung's fork | RT-OCF | iotivity-lite |
| --- | --- | --- | --- |
| multicast plaintext | `m4` on 5683 | `mcast_v4` on 5683 | `mcast4` on 5683 |
| multicast secure | `m4s` on **5684** | none | none |
| unicast plaintext | `u4`, kernel-assigned | `ucast_v4`, kernel-assigned | kernel-assigned |
| unicast secure | `u4s`, kernel-assigned | `dtls_v4`, kernel-assigned | `secure_port4`, dynamic |
| source | `caipadapter.c:218-223`, `caipinterface.h:165`, `caipserver.c:732,847,997-1000` | `rt_udp.c:152,164` | `port/linux/ipadapter.c:79,1491` |

"Kernel-assigned" is literal in classic: the unicast pair's ports are initialised to 0 (`caipadapter.c:218-219`), `CACreateSocket` binds that (`caipserver.c:732`), and `getsockname` reads back what the kernel chose (`:826`). Only the multicast pair gets fixed numbers (`:222-223`). A reply from an appliance therefore comes from a port nothing advertised, and it changes across reboots.

All three bind their multicast sockets to `INADDR_ANY`, so a *unicast* datagram to 5683 lands on one and is served. That is why plaintext `/oic/res` answers on 5683 across stacks. The convention has a mechanism behind it and no clause: OCF Core fixes 5683 as the multicast listen port and requires the discovery resources on an unsecured endpoint, while leaving the unsecured unicast endpoint on any port the implementer likes.

5684 is the divergence: classic binds it, the table above shows what the other two put there, and every 5684 in OCF Core 2.2.8 is `coap+tcp` default-port text. An appliance answering a DTLS ClientHello on 5684 is running something classic-shaped, and its answer will come from the kernel-assigned secure socket.

Replies from those kernel-assigned sockets are why a port probe has to select on the reply's source port, and why a stateful firewall or a bridge NAT can make a live port look dead. See [docs/appliance-compatibility.md](appliance-compatibility.md).

## What the TizenRT build changes

The table above is the fork as TizenRT compiles it, and three of its build-time choices decide what discovery can reach. All three are invisible from upstream source.

- **IPv6 is compiled out, not merely unbound.** `caipadapter.c:235-237` wraps `ipv6enabled` in `#ifndef __TIZENRT__`, and in `caipserver.c` the `IPV6_JOIN_GROUP` call and the body of `sendMulticastData6` go the same way. So an appliance can answer an IPv6 ping at the OS level while its OCF stack listens on no IPv6 address at all. A probe to the OCF site-local multicast group reaching nothing therefore says nothing about whether the device is up.
- **Multicast TTL is 1, set explicitly** (`caipserver.c:174`, applied at `:1540`). Upstream never sets the option. Multicast discovery cannot leave the segment, by design rather than by accident.
- **The build is a TCP client only.** `DISABLE_TCP_SERVER` gates both the TCP port lookup and the TCP field of the discovery response (`ocresource.c:109,545`), so the device dials the cloud and never listens — and its `/oic/res` advertises no TCP port to find.

## The rule

A stack checkout corroborates a hardware finding. It never substitutes for one, and it is evidence only about devices proven to run it. Name the tree a citation comes from, name the device a measurement comes from, and keep the two claims apart.
