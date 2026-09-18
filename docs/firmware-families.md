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

## Anchoring the version

Once the stack is known, match `file:line` pairs from the log against the same file at each stock release tag. The line a given message sits on moves between releases, so a handful of anchors narrows the era.

For the two appliances here, `ca_adapter_net_ssl.c` exists only from 1.2 onward, which sets the floor, and the log's `ocstack.c:537` "CASendRequest failed" sits 11 lines after stock 1.2.1's 526, where 1.3.x and 2.0.0 put it past 670.

Read the result as an era. A vendor fork adds log statements, so the appliance's line numbers should sit a little after the stock tag's, and some messages in these logs appear in no stock release at all.

## Which directory dialect

Three separate facts, often conflated:

- **`icv` on `/oic/d`** reports the spec version the firmware claims. Both appliances here report `core.1.1.0`, which is also IoTivity classic 1.2.1's compiled-in default (`octypes.h:289`, served at `ocresource.c:1429` unless the integrator overrides it). So it is a decent hint about the build and a weak one about anything else.
- **The dialect served is chosen by the request.** Both stock stacks pick the `/oic/res` representation from the Accept option. Accept 60 selects the OIC 1.1 form; Accept 10000 asks for the OCF 1.0 form. Both appliances here answer 60 and return `4.06` to 10000, and a `4.06` after a clean parse says the board declines that format outright.
- **What the answer carries** follows from the dialect. OCF 1.0 and later carry a secure `eps` entry; an OIC 1.1 device carries `p.sec`/`port` on its `/oic/sec/doxm` link, and its directory has no `eps` key anywhere. A missing `eps` therefore identifies the generation, and anyone chasing it as a defect is chasing the wrong thing. `discover_ocf_secure_ports` reads both forms from whichever answer arrives.

## What each stack binds

Relevant because it decides which ports answer, and because two of these three disagree with the appliances here.

| | IoTivity classic 1.2.1 | RT-OCF | iotivity-lite |
| --- | --- | --- | --- |
| multicast plaintext | `m4` on 5683 | `mcast_v4` on 5683 | `mcast4` on 5683 |
| multicast secure | `m4s` on **5684** | none | none |
| unicast plaintext | `u4`, kernel-assigned | `ucast_v4`, kernel-assigned | kernel-assigned |
| unicast secure | `u4s`, kernel-assigned | `dtls_v4`, kernel-assigned | `secure_port4`, dynamic |
| source | `caipadapter.c:203-208`, `caipinterface.h:163-164`, `caipserver.c:656-745` | `rt_udp.c:152,164` | `port/linux/ipadapter.c:79,1491` |

All three bind their multicast sockets to `INADDR_ANY`, so a *unicast* datagram to 5683 lands on one and is served. That is why plaintext `/oic/res` answers on 5683 across stacks. The convention has a mechanism behind it and no clause: OCF Core fixes 5683 as the multicast listen port and requires the discovery resources on an unsecured endpoint, while leaving the unsecured unicast endpoint on any port the implementer likes.

5684 is the divergence: classic binds it, the table above shows what the other two put there, and every 5684 in OCF Core 2.2.8 is `coap+tcp` default-port text. An appliance answering a DTLS ClientHello on 5684 is running something classic-shaped, and its answer will come from the kernel-assigned secure socket.

Replies from those kernel-assigned sockets are why a port probe has to select on the reply's source port, and why a stateful firewall or a bridge NAT can make a live port look dead. See [docs/appliance-compatibility.md](appliance-compatibility.md).

## The rule

A stack checkout corroborates a hardware finding. It never substitutes for one, and it is evidence only about devices proven to run it. Name the tree a citation comes from, name the device a measurement comes from, and keep the two claims apart.
