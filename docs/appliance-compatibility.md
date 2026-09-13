# Is your appliance compatible?

Which Samsung appliances answer a local DTLS-CoAP session, how to find out,
and the firmware-family caveat behind the answer.

Getting the client certificate a compatible appliance needs is in
[docs/certificates.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/certificates.md).

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

`live` means a DTLS server answered its first flight; `dead` means silent or not DTLS. Once you have the client cert (see [docs/certificates.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/certificates.md)), add the explicit `--diagnostic` flag to run the stateful diagnostic drive, which reports `completed` (cert accepted) or `rejected` with the server's fatal alert. Diagnostic mode can allocate appliance-side DTLS state and is never used by discovery or reconnect. An `unsupported_certificate` / `unknown_ca` alert means the endpoint is reachable but this certificate profile was rejected. It is not a reason to disable verification or keep retrying. The same bounded stateless API gates the bridge's reconnect loop and, when `OCF_PORT` is unset, probes both standard 5684 and ports 49152–49160.

A device that rejects the certificate profile may still run a PSK endpoint, and `diagnose_dtls_handshake` takes any authentication provider through `auth=` so that carrier can be characterised the same way:

```python
from smartthings_local.protocol.auth import PskAuth
from smartthings_local.protocol.dtls_probe import diagnose_dtls_handshake

result = diagnose_dtls_handshake(
    appliance_host,
    secure_port,
    auth=PskAuth(identity=psk_identity, key=psk_key),
)
```

`auth=` is mutually exclusive with `cert_pem`/`key_pem`/`cert_path`/`key_path`. A `rejected` outcome carrying `unknown_psk_identity` means the endpoint negotiated ECDHE-PSK and then refused the credential, which distinguishes a PSK device from one with no local DTLS at all. The CLI exposes the same thing as `--diagnostic --psk-identity HEX --psk-key HEX`, and since a command line is readable by every process on the host, pass a throwaway value there rather than a real credential.

A diagnostic never enforces trust, whichever credential it is given. A provider's own verification, including a `SamsungServerProfile`'s pinned server identity, is deliberately not honoured: the result has to report what the appliance did, so an untrusted chain is classified rather than rejected locally. Use `DtlsCoapSession` when the trust decision is the point.

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

## Tested combinations

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

## Firmware families: a limitation

Descriptors are firmware-family-specific. Each descriptor hardcodes the resource layout of one firmware family: which hrefs it polls, which fields it reads, which write surfaces it exposes. There's no runtime feature detection. The three sample descriptors here (`mqtt_demo/samples/`) are frozen references.

**What this means in practice:** if you set `APPLIANCE_<n>_CLASS=fridge` on a fridge that speaks a different firmware family than the one this descriptor was built for, the bridge will start and connect fine, but many sensors will publish as unknown and some controls won't work. Nothing catastrophic. You just get a half-broken HA device card.

If your appliance model doesn't match a row in the tested table above, it may still work if it's on the same firmware family; otherwise you'd write a new descriptor (see "Adding a new appliance class" below). The ARTIK051 fridge and the newer RF9000B-class fridge, for example, expose different resource models (collection-resource vs per-instance-resource) and can't share a descriptor even though they're both "fridges".
