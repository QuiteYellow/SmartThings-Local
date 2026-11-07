# Client certificates for AC14K_M-compatible firmware

How to obtain the client certificate a compatible appliance accepts, why it works, and how durable it is. Passing one to the library is covered by [Authentication](https://github.com/QuiteYellow/SmartThings-Local/blob/main/README.md#authentication) in the README. Whether a given appliance accepts this credential at all is covered by [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md).

For a compatible firmware family, the bridge authenticates with a **client cert** whose Subject DN carries a UUID that those appliances' on-device ACLs grant full access to. The UUID is what authorizes; on the appliances tested, the signer and chain are not checked, so `setup_cert.py` self-signs the cert by default. `--fallback` signs it with `AC14K_M` instead, an intermediate CA that has been public for years, for a device that does validate the chain.

`setup_cert.py` carries that UUID as the constant `CLIENT_UUID`. It is a cloud service identity, published in the subject DN of a public server certificate as `OU=uuid:<UUID>`, and it is pinned by the installed base: rotating it would mean pushing an ACL change to every appliance in the field. Two certificates issued years apart, under different sub-CA generations, were observed carrying the same value. Set `UUID=<uuid>` to override the constant.

## Why this works

- The compatible appliances tested carry a **factory-baked ACE** in `/oic/sec/acl` granting this UUID `perm=31` on `href=*`.
- IoTivity classic derives peerId by scanning the raw subject for `"uuid:"` (`ca_adapter_net_ssl.c:78,2268` in Samsung's fork, `:75,1769` upstream, where the code is the same), which is RDN-agnostic. A cert with the UUID in CN authenticates the same as one with it in OU.
- The signature is not a gate on the appliances tested. A self-signed leaf, and a leaf signed by a CA the appliance has never seen, read the same resources as an `AC14K_M`-signed one, over both DTLS and TCP-TLS, and a leaf carrying an un-ACL'd UUID is refused `4.01` on every resource. Signer, chain, digest and key are all cosmetic there.
- No original private key comes into it either way: `setup_cert.py` mints a fresh key of your own. Different key, same identity, same access.

## One-command setup

```sh
pip install -r requirements-bootstrap.txt
python setup_cert.py
```

Nothing in this reaches an appliance. The UUID is a constant, the key and leaf are minted locally by `openssl`, and the only network access is the `--fallback` bundle fetch. Checking the result against a device is a separate step, below.

What it does:

1. Takes the UUID from `CLIENT_UUID` (or from `UUID=<uuid>` in the environment).
2. Generates a fresh RSA-2048 key pair you own.
3. Builds a CSR with the UUID in OU + CN + SAN.
4. Signs the leaf with its own key, using SHA-256. There is no CA, so the fullchain PEM holds the one certificate.

With `--fallback`, step 4 becomes the pre-2026 recipe instead: fetch the AC14K_M signing CA, private key and upstream chain (RemoteAccessCA → CECA → ROOTCA) from a public mirror, check that the cert and key actually pair (modulus match), sign the leaf with `AC14K_M` using SHA-1 as the original recipe did, and concatenate `leaf + AC14K_M + 3 upstream CAs`.

Output in `./certs/`: `client_fullchain.pem` + `client.key`.

The AC14K_M bundle is not in this repo. `--fallback` fetches it from a public mirror each run, and if that fetch fails the script prints the workaround: supply the bundle via `AC14K_M_CERT_BUNDLE=/path/to/cert.pem`, or point at another mirror with `BRAYSTORM_URL=<mirror>`.

On Fedora/RHEL (and other hardened OpenSSL 3.x builds) the default crypto policy blocks SHA-1 signing, which `--fallback` needs. (The default path signs with SHA-256 and is unaffected.) The script detects this, retries the signing step once with SHA-1 force-enabled for just that command, and only fails if the retry also fails. If it does, it prints the remedy: `sudo update-crypto-policies --set DEFAULT:SHA1` (undo afterward with `sudo update-crypto-policies --set DEFAULT`).

## Checking the cert against a device

```sh
python -m smartthings_local.protocol.dtls_probe <ip> <port> --diagnostic \
    --cert certs/client_fullchain.pem --key certs/client.key
```

`--diagnostic` reports the server's own flight and any fatal alert, so a refusal names itself: `alert=unknown_ca` is the OCF-PKI wall ([#16](https://github.com/QuiteYellow/SmartThings-Local/issues/16)), while a bare `handshake_failure` with nothing ahead of it is something else.

Find the port with `discover_ocf_secure_ports`. It is assigned by the appliance and differs between units, so there is no default worth guessing at; an earlier `--test` flag here defaulted to `49154` and reported a timeout on any appliance that had landed elsewhere.

A completed handshake does not prove the certificate authorized, because these appliances complete one with no client certificate at all. What settles that is an authenticated read over a `DtlsCoapSession`: `GET /oic/sec/acl` returning `2.05`, where an anonymous peer gets `4.01`.

## How durable is this on the compatible firmware families?

Rotating the published UUID would require coordinated cloud certificate, ACL, and device identity changes across the compatible firmware families. `AC14K_M` has been public for years and remains accepted by the appliances listed in [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md), but it is already rejected by other 2026 appliance profiles. Do not extrapolate this certificate path to an untested model.

> **Legacy path:** earlier versions used a per-hub-UUID cert via an anonymous `/oic/sec/doxm` read escalation. That still works on the dryer-family firmware but isn't necessary: the cert minted here authenticates against the compatible families above, and survives device resets. The old `bootstrap.py` for the legacy flow was removed when the package was renamed; see git history if you need it.

## Appliances that drop off the network during the handshake

Some units leave the network for about ten seconds whenever they have to put a handshake flight on the wire that will not fit one Ethernet frame. Their own flight is that size, so they never finish a handshake, and the logs stay silent about why: the client records a timeout while the appliance's smart-connect indicator blinks. This is [issue #20](https://github.com/QuiteYellow/SmartThings-Local/issues/20) and [mbillow/localthings#504](https://github.com/mbillow/localthings/issues/504), four appliances between them.

A client can steer around it. DTLS carries a `max_fragment_length` extension, and a unit that honours it splits its flight at the DTLS layer, so every datagram stays inside one frame. Measured on both appliances on issue #20 on 2026-10-25: each probe that omitted the extension took the unit off the network for nine to ten seconds, and both probes that offered it drew the appliance's whole flight with no loss.

`openssl s_client` sends the extension with `-maxfraglen`, so OpenSSL itself supports it. The Python bindings are where it stops. `cryptography` publishes neither `SSL_CTX_set_tlsext_max_fragment_length` nor the `SSL_CTX_ctrl` that macro goes through, and it links OpenSSL statically with those symbols hidden, so there is no route to them from `pyOpenSSL` either.

Hence a DTLS client belonging to this package, which `FragmentingCertificateAuth` carries:

```python
from smartthings_local.protocol.auth import FragmentingCertificateAuth

auth = FragmentingCertificateAuth.from_files("client.pem", "client.key")
```

Add `server_profile=SamsungServerProfile.bound_device(certificate_uuid)` when you hold the appliance's hardware leaf UUID and want it pinned.

Three things to know before choosing it.

*Opt-in only.* Nothing in this package selects this provider, and the usual certificate path still runs on pyOpenSSL. The engine has met no appliance yet. It is tested against OpenSSL acting as the server, on the dependency floor and on current, which is weaker evidence than hardware.

*A server profile is optional, as it is on `CertificateAuth`.* Without one, the peer's chain is verified against the bundled OCF root and nothing further is pinned, which is what the pyOpenSSL path does with a profileless context. With one, the profile's role, subject and UUID checks apply on top. Nothing per-appliance is needed either way: the client certificate's own subject UUID is a constant that does not rotate, and a profile pins the appliance's hardware leaf UUID, which is a separate identity and differs between units.

*Only the carrier changes.* Trust still rests on the bundled OCF root plus any extra CA the profile holds, and the leaf must satisfy the same role, subject and UUID checks. The engine restates none of those rules; it calls the profile and acts on the verdict.

An appliance that already finishes a handshake gains nothing from this provider. It is for the units that stall.

## What an integration needs from the library

Three pieces of supported API come with the engine, for a Home Assistant integration or anything else driving it.

**`DtlsConnectionProvider`** is the seam. A credential whose carrier is not pyOpenSSL answers `create_dtls_connection(*, mtu)` and returns a `DtlsConnection`; `DtlsCoapSession` and `diagnose_dtls_handshake` use it in place of building a context. Both types are in `docs/api.md`, and `DtlsConnection` states the whole surface the library drives, which is eight methods. An earlier private spelling, `_create_dtls_connection`, is still consulted and raises a `DeprecationWarning`.

**`DtlsCoapSession.negotiated_fragment_length`** reports the limit in force, or `None`. Because these appliances cannot send a record larger than a negotiated length, this is the ceiling on any single representation a read can return. Check it before reading a resource you expect to be large, since the read will otherwise stall at its first block.

**`FragmentLimitTimeoutError`** is raised when a read gives up on its *first* block while a fragment length is in force. It subclasses `SessionTimeoutError`, so existing handlers are unaffected, and it carries `.fragment_length`.

That last one establishes exactly one thing: the first block drew nothing while a limit was negotiated. An appliance that has powered its radio down produces the same silence, so the error names the conditions rather than proving a cause. What separates the two is whether smaller resources on the same device still answer, and that is the caller's to decide. A timeout on a later block stays an ordinary `SessionTimeoutError`, because blocks were arriving and the deadline was the binding constraint.
