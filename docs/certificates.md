# Client certificates for AC14K_M-compatible firmware

How to obtain the client certificate a compatible appliance accepts, why it works, and how durable it is. Passing one to the library is covered by [Authentication](https://github.com/QuiteYellow/SmartThings-Local/blob/main/README.md#authentication) in the README. Whether a given appliance accepts this credential at all is covered by [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md).

For a compatible firmware family, the bridge authenticates with a **client cert** whose Subject DN carries a UUID that those appliances' on-device ACLs grant full access to. The UUID is what authorizes; on the appliances tested, the signer and chain are not checked, so `setup_cert.py` self-signs the cert by default. `--fallback` signs it with `AC14K_M` instead, an intermediate CA that has been public for years, for a device that does validate the chain.

`setup_cert.py` carries that UUID as the constant `CLIENT_UUID`. It is a cloud service identity, published in the subject DN of a public server certificate as `OU=uuid:<UUID>`, and it is pinned by the installed base: rotating it would mean pushing an ACL change to every appliance in the field. Two certificates issued years apart, under different sub-CA generations, were observed carrying the same value. Set `UUID=<uuid>` to override the constant.

## Why this works

- The compatible appliances tested carry a **factory-baked ACE** in `/oic/sec/acl` granting this UUID `perm=31` on `href=*`.
- IoTivity classic derives peerId by scanning the raw subject for `"uuid:"` (`ca_adapter_net_ssl.c:78,2268` in Samsung's fork at the pin in [`AGENTS.md`](https://github.com/QuiteYellow/SmartThings-Local/blob/main/AGENTS.md); `:75,1769` upstream, where the code is the same), which is RDN-agnostic. A cert with the UUID in CN authenticates the same as one with it in OU.
- The signature is not a gate on the appliances tested. A self-signed leaf, and a leaf signed by a CA the appliance has never seen, read the same resources as an `AC14K_M`-signed one, over both DTLS and TCP-TLS, and a leaf carrying an un-ACL'd UUID is refused `4.01` on every resource. Signer, chain, digest and key are all cosmetic there.
- No original private key comes into it either way: `setup_cert.py` mints a fresh key of your own. Different key, same identity, same access.

## One-command setup

```sh
pip install -r requirements-bootstrap.txt
TARGET_IP=$APPLIANCE_IP python setup_cert.py --test
```

What it does:

1. Takes the UUID from `CLIENT_UUID` (or from `UUID=<uuid>` in the environment).
2. Generates a fresh RSA-2048 key pair you own.
3. Builds a CSR with the UUID in OU + CN + SAN.
4. Signs the leaf with its own key, using SHA-256. There is no CA, so the fullchain PEM holds the one certificate.
5. With `--test`: opens a DTLS handshake against `$TARGET_IP:$TARGET_PORT` (default `49154`) and GETs `/oic/sec/acl`; a `2.05` reply proves the cert authenticated (anonymous peers get `4.01`).

With `--fallback`, step 4 becomes the pre-2026 recipe instead: fetch the AC14K_M signing CA, private key and upstream chain (RemoteAccessCA → CECA → ROOTCA) from a public mirror, check that the cert and key actually pair (modulus match), sign the leaf with `AC14K_M` using SHA-1 as the original recipe did, and concatenate `leaf + AC14K_M + 3 upstream CAs`.

Output in `./certs/`: `client_fullchain.pem` + `client.key`.

The AC14K_M bundle is not in this repo. `--fallback` fetches it from a public mirror each run, and if that fetch fails the script prints the workaround: supply the bundle via `AC14K_M_CERT_BUNDLE=/path/to/cert.pem`, or point at another mirror with `BRAYSTORM_URL=<mirror>`.

On Fedora/RHEL (and other hardened OpenSSL 3.x builds) the default crypto policy blocks SHA-1 signing, which `--fallback` needs. (The default path signs with SHA-256 and is unaffected.) The script detects this, retries the signing step once with SHA-1 force-enabled for just that command, and only fails if the retry also fails. If it does, it prints the remedy: `sudo update-crypto-policies --set DEFAULT:SHA1` (undo afterward with `sudo update-crypto-policies --set DEFAULT`).

## How durable is this on the compatible firmware families?

Rotating the published UUID would require coordinated cloud certificate, ACL, and device identity changes across the compatible firmware families. `AC14K_M` has been public for years and remains accepted by the appliances listed in [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md), but it is already rejected by other 2026 appliance profiles. Do not extrapolate this certificate path to an untested model.

> **Legacy path:** earlier versions used a per-hub-UUID cert via an anonymous `/oic/sec/doxm` read escalation. That still works on the dryer-family firmware but isn't necessary: the cert minted here authenticates against the compatible families above, and survives device resets. The old `bootstrap.py` for the legacy flow was removed when the package was renamed; see git history if you need it.
