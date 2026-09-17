# Client certificates for AC14K_M-compatible firmware

How to obtain the client certificate a compatible appliance accepts, why it works, and how durable it is. Passing one to the library is covered by [Authentication](https://github.com/QuiteYellow/SmartThings-Local/blob/main/README.md#authentication) in the README. Whether a given appliance accepts this credential at all is covered by [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md).

For a compatible firmware family, the bridge authenticates with a **client cert** whose Subject DN carries a UUID that those appliances' on-device ACLs grant full access to. The UUID is what authorizes; on the appliances tested, the signer and chain are not checked, so `setup_cert.py` self-signs the cert by default. `--fallback` signs it with `AC14K_M` instead, an intermediate CA that has been public for years, for a device that does validate the chain.

You can read the UUID yourself out of the cloud gateway's server cert:

```sh
openssl s_client -connect <host-containing-uuid>:443 \
                 -servername <host-containing-uuid> \
                 -showcerts < /dev/null 2>/dev/null \
  | openssl x509 -noout -subject
```

The UUID lives in `OU=uuid:<UUID>`. The server cert is currently valid through **2035-04-09**.

## Why this works

- The compatible appliances tested carry a **factory-baked ACE** in `/oic/sec/acl` granting this UUID `perm=31` on `href=*`.
- TizenRT iotivity derives peerId from `memmem(subject_dn, "uuid:")`, which is RDN-agnostic. A cert with the UUID in CN authenticates the same as one with it in OU.
- The signature is not a gate on the appliances tested. A self-signed leaf, and a leaf signed by a CA the appliance has never seen, read the same resources as an `AC14K_M`-signed one, over both DTLS and TCP-TLS, and a leaf carrying an un-ACL'd UUID is refused `4.01` on every resource. Signer, chain, digest and key are all cosmetic there.
- No original private key comes into it either way: `setup_cert.py` mints a fresh key of your own. Different key, same identity, same access.

## One-command setup

```sh
pip install -r requirements-bootstrap.txt
TARGET_IP=$APPLIANCE_IP python setup_cert.py --test
```

What it does:

1. Fetches the cloud gateway's server cert and extracts the current UUID from its subject DN.
2. Generates a fresh RSA-2048 key pair you own.
3. Builds a CSR with the UUID in OU + CN + SAN.
4. Signs the leaf with its own key, using SHA-256. There is no CA, so the fullchain PEM holds the one certificate.
5. With `--test`: opens a DTLS handshake against `$TARGET_IP:$TARGET_PORT` (default `49154`) and GETs `/oic/sec/acl`; a `2.05` reply proves the cert authenticated (anonymous peers get `4.01`).

With `--fallback`, step 4 becomes the pre-2026 recipe instead: fetch the AC14K_M signing CA, private key and upstream chain (RemoteAccessCA → CECA → ROOTCA) from a public mirror, check that the cert and key actually pair (modulus match), sign the leaf with `AC14K_M` using SHA-1 as the original recipe did, and concatenate `leaf + AC14K_M + 3 upstream CAs`.

Output in `./certs/`: `client_fullchain.pem` + `client.key`.

Neither the UUID nor the AC14K_M bundle is hardcoded in this repo. The UUID is fetched live each run, and the bundle whenever `--fallback` calls for it. If either fetch fails, the script prints an inline workaround: supply the UUID via `UUID=<uuid>` env, or supply the AC14K_M bundle via `AC14K_M_CERT_BUNDLE=/path/to/cert.pem`. `BRAYSTORM_URL=<mirror>` points at a different bundle source.

On Fedora/RHEL (and other hardened OpenSSL 3.x builds) the default crypto policy blocks SHA-1 signing, which `--fallback` needs. (The default path signs with SHA-256 and is unaffected.) The script detects this, retries the signing step once with SHA-1 force-enabled for just that command, and only fails if the retry also fails. If it does, it prints the remedy: `sudo update-crypto-policies --set DEFAULT:SHA1` (undo afterward with `sudo update-crypto-policies --set DEFAULT`).

## How durable is this on the compatible firmware families?

Rotating the published UUID would require coordinated cloud certificate, ACL, and device identity changes across the compatible firmware families. `AC14K_M` has been public for years and remains accepted by the appliances listed in [docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md), but it is already rejected by other 2026 appliance profiles. Do not extrapolate this certificate path to an untested model.

> **Legacy path:** earlier versions used a per-hub-UUID cert via an anonymous `/oic/sec/doxm` read escalation. That still works on the dryer-family firmware but isn't necessary: the cert minted here authenticates against the compatible families above, and survives device resets. The old `bootstrap.py` for the legacy flow was removed when the package was renamed; see git history if you need it.
