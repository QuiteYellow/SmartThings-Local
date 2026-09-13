# Client certificates for AC14K_M-compatible firmware

How to obtain the client certificate a compatible appliance accepts, why it
works, and how durable it is. Passing one to the library is covered by
[Authentication](https://github.com/QuiteYellow/SmartThings-Local/blob/main/README.md#authentication) in the README. Whether a
given appliance accepts this credential at all is covered by
[docs/appliance-compatibility.md](https://github.com/QuiteYellow/SmartThings-Local/blob/main/docs/appliance-compatibility.md).

For a compatible firmware family, the bridge authenticates with a **client
cert** signed by `AC14K_M`, an intermediate CA that has been public for years.
The cert's Subject DN carries a UUID that those appliances' on-device ACLs
grant full access to.

You can read the UUID yourself out of the relevant server cert:

```sh
openssl s_client -connect <samsung-host>:443 -servername <samsung-host> \
                 -showcerts < /dev/null 2>/dev/null \
  | openssl x509 -noout -subject
# subject=C=KR, O=Samsung Electronics, OU=uuid:<UUID>, CN=*.samsungiotcloud.com
```

The UUID lives in `OU=uuid:<UUID>`. The server cert is currently valid through **2035-04-09**.

This README doesn't pin the literal UUID: the setup script extracts it live each run, so it self-updates if upstream rotates.

## Why this works

- Each currently supported Tizen/RT-OCF firmware family has a **factory-baked ACE** in `/oic/sec/acl` granting this UUID `perm=31` on `href=*`.
- TizenRT iotivity derives peerId from `memmem(subject_dn, "uuid:")`, which is RDN-agnostic. A cert with the UUID in CN authenticates the same as one with it in OU.
- We don't need the matching private key from the original keyholder. We mint our own key and have `AC14K_M` sign our leaf. Different key, same identity, same access.

## One-command setup

```sh
pip install -r requirements-bootstrap.txt
TARGET_IP=$APPLIANCE_IP python setup_cert.py --test
```

What it does:

1. Fetches the AC14K_M signing CA + private key + upstream chain (RemoteAccessCA → CECA → ROOTCA) from a public mirror.
2. Fetches the relevant server cert and extracts the current UUID from its subject DN.
3. Sanity-checks that the AC14K_M cert and key actually pair (modulus match) before signing anything.
4. Generates a fresh RSA-2048 key pair you own.
5. Builds a CSR with the UUID in OU + CN + SAN and signs it with `AC14K_M` (SHA-1, matching the on-device trust hierarchy).
6. Concatenates `leaf + AC14K_M + 3 upstream CAs` into the fullchain PEM.
7. With `--test`: opens a DTLS handshake against `$TARGET_IP:$TARGET_PORT` (default `49154`) and GETs `/oic/sec/acl`; a `2.05` reply proves the cert authenticated (anonymous peers get `4.01`).

Output in `./certs/`: `client_fullchain.pem` + `client.key`.

Neither the UUID nor the AC14K_M bundle is hardcoded in this repo; both are fetched live each run, so the script self-updates if upstream rotates. If either fetch fails, the script prints an inline workaround: supply the UUID via `UUID=<uuid>` env, or supply the AC14K_M bundle via `AC14K_M_CERT_BUNDLE=/path/to/cert.pem`. `BRAYSTORM_URL=<mirror>` points at a different bundle source.

On Fedora/RHEL (and other hardened OpenSSL 3.x builds) the default crypto policy blocks SHA-1 signing, which step 5 needs. The script detects this, retries the signing step once with SHA-1 force-enabled for just that command, and only fails if the retry also fails. If it does, it prints the remedy: `sudo update-crypto-policies --set DEFAULT:SHA1` (undo afterward with `sudo update-crypto-policies --set DEFAULT`).

## How durable is this on the compatible firmware families?

Rotating the published UUID would require coordinated cloud certificate, ACL,
and device identity changes across the compatible firmware families.
`AC14K_M` has been public for years and remains accepted by the tested rows
above, but it is already rejected by other 2026 appliance profiles. Do not
extrapolate this certificate path to an untested model.

> **Legacy path:** earlier versions used a per-hub-UUID cert via an anonymous `/oic/sec/doxm` read escalation. That still works on the dryer-family firmware but isn't necessary: the cert minted here authenticates against every appliance and survives device resets. The old `bootstrap.py` for the legacy flow was removed when the package was renamed; see git history if you need it.
