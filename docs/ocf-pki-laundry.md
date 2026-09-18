# Newer OCF-PKI laundry: connection findings and current limits

This is a compatibility and implementation note, not an ownership-reset or
onboarding guide. It records the sanitized protocol facts that made local
control possible on two Samsung Bespoke AI Laundry Combo appliances and maps
those facts to [issue #16](https://github.com/QuiteYellow/SmartThings-Local/issues/16)
and [issue #20](https://github.com/QuiteYellow/SmartThings-Local/issues/20).

The important distinction is that endpoint reachability, DTLS authentication,
resource authorization, and OCF ownership are four separate states. A response
at one layer is not proof that the next layer is usable.

## Hardware and software validated

The locally validated appliances are two `WD53DBA900HZA1` all-in-one
washer/dryers. Both report:

- model family `AWM-US-M64-24-WD80`;
- Tizen 7 / One UI 7 Laundry Combo; and
- primary software version `20260416.215549`.

Issue #16 reports `WD53DBA900HZ` and the same primary software version. The
reported protocol behavior also matches, so it is the same appliance/software
profile for the purposes of this library.

Issue #20 is different hardware: a `WW11BB534DAWS6` washer and
`DV90BB5245AWS6` dryer. Only the washer has detailed protocol evidence in that
issue, so nothing here claims that the dryer has the same profile.

## How the WD53 connection was established

### 1. Discover OCF instead of assuming a 4915x port

The WD53 exposes its public OCF surface on UDP 5683. `GET /oic/res` returns a
multi-block resource directory and advertises secure endpoint data. The two
validated units exposed the same 72 hrefs. They also have IPv4, IPv6 ULA, and
IPv6 link-local endpoints, and the secure endpoint can move.

The practical rules are:

- include the standard CoAP-DTLS port 5684 as well as the 4915x appliance
  range;
- preserve an IPv6 scope ID instead of flattening a link-local address into a
  host string;
- rediscover the secure endpoint before authentication when the appliance has
  slept or restarted; and
- prove a server with a DTLS ClientHello instead of treating an Nmap
  `open|filtered` result as protocol evidence, and read the endpoint off the
  reply's source port.

The production liveness probe must stop after the first
HelloVerifyRequest/ServerHello/Alert. It never returns the cookie to the
appliance, and packet-loss retries resend the exact same first flight. This
avoids creating half-open DTLS associations while searching several candidate
ports.

### 2. Treat the AC14K_M rejection as an authentication-profile result

An AC14K_M client chain reaches the WD53 DTLS server but is rejected with a
fatal `unknown_ca` alert. RSA versus ECDSA client keys do not change that
result. Re-signing only a leaf with SHA-256 cannot repair a trust chain the
appliance does not accept.

That result does **not** mean local OCF was removed. It means the fleet
certificate used by older SmartThings appliances is not the runtime principal
for this profile. Repeated AC14K_M attempts, a broader cipher list, or disabling
server verification do not produce authorization.

The accepted cipher for the authenticated paths below is exactly
`ECDHE-ECDSA-AES128-GCM-SHA256`. The production sessions did not disable TLS
verification. A first-flight diagnostic can classify an offered certificate
without authenticating it, but that observation never grants authorization.

### 3. Read and classify the public security state

The public security resources expose enough redacted state to choose a safe
next step:

- `/oic/sec/doxm` advertises standard manufacturer-certificate OTM `2` and
  Samsung manufacturer-certificate OTM `0xFF02` (`65282`);
- the two validated units were observed with each of those methods selected;
- `/oic/sec/pstat` distinguishes an operational owned device from a real
  manufacturer ownership-transfer window;
- the provisioning nonce rotates on every read; and
- this model declares that additional authorization is required.

Device, owner, and resource-owner UUIDs are sensitive identifiers and are not
needed in a public fixture. They must be compared locally and replaced with
synthetic values in tests or diagnostics.

### 4. Use the model's authorized, non-reset transition

During one-time research while the appliance was idle, the signed-in
SmartThings Android path was used to invoke the model's signed same-account,
non-factory-reset confirmation. This was a setup research carrier, not a
runtime dependency. It intentionally moved the OCF security state from owned
operation into a bounded, unowned manufacturer-OTM window; the later steps
installed a new OCF owner. SmartThings pairing survived on the two tested
units, but that does not make an ownership-changing operation generically safe.
The fresh confirmation had to occur immediately before the manufacturer DTLS
connection; a delayed confirmation missed the firmware's window.

The installed `5.0.47` appliance stack exposed provisioning feature `0x4000`
and validated two proof requests in this exact order:

Here `serial_hash_ascii` is the 128-character lowercase hexadecimal SHA-512
digest of the ASCII registration serial.

1. `TriggerSerialHashRequest` checks
   `SHA256(serial_hash_ascii || nonce_raw)`. The nonce is the current raw four
   bytes, not its eight-character hexadecimal text. This proof contains no
   account value.
2. The appliance rotates its nonce. `TriggerAutoResetHashRequest` then checks
   `SHA256(serial_hash_ascii || SHA256(user_id_ascii) || fresh_nonce_raw)`,
   where the inner SHA-256 is its raw 32-byte digest and the same-account user
   ID is ten ASCII characters. There are no delimiters between fields.

The order is the inverse of the method names in a newer application helper.
Reversing the requests caused the second stage to fail; matching the appliance
order opened the clean manufacturer-certificate RFOTM state. Only a fresh
public DOXM/PSTAT read—not an application callback—was accepted as proof of
that transition. No serial, account ID, nonce, or computed proof is included
here.

This authorization transition is the part that is **not yet a supported public
workflow**. The public formulas explain the installed firmware's checks; they
do not supply Samsung's signed request authority or disclose an account value.
A stock SmartThings-paired appliance must not be reset, claimed, or have its
owner replaced merely because its public OCF endpoint is reachable. A public
implementation still needs a model-supported same-account grant that does not
depend on private application state, captured credentials, or
reverse-engineering tools.

### 5. Open manufacturer DTLS without a client identity leaf

Inside the confirmed manufacturer window, the successful carrier is
server-authenticated DTLS using Samsung's manufacturer trust path. The client
does not present an AC14K_M, TEST, or OneApp identity leaf. This trust-only
connection can read the authenticated OCF security state needed for the
selected manufacturer OTM.

No new Samsung CA private key is needed for this step. The earlier
`unknown_ca` result and the successful manufacturer carrier are different
authentication modes, not contradictory observations.

### 6. Derive, stage, prove, and finalize OwnerPSK

The standards-based OwnerPSK derivation uses the selected method's exact label:

- method `2`: `oic.sec.doxm.mfgcert`;
- method `0xFF02`: `x.org.iotivity.conmfgcert`.

For the negotiated `ECDHE-ECDSA-AES128-GCM-SHA256` session, IoTivity computes:

1. `key_block = P_SHA256(master_secret, "key expansion" || server_random || client_random, 120)`;
2. `OwnerPSK = P_SHA256(key_block, selected_otm_label || owner_uuid || appliance_uuid, 16)`.

The master secret is 48 bytes, each random is 32 bytes, and each UUID is its
raw 16-byte value. The derivation is pure; obtaining the authenticated session
and deciding that an ownership transaction is authorized are separate
responsibilities.

The validated transaction stages the derived credential before the first
security mutation, writes only the reviewed credential/ACL/DOXM/PSTAT shapes,
then proves the new key on a fresh ECDHE-PSK session before publishing it as a
usable runtime credential. Final DOXM/PSTAT and public postflight reads must
all agree before the transaction is considered complete.

The resulting OwnerPSK is per appliance. It is never logged, returned by a
diagnostic, embedded in a fixture, or committed to source control.

### 7. Run normal control over OwnerPSK

After finalization, normal reads and writes use ECDHE-PSK CoAP-DTLS over the
currently advertised LAN endpoint. On each validated WD53, that path returned
39 complete protected representations with no link stubs. Low-risk settings
and power changes were accepted, verified by exact protected readback, and
restored. The same changes remained visible through SmartThings, demonstrating
coexistence for the tested transaction rather than a cloud replacement.

When the panel enters deep sleep, the secure endpoint can disappear. Runtime
code therefore retains last-good state honestly, backs off, and rediscovers
the endpoint when the panel returns; it does not use the cloud or an Android
application as a wake or polling dependency.

## How this maps to issues #16 and #20

### Issue #16: exact WD53 profile

Issue #16 reproduces both halves of the initial diagnosis:

- standard OCF ports rather than a fixed 4915x-only assumption; and
- AC14K_M client authentication rejected with `unknown_ca`.

The validated WD53 work demonstrates a path beyond that boundary:
manufacturer OTM followed by per-appliance OwnerPSK runtime authentication.
The remaining upstream gap is not proof that the protocol works; it is a safe,
portable, owner-preserving authorization and credential setup flow.

### Issue #20: related `0xFF02` evidence, different models

The washer in issue #20 exposes public OCF on 5683, a DTLS listener on 49154,
and reports `owned:false`, `isop:false`, with only OTM `0xFF02` advertised. That
is consistent with a Samsung manufacturer-OTM window, and it makes the WD53
`0xFF02` transport and OwnerPSK work directly relevant.

It is not yet proof of support. The issue reports `handshake_failure` rather
than the WD53's `unknown_ca`, and the model-specific additional-authorization,
nonce, confirmation timing, security payload, and protected-read behavior have
not been validated. The dryer in the issue has not supplied equivalent
evidence. Both devices need independent, non-destructive validation.

## What this pull request does and does not solve

This pull request implements the endpoint half of these reports:

- bounded, connected IPv4/IPv6 stateless probes;
- byte-identical first-flight retransmission;
- concurrent standard-port and 4915x probing;
- deterministic listener selection; and
- an explicit ambiguous result instead of first-responder guessing.

It does not make AC14K_M authenticate to either issue's appliance and does not
perform OTM or write `/oic/sec/*`. Follow-up package work is still required for
explicit authentication providers, PSK sessions, Samsung certificate profiles,
OwnerPSK derivation, reviewed OCF security codecs, and the separately reviewed
authorization/setup policy.

## Safe evidence for another device report

Useful public evidence is limited to:

- retail model without a serial number;
- software version;
- sanitized candidate ports and first-flight response classes;
- redacted `/oic/res`, `/oic/sec/doxm`, and `/oic/sec/pstat` shapes; and
- the fixed TLS alert number/name.

Do not post appliance or owner UUIDs, account identifiers, network addresses,
registration values, nonces, certificate fingerprints, credentials, packet
captures, or raw exception traces.
