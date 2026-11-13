# Intended behaviour

Each line is a behaviour someone chose on purpose, and why. If a result contradicts a line, either it is a bug or the line changes in the same commit as the behaviour.

## Diagnostics

- `diagnose_dtls_handshake` never enforces trust, whatever credential it gets, `FragmentingCertificateAuth` included. A diagnostic reports the appliance's own alert, and a local refusal hides it. (2026-11-13)

## The certificate engine

- `FragmentingCertificateAuth` is opt-in, and nothing in the package selects it. Its hardware evidence is two appliances that already work on pyOpenSSL, and the units it exists for (#20) are untested with it. (2026-11-07)
- When the engine refuses the peer before its own flight, it sends one epoch-zero fatal `handshake_failure`. Otherwise the peer keeps a half-open handshake for this client. TizenRT's `iotivity_1.2-rel` fork frees that state on a fatal alert, which is read in code and not measured. (2026-11-13)
- The engine verifies the server chain for the SSL-server purpose. The pyOpenSSL path refuses a leaf whose EKU lacks serverAuth, and the two paths must give the same trust answer. (2026-11-13)

## Requests

- Under a negotiated fragment length, every CoAP message fits the length whole, and `post()` uses Block1 at the largest block size that fits. One CoAP message is one record, and a record over the length is refused. (2026-11-13)
- A request that cannot fit raises `ValueError` before anything is sent. The engine's own refusal is a bare `SSL.Error`, which no caller handles. (2026-11-13)
- The private `_create_dtls_connection` hook still works and warns with `FutureWarning`. The default filters hide a `DeprecationWarning` that is attributed to package code, so the integration that uses the hook would never see it. (2026-11-13)
