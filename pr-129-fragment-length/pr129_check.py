#!/usr/bin/env python3
"""pr129_check.py -- does PR #129's certificate engine work on your appliance?

For appliances that need a negotiated fragment length: the washer and dryer on
QuiteYellow/SmartThings-Local#20, which leave the network when they must send a
DTLS handshake flight that does not fit one frame, and the TP1X boards on
mbillow/localthings#504. PR #129 adds `FragmentingCertificateAuth`, a
client-certificate credential whose ClientHello offers `max_fragment_length`,
so the appliance splits its flight to fit. This script drives that credential
through the library's own `DtlsCoapSession`, the same path an integration would
use.

Per appliance, at most two DTLS handshakes, each in its own session:

  Arm 1  max_fragment_length 1024, the library default. Handshake, report the
         length in force, GET /oic/d (small), then GET each --path in order
         (default /device/0, the large state read), close.
  Arm 2  max_fragment_length 512, the length already measured on the #20
         units on 2026-10-25. The same reads, close. Runs only if arm 1's
         handshake completed.

         /oic/d goes first in each arm because a session can stop answering
         after a large read fails. For the same reason a failed --path usually
         leaves the later ones in that arm unanswered, so list the ones you
         expect to be smaller first. At this commit a read under a fragment
         length first sends a primer: a GET that asks for block 0 at a size
         that fits. The appliance firmware does not answer the primer, but it
         keeps the size, and the plain GET that follows on the same token comes
         back in blocks of that size. On a dryer here, /device/0 (4607 bytes)
         came back in 512-byte blocks at 1024 on 2026-11-19. Whether these
         units do the same is what this run measures. A
         FragmentLimitTimeoutError on /device/0 means they do not.

What it reports:

  - whether each handshake completed, and the fragment length in force;
  - the reason a handshake failed, as the library logs it. A fatal alert from
    the appliance is named, for example `unknown_ca`, which is the certificate
    wall on issue #16;
  - the CoAP response code and size for each read;
  - after each arm, whether the appliance still answers plaintext CoAP, and
    how long it took. That separates "left the network" from "refused us".

What it never does: write anything, touch /oic/sec/*, retry a handshake, or
print an address, a device UUID, a serial or certificate detail. The output
is meant to be pasted into the issue as it stands. Read it first anyway.

Cost: if a handshake times out, the appliance can refuse new handshakes from
this script's local port for more than 10 minutes. That was measured on a
dryer on 2026-11-13. Your integration uses its own port, but disable it for
these appliances during the run anyway, so that two clients do not contend.
With two appliances the run takes about 4 minutes. Most of that is a 60 s
quiet time before each handshake after the first, which starts again when
the appliance answers after a drop-off. Each drop-off adds its recovery
time, so a run where the appliances drop off can take 6 minutes or more.

Install and run, on a machine on the appliances' network (Python 3.11+ and git).
Run it on the host itself, not in a container on Docker's bridge network:
these appliances answer from a different port than the one addressed, and
the bridge NAT drops those replies (#110).

    python3 -m venv stl-129
    stl-129/bin/pip install "smartthings-local @ git+https://github.com/QuiteYellow/SmartThings-Local@f74a26e2fd37708861feb3c55368532bff57973d"
    stl-129/bin/python pr129_check.py \\
        --cert certs/client_fullchain.pem --key certs/client.key \\
        <dryer-ip> <washer-ip>

For other resources, name them with --path, once per resource, for example
on a TP1X board:

    stl-129/bin/python pr129_check.py --cert ... --key ... \\
        --path /information/vs/0 --path /oic/res <board-ip>

--path takes GET-only resource paths: no query, and nothing under /oic/sec.

The certificate and key are the ones `setup_cert.py` wrote, or the client
certificate chain and key your integration uses, as PEM files. The secure port
is discovered from each appliance's plaintext directory; there is no default,
because these appliances bind their DTLS socket to port 0 and the port moves
across a reboot.
"""

import argparse
import logging
import re
import sys
import time
import warnings
from importlib.metadata import PackageNotFoundError, version


def _show_warning(message, category, filename, lineno, file=None, line=None):
    """Print a warning's class only.

    The default line starts with the path of the file that raised it, and
    that path holds the user's home directory. Set before the library import,
    so warnings raised at import time are covered too.
    """
    print(f"warning: {category.__name__}", file=sys.stderr)


warnings.showwarning = _show_warning

try:
    from smartthings_local.errors import (
        EndpointError,
        FragmentLimitTimeoutError,
        PeerInitiatedHandshakeError,
        SessionError,
        SessionTimeoutError,
    )
    from smartthings_local.protocol.auth import FragmentingCertificateAuth
    from smartthings_local.protocol.dtls_session import DtlsCoapSession
    from smartthings_local.protocol.ocf_discovery import (
        discover_ocf_secure_ports,
    )
except ImportError:
    sys.exit(
        "This needs smartthings-local from PR #129. Install it with the pip "
        "line at the top of this script."
    )

# The hard ceiling on DTLS handshakes for the whole run: two per appliance,
# two appliances. --max-handshakes can lower it, never raise it.
HANDSHAKE_CEILING = 4
# The minimum quiet time before a handshake, whatever the flags say. It
# counts from the end of the last handshake, or from when the appliance
# answered plaintext again if that was later, so a drop-off cannot eat into
# it. Recovery from an abandoned handshake on these appliances is measured in
# minutes, so this is a floor, not a tuning knob.
MIN_GAP_S = 60.0
# Short on purpose. The engine retransmits a flight after 1 s, then 2 s, then
# 4 s, and each repeat of the cookie ClientHello asks the appliance for its
# whole flight again. If the appliance ignores the fragment length, that
# flight is the one that takes it off the network, so 15 s would trigger the
# drop up to four times (#20, issuecomment-5950814708). 3 s allows one repeat.
# Measured handshakes with a fragment length took 0.6 to 1.3 s on a dryer
# and an oven here (the longest, 1.23 s, from this script on 2026-11-14).
HANDSHAKE_TIMEOUT_S = 3.0
# How long to wait for the plaintext directory after an arm. On #20 the
# drop-off lasted 9.2 to 10.5 s in the first capture, and 22.8 and 26.2 s in
# the MTU matrix run (issuecomment-6401470854).
LIVENESS_BUDGET_S = 60.0
# Outside Linux's default ephemeral range (32768-60999), so no other process
# holds it, and away from 26900, which the #20 MTU matrix script used.
DEFAULT_LOCAL_PORT = 26960

# Per large read. /device/0 on a dryer took 2.2 s in 512-byte blocks; an oven
# here returns about 13 KB, so 30 s leaves room for 64-byte-block pacing too.
LARGE_READ_TIMEOUT_S = 30.0
MAX_PATHS = 6


def _path(text):
    """Parse one --path into segments. GET only: no query, no /oic/sec."""
    if not text.startswith("/") or "?" in text or "#" in text:
        raise argparse.ArgumentTypeError(
            "a path starts with / and carries no query")
    segments = text.strip("/").split("/")
    if not all(segments):
        raise argparse.ArgumentTypeError("a path has no empty segment")
    if segments[:2] == ["oic", "sec"]:
        raise argparse.ArgumentTypeError("this script reads nothing under "
                                         "/oic/sec")
    return segments

_ALERT_NAMES = {
    10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    110: "unsupported_extension",
}
_PEER_ALERT = re.compile(r"peer sent fatal alert (\d+)")
# The words of the engine's own refusal reasons at b40b720 (_dtls_cert.py and
# _dtls_base.py), such as "server offered unexpected curve 0x0017" or
# "malformed ServerHello". A reason is printed only if every word is one of
# these. An allowlist, not a blocklist, so an IPv6 address, a dotted
# hostname or a serial cannot pass by being a shape nobody thought to block.
# A single-label hostname such as "oven-kitchen" has the shape of a plain
# word and would pass; no engine reason carries outside text, so none can
# contain one.
_PROTOCOL_WORDS = frozenset({
    "DTLS", "1.2", "ECDH", "secp256r1", "Certificate", "CertificateRequest",
    "ServerHello", "ServerKeyExchange", "ServerHelloDone", "HelloVerifyRequest",
    "Finished",
})
_SAFE_WORD = re.compile(
    r"[a-z]+(-[a-z]+)*"            # plain words
    r"|0x[0-9a-f]{1,4}"            # a curve or ciphersuite code
    r"|\(\d{1,3},\d{1,3}\)"        # a signature algorithm pair, as "(4,1)"
    r"|[A-Z][A-Za-z0-9]{0,39}Error"  # an exception class name
)


def _is_safe_reason(reason):
    words = reason.split()
    return 0 < len(words) <= 20 and all(
        word in _PROTOCOL_WORDS or _SAFE_WORD.fullmatch(word)
        for word in (w.rstrip(",:") for w in words))


class _HandshakeReasons(logging.Handler):
    """Keep the reason the session logs when a handshake fails.

    `DtlsCoapSession` raises a redacted `SessionError` by contract and logs
    the TLS-layer reason instead, so the log is where the alert is.
    """

    def __init__(self):
        super().__init__(logging.WARNING)
        self.reasons = []

    def emit(self, record):
        message = record.getMessage()
        prefix = "dtls handshake failed at the TLS layer: "
        if message.startswith(prefix):
            self.reasons.append(message[len(prefix):])


def _describe_reason(reason):
    """Name a peer alert, or pass a reason through only if it is plainly safe."""
    match = _PEER_ALERT.search(reason)
    if match:
        number = int(match.group(1))
        name = _ALERT_NAMES.get(number, "unlisted")
        return f"the appliance sent fatal alert {number} ({name})"
    if _is_safe_reason(reason):
        return f"refused locally: {reason}"
    return "refused; the reason was withheld because it may identify something"


class _Run:
    def __init__(self, args, reasons):
        self.args = args
        self.reasons = reasons
        self.handshakes = 0
        self.quiet_since = None
        self.host = None

    def _wait_for_gap(self):
        if self.quiet_since is None:
            return
        remaining = MIN_GAP_S - (time.monotonic() - self.quiet_since)
        if remaining > 0:
            print(f"  waiting {remaining:.0f} s before the next handshake")
            time.sleep(remaining)

    def reads(self):
        """/oic/d first, then each --path, as (segments, timeout)."""
        return [(["oic", "d"], 10.0)] + [
            (path, LARGE_READ_TIMEOUT_S) for path in self.args.paths]

    def secure_port(self, host):
        """Return (port or None, seconds until the directory answered).

        The seconds are None only when the directory never answered. An
        answer that lists no usable port still counts as an answer, because
        this is also the check for whether the appliance left the network.
        """
        started = time.monotonic()
        while time.monotonic() - started < LIVENESS_BUDGET_S:
            result = discover_ocf_secure_ports(host, timeout=3.0, retries=0)
            if result.response_received:
                elapsed = time.monotonic() - started
                if not result.found:
                    print("    the directory answered but lists no secure "
                          "port")
                    return None, elapsed
                if len(result.ports) != 1:
                    print(f"    the directory lists {len(result.ports)} secure "
                          "ports; refusing to guess which one")
                    return None, elapsed
                return result.ports[0], elapsed
            time.sleep(2.0)
        return None, None

    def arm(self, name, host, port, fragment_length, reads):
        """Run one session. Return True if its handshake completed.

        `reads` is a sequence of (path, timeout), read in order.
        """
        if self.handshakes >= self.args.max_handshakes:
            print(f"  {name}: skipped, the handshake ceiling "
                  f"({self.args.max_handshakes}) is reached")
            return False
        print()
        self._wait_for_gap()
        print(f"  {name}: max_fragment_length {fragment_length}")
        auth = FragmentingCertificateAuth.from_files(
            self.args.cert, self.args.key,
            max_fragment_length=fragment_length,
        )
        session = DtlsCoapSession(
            host, port, auth=auth, local_port=self.args.local_port)
        del self.reasons[:]
        self.handshakes += 1
        started = time.monotonic()
        try:
            session.connect(timeout=HANDSHAKE_TIMEOUT_S)
        except PeerInitiatedHandshakeError:
            print("    handshake refused: the appliance was opening its own "
                  "handshake toward this port. Not retried.")
            return False
        except SessionTimeoutError:
            print(f"    handshake: not completed within "
                  f"{HANDSHAKE_TIMEOUT_S:.0f} s. One attempt is not "
                  "conclusive; the plaintext check below says whether the "
                  "appliance left the network.")
            return False
        except EndpointError:
            print("    handshake: the local socket failed (is --local-port "
                  "in use?)")
            return False
        except SessionError:
            reason = self.reasons[-1] if self.reasons else "no reason logged"
            print(f"    handshake failed: {_describe_reason(reason)}")
            return False
        finally:
            self.quiet_since = time.monotonic()
        elapsed_ms = (self.quiet_since - started) * 1000
        in_force = session.negotiated_fragment_length
        print(f"    handshake completed in {elapsed_ms:.0f} ms, "
              f"fragment length in force: {in_force}")
        try:
            session.start_reader()
            for path, read_timeout in reads:
                self._read(session, path, read_timeout)
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001 -- the class only, never the text
                print("    close raised; the appliance may still hold this "
                      "session")
            self.quiet_since = time.monotonic()
        return True

    @staticmethod
    def _read(session, path, read_timeout):
        label = "GET /" + "/".join(path)
        started = time.monotonic()
        try:
            code, payload = session.get(path, timeout=read_timeout)
        except FragmentLimitTimeoutError as exc:
            print(f"    {label}: FragmentLimitTimeoutError, the first block "
                  f"never arrived (length {exc.fragment_length})")
            return
        except Exception as exc:  # noqa: BLE001 -- the class only
            elapsed = time.monotonic() - started
            print(f"    {label}: {type(exc).__name__} after {elapsed:.1f} s")
            return
        elapsed_ms = (time.monotonic() - started) * 1000
        print(f"    {label}: {code >> 5}.{code & 31:02d}, "
              f"{len(payload or b'')} bytes in {elapsed_ms:.0f} ms")

    def liveness(self):
        """Report whether the appliance still answers plaintext CoAP."""
        port, elapsed = self.secure_port(self.host)
        if elapsed is not None:
            # The quiet time before the next handshake starts now.
            self.quiet_since = time.monotonic()
        if elapsed is None:
            print(f"    plaintext CoAP: no answer within "
                  f"{LIVENESS_BUDGET_S:.0f} s")
        else:
            print(f"    plaintext CoAP answered after {elapsed:.1f} s")
        return port

    def appliance(self, label, host):
        self.host = host
        print(f"\n{label} (<host>)")
        port, elapsed = self.secure_port(host)
        if port is None:
            if elapsed is None:
                print("  the plaintext directory did not answer; skipping")
            return
        print("  secure port discovered from the plaintext directory")
        completed = self.arm("arm 1", host, port, 1024, self.reads())
        port = self.liveness()
        if not completed:
            print("  arm 2: skipped, arm 1's handshake did not complete")
            return
        if port is None:
            print("  arm 2: skipped, no secure port after arm 1")
            return
        # /oic/d first: a session can stop answering after a large read
        # times out, so the small read must not come after it.
        self.arm("arm 2", host, port, 512, self.reads())
        self.liveness()


def _confirm():
    print(
        "Before you start: disable your integration for these appliances.\n"
        "If a handshake times out, the appliance can refuse new handshakes\n"
        "from this script's local port for more than 10 minutes. Wait at\n"
        "least 15 minutes before a second run, or pass a different\n"
        "--local-port. With two appliances the run takes about 4 minutes,\n"
        "or 6 minutes or more if the appliances drop off the network.\n"
    )
    try:
        input("Press Enter to start, or Ctrl-C to stop. ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("hosts", nargs="+", metavar="host",
                    help="one or two appliance addresses")
    ap.add_argument("--cert", required=True,
                    help="client certificate chain from setup_cert.py")
    ap.add_argument("--key", required=True,
                    help="client private key from setup_cert.py")
    ap.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT,
                    help="source port held for every handshake "
                         f"(default {DEFAULT_LOCAL_PORT})")
    ap.add_argument("--max-handshakes", type=int, default=HANDSHAKE_CEILING,
                    help=f"at most {HANDSHAKE_CEILING}, the default")
    ap.add_argument("--path", dest="paths", action="append", type=_path,
                    metavar="PATH",
                    help="a resource to GET after /oic/d, once per resource "
                         f"(at most {MAX_PATHS}; default /device/0)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the prompt before the run starts")
    args = ap.parse_args(argv)
    if len(args.hosts) > 2:
        ap.error("pass one or two appliances")
    if args.paths is None:
        args.paths = [["device", "0"]]
    if len(args.paths) > MAX_PATHS:
        ap.error(f"pass at most {MAX_PATHS} --path values")
    if not 1 <= args.max_handshakes <= HANDSHAKE_CEILING:
        ap.error(f"--max-handshakes must be 1 to {HANDSHAKE_CEILING}")
    if not 1024 <= args.local_port <= 65535:
        ap.error("--local-port must be 1024 to 65535")
    # Fail on a bad credential here, before anything goes on the wire. The
    # provider reads its files lazily, at the first connect, so load them
    # once now with the same loader the engine uses.
    try:
        FragmentingCertificateAuth.from_files(
            args.cert, args.key)._load_client_credential()
    except Exception as exc:  # noqa: BLE001 -- the class only, never the text
        ap.error(f"cannot use --cert/--key ({type(exc).__name__})")

    # Library loggers go nowhere except the handler that keeps the reason;
    # Python's last-resort handler would otherwise print their raw text.
    logging.getLogger("smartthings_local").addHandler(logging.NullHandler())
    reasons = _HandshakeReasons()
    logging.getLogger("smartthings_local.protocol.dtls_session").addHandler(
        reasons)

    if not args.yes:
        _confirm()
    try:
        installed = version("smartthings-local")
    except PackageNotFoundError:
        installed = "unknown"
    print(f"smartthings-local {installed}, Python "
          f"{sys.version_info.major}.{sys.version_info.minor}, "
          f"handshake ceiling {args.max_handshakes}, fixed local port")
    run = _Run(args, reasons.reasons)
    status = 0
    try:
        for number, host in enumerate(args.hosts, start=1):
            run.appliance(f"appliance {number}", host)
    except KeyboardInterrupt:
        print("\nstopped by Ctrl-C")
        status = 130
    except Exception as exc:  # noqa: BLE001 -- the class only, never the text
        print(f"\nstopped by {type(exc).__name__}")
        status = 1
    # Every exit after the prompt reminds the user, because the prompt told
    # them to disable their integration.
    print(f"\nhandshakes used: {run.handshakes} of {args.max_handshakes}")
    print("Re-enable your integration now.")
    return status


if __name__ == "__main__":
    # A traceback prints file paths and the exception's text, so anything
    # that escapes main() is reported by its class only. That includes a
    # Ctrl-C outside the windows main() handles itself.
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("stopped by Ctrl-C", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 -- the class only, never the text
        print(f"stopped by {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
