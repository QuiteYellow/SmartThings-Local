#!/usr/bin/env python3
"""Drive a PSK credential through DtlsCoapSession, twice, and report.

Written for https://github.com/QuiteYellow/SmartThings-Local/pull/121, which
wires PskAuth to the library's own DTLS 1.2 ECDHE-PSK engine. The engine
itself was already tested against hardware through a standalone probe
(pr-115-purepy-psk/oven_psk_test.py). What is untested is the engine reached
through the library: the connection seam, the shared handshake driver, the
fixed local source port, CoAP correlation and close().

Unlike that earlier probe this imports nothing of its own. It uses the
installed smartthings-local, so what it exercises is the shipped path.

What it does, and nothing else:

1. one DTLS 1.2 ECDHE-PSK session, with the identity sent at an explicit
   length so a zero byte inside it survives
2. one CoAP GET of /oic/d over that session
3. a clean close(), which sends close_notify
4. the same three again on the same local port, to see whether a second
   session succeeds once the first released the appliance's peer entry

It never writes to the appliance, never reads or writes a security resource,
and never retries beyond the DTLS flight retransmissions the library owns.

STOP YOUR INTEGRATION FIRST. Measured on the maintainer's appliances: a
second DTLS client to one device gets silence rather than an error, so a
session held by Home Assistant makes a healthy appliance look dead here.

Install into a throwaway environment, never your Home Assistant one:

    uv venv /tmp/psk-test --python 3.13
    uv pip install --python /tmp/psk-test/bin/python \
      "git+https://github.com/QuiteYellow/SmartThings-Local.git@feat/psk-engine-wiring"

Then:

    export PSK_HOST=192.0.2.100
    export PSK_PORT=49154
    export PSK_IDENTITY=<32 hex chars, the raw 16-byte owner UUID>
    export PSK_KEY=<32 or 64 hex chars>
    /tmp/psk-test/bin/python psk_session_check.py

Add --debug for the library's own DEBUG logging, which is the most useful
thing to paste back if a step fails.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time

try:
    from smartthings_local._version import version
    from smartthings_local.protocol.auth import PskAuth
    from smartthings_local.protocol.dtls_session import DtlsCoapSession
except ImportError as exc:
    sys.exit(f"smartthings-local is not installed in this interpreter: {exc}")

LOCAL_PORT = 51234
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _scrub(text: str, host: str) -> str:
    """Remove your address from anything this prints.

    The output of this script is meant to be pasteable into a public thread,
    so it must not carry your network details. The library logs the host it
    is talking to in its reader loop (dtls_session.py, "reader exiting:
    socket error ... from ..."), and a stray OSError can carry it too, so
    both the host as you gave it and any bare IPv4 literal are replaced.
    """
    if host:
        text = text.replace(host, "<host>")
    return _IPV4.sub("<ip>", text)


class _ScrubbingFilter(logging.Filter):
    """Apply _scrub to formatted log records before they are emitted."""

    def __init__(self, host: str) -> None:
        super().__init__()
        self.host = host

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _scrub(record.getMessage(), self.host)
            record.args = ()
        except Exception:
            record.msg = "<log line suppressed: could not be scrubbed>"
            record.args = ()
        return True


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"{name} is not set; see the docstring at the top of this file")
    return value


def _hexbytes(name: str, lengths: tuple[int, ...]) -> bytes:
    try:
        value = bytes.fromhex(_env(name).strip())
    except ValueError:
        sys.exit(f"{name} must be hex")
    if len(value) not in lengths:
        sys.exit(f"{name} must decode to {' or '.join(map(str, lengths))} "
                 f"bytes, got {len(value)}")
    return value


def _attempt(label: str, host: str, port: int, auth: PskAuth) -> bool:
    """One session: connect, read /oic/d, close. True if all three worked."""
    print(f"\n--- {label} ---")
    session = DtlsCoapSession(host, port, auth=auth, local_port=LOCAL_PORT)
    started = time.monotonic()
    try:
        session.connect()
    except Exception as exc:
        print(f"connect failed after {time.monotonic() - started:.1f}s: "
              f"{type(exc).__name__}: {_scrub(str(exc), host)}")
        return False
    print(f"handshake completed in {time.monotonic() - started:.1f}s")

    ok = False
    try:
        # Without start_reader() the handshake completes and every GET times
        # out, which looks exactly like a dead device.
        session.start_reader()
        code, payload = session.get(["oic", "d"], timeout=10.0)
        # 0x45 is 2.05 Content. The length is the useful part: /oic/d carries
        # your device UUID, so printing the payload would put it in a public
        # paste. Decode it yourself if you want to check the id matches.
        print(f"GET /oic/d -> code 0x{code:02x}, {len(payload)} bytes of CBOR")
        ok = code == 0x45
    except Exception as exc:
        print(f"GET failed: {type(exc).__name__}: {_scrub(str(exc), host)}")
    finally:
        try:
            session.close()
            print("closed, close_notify sent")
        except Exception as exc:
            print(f"close failed: {type(exc).__name__}: {_scrub(str(exc), host)}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug", action="store_true",
                        help="turn on the library's DEBUG logging")
    args = parser.parse_args()
    host = _env("PSK_HOST")
    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s %(name)s %(message)s")
        logging.getLogger("smartthings_local").setLevel(logging.DEBUG)
        scrubber = _ScrubbingFilter(host)
        for handler in logging.getLogger().handlers:
            handler.addFilter(scrubber)
    try:
        port = int(_env("PSK_PORT"))
    except ValueError:
        return int(bool(sys.exit("PSK_PORT must be an integer")))
    identity = _hexbytes("PSK_IDENTITY", (16,))
    key = _hexbytes("PSK_KEY", (16, 32))

    print(f"smartthings-local {version}")
    zero = b"\x00" in identity
    print(f"identity is {len(identity)} bytes and "
          f"{'contains' if zero else 'does not contain'} a zero byte")

    try:
        auth = PskAuth(identity=identity, key=key)
    except (TypeError, ValueError) as exc:
        return int(bool(sys.exit(f"PskAuth refused the credential: {exc}")))

    first = _attempt("first session", host, port, auth)
    second = _attempt("second session, same local port", host, port, auth)

    print("\n--- summary ---")
    print(f"first session read /oic/d:  {'yes' if first else 'no'}")
    print(f"second session read /oic/d: {'yes' if second else 'no'}")
    if first and not second:
        print("A first session that works and a second that does not is the\n"
              "interesting outcome: it would point at the appliance keeping a\n"
              "peer entry across our close. Please say so on the PR.")
    return 0 if first else 1


if __name__ == "__main__":
    raise SystemExit(main())
