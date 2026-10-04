#!/usr/bin/env python3
"""Cycle slowly through DTLS handshake variants against one appliance.

Issue #20's washer stops answering the network after it accepts the client's
cookie and before the first byte of its own flight. The variants below each
change one thing the ClientHello controls at that step, so a run says which
of them -- if any -- the appliance cares about.

**What it sends.** One DTLS handshake per variant, to the appliance's secure
port, using your own client certificate. No CoAP request is made and nothing
is written to the appliance: the handshake completes or fails and the session
is then closed. Between handshakes it sends four ICMP echo requests and reads
the plaintext OCF directory on 5683.

**What it reports.** Per run: the outcome, the round-trip time, any alert, the
server's handshake flight, which extensions the server echoed, which curve it
chose, how many ClientHellos were sent, and how many bytes of close_notify
were sent. The output names the port but not your address.

**Requires** a checkout of this repository to import ``smartthings_local``
from; run it from the checkout root, as you would ``python3 -m
smartthings_local.protocol.dtls_probe``.

Two properties matter more than the variants:

* **Clean close.** The appliance firmware frees a peer when it receives
  close_notify and has no idle timeout to reclaim one otherwise, so an
  abandoned peer stays abandoned. ``diagnose_dtls_handshake`` closes the
  socket without a shutdown (``dtls_probe.py``), which is how six runs in six
  minutes took a healthy dryer's DTLS endpoint down on 2026-10-04 while
  leaving its ICMP and plaintext CoAP answering normally. This script sends
  close_notify itself and counts the bytes.
* **A health gate between runs.** Ping plus a plaintext directory read before
  each handshake, so a degrading appliance is never handed another one.

Stage 1 proves, against a local UDP sink, that each variant's ClientHello
really differs as intended. It touches no hardware, and a failure there stops
the run: a variant that did not apply would otherwise look like a device
result.

Usage:
  handshake_matrix.py HOST [--port N] [--cert PATH --key PATH]
                      [--interval S] [--repeats N] [--variants a,b,...]
                      [--no-clean-close] [--no-health-gate] [--list]

Credentials default to $CERT_PATH / $KEY_PATH. Nothing is written to disk and
no host or credential is recorded in this file.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter

from OpenSSL import SSL

import smartthings_local.protocol.dtls_probe as probe
from smartthings_local.protocol.coap import split_dtls
from smartthings_local.protocol.ocf_discovery import discover_ocf_secure_ports

_MAX_DATAGRAM = 65535

# Verified empirically on OpenSSL 4.0.0 and 4.0.2 rather than cited: each bit
# is confirmed to remove its extension in stage 1 before any run proceeds.
OP_NO_TICKET = SSL.OP_NO_TICKET
OP_NO_ENCRYPT_THEN_MAC = 0x00080000
OP_NO_EXTENDED_MASTER_SECRET = 0x00000001
STRIP_EXTENSIONS = (
    OP_NO_TICKET | OP_NO_ENCRYPT_THEN_MAC | OP_NO_EXTENDED_MASTER_SECRET)

EXT_NAMES = {
    0: 'server_name', 10: 'supported_groups', 11: 'ec_point_formats',
    13: 'signature_algorithms', 22: 'encrypt_then_mac',
    23: 'extended_master_secret', 35: 'session_ticket',
    65281: 'renegotiation_info',
}
GROUP_NAMES = {
    23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1',
    29: 'x25519', 30: 'x448',
}

# Each variant changes exactly one thing, so a difference in outcome has one
# candidate cause. 'baseline' is what the library sends today.
VARIANTS = {
    'baseline': {
        'options': 0, 'curves': None,
        'why': 'what the library sends today -- the control',
    },
    'p256': {
        'options': 0, 'curves': b'P-256',
        'why': 'the ClientHello leads supported_groups with x25519, and a '
               'server generates its ECDHE key at the step where the '
               'washer stops answering',
    },
    'noext': {
        'options': STRIP_EXTENSIONS, 'curves': None,
        'why': 'drops session_ticket, encrypt_then_mac and '
               'extended_master_secret, which are negotiated in ServerHello',
    },
    'p256+noext': {
        'options': STRIP_EXTENSIONS, 'curves': b'P-256',
        'why': 'both at once, to catch a pair that only matters together',
    },
}


# --------------------------------------------------------------------------
# Context shaping
# --------------------------------------------------------------------------

def _apply(ctx, variant):
    spec = VARIANTS[variant]
    if spec['options']:
        ctx.set_options(spec['options'])
    if spec['curves'] is not None:
        if SSL._lib.SSL_CTX_set1_curves_list(ctx._context, spec['curves']) != 1:
            raise RuntimeError(f'could not restrict curves for {variant!r}')
    return ctx


_orig_context = probe._diagnostic_context
_orig_drive = probe._drive_dtls_handshake
_state = {'variant': 'baseline', 'clean_close': True}


def _patched_context(**kw):
    return _apply(_orig_context(**kw), _state['variant'])


def _patched_drive(connection, sock, **kw):
    """Drive the handshake, then close_notify before the socket goes away.

    The connection is a memory BIO, so OpenSSL's close_notify has to be pulled
    out and sent here; ``conn.shutdown()`` alone only queues it.
    """
    sent = Counter()

    def on_record_sent(record):
        # Record layer: type 22 is Handshake, and byte 13 is the handshake
        # message type once the record header is past.
        if record and record[0] == 22 and len(record) > 13:
            sent[record[13]] += 1

    kw['on_record_sent'] = on_record_sent
    completed = _orig_drive(connection, sock, **kw)
    _state['client_hellos'] = sent[1]
    _state['close_bytes'] = 0
    if completed and _state['clean_close']:
        try:
            connection.shutdown()
        except Exception:
            pass
        try:
            out = connection.bio_read(_MAX_DATAGRAM)
        except Exception:
            out = b''
        for record in split_dtls(out or b''):
            try:
                sock.send(record)
                _state['close_bytes'] += len(record)
            except OSError:
                break
    return completed


probe._diagnostic_context = _patched_context
probe._drive_dtls_handshake = _patched_drive


# --------------------------------------------------------------------------
# Stage 1: prove each variant differs, with no hardware involved
# --------------------------------------------------------------------------

def _parse_client_hello(buf):
    """Return (cipher suites, extension ids, supported groups) or None."""
    if len(buf) < 13 or buf[0] != 22:
        return None
    body = buf[13:13 + struct.unpack('>H', buf[11:13])[0]]
    if not body or body[0] != 1:
        return None
    msg = body[12:12 + int.from_bytes(body[9:12], 'big')]
    o = 2 + 32
    o += 1 + msg[o]                      # session id
    o += 1 + msg[o]                      # cookie
    csl = struct.unpack('>H', msg[o:o + 2])[0]
    suites = [struct.unpack('>H', msg[o + 2 + i:o + 4 + i])[0]
              for i in range(0, csl, 2)]
    o += 2 + csl
    o += 1 + msg[o]                      # compression
    exts, groups = [], []
    if o + 2 <= len(msg):
        end = o + 2 + struct.unpack('>H', msg[o:o + 2])[0]
        o += 2
        while o + 4 <= end:
            eid, elen = struct.unpack('>HH', msg[o:o + 4])
            val = msg[o + 4:o + 4 + elen]
            exts.append(eid)
            if eid == 10 and len(val) >= 2:
                n = struct.unpack('>H', val[0:2])[0]
                groups = [struct.unpack('>H', val[2 + i:4 + i])[0]
                          for i in range(0, n, 2)]
            o += 4 + elen
    return suites, exts, groups


def _local_client_hello(variant, cert, key):
    """Capture one ClientHello this variant emits, against a local sink."""
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(('127.0.0.1', 0))
    port = sink.getsockname()[1]
    got = {}

    def recv():
        sink.settimeout(2.0)
        try:
            got['buf'] = sink.recvfrom(4096)[0]
        except Exception:
            pass

    th = threading.Thread(target=recv)
    th.start()
    ctx = SSL.Context(SSL.DTLS_METHOD)
    ctx.set_cipher_list(probe._DTLS_CIPHERS)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
    ctx.use_certificate_chain_file(cert)
    ctx.use_privatekey_file(key)
    _apply(ctx, variant)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('127.0.0.1', port))
    sock.setblocking(False)
    conn = SSL.Connection(ctx, sock)
    conn.set_connect_state()
    try:
        conn.do_handshake()
    except Exception:
        pass
    th.join()
    sock.close()
    sink.close()
    if 'buf' not in got:
        return None
    return _parse_client_hello(got['buf'])


def self_check(variants, cert, key):
    print('STAGE 1 -- does each variant change what is sent? (no hardware)')
    baseline = _local_client_hello('baseline', cert, key)
    if baseline is None:
        print('  could not capture the ClientHello -- stopping')
        return False
    b_exts, b_groups = set(baseline[1]), baseline[2]
    print(f'  baseline extensions : '
          f'{[EXT_NAMES.get(e, e) for e in baseline[1]]}')
    print(f'  baseline groups     : '
          f'{[GROUP_NAMES.get(g, g) for g in b_groups]}')
    ok = True
    for name in variants:
        got = _local_client_hello(name, cert, key)
        if got is None:
            print(f'  {name:11}: FAILED to capture')
            ok = False
            continue
        exts, groups = set(got[1]), got[2]
        removed = sorted(b_exts - exts)
        spec = VARIANTS[name]
        want_ext = {35, 22, 23} if spec['options'] else set()
        want_grp = [23] if spec['curves'] else b_groups
        good = set(removed) == want_ext and groups == want_grp
        ok = ok and good
        print(f'  {name:11}: removed={[EXT_NAMES.get(e, e) for e in removed]} '
              f'groups={[GROUP_NAMES.get(g, g) for g in groups]} '
              f'-> {"applied" if good else "DID NOT APPLY"}')
    print(f'  all variants applied: {ok}')
    if not ok:
        print('  stopping: a variant that did not apply would read as a '
              'device result')
    print()
    return ok


# --------------------------------------------------------------------------
# Health gate
# --------------------------------------------------------------------------

def icmp_ok(host, count=4):
    try:
        out = subprocess.run(
            ['ping', '-c', str(count), '-W', '2', host],
            capture_output=True, text=True, timeout=count * 3 + 5)
    except FileNotFoundError:
        # Slim containers ship no ping. The plaintext read below is the gate
        # that actually decides whether to proceed, so say so and carry on.
        return 'unavailable (no ping binary)'
    except Exception as exc:
        return f'unavailable ({type(exc).__name__})'
    for field in out.stdout.split(','):
        if 'packet loss' in field:
            # macOS puts the round-trip line straight after this field with no
            # comma between them, so keep only the first line.
            return field.strip().splitlines()[0].strip()
    return 'no statistics line'


def plaintext_ok(host):
    try:
        r = discover_ocf_secure_ports(host, timeout=4.0)
    except Exception as exc:
        return False, repr(exc)
    return bool(getattr(r, 'response_received', False)), repr(r)


# --------------------------------------------------------------------------
# Hardware runs
# --------------------------------------------------------------------------

def server_flight_detail(datagrams):
    """ServerHello extensions and the ServerKeyExchange named curve."""
    sh_exts, curves = None, []
    for d in datagrams:
        o = 0
        while o + 13 <= len(d):
            ct = d[o]
            ln = struct.unpack('>H', d[o + 11:o + 13])[0]
            body = d[o + 13:o + 13 + ln]
            o += 13 + ln
            if ct != 22 or len(body) < 12:
                continue
            if int.from_bytes(body[6:9], 'big'):
                continue             # a fragment continuation
            msg = body[12:]
            if body[0] == 2 and sh_exts is None:        # ServerHello
                p = 2 + 32
                p += 1 + msg[p]
                p += 2 + 1
                exts = []
                if p + 2 <= len(msg):
                    end = p + 2 + struct.unpack('>H', msg[p:p + 2])[0]
                    p += 2
                    while p + 4 <= end:
                        eid, elen = struct.unpack('>HH', msg[p:p + 4])
                        exts.append(eid)
                        p += 4 + elen
                sh_exts = exts
            elif body[0] == 12 and len(msg) >= 3 and msg[0] == 3:
                curves.append(struct.unpack('>H', msg[1:3])[0])
    return sh_exts, curves


def run_one(host, port, variant, cert, key, timeout):
    _state['variant'] = variant
    _state['client_hellos'] = 0
    _state['close_bytes'] = 0
    started = time.time()
    result = probe.diagnose_dtls_handshake(
        host, port, cert_path=cert, key_path=key, timeout=timeout, retries=2)
    sh_exts, curves = server_flight_detail(result.datagrams)
    return {
        'variant': variant,
        'at': time.strftime('%H:%M:%S', time.localtime(started)),
        'outcome': result.outcome,
        'rtt_ms': None if result.rtt_s is None else round(result.rtt_s * 1000),
        'alert': result.alert,
        'flight': result.handshake_msgs,
        'server_hello_exts': sh_exts,
        'curve': [GROUP_NAMES.get(c, c) for c in curves],
        'client_hellos_sent': _state['client_hellos'],
        'close_notify_bytes': _state['close_bytes'],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('host', nargs='?')
    ap.add_argument('--port', type=int)
    ap.add_argument('--cert', default=os.environ.get('CERT_PATH'))
    ap.add_argument('--key', default=os.environ.get('KEY_PATH'))
    ap.add_argument('--interval', type=float, default=60.0,
                    help='seconds between handshakes (default 60)')
    ap.add_argument('--repeats', type=int, default=1,
                    help='passes through the variant list (default 1)')
    ap.add_argument('--variants', default=','.join(VARIANTS),
                    help='comma-separated subset, in order')
    ap.add_argument('--timeout', type=float, default=6.0)
    ap.add_argument('--no-clean-close', action='store_true',
                    help='skip close_notify -- leaves a peer behind per run')
    ap.add_argument('--no-health-gate', action='store_true')
    ap.add_argument('--list', action='store_true',
                    help='describe the variants and exit')
    args = ap.parse_args(argv)

    if args.list:
        for name, spec in VARIANTS.items():
            print(f'{name:11} {spec["why"]}')
        return 0
    if not args.host:
        ap.error('HOST is required')
    if not args.cert or not args.key:
        ap.error('--cert/--key, or $CERT_PATH/$KEY_PATH, are required')

    chosen = [v.strip() for v in args.variants.split(',') if v.strip()]
    unknown = [v for v in chosen if v not in VARIANTS]
    if unknown:
        ap.error(f'unknown variants: {unknown}; try --list')

    _state['clean_close'] = not args.no_clean_close
    print(f'OpenSSL: {SSL.OpenSSL_version(SSL.SSLEAY_VERSION).decode()}')
    print(f'cipher list: {probe._DTLS_CIPHERS.decode()}')
    print(f'clean close: {_state["clean_close"]}   '
          f'health gate: {not args.no_health_gate}   '
          f'interval: {args.interval}s\n')

    if not self_check(chosen, args.cert, args.key):
        return 1

    port = args.port
    if port is None:
        found, detail = plaintext_ok(args.host)
        print(f'discovery: {detail}')
        if not found:
            print('no secure port discovered -- pass --port')
            return 1
        r = discover_ocf_secure_ports(args.host, timeout=4.0)
        port = getattr(r, 'port', None) or (getattr(r, 'ports', None) or [None])[0]
        if not port:
            print('discovery answered but named no port -- pass --port')
            return 1
    # The address is yours and the port is the part that matters to a reader,
    # so the output names the port only and leaves the host out.
    print(f'target: <host>:{port}\n')

    schedule = [v for _ in range(args.repeats) for v in chosen]
    rows = []
    print(f'STAGE 2 -- {len(schedule)} handshakes, one every {args.interval}s '
          f'(about {len(schedule) * args.interval / 60:.0f} min)\n')
    try:
        for i, variant in enumerate(schedule, 1):
            if not args.no_health_gate:
                loss = icmp_ok(args.host)
                alive, _ = plaintext_ok(args.host)
                print(f'[{i}/{len(schedule)}] health: ping {loss}, '
                      f'plaintext {"ok" if alive else "SILENT"}')
                if not alive:
                    print('         appliance is not answering plaintext -- '
                          'not sending another handshake')
                    rows.append({'variant': variant, 'outcome': 'skipped',
                                 'at': time.strftime('%H:%M:%S'),
                                 'rtt_ms': None, 'alert': None, 'flight': [],
                                 'server_hello_exts': None, 'curve': [],
                                 'client_hellos_sent': 0,
                                 'close_notify_bytes': 0})
                    time.sleep(args.interval)
                    continue
            row = run_one(args.host, port, variant, args.cert, args.key,
                          args.timeout)
            rows.append(row)
            print(f'         {variant:11} {row["outcome"]:9} '
                  f'rtt={row["rtt_ms"]}ms curve={row["curve"]} '
                  f'alert={row["alert"]}')
            print(f'         {"":11} ClientHellos_sent={row["client_hellos_sent"]} '
                  f'close_notify={row["close_notify_bytes"]}B '
                  f'server_hello_exts='
                  f'{[EXT_NAMES.get(e, e) for e in (row["server_hello_exts"] or [])]}')
            print(f'         {"":11} flight={row["flight"]}')
            if i < len(schedule):
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print('\ninterrupted -- the table below covers the runs that finished')

    print('\nSUMMARY')
    print(f'{"time":9} {"variant":11} {"outcome":10} {"rtt":>6} '
          f'{"CH":>3} {"close":>6} curve')
    for r in rows:
        print(f'{r["at"]:9} {r["variant"]:11} {r["outcome"]:10} '
              f'{str(r["rtt_ms"]):>6} {r["client_hellos_sent"]:>3} '
              f'{r["close_notify_bytes"]:>5}B {",".join(r["curve"])}')
    done = [r for r in rows if r['outcome'] != 'skipped']
    print(f'\n{len(done)} of {len(rows)} runs reached the appliance.')
    print('CH counts the ClientHellos sent: 2 is a clean run, 3 means the '
          'handshake went over a peer the appliance had not freed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
