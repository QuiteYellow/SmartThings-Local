#!/usr/bin/env python3
"""mtu_matrix.py -- does an over-MTU datagram explain this appliance's drop-off?

For a Samsung appliance that answers a DTLS ClientHello with a
HelloVerifyRequest and then leaves the network before sending a byte of its
own flight (QuiteYellow/SmartThings-Local#20, mbillow/localthings#504).

It answers three questions, in order, and stops early if the appliance is
already unreachable:

  Stage 2  Is a fragmented datagram fatal in UDP as well as ICMP, and where
           is the threshold?  A ladder of one-shot CoAP GETs padded to
           1200 / 1472 / 1473 / 1920 payload bytes.  1472 is the last size
           that fits one frame; 1473 is the first that the sending kernel
           splits into two IP fragments.

  Stage 3  Does the appliance honour a max_fragment_length offer?  Two
           ClientHello pairs that differ by one extension.  mbed TLS 2.28
           clamps a server's handshake datagrams to the negotiated MFL and
           fragments its flight at the DTLS layer to fit (ssl_msg.c:191-217
           and :2258-2305).  mbed TLS 2.7.8 parses and echoes the extension
           but applies it only to application data, and never fragments a
           handshake message at all (ssl_tls.c:2987).  So the two firmware
           generations answer this differently, and the answer decides
           whether a client can avoid the appliance's over-MTU flight.

  Both     Does the appliance survive each one?  Liveness is a plain CoAP
           GET /oic/res on the plaintext port, polled until it answers.

Nothing here completes a handshake: no keys, no certificate, no credentials of
any kind, and nothing identifying is read or printed.  The output carries no
address, device UUID, serial or certificate detail, so it is safe to paste
into an issue as it stands.

The ClientHellos are built by hand precisely so the second one can carry an
extension OpenSSL will not send -- pyOpenSSL exposes no
SSL_CTX_set_tlsext_max_fragment_length, and cryptography's bindings do not
either.  Reading the server's flight needs no crypto: datagram sizes and
record headers are enough, and a UDP socket already reports one datagram per
recvfrom, so a flight that arrived over-MTU shows up as one payload larger
than 1472 bytes with no packet capture needed.

Stdlib only, except that an omitted --port is discovered through
smartthings-local if it is installed.  No root.  Run it from a machine on the
appliance's subnet:

    python3 mtu_matrix.py <appliance-ip>

    --port N             the DTLS port.  Omitted, it is discovered: these
                         devices bind their DTLS socket to port 0, so the
                         port moves across a reboot and a fixed default is a
                         trap (see the v0.1.22 notes on setup_cert.py --test)
    --plaintext-port N   where CoAP answers in the clear (default 5683)
    --mfl 512|1024|2048|4096   size to offer in stage 3 (default 512)
    --max-hellos N       hard ceiling on ClientHellos sent (default 6)
    --no-post-check      skip the closing DTLS health check
    --local-port N       source port held across every DTLS attempt, so the
                         firmware evicts one stale peer instead of keeping a
                         new one per arm (default 26900)
    --recover N          seconds to wait for liveness after each probe
    --skip-ladder        stage 3 only
    --skip-mfl           stage 2 only
    --emit-only          print what would be sent and exit (no hardware)
"""

import argparse
import os
import socket
import struct
import sys
import time

# ---------------------------------------------------------------- framing ---

_DTLS_1_2 = b'\xfe\xfd'
_CT_HANDSHAKE = 22
_CT_ALERT = 21
_HT_CLIENT_HELLO = 1
_HS_NAMES = {
    0: 'HelloRequest', 1: 'ClientHello', 2: 'ServerHello',
    3: 'HelloVerifyRequest', 11: 'Certificate', 12: 'ServerKeyExchange',
    13: 'CertificateRequest', 14: 'ServerHelloDone', 15: 'CertificateVerify',
    16: 'ClientKeyExchange', 20: 'Finished',
}
_ALERTS = {0: 'close_notify', 40: 'handshake_failure', 48: 'unknown_ca'}

# The suite the appliance already accepts from this library, so the control
# arm reproduces the known failure rather than inventing a new one.
_SUITE_ECDHE_ECDSA_AES128_GCM = 0xC02B
_MFL_CODES = {512: 1, 1024: 2, 2048: 3, 4096: 4}

# One IP header plus one UDP header. A payload above (1500 - 28) is split.
_IP_UDP_OVERHEAD = 28
_ETH_MTU = 1500
_LADDER = (1200, 1472, 1473, 1920)

# Minimum gap between DTLS attempts, enforced regardless of --settle. The
# measured recovery from a run of abandoned handshakes is minutes, not
# seconds, and on 2026-10-17 a --settle of 8 put two arms ~10s apart and left
# the dryer refusing its bridge for 8.5 minutes.
_MIN_HANDSHAKE_GAP = 30.0

# One source port for every DTLS attempt in a run, so the firmware sees one
# peer re-connecting rather than a new peer per arm. It keys peers on
# (address, port) and evicts the stale one when the 5-tuple repeats, which is
# the v0.1.1 fixed-source-port mechanism. Chosen outside Linux's default
# ephemeral range (32768-60999) so an unrelated process cannot hold it, the
# same reason the bridge's base moved to 26849.
_DEFAULT_LOCAL_PORT = 26900


def _record(content_type, seq, payload):
    """One DTLS record at epoch 0.

    Header is type(1) version(2) epoch(2) sequence_number(6) length(2) = 13
    bytes. The sequence number is a uint48, so it takes all six bytes; an
    earlier draft truncated it to four and shifted every field after it.
    """
    return (bytes([content_type]) + _DTLS_1_2 + struct.pack('>H', 0)
            + seq.to_bytes(6, 'big') + struct.pack('>H', len(payload))
            + payload)


def _handshake(msg_type, msg_seq, body):
    """One unfragmented DTLS handshake message."""
    return (bytes([msg_type]) + len(body).to_bytes(3, 'big')
            + struct.pack('>H', msg_seq)
            + (0).to_bytes(3, 'big') + len(body).to_bytes(3, 'big') + body)


def _extensions(mfl_code=None):
    """The extension set OpenSSL sends for this handshake, plus optional MFL.

    Keeping these identical across both stage-3 arms is what makes the
    comparison mean anything: the arms differ by extension 1 and nothing else.
    """
    out = bytearray()
    out += struct.pack('>HH', 0xFF01, 1) + b'\x00'          # renegotiation_info
    out += struct.pack('>HH', 0x000B, 2) + b'\x01\x00'      # ec_point_formats
    groups = (29, 23, 30, 24, 25)   # x25519, secp256r1, x448, secp384r1, p521
    out += struct.pack('>HHH', 0x000A, 2 + 2 * len(groups), 2 * len(groups))
    for g in groups:
        out += struct.pack('>H', g)
    out += struct.pack('>HH', 0x0023, 0)                    # session_ticket
    out += struct.pack('>HH', 0x0016, 0)                    # encrypt_then_mac
    out += struct.pack('>HH', 0x0017, 0)             # extended_master_secret
    sigalgs = (0x0403, 0x0401, 0x0503, 0x0501, 0x0603, 0x0601)
    out += struct.pack('>HHH', 0x000D, 2 + 2 * len(sigalgs), 2 * len(sigalgs))
    for s in sigalgs:
        out += struct.pack('>H', s)
    if mfl_code is not None:
        out += struct.pack('>HH', 0x0001, 1) + bytes([mfl_code])
    return bytes(out)


def client_hello(client_random, cookie=b'', *, msg_seq=0, rec_seq=0,
                 mfl_code=None):
    body = bytearray(_DTLS_1_2)
    body += client_random
    body.append(0)                                   # session_id
    body.append(len(cookie))
    body += cookie
    body += struct.pack('>HH', 2, _SUITE_ECDHE_ECDSA_AES128_GCM)
    body += b'\x01\x00'                              # null compression
    exts = _extensions(mfl_code)
    body += struct.pack('>H', len(exts)) + exts
    return _record(_CT_HANDSHAKE, rec_seq,
                   _handshake(_HT_CLIENT_HELLO, msg_seq, bytes(body)))


def peer_cleanup_alert(rec_seq):
    """One epoch-zero fatal handshake_failure, to free the peer we opened.

    This stops mid-handshake, which is the half-open state #77 describes: a
    peer left after the HelloVerifyRequest swallows the next clean attempt.
    The alert that was measured to free it is a fatal handshake_failure at
    epoch zero (shipped as connect(cleanup_hvr_peer=True) in v0.1.15), not the
    warning-level close_notify a completed session sends. An earlier draft of
    this script sent close_notify and would have left the peer behind.
    """
    return _record(_CT_ALERT, rec_seq, bytes([2, 40]))


def iter_records(datagram):
    """Yield (content_type, body) per record, in record order."""
    off = 0
    while off + 13 <= len(datagram):
        ctype = datagram[off]
        length = struct.unpack('>H', datagram[off + 11:off + 13])[0]
        body = datagram[off + 13:off + 13 + length]
        if len(body) != length:
            return
        yield ctype, body
        off += 13 + length


def iter_messages(datagram):
    """Yield (msg_type, msg_seq, frag_offset, frag_len, total_len) per
    handshake message fragment, and (None, ...) entries for other records."""
    for ctype, body in iter_records(datagram):
        if ctype == _CT_HANDSHAKE and len(body) >= 12:
            off = 0
            while off + 12 <= len(body):
                total = int.from_bytes(body[off + 1:off + 4], 'big')
                mseq = struct.unpack('>H', body[off + 4:off + 6])[0]
                foff = int.from_bytes(body[off + 6:off + 9], 'big')
                flen = int.from_bytes(body[off + 9:off + 12], 'big')
                yield body[off], mseq, foff, flen, total
                off += 12 + flen
        elif ctype == _CT_ALERT and len(body) >= 2:
            yield None, ('alert', body[0], body[1]), 0, 0, 0
        else:
            yield None, ('record', ctype, len(body)), 0, 0, 0


def describe(datagram):
    """Name every record in one datagram, handshake fragments included."""
    out = []
    for mtype, mseq, foff, flen, total in iter_messages(datagram):
        if mtype is None:
            kind = mseq
            if kind[0] == 'alert':
                out.append('Alert(%d,%s)'
                           % (kind[1], _ALERTS.get(kind[2], kind[2])))
            else:
                out.append('record(type=%d,len=%d)' % (kind[1], kind[2]))
            continue
        tag = '%s(seq=%d' % (_HS_NAMES.get(mtype, 'hs%d' % mtype), mseq)
        if flen != total or foff:
            tag += ',frag %d:%d of %d' % (foff, foff + flen, total)
        out.append(tag + ')')
    return out or ['unparsed %dB' % len(datagram)]


def hello_verify_cookie(datagram):
    for ctype, body in iter_records(datagram):
        if ctype != _CT_HANDSHAKE or len(body) < 15 or body[0] != 3:
            continue
        msg = body[12:]
        if len(msg) >= 3 and len(msg) == 3 + msg[2]:
            return msg[3:]
    return None


def classify(datagrams):
    """Split what arrived into the server's flight, peer-opened handshakes and
    retransmissions.

    Three distinctions earlier releases had to learn:

    * An inbound epoch-0 ClientHello is the peer opening its own handshake,
      not a reply to ours (#98, PeerInitiatedHandshakeError; my dryer does
      this after an outage). Counting one as a flight would let this script
      report a flight where none arrived.
    * A peer resending what it already sent is a retransmission, and identity
      comes from (message_seq, fragment_offset), not from the datagram (the
      v0.1.21 repeat-HelloVerifyRequest fix).
    * Anything else is the flight.
    """
    flight, peer_hellos, repeats = [], [], []
    seen = set()
    for dgram in datagrams:
        msgs = [m for m in iter_messages(dgram) if m[0] is not None]
        if any(m[0] == _HT_CLIENT_HELLO for m in msgs):
            peer_hellos.append(dgram)
            continue
        ids = {(m[0], m[1], m[2]) for m in msgs}
        if ids and ids <= seen:
            repeats.append(dgram)
            continue
        seen |= ids
        flight.append(dgram)
    return flight, peer_hellos, repeats


# ------------------------------------------------------------------- CoAP ---

def coap_get_res(pad_to=0):
    """A CoAP CON GET /oic/res, optionally padded to a total payload size."""
    msg = bytearray([0x44, 0x01])
    msg += os.urandom(2)                              # message id
    msg += os.urandom(4)                              # token
    msg += bytes([0xB3]) + b'oic'                     # Uri-Path: oic
    msg += bytes([0x03]) + b'res'                     # Uri-Path: res
    if pad_to > len(msg) + 1:
        msg += b'\xff' + b'\x00' * (pad_to - len(msg) - 1)
    return bytes(msg)


def _udp_socket(timeout=2.0, local_port=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if local_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('', local_port))
        except OSError:
            sock.close()
            raise
    sock.settimeout(timeout)
    return sock


def recv_from_host(sock, host, deadline):
    """recvfrom, keeping only datagrams from the appliance's address.

    The source *port* is deliberately not matched: an OCF stack binds its DTLS
    socket to port 0 and answers from an ephemeral port, so a connected socket
    reported live appliances as dead (#66, fixed in v0.1.14). The address check
    is what that fix kept, and this script keeps it too -- without it, any host
    on the network could put bytes in these results.
    """
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None, None
        sock.settimeout(remaining)
        try:
            dgram, addr = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            return None, None
        if addr[0] == host:
            return dgram, addr[1]


def plaintext_alive(host, port, timeout=2.0, attempts=2):
    """One small CoAP GET. True if the appliance answers."""
    for _ in range(attempts):
        sock = _udp_socket(timeout=timeout)
        try:
            sock.sendto(coap_get_res(), (host, port))
            dgram, _ = recv_from_host(sock, host, time.time() + timeout)
            if dgram is not None:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def wait_for_life(host, port, limit):
    """Poll liveness until it answers. Returns (alive, seconds_waited)."""
    started = time.time()
    while time.time() - started < limit:
        if plaintext_alive(host, port, timeout=1.5, attempts=1):
            return True, time.time() - started
        time.sleep(1.0)
    return False, time.time() - started


def discover_port(host, discovery_port):
    """Ask the library where the DTLS port is, rather than defaulting to one.

    ``discovery_port`` is passed explicitly: the library's 5683 default is
    documented as a convenience, and this script already lets the caller say
    where public CoAP answers, so the two must agree.

    A fixed default is the trap setup_cert.py --test fell into: it dialled
    49154 without checking, and on a unit whose secure port had landed
    elsewhere it reported a timeout that was read as a silent appliance
    (v0.1.22). These devices bind the socket to port 0, so the port moves.
    """
    try:
        from smartthings_local.protocol.ocf_discovery import (
            discover_ocf_secure_ports)
    except Exception:
        return None, ('smartthings-local is not importable here, so the port '
                      'cannot be discovered. Pass --port with the port your '
                      'bridge or probe reported.')
    try:
        result = discover_ocf_secure_ports(
            host, discovery_port=discovery_port, timeout=5.0)
    except Exception as exc:
        return None, 'discovery raised %s' % type(exc).__name__
    ports = tuple(getattr(result, 'ports', ()) or ())
    if len(ports) == 1:
        return ports[0], None
    if not ports:
        return None, ('the appliance advertised no secure port. Pass --port '
                      'if you know it.')
    return None, ('the appliance advertised %d secure ports, so this script '
                  'will not pick one. Pass --port.' % len(ports))


# ----------------------------------------------------------------- stages ---

def _ext_ids(mfl_code):
    ids, exts, p = [], _extensions(mfl_code), 0
    while p + 4 <= len(exts):
        eid, elen = struct.unpack('>HH', exts[p:p + 4])
        ids.append('0x%04x' % eid)
        p += 4 + elen
    return ids


def stage0(args, mfl_code):
    """Prove, with no hardware, that the arms differ and by how much."""
    print('STAGE 0 -- what will be sent (no hardware)')
    for size in _LADDER:
        total = size + _IP_UDP_OVERHEAD
        print('  ladder %4dB payload -> %4dB on the wire, %s'
              % (size, total,
                 'two IP fragments' if total > _ETH_MTU else 'one frame'))
    control = client_hello(b'\x00' * 32)
    offered = client_hello(b'\x00' * 32, mfl_code=mfl_code)
    print('  control ClientHello  : %dB, extensions %s'
          % (len(control), _ext_ids(None)))
    print('  mfl%-4d ClientHello  : %dB, extensions %s'
          % (args.mfl, len(offered), _ext_ids(mfl_code)))
    print('  the two arms differ by %dB, extension 0x0001 = %d (%d bytes)'
          % (len(offered) - len(control), mfl_code, args.mfl))
    print('  ClientHello ceiling  : %d; each peer is freed with an epoch-0 '
          'fatal handshake_failure' % args.max_hellos)
    print('  pacing: at least %.0fs between DTLS attempts, from one source '
          'port (%d)' % (_MIN_HANDSHAKE_GAP, args.local_port))
    print('  COST: abandoned handshakes can leave an appliance refusing DTLS '
          'for several minutes.')
    print('        Measured here 2026-10-17: a dryer rejected its bridge for '
          '8.5 minutes after a run,')
    print('        while plaintext CoAP answered throughout. Expect a local '
          'integration to go')
    print('        offline for a few minutes after this. The oven in the same '
          'run was unaffected.')
    if len(offered) - len(control) != 5 or _ext_ids(mfl_code)[-1] != '0x0001':
        print('  REFUSING TO RUN: the MFL arm is not carrying the extension')
        return False
    return True


def stage2(args):
    """The UDP size ladder: is a fragmented datagram fatal, and from where?"""
    print('\nSTAGE 2 -- fragmented UDP, no DTLS')
    rows = []
    for size in _LADDER:
        if not plaintext_alive(args.host, args.plaintext_port):
            print('  %4dB: skipped, appliance is not answering plaintext'
                  % size)
            rows.append((size, 'skipped', None))
            continue
        sock = _udp_socket(timeout=1.0)
        try:
            sock.sendto(coap_get_res(pad_to=size),
                        (args.host, args.plaintext_port))
            dgram, _ = recv_from_host(sock, args.host, time.time() + 1.0)
            answered = dgram is not None
        except OSError:
            answered = False
        finally:
            sock.close()
        alive, waited = wait_for_life(args.host, args.plaintext_port,
                                      args.recover)
        verdict_text = 'answered' if answered else 'no answer'
        if not alive:
            verdict_text += ', still down after %.0fs' % waited
        elif waited > 2.0:
            verdict_text += ', recovered after %.1fs' % waited
        else:
            verdict_text += ', stayed up'
        print('  %4dB payload (%4dB wire, %s): %s'
              % (size, size + _IP_UDP_OVERHEAD,
                 'fragmented' if size + _IP_UDP_OVERHEAD > _ETH_MTU
                 else 'one frame', verdict_text))
        rows.append((size, verdict_text, waited))
        time.sleep(args.settle)
    return rows


def one_hello_pair(args, mfl_code, label, budget):
    """CH, cookie, CH again, then listen. Frees the peer on every exit."""
    sock = _udp_socket(timeout=args.timeout, local_port=args.local_port)
    target = (args.host, args.port)
    cookie = None
    rec_seq = 0
    source_ports = set()
    client_random = os.urandom(32)
    try:
        if budget['left'] < 2:
            return {'label': label, 'budget_exhausted': True, 'flight': [],
                    'peer_hellos': [], 'repeats': []}
        sock.sendto(client_hello(client_random, rec_seq=rec_seq), target)
        budget['left'] -= 1
        rec_seq += 1
        deadline = time.time() + args.timeout
        while cookie is None:
            dgram, sport = recv_from_host(sock, args.host, deadline)
            if dgram is None:
                break
            source_ports.add(sport)
            cookie = hello_verify_cookie(dgram)
        if cookie is None:
            return {'label': label, 'cookie': False, 'flight': [],
                    'peer_hellos': [], 'repeats': [],
                    'source_ports': sorted(source_ports)}

        sock.sendto(client_hello(client_random, cookie, msg_seq=1,
                                 rec_seq=rec_seq, mfl_code=mfl_code), target)
        budget['left'] -= 1
        rec_seq += 1
        arrived = []
        deadline = time.time() + args.listen
        while True:
            dgram, sport = recv_from_host(sock, args.host, deadline)
            if dgram is None:
                break
            source_ports.add(sport)
            arrived.append(dgram)
        flight, peer_hellos, repeats = classify(arrived)
        return {'label': label, 'cookie': True, 'flight': flight,
                'peer_hellos': peer_hellos, 'repeats': repeats,
                'source_ports': sorted(source_ports)}
    finally:
        try:
            sock.sendto(peer_cleanup_alert(rec_seq), target)
        except OSError:
            pass
        sock.close()


def stage3(args, mfl_code, budget):
    print('\nSTAGE 3 -- one ClientHello pair per arm, differing by MFL only')
    out = []
    for label, code in (('control', None), ('mfl%d' % args.mfl, mfl_code)):
        if not plaintext_alive(args.host, args.plaintext_port):
            print('  %-8s: skipped, appliance is not answering plaintext'
                  % label)
            out.append({'label': label, 'skipped': True})
            continue
        result = one_hello_pair(args, code, label, budget)
        if result.get('budget_exhausted'):
            print('  %-8s: skipped, the ClientHello ceiling is reached'
                  % label)
            out.append(result)
            continue
        alive, waited = wait_for_life(args.host, args.plaintext_port,
                                      args.recover)
        result['alive'] = alive
        sizes = [len(d) for d in result['flight']]
        print('  %-8s: cookie %s, flight %d datagram(s) %s'
              % (label, 'received' if result.get('cookie') else 'NOT received',
                 len(sizes), sizes if sizes else ''))
        for dgram in result['flight']:
            print('              %5dB  %s%s'
                  % (len(dgram), ', '.join(describe(dgram)),
                     '   [over-MTU: arrived IP-fragmented]'
                     if len(dgram) + _IP_UDP_OVERHEAD > _ETH_MTU else ''))
        if result['repeats']:
            print('              plus %d retransmission(s), not counted'
                  % len(result['repeats']))
        if result['peer_hellos']:
            print('              plus %d ClientHello(s) from the appliance '
                  'itself, not counted as a flight'
                  % len(result['peer_hellos']))
        ports = result.get('source_ports') or []
        if ports and ports != [args.port]:
            print('              answered from source port(s) %s, not the %d '
                  'dialled' % (ports, args.port))
        print('              appliance %s%s'
              % ('stayed up' if alive and waited <= 2.0
                 else ('recovered after %.1fs' % waited) if alive
                 else 'still down after %.0fs' % waited,
                 '' if alive else ' <-- the drop reproduced'))
        out.append(result)
        gap = max(args.settle, _MIN_HANDSHAKE_GAP)
        print('              waiting %.0fs before the next DTLS attempt'
              % gap)
        time.sleep(gap)
    return out


def post_check(args, budget):
    """Can the appliance still start a DTLS handshake when we are done?

    Stage 1 and the recovery polls are plaintext CoAP, and on these devices
    plaintext and DTLS are independent: a run that leaves the DTLS stack
    refusing handshakes still answers a plaintext GET. That is exactly what
    happened on 2026-10-17, when every arm reported 'stayed up' and the
    appliance then rejected its own bridge for 8.5 minutes. A script that
    disturbs DTLS has to report on DTLS.
    """
    print('\nPOST-CHECK -- can it still start a DTLS handshake?')
    print('  %d ClientHello(s) sent so far, all from source port %d, so the '
          'firmware saw one peer reconnecting rather than one per arm.'
          % (args.max_hellos - budget['left'], args.local_port))
    if budget['left'] < 2:
        print('  skipped: the ClientHello ceiling is reached. DTLS health '
              'after this run is UNMEASURED.')
        return None
    result = one_hello_pair(args, None, 'post-check', budget)
    alerts = [m for d in result['flight'] for m in describe(d)
              if m.startswith('Alert')]
    if not result.get('cookie'):
        print('  no HelloVerifyRequest came back. The DTLS stack is not '
              'answering, so this run left it unable to handshake.')
        return False
    if alerts:
        print('  the appliance answered the cookie with %s, so it is '
              'refusing handshakes right now.' % ', '.join(alerts))
        return False
    if result['flight']:
        print('  a server flight came back, so it still accepts a new '
              'handshake.')
        return True
    print('  cookie answered, then silence. Inconclusive: that is either the '
          'drop this script is about or a wedged peer it left behind.')
    return None


def verdict(ladder, arms, dtls_ok=None):
    print('\nVERDICT')
    frag_fatal = [r for r in ladder
                  if r[0] + _IP_UDP_OVERHEAD > _ETH_MTU
                  and 'still down' in str(r[1])]
    small_fine = [r for r in ladder
                  if r[0] + _IP_UDP_OVERHEAD <= _ETH_MTU
                  and 'stayed up' in str(r[1])]
    if ladder:
        if frag_fatal and small_fine:
            print('  A fragmented UDP datagram drops this appliance and an '
                  'unfragmented one does not, so the fault is not specific '
                  'to ICMP.')
        elif frag_fatal:
            print('  Fragmented sizes dropped it, but no unfragmented size '
                  'stayed up, so this run does not separate size from '
                  'fragmentation.')
        else:
            print('  No size in the ladder dropped it. Either this unit is '
                  'not the one in #20, or conditions differed from the '
                  'capture that showed the drop.')

    usable = [a for a in arms
              if not a.get('skipped') and not a.get('budget_exhausted')]
    control = next((a for a in usable if a['label'] == 'control'), None)
    mfl = next((a for a in usable if a['label'] != 'control'), None)
    if not (control and mfl):
        print('  Stage 3 did not run both arms, so it settles nothing.')
    else:
        c_flight, m_flight = control['flight'], mfl['flight']
        if not c_flight and m_flight:
            big = [d for d in m_flight if len(d) + _IP_UDP_OVERHEAD > _ETH_MTU]
            if big:
                print('  The MFL arm drew a flight, but at least one datagram '
                      'is still over-MTU, so the offer was not applied to the '
                      'handshake. This firmware will not take a client-side '
                      'MTU fix.')
            else:
                print('  DECISIVE: the control drew no flight, and offering '
                      'max_fragment_length drew one entirely under the MTU. '
                      'The over-MTU flight is the mechanism, and a client '
                      'that can send this extension avoids it. Our cert path '
                      'is OpenSSL, which cannot send it, so shipping this fix '
                      'means a certificate-capable engine of our own.')
        elif c_flight and not m_flight:
            print('  The control drew a flight and the MFL arm did not. That '
                  'is backwards for the MTU reading; suspect run-to-run '
                  'variance and repeat before concluding anything.')
        elif c_flight and m_flight:
            # A unit that completes its flight either way still answers the
            # question the fix depends on: does this firmware act on the
            # extension at all? Compare the datagram shapes, not the outcome.
            c_big = max(len(d) for d in c_flight) + _IP_UDP_OVERHEAD
            m_big = max(len(d) for d in m_flight) + _IP_UDP_OVERHEAD
            print('  This unit completes its flight either way, so it is not '
                  'failing the way #20 fails. The comparison still settles '
                  'whether the firmware acts on the extension:')
            print('    control: %d datagram(s), largest %dB on the wire'
                  % (len(c_flight), c_big))
            print('    offered: %d datagram(s), largest %dB on the wire'
                  % (len(m_flight), m_big))
            if c_big > _ETH_MTU and m_big <= _ETH_MTU:
                print('  HONOURED: the offer moved this firmware off an '
                      'over-MTU flight and onto DTLS-layer fragmentation. A '
                      'client that can send extension 1 avoids IP '
                      'fragmentation here. OpenSSL cannot send it, so '
                      'shipping that means a certificate-capable engine of '
                      'our own.')
            elif c_big > _ETH_MTU:
                print('  IGNORED: the flight is over-MTU with and without the '
                      'offer, so this firmware will not take a client-side '
                      'MTU fix.')
            else:
                print('  This unit never sends an over-MTU flight, so it has '
                      'nothing for the extension to fix. That is the other '
                      'firmware generation, and it is not the #20 shape.')
        else:
            print('  Neither arm drew a flight. The appliance accepted the '
                  'cookie and sent nothing either way, so MFL changed '
                  'nothing here and the mechanism is still open.')
    if dtls_ok is False:
        print('\n  WARNING: the appliance was not accepting a DTLS handshake '
              'when this finished. Earlier \'stayed up\' lines are plaintext '
              'only. Leave it alone for about ten minutes; a dryer here '
              'recovered after 8.5.')
    elif dtls_ok is None:
        print('\n  DTLS health after the run was not established, so do not '
              'read the plaintext \'stayed up\' lines as the appliance being '
              'fully healthy.')
    print('\n  Nothing above completed a handshake, so none of it says '
          'whether this appliance would accept our certificate, or that any '
          'server identity was verified.')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('host', nargs='?')
    ap.add_argument('--port', type=int,
                    help='the DTLS port; discovered when omitted, because '
                         'these devices move it across a reboot')
    ap.add_argument('--plaintext-port', type=int, default=5683,
                    help='where CoAP answers in the clear (default 5683)')
    ap.add_argument('--mfl', type=int, default=512, choices=sorted(_MFL_CODES),
                    help='max_fragment_length to offer (default 512)')
    ap.add_argument('--max-hellos', type=int, default=6,
                    help='hard ceiling on ClientHellos sent (default 6: two '
                         'per arm plus the post-check)')
    ap.add_argument('--no-post-check', dest='post_check',
                    action='store_false',
                    help='skip the closing DTLS health check')
    ap.add_argument('--local-port', type=int, default=_DEFAULT_LOCAL_PORT,
                    help='source port held across every DTLS attempt so the '
                         'firmware evicts its stale peer instead of '
                         'accumulating one per arm (default %d)'
                         % _DEFAULT_LOCAL_PORT)
    ap.add_argument('--timeout', type=float, default=4.0,
                    help='seconds to wait for the HelloVerifyRequest')
    ap.add_argument('--listen', type=float, default=8.0,
                    help='seconds to listen for the server flight')
    ap.add_argument('--recover', type=float, default=30.0,
                    help='seconds to wait for liveness after each probe')
    ap.add_argument('--settle', type=float, default=15.0,
                    help='seconds between probes')
    ap.add_argument('--skip-ladder', action='store_true')
    ap.add_argument('--skip-mfl', action='store_true')
    ap.add_argument('--emit-only', action='store_true',
                    help='print what would be sent and exit')
    args = ap.parse_args(argv)
    mfl_code = _MFL_CODES[args.mfl]
    if args.max_hellos < 2:
        ap.error('--max-hellos must allow at least one pair')

    if not stage0(args, mfl_code):
        return 2
    if args.emit_only:
        return 0
    if not args.host:
        ap.error('a host is required unless --emit-only is given')

    if args.port is None and not args.skip_mfl:
        args.port, why = discover_port(args.host, args.plaintext_port)
        if args.port is None:
            print('\nNo DTLS port: %s' % why)
            return 1
        print('\ndiscovered DTLS port: %d' % args.port)
    print('\ntarget: <host>:%s   plaintext: %d'
          % (args.port, args.plaintext_port))

    print('STAGE 1 -- baseline liveness')
    if not plaintext_alive(args.host, args.plaintext_port):
        print('  plaintext CoAP GET /oic/res: SILENT')
        print('  The appliance is not answering before any probe. Nothing '
              'below would be interpretable, so stopping here. Try again '
              'when it is reachable.')
        return 1
    print('  plaintext CoAP GET /oic/res: answered')

    ladder = [] if args.skip_ladder else stage2(args)
    arms, dtls_ok = [], None
    if not args.skip_mfl:
        budget = {'left': args.max_hellos}
        arms = stage3(args, mfl_code, budget)
        if args.post_check:
            dtls_ok = post_check(args, budget)
    verdict(ladder, arms, dtls_ok)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\ninterrupted')
        sys.exit(130)
    except OSError as exc:
        # Redacted on purpose: a backend error can carry the address or a
        # local path, and this output is meant to be pasteable (v0.1.2's typed
        # redacted failures, and the v0.1.16 note on why).
        print('\nnetwork error: %s (details withheld so this output stays '
              'safe to paste)' % type(exc).__name__)
        sys.exit(1)
