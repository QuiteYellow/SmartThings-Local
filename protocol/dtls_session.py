"""CoAP-over-DTLS client for Samsung RT-OCF appliances (RFC 7252 + 6347).

Replaces the TLS-over-TCP transport used in the original dryer bridge.
Both the oven (UDP/49154) and the dryer (UDP/49155) speak CoAP-over-DTLS
with the ECDHE-ECDSA-AES128-GCM-SHA256 cipher and a client cert.

Wire-level details that matter (from local-tools/oven-findings.md §17):
  * DTLS ciphertext MTU must be 1200; otherwise OpenSSL fragments the
    client cert across two datagrams and TizenRT drops the second.
  * Samsung's RT-OCF uses ACK+separate-CON for the larger responses.
    The reader MUST correlate by (token, mid) — not arrival order —
    or interleaved one-shot / OBSERVE traffic mis-attributes.
  * Multi-block GET requires the SAME CoAP token across every block
    of the response ("token-stable Block2"). Fresh-token-per-block
    is silently dropped by the server.

Reader thread owns the UDP socket. Callers issue get()/post() and block
on a per-token Event the reader signals. OBSERVE notifications are
delivered via the on_notification callback.
"""
import os
import socket
import threading
import time
from pathlib import Path

from OpenSSL import SSL

from .coap import (
    URI_PATH, URI_QUERY, OBSERVE, CONTENT_FORMAT, ACCEPT, BLOCK2, SIZE2,
    TYPE_CON, TYPE_NON, TYPE_ACK, TYPE_RST,
    METHOD_GET, METHOD_POST, CF_CBOR,
    OBSERVE_REGISTER, OBSERVE_DEREGISTER, BLOCK_SZX,
    encode_options, parse_coap, build_coap, block_value, fmt_code,
    split_dtls as _split_dtls,
)
import logging

logger = logging.getLogger(__name__)

_OCF_ROOT_CA = str(Path(__file__).parent / 'ocf_root_ca.pem')


# Diagnostic logging — when DEBUG_BRIDGE=1 in env, the bridge dumps
# every received CoAP frame, every /operational/state/vs/0 + /oven/vs/0
# + /power/vs/0 + /mode/vs/0-options rep change, the full link tree at
# seed time, and the /oic/res directory. Useful for reverse-engineering
# new resources and field semantics; otherwise quiet.
DEBUG_BRIDGE = os.environ.get('DEBUG_BRIDGE') == '1'

# Per-block retransmission: send up to this many times before giving up.
# Each attempt waits at most _BLOCK_ACK_TIMEOUT seconds (capped by the
# overall deadline). Matches RFC 7252 CON retransmit behaviour.
_BLOCK_MAX_ATTEMPTS = 3
_BLOCK_ACK_TIMEOUT  = 4.0

# Inter-request pacing: minimum seconds between CoAP CON sends on one session.
# Samsung's RT-OCF stacks drop requests when hit faster than their firmware
# ceiling (dryer ~14 req/s, oven ~8 req/s, dishwasher unknown). 5 req/s
# (200 ms) is conservative enough for all tested devices; tune per device
# once the ceiling is measured empirically.
_DEFAULT_RATE_LIMIT_RPS = 5.0


class DtlsCoapSession:
    """Single sustained DTLS-CoAP session.

    Caller drives lifecycle:
        sess = DtlsCoapSession(host, port, cert, key)
        sess.connect()
        sess.start_reader()
        sess.subscribe([...], on_notification=cb)   # OBSERVE
        code, body = sess.get(['device', '0'])      # Block2 fetch
        code, _    = sess.post(['mode','vs','0'], cbor)
        sess.close()
    """

    HANDSHAKE_TIMEOUT_S = 12.0
    READER_RECV_TIMEOUT_S = 1.0  # short so stop_event propagates quickly
    MAX_BLOCKS = 32              # safety bound for Block2 fetches

    def __init__(self, host, port, cert_path, key_path,
                 on_notification=None, mtu=1200,
                 rate_limit_rps: float = _DEFAULT_RATE_LIMIT_RPS):
        self.host = host
        self.port = port
        self.cert_path = str(cert_path)
        self.key_path  = str(key_path)
        self.on_notification = on_notification  # fn(href, payload_bytes)
        self.mtu = mtu
        self._min_req_interval = 1.0 / rate_limit_rps

        self.sock = None
        self.conn = None
        self.dest = None

        self._send_lock = threading.Lock()
        # Randomize MID and token counter starting points so reconnects
        # don't reuse identifiers from previous sessions — Samsung's
        # RT-OCF appears to remember observer state across DTLS
        # sessions, and re-registering with a token it still thinks is
        # active is silently no-ops.
        self._mid = int.from_bytes(os.urandom(2), 'big')
        self._tok_counter = int.from_bytes(os.urandom(4), 'big')
        # OBSERVE tokens are 1-byte (Samsung silently drops TKL>1
        # OBSERVE registrations). Pick a random starting byte in the
        # 0x40..0xff range so each session uses fresh values.
        self._observe_tok_counter = 0x40 + (os.urandom(1)[0] & 0xBF)
        # token (bytes) → (Event, container_dict)
        self._pending = {}
        # token (bytes) → href (str)
        self._observe_tokens = {}

        self._stop = threading.Event()
        self._reader_thread = None
        self._last_send_ts = 0.0

    def pace(self) -> None:
        """Sleep only the part of the rate-limit interval not already consumed
        since the last real send. Uses _stop so session teardown wakes it."""
        remaining = self._min_req_interval - (time.monotonic() - self._last_send_ts)
        if remaining > 0:
            self._stop.wait(remaining)

    # ---- lifecycle ---------------------------------------------------

    def connect(self):
        """DTLS handshake. Blocks up to HANDSHAKE_TIMEOUT_S. Raises
        ConnectionError / TimeoutError on failure."""
        ctx = SSL.Context(SSL.DTLS_METHOD)

        ctx.load_verify_locations(_OCF_ROOT_CA)
        ctx.set_verify(SSL.VERIFY_PEER, lambda conn, cert, err, depth, ok: ok)
        # @SECLEVEL=0 permits SHA-1 in Samsung's server cert chain (AC14K_M
        # intermediate is SHA-1 signed). This is the only channel that reaches
        # the OpenSSL instance cryptography bundles — ctypes and cffi bindings
        # do not expose SSL_CTX_set_security_level on this build.
        ctx.set_cipher_list(b'ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0')
        ctx.use_certificate_chain_file(self.cert_path)
        ctx.use_privatekey_file(self.key_path)
        ctx.check_privatekey()

        conn = SSL.Connection(ctx, None)
        conn.set_connect_state()
        conn.set_ciphertext_mtu(self.mtu)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        dest = (self.host, self.port)

        t0 = time.time()
        while time.time() - t0 < self.HANDSHAKE_TIMEOUT_S:
            try:
                conn.do_handshake()
                break
            except SSL.WantReadError:
                pass
            except SSL.Error as e:
                sock.close()
                raise ConnectionError(f"DTLS handshake error: {e}") from e
            try:
                o = conn.bio_read(65535)
                if o:
                    for r in _split_dtls(o):
                        sock.sendto(r, dest)
            except SSL.WantReadError:
                pass
            try:
                d, _ = sock.recvfrom(65535)
                if d:
                    conn.bio_write(d)
            except socket.timeout:
                pass
            time.sleep(0.05)
        else:
            sock.close()
            raise TimeoutError(
                f"DTLS handshake timeout to {self.host}:{self.port}")

        self.sock = sock
        self.conn = conn
        self.dest = dest
        self._stop.clear()

    def start_reader(self):
        """Spawn the reader thread. Must be called after connect()."""
        if self.sock is None:
            raise RuntimeError("connect() before start_reader()")
        t = threading.Thread(target=self._reader_loop,
                             daemon=True, name='dtls-reader')
        t.start()
        self._reader_thread = t

    def join(self):
        """Block until the reader thread exits (i.e. socket dies)."""
        if self._reader_thread is not None:
            self._reader_thread.join()

    def _send_observe_dereg(self, tok, path_segs):
        """Send a single OBSERVE deregister GET (Observe option = 1)
        on the existing token. Best-effort — caller swallows errors."""
        if self.conn is None:
            return
        mid = self._next_mid()
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        opts.append((OBSERVE, OBSERVE_DEREGISTER))
        opts.append((ACCEPT, CF_CBOR))
        self._send_dgram(
            build_coap(TYPE_CON, METHOD_GET, mid, tok, opts))

    def close(self):
        """Tear down session. Sends best-effort OBSERVE deregisters
        first so Samsung's RT-OCF cleans up its observer table —
        without this, the per-cert observer state survives DTLS close
        and a quick reconnect with the same tokens silently no-ops."""
        # Send dereg for every active observation while the conn is
        # still healthy. Tiny sleep lets the records reach the wire
        # before we shut DTLS down.
        if self.conn is not None and self._observe_tokens:
            for tok, href in list(self._observe_tokens.items()):
                segs = [s for s in href.split('/') if s]
                try:
                    self._send_observe_dereg(tok, segs)
                except Exception as e:
                    logger.warning("dereg %s: %s", href, e)
            time.sleep(0.1)

        self._stop.set()
        if self.conn is not None:
            try:
                self.conn.shutdown()
            except Exception:
                pass
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        for tok, (ev, container) in list(self._pending.items()):
            container.setdefault('err', 'socket closed')
            ev.set()
        self._pending.clear()
        self._observe_tokens.clear()
        self.sock = None
        self.conn = None

    # ---- send / receive plumbing -------------------------------------

    def _next_mid(self):
        self._mid = (self._mid + 1) & 0xFFFF
        return self._mid

    def _next_tok(self):
        self._tok_counter = (self._tok_counter + 1) & 0xFFFFFFFF
        # 4-byte tokens — fits within tkl=8 cap with headroom and
        # avoids collisions across long-running OBSERVE subscriptions.
        return self._tok_counter.to_bytes(4, 'big')

    def _next_observe_tok(self):
        # Single-byte tokens for OBSERVE registrations. Samsung
        # RT-OCF accepts these but silently drops TKL=4 OBSERVE
        # registrations. Counter is randomly seeded per session so
        # reconnects don't collide with stale observer state Samsung
        # may still be holding from the previous run.
        self._observe_tok_counter = (self._observe_tok_counter + 1) & 0xFF
        # Avoid 0x00 — some CoAP stacks treat an all-zero token as
        # equivalent to "no token" / empty (TKL=0).
        if self._observe_tok_counter == 0:
            self._observe_tok_counter = 1
        return bytes([self._observe_tok_counter])

    def _send_dgram(self, datagram):
        """Send a CoAP datagram. Holds the send lock for the
        BIO-drain so two writers can't interleave records."""
        with self._send_lock:
            if self.conn is None:
                raise ConnectionError("DTLS session closed")
            try:
                self.conn.send(datagram)
                self._last_send_ts = time.monotonic()
                while True:
                    o = self.conn.bio_read(65535)
                    if not o:
                        break
                    for r in _split_dtls(o):
                        self.sock.sendto(r, self.dest)
            except SSL.WantReadError:
                pass

    def _reader_loop(self):
        """Pump UDP socket → DTLS BIO → CoAP parser. Demuxes to pending
        / observe handlers. Exits on socket error or stop event."""
        sock = self.sock
        conn = self.conn
        sock.settimeout(self.READER_RECV_TIMEOUT_S)
        try:
            while not self._stop.is_set():
                try:
                    d, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except (OSError, ValueError):
                    return
                if not d:
                    continue
                # pyOpenSSL's SSL.Connection is not thread-safe — the
                # same SSL object must not be touched by multiple
                # threads concurrently. Drain decrypted records into a
                # local list under _send_lock so the reader never races
                # a sender's conn.send()/bio_read(). Dispatch happens
                # AFTER releasing the lock because _dispatch_coap may
                # call _send_dgram (auto-ACK for CON frames), which
                # re-acquires the lock — holding it across dispatch
                # would deadlock.
                packets = []
                exit_reader = False
                with self._send_lock:
                    try:
                        conn.bio_write(d)
                    except SSL.Error as e:
                        logger.warning("DTLS bio_write: %s", e)
                        return
                    while True:
                        try:
                            pl = conn.recv(65535)
                        except SSL.WantReadError:
                            break
                        except SSL.ZeroReturnError:
                            logger.info("DTLS peer closed connection")
                            exit_reader = True
                            break
                        except SSL.Error as e:
                            logger.warning("DTLS recv: %s", e)
                            exit_reader = True
                            break
                        if not pl:
                            break
                        packets.append(pl)
                for pl in packets:
                    try:
                        self._dispatch_coap(pl)
                    except Exception as e:
                        logger.warning("dispatch: %s", e)
                if exit_reader:
                    return
        finally:
            # Make sure pending waiters don't hang if the reader dies.
            for tok, (ev, container) in list(self._pending.items()):
                container.setdefault('err', 'reader exited')
                ev.set()

    def _dispatch_coap(self, datagram):
        try:
            mt, code, mid, tok, ropts, payload = parse_coap(datagram)
        except Exception as e:
            logger.debug("malformed CoAP: %s", e)
            return

        if DEBUG_BRIDGE:
            kind = ['CON', 'NON', 'ACK', 'RST'][mt]
            logger.info("rx %s code=%s mid=%04x tok=%s opts=%d pl=%d",
                        kind, fmt_code(code), mid, tok.hex() or '-',
                        len(ropts), len(payload))

        # ACK back any CON from the device to suppress retransmits.
        # RFC 7252 §4.2 — ACK is a bare frame (token len 0, code 0).
        if mt == TYPE_CON:
            try:
                self._send_dgram(build_coap(TYPE_ACK, 0, mid, b'', []))
            except Exception as e:
                logger.warning("ACK send: %s", e)

        # Empty ACK with no options & no payload = "separate response
        # coming" — used by Samsung's RT-OCF for the larger reads. Stop
        # the retransmit timer on the client side and wait for the CON.
        if mt == TYPE_ACK and code == 0 and not payload and not ropts:
            return

        # Pending one-shot? Resolve and return.
        rec = self._pending.get(tok)
        if rec is not None:
            ev, container = rec
            container['code']    = code
            container['mtype']   = mt
            container['mid']     = mid
            container['options'] = ropts
            container['payload'] = payload
            ev.set()
            return

        # OBSERVE notification?
        href = self._observe_tokens.get(tok)
        if href is not None:
            if code != 0x45:
                logger.warning("observe %s: non-2.05 %s",
                               href, fmt_code(code))
                return
            cb = self.on_notification
            if cb is not None:
                try:
                    cb(href, payload)
                except Exception as e:
                    logger.warning("notification callback %s: %s",
                                   href, e)
            return

        # Stale token (post-reconnect or unknown) — drop quietly.

    # ---- request primitives ------------------------------------------

    def get(self, path_segs, query=(), timeout=10.0):
        """Token-stable Block2 GET. Returns (code, payload_bytes).

        Reuses one CoAP token across every block of a multi-block
        response — Samsung's server keys per-transfer state on the
        token, and dropping a fresh token on block 1+ silently drops
        the request."""
        if self.conn is None:
            raise ConnectionError("DTLS session closed")
        tok = self._next_tok()
        blob = b''
        num = 0
        last_code = None
        last_opts = []
        deadline = time.time() + timeout
        szx = BLOCK_SZX   # server may negotiate down; track per-transfer
        while True:
            if num > 0:
                self.pace()
            container = {}
            for attempt in range(_BLOCK_MAX_ATTEMPTS):
                ev = threading.Event()
                container = {}
                self._pending[tok] = (ev, container)
                try:
                    mid = self._next_mid()
                    opts = [(URI_PATH, s.encode()) for s in path_segs]
                    for q in query:
                        opts.append((URI_QUERY, q.encode()))
                    opts.append((ACCEPT, CF_CBOR))
                    if num > 0:
                        opts.append((BLOCK2, block_value(num, 0, szx)))
                    self._send_dgram(
                        build_coap(TYPE_CON, METHOD_GET, mid, tok, opts))
                    per_wait = min(_BLOCK_ACK_TIMEOUT,
                                   max(0.1, deadline - time.time()))
                    if ev.wait(per_wait):
                        break  # got a response
                    remaining = deadline - time.time()
                    if remaining <= 0 or attempt == _BLOCK_MAX_ATTEMPTS - 1:
                        logger.debug(
                            "GET %s /%s block %d: timed out after %d attempt(s)",
                            self.host, '/'.join(path_segs), num, attempt + 1,
                        )
                        raise TimeoutError(
                            f"GET /{'/'.join(path_segs)} block {num} timeout")
                    logger.debug(
                        "GET %s /%s block %d: attempt %d/%d timeout, retrying",
                        self.host, '/'.join(path_segs), num,
                        attempt + 1, _BLOCK_MAX_ATTEMPTS,
                    )
                finally:
                    self._pending.pop(tok, None)
            if 'err' in container:
                raise ConnectionError(container['err'])

            code = container['code']
            payload = container['payload']
            ropts = container['options']
            last_code = code
            last_opts = ropts
            blob += payload
            # 4.xx / 5.xx responses don't carry Block2 continuation —
            # bail with whatever we got. Caller decides if 4.xx is fatal.
            if code >> 5 != 2:
                return code, blob
            b2 = [v for n, v in ropts if n == BLOCK2]
            more = 0
            if b2:
                bv = int.from_bytes(b2[0], 'big')
                more = (bv >> 3) & 1
                server_szx = bv & 0x07
                if server_szx != szx:
                    szx = server_szx
            if not more:
                break
            num += 1
            if num > self.MAX_BLOCKS:
                raise ConnectionError(
                    f"GET /{'/'.join(path_segs)}: >{self.MAX_BLOCKS} "
                    f"blocks, aborting")
        return last_code, blob

    def post(self, path_segs, body_cbor, timeout=8.0):
        """Single-frame POST with a CBOR-encoded body. Returns
        (code, payload_bytes). body_cbor must already be encoded."""
        if self.conn is None:
            raise ConnectionError("DTLS session closed")
        tok = self._next_tok()
        mid = self._next_mid()
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        opts.append((CONTENT_FORMAT, CF_CBOR))
        opts.append((ACCEPT, CF_CBOR))
        datagram = build_coap(TYPE_CON, METHOD_POST, mid, tok, opts,
                              body_cbor)
        ev = threading.Event()
        container = {}
        self._pending[tok] = (ev, container)
        try:
            self._send_dgram(datagram)
            if not ev.wait(timeout):
                raise TimeoutError(
                    f"POST /{'/'.join(path_segs)} timeout")
            if 'err' in container:
                raise ConnectionError(container['err'])
            return container['code'], container['payload']
        finally:
            self._pending.pop(tok, None)

    def ping(self):
        """RFC 7252 §4.4 CoAP Ping — empty CON, no token, no payload.
        Fire-and-forget: we do not wait for the matching RST because
        Samsung's RT-OCF doesn't reliably emit one (verified
        2026-06-04: every sync ping timed out while polls succeeded
        at 200+/window). The send itself is the keepalive — it
        tickles Samsung's observer state so OBSERVE subscriptions
        aren't aged out.

        Real half-open-session detection lives in PollScheduler's
        `last_success_ts`, surfaced through KeepaliveTask's
        `liveness_fn`."""
        if self.conn is None:
            raise ConnectionError("DTLS session closed")
        mid = self._next_mid()
        self._send_dgram(build_coap(TYPE_CON, 0, mid, b'', []))
        return mid

    def refresh_observes(self, paths):
        """Drop all current OBSERVE registrations and re-subscribe to
        the given paths. Used as a periodic safety net — CoAP OBSERVE
        has no built-in TTL but Samsung's RT-OCF can age out its
        observer table during cloud blips even while the DTLS session
        stays healthy. Without this, internet recovery on a still-
        reachable device leaves push permanently dead.

        Best-effort: dereg failures are logged and we still bind fresh
        tokens via subscribe. Brief race window where a notify on the
        old token gets dropped as 'stale' — acceptable for a 6h-scale
        safety net."""
        if self.conn is None:
            raise ConnectionError("DTLS session closed")
        for tok, href in list(self._observe_tokens.items()):
            segs = [s for s in href.split('/') if s]
            try:
                self._send_observe_dereg(tok, segs)
            except Exception as e:
                logger.warning("refresh dereg %s: %s", href, e)
        self._observe_tokens.clear()
        time.sleep(0.1)
        for path in paths:
            try:
                self.subscribe(list(path))
                time.sleep(0.05)
            except Exception as e:
                logger.warning("refresh subscribe %s: %s", path, e)

    def subscribe(self, path_segs):
        """Register an OBSERVE on the given path. The initial 2.05
        notification and all subsequent state-change notifications
        will fire on_notification(href, payload_bytes).

        Returns the token used (in case the caller wants to deregister
        later)."""
        if self.conn is None:
            raise ConnectionError("DTLS session closed")
        tok = self._next_observe_tok()
        href = '/' + '/'.join(path_segs)
        # Register the token BEFORE sending — otherwise the device
        # could respond between send() and the dict insert, and the
        # reader thread would drop the initial 2.05 as "stale".
        self._observe_tokens[tok] = href
        mid = self._next_mid()
        opts = [(URI_PATH, s.encode()) for s in path_segs]
        opts.append((OBSERVE, OBSERVE_REGISTER))
        opts.append((ACCEPT, CF_CBOR))
        self._send_dgram(
            build_coap(TYPE_CON, METHOD_GET, mid, tok, opts))
        return tok
