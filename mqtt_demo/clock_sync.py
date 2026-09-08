"""Periodic appliance clock sync.

Samsung appliances keep their own wall clock and normally correct it
against Samsung's cloud. A bridge-only deployment blocks that path, so
the display clock free-runs and drifts. The appliance exposes the clock
as a write on `/configuration/vs/0`:

    {'x.com.samsung.da.currentTime': '<YYYY-MM-DD>T<HH:MM:SS>'}

The field is write-only. A GET of that resource returns the resource
metadata without it, which is why no device-tree dump carries the name
and why the bridge never puts the value in its cache -- there is nothing
the appliance can ever confirm it with. Verified on hardware, a TP1X
range, in LocalThings #404 / #428; the vendor field itself was first
documented on the SmartThings community forum:
https://community.smartthings.com/t/samsung-oven-range-and-cooktop-sync-time-api/251391

The timestamp is the host's LOCAL wall clock, no timezone suffix, so the
container's TZ is what lands on the appliance display.

Both that forum thread and LocalThings warn that a timestamp far outside
the appliance's certificate validity window can break its certificate
verification and leave it unresponsive. A host whose own clock is wrong
would write exactly such a value, so `PLAUSIBLE_FROM`/`PLAUSIBLE_UNTIL`
gate every write: an unsynced host clock skips the sync instead of
bricking the appliance.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Callable, Optional

import cbor2

from smartthings_local.protocol.coap import fmt_code
from smartthings_local.protocol.dtls_session import DtlsCoapSession

# Wire format the appliance accepts: local wall clock, second precision,
# no offset and no 'Z'.
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


def zone_name(now: datetime) -> str:
    """Return the zone abbreviation the stamp was written in.

    The wire format carries no offset, so the stamp alone cannot show
    which zone produced it and a container running UTC writes a panel an
    hour behind during BST while still answering 2.04. Logging the zone
    beside the stamp is what separates those two cases.
    """
    try:
        return now.astimezone().tzname() or time.tzname[0]
    except (OverflowError, OSError, ValueError):
        return time.tzname[0]

# Host-clock sanity gate. A container that came up before its NTP sync
# lands (or with no RTC at all) reports a date well before this floor;
# writing that to the appliance is the failure mode the forum thread
# warns about. The ceiling catches the same fault in the other
# direction.
PLAUSIBLE_FROM  = datetime(2026, 1, 1)
PLAUSIBLE_UNTIL = datetime(2046, 1, 1)

# Delay before the first sync of a session. Keeps the write clear of the
# seed + discovery burst on connect.
INITIAL_DELAY_S = 15.0

WRITE_TIMEOUT_S = 8.0


class ClockSyncTask:
    """Writes the host's local wall clock to the appliance periodically.

    Session-scoped, like KeepaliveTask and ObserveRefreshTask, but the
    schedule is not: `last_sync_ts` carries the previous session's last
    successful write in, and `on_sync` reports each one back out. A
    bridge that reconnects every few minutes therefore still syncs on
    the requested interval rather than once per reconnect.
    """

    def __init__(self,
                 session: DtlsCoapSession,
                 path_segs,
                 field: str,
                 interval_s: float,
                 logger=None,
                 last_sync_ts: Optional[float] = None,
                 on_sync: Optional[Callable[[float], None]] = None,
                 now_fn: Callable[[], datetime] = datetime.now):
        self.session = session
        self.path_segs = list(path_segs)
        self.field = field
        self.interval_s = interval_s
        self.log = logger
        self.last_sync_ts = last_sync_ts
        self.on_sync = on_sync
        self.now_fn = now_fn
        self._sync_count = 0

    @property
    def sync_count(self) -> int:
        return self._sync_count

    @property
    def href(self) -> str:
        return '/' + '/'.join(self.path_segs)

    def sync_now(self, reason: str = 'periodic') -> bool:
        """Write the host clock once. Returns True on a 2.xx response."""
        now = self.now_fn()
        if not (PLAUSIBLE_FROM <= now < PLAUSIBLE_UNTIL):
            if self.log:
                self.log.warning(
                    "clock sync (%s) skipped: host clock reads %s %s, "
                    "outside the plausible window -- writing it could break "
                    "the appliance's certificate verification",
                    reason, now.strftime(TIME_FORMAT), zone_name(now))
            return False

        stamp = now.strftime(TIME_FORMAT)
        body = {self.field: stamp}
        try:
            code, _ = self.session.post(self.path_segs, cbor2.dumps(body),
                                        timeout=WRITE_TIMEOUT_S)
        except Exception as e:
            if self.log:
                self.log.warning("clock sync (%s) %s: %s",
                                 reason, self.href, e)
            return False

        ok = code >> 5 == 2
        if ok:
            self._sync_count += 1
            self.last_sync_ts = time.time()
            if self.on_sync:
                self.on_sync(self.last_sync_ts)
        # The write is not cached either way: the appliance never reads
        # the field back, so a cached copy would be state invented by the
        # bridge rather than state the device reported.
        if self.log:
            log = self.log.info if ok else self.log.warning
            log("clock sync (%s) %s = %s %s -> %s",
                reason, self.href, stamp, zone_name(now), fmt_code(code))
        return ok

    def _initial_delay(self) -> float:
        """Seconds until the first sync of this session."""
        if self.last_sync_ts is None:
            return INITIAL_DELAY_S
        due_in = self.interval_s - (time.time() - self.last_sync_ts)
        return max(INITIAL_DELAY_S, due_in)

    def run_forever(self, stop: threading.Event) -> None:
        if stop.wait(self._initial_delay()):
            return
        self.sync_now()
        while not stop.wait(self.interval_s):
            self.sync_now()
