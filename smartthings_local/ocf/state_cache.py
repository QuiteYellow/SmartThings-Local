"""Single source of truth for one appliance's state.

All writers (OBSERVE notify, poll, seed, optimistic) call apply_rep().
A registered on_change callback fires after any apply that mutated the
cache, which the bridge wires to its MQTT publish gate.

Writers pass ``merge=True`` when their representation is a partial one.
An OBSERVE notification on these appliances can be a **sparse delta**: the
dryer's ``/course/vs/0`` answers a GET with 944 B across three keys and
notifies with ``{'x.com.samsung.da.options': ['Course_27']}`` alone, the
other keys absent, while a GET taken afterwards is byte-identical to the
first. Assigning such a payload over the cache drops everything it does
not mention. Measured 2026-09-25, recorded in
``local-tools/HARDWARE-RESULTS-2026-09-25-notification-deltas.md``.

Only a genuine notification is partial. A poll, a sweep, a seed, a
registration response and a Block2 fetchback all carry the complete
representation, so they keep assigning and a key that disappears there is
honoured as gone. The ``source`` label cannot be used to tell these apart:
a fetchback triggered by a notification is reported with the notification's
own source, so the caller states the shape explicitly.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional, Protocol


class _ObservationHook(Protocol):
    def on_observation(self, state: dict, href: str, rep: dict) -> None: ...


class StateCache:

    def __init__(self, descriptor: '_ObservationHook'):
        self.descriptor = descriptor
        self.links: dict[str, dict] = {}
        self.last_updated: dict[str, float] = {}
        self.source: dict[str, str] = {}
        self.descriptor_state: dict = {}
        self._on_change: Optional[Callable[[bool, str], None]] = None
        self._lock = threading.RLock()

    def set_on_change(self, cb: Callable[[bool, str], None]) -> None:
        self._on_change = cb

    def apply_rep(self, href: str, rep: dict, source: str,
                  *, merge: bool = False) -> bool:
        """Apply one representation. ``merge`` folds a partial one into
        what is already held; the default replaces.

        The observation hook always receives the resulting representation
        rather than the incoming fragment, so a descriptor reading a field
        the fragment happens to omit sees the value that is actually
        current.
        """
        if not isinstance(rep, dict):
            return False
        with self._lock:
            prior = self.links.get(href)
            if merge and prior:
                resulting = {**prior, **rep}
            else:
                resulting = rep
            changed = prior != resulting
            self.links[href] = resulting
            self.last_updated[href] = time.time()
            self.source[href] = source
        hook = self.descriptor.on_observation
        if hook is not None:
            try:
                hook(self.descriptor_state, href, resulting)
            except Exception:
                pass
        if self._on_change is not None:
            try:
                self._on_change(changed, source)
            except Exception:
                pass
        return changed

    def apply_optimistic(self, href: str, body: dict) -> bool:
        if not isinstance(body, dict):
            return False
        with self._lock:
            merged = dict(self.links.get(href) or {})
            merged.update(body)
        return self.apply_rep(href, merged, source='optimistic')

    @staticmethod
    def index_device_tree(device0_body) -> dict[str, dict]:
        """Turn a /device/0 CBOR list-of-{href, rep} sweep response into
        a dict keyed by href. Some responses put a device-level `/device/0`
        rep first, while others put a normal resource in that slot.

        Replaces the old standalone sensors.index_links — folded in
        here because every current and future caller immediately feeds
        the result into apply_rep on this same cache."""
        out: dict[str, dict] = {}
        if not isinstance(device0_body, list):
            return out
        for entry in device0_body:
            if (
                isinstance(entry, dict)
                and 'href' in entry
                and entry['href'] != '/device/0'
            ):
                out[entry['href']] = entry.get('rep') or {}
        return out

    def get(self, href: str) -> Optional[dict]:
        with self._lock:
            return self.links.get(href)

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            return dict(self.links)

    def freshness_s(self, href: str) -> Optional[float]:
        ts = self.last_updated.get(href)
        return None if ts is None else (time.time() - ts)

    def stalest(self) -> Optional[tuple[str, float]]:
        with self._lock:
            if not self.last_updated:
                return None
            href = min(self.last_updated, key=self.last_updated.get)
            return href, time.time() - self.last_updated[href]
