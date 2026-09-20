"""Oven descriptor (Samsung NV7000BS-class).

Resource map captured 2026-05-31 via DTLS-CoAP with the client cert.
See `local-tools/comparisons/oven-tree.md` for the full field reference.

Write surfaces this descriptor exposes:

  proven:
    * UpperLamp via /mode/vs/0 options RMW (probe_oven_lamp_toggle.py)
      — works even with Remote Control off.

    * Cycle start via an OCF batch write to /device/0 carrying mode,
      setpoint, cook time and the run command together
      (docs/oven-cook-start.md). Measured 2026-09-20; separate writes
      to each resource do not start a cycle from idle, which is why
      the three parameters are staged here and sent as one batch.
    * Stop via /operational/state/vs/0 state='Ready' — a plain
      single-resource write, measured in the same run.

  unproven (first HA use is also the test):
    * Sound, FastPreheat — same RMW pattern as lamp.
    * Setpoint via /temperatures/vs/0 items RMW. Mid-cook write may
      or may not retune the element (plan §K-U #2).
    * Power on/off via /power/vs/0.

Untested writes are gated behind <prefix>/remote_available so HA
disables them in the UI when the oven's Remote Control switch is off.

The HA surface splits by cycle state so no control ever changes
meaning: Setpoint and Cook time are live and cycle-gated, while
Program / Program temperature / Program duration / Start are
idle-gated and stage a cook the appliance has not been told about
yet."""
import json
import logging
import time
from datetime import datetime, timezone

from ..descriptor import (
    LOCAL_ONLY,
    ApplianceDescriptor,
    ClockSync,
    avail_base,
    avail_with_cycle,
    avail_with_remote_and_cycle,
    avail_with_remote_and_idle,
    device_block,
    encode,
)
from smartthings_local.ocf.poll_scheduler import PollTier

# Module-level child of the `mqtt_demo` tree — see mqtt_demo/logger.py.
# Command handlers refuse a start with a reason, and the reason is
# only useful if it reaches the log.
log = logging.getLogger('mqtt_demo.oven')


# ---------------------------------------------------------------------
# OBSERVE paths — every push-eligible /<x>/vs/0 resource on the oven.
# Same wedge-safety story as the dryer: only `/<x>/vs/0` siblings push;
# OCF-standard `/<x>/0` paths accept registration but never fire.
# Security paths (/oic/sec/{doxm,pstat,acl,cred}) are deliberately
# EXCLUDED — those are the surfaces that nearly bricked the oven in
# prior sessions. The bridge has no reason to touch them.
# ---------------------------------------------------------------------
OBSERVE_PATHS = [
    ['operational', 'state', 'vs', '0'],    # state, time, progress
    ['power',       'vs', '0'],             # power On/Off
    ['oven',        'vs', '0'],             # cavity state (Cooking, Idle, …)
    ['temperatures','vs', '0'],             # current + desired temp
    ['doors',       'vs', '0'],             # openState
    ['kidslock',    'vs', '0'],             # child lock
    ['remotectrl',  'vs', '0'],             # remote control enabled
    ['mode',        'vs', '0'],             # cooking mode + options array
    ['alarms',      'vs', '0'],             # alarm code (OV_E_OFF etc.)
    ['connected',   'vs', '0'],             # cloud connectivity status
    ['otninformation', 'vs', '0'],          # firmware-update flags
]


# Setpoint bounds — union across modeSpec entries on this oven. Per-mode
# bounds (e.g. PlateWarm 30–80) tighten this; the firmware will refuse
# out-of-range writes for the active mode and the HA UI will surface
# the resulting 4.xx in the bridge log.
SETPOINT_MIN_C = 30
SETPOINT_MAX_C = 270
SETPOINT_STEP_C = 5


# Options offered by the Program select. Discovery payloads are built
# before any resource has been read, so this cannot be the board's live
# answer — it is the startable set this appliance class publishes. The
# live set is republished each state update as `program_startable`, and
# Start validates against that, so selecting a mode a given unit does
# not declare startable fails with a reason rather than reaching the
# appliance. Order follows the board's own modeSpec order.
PROGRAM_MODES = (
    'Convection',
    'TopHeatPluseConvection',
    'Conventional',
    'LargeGrill',
    'SmallGrill',
    'BottomHeatPluseConvection',
    'PlateWarm',
    'KeepWarm',
    'Bottom',
    'EcoConvection',
    'FanGrill',
    'Defrost',
)


# Samsung's operational state strings → OCF currentMachineState shape.
_SAMSUNG_STATE_TO_OCF = {
    'Ready':   'idle',
    'Run':     'active',
    'Running': 'active',
    'Pause':   'pause',
    'Paused':  'pause',
    'End':     'idle',
    'Stop':    'idle',
}


def _num(v):
    try: return float(v)
    except (TypeError, ValueError): return None


def _int(v):
    try: return int(v)
    except (TypeError, ValueError): return None


def _option_value(options, prefix, default=None):
    """Find `<prefix>_<value>` in an options array and return <value>."""
    for o in options:
        if o.startswith(prefix + '_'):
            return o.split('_', 1)[1]
    return default


def _replace_in_options(options, prefix, new_value):
    """Return a new options array with any `<prefix>_*` entry replaced
    by `<prefix>_<new_value>`. Caller must verify `options` is the live
    options array first (Samsung uses replace-not-merge on this field)."""
    return [f"{prefix}_{new_value}" if o.startswith(prefix + '_') else o
            for o in options]


def _hms_wire(minutes):
    """`HH:MM:SS` with a ZERO-PADDED hour — the appliance's wire format.

    Deliberately separate from _fmt_hms below, which formats display
    strings for the kitchen-timer sensors and leaves the hour unpadded.
    The two look interchangeable and are not: a single-digit hour is
    mis-parsed by the firmware, and writing '0:10:00' for a ten-minute
    cook produced a ten-hour one on hardware (2026-09-20). The measured
    start payload in docs/oven-cook-start.md is '00:01:00'.

    Anything writing operationTime or remainingTime must come through
    here; that these were two independent format expressions is how the
    divergence happened in the first place."""
    h, m = divmod(int(minutes), 60)
    return f"{h:02d}:{m:02d}:00"


def _fmt_hms(seconds):
    """Format an integer second count as `H:MM:SS`. Returns None on
    bad input so callers can leave the field null rather than emitting
    a misleading `0:00:00`."""
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return None
    if s < 0:
        s = 0
    h, rest = divmod(s, 3600)
    m, sec = divmod(rest, 60)
    return f"{h}:{m:02d}:{sec:02d}"


# ---------------------------------------------------------------------
# modeSpec — the board's own statement of what each mode will accept.
# `/mode/vs/0` carries it as a JSON *string*, one entry per mode, whose
# `control` field is the gate on remote start:
#
#   Start&Setting  remote start accepted
#   Setting        adjustable while running, not startable
#   NotSupported   neither
#
# See docs/oven-cook-start.md. Every bound below is read from the board
# rather than assumed, so a model with a different mode table gates
# itself correctly.
# ---------------------------------------------------------------------
_NOT_SUPPORTED = 'NotSupported'


def _spec_int(entry, key):
    v = entry.get(key)
    if v is None or v == _NOT_SUPPORTED:
        return None
    return _int(v)


def _hms_to_minutes(v):
    """'HH:MM:SS' → integer minutes, or None."""
    if not isinstance(v, str) or v == _NOT_SUPPORTED:
        return None
    try:
        h, m, s = v.split(':')
        return int(h) * 60 + int(m) + (1 if int(s) > 0 else 0)
    except (ValueError, AttributeError):
        return None


def parse_mode_spec(links):
    """{mode: {...bounds...}} from `/mode/vs/0`'s modeSpec.

    Returns {} when the resource is unseeded or the field is missing or
    unparseable, which callers must treat as "cannot start anything"
    rather than "no restrictions"."""
    raw = (links.get('/mode/vs/0') or {}).get('x.com.samsung.da.modeSpec')
    if not isinstance(raw, str):
        return {}
    try:
        entries = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(entries, list):
        return {}
    out = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        mode = e.get('mode')
        if not isinstance(mode, str):
            continue
        out[mode] = {
            'control':      e.get('control'),
            'startable':    e.get('control') == 'Start&Setting',
            'temp_min_c':   _spec_int(e, 'tempMinC'),
            'temp_max_c':   _spec_int(e, 'tempMaxC'),
            'temp_default_c': _spec_int(e, 'tempDefaultC'),
            'temp_step_c':  _spec_int(e, 'tempIntervalC') or SETPOINT_STEP_C,
            'time_min':     _hms_to_minutes(e.get('timeMin')),
            'time_max':     _hms_to_minutes(e.get('timeMax')),
            'time_default': _hms_to_minutes(e.get('timeDefault')),
        }
    return out


def startable_modes(links):
    """Modes the board says it will start, in the order it lists them."""
    return [m for m, s in parse_mode_spec(links).items() if s['startable']]


# ---------------------------------------------------------------------
# flatten — Samsung /device/0 links → HA-flavoured sensor dict.
# Every field reads from `/<x>/vs/0` paths so push updates immediately
# drive every entity. Where a field is settable (lamp, mode, setpoint),
# we publish it as a read-side sensor here AND as a writeable entity
# in build_discovery; the read side closes the HA UI feedback loop.
# ---------------------------------------------------------------------
def flatten(links):
    g = lambda href, k, default=None: (links.get(href) or {}).get(k, default)

    # Operational
    sam_state = g('/operational/state/vs/0', 'x.com.samsung.da.state')
    machine_state = (_SAMSUNG_STATE_TO_OCF.get(sam_state, sam_state)
                     if sam_state is not None else None)

    operation_time = g('/operational/state/vs/0',
                       'x.com.samsung.da.operationTime')
    remaining = g('/operational/state/vs/0',
                  'x.com.samsung.da.remainingTime')
    rem_min = None
    if remaining:
        try:
            h, m, s = remaining.split(':')
            rem_min = int(h) * 60 + int(m) + (1 if int(s) > 0 else 0)
        except Exception:
            pass
    # operationTime parsed as minutes — the source of truth for "Cook
    # time" in HA (mid-cycle SmartThings updates land here, not in
    # /mode/vs/0 UpperTimerSet which is vestigial).
    op_min = None
    if operation_time:
        try:
            h, m, s = operation_time.split(':')
            op_min = int(h) * 60 + int(m) + (1 if int(s) > 0 else 0)
        except Exception:
            pass

    # Cavity state — Cooking, Idle, Preheating, …
    oven_state = g('/oven/vs/0', 'x.com.samsung.da.state')

    # Temperatures
    temps_items = (g('/temperatures/vs/0',
                     'x.com.samsung.da.items') or [])
    cur_c = des_c = None
    if temps_items:
        cur_c = _int(temps_items[0].get('x.com.samsung.da.current'))
        des_c = _int(temps_items[0].get('x.com.samsung.da.desired'))
    # With no cycle set the oven reports desired=0. That means "no
    # setpoint", not a 0 °C target, and HA rejects it against the Number
    # entity's 30-270 range on every publish. Anything outside the
    # settable band is absent, not a value: null lands as unknown on both
    # the Number and the Setpoint sensor, the way completion_minutes
    # already reads when idle. _setpoint applies the same bounds on write.
    if des_c is not None and not (SETPOINT_MIN_C <= des_c <= SETPOINT_MAX_C):
        des_c = None

    # Door
    doors_items = g('/doors/vs/0', 'x.com.samsung.da.items') or []
    door = doors_items[0].get('x.com.samsung.da.openState') if doors_items else None
    door_open = (door == 'Open') if door is not None else None

    # Power
    sam_power = g('/power/vs/0', 'x.com.samsung.da.power')
    power_bin = (sam_power == 'On') if sam_power is not None else None

    # Kidslock + Remote
    sam_kids = g('/kidslock/vs/0', 'x.com.samsung.da.kidsLock')
    kids_bin = (sam_kids != 'Ready') if sam_kids is not None else None
    sam_rc = g('/remotectrl/vs/0',
               'x.com.samsung.da.remoteControlEnabled')
    rc_bin = (str(sam_rc).lower() == 'true') if sam_rc is not None else None

    # Mode + options
    modes = g('/mode/vs/0', 'x.com.samsung.da.modes') or []
    current_mode = modes[0] if modes else None
    options = g('/mode/vs/0', 'x.com.samsung.da.options') or []
    lamp = _option_value(options, 'UpperLamp')          # 'On' / 'Off'
    # The door-coupling override (open → On, close → Off) lives in
    # project() below — it needs descriptor_state to compare the
    # latest door transition against the latest lamp value change so
    # an HA-initiated optimistic write isn't clobbered by stale door
    # state.
    sound = _option_value(options, 'Sound')             # 'On' / 'Off'
    fastpreheat = _option_value(options, 'fastpreheat') # 'On' / 'Off'
    # NaturalSteam only appears in the options array after it's been
    # touched in the SmartThings app at least once. Until then it's
    # absent, so `_option_value` returns None — surface that as None
    # (HA renders as "Unknown") rather than "Off", which would falsely
    # imply we know it's disabled.
    natural_steam = _option_value(options, 'NaturalSteam')  # 'On' / 'Off' / None
    timer_state = _option_value(options, 'UpperTimerState')   # 'Ready' / 'Running'
    # UpperTimerCurrent/UpperTimerSet are integer seconds. Format as
    # H:MM:SS for HA display so users see "1:10:00", not "4200".
    timer_current_raw = _option_value(options, 'UpperTimerCurrent')
    timer_set_raw = _option_value(options, 'UpperTimerSet')
    timer_current = _fmt_hms(timer_current_raw)
    timer_set = _fmt_hms(timer_set_raw)
    timer_current_seconds = _int(timer_current_raw)
    timer_set_seconds = _int(timer_set_raw)

    # Alarms
    alarm_items = g('/alarms/vs/0', 'x.com.samsung.da.items') or []
    alarm_code = (alarm_items[0].get('x.com.samsung.da.code')
                  if alarm_items else None)
    alarm_time = (alarm_items[0].get('x.com.samsung.da.triggeredTime')
                  if alarm_items else None)
    # OV_E_OFF appears when the oven is off / no alarm; treat as inactive.
    alarm_active = bool(alarm_code) and alarm_code != 'OV_E_OFF'

    # Connectivity / firmware
    sam_connected = g('/connected/vs/0', 'x.com.samsung.da.connected')
    connected_bin = (sam_connected == 'On') if sam_connected is not None else None
    fw_update_available = g('/otninformation/vs/0',
                            'x.com.samsung.da.newVersionAvailable')
    fw_update_bin = (str(fw_update_available).lower() == 'true'
                     if fw_update_available is not None else None)

    return {
        # Popped by project_program() before publish — the parsed
        # modeSpec is how the staged program gets its bounds, and
        # project() has no link dict of its own.
        SPEC_KEY:                  parse_mode_spec(links),
        'machine_state':           machine_state,
        # `cycle_active` gates the writable controls in HA. The oven
        # only honours setpoint / cook-time / option writes (and Stop)
        # while a cycle is active — outside an active cycle, writes
        # return 2.04 but get rolled back within ~3s.
        'cycle_active':            machine_state == 'active',
        'oven_state':              oven_state,
        'progress_percentage':     _int(g('/operational/state/vs/0',
                                          'x.com.samsung.da.progressPercentage')),
        'operation_time':          operation_time,
        'operation_time_minutes':  op_min,
        'completion_time':         remaining,
        'completion_minutes':      rem_min,
        # The appliance's own remainingTime, published unmodified.
        # `completion_*` above is overwritten by project() with an
        # extrapolation while a cycle runs, which is right for a UI and
        # wrong for measuring what the appliance actually does — e.g.
        # whether the countdown holds during preheat. Keep both.
        'remaining_time':          remaining,
        'remaining_minutes':       rem_min,
        'current_temp_c':          cur_c,
        'target_temp_c':           des_c,
        'door':                    door,
        'door_open':               door_open,
        'power_state':             sam_power,
        'power_state_binary':      power_bin,
        'child_lock':              sam_kids,
        'child_lock_binary':       kids_bin,
        'remote_control':          sam_rc,
        'remote_control_binary':   rc_bin,
        'mode':                    current_mode,
        'lamp':                    lamp,
        'sound':                   sound,
        'fastpreheat':             fastpreheat,
        'natural_steam':           natural_steam,
        'timer_state':             timer_state,
        'timer_current':           timer_current,
        'timer_set':               timer_set,
        'timer_current_seconds':   timer_current_seconds,
        'timer_set_seconds':       timer_set_seconds,
        'alarm_code':              alarm_code,
        'alarm_time':              alarm_time,
        'alarm_active':            alarm_active,
        'connected':               sam_connected,
        'connected_binary':        connected_bin,
        'firmware_update_available': fw_update_bin,
    }


# ---------------------------------------------------------------------
# Remaining-time anchor + projection. The oven pushes /operational/state
# on state transitions but probably not on remainingTime ticks (matches
# dryer behaviour). Capture (ts, total_seconds) at each push and
# extrapolate downward while machine_state == active.
# ---------------------------------------------------------------------
def _hms_to_seconds(v):
    if not isinstance(v, str):
        return None
    try:
        h, m, s = v.split(':')
        return int(h) * 3600 + int(m) * 60 + int(s)
    except (ValueError, AttributeError):
        return None


def on_observation(state, href, rep):
    now = time.time()
    if href == '/operational/state/vs/0':
        total = _hms_to_seconds(rep.get('x.com.samsung.da.operationTime'))
        rem = _hms_to_seconds(rep.get('x.com.samsung.da.remainingTime'))
        prog = _int(rep.get('x.com.samsung.da.progressPercentage'))
        state['_total_s'] = total

        # Anchor only on a CHANGE, for the same reason the door and lamp
        # timestamps below do: this resource is polled twice a second
        # during a cycle, so re-anchoring on every update pins the
        # extrapolation to the value it was just given. The clock then
        # sits still for a whole granule and jumps — which is what it
        # did, because this used to anchor unconditionally.
        #
        # Anchoring on the transition also removes the quantisation: at
        # the instant remaining steps 600 → 540, remaining really is
        # 540, so the only error left is the polling interval.
        if rem != state.get('_rem_last'):
            state['_rem_last'] = rem
            if rem is not None:
                state['remaining_anchor'] = (now, rem)
        if prog != state.get('_prog_last'):
            state['_prog_last'] = prog
            if prog is not None:
                state['progress_anchor'] = (now, prog)

        # Drop the anchors when the cycle ends so the next one cannot
        # inherit them.
        sam = rep.get('x.com.samsung.da.state')
        if _SAMSUNG_STATE_TO_OCF.get(sam, sam) != 'active':
            for k in ('remaining_anchor', 'progress_anchor',
                      '_rem_last', '_prog_last'):
                state.pop(k, None)
        return
    # Door + lamp tracking feeds the lamp/door coupling in project().
    # Both timestamps bump only on value CHANGES so the comparison
    # tells us which event happened more recently. /doors is hot-tier
    # (1s) and would otherwise dominate; /mode is warm-tier (30s) and
    # picks up HA optimistic writes via apply_optimistic → apply_rep.
    if href == '/doors/vs/0':
        items = rep.get('x.com.samsung.da.items') or []
        door = items[0].get('x.com.samsung.da.openState') if items else None
        if door != state.get('_door_last'):
            state['_door_last'] = door
            state['_door_change_ts'] = now
        return
    if href == '/mode/vs/0':
        options = rep.get('x.com.samsung.da.options') or []
        lamp = _option_value(options, 'UpperLamp')
        if lamp != state.get('_lamp_last'):
            state['_lamp_last'] = lamp
            state['_lamp_change_ts'] = now


def estimate_remaining(state, now):
    """(seconds_remaining, source) for the cook clock, or (None, None).

    Two fields describe the same clock at different resolutions:

      remainingTime        steps once a minute, so 60s granularity
      progressPercentage   steps once per 1% of the cook, so the
                           granularity is total/100

    Progress is the finer of the two for any cook under 100 minutes,
    which is most of them: 6s on a ten-minute bake against 60s. Past
    that the arithmetic inverts and remainingTime wins, so this picks
    whichever is actually finer for the duration in hand rather than
    always preferring one. `clock_source` says which was used.

    Both were measured to be the same clock, running from the moment of
    Start and through preheat rather than from reaching temperature
    (local-tools/watch_preheat.py, 2026-09-20): a 10-minute cook ticked
    remaining down 60s per wall minute while progress moved 1% per 6s,
    implying the same 10-minute total.

    Whichever source is chosen, the value is extrapolated by wall clock
    from its last change, so the published clock advances every second
    instead of once per granule."""
    total = state.get('_total_s')
    cands = []

    pa = state.get('progress_anchor')
    if total and pa is not None:
        ts, pct = pa
        if pct is not None:
            cands.append(('progress', total / 100.0,
                          total * (100 - pct) / 100.0 - (now - ts)))

    ra = state.get('remaining_anchor')
    if ra is not None:
        ts, secs = ra
        if secs is not None:
            cands.append(('remaining', 60.0, secs - (now - ts)))

    if not cands:
        return None, None
    source, _granule, value = min(cands, key=lambda c: c[1])
    value = max(0, int(round(value)))
    if total:
        value = min(value, total)
    return value, source


def project(state, sensors):
    sensors = dict(sensors)
    # Remaining-time projection: the oven pushes /operational/state on
    # state transitions but not on remainingTime ticks. Extrapolate
    # from the most recent anchor while the machine is active.
    if sensors.get('machine_state') == 'active':
        now = time.time()
        remaining, source = estimate_remaining(state, now)
        if remaining is not None:
            h, rest = divmod(remaining, 3600)
            m, s = divmod(rest, 60)
            sensors['completion_time'] = f"{h}:{m:02d}:{s:02d}"
            sensors['completion_minutes'] = h * 60 + m + (1 if s > 0 else 0)
            sensors['clock_source'] = source
            # An absolute finish time rather than a ticking countdown.
            # HA renders a `timestamp` sensor as a live relative time,
            # so the UI counts down every second on its own while this
            # value stays CONSTANT between anchor changes — it is
            # anchor_ts + anchored_remaining, which does not move as
            # `now` advances.
            #
            # That matters because the bridge republishes the whole
            # state topic whenever any field changes. A per-second
            # countdown here would republish twice a second for the
            # length of every cook and write a recorder row per sensor
            # each time, to show what the frontend can derive for free.
            sensors['finish_at'] = datetime.fromtimestamp(
                now + remaining, tz=timezone.utc).isoformat(
                    timespec='seconds')
    # Lamp / door coupling. The oven hardware auto-drives the lamp from
    # the door state, but /mode/vs/0 only polls every 30s. When a door
    # TRANSITION is more recent than the last lamp VALUE change, derive
    # lamp from door for sub-second freshness. When a lamp toggle is
    # more recent (HA optimistic write, or panel-driven /mode diff),
    # the cache value wins — preserves HA toggle responsiveness even
    # while the door is closed.
    door_ts = state.get('_door_change_ts')
    lamp_ts = state.get('_lamp_change_ts')
    door_open = sensors.get('door_open')
    if door_ts is not None and (lamp_ts is None or door_ts > lamp_ts):
        if door_open is True:
            sensors['lamp'] = 'On'
        elif door_open is False:
            sensors['lamp'] = 'Off'
    return project_program(state, sensors)


def log_state_change(sensors):
    return (f"machine={sensors.get('machine_state')} "
            f"oven={sensors.get('oven_state')} "
            f"temp={sensors.get('current_temp_c')}/"
            f"{sensors.get('target_temp_c')}°C "
            f"mode={sensors.get('mode')} "
            f"timer_set={sensors.get('timer_set_seconds')} "
            f"timer_cur={sensors.get('timer_current_seconds')}")


# ---------------------------------------------------------------------
# HA discovery inventory
# ---------------------------------------------------------------------
MODEL = 'OCF oven (TizenRT-iotivity, NV7000BS-class)'

# (key, friendly name, extra config)
#
# Only read-only sensors live here. Fields that ALSO have an
# interactive entity (light, switch, number, select) are removed —
# the interactive entity already surfaces the live state, so a
# duplicate read-only "Lamp state" / "Fast preheat state" / etc.
# sensor would just clutter the device card with the same value
# twice.
_SENSORS = [
    ('machine_state',       'Machine state',        {'icon': 'mdi:stove'}),
    ('oven_state',          'Cavity state',         {}),
    # Cooking mode is read-only via local OCF — the oven owns the
    # `modes` field once a cycle is active and rolls back any writes.
    ('mode',                'Cooking mode',         {'icon': 'mdi:tune'}),
    ('progress_percentage', 'Progress percent',
        {'unit_of_measurement': '%', 'state_class': 'measurement'}),
    ('operation_time',      'Elapsed time',         {'icon': 'mdi:timer'}),
    ('completion_time',     'Completion time',      {'icon': 'mdi:timer-sand'}),
    ('completion_minutes',  'Remaining minutes',
        {'unit_of_measurement': 'min', 'device_class': 'duration',
         'state_class': 'measurement'}),
    # Absolute finish time. HA turns a timestamp sensor into a live
    # relative countdown, which is the smooth clock; the fields above
    # stay minute-resolution so they do not churn the recorder.
    ('finish_at',           'Finishes at',
        {'device_class': 'timestamp'}),
    # Which field drove the clock — progress on a short cook, remaining
    # on a long one. Diagnostic: it answers "why did the estimate jump"
    # without needing the bridge log.
    ('clock_source',        'Clock source',
        {'icon': 'mdi:timer-cog-outline', 'entity_category': 'diagnostic'}),
    ('current_temp_c',      'Temperature',
        {'unit_of_measurement': '°C', 'device_class': 'temperature',
         'state_class': 'measurement'}),
    # target_temp_c is also exposed as a Number entity for editing,
    # but the Number is RC-gated. The sensor stays always-visible so
    # the user can see the current setpoint even with Remote Control
    # off at the oven.
    ('target_temp_c',       'Setpoint',
        {'unit_of_measurement': '°C', 'device_class': 'temperature',
         'state_class': 'measurement', 'icon': 'mdi:thermometer-chevron-up'}),
    # power_state: read-only. The oven doesn't expose a meaningful
    # POST /power/vs/0 from cold — turning the unit on at the panel
    # is a physical action — so we don't ship a Power switch entity.
    ('power_state',         'Power state',          {'icon': 'mdi:power'}),
    ('door',                'Door state',           {}),
    ('child_lock',          'Child lock state',     {}),
    ('remote_control',      'Remote control state', {}),
    ('timer_state',         'Timer state',          {}),
    ('timer_current',       'Timer remaining',      {'icon': 'mdi:timer-sand'}),
    ('timer_set',           'Timer set',            {'icon': 'mdi:timer'}),
    ('alarm_code',          'Alarm code',
        {'icon': 'mdi:alert', 'entity_category': 'diagnostic'}),
    ('alarm_time',          'Alarm time',
        {'icon': 'mdi:clock-alert', 'entity_category': 'diagnostic'}),
    ('connected',           'Cloud connectivity',
        {'entity_category': 'diagnostic'}),
]

# (key, friendly, value_template, device_class, extras)
_BINARY_SENSORS = [
    ('running', 'Running',
        "{{ 'ON' if value_json.machine_state == 'active' else 'OFF' }}",
        'running', {}),
    ('door_open', 'Door',
        "{{ 'ON' if value_json.door_open else 'OFF' }}",
        'door', {}),
    # `power_switch` binary_sensor would duplicate the Power switch
    # entity below; the switch already shows on/off state.
    ('child_lock_active', 'Child lock',
        "{{ 'ON' if value_json.child_lock_binary else 'OFF' }}",
        'lock', {}),
    ('remote_control_enabled', 'Remote control',
        "{{ 'ON' if value_json.remote_control_binary else 'OFF' }}",
        'connectivity', {}),
    ('alarm_active', 'Alarm active',
        "{{ 'ON' if value_json.alarm_active else 'OFF' }}",
        'problem', {}),
    ('connected_bin', 'Connected',
        "{{ 'ON' if value_json.connected_binary else 'OFF' }}",
        'connectivity', {'entity_category': 'diagnostic'}),
    ('firmware_update_available', 'Firmware update available',
        "{{ 'ON' if value_json.firmware_update_available else 'OFF' }}",
        'update', {'entity_category': 'diagnostic'}),
]


# MQTT command-topic suffixes (under <prefix>/cmd/…)
CMD_LAMP         = 'cmd/lamp'
CMD_SOUND        = 'cmd/sound'
CMD_FASTPREHEAT  = 'cmd/fastpreheat'
CMD_NATURALSTEAM = 'cmd/naturalsteam'
CMD_POWER        = 'cmd/power'
CMD_STOP         = 'cmd/stop'
CMD_SETPOINT     = 'cmd/setpoint'
CMD_COOK_TIME    = 'cmd/cook_time'
CMD_PROG_MODE    = 'cmd/program_mode'
CMD_PROG_TEMP    = 'cmd/program_temp'
CMD_PROG_TIME    = 'cmd/program_time'
CMD_START        = 'cmd/start'
CMD_START_PROGRAM = 'cmd/start_program'
# NOTE — no CMD_START or CMD_MODE. Reverse-engineered 2026-05-31:
#   * `state='Run'` writes to /operational/state/vs/0 are accepted
#     (2.04) and machine briefly goes active, but the oven cavity
#     stays Ready (no Preheat) and the cycle self-cancels within
#     ~3s. Tried every byte-level approximation of SmartThings's
#     working start (matching all four fields on /operational/state,
#     +operationTime, +remainingTime, +progressPercentage='1', plus
#     /temperatures/vs/0 desired, with and without /mode/vs/0 modes,
#     with PUT vs POST, paced 1s apart, with OCF-version-options
#     2049/2053, with Samsung vendor-option 65524=0xc0) — none of
#     these engage the cavity. The differentiator must be something
#     invisible at the OBSERVE-push level (likely a cloud-mediated
#     auth path the SmartThings app uses). See project_oven_remote
#     _start_open.md for full notes.
#   * `modes=['Convection']` writes to /mode/vs/0 succeed (2.04)
#     but the oven owns the field once a cycle is active and rolls
#     local writes back to ['NoOperation']. mode is surfaced as a
#     read-only sensor instead.


def build_discovery(topic_prefix, ha_prefix, device_name):
    state_topic   = f"{topic_prefix}/state"
    avail_topic   = f"{topic_prefix}/availability"
    remote_topic  = f"{topic_prefix}/remote_available"
    cycle_topic   = f"{topic_prefix}/cycle_active"
    dev = device_block(topic_prefix, device_name, MODEL)
    out = []

    # --- read-only sensors -------------------------------------------
    for key, name, extra in _SENSORS:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{key}",
            'object_id':      f"{topic_prefix}_{key}",
            'state_topic':    state_topic,
            'value_template': f"{{{{ value_json.{key} }}}}",
            'availability':   avail_base(avail_topic),
            'device':         dev,
        }
        cfg.update(extra)
        out.append((f"{ha_prefix}/sensor/{topic_prefix}/{key}/config",
                    encode(cfg)))

    for key, name, template, dclass, extra in _BINARY_SENSORS:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{key}",
            'object_id':      f"{topic_prefix}_{key}",
            'state_topic':    state_topic,
            'value_template': template,
            'payload_on':     'ON',
            'payload_off':    'OFF',
            'device_class':   dclass,
            'availability':   avail_base(avail_topic),
            'device':         dev,
        }
        cfg.update(extra)
        out.append((f"{ha_prefix}/binary_sensor/{topic_prefix}/{key}/config",
                    encode(cfg)))

    # --- light: oven lamp (proven via probe_oven_lamp_states.py;
    # binary On/Off only — High/Low/Dim coerce back to previous
    # state. Works regardless of Remote Control switch, so we only
    # gate on base availability). For the MQTT light default schema,
    # state_value_template's output must match payload_on/payload_off
    # exactly (case-sensitive) for HA to recognise the state.
    cfg = {
        'name':                 'Lamp',
        'unique_id':            f"{topic_prefix}_lamp_light",
        'object_id':            f"{topic_prefix}_lamp_light",
        'state_topic':          state_topic,
        'state_value_template': "{{ value_json.lamp }}",
        'command_topic':        f"{topic_prefix}/{CMD_LAMP}",
        'payload_on':           'On',
        'payload_off':          'Off',
        'icon':                 'mdi:track-light',
        'availability':         avail_base(avail_topic),
        'device':               dev,
    }
    out.append((f"{ha_prefix}/light/{topic_prefix}/lamp/config",
                encode(cfg)))

    # --- switches. Sound is always-available — independent of cycle
    # state, no RC required. Fast preheat + Natural steam are
    # options-array writes the oven only honours mid-cycle, so they
    # gate on RC + cycle_active. Power deliberately omitted: turning
    # the oven on is a physical-panel action; read-only power_state
    # sensor reflects its state.
    cfg = {
        'name':           'Sound',
        'unique_id':      f"{topic_prefix}_sound_switch",
        'object_id':      f"{topic_prefix}_sound_switch",
        'state_topic':    state_topic,
        'value_template': '{{ value_json.sound }}',
        'state_on':       'On',
        'state_off':      'Off',
        'command_topic':  f"{topic_prefix}/{CMD_SOUND}",
        'payload_on':     'On',
        'payload_off':    'Off',
        'icon':           'mdi:volume-high',
        'availability':   avail_base(avail_topic),
        'device':         dev,
    }
    out.append((f"{ha_prefix}/switch/{topic_prefix}/sound/config",
                encode(cfg)))

    cycle_switches = [
        ('fastpreheat',   'Fast preheat',  '{{ value_json.fastpreheat }}',   CMD_FASTPREHEAT,  'mdi:fire'),
        ('natural_steam', 'Natural steam', '{{ value_json.natural_steam }}', CMD_NATURALSTEAM, 'mdi:kettle-steam'),
    ]
    for key, name, tpl, cmd, icon in cycle_switches:
        cfg = {
            'name':              name,
            'unique_id':         f"{topic_prefix}_{key}_switch",
            'object_id':         f"{topic_prefix}_{key}_switch",
            'state_topic':       state_topic,
            'value_template':    tpl,
            'state_on':          'On',
            'state_off':         'Off',
            'command_topic':     f"{topic_prefix}/{cmd}",
            'payload_on':        'On',
            'payload_off':       'Off',
            'icon':              icon,
            'availability':      avail_with_remote_and_cycle(
                                     avail_topic, remote_topic, cycle_topic),
            'availability_mode': 'all',
            'device':            dev,
        }
        out.append((f"{ha_prefix}/switch/{topic_prefix}/{key}/config",
                    encode(cfg)))

    # --- number: setpoint (RC-gated, slider input) ------------------
    cfg = {
        'name':              'Setpoint',
        'unique_id':         f"{topic_prefix}_setpoint",
        'object_id':         f"{topic_prefix}_setpoint",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.target_temp_c }}',
        'command_topic':     f"{topic_prefix}/{CMD_SETPOINT}",
        'min':               SETPOINT_MIN_C,
        'max':               SETPOINT_MAX_C,
        'step':              SETPOINT_STEP_C,
        'unit_of_measurement': '°C',
        'device_class':      'temperature',
        'mode':              'slider',
        'icon':              'mdi:thermometer-chevron-up',
        # RC + cycle_active gated — Samsung's local-OCF surface only
        # honours setpoint changes while a cycle is actually running
        # (idle writes get rolled back within ~3s).
        'availability':      avail_with_remote_and_cycle(
                                 avail_topic, remote_topic, cycle_topic),
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/number/{topic_prefix}/setpoint/config",
                encode(cfg)))

    # --- button: Stop cycle ----------------------------------------
    # Gated on cycle_active — there's nothing to stop when idle.
    # There is no Start button: local-OCF cycle start is not
    # reproducible on this firmware (see project_oven_remote_start
    # _open.md memory note for the full investigation). Cooking mode
    # is similarly omitted — read-only via local OCF, surfaced as a
    # sensor.
    cfg = {
        'name':              'Stop cycle',
        'unique_id':         f"{topic_prefix}_stop",
        'object_id':         f"{topic_prefix}_stop",
        'command_topic':     f"{topic_prefix}/{CMD_STOP}",
        'payload_press':     'Stop',
        'icon':              'mdi:stop',
        'availability':      avail_with_cycle(avail_topic, cycle_topic),
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/button/{topic_prefix}/stop/config",
                encode(cfg)))

    # --- number: Cook time in minutes (RC + cycle gated; the oven
    # only honours operationTime writes while running). Source of
    # truth is `operationTime` on /operational/state/vs/0;
    # SmartThings's mid-cycle time changes land in that same field.
    cfg = {
        'name':              'Cook time',
        'unique_id':         f"{topic_prefix}_cook_time",
        'object_id':         f"{topic_prefix}_cook_time",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.operation_time_minutes | int(0) }}',
        'command_topic':     f"{topic_prefix}/{CMD_COOK_TIME}",
        'min':               0,
        'max':               1439,    # 23:59 — matches modeSpec timeMax
        'step':              1,
        'unit_of_measurement': 'min',
        'mode':              'box',
        'icon':              'mdi:timer',
        'availability':      avail_with_remote_and_cycle(
                                 avail_topic, remote_topic, cycle_topic),
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/number/{topic_prefix}/cook_time/config",
                encode(cfg)))

    # --- staged cook program (idle-only) ----------------------------
    # A cook start is one batch write carrying mode, setpoint and cook
    # time together, so these three entities stage a program in the
    # bridge and the Start button sends it. They are the mirror image
    # of Setpoint / Cook time above: those are live and cycle-gated,
    # these are idle-gated, so exactly one pair is ever actionable and
    # neither control ever changes meaning under the user.
    prog_avail = avail_with_remote_and_idle(
        avail_topic, remote_topic, cycle_topic)

    cfg = {
        'name':              'Program',
        'unique_id':         f"{topic_prefix}_program",
        'object_id':         f"{topic_prefix}_program",
        'state_topic':       state_topic,
        'value_template':    "{{ value_json.program_mode if value_json.program_mode else 'None' }}",
        'command_topic':     f"{topic_prefix}/{CMD_PROG_MODE}",
        # Fixed at discovery time, before any resource has been read, so
        # this is the class-wide list. The board's live answer is
        # published as `program_startable` and is what Start validates
        # against, so an option this unit cannot start is refused with a
        # reason rather than sent.
        'options':           ['None'] + list(PROGRAM_MODES),
        'icon':              'mdi:chef-hat',
        'availability':      prog_avail,
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/select/{topic_prefix}/program/config",
                encode(cfg)))

    cfg = {
        'name':              'Program temperature',
        'unique_id':         f"{topic_prefix}_program_temp",
        'object_id':         f"{topic_prefix}_program_temp",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.program_temp_c if value_json.program_temp_c is not none else 0 }}',
        'command_topic':     f"{topic_prefix}/{CMD_PROG_TEMP}",
        # Union bounds across the class; the selected mode's own
        # tempMinC/tempMaxC are the real check and are applied at Start.
        'min':               SETPOINT_MIN_C,
        'max':               SETPOINT_MAX_C,
        'step':              SETPOINT_STEP_C,
        'unit_of_measurement': '°C',
        'device_class':      'temperature',
        'mode':              'box',
        'icon':              'mdi:thermometer',
        'availability':      prog_avail,
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/number/{topic_prefix}/program_temp/config",
                encode(cfg)))

    cfg = {
        'name':              'Program duration',
        'unique_id':         f"{topic_prefix}_program_time",
        'object_id':         f"{topic_prefix}_program_time",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.program_minutes if value_json.program_minutes is not none else 0 }}',
        'command_topic':     f"{topic_prefix}/{CMD_PROG_TIME}",
        'min':               1,
        'max':               1439,
        'step':              1,
        'unit_of_measurement': 'min',
        'mode':              'box',
        'icon':              'mdi:timer-outline',
        'availability':      prog_avail,
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/number/{topic_prefix}/program_time/config",
                encode(cfg)))

    # --- button: Start ----------------------------------------------
    # Momentary by design: a switch could be left latched, and this one
    # makes an appliance heat. Availability covers bridge up, Remote
    # Control on and no cycle running; the staged program is checked
    # against the board's own modeSpec when pressed, so a program the
    # board will not start is refused with a logged reason.
    #
    # For a confirmation step, set `confirmation` on the Lovelace
    # button card — MQTT discovery has no equivalent.
    cfg = {
        'name':              'Start',
        'unique_id':         f"{topic_prefix}_start",
        'object_id':         f"{topic_prefix}_start",
        'command_topic':     f"{topic_prefix}/{CMD_START}",
        'payload_press':     'Start',
        'icon':              'mdi:play',
        'availability':      prog_avail,
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/button/{topic_prefix}/start/config",
                encode(cfg)))

    # --- removal: publish empty payload to the discovery topics of
    # entities we used to expose. HA treats an empty retained payload
    # on a discovery topic as "delete this entity", so the old
    # read-only Cooking-mode select disappears cleanly.
    out.append((f"{ha_prefix}/select/{topic_prefix}/mode/config",  b''))

    return out


# ---------------------------------------------------------------------
# Staged cook program.
#
# A cook start is one OCF batch write carrying mode, setpoint and cook
# time together — the appliance will not assemble a job from separate
# writes while it is idle (docs/oven-cook-start.md). HA entities write
# independently, so the three parameters are staged in bridge-local
# state and the Start button assembles the batch.
#
# The program lives in the descriptor state dict, which is the same
# dict threaded into on_observation and project, so project() can
# publish the staged values back for the entities to display.
# ---------------------------------------------------------------------
PROGRAM_KEY = 'program'

#: flatten() stashes the parsed modeSpec here so project() can reach it
#: without needing the link dict; project_program() pops it before the
#: sensor dict is published, so it never reaches MQTT.
SPEC_KEY = '_mode_spec'


def _program(state):
    prog = state.get(PROGRAM_KEY)
    if prog is None:
        prog = state[PROGRAM_KEY] = {'mode': None, 'temp_c': None,
                                     'minutes': None}
    return prog


def _apply_mode_defaults(prog, spec):
    """Adopt a mode's own default temperature and duration.

    Called when the staged mode changes, so picking a program lands the
    board's defaults the way selecting it on the panel does, instead of
    carrying the previous mode's numbers into one whose range may not
    even contain them."""
    prog['temp_c'] = spec.get('temp_default_c')
    prog['minutes'] = spec.get('time_default')


def project_program(state, sensors):
    """Publish the staged program plus the bounds it is checked against.

    `program_startable` is what the board declares right now, which is
    what the Start button actually validates against. The select's
    options are fixed at discovery time and cannot track it, so
    publishing it gives an automation — and anyone reading the state
    topic — the real answer."""
    prog = _program(state)
    spec_all = sensors.pop(SPEC_KEY, None) or {}
    spec = spec_all.get(prog['mode'] or '', {})
    sensors['program_mode'] = prog['mode']
    sensors['program_temp_c'] = prog['temp_c']
    sensors['program_minutes'] = prog['minutes']
    sensors['program_startable'] = sorted(
        m for m, s in spec_all.items() if s['startable'])
    sensors['program_temp_min_c'] = spec.get('temp_min_c')
    sensors['program_temp_max_c'] = spec.get('temp_max_c')
    sensors['program_time_min'] = spec.get('time_min')
    sensors['program_time_max'] = spec.get('time_max')
    sensors['program_ready'] = _program_error(
        prog, spec_all, sensors) is None
    return sensors


def _program_error(prog, spec_all, sensors):
    """None when the staged program can be sent, else why not.

    Every bound is the board's own. Checking here rather than letting
    the firmware refuse means the reason reaches the log as a sentence
    instead of a bare 4.xx."""
    mode = prog.get('mode')
    if not mode:
        return 'no program selected'
    if not spec_all:
        return ('the board publishes no modeSpec, so it declares no '
                'startable mode')
    spec = spec_all.get(mode)
    if spec is None:
        return f'{mode} is not a mode this board reports'
    if not spec['startable']:
        return (f"the board declares {mode} as {spec['control']!r}, "
                f"not Start&Setting")

    temp = prog.get('temp_c')
    lo, hi = spec['temp_min_c'], spec['temp_max_c']
    if lo is not None or hi is not None:
        if temp is None:
            return f'{mode} needs a temperature'
        if lo is not None and temp < lo:
            return f'{temp}C is below {mode} minimum {lo}C'
        if hi is not None and temp > hi:
            return f'{temp}C is above {mode} maximum {hi}C'

    mins = prog.get('minutes')
    tlo, thi = spec['time_min'], spec['time_max']
    if tlo is not None or thi is not None:
        if mins is None:
            return f'{mode} needs a duration'
        if tlo is not None and mins < tlo:
            return f'{mins}min is below {mode} minimum {tlo}min'
        if thi is not None and mins > thi:
            return f'{mins}min is above {mode} maximum {thi}min'

    if not sensors.get('remote_control_binary'):
        return 'Remote Control is off at the appliance'
    if sensors.get('machine_state') == 'active':
        return 'a cycle is already running'
    return None


def build_start_batch(prog, spec_all, links):
    """The OCF batch that starts a cook.

    Shape and field names are the measured ones from
    docs/oven-cook-start.md: a bare `/devices/0` marker first, then one
    element per resource, with the run command carried inside the
    `/operational/state/vs/0` element rather than sent separately."""
    mode = prog['mode']
    spec = spec_all.get(mode, {})
    batch = [
        {'href': '/devices/0'},
        {'href': '/mode/vs/0',
         'rep': {'x.com.samsung.da.modes': [mode]}},
    ]
    # Modes whose spec reports no temperature range take no setpoint
    # element; sending one would be inventing a field the board did not
    # advertise for that mode.
    if spec.get('temp_min_c') is not None or spec.get('temp_max_c') is not None:
        items = _temps_items(links) or [{}]
        unit = items[0].get('x.com.samsung.da.unit') or 'Celsius'
        batch.append({
            'href': '/temperatures/vs/0',
            'rep': {'x.com.samsung.da.items': [{
                'x.com.samsung.da.desired': str(prog['temp_c']),
                'x.com.samsung.da.id':      '0',
                'x.com.samsung.da.unit':    unit,
            }]},
        })
    op_rep = {'x.com.samsung.da.state': 'Run'}
    if prog.get('minutes') is not None:
        op_rep['x.com.samsung.da.operationTime'] = _hms_wire(prog['minutes'])
    batch.append({'href': '/operational/state/vs/0', 'rep': op_rep})
    return batch


# ---------------------------------------------------------------------
# Command handlers — fn(payload, links) → (path_segs, body_dict) | None.
# Read-modify-write handlers (lamp/sound/fastpreheat) snapshot the
# `/mode/vs/0` options array and replace just their slot. /temperatures
# is also RMW because Samsung's write semantics on the items array are
# replace-not-merge.
# ---------------------------------------------------------------------
def _mode_options(links):
    """Return the live `/mode/vs/0` options array (a copy), or None
    if /mode/vs/0 isn't seeded yet."""
    rep = links.get('/mode/vs/0') or {}
    opts = rep.get('x.com.samsung.da.options')
    if not opts:
        return None
    return list(opts)


def _temps_items(links):
    """Return a deep-ish copy of the /temperatures/vs/0 items array."""
    rep = links.get('/temperatures/vs/0') or {}
    items = rep.get('x.com.samsung.da.items') or []
    return [dict(it) for it in items] if items else None


def command_handlers(state=None):
    """Handlers for this appliance class.

    `state` is the descriptor state dict; the staged cook program lives
    in it so project() can publish it. It defaults to None so a test can
    build the read-modify-write handlers without one."""
    state = {} if state is None else state

    # --- staged program -------------------------------------------
    # These four change bridge-local state only and send nothing, so
    # they return LOCAL_ONLY rather than None; None means rejected.

    def _program_mode(p, links):
        prog = _program(state)
        if p in ('None', '', 'none'):
            prog.update(mode=None, temp_c=None, minutes=None)
            return LOCAL_ONLY
        if p not in PROGRAM_MODES:
            return None
        prog['mode'] = p
        # Adopt the board's own defaults for the new mode where it
        # publishes them, so the staged numbers are always inside the
        # range they will be checked against.
        spec = parse_mode_spec(links).get(p)
        if spec is not None:
            _apply_mode_defaults(prog, spec)
        return LOCAL_ONLY

    def _program_temp(p, _links):
        v = _int(_num(p))
        if v is None:
            return None
        _program(state)['temp_c'] = v
        return LOCAL_ONLY

    def _program_time(p, _links):
        v = _int(_num(p))
        if v is None or v < 0:
            return None
        _program(state)['minutes'] = v
        return LOCAL_ONLY

    def _start(_p, links):
        prog = _program(state)
        spec_all = parse_mode_spec(links)
        why = _program_error(prog, spec_all, flatten(links))
        if why is not None:
            log.warning("start refused: %s", why)
            return None
        log.info("starting cook: %s %sC %smin",
                 prog['mode'], prog['temp_c'], prog['minutes'])
        return ['device', '0'], build_start_batch(prog, spec_all, links)

    def _start_program(p, links):
        """Stage and start in one message, for automations.

        The entity path needs four interactions to start a cook, which
        is right for a person and wrong for an automation. This takes
        {"mode": ..., "temp_c": ..., "minutes": ...} and does the lot,
        the same shape HA core's Miele integration uses for
        miele.set_program_oven. Omitted temperature or duration fall
        back to the mode's own defaults."""
        try:
            req = json.loads(p)
        except (ValueError, TypeError):
            log.warning("start_program: payload is not JSON: %r", p)
            return None
        if not isinstance(req, dict):
            log.warning("start_program: payload is not an object: %r", p)
            return None
        mode = req.get('mode')
        if mode not in PROGRAM_MODES:
            log.warning("start_program: unknown mode %r", mode)
            return None
        spec_all = parse_mode_spec(links)
        prog = dict(_program(state))
        prog['mode'] = mode
        spec = spec_all.get(mode)
        if spec is not None:
            _apply_mode_defaults(prog, spec)
        if 'temp_c' in req:
            prog['temp_c'] = _int(_num(req.get('temp_c')))
        if 'minutes' in req:
            prog['minutes'] = _int(_num(req.get('minutes')))
        why = _program_error(prog, spec_all, flatten(links))
        if why is not None:
            log.warning("start_program refused: %s", why)
            return None
        # Only adopt it as the staged program once it has passed, so a
        # rejected automation does not leave a bad program in the UI.
        _program(state).update(prog)
        log.info("start_program: %s %sC %smin",
                 prog['mode'], prog['temp_c'], prog['minutes'])
        return ['device', '0'], build_start_batch(prog, spec_all, links)

    def _lamp(p, links):
        if p not in ('On', 'Off'):
            return None
        opts = _mode_options(links)
        if opts is None:
            return None
        return ['mode', 'vs', '0'], {
            'x.com.samsung.da.options': _replace_in_options(opts, 'UpperLamp', p),
        }

    def _sound(p, links):
        if p not in ('On', 'Off'):
            return None
        opts = _mode_options(links)
        if opts is None:
            return None
        return ['mode', 'vs', '0'], {
            'x.com.samsung.da.options': _replace_in_options(opts, 'Sound', p),
        }

    def _fastpreheat(p, links):
        if p not in ('On', 'Off'):
            return None
        opts = _mode_options(links)
        if opts is None:
            return None
        return ['mode', 'vs', '0'], {
            'x.com.samsung.da.options': _replace_in_options(
                opts, 'fastpreheat', p),
        }

    def _naturalsteam(p, links):
        # NaturalSteam_* only appears in the options array after the
        # SmartThings app has touched it once. If absent, append the
        # slot — the oven creates it on first write, so the bridge
        # doesn't need a "prime via app" dance.
        if p not in ('On', 'Off'):
            return None
        opts = _mode_options(links)
        if opts is None:
            return None
        if not any(o.startswith('NaturalSteam_') for o in opts):
            opts = opts + [f'NaturalSteam_{p}']
        else:
            opts = _replace_in_options(opts, 'NaturalSteam', p)
        return ['mode', 'vs', '0'], {
            'x.com.samsung.da.options': opts,
        }

    def _power(p, _links):
        if p not in ('On', 'Off'):
            return None
        return ['power', 'vs', '0'], {'x.com.samsung.da.power': p}

    def _stop(_p, _links):
        return ['operational', 'state', 'vs', '0'], {
            'x.com.samsung.da.state': 'Ready',
        }

    def _setpoint(p, links):
        try:
            temp = float(p)
        except (TypeError, ValueError):
            return None
        temp_i = int(round(temp / SETPOINT_STEP_C) * SETPOINT_STEP_C)
        if not (SETPOINT_MIN_C <= temp_i <= SETPOINT_MAX_C):
            return None
        items = _temps_items(links)
        if items is None:
            return None
        items[0]['x.com.samsung.da.desired'] = str(temp_i)
        return ['temperatures', 'vs', '0'], {
            'x.com.samsung.da.items': items,
        }

    def _cook_time(p, links):
        # HA sends minutes; oven cycle duration lives in
        # /operational/state/vs/0 as `operationTime` / `remainingTime`
        # (H:MM:SS strings). Writing both — mirroring SmartThings's
        # observed behaviour, which resets the live countdown to the
        # new duration. Clamp to modeSpec's 0..23:59.
        try:
            minutes = int(round(float(p)))
        except (TypeError, ValueError):
            return None
        if not (0 <= minutes <= 1439):
            return None
        hms = _hms_wire(minutes)
        return ['operational', 'state', 'vs', '0'], {
            'x.com.samsung.da.operationTime': hms,
            'x.com.samsung.da.remainingTime': hms,
        }

    return {
        CMD_LAMP:         _lamp,
        CMD_SOUND:        _sound,
        CMD_FASTPREHEAT:  _fastpreheat,
        CMD_NATURALSTEAM: _naturalsteam,
        CMD_POWER:        _power,
        CMD_STOP:         _stop,
        CMD_SETPOINT:     _setpoint,
        CMD_COOK_TIME:    _cook_time,
        CMD_PROG_MODE:    _program_mode,
        CMD_PROG_TEMP:    _program_temp,
        CMD_PROG_TIME:    _program_time,
        CMD_START:        _start,
        CMD_START_PROGRAM: _start_program,
    }


# --- Poll tiers --------------------------------------------------------
# Empirical ceiling on this firmware is ~8 req/s (probe_poll_rate_combined.py
# 2026-06-03). Hot tier covers what changes mid-cook; doors get the tightest
# cadence because door open/close needs sub-second freshness in HA.
# Per-tier timeouts are scaled to cadence: hot tier retries every 1s, so
# a tight 2s ceiling caps the cascade damage from one wedged poll. Warm
# and cold tiers have more headroom; sweep is multi-block Block2 and
# tolerates ~15s.
OVEN_POLL_TIERS = [
    PollTier(
        name='hot',
        interval_s=1.0,
        active_interval_s=0.5,
        timeout_s=2.0,
        paths=(
            ('operational', 'state', 'vs', '0'),
            ('doors', 'vs', '0'),
            ('oven', 'vs', '0'),
            ('temperatures', 'vs', '0'),
        ),
    ),
    PollTier(
        name='warm',
        interval_s=30.0,
        timeout_s=4.0,
        paths=(
            ('power', 'vs', '0'),
            ('kidslock', 'vs', '0'),
            ('remotectrl', 'vs', '0'),
            ('mode', 'vs', '0'),
            ('alarms', 'vs', '0'),
            ('connected', 'vs', '0'),
        ),
    ),
    PollTier(
        name='cold',
        interval_s=600.0,
        timeout_s=6.0,
        paths=(
            ('otninformation', 'vs', '0'),
        ),
    ),
    PollTier(
        name='sweep',
        interval_s=300.0,
        timeout_s=15.0,
        paths=(('device', '0'),),
        is_sweep=True,
    ),
]


# The oven's own wall clock. `x.com.samsung.da.currentTime` on
# `/configuration/vs/0` came from LocalThings #404 / #428, verified
# there on a TP1X range; both the periodic write and the button answer
# 2.04 on this oven too (TP1X_DA-KS-OVEN-0107X, 2026-09-08). The field is
# write-only: a GET of the resource still comes back empty, so the
# front panel is the only read-back. Panel set to 19:47 by hand, synced
# at 17:48, panel followed -- the write lands, it is not just accepted.
OVEN_CLOCK_SYNC = ClockSync(
    path_segs=['configuration', 'vs', '0'],
    field='x.com.samsung.da.currentTime',
    requires_href='/configuration/vs/0',
)


def _is_active(links: dict) -> bool:
    rep = links.get('/operational/state/vs/0') or {}
    sam_state = rep.get('x.com.samsung.da.state')
    return _SAMSUNG_STATE_TO_OCF.get(sam_state) == 'active'


# ---------------------------------------------------------------------
OVEN = ApplianceDescriptor(
    name='oven',
    default_observe_port=49154,
    observe_paths=OBSERVE_PATHS,
    seed_path=['device', '0'],
    flatten=flatten,
    build_discovery=build_discovery,
    command_handlers=command_handlers,
    on_observation=on_observation,
    project=project,
    remote_available_field='remote_control_binary',
    cycle_active_field='cycle_active',
    log_state_change=log_state_change,
    poll_tiers=OVEN_POLL_TIERS,
    is_active=_is_active,
    clock_sync=OVEN_CLOCK_SYNC,
)
