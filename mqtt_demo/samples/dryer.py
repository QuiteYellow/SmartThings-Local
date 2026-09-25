"""Dryer descriptor.

Lifts the dryer-specific OBSERVE paths, sensor flattening, HA discovery
inventory, and MQTT command handlers out of the original
samsung_dryer/{bridge,sensors,discovery}.py modules into one place.
"""
import time
from datetime import datetime, timezone

from ..descriptor import (
    WIFI_PATH,
    WIFI_RSSI_SENSOR,
    ApplianceDescriptor,
    avail_base,
    avail_with_remote,
    device_block,
    encode,
    wifi_rssi_dbm,
)
from smartthings_local.ocf.poll_scheduler import PollTier


# --- OBSERVE paths -----------------------------------------------------
# Only Samsung's `/<x>/vs/0` siblings actually push notifications; the
# OCF-standard `/<x>/0` paths accept registration silently but never
# fire. flatten() derives the OCF-shaped values from the live /vs/0
# strings.
OBSERVE_PATHS = [
    ['operational', 'state', 'vs', '0'],     # state, remainingTime, progress
    ['power',       'vs', '0'],              # power on/off
    ['kidslock',    'vs', '0'],              # child lock
    ['remotectrl',  'vs', '0'],              # remote control enabled
    ['energy',      'consumption', 'vs', '0'],
    ['course',      'vs', '0'],
    ['washer',      'vs', '0'],              # dryLevel, dryTime, type
    ['diagnosis',   'vs', '0'],
    ['alarms',      'vs', '0'],
    ['st',          'dryercourse', 'vs', '0'],
    ['wm',          'jobbeginingstatus', 'vs', '0'],
]


# --- Course table ------------------------------------------------------
# Captured 2026-05-29 by dialing every course on a
# DA_WM_TP2_20_COMMON_DV5000T dryer. Other Samsung dryers may report a
# different Table_NN; capture a fresh table for them with
# local-tools/course_mapper.py.
COURSE_NAMES = {
    'Table_03': {
        0x16: 'Cotton',
        0x18: 'Synthetics',
        0x19: 'Delicates',
        0x1A: 'Wool',
        0x1B: 'Bedding',
        0x1C: 'Shirts',
        0x1D: 'Towels',
        0x1E: 'Outdoor',
        0x1F: 'Mixed Load',
        0x20: 'Iron Dry',
        0x23: 'Quick Dry 35',
        0x24: 'Cool Air',
        0x25: 'Warm Air',
        0x27: 'Time Dry',
    },
}

_COURSE_CODE_BY_NAME = {
    name: code
    for table_codes in COURSE_NAMES.values()
    for code, name in table_codes.items()
}


def _decode_course(s):
    """`Table_03_Course_16` → `Cotton`. Pass through verbatim if the
    table or code isn't in our lookup."""
    if not isinstance(s, str) or '_Course_' not in s:
        return s
    table_part, _, code_str = s.partition('_Course_')
    table = COURSE_NAMES.get(table_part)
    if not table:
        return s
    try:
        code = int(code_str, 16)
    except ValueError:
        return s
    return table.get(code, s)


def _encode_course(name):
    """`Cotton` → `Course_16`. Returns None for unknown names so the
    caller refuses rather than POST garbage."""
    code = _COURSE_CODE_BY_NAME.get(name)
    if code is None:
        return None
    return f"Course_{code:02X}"


def _course_options():
    """Stable-sorted human course names for the HA select dropdown."""
    return sorted(_COURSE_CODE_BY_NAME.keys())


# --- Samsung-state → OCF currentMachineState ---------------------------
_SAMSUNG_STATE_TO_OCF = {
    'Ready':   'idle',
    'Run':     'active',
    'Running': 'active',
    'Pause':   'pause',
    'Paused':  'pause',
    'End':     'idle',
}


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# `progress` values this board declares in its own
# `supportedProgress` list (dryer_device0.json, DA_WM_TP2_20_COMMON),
# plus the 'Idle' the bridge substitutes for the firmware's literal
# "None". Published as the enum sensor's option list, so a board that
# reports a progress outside this set will show as unknown in HA rather
# than as text — capture its list and extend this one.
PROGRESS_OPTIONS = ('Idle', 'Drying', 'Cooling', 'Finish')

# Dry levels this board lists in `supportedDryLevel`. Discovery payloads
# are built before any resource has been read, so the select's options
# cannot be the board's live answer; the live list is republished as
# `dry_level_supported` and the write handler validates against it.
# Other boards use words here (Damp/Less/Normal/More/Very on TP1_21
# per localthings) — a bridge for one of those needs its own list.
DRY_LEVEL_OPTIONS = ('None', '1', '2', '3')

# Delay-end bounds in hours. The firmware field is `delayEndTime`, a
# duration to the END of the cycle written as HH:MM:SS; localthings
# measured that on a WD80T634 (their #427) and offers the same 0–24 h
# range. 0 clears the delay.
DELAY_END_MAX_H = 24


def _active_alarm_codes(items):
    """Codes currently raised on /alarms/vs/0, joined, or None.

    The resource is level-triggered: every notification carries the full
    set, so this reads the whole list each time rather than accumulating.
    Rows in state `Deleted` are the firmware's retained history of a
    cleared fault, and `<Name>_OFF` rows are per-type placeholders some
    boards pre-populate; both mean "not firing". This is the same rule
    localthings' `_active_alarm_codes` applies across families."""
    if not isinstance(items, list):
        return None
    codes = []
    for item in items:
        if not isinstance(item, dict):
            continue
        code = item.get('x.com.samsung.da.code')
        if not code:
            continue
        if str(item.get('x.com.samsung.da.state', '')).lower() == 'deleted':
            continue
        if str(code).lower().endswith('_off'):
            continue
        codes.append(str(code))
    return ', '.join(codes) if codes else None


def _hms_to_hours(v):
    """'HH:MM:SS' → hours as a float, or None."""
    if not isinstance(v, str):
        return None
    try:
        h, m, s = v.split(':')
        return round(int(h) + int(m) / 60.0 + int(s) / 3600.0, 2)
    except (ValueError, AttributeError):
        return None


# --- flatten -----------------------------------------------------------
def flatten(links):
    """Map a /device/0 link dict to the flat sensor dict that's
    published to MQTT. Every field reads from `/<x>/vs/0` paths so push
    updates immediately drive every entity."""
    g = lambda href, k, default=None: (links.get(href) or {}).get(k, default)

    inst_w = _num(g('/energy/consumption/vs/0',
                    'x.com.samsung.da.instantaneousPower'))
    cum_wh = _num(g('/energy/consumption/vs/0',
                    'x.com.samsung.da.cumulativePower'))
    if inst_w is not None and inst_w < 0:
        # The dryer reports a phantom -500W when idle; HA energy
        # dashboard hates negatives.
        inst_w = 0.0

    sam_state = g('/operational/state/vs/0', 'x.com.samsung.da.state')
    machine_state = (_SAMSUNG_STATE_TO_OCF.get(sam_state, sam_state)
                     if sam_state is not None
                     else g('/operational/state/0', 'currentMachineState'))

    progress = g('/operational/state/vs/0', 'x.com.samsung.da.progress')
    # HA's value_template treats the literal "None" as null (renders as
    # "Unknown"). Substitute something we can render verbatim.
    if progress in (None, 'None'):
        progress = 'Idle'

    # The board parks progressPercentage at "1" while Ready
    # (dryer_device0.json), so a raw publish shows 1 % on an idle
    # machine. It only means anything during a cycle.
    progress_pct = _int(g('/operational/state/vs/0',
                          'x.com.samsung.da.progressPercentage')
                        or g('/operational/state/0', 'progressPercentage'))
    if machine_state != 'active':
        progress_pct = 0

    remaining = (g('/operational/state/vs/0',
                   'x.com.samsung.da.remainingTime')
                 or g('/operational/state/0', 'remainingTime'))
    rem_min = None
    if remaining:
        try:
            h, m, s = remaining.split(':')
            rem_min = int(h) * 60 + int(m) + (1 if int(s) > 0 else 0)
        except Exception:
            pass

    sam_power = g('/power/vs/0', 'x.com.samsung.da.power')
    sam_kids  = g('/kidslock/vs/0', 'x.com.samsung.da.kidsLock')
    sam_rc    = g('/remotectrl/vs/0',
                  'x.com.samsung.da.remoteControlEnabled')
    power_bin = (sam_power == 'On') if sam_power is not None else None
    kids_bin  = (sam_kids != 'Ready') if sam_kids is not None else None
    rc_bin    = (str(sam_rc).lower() == 'true') if sam_rc is not None else None

    delay_end = g('/operational/state/vs/0', 'x.com.samsung.da.delayEndTime')

    # Fault channel. Empty `{}` at rest on this board; a fault arrives as
    # an ErrorCode_<CODE> item (local-tools/android-capture resolves the
    # 78-code table for this class).
    alarm_code = _active_alarm_codes(g('/alarms/vs/0',
                                       'x.com.samsung.da.items'))

    fw_new = g('/otninformation/vs/0', 'x.com.samsung.da.newVersionAvailable')
    fw_bin = (str(fw_new).lower() == 'true') if fw_new is not None else None

    return {
        'machine_state':         machine_state,
        'progress':              progress,
        'progress_percentage':   progress_pct,
        'completion_time':       remaining,
        'completion_minutes':    rem_min,
        'delay_end_time':        delay_end,
        'delay_end_hours':       _hms_to_hours(delay_end),
        'alarm_code':            alarm_code,
        'alarm_active':          alarm_code is not None,
        # "Why did the cycle not start" — door open, no water, and so on.
        # `None` on this board when nothing is wrong.
        'job_beginning_status':  g('/wm/jobbeginingstatus/vs/0',
                                   'x.com.samsung.da.currentStatus'),
        'firmware_update_available': fw_bin,
        'power_state':           sam_power,
        'power_state_binary':    power_bin,
        'child_lock':            sam_kids,
        'child_lock_binary':     kids_bin,
        'remote_control':        sam_rc,
        'remote_control_binary': rc_bin,
        'power_watts':           inst_w,
        'energy_kwh':            round(cum_wh / 1000.0, 2)
                                    if cum_wh is not None else None,
        'energy_wh_cumulative':  int(cum_wh) if cum_wh is not None else None,
        'dryer_mode':            _decode_course(
                                     g('/st/dryercourse/vs/0',
                                       'x.com.samsung.da.st.dryerMode')),
        # Published as the raw string so the select's state matches its
        # options verbatim ("2", not 2). The board's own list rides
        # alongside; the write handler checks against it.
        'dry_level':             g('/washer/vs/0',
                                   'x.com.samsung.da.dryLevel'),
        'dry_level_supported':   g('/washer/vs/0',
                                   'x.com.samsung.da.supportedDryLevel'),
        'dry_time':              g('/washer/vs/0',
                                   'x.com.samsung.da.dryTime'),
        'dryer_type':            g('/washer/vs/0',
                                   'x.com.samsung.da.dryerType'),
        'wrinkle_prevent':       g('/washer/vs/0',
                                   'x.com.samsung.da.wrinklePrevent'),
        'diagnosis':             g('/diagnosis/vs/0',
                                   'x.com.samsung.da.diagnosisStart'),
        'country_code':          g('/configuration/vs/0',
                                   'x.com.samsung.da.countryCode'),
        'wifi_rssi':             wifi_rssi_dbm(links),
    }


# --- Remaining-time anchor + extrapolation ----------------------------
# The dryer pushes /operational/state/vs/0 on state transitions but not
# on remainingTime ticks. Anchor = (timestamp, total_seconds) at the
# last CHANGE of remainingTime; project() extrapolates downward while
# machine_state == 'active'.
#
# Anchoring on a change rather than on every observation matters
# because this resource is hot-polled every second: re-anchoring on
# each poll pinned the extrapolation to the value it was just handed,
# so the clock sat still for a whole minute and then jumped. At the
# instant remaining steps 600 → 540 it really is 540, so anchoring
# there leaves only the polling interval as error. Same reasoning as
# the oven descriptor's on_observation.

# How far the published finish time may move before it is republished.
# Sampling jitter of a minute-granular field is under a poll interval;
# anything larger is a real change (a pause, a course edit).
FINISH_DEADBAND_S = 15


def _hms_to_seconds(v):
    if not isinstance(v, str):
        return None
    try:
        h, m, s = v.split(':')
        return int(h) * 3600 + int(m) * 60 + int(s)
    except (ValueError, AttributeError):
        return None


def on_observation(state, href, rep):
    if href != '/operational/state/vs/0':
        return
    rem = _hms_to_seconds(rep.get('x.com.samsung.da.remainingTime'))
    if rem != state.get('_rem_last'):
        state['_rem_last'] = rem
        if rem is not None:
            state['remaining_anchor'] = (time.time(), rem)
    # Drop the anchor when the cycle ends so the next one cannot
    # inherit it, and so the held finish time is not carried over.
    sam = rep.get('x.com.samsung.da.state')
    if _SAMSUNG_STATE_TO_OCF.get(sam, sam) != 'active':
        for k in ('remaining_anchor', '_rem_last', '_finish_published'):
            state.pop(k, None)


def project(state, sensors):
    anchor = state.get('remaining_anchor')
    if sensors.get('machine_state') != 'active' or anchor is None:
        return sensors
    ts, total = anchor
    now = time.time()
    remaining = max(0, int(total - (now - ts)))
    # Minute resolution deliberately: the bridge republishes the whole
    # state topic whenever any field changes, so a seconds field here
    # ticked once a second for the length of every cycle and wrote a
    # recorder row per sensor each time. finish_at carries the
    # precision instead.
    mins = (remaining + 59) // 60
    h, m = divmod(mins, 60)
    sensors = dict(sensors)
    sensors['completion_time'] = f"{h}:{m:02d}:00"
    sensors['completion_minutes'] = mins
    # Absolute finish time for HA's `timestamp` device class, which the
    # frontend renders as a live countdown on its own. It is anchor_ts +
    # anchored_remaining, so it does not move as `now` advances, and it
    # is held across anchor changes smaller than the deadband so the
    # state topic is not republished for sampling jitter.
    finish_epoch = ts + total
    held = state.get('_finish_published')
    if held is None or abs(finish_epoch - held) > FINISH_DEADBAND_S:
        state['_finish_published'] = finish_epoch
        held = finish_epoch
    sensors['finish_at'] = datetime.fromtimestamp(
        held, tz=timezone.utc).isoformat(timespec='seconds')
    return sensors


# --- Log-line ----------------------------------------------------------
def log_state_change(sensors):
    return (f"machine={sensors.get('machine_state')} "
            f"power={sensors.get('power_watts')}W "
            f"energy={sensors.get('energy_kwh')}kWh")


# --- HA discovery ------------------------------------------------------
MODEL = 'OCF dryer (TizenRT-iotivity)'

# (key, friendly name, extra-config-dict)
#
# Only read-only sensors live here. `dry_level` has a select entity
# below, so it is not duplicated as a sensor. `machine_state` and
# `progress` carry `device_class: enum` with a fixed option list so HA
# stores and translates them as states rather than free text; the
# other string sensors have no measured option list on this board and
# stay text.
_SENSORS = [
    ('machine_state',       'Machine state',
        {'icon': 'mdi:tumble-dryer', 'device_class': 'enum',
         'options': ['idle', 'active', 'pause']}),
    ('progress',            'Progress',
        {'device_class': 'enum', 'options': list(PROGRESS_OPTIONS)}),
    ('progress_percentage', 'Progress percent',
        {'unit_of_measurement': '%', 'state_class': 'measurement'}),
    ('completion_time',     'Completion time',     {'icon': 'mdi:timer-sand'}),
    ('completion_minutes',  'Remaining minutes',
        {'unit_of_measurement': 'min', 'device_class': 'duration',
         'state_class': 'measurement'}),
    # Absolute finish time. HA renders a timestamp sensor as a live
    # relative countdown; the fields above stay minute-resolution so
    # they do not churn the recorder.
    ('finish_at',           'Finishes at',
        {'device_class': 'timestamp'}),
    ('delay_end_time',      'Delay end time',      {'icon': 'mdi:timer'}),
    ('power_state',         'Power state',         {}),
    ('power_watts',         'Power',
        {'unit_of_measurement': 'W', 'device_class': 'power',
         'state_class': 'measurement'}),
    ('energy_kwh',          'Energy',
        {'unit_of_measurement': 'kWh', 'device_class': 'energy',
         'state_class': 'total_increasing'}),
    ('dryer_mode',          'Dryer mode',          {}),
    ('dry_time',            'Dry time',            {}),
    ('dryer_type',          'Dryer type',          {}),
    ('wrinkle_prevent',     'Wrinkle prevent',     {}),
    ('alarm_code',          'Alarm code',
        {'icon': 'mdi:alert', 'entity_category': 'diagnostic'}),
    ('job_beginning_status', 'Job beginning status',
        {'icon': 'mdi:play-circle-outline', 'entity_category': 'diagnostic'}),
    ('diagnosis',           'Diagnosis',
        {'entity_category': 'diagnostic'}),
    ('country_code',        'Country code',
        {'entity_category': 'diagnostic'}),
    WIFI_RSSI_SENSOR,
]

# (key, friendly name, value_template, device_class, extras)
_BINARY_SENSORS = [
    ('running', 'Running',
        "{{ 'ON' if value_json.machine_state == 'active' else 'OFF' }}",
        'running', {}),
    ('power_switch', 'Power switch',
        "{{ 'ON' if value_json.power_state_binary else 'OFF' }}",
        'power', {}),
    ('child_lock_active', 'Child lock',
        "{{ 'ON' if value_json.child_lock_binary else 'OFF' }}",
        'lock', {}),
    ('remote_control_enabled', 'Remote control',
        "{{ 'ON' if value_json.remote_control_binary else 'OFF' }}",
        'connectivity', {}),
    ('alarm_active', 'Alarm active',
        "{{ 'ON' if value_json.alarm_active else 'OFF' }}",
        'problem', {}),
    ('firmware_update_available', 'Firmware update available',
        "{{ 'ON' if value_json.firmware_update_available else 'OFF' }}",
        'update', {'entity_category': 'diagnostic'}),
]

# Discovery topics this descriptor used to publish and no longer does.
# An empty retained payload on each tells HA to remove the entity;
# without it the broker keeps serving the old config forever.
# (platform, key)
_RETIRED = [
    ('sensor', 'job_state'),   # duplicated `progress`
    ('sensor', 'dry_level'),   # replaced by the select below
]

# MQTT command-topic suffixes. The bridge subscribes to <prefix>/cmd/#
# and dispatches by suffix.
CMD_WRINKLE_PREVENT = 'cmd/wrinkle_prevent'
CMD_OPERATIONAL     = 'cmd/operational_state'
CMD_DRYER_MODE      = 'cmd/dryer_mode'
CMD_DRY_LEVEL       = 'cmd/dry_level'
CMD_DELAY_END       = 'cmd/delay_end'


def build_discovery(topic_prefix, ha_prefix, device_name):
    """Return list of (discovery_topic, payload_bytes) tuples ready to
    publish (retained) on MQTT connect."""
    state_topic   = f"{topic_prefix}/state"
    avail_topic   = f"{topic_prefix}/availability"
    remote_topic  = f"{topic_prefix}/remote_available"
    dev = device_block(topic_prefix, device_name, MODEL)
    out = []

    # read-only sensors
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

    for platform, key in _RETIRED:
        out.append((f"{ha_prefix}/{platform}/{topic_prefix}/{key}/config",
                    b''))

    # switch: wrinkle prevent (always available)
    cfg = {
        'name':           'Wrinkle prevent',
        'unique_id':      f"{topic_prefix}_wrinkle_prevent_switch",
        'object_id':      f"{topic_prefix}_wrinkle_prevent_switch",
        'state_topic':    state_topic,
        'value_template': '{{ value_json.wrinkle_prevent }}',
        'state_on':       'On',
        'state_off':      'Off',
        'command_topic':  f"{topic_prefix}/{CMD_WRINKLE_PREVENT}",
        'payload_on':     'On',
        'payload_off':    'Off',
        'icon':           'mdi:iron',
        'availability':   avail_base(avail_topic),
        'device':         dev,
    }
    out.append((f"{ha_prefix}/switch/{topic_prefix}/wrinkle_prevent/config",
                encode(cfg)))

    # buttons: Start / Pause / Stop (gated on remote control)
    buttons = [
        ('start', 'Start cycle', 'Run',   'mdi:play'),
        ('pause', 'Pause cycle', 'Pause', 'mdi:pause'),
        ('stop',  'Stop cycle',  'Ready', 'mdi:stop'),
    ]
    for key, name, payload_press, icon in buttons:
        cfg = {
            'name':              name,
            'unique_id':         f"{topic_prefix}_{key}",
            'object_id':         f"{topic_prefix}_{key}",
            'command_topic':     f"{topic_prefix}/{CMD_OPERATIONAL}",
            'payload_press':     payload_press,
            'icon':               icon,
            'availability':      avail_with_remote(avail_topic, remote_topic),
            'availability_mode': 'all',
            'device':            dev,
        }
        out.append((f"{ha_prefix}/button/{topic_prefix}/{key}/config",
                    encode(cfg)))

    # select: course (gated on remote control)
    cfg = {
        'name':              'Course',
        'unique_id':         f"{topic_prefix}_course_select",
        'object_id':         f"{topic_prefix}_course_select",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.dryer_mode }}',
        'command_topic':     f"{topic_prefix}/{CMD_DRYER_MODE}",
        'options':           _course_options(),
        'icon':              'mdi:tumble-dryer',
        'availability':      avail_with_remote(avail_topic, remote_topic),
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/select/{topic_prefix}/course/config",
                encode(cfg)))

    # select: dry level. Not gated on Remote Control: this board reports
    # isModelSettingWithoutSC=true on /wm/setinfo/vs/0, and localthings
    # exercised the dryLevel write end to end on a DV5000T with Smart
    # Control off (their PR #407). The same flag is why Wrinkle prevent
    # above is ungated.
    cfg = {
        'name':              'Dry level',
        'unique_id':         f"{topic_prefix}_dry_level_select",
        'object_id':         f"{topic_prefix}_dry_level_select",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.dry_level }}',
        'command_topic':     f"{topic_prefix}/{CMD_DRY_LEVEL}",
        'options':           list(DRY_LEVEL_OPTIONS),
        'icon':              'mdi:water-percent',
        'entity_category':   'config',
        'availability':      avail_base(avail_topic),
        'device':            dev,
    }
    out.append((f"{ha_prefix}/select/{topic_prefix}/dry_level/config",
                encode(cfg)))

    # number: delay end, in hours (gated on remote control — it writes
    # the same /operational/state/vs/0 resource as Start, which needs
    # it; whether this field alone is honoured without it is unmeasured)
    cfg = {
        'name':              'Delay end',
        'unique_id':         f"{topic_prefix}_delay_end",
        'object_id':         f"{topic_prefix}_delay_end",
        'state_topic':       state_topic,
        'value_template':    '{{ value_json.delay_end_hours }}',
        'command_topic':     f"{topic_prefix}/{CMD_DELAY_END}",
        'min':               0,
        'max':               DELAY_END_MAX_H,
        'step':              0.5,
        'unit_of_measurement': 'h',
        'device_class':      'duration',
        'mode':              'box',
        'icon':              'mdi:timer-plus-outline',
        'availability':      avail_with_remote(avail_topic, remote_topic),
        'availability_mode': 'all',
        'device':            dev,
    }
    out.append((f"{ha_prefix}/number/{topic_prefix}/delay_end/config",
                encode(cfg)))

    return out


# --- MQTT command handlers --------------------------------------------
def command_handlers(state=None):
    """Handlers for this appliance class.

    `state` is the descriptor state dict the bridge threads in; this
    class keeps no cross-command state, so it is accepted and ignored.
    See ApplianceDescriptor.command_handlers."""
    """topic_suffix → fn(payload, links) → (path_segs, body_dict) | None.

    `None` means refuse the command (caller logs & drops). Dryer
    handlers don't need the links snapshot — they're all single-field
    writes."""
    def _wrinkle(p, _links):
        if p not in ('On', 'Off'):
            return None
        return ['washer', 'vs', '0'], {'x.com.samsung.da.wrinklePrevent': p}

    def _operational(p, _links):
        if p not in ('Run', 'Pause', 'Ready'):
            return None
        return ['operational', 'state', 'vs', '0'], {'x.com.samsung.da.state': p}

    def _course(p, _links):
        code = _encode_course(p)
        if code is None:
            return None
        return ['st', 'dryercourse', 'vs', '0'], {'x.com.samsung.da.st.dryerMode': code}

    def _dry_level(p, links):
        # The select's options are the class list; the board's live
        # supportedDryLevel is the one that counts. Refuse a value the
        # board does not list rather than POST it.
        rep = links.get('/washer/vs/0') or {}
        supported = rep.get('x.com.samsung.da.supportedDryLevel') or DRY_LEVEL_OPTIONS
        if p not in supported:
            return None
        return ['washer', 'vs', '0'], {'x.com.samsung.da.dryLevel': p}

    def _delay_end(p, _links):
        try:
            hours = float(p)
        except (TypeError, ValueError):
            return None
        if not (0 <= hours <= DELAY_END_MAX_H):
            return None
        total_min = int(round(hours * 60))
        h, m = divmod(total_min, 60)
        # Zero-padded hour: the oven measured `0:10:00` being read as a
        # ~609-minute duration where `00:10:00` was right, and this is
        # the same firmware family's duration format.
        return ['operational', 'state', 'vs', '0'], {
            'x.com.samsung.da.delayEndTime': f"{h:02d}:{m:02d}:00"}

    return {
        CMD_WRINKLE_PREVENT: _wrinkle,
        CMD_OPERATIONAL:     _operational,
        CMD_DRYER_MODE:      _course,
        CMD_DRY_LEVEL:       _dry_level,
        CMD_DELAY_END:       _delay_end,
    }


# --- Poll tiers --------------------------------------------------------
# Empirical ceiling on this firmware is ~14 req/s (probe_poll_rate_combined.py
# 2026-06-03). The hot tier sits at 1s idle / 0.5s active — comfortably under
# the ceiling and leaves headroom for the warm + sweep budgets.
# Per-tier timeouts are scaled to cadence: hot tier retries every 1s, so
# a tight 2s ceiling caps the cascade damage from one wedged poll. Warm
# tier has more headroom; sweep is multi-block Block2 and tolerates ~15s.
DRYER_POLL_TIERS = [
    PollTier(
        name='hot',
        interval_s=1.0,
        active_interval_s=0.5,
        timeout_s=2.0,
        paths=(
            ('operational', 'state', 'vs', '0'),
        ),
    ),
    PollTier(
        name='warm',
        interval_s=15.0,
        timeout_s=4.0,
        paths=(
            ('power', 'vs', '0'),
            ('kidslock', 'vs', '0'),
            ('remotectrl', 'vs', '0'),
            ('alarms', 'vs', '0'),
            ('course', 'vs', '0'),
            ('washer', 'vs', '0'),
            ('st', 'dryercourse', 'vs', '0'),
            ('wm', 'jobbeginingstatus', 'vs', '0'),
            ('energy', 'consumption', 'vs', '0'),
            ('diagnosis', 'vs', '0'),
        ),
    ),
    # Off the /device/0 batch, so the sweep never refreshes it. RSSI
    # moves on every read, and each read republishes the state topic,
    # so this is paced as a diagnostic rather than as state.
    PollTier(
        name='wifi',
        interval_s=120.0,
        timeout_s=6.0,
        paths=(WIFI_PATH,),
    ),
    PollTier(
        name='sweep',
        interval_s=300.0,
        timeout_s=15.0,
        paths=(('device', '0'),),
        is_sweep=True,
    ),
]


def _is_active(links: dict) -> bool:
    rep = links.get('/operational/state/vs/0') or {}
    sam_state = rep.get('x.com.samsung.da.state')
    return _SAMSUNG_STATE_TO_OCF.get(sam_state) == 'active'


# --- Descriptor --------------------------------------------------------
DRYER = ApplianceDescriptor(
    name='dryer',
    default_observe_port=49155,
    observe_paths=OBSERVE_PATHS,
    seed_path=['device', '0'],
    flatten=flatten,
    build_discovery=build_discovery,
    command_handlers=command_handlers,
    on_observation=on_observation,
    project=project,
    remote_available_field='remote_control_binary',
    log_state_change=log_state_change,
    poll_tiers=DRYER_POLL_TIERS,
    is_active=_is_active,
)
