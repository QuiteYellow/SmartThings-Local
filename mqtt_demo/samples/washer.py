"""Washer descriptor (Samsung WW11DB7B34GWU3-class, DA_WM_TP1_21).

Resource map captured 2026-07-02 with capture_resources.py. The
operational-state, alarm, firmware and Wi-Fi handling is the dryer's,
imported from dryer.py rather than copied, so a fix there reaches this
class too: the remaining-time anchor and `finish_at`, the zeroed
progress percentage while idle, and the alarm rule all come from there.
Washer-specific surfaces: water temperature, spin level and rinse cycles
on /washer/vs/0 (each with a supported* list), cumulative water on
/water/consumption/vs/0, and the course on /st/washercourse/vs/0.

Read-only for now: see WRITES_ENABLED.
"""
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
from .dryer import (
    _SAMSUNG_STATE_TO_OCF,
    _active_alarm_codes,
    _int,
    _num,
    on_observation,
    project,
)
from smartthings_local.ocf.poll_scheduler import PollTier


# --- Writes ------------------------------------------------------------
# The resource map above is a measurement; the writes below are not. No
# Start/Pause/Stop or option write has been sent to this washer through
# this descriptor, and the Remote-Control gating is carried over from
# the dryer rather than observed here. Until a write has been measured,
# the descriptor publishes the settings as plain sensors, registers no
# command handlers, and retires any button/select a writable build left
# retained on the broker. Flip to True once the readings have been
# checked against the panel and a write has been tried by hand.
WRITES_ENABLED = False


# --- OBSERVE paths -----------------------------------------------------
# Only Samsung's `/<x>/vs/0` siblings actually push notifications; the
# OCF-standard `/<x>/0` paths accept registration silently but never
# fire.
OBSERVE_PATHS = [
    ['operational', 'state', 'vs', '0'],   # state, remainingTime, progress
    ['power',       'vs', '0'],
    ['kidslock',    'vs', '0'],
    ['remotectrl',  'vs', '0'],
    ['energy',      'consumption', 'vs', '0'],
    ['water',       'consumption', 'vs', '0'],
    ['course',      'vs', '0'],
    ['washer',      'vs', '0'],            # waterTemp, spinLevel, rinse
    ['diagnosis',   'vs', '0'],
    ['alarms',      'vs', '0'],
    ['st',          'washercourse', 'vs', '0'],
    ['wm',          'jobbeginingstatus', 'vs', '0'],
]


# --- Option tables -----------------------------------------------------
# supported* lists captured 2026-07-02 from a WW11DB7B34GWU3. Discovery
# payloads are built before the first device contact, so the HA select
# options have to be static; other models may support different values —
# recapture with capture_resources.py if a select shows options the
# machine refuses.
WATER_TEMPS  = ['None', 'Cold', '20', '30', '40', '60', '90']
SPIN_LEVELS  = ['RinseHold', 'NoSpin', '400', '800', '1000', '1200', '1400']
RINSE_CYCLES = ['0', '1', '2', '3', '4', '5']


# --- Course table ------------------------------------------------------
# Course names for Table_02, from LocalThings' `washer_cycle_table_02`
# (custom_components/localthings/translations/en.json at
# mbillow/localthings@0b268a9, MIT). They cross-checked it across several
# Table_02 washers; the sources are listed in their
# registry/capabilities/washer.py.
#
# Trimmed to the 23 courses this washer declares itself: the first byte
# of each record in /course/vs/0 `supportedOptions` (washer-capture.json),
# split at the width its header states, which is how LocalThings'
# `_course_records` reads it. The codes are this washer's own; the names
# are LocalThings', and only 0x1C ("Eco 40-60") has been seen selected
# here. A code not in the table is published raw rather than given a
# guessed name.
COURSE_NAMES = {
    'Table_02': {
        0x1B: 'Cotton',
        0x1C: 'Eco 40-60',
        0x1D: 'Super Speed',
        0x1E: "15' Quick Wash",
        0x20: 'Hygiene Steam',
        0x21: 'Colors',
        0x22: 'Wool',
        0x23: 'Outdoor',
        0x24: 'Bedding',
        0x25: 'Synthetics',
        0x26: 'Delicates',
        0x27: 'Rinse+Spin',
        0x28: 'Drain/Spin',
        0x29: 'Drum Clean+',
        0x2D: 'Silent Wash',
        0x2E: 'Baby Care',
        0x2F: 'Activewear',
        0x30: 'Cloudy Day',
        0x32: 'Shirts',
        0x33: 'Towels',
        0x66: 'Denim',
        0x8F: 'Intense Cold',
        0x96: 'Less Microfiber',
    },
}


def _decode_course(s):
    """`Table_02_Course_1C` → `Eco 40-60`. Pass through verbatim if the
    table or code isn't in the lookup."""
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


# `progress` values this board declares in its own `supportedProgress`
# list (washer-capture.json), with the firmware's literal "None" replaced
# by the 'Idle' the bridge publishes. Used as the enum sensor's options.
PROGRESS_OPTIONS = ('Idle', 'Weightsensing', 'Wash', 'Rinse', 'Spin', 'Finish')


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
        # Same phantom -500W idle reading as the dryer; HA energy
        # dashboard hates negatives.
        inst_w = 0.0

    # cumulativeWater is in millilitres (2654100 ≈ 2654L lifetime on a
    # 2-year-old machine — litres would be an ocean).
    cum_water_ml = _num(g('/water/consumption/vs/0',
                          'x.com.samsung.da.cumulativeWater'))

    sam_state = g('/operational/state/vs/0', 'x.com.samsung.da.state')
    machine_state = (_SAMSUNG_STATE_TO_OCF.get(sam_state, sam_state)
                     if sam_state is not None
                     else g('/operational/state/0', 'currentMachineState'))

    progress = g('/operational/state/vs/0', 'x.com.samsung.da.progress')
    # HA's value_template treats the literal "None" as null (renders as
    # "Unknown"). Substitute something we can render verbatim.
    if progress in (None, 'None'):
        progress = 'Idle'

    # This board parks progressPercentage at "1" while Ready
    # (washer-capture.json), as the dryer's does. It only means anything
    # during a cycle.
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

    # Empty `{}` at rest on this board (washer-capture.json).
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
        'delay_end_time':        g('/operational/state/vs/0',
                                   'x.com.samsung.da.delayEndTime'),
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
        'water_liters':          round(cum_water_ml / 1000.0, 1)
                                    if cum_water_ml is not None else None,
        'washer_course':         _decode_course(
                                     g('/st/washercourse/vs/0',
                                       'x.com.samsung.da.st.washerMode')),
        'water_temperature':     g('/washer/vs/0',
                                   'x.com.samsung.da.waterTemperature'),
        'spin_level':            g('/washer/vs/0',
                                   'x.com.samsung.da.spinLevel'),
        'rinse_cycles':          g('/washer/vs/0',
                                   'x.com.samsung.da.rinseCycles'),
        'diagnosis':             g('/diagnosis/vs/0',
                                   'x.com.samsung.da.diagnosisStart'),
        'country_code':          g('/configuration/vs/0',
                                   'x.com.samsung.da.countryCode'),
        'wifi_rssi':             wifi_rssi_dbm(links),
    }


# --- Remaining-time anchor + extrapolation ----------------------------
# on_observation and project are the dryer's, imported above: same
# firmware behaviour (/operational/state/vs/0 pushes on transitions, not
# on remainingTime ticks) and the same hot-poll cadence, so the same
# anchor-on-change rule applies. They publish minute-resolution
# completion fields plus `finish_at`, and drop the anchor at cycle end.


# --- Log-line ----------------------------------------------------------
def log_state_change(sensors):
    return (f"machine={sensors.get('machine_state')} "
            f"power={sensors.get('power_watts')}W "
            f"energy={sensors.get('energy_kwh')}kWh")


# --- HA discovery ------------------------------------------------------
MODEL = 'OCF washer (TizenRT-iotivity)'

# (key, friendly name, extra-config-dict)
_SENSORS = [
    ('machine_state',       'Machine state',
        {'icon': 'mdi:washing-machine', 'device_class': 'enum',
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
    ('water_liters',        'Water',
        {'unit_of_measurement': 'L', 'device_class': 'water',
         'state_class': 'total_increasing'}),
    ('washer_course',       'Course',              {'icon': 'mdi:format-list-bulleted'}),
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

# The /washer/vs/0 settings as plain sensors, published in place of the
# selects while WRITES_ENABLED is off.
_SETTING_SENSORS = [
    ('water_temperature', 'Water temperature', {'icon': 'mdi:thermometer-water'}),
    ('spin_level',        'Spin level',        {'icon': 'mdi:rotate-right'}),
    ('rinse_cycles',      'Rinse cycles',      {'icon': 'mdi:water-sync'}),
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

# Discovery topics this descriptor published before the rebase onto the
# current dryer, and no longer does. An empty retained payload on each
# tells HA to remove the entity; without it the broker keeps serving the
# old config forever. No release ever carried them, so this reaches only
# an install that ran the branch.
# (platform, key)
_RETIRED = [
    ('sensor', 'job_state'),          # duplicated `progress`
    ('sensor', 'job_begin_status'),   # renamed `job_beginning_status`
]

# MQTT command-topic suffixes. The bridge subscribes to <prefix>/cmd/#
# and dispatches by suffix.
CMD_OPERATIONAL  = 'cmd/operational_state'
CMD_WATER_TEMP   = 'cmd/water_temperature'
CMD_SPIN_LEVEL   = 'cmd/spin_level'
CMD_RINSE_CYCLES = 'cmd/rinse_cycles'

# (key, friendly name, payload_press, icon)
_BUTTONS = [
    ('start', 'Start cycle', 'Run',   'mdi:play'),
    ('pause', 'Pause cycle', 'Pause', 'mdi:pause'),
    ('stop',  'Stop cycle',  'Ready', 'mdi:stop'),
]

# (key, friendly name, sensor key, command suffix, options, icon)
_SELECTS = [
    ('water_temperature', 'Water temperature', 'water_temperature',
     CMD_WATER_TEMP,   WATER_TEMPS,  'mdi:thermometer-water'),
    ('spin_level',        'Spin level',        'spin_level',
     CMD_SPIN_LEVEL,   SPIN_LEVELS,  'mdi:rotate-right'),
    ('rinse_cycles',      'Rinse cycles',      'rinse_cycles',
     CMD_RINSE_CYCLES, RINSE_CYCLES, 'mdi:water-sync'),
]


def _retire(ha_prefix, topic_prefix, platform, key):
    # An empty retained payload tells HA to remove the entity; without
    # it the broker keeps serving the old config forever.
    return (f"{ha_prefix}/{platform}/{topic_prefix}/{key}/config", b'')


def build_discovery(topic_prefix, ha_prefix, device_name):
    """Return list of (discovery_topic, payload_bytes) tuples ready to
    publish (retained) on MQTT connect."""
    state_topic   = f"{topic_prefix}/state"
    avail_topic   = f"{topic_prefix}/availability"
    remote_topic  = f"{topic_prefix}/remote_available"
    dev = device_block(topic_prefix, device_name, MODEL)
    out = []

    # read-only sensors
    sensors = _SENSORS if WRITES_ENABLED else _SENSORS + _SETTING_SENSORS
    for key, name, extra in sensors:
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

    # Before the early return below, so a read-only build clears these too.
    for platform, key in _RETIRED:
        out.append(_retire(ha_prefix, topic_prefix, platform, key))

    if not WRITES_ENABLED:
        for key, *_ in _BUTTONS:
            out.append(_retire(ha_prefix, topic_prefix, 'button', key))
        for key, *_ in _SELECTS:
            out.append(_retire(ha_prefix, topic_prefix, 'select', key))
        return out

    for key, *_ in _SETTING_SENSORS:
        out.append(_retire(ha_prefix, topic_prefix, 'sensor', key))

    # buttons: Start / Pause / Stop (gated on remote control)
    for key, name, payload_press, icon in _BUTTONS:
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

    # selects: water temp / spin / rinse (gated on remote control — the
    # dryer only honours option writes with RC enabled; assumed, not yet
    # measured, to hold here too)
    for key, name, sensor_key, cmd, options, icon in _SELECTS:
        cfg = {
            'name':              name,
            'unique_id':         f"{topic_prefix}_{key}_select",
            'object_id':         f"{topic_prefix}_{key}_select",
            'state_topic':       state_topic,
            'value_template':    f"{{{{ value_json.{sensor_key} }}}}",
            'command_topic':     f"{topic_prefix}/{cmd}",
            'options':           options,
            'icon':              icon,
            'availability':      avail_with_remote(avail_topic, remote_topic),
            'availability_mode': 'all',
            'device':            dev,
        }
        out.append((f"{ha_prefix}/select/{topic_prefix}/{key}/config",
                    encode(cfg)))

    return out


# --- MQTT command handlers --------------------------------------------
def command_handlers(state=None):
    """topic_suffix → fn(payload, links) → (path_segs, body_dict) | None.

    `None` means refuse the command (caller logs & drops). All washer
    handlers are single-field writes; validation is against the static
    option tables the selects were built from. `state` is accepted and
    ignored: this class keeps no cross-command state.

    Empty while WRITES_ENABLED is off, so the bridge drops every
    command topic as unknown."""
    if not WRITES_ENABLED:
        return {}

    def _operational(p, _links):
        if p not in ('Run', 'Pause', 'Ready'):
            return None
        return ['operational', 'state', 'vs', '0'], {'x.com.samsung.da.state': p}

    def _water_temp(p, _links):
        if p not in WATER_TEMPS:
            return None
        return ['washer', 'vs', '0'], {'x.com.samsung.da.waterTemperature': p}

    def _spin(p, _links):
        if p not in SPIN_LEVELS:
            return None
        return ['washer', 'vs', '0'], {'x.com.samsung.da.spinLevel': p}

    def _rinse(p, _links):
        if p not in RINSE_CYCLES:
            return None
        return ['washer', 'vs', '0'], {'x.com.samsung.da.rinseCycles': p}

    return {
        CMD_OPERATIONAL:  _operational,
        CMD_WATER_TEMP:   _water_temp,
        CMD_SPIN_LEVEL:   _spin,
        CMD_RINSE_CYCLES: _rinse,
    }


# --- Poll tiers --------------------------------------------------------
# Same DA_WM_TP1_21 platform as the dryer (~14 req/s ceiling measured
# there); identical cadence structure keeps us well under it.
WASHER_POLL_TIERS = [
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
            ('st', 'washercourse', 'vs', '0'),
            ('wm', 'jobbeginingstatus', 'vs', '0'),
            ('energy', 'consumption', 'vs', '0'),
            ('water', 'consumption', 'vs', '0'),
            ('diagnosis', 'vs', '0'),
        ),
    ),
    # Off the /device/0 batch, so the sweep never refreshes it. Paced as
    # a diagnostic, as on the dryer.
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
WASHER = ApplianceDescriptor(
    name='washer',
    default_observe_port=49154,
    observe_paths=OBSERVE_PATHS,
    seed_path=['device', '0'],
    flatten=flatten,
    build_discovery=build_discovery,
    command_handlers=command_handlers,
    on_observation=on_observation,
    project=project,
    remote_available_field='remote_control_binary',
    log_state_change=log_state_change,
    poll_tiers=WASHER_POLL_TIERS,
    is_active=_is_active,
)
