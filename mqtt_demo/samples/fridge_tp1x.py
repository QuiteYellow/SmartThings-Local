"""TP1X fridge descriptor (Samsung TP1X_REF_21K-class).

Resource map captured 2026-07-02 with capture_resources.py. Unlike the
washer/dryer/oven this is an always-on device: no operational cycle, no
remote-control gate, no course machinery — so there's no
remote_available/cycle_active availability topic and no remaining-time
extrapolation hooks.

Temperatures are exposed twice by the firmware: OCF-standard numeric
resources (/temperature/{current,desired}/{cooler,freezer}/0) and the
Samsung items array on /temperatures/vs/0. Reads prefer the numeric OCF
resources. Each carries its own unit (`units` on the OCF resource,
`x.com.samsung.da.unit` on an item), and LocalThings found the same
fields in °F on some fridges, so a reading is converted from the unit
it states rather than assumed to be °C. Setpoint WRITES go through the
/temperatures/vs/0 items array read-modify-write, mirroring the oven's
proven pattern (Samsung's write semantics on the items array are
replace-not-merge).

Not the same class as fridge.py: that one is the older ARTIK051 family,
with a different resource tree (/doors/vs/0, /mode/vs/0, /sabbath/vs/0)
and writes measured only there.

Read-only for now: see WRITES_ENABLED.
"""
from ..descriptor import (
    ApplianceDescriptor,
    avail_base,
    device_block,
    encode,
)
from smartthings_local.ocf.poll_scheduler import PollTier


# --- Writes ------------------------------------------------------------
# The resource map above is a measurement; the writes below are not. The
# setpoint write follows the oven's pattern and the toggles are single
# field writes, but none has been sent to this fridge through this
# descriptor. Until one has, the descriptor publishes the setpoints and
# toggles as plain sensors, registers no command handlers, and retires
# any switch/number a writable build left retained on the broker. Flip
# to True once the readings have been checked against the panel and a
# write has been tried by hand.
WRITES_ENABLED = False


# --- OBSERVE paths -----------------------------------------------------
# Only Samsung's `/<x>/vs/0` siblings push; the OCF-standard `/<x>/0`
# paths (doors, temperature/*) register silently but never fire — they
# are covered by the poll tiers instead.
OBSERVE_PATHS = [
    ['doors',         'vs', '0'],
    ['temperatures',  'vs', '0'],
    ['energy',        'consumption', 'vs', '0'],
    ['refrigeration', 'vs', '0'],
    ['icemaker',      'status', 'vs', '0'],
    ['icemaker',      'one', 'vs', '0'],
    ['icemaker',      'two', 'vs', '0'],
    ['filter',        'waterfilter', 'vs', '0'],
    ['autofill',      'vs', '0'],
    ['runningmode',   'vs', '0'],
    ['alarms',        'vs', '0'],
]

# Setpoint ranges from the OCF temperature resources (capture
# 2026-07-02): cooler 1..7°C, freezer -23..-15°C.
FRIDGE_MIN_C,  FRIDGE_MAX_C  = 1, 7
FREEZER_MIN_C, FREEZER_MAX_C = -23, -15


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _to_celsius(value, unit):
    """`value` in the unit the resource states → °C, or None.

    'C'/'Celsius' and 'F'/'Fahrenheit' are the two spellings seen
    (OCF `units` and the Samsung item's `unit`). A missing or other unit
    gives None: HA's unit is fixed at discovery as °C, so publishing a
    number in an unknown unit would be wrong without looking wrong."""
    v = _num(value)
    u = str(unit or '').strip().upper()
    if v is None:
        return None
    if u.startswith('C'):
        return v
    if u.startswith('F'):
        return round((v - 32) * 5 / 9, 1)
    return None


def _temps_item(links, description):
    """Find the /temperatures/vs/0 item with the given description
    ('Freezer' / 'Fridge'). Returns the item dict or None."""
    rep = links.get('/temperatures/vs/0') or {}
    for it in rep.get('x.com.samsung.da.items') or []:
        if it.get('x.com.samsung.da.description') == description:
            return it
    return None


# --- flatten -----------------------------------------------------------
def flatten(links):
    """Map a /device/0 link dict to the flat sensor dict published to
    MQTT. Temperatures prefer the numeric OCF resources and fall back
    to the Samsung items array (both are poll/push fed)."""
    g = lambda href, k, default=None: (links.get(href) or {}).get(k, default)

    def temp(kind, side, description, field):
        rep = links.get(f'/temperature/{kind}/{side}/0') or {}
        v = _to_celsius(rep.get('temperature'), rep.get('units'))
        if v is not None:
            return v
        item = _temps_item(links, description)
        if not item:
            return None
        return _to_celsius(item.get(field), item.get('x.com.samsung.da.unit'))

    fridge_c         = temp('current', 'cooler',  'Fridge',  'x.com.samsung.da.current')
    fridge_target_c  = temp('desired', 'cooler',  'Fridge',  'x.com.samsung.da.desired')
    freezer_c        = temp('current', 'freezer', 'Freezer', 'x.com.samsung.da.current')
    freezer_target_c = temp('desired', 'freezer', 'Freezer', 'x.com.samsung.da.desired')

    inst_w = _num(g('/energy/consumption/vs/0',
                    'x.com.samsung.da.instantaneousPower'))
    cum_wh = _num(g('/energy/consumption/vs/0',
                    'x.com.samsung.da.cumulativePower'))

    door_cooler  = g('/door/cooler/0',  'openState')
    door_freezer = g('/door/freezer/0', 'openState')
    doors_open = None
    if door_cooler is not None or door_freezer is not None:
        doors_open = 'Open' in (door_cooler, door_freezer)

    filter_usage = _num(g('/filter/waterfilter/vs/0',
                          'x.com.samsung.da.filterUsage'))

    return {
        'fridge_temp_c':         fridge_c,
        'fridge_target_c':       fridge_target_c,
        'freezer_temp_c':        freezer_c,
        'freezer_target_c':      freezer_target_c,
        'door_cooler':           door_cooler,
        'door_freezer':          door_freezer,
        'any_door_open':         doors_open,
        'power_watts':           inst_w,
        'energy_kwh':            round(cum_wh / 1000.0, 2)
                                    if cum_wh is not None else None,
        'energy_wh_cumulative':  int(cum_wh) if cum_wh is not None else None,
        'rapid_fridge':          g('/refrigeration/vs/0',
                                   'x.com.samsung.da.rapidFridge'),
        'rapid_freezing':        g('/refrigeration/vs/0',
                                   'x.com.samsung.da.rapidFreezing'),
        'ice_maker':             g('/icemaker/status/vs/0',
                                   'x.com.samsung.da.iceMaker'),
        'ice_maker_one_state':   g('/icemaker/one/vs/0',
                                   'x.com.samsung.da.iceMaker.state'),
        'ice_maker_one_status':  g('/icemaker/one/vs/0',
                                   'x.com.samsung.da.iceMaker.iceMakingStatus'),
        'ice_maker_two_state':   g('/icemaker/two/vs/0',
                                   'x.com.samsung.da.iceMaker.state'),
        'ice_maker_two_status':  g('/icemaker/two/vs/0',
                                   'x.com.samsung.da.iceMaker.iceMakingStatus'),
        'water_filter_usage':    int(filter_usage)
                                    if filter_usage is not None else None,
        'water_filter_status':   g('/filter/waterfilter/vs/0',
                                   'x.com.samsung.da.filterStatus'),
        'autofill':              g('/autofill/vs/0',
                                   'x.com.samsung.da.autofill'),
        'ai_level':              g('/energy/ailevel/vs/0', 'aiLevel'),
        'running_mode':          g('/runningmode/vs/0',
                                   'x.com.samsung.da.runningMode'),
        'device_sound':          g('/status/lock/vs/0',
                                   'x.com.samsung.da.device.sound'),
    }


# --- Log-line ----------------------------------------------------------
def log_state_change(sensors):
    return (f"fridge={sensors.get('fridge_temp_c')}°C "
            f"freezer={sensors.get('freezer_temp_c')}°C "
            f"doors={'open' if sensors.get('any_door_open') else 'closed'} "
            f"power={sensors.get('power_watts')}W")


# --- HA discovery ------------------------------------------------------
MODEL = 'OCF refrigerator (TizenRT-iotivity)'

# (key, friendly name, extra-config-dict)
_SENSORS = [
    ('fridge_temp_c',        'Fridge temperature',
        {'unit_of_measurement': '°C', 'device_class': 'temperature',
         'state_class': 'measurement'}),
    ('freezer_temp_c',       'Freezer temperature',
        {'unit_of_measurement': '°C', 'device_class': 'temperature',
         'state_class': 'measurement'}),
    ('power_watts',          'Power',
        {'unit_of_measurement': 'W', 'device_class': 'power',
         'state_class': 'measurement'}),
    ('energy_kwh',           'Energy',
        {'unit_of_measurement': 'kWh', 'device_class': 'energy',
         'state_class': 'total_increasing'}),
    ('water_filter_usage',   'Water filter usage',
        {'unit_of_measurement': '%', 'state_class': 'measurement',
         'icon': 'mdi:water-percent'}),
    ('water_filter_status',  'Water filter status', {'icon': 'mdi:filter'}),
    ('ice_maker_one_status', 'Ice maker 1 status',  {'icon': 'mdi:snowflake'}),
    ('ice_maker_two_status', 'Ice maker 2 status',  {'icon': 'mdi:snowflake'}),
    ('ai_level',             'AI energy level',     {'icon': 'mdi:leaf'}),
    ('running_mode',         'Running mode',        {'icon': 'mdi:fridge-outline'}),
]

# (key, friendly name, value_template, device_class)
_BINARY_SENSORS = [
    ('door_cooler_open', 'Fridge door',
        "{{ 'ON' if value_json.door_cooler == 'Open' else 'OFF' }}",
        'door'),
    ('door_freezer_open', 'Freezer door',
        "{{ 'ON' if value_json.door_freezer == 'Open' else 'OFF' }}",
        'door'),
    ('any_door_open', 'Any door',
        "{{ 'ON' if value_json.any_door_open else 'OFF' }}",
        'door'),
]

# MQTT command-topic suffixes.
CMD_FRIDGE_TEMP   = 'cmd/fridge_temp'
CMD_FREEZER_TEMP  = 'cmd/freezer_temp'
CMD_RAPID_FRIDGE  = 'cmd/rapid_fridge'
CMD_RAPID_FREEZE  = 'cmd/rapid_freezing'
CMD_ICE_MAKER     = 'cmd/ice_maker'

# (key, friendly name, sensor key, command suffix, icon)
_SWITCHES = [
    ('rapid_fridge',   'Power Cool',   'rapid_fridge',
     CMD_RAPID_FRIDGE, 'mdi:snowflake-variant'),
    ('rapid_freezing', 'Power Freeze', 'rapid_freezing',
     CMD_RAPID_FREEZE, 'mdi:snowflake-alert'),
    ('ice_maker',      'Ice maker',    'ice_maker',
     CMD_ICE_MAKER,    'mdi:delete-variant'),
]

# (key, friendly name, sensor key, command suffix, min, max, icon)
_NUMBERS = [
    ('fridge_temp',  'Fridge setpoint',  'fridge_target_c',
     CMD_FRIDGE_TEMP,  FRIDGE_MIN_C,  FRIDGE_MAX_C,  'mdi:thermometer'),
    ('freezer_temp', 'Freezer setpoint', 'freezer_target_c',
     CMD_FREEZER_TEMP, FREEZER_MIN_C, FREEZER_MAX_C, 'mdi:thermometer-minus'),
]

# The switch and number values as plain sensors, published in their
# place while WRITES_ENABLED is off.
_SETTING_SENSORS = [
    ('fridge_target_c',  'Fridge setpoint',
        {'unit_of_measurement': '°C', 'device_class': 'temperature',
         'icon': 'mdi:thermometer'}),
    ('freezer_target_c', 'Freezer setpoint',
        {'unit_of_measurement': '°C', 'device_class': 'temperature',
         'icon': 'mdi:thermometer-minus'}),
    ('rapid_fridge',     'Power Cool',   {'icon': 'mdi:snowflake-variant'}),
    ('rapid_freezing',   'Power Freeze', {'icon': 'mdi:snowflake-alert'}),
    ('ice_maker',        'Ice maker',    {'icon': 'mdi:delete-variant'}),
]


def _retire(ha_prefix, topic_prefix, platform, key):
    # An empty retained payload tells HA to remove the entity; without
    # it the broker keeps serving the old config forever.
    return (f"{ha_prefix}/{platform}/{topic_prefix}/{key}/config", b'')


def build_discovery(topic_prefix, ha_prefix, device_name):
    """Return list of (discovery_topic, payload_bytes) tuples ready to
    publish (retained) on MQTT connect."""
    state_topic = f"{topic_prefix}/state"
    avail_topic = f"{topic_prefix}/availability"
    dev = device_block(topic_prefix, device_name, MODEL)
    avail = avail_base(avail_topic)
    out = []

    sensors = _SENSORS if WRITES_ENABLED else _SENSORS + _SETTING_SENSORS
    for key, name, extra in sensors:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{key}",
            'object_id':      f"{topic_prefix}_{key}",
            'state_topic':    state_topic,
            'value_template': f"{{{{ value_json.{key} }}}}",
            'availability':   avail,
            'device':         dev,
        }
        cfg.update(extra)
        out.append((f"{ha_prefix}/sensor/{topic_prefix}/{key}/config",
                    encode(cfg)))

    for key, name, template, dclass in _BINARY_SENSORS:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{key}",
            'object_id':      f"{topic_prefix}_{key}",
            'state_topic':    state_topic,
            'value_template': template,
            'payload_on':     'ON',
            'payload_off':    'OFF',
            'device_class':   dclass,
            'availability':   avail,
            'device':         dev,
        }
        out.append((f"{ha_prefix}/binary_sensor/{topic_prefix}/{key}/config",
                    encode(cfg)))

    if not WRITES_ENABLED:
        for key, *_ in _SWITCHES:
            out.append(_retire(ha_prefix, topic_prefix, 'switch', key))
        for key, *_ in _NUMBERS:
            out.append(_retire(ha_prefix, topic_prefix, 'number', key))
        return out

    for key, *_ in _SETTING_SENSORS:
        out.append(_retire(ha_prefix, topic_prefix, 'sensor', key))

    for key, name, sensor_key, cmd, icon in _SWITCHES:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{key}_switch",
            'object_id':      f"{topic_prefix}_{key}_switch",
            'state_topic':    state_topic,
            'value_template': f"{{{{ value_json.{sensor_key} }}}}",
            'state_on':       'On',
            'state_off':      'Off',
            'command_topic':  f"{topic_prefix}/{cmd}",
            'payload_on':     'On',
            'payload_off':    'Off',
            'icon':           icon,
            'availability':   avail,
            'device':         dev,
        }
        out.append((f"{ha_prefix}/switch/{topic_prefix}/{key}/config",
                    encode(cfg)))

    for key, name, sensor_key, cmd, mn, mx, icon in _NUMBERS:
        cfg = {
            'name':              f"{name}",
            'unique_id':         f"{topic_prefix}_{key}_number",
            'object_id':         f"{topic_prefix}_{key}_number",
            'state_topic':       state_topic,
            'value_template':    f"{{{{ value_json.{sensor_key} }}}}",
            'command_topic':     f"{topic_prefix}/{cmd}",
            'min':               mn,
            'max':               mx,
            'step':              1,
            'unit_of_measurement': '°C',
            'device_class':      'temperature',
            'mode':              'slider',
            'icon':              icon,
            'availability':      avail,
            'device':            dev,
        }
        out.append((f"{ha_prefix}/number/{topic_prefix}/{key}/config",
                    encode(cfg)))

    return out


# --- MQTT command handlers --------------------------------------------
def _temps_items_copy(links):
    """Copy of the /temperatures/vs/0 items array, or None if not
    seeded yet. Samsung's write semantics on the items array are
    replace-not-merge, so handlers modify a copy and POST all items."""
    rep = links.get('/temperatures/vs/0') or {}
    items = rep.get('x.com.samsung.da.items') or []
    return [dict(it) for it in items] if items else None


def command_handlers(state=None):
    """topic_suffix → fn(payload, links) → (path_segs, body_dict) | None.

    Setpoints are read-modify-write on the /temperatures/vs/0 items
    array (matched by description, not index). The rapid/ice-maker
    toggles are single-field writes; if the firmware reverts them the
    bridge's optimistic-publish-then-verify pattern surfaces that in HA
    within the fetchback window. `state` is accepted and ignored: this
    class keeps no cross-command state.

    Empty while WRITES_ENABLED is off, so the bridge drops every
    command topic as unknown."""
    if not WRITES_ENABLED:
        return {}

    def _setpoint(description, mn, mx):
        def handler(p, links):
            try:
                temp = int(round(float(p)))
            except (TypeError, ValueError):
                return None
            if not (mn <= temp <= mx):
                return None
            items = _temps_items_copy(links)
            if items is None:
                return None
            for it in items:
                if it.get('x.com.samsung.da.description') == description:
                    # The payload and bounds are °C. A board reporting
                    # °F would read the same number as °F, so refuse
                    # rather than convert a write nobody has measured.
                    unit = str(it.get('x.com.samsung.da.unit') or '')
                    if not unit.strip().upper().startswith('C'):
                        return None
                    it['x.com.samsung.da.desired'] = str(temp)
                    break
            else:
                return None
            return ['temperatures', 'vs', '0'], {
                'x.com.samsung.da.items': items,
            }
        return handler

    def _rapid(field):
        def handler(p, _links):
            if p not in ('On', 'Off'):
                return None
            return ['refrigeration', 'vs', '0'], {field: p}
        return handler

    def _ice_maker(p, _links):
        if p not in ('On', 'Off'):
            return None
        return ['icemaker', 'status', 'vs', '0'], {
            'x.com.samsung.da.iceMaker': p,
        }

    return {
        CMD_FRIDGE_TEMP:  _setpoint('Fridge',  FRIDGE_MIN_C,  FRIDGE_MAX_C),
        CMD_FREEZER_TEMP: _setpoint('Freezer', FREEZER_MIN_C, FREEZER_MAX_C),
        CMD_RAPID_FRIDGE: _rapid('x.com.samsung.da.rapidFridge'),
        CMD_RAPID_FREEZE: _rapid('x.com.samsung.da.rapidFreezing'),
        CMD_ICE_MAKER:    _ice_maker,
    }


# --- Poll tiers --------------------------------------------------------
# No cycle to track, so no active_interval anywhere. Doors get the
# tightest cadence (door-open automation is the main hot use-case);
# everything else moves on minute timescales. Total steady-state load
# ~1.5 req/s — far below the ~8 req/s worst-case ceiling measured on
# this firmware family (oven).
FRIDGE_TP1X_POLL_TIERS = [
    PollTier(
        name='hot',
        interval_s=2.0,
        timeout_s=3.0,
        paths=(
            ('door', 'cooler', '0'),
            ('door', 'freezer', '0'),
        ),
    ),
    PollTier(
        name='warm',
        interval_s=30.0,
        timeout_s=5.0,
        paths=(
            ('temperature', 'current', 'cooler', '0'),
            ('temperature', 'current', 'freezer', '0'),
            ('temperature', 'desired', 'cooler', '0'),
            ('temperature', 'desired', 'freezer', '0'),
            ('temperatures', 'vs', '0'),
            ('energy', 'consumption', 'vs', '0'),
            ('refrigeration', 'vs', '0'),
            ('icemaker', 'status', 'vs', '0'),
            ('icemaker', 'one', 'vs', '0'),
            ('icemaker', 'two', 'vs', '0'),
        ),
    ),
    PollTier(
        name='cold',
        interval_s=300.0,
        timeout_s=8.0,
        paths=(
            ('filter', 'waterfilter', 'vs', '0'),
            ('autofill', 'vs', '0'),
            ('energy', 'ailevel', 'vs', '0'),
            ('runningmode', 'vs', '0'),
            ('status', 'lock', 'vs', '0'),
        ),
    ),
    PollTier(
        name='sweep',
        interval_s=600.0,
        timeout_s=15.0,
        paths=(('device', '0'),),
        is_sweep=True,
    ),
]


# --- Descriptor --------------------------------------------------------
FRIDGE_TP1X = ApplianceDescriptor(
    name='fridge_tp1x',
    default_observe_port=49154,
    observe_paths=OBSERVE_PATHS,
    seed_path=['device', '0'],
    flatten=flatten,
    build_discovery=build_discovery,
    command_handlers=command_handlers,
    log_state_change=log_state_change,
    poll_tiers=FRIDGE_TP1X_POLL_TIERS,
)
