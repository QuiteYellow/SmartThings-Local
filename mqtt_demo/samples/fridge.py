"""Fridge descriptor — Samsung ARTIK051_REF_17K (and compatible).

Firmware: DA-REF-ART-COMMON-1_20201124
Protocol: CoAP-DTLS UDP port 49155
Device ID example: 5ce4dafb-f37e-69f9-8d80-b79def93e140

Resource map discovered 2026-06-27 by Nikki Gordon-Bloomfield
(github.com/aminorjourney/SmartThings-Local) against a live
ARTIK051_REF_17K unit — the first known public documentation of
this firmware's local CoAP-DTLS resource layout.

Key differences from newer Tizen RT firmware:
  - /oic/res advertises only 15 paths; full resource tree at /device/0
  - /hass/state/vs/0 and /hass/command/vs/0 are vestigial (404)
  - Door state at /doors/vs/0 (plural, Samsung) AND /door/{room}/0 (OCF)
  - Three doors: id=0 (fridge/cooler), id=1 (freezer), id=2 (convertible)
  - Energy monitoring IS present: /energy/consumption/vs/0
  - Water filter status at /filter/waterfilter/vs/0 (not just /mode/vs/0)
  - Ice maker at /icemaker/one/vs/0 and /icemaker/status/vs/0
  - Defrost control: /defrost/block/vs/0, /defrost/delay/vs/0
  - Temperature setpoints in /temperatures/vs/0 items[].desired
  - Port is 49155, not 49154
  - seed_path is /device/0 (same as dryer/oven — returns full link dict)
"""
import time

from ..descriptor import (
    ApplianceDescriptor,
    avail_base,
    device_block,
    encode,
)
from smartthings_local.ocf.poll_scheduler import PollTier


MODEL = 'ARTIK051_REF_17K'


# --- OBSERVE paths -------------------------------------------------------
OBSERVE_PATHS = [
    ['doors',               'vs', '0'],   # all door open/close states
    ['temperatures',        'vs', '0'],   # fridge + freezer temps + setpoints
    ['refrigeration',       'vs', '0'],   # rapidFridge, rapidFreezing
    ['mode',                'vs', '0'],   # active modes incl. convertible zone
    ['sabbath',             'vs', '0'],   # sabbath mode
    ['energy',  'consumption', 'vs', '0'], # power watts + cumulative Wh
    ['icemaker', 'one',     'vs', '0'],   # ice maker state
    ['filter',  'waterfilter', 'vs', '0'], # filter usage + status
    ['defrost', 'block',    'vs', '0'],   # defrost block mode
]


# --- helpers -------------------------------------------------------------
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


# --- flatten -------------------------------------------------------------
def flatten(links):
    """Map /device/0 link dict to flat sensor dict published to MQTT."""
    g = lambda href, k, default=None: (links.get(href) or {}).get(k, default)

    # --- temperatures ---
    temp_items = g('/temperatures/vs/0', 'x.com.samsung.da.items') or []
    fridge_temp = fridge_set = fridge_min = fridge_max = None
    freezer_temp = freezer_set = freezer_min = freezer_max = None
    for item in temp_items:
        desc = item.get('x.com.samsung.da.description', '')
        if desc == 'Fridge':
            fridge_temp = _num(item.get('x.com.samsung.da.current'))
            fridge_set  = _num(item.get('x.com.samsung.da.desired'))
            fridge_min  = _num(item.get('x.com.samsung.da.minimum'))
            fridge_max  = _num(item.get('x.com.samsung.da.maximum'))
        elif desc == 'Freezer':
            freezer_temp = _num(item.get('x.com.samsung.da.current'))
            freezer_set  = _num(item.get('x.com.samsung.da.desired'))
            freezer_min  = _num(item.get('x.com.samsung.da.minimum'))
            freezer_max  = _num(item.get('x.com.samsung.da.maximum'))

    # --- doors ---
    door_items = g('/doors/vs/0', 'x.com.samsung.da.items') or []
    door_states = {item.get('x.com.samsung.da.id'): item.get('x.com.samsung.da.openState', 'Close')
                   for item in door_items}
    door_fridge_open      = door_states.get('0', 'Close') == 'Open'
    door_freezer_open     = door_states.get('1', 'Close') == 'Open'
    door_convertible_open = door_states.get('2', 'Close') == 'Open'

    # --- energy ---
    inst_w  = _num(g('/energy/consumption/vs/0', 'x.com.samsung.da.instantaneousPower'))
    cum_wh  = _num(g('/energy/consumption/vs/0', 'x.com.samsung.da.cumulativeConsumption'))
    cum_kwh = round(cum_wh / 1000.0, 3) if cum_wh is not None else None

    # --- refrigeration ---
    rapid_fridge   = g('/refrigeration/vs/0', 'x.com.samsung.da.rapidFridge',   'Off')
    rapid_freezing = g('/refrigeration/vs/0', 'x.com.samsung.da.rapidFreezing', 'Off')

    # --- ice maker ---
    ice_state  = g('/icemaker/one/vs/0', 'x.com.samsung.da.iceMaker.state', 'Off')
    ice_status = g('/icemaker/one/vs/0', 'x.com.samsung.da.iceMaker.iceMakingStatus', 'ICESTATUS_STOP')
    ice_type   = g('/icemaker/one/vs/0', 'x.com.samsung.da.iceType.desired', 'Off')

    # --- water filter ---
    filter_usage  = _int(g('/filter/waterfilter/vs/0', 'x.com.samsung.da.filterUsage'))
    filter_status = g('/filter/waterfilter/vs/0', 'x.com.samsung.da.filterStatus', 'normal')


    # --- mode ---
    modes = g('/mode/vs/0', 'x.com.samsung.da.modes') or []
    supported_options = g('/mode/vs/0', 'x.com.samsung.da.supportedOptions') or []
    water_filter_ok = 'WATERFILTER_DISABLE' not in modes

    # --- sabbath ---
    sabbath = g('/sabbath/vs/0', 'x.com.samsung.da.sabbathMode', 'Off')

    # --- information ---
    serial = g('/information/vs/0', 'x.com.samsung.da.serialNum')

    return {
        # temperatures
        'fridge_temp_c':          fridge_temp,
        'freezer_temp_c':         freezer_temp,
        'fridge_setpoint_c':      fridge_set,
        'freezer_setpoint_c':     freezer_set,
        'fridge_temp_min_c':      fridge_min,
        'fridge_temp_max_c':      fridge_max,
        'freezer_temp_min_c':     freezer_min,
        'freezer_temp_max_c':     freezer_max,

        # doors
        'door_fridge_open':       door_fridge_open,
        'door_freezer_open':      door_freezer_open,
        'door_convertible_open':  door_convertible_open,
        'any_door_open':          door_fridge_open or door_freezer_open or door_convertible_open,

        # energy
        'power_watts':            inst_w,
        'energy_kwh':             cum_kwh,
        'energy_wh_cumulative':   _int(cum_wh),

        # refrigeration modes
        'rapid_fridge':           rapid_fridge,
        'rapid_freezing':         rapid_freezing,
        'rapid_fridge_binary':    rapid_fridge   == 'On',
        'rapid_freezing_binary':  rapid_freezing == 'On',

        # ice maker
        'ice_maker_state':        ice_state,
        'ice_making_status':      ice_status,
        'ice_type':               ice_type,
        'ice_maker_on':           ice_state == 'On',

        # water filter
        'filter_usage_pct':       filter_usage,
        'filter_status':          filter_status,
        'filter_ok':              filter_status == 'normal',


        # mode
        'water_filter_ok':        water_filter_ok,
        'sabbath_mode':           sabbath,
        'sabbath_mode_binary':    sabbath == 'On',
        'active_modes':           ', '.join(modes) if modes else '',

        # info
        'serial':                 serial,
    }


# --- sensor / binary_sensor tables -------------------------------------
_SENSORS = [
    ('fridge_temp_c',     'Fridge temperature',
     {'unit_of_measurement': '°C', 'device_class': 'temperature',
      'icon': 'mdi:fridge'}),
    ('freezer_temp_c',    'Freezer temperature',
     {'unit_of_measurement': '°C', 'device_class': 'temperature',
      'icon': 'mdi:snowflake-thermometer'}),
    ('fridge_setpoint_c', 'Fridge setpoint',
     {'unit_of_measurement': '°C', 'device_class': 'temperature',
      'icon': 'mdi:fridge-outline', 'entity_category': 'config'}),
    ('freezer_setpoint_c','Freezer setpoint',
     {'unit_of_measurement': '°C', 'device_class': 'temperature',
      'icon': 'mdi:snowflake', 'entity_category': 'config'}),
    ('power_watts',       'Power',
     {'unit_of_measurement': 'W', 'device_class': 'power',
      'icon': 'mdi:lightning-bolt'}),
    ('energy_kwh',        'Energy',
     {'unit_of_measurement': 'kWh', 'device_class': 'energy',
      'state_class': 'total_increasing', 'icon': 'mdi:lightning-bolt'}),
    ('filter_usage_pct',  'Water filter usage',
     {'unit_of_measurement': '%', 'icon': 'mdi:water-check'}),
    ('filter_status',     'Water filter status',
     {'icon': 'mdi:water-check', 'entity_category': 'diagnostic'}),
    ('ice_maker_state',   'Ice maker',
     {'icon': 'mdi:cube-outline'}),
    ('ice_making_status', 'Ice making status',
     {'icon': 'mdi:cube-outline', 'entity_category': 'diagnostic'}),
    ('active_modes',      'Active modes',
     {'icon': 'mdi:format-list-bulleted', 'entity_category': 'diagnostic'}),
    ('serial',            'Serial number',
     {'icon': 'mdi:identifier', 'entity_category': 'diagnostic'}),
]

_BINARY_SENSORS = [
    ('door_fridge_open',      'Fridge door',
     "{{ 'ON' if value_json.door_fridge_open else 'OFF' }}",       'door', {}),
    ('door_freezer_open',     'Freezer door',
     "{{ 'ON' if value_json.door_freezer_open else 'OFF' }}",      'door', {}),
    ('door_convertible_open', 'Convertible zone door',
     "{{ 'ON' if value_json.door_convertible_open else 'OFF' }}",  'door', {}),
    ('any_door_open',         'Any door open',
     "{{ 'ON' if value_json.any_door_open else 'OFF' }}",          'door',
     {'icon': 'mdi:fridge-alert'}),
    ('filter_ok',             'Water filter OK',
     "{{ 'ON' if value_json.filter_ok else 'OFF' }}",              None,
     {'icon': 'mdi:water-check'}),
    ('ice_maker_on',          'Ice maker on',
     "{{ 'ON' if value_json.ice_maker_on else 'OFF' }}",           None,
     {'icon': 'mdi:cube-outline'}),
    ('rapid_fridge_binary',   'Power cool',
     "{{ 'ON' if value_json.rapid_fridge_binary else 'OFF' }}",    None,
     {'icon': 'mdi:snowflake-alert'}),
    ('rapid_freezing_binary', 'Power freeze',
     "{{ 'ON' if value_json.rapid_freezing_binary else 'OFF' }}",  None,
     {'icon': 'mdi:snowflake-variant'}),
    ('sabbath_mode_binary',   'Sabbath mode',
     "{{ 'ON' if value_json.sabbath_mode_binary else 'OFF' }}",    None,
     {'icon': 'mdi:star-david'}),
]

# MQTT command-topic suffixes
CMD_RAPID_FRIDGE   = 'cmd/rapid_fridge'
CMD_RAPID_FREEZING = 'cmd/rapid_freezing'
CMD_SABBATH        = 'cmd/sabbath_mode'
CMD_FRIDGE_TEMP    = 'cmd/fridge_setpoint'
CMD_FREEZER_TEMP   = 'cmd/freezer_setpoint'
CMD_ICE_MAKER      = 'cmd/ice_maker'


def build_discovery(topic_prefix, ha_prefix, device_name):
    state_topic = f"{topic_prefix}/state"
    avail_topic = f"{topic_prefix}/availability"
    dev = {
        'identifiers':  [topic_prefix],
        'name':         device_name,
        'manufacturer': 'Samsung Electronics',
        'model':        MODEL,
        'sw_version':   'DA-REF-ART-COMMON-1_20201124',
    }
    avail       = avail_base(avail_topic)
    out         = []

    # --- read-only sensors ---
    for key, name, extra in _SENSORS:
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

    # --- binary sensors ---
    for key, name, template, dclass, extra in _BINARY_SENSORS:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{key}",
            'object_id':      f"{topic_prefix}_{key}",
            'state_topic':    state_topic,
            'value_template': template,
            'payload_on':     'ON',
            'payload_off':    'OFF',
            'availability':   avail,
            'device':         dev,
        }
        if dclass:
            cfg['device_class'] = dclass
        cfg.update(extra)
        out.append((f"{ha_prefix}/binary_sensor/{topic_prefix}/{key}/config",
                    encode(cfg)))

    # --- switches: power cool, power freeze, sabbath, ice maker, defrost block ---
    switches = [
        ('rapid_fridge_switch',   'Power cool',    'rapid_fridge',
         CMD_RAPID_FRIDGE,   'mdi:snowflake-alert'),
        ('rapid_freezing_switch', 'Power freeze',  'rapid_freezing',
         CMD_RAPID_FREEZING, 'mdi:snowflake-variant'),
        ('sabbath_switch',        'Sabbath mode',  'sabbath_mode',
         CMD_SABBATH,        'mdi:star-david'),
        ('ice_maker_switch',      'Ice maker',     'ice_maker_state',
         CMD_ICE_MAKER,      'mdi:cube-outline'),
    ]
    for uid, name, val_key, cmd_topic_suffix, icon in switches:
        cfg = {
            'name':           name,
            'unique_id':      f"{topic_prefix}_{uid}",
            'object_id':      f"{topic_prefix}_{uid}",
            'state_topic':    state_topic,
            'value_template': f"{{{{ value_json.{val_key} }}}}",
            'state_on':       'On',
            'state_off':      'Off',
            'command_topic':  f"{topic_prefix}/{cmd_topic_suffix}",
            'payload_on':     'On',
            'payload_off':    'Off',
            'icon':           icon,
            'availability':   avail,
            'device':         dev,
        }
        out.append((f"{ha_prefix}/switch/{topic_prefix}/{uid}/config",
                    encode(cfg)))

    # --- numbers: fridge + freezer setpoints ---
    for uid, name, cmd, min_v, max_v, val_key in [
        ('fridge_setpoint_number',  'Fridge setpoint',
         CMD_FRIDGE_TEMP,  1,   7,   'fridge_setpoint_c'),
        ('freezer_setpoint_number', 'Freezer setpoint',
         CMD_FREEZER_TEMP, -23, -15, 'freezer_setpoint_c'),
    ]:
        cfg = {
            'name':                name,
            'unique_id':           f"{topic_prefix}_{uid}",
            'object_id':           f"{topic_prefix}_{uid}",
            'state_topic':         state_topic,
            'value_template':      f"{{{{ value_json.{val_key} }}}}",
            'command_topic':       f"{topic_prefix}/{cmd}",
            'min':                 min_v,
            'max':                 max_v,
            'step':                1,
            'unit_of_measurement': '°C',
            'device_class':        'temperature',
            'icon':                'mdi:thermometer',
            'availability':        avail,
            'device':              dev,
        }
        out.append((f"{ha_prefix}/number/{topic_prefix}/{uid}/config",
                    encode(cfg)))

    return out


# --- MQTT command handlers -----------------------------------------------
def command_handlers():

    def _rapid_fridge(p, _links):
        if p not in ('On', 'Off'):
            return None
        return (['refrigeration', 'vs', '0'],
                {'x.com.samsung.da.rapidFridge': p})

    def _rapid_freezing(p, _links):
        if p not in ('On', 'Off'):
            return None
        return (['refrigeration', 'vs', '0'],
                {'x.com.samsung.da.rapidFreezing': p})

    def _sabbath(p, _links):
        if p not in ('On', 'Off'):
            return None
        return (['sabbath', 'vs', '0'],
                {'x.com.samsung.da.sabbathMode': p})

    def _ice_maker(p, _links):
        if p not in ('On', 'Off'):
            return None
        return (['icemaker', 'one', 'vs', '0'],
                {'x.com.samsung.da.iceMaker.state': p,
                 'x.com.samsung.da.iceType.desired': p})

    def _fridge_temp(p, links):
        try:
            val = str(int(float(p)))
        except (ValueError, TypeError):
            return None
        items = ((links.get('/temperatures/vs/0') or {})
                 .get('x.com.samsung.da.items', []))
        new_items = [
            dict(item, **{'x.com.samsung.da.desired': val})
            if item.get('x.com.samsung.da.description') == 'Fridge' else item
            for item in items
        ]
        if not new_items:
            return None
        return (['temperatures', 'vs', '0'],
                {'x.com.samsung.da.items': new_items})

    def _freezer_temp(p, links):
        try:
            val = str(int(float(p)))
        except (ValueError, TypeError):
            return None
        items = ((links.get('/temperatures/vs/0') or {})
                 .get('x.com.samsung.da.items', []))
        new_items = [
            dict(item, **{'x.com.samsung.da.desired': val})
            if item.get('x.com.samsung.da.description') == 'Freezer' else item
            for item in items
        ]
        if not new_items:
            return None
        return (['temperatures', 'vs', '0'],
                {'x.com.samsung.da.items': new_items})

    return {
        CMD_RAPID_FRIDGE:   _rapid_fridge,
        CMD_RAPID_FREEZING: _rapid_freezing,
        CMD_SABBATH:        _sabbath,
        CMD_FRIDGE_TEMP:    _fridge_temp,
        CMD_FREEZER_TEMP:   _freezer_temp,
        CMD_ICE_MAKER:      _ice_maker,
    }


# --- Poll tiers ----------------------------------------------------------
FRIDGE_POLL_TIERS = [
    PollTier(
        name='hot',
        interval_s=2.0,
        active_interval_s=1.0,
        paths=(
            ('doors', 'vs', '0'),
            ('energy', 'consumption', 'vs', '0'),
        ),
    ),
    PollTier(
        name='warm',
        interval_s=30.0,
        paths=(
            ('temperatures',        'vs', '0'),
            ('refrigeration',       'vs', '0'),
            ('mode',                'vs', '0'),
            ('sabbath',             'vs', '0'),
            ('icemaker', 'one',     'vs', '0'),
            ('filter', 'waterfilter','vs', '0'),
            ('defrost', 'block',    'vs', '0'),
        ),
    ),
    PollTier(
        name='sweep',
        interval_s=300.0,
        paths=(('device', '0'),),
        is_sweep=True,
    ),
]


def _is_active(_links: dict) -> bool:
    """Fridge is always active — doors can open any time, energy always flowing."""
    return True


def log_state_change(sensors: dict) -> str:
    parts = []
    ft = sensors.get('fridge_temp_c')
    fz = sensors.get('freezer_temp_c')
    pw = sensors.get('power_watts')
    if ft is not None: parts.append(f"fridge={ft}°C")
    if fz is not None: parts.append(f"freezer={fz}°C")
    if pw is not None: parts.append(f"power={pw}W")
    if sensors.get('any_door_open'):
        open_doors = []
        if sensors.get('door_fridge_open'):      open_doors.append('fridge')
        if sensors.get('door_freezer_open'):     open_doors.append('freezer')
        if sensors.get('door_convertible_open'): open_doors.append('convertible')
        parts.append(f"DOOR OPEN: {', '.join(open_doors)}")
    return ' | '.join(parts) if parts else 'idle'


# --- Descriptor ----------------------------------------------------------
FRIDGE = ApplianceDescriptor(
    name='fridge',
    default_observe_port=49155,
    observe_paths=OBSERVE_PATHS,
    seed_path=['device', '0'],
    flatten=flatten,
    build_discovery=build_discovery,
    command_handlers=command_handlers,
    log_state_change=log_state_change,
    poll_tiers=FRIDGE_POLL_TIERS,
    is_active=_is_active,
)
