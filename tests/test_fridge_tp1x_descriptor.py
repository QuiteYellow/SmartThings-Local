"""TP1X fridge descriptor: readings mapped, writes held back.

Same arrangement as the washer (see test_washer_descriptor.py): the
resource map was measured, the writes were not, so WRITES_ENABLED ships
off and these tests pin what that means on the wire.
"""
import json

import pytest

from mqtt_demo.samples import get_descriptor
from mqtt_demo.samples import fridge_tp1x as ref


def _discovery(writes):
    old = ref.WRITES_ENABLED
    ref.WRITES_ENABLED = writes
    try:
        return dict(ref.build_discovery('rf', 'homeassistant', 'Fridge'))
    finally:
        ref.WRITES_ENABLED = old


def test_registered_separately_from_fridge():
    assert get_descriptor('fridge_tp1x') is ref.FRIDGE_TP1X
    assert get_descriptor('fridge') is not ref.FRIDGE_TP1X


def test_writes_off_by_default():
    assert ref.WRITES_ENABLED is False
    assert ref.FRIDGE_TP1X.command_handlers({}) == {}


def test_read_only_discovery_retires_controls():
    disc = _discovery(writes=False)
    for key in ('rapid_fridge', 'rapid_freezing', 'ice_maker'):
        assert disc[f'homeassistant/switch/rf/{key}/config'] == b''
    for key in ('fridge_temp', 'freezer_temp'):
        assert disc[f'homeassistant/number/rf/{key}/config'] == b''
    for key in ('fridge_target_c', 'freezer_target_c', 'rapid_fridge'):
        cfg = json.loads(disc[f'homeassistant/sensor/rf/{key}/config'])
        assert 'command_topic' not in cfg
    assert not any(b'command_topic' in v for v in disc.values())


def test_writable_discovery_retires_setting_sensors():
    disc = _discovery(writes=True)
    assert disc['homeassistant/sensor/rf/fridge_target_c/config'] == b''
    assert disc['homeassistant/number/rf/fridge_temp/config'] != b''


def test_flatten():
    s = ref.flatten({
        '/temperature/current/cooler/0': {'temperature': 4.0, 'units': 'C'},
        '/temperatures/vs/0': {'x.com.samsung.da.items': [
            {'x.com.samsung.da.description': 'Freezer',
             'x.com.samsung.da.current': '-18', 'x.com.samsung.da.desired': '-19',
             'x.com.samsung.da.unit': 'Celsius'},
        ]},
        '/door/cooler/0': {'openState': 'Closed'},
        '/door/freezer/0': {'openState': 'Open'},
        '/energy/consumption/vs/0': {'x.com.samsung.da.cumulativePower': '250000'},
    })
    assert s['fridge_temp_c'] == 4.0
    assert s['freezer_temp_c'] == -18.0
    assert s['freezer_target_c'] == -19
    assert s['any_door_open'] is True
    assert s['energy_kwh'] == pytest.approx(250.0)
    assert ref.flatten({})['any_door_open'] is None


def test_fahrenheit_readings_are_converted():
    """Some boards report the same resources in °F; the unit each
    resource states is the one that counts."""
    s = ref.flatten({
        '/temperature/current/cooler/0': {'temperature': 37.0, 'units': 'F'},
        '/temperature/desired/cooler/0': {'temperature': 37.0, 'units': 'F'},
        '/temperatures/vs/0': {'x.com.samsung.da.items': [
            {'x.com.samsung.da.description': 'Freezer',
             'x.com.samsung.da.current': '0', 'x.com.samsung.da.desired': '-2',
             'x.com.samsung.da.unit': 'Fahrenheit'},
        ]},
    })
    assert s['fridge_temp_c'] == pytest.approx(2.8)
    assert s['fridge_target_c'] == pytest.approx(2.8)
    assert s['freezer_temp_c'] == pytest.approx(-17.8)
    assert s['freezer_target_c'] == pytest.approx(-18.9)


def test_missing_unit_is_not_guessed():
    s = ref.flatten({'/temperature/current/cooler/0': {'temperature': 37.0}})
    assert s['fridge_temp_c'] is None


def test_setpoint_write_refused_on_a_fahrenheit_board():
    old = ref.WRITES_ENABLED
    ref.WRITES_ENABLED = True
    try:
        handler = ref.command_handlers()[ref.CMD_FRIDGE_TEMP]
    finally:
        ref.WRITES_ENABLED = old
    items = [{'x.com.samsung.da.description': 'Fridge',
              'x.com.samsung.da.desired': '37',
              'x.com.samsung.da.unit': 'Fahrenheit'}]
    assert handler('3', {'/temperatures/vs/0':
                         {'x.com.samsung.da.items': items}}) is None
    items[0]['x.com.samsung.da.unit'] = 'Celsius'
    path, body = handler('3', {'/temperatures/vs/0':
                               {'x.com.samsung.da.items': items}})
    assert body['x.com.samsung.da.items'][0]['x.com.samsung.da.desired'] == '3'
