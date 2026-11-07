"""Washer descriptor: readings mapped, writes held back.

The washer's resource map was measured; none of its writes has been. So
the class ships with WRITES_ENABLED off, and these tests pin what that
has to mean on the wire: no command reaches the appliance, the settings
still show in HA, and a button or select left retained by a writable
build is cleared rather than left pointing at a dead command topic.
"""
import json
import time

import pytest

from mqtt_demo.samples import get_descriptor
from mqtt_demo.samples import washer


def _discovery(writes):
    old = washer.WRITES_ENABLED
    washer.WRITES_ENABLED = writes
    try:
        return dict(washer.build_discovery('wm', 'homeassistant', 'Washer'))
    finally:
        washer.WRITES_ENABLED = old


def test_registered():
    assert get_descriptor('washer') is washer.WASHER


def test_writes_off_by_default():
    assert washer.WRITES_ENABLED is False
    assert washer.WASHER.command_handlers({}) == {}


def test_read_only_discovery_retires_controls():
    disc = _discovery(writes=False)
    for key in ('start', 'pause', 'stop'):
        assert disc[f'homeassistant/button/wm/{key}/config'] == b''
    for key in ('water_temperature', 'spin_level', 'rinse_cycles'):
        assert disc[f'homeassistant/select/wm/{key}/config'] == b''
        cfg = json.loads(disc[f'homeassistant/sensor/wm/{key}/config'])
        assert 'command_topic' not in cfg
    assert not any(b'command_topic' in v for v in disc.values())


def test_writable_discovery_retires_setting_sensors():
    disc = _discovery(writes=True)
    for key in ('water_temperature', 'spin_level', 'rinse_cycles'):
        assert disc[f'homeassistant/sensor/wm/{key}/config'] == b''
        assert disc[f'homeassistant/select/wm/{key}/config'] != b''


def test_discovery_retires_the_renamed_sensors():
    """`job_state` and `job_begin_status` were published before the
    rebase onto the current dryer. An install that ran that revision
    keeps both entities until the retained config is cleared, so the
    clearing has to happen in either write mode."""
    for writes in (False, True):
        disc = _discovery(writes=writes)
        for key in ('job_state', 'job_begin_status'):
            assert disc[f'homeassistant/sensor/wm/{key}/config'] == b''


def test_flatten():
    s = washer.flatten({
        '/operational/state/vs/0': {'x.com.samsung.da.state': 'Run',
                                    'x.com.samsung.da.remainingTime': '01:05:30'},
        '/energy/consumption/vs/0': {'x.com.samsung.da.instantaneousPower': '-500',
                                     'x.com.samsung.da.cumulativePower': '123456'},
        '/water/consumption/vs/0': {'x.com.samsung.da.cumulativeWater': '2654100'},
        '/washer/vs/0': {'x.com.samsung.da.spinLevel': '1200'},
    })
    assert s['machine_state'] == 'active'
    assert s['completion_minutes'] == 66
    assert s['power_watts'] == 0.0
    assert s['energy_kwh'] == pytest.approx(123.46)
    assert s['water_liters'] == pytest.approx(2654.1)
    assert s['spin_level'] == '1200'
    assert washer.flatten({})['progress'] == 'Idle'
    assert 'job_state' not in s


OP = '/operational/state/vs/0'


def test_progress_percentage_is_zero_while_idle():
    # The board parks progressPercentage at "1" while Ready.
    s = washer.flatten({OP: {'x.com.samsung.da.state': 'Ready',
                             'x.com.samsung.da.progressPercentage': '1'}})
    assert s['progress_percentage'] == 0
    s = washer.flatten({OP: {'x.com.samsung.da.state': 'Run',
                             'x.com.samsung.da.progressPercentage': '42'}})
    assert s['progress_percentage'] == 42


def test_progress_values_are_within_the_enum_options():
    # supportedProgress from washer-capture.json.
    for raw in ('None', 'Weightsensing', 'Wash', 'Rinse', 'Spin', 'Finish'):
        s = washer.flatten({OP: {'x.com.samsung.da.progress': raw}})
        assert s['progress'] in washer.PROGRESS_OPTIONS


def test_course_is_named_from_table_02():
    def course(code):
        return washer.flatten({'/st/washercourse/vs/0': {
            'x.com.samsung.da.st.washerMode': code}})['washer_course']
    assert course('Table_02_Course_1C') == 'Eco 40-60'
    # Unknown codes and tables pass through rather than get a guess.
    assert course('Table_02_Course_FF') == 'Table_02_Course_FF'
    assert course('Table_09_Course_1C') == 'Table_09_Course_1C'


def test_alarms():
    s = washer.flatten({'/alarms/vs/0': {}})
    assert s['alarm_code'] is None and s['alarm_active'] is False
    s = washer.flatten({'/alarms/vs/0': {'x.com.samsung.da.items': [
        {'x.com.samsung.da.code': 'ErrorCode_4C'},
        {'x.com.samsung.da.code': 'ErrorCode_DC',
         'x.com.samsung.da.state': 'Deleted'},
    ]}})
    assert s['alarm_code'] == 'ErrorCode_4C' and s['alarm_active'] is True


def test_countdown_anchors_on_change_not_on_every_poll(monkeypatch):
    """Hot polls repeat the same remainingTime for a minute; the anchor
    must stay put through them so the projection keeps counting down."""
    now = [1000.0]
    monkeypatch.setattr(time, 'time', lambda: now[0])
    state = {}
    rep = {'x.com.samsung.da.state': 'Run',
           'x.com.samsung.da.remainingTime': '00:10:00'}
    washer.on_observation(state, OP, rep)
    now[0] += 45
    washer.on_observation(state, OP, rep)   # same value, later poll
    out = washer.project(state, washer.flatten({OP: rep}))
    assert out['completion_minutes'] == 10  # 555 s left, rounded up
    assert state['remaining_anchor'] == (1000.0, 600)
    assert out['finish_at'].startswith('1970-01-01T00:26:40')


def test_anchor_dropped_at_cycle_end():
    state = {}
    washer.on_observation(state, OP, {'x.com.samsung.da.state': 'Run',
                                      'x.com.samsung.da.remainingTime': '00:10:00'})
    assert 'remaining_anchor' in state
    washer.on_observation(state, OP, {'x.com.samsung.da.state': 'Ready',
                                      'x.com.samsung.da.remainingTime': '00:00:00'})
    assert 'remaining_anchor' not in state


def test_discovery_has_finish_at_and_alarm():
    disc = _discovery(writes=False)
    cfg = json.loads(disc['homeassistant/sensor/wm/finish_at/config'])
    assert cfg['device_class'] == 'timestamp'
    assert disc['homeassistant/binary_sensor/wm/alarm_active/config']
