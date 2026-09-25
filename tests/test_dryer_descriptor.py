"""Dryer descriptor contracts: what flatten() publishes, what the
command handlers send, and what discovery advertises.

The link dicts here follow local-tools/comparisons/dryer_device0.json
(DA_WM_TP2_20_COMMON), which is the board every value below was read
from.
"""

from __future__ import annotations

import json
import time

import pytest

from mqtt_demo.samples import dryer

OP = '/operational/state/vs/0'


def links(state='Ready', progress='None', pct='1', remaining='03:20:00',
          delay_end='00:00:00', alarms=None):
    """An idle dryer as the batch reports it, with the fields the tests
    vary exposed as arguments."""
    lk = {
        OP: {
            'x.com.samsung.da.state': state,
            'x.com.samsung.da.remainingTime': remaining,
            'x.com.samsung.da.progressPercentage': pct,
            'x.com.samsung.da.progress': progress,
            'x.com.samsung.da.delayEndTime': delay_end,
        },
        '/washer/vs/0': {
            'x.com.samsung.da.wrinklePrevent': 'Off',
            'x.com.samsung.da.dryLevel': '2',
            'x.com.samsung.da.supportedDryLevel': ['None', '1', '2', '3'],
            'x.com.samsung.da.dryTime': '00:00:00',
            'x.com.samsung.da.dryerType': 'Electricity',
        },
        '/wm/jobbeginingstatus/vs/0': {'x.com.samsung.da.currentStatus': 'None'},
        '/otninformation/vs/0': {'x.com.samsung.da.newVersionAvailable': 'false'},
        '/alarms/vs/0': {} if alarms is None else {'x.com.samsung.da.items': alarms},
    }
    return lk


def discovery():
    return {topic: (json.loads(payload) if payload else None)
            for topic, payload in dryer.build_discovery('t', 'ha', 'Dryer')}


# --- progress ---------------------------------------------------------

def test_progress_percentage_is_zero_while_idle():
    """The board parks progressPercentage at "1" while Ready."""
    assert dryer.flatten(links())['progress_percentage'] == 0


def test_progress_percentage_is_published_while_active():
    assert dryer.flatten(links(state='Run', progress='Drying',
                               pct='42'))['progress_percentage'] == 42


def test_job_state_is_no_longer_published():
    assert 'job_state' not in dryer.flatten(links())


def test_progress_values_are_within_the_enum_options():
    for raw in ('None', 'Drying', 'Cooling', 'Finish'):
        assert dryer.flatten(links(progress=raw))['progress'] in dryer.PROGRESS_OPTIONS


# --- alarms -----------------------------------------------------------

def test_no_alarm_items_means_no_alarm():
    s = dryer.flatten(links())
    assert s['alarm_code'] is None
    assert s['alarm_active'] is False


def test_a_created_error_code_is_an_active_alarm():
    s = dryer.flatten(links(alarms=[
        {'x.com.samsung.da.code': 'ErrorCode_3CA',
         'x.com.samsung.da.state': 'Created'}]))
    assert s['alarm_code'] == 'ErrorCode_3CA'
    assert s['alarm_active'] is True


def test_deleted_and_off_rows_do_not_count():
    s = dryer.flatten(links(alarms=[
        {'x.com.samsung.da.code': 'ErrorCode_3CA',
         'x.com.samsung.da.state': 'Deleted'},
        {'x.com.samsung.da.code': 'FilterAlarm_OFF'},
    ]))
    assert s['alarm_code'] is None
    assert s['alarm_active'] is False


def test_several_active_codes_are_joined():
    s = dryer.flatten(links(alarms=[
        {'x.com.samsung.da.code': 'ErrorCode_3CA', 'x.com.samsung.da.state': 'Created'},
        {'x.com.samsung.da.code': 'FilterAlarm'},
    ]))
    assert s['alarm_code'] == 'ErrorCode_3CA, FilterAlarm'


# --- the fields that were polled but never published ------------------

def test_job_beginning_status_and_firmware_flag_are_published():
    s = dryer.flatten(links())
    assert s['job_beginning_status'] == 'None'
    assert s['firmware_update_available'] is False


# --- delay end --------------------------------------------------------

def test_delay_end_is_published_in_hours():
    assert dryer.flatten(links(delay_end='01:30:00'))['delay_end_hours'] == 1.5
    assert dryer.flatten(links())['delay_end_hours'] == 0.0


@pytest.mark.parametrize('payload, wire', [
    ('1.5', '01:30:00'),
    ('0', '00:00:00'),
    ('24', '24:00:00'),
    ('10', '10:00:00'),
])
def test_delay_end_write_is_zero_padded_hms(payload, wire):
    h = dryer.command_handlers()[dryer.CMD_DELAY_END]
    path, body = h(payload, links())
    assert path == ['operational', 'state', 'vs', '0']
    assert body == {'x.com.samsung.da.delayEndTime': wire}


@pytest.mark.parametrize('payload', ['-1', '25', 'soon', ''])
def test_delay_end_refuses_out_of_range(payload):
    assert dryer.command_handlers()[dryer.CMD_DELAY_END](payload, links()) is None


# --- dry level --------------------------------------------------------

def test_dry_level_is_published_as_the_boards_string():
    s = dryer.flatten(links())
    assert s['dry_level'] == '2'
    assert s['dry_level_supported'] == ['None', '1', '2', '3']


def test_dry_level_write_goes_to_the_washer_resource():
    h = dryer.command_handlers()[dryer.CMD_DRY_LEVEL]
    assert h('3', links()) == (['washer', 'vs', '0'],
                               {'x.com.samsung.da.dryLevel': '3'})


def test_dry_level_write_is_checked_against_the_live_list():
    """The select offers the class list; the board's supportedDryLevel
    is what a write has to satisfy."""
    h = dryer.command_handlers()[dryer.CMD_DRY_LEVEL]
    lk = links()
    lk['/washer/vs/0']['x.com.samsung.da.supportedDryLevel'] = ['None', '1']
    assert h('3', lk) is None
    assert h('1', lk) is not None


# --- finish time ------------------------------------------------------

def test_anchor_moves_only_when_remaining_changes():
    """Hot-polled once a second: re-anchoring on every observation would
    pin the extrapolation to the value it was just handed."""
    state = {}
    rep = {'x.com.samsung.da.state': 'Run',
           'x.com.samsung.da.remainingTime': '00:10:00'}
    dryer.on_observation(state, OP, rep)
    first = state['remaining_anchor']
    time.sleep(0.01)
    dryer.on_observation(state, OP, rep)
    assert state['remaining_anchor'] is first
    dryer.on_observation(state, OP, {**rep, 'x.com.samsung.da.remainingTime': '00:09:00'})
    assert state['remaining_anchor'] is not first
    assert state['remaining_anchor'][1] == 540


def test_anchor_is_dropped_when_the_cycle_ends():
    state = {}
    dryer.on_observation(state, OP, {'x.com.samsung.da.state': 'Run',
                                     'x.com.samsung.da.remainingTime': '00:10:00'})
    dryer.on_observation(state, OP, {'x.com.samsung.da.state': 'Ready',
                                     'x.com.samsung.da.remainingTime': '00:10:00'})
    assert 'remaining_anchor' not in state


def test_finish_at_is_the_anchor_plus_remaining_and_holds_across_polls():
    state = {}
    dryer.on_observation(state, OP, {'x.com.samsung.da.state': 'Run',
                                     'x.com.samsung.da.remainingTime': '00:10:00'})
    ts, secs = state['remaining_anchor']
    s1 = dryer.project(state, dryer.flatten(links(state='Run', progress='Drying')))
    s2 = dryer.project(state, dryer.flatten(links(state='Run', progress='Drying')))
    assert s1['finish_at'] == s2['finish_at']
    assert state['_finish_published'] == ts + secs
    assert s1['completion_minutes'] == 10
    assert s1['completion_time'] == '0:10:00'


def test_completion_time_carries_no_seconds():
    """A seconds field republishes the whole state topic every second."""
    state = {}
    dryer.on_observation(state, OP, {'x.com.samsung.da.state': 'Run',
                                     'x.com.samsung.da.remainingTime': '00:09:30'})
    s = dryer.project(state, dryer.flatten(links(state='Run', progress='Drying')))
    assert s['completion_time'].endswith(':00')
    assert s['completion_minutes'] == 10


def test_no_projection_while_idle():
    s = dryer.flatten(links())
    assert dryer.project({}, s) == s
    assert 'finish_at' not in s


# --- discovery --------------------------------------------------------

def test_discovery_retires_the_replaced_sensors():
    d = discovery()
    assert d['ha/sensor/t/job_state/config'] is None
    assert d['ha/sensor/t/dry_level/config'] is None


def test_discovery_advertises_the_new_entities():
    d = discovery()
    assert d['ha/select/t/dry_level/config']['options'] == list(dryer.DRY_LEVEL_OPTIONS)
    assert d['ha/number/t/delay_end/config']['max'] == dryer.DELAY_END_MAX_H
    assert d['ha/sensor/t/finish_at/config']['device_class'] == 'timestamp'
    assert d['ha/binary_sensor/t/alarm_active/config']['device_class'] == 'problem'
    assert d['ha/sensor/t/job_beginning_status/config']['entity_category'] == 'diagnostic'
    assert d['ha/binary_sensor/t/firmware_update_available/config']['entity_category'] == 'diagnostic'


def test_country_code_stays_as_a_diagnostic():
    assert discovery()['ha/sensor/t/country_code/config']['entity_category'] == 'diagnostic'


def test_state_sensors_declare_their_enum_options():
    d = discovery()
    assert d['ha/sensor/t/machine_state/config']['options'] == ['idle', 'active', 'pause']
    assert d['ha/sensor/t/progress/config']['options'] == list(dryer.PROGRESS_OPTIONS)


def test_dry_level_select_is_not_remote_control_gated():
    """isModelSettingWithoutSC=true on this board; the write landed with
    Smart Control off in localthings' PR #407 on the same model."""
    avail = discovery()['ha/select/t/dry_level/config']['availability']
    assert [a['topic'] for a in avail] == ['t/availability']


def test_every_published_key_has_a_discovery_entity_or_is_a_helper():
    """Nothing flatten() publishes should be invisible in HA unless it
    is deliberately a helper the entities read."""
    helpers = {
        'completion_time', 'dry_level_supported', 'delay_end_time',
        'power_state_binary', 'child_lock_binary', 'remote_control_binary',
        'energy_wh_cumulative', 'child_lock', 'remote_control',
        'alarm_active', 'firmware_update_available', 'dry_level',
    }
    advertised = {t.split('/')[3] for t, p in discovery().items() if p}
    # Entities whose topic slug differs from the field they read.
    advertised |= {'running', 'power_switch', 'child_lock_active',
                   'remote_control_enabled', 'delay_end_hours'}
    state = {}
    dryer.on_observation(state, OP, {'x.com.samsung.da.state': 'Run',
                                     'x.com.samsung.da.remainingTime': '00:10:00'})
    published = set(dryer.project(state, dryer.flatten(links(state='Run'))))
    missing = published - advertised - helpers
    assert not missing, missing
