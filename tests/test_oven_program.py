"""Staged cook program and the batch write that starts it.

The reference batch in test_start_batch_matches_measured_payload is the
one measured starting a real oven on 2026-09-20 (docs/oven-cook-start.md).
If that test changes, the wire format changed, and it needs a hardware
run rather than an edit.
"""
import json
import time

import pytest

from mqtt_demo.descriptor import LOCAL_ONLY
from mqtt_demo.samples import oven


MODE_SPEC = json.dumps([
    {"mode": "Defrost", "control": "Start&Setting", "tempMinC": "30",
     "tempMaxC": "60", "tempDefaultC": "30", "tempIntervalC": "5",
     "timeMin": "00:01:00", "timeMax": "23:59:00", "timeDefault": "01:00:00"},
    {"mode": "Convection", "control": "Start&Setting", "tempMinC": "30",
     "tempMaxC": "250", "tempDefaultC": "160", "tempIntervalC": "5",
     "timeMin": "00:01:00", "timeMax": "23:59:00", "timeDefault": "01:00:00"},
    {"mode": "Autocook", "control": "Setting", "tempMinC": "NotSupported",
     "tempMaxC": "NotSupported", "tempDefaultC": "NotSupported",
     "timeMin": "NotSupported", "timeMax": "NotSupported",
     "timeDefault": "NotSupported"},
    {"mode": "SteamClean", "control": "NotSupported",
     "tempMinC": "NotSupported", "tempMaxC": "NotSupported",
     "tempDefaultC": "NotSupported", "timeMin": "NotSupported",
     "timeMax": "NotSupported", "timeDefault": "NotSupported"},
])


def links(state='Ready', remote='true'):
    """An idle, remote-control-enabled oven."""
    return {
        '/mode/vs/0': {
            'x.com.samsung.da.modes': ['NoOperation'],
            'x.com.samsung.da.modeSpec': MODE_SPEC,
            'x.com.samsung.da.options': ['DeviceType_NV7000BS/EUI',
                                         'UpperLamp_Off', 'Sound_On'],
        },
        '/operational/state/vs/0': {
            'x.com.samsung.da.state': state,
            'x.com.samsung.da.operationTime': '00:00:00',
            'x.com.samsung.da.remainingTime': '00:00:00',
        },
        '/oven/vs/0': {'x.com.samsung.da.state': state},
        '/remotectrl/vs/0': {'x.com.samsung.da.remoteControlEnabled': remote},
        '/temperatures/vs/0': {'x.com.samsung.da.items': [{
            'x.com.samsung.da.id': '0',
            'x.com.samsung.da.desired': '0',
            'x.com.samsung.da.current': '28',
            'x.com.samsung.da.unit': 'Celsius',
        }]},
    }


def stage(h, lk, mode='Defrost', temp=None, minutes=None):
    assert h[oven.CMD_PROG_MODE](mode, lk) is LOCAL_ONLY
    if temp is not None:
        assert h[oven.CMD_PROG_TEMP](str(temp), lk) is LOCAL_ONLY
    if minutes is not None:
        assert h[oven.CMD_PROG_TIME](str(minutes), lk) is LOCAL_ONLY


# --- modeSpec parsing -------------------------------------------------

def test_startable_modes_come_from_the_board():
    assert oven.startable_modes(links()) == ['Defrost', 'Convection']


def test_missing_modespec_yields_nothing_startable():
    lk = links()
    del lk['/mode/vs/0']['x.com.samsung.da.modeSpec']
    assert oven.parse_mode_spec(lk) == {}
    assert oven.startable_modes(lk) == []


def test_not_supported_bounds_become_none():
    spec = oven.parse_mode_spec(links())['Autocook']
    assert spec['temp_min_c'] is None
    assert spec['time_default'] is None
    assert spec['startable'] is False


# --- staging ----------------------------------------------------------

def test_selecting_a_mode_adopts_its_defaults():
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Convection')
    assert state['program'] == {'mode': 'Convection', 'temp_c': 160,
                                'minutes': 60}


def test_switching_mode_replaces_the_previous_numbers():
    """A stale setpoint must not survive into a mode whose range may
    not contain it -- 160C is legal for Convection, not for Defrost."""
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Convection')
    stage(h, links(), 'Defrost')
    assert state['program']['temp_c'] == 30


def test_selecting_none_clears_the_program():
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Defrost')
    assert h[oven.CMD_PROG_MODE]('None', links()) is LOCAL_ONLY
    assert state['program'] == {'mode': None, 'temp_c': None, 'minutes': None}


def test_staging_writes_nothing_to_the_appliance():
    """The point of the design: the parameters are held, not sent."""
    state = {}
    h = oven.command_handlers(state)
    for cmd, val in ((oven.CMD_PROG_MODE, 'Defrost'),
                     (oven.CMD_PROG_TEMP, '45'),
                     (oven.CMD_PROG_TIME, '12')):
        assert h[cmd](val, links()) is LOCAL_ONLY


def test_unparseable_program_values_are_rejected():
    h = oven.command_handlers({})
    assert h[oven.CMD_PROG_TEMP]('hot', links()) is None
    assert h[oven.CMD_PROG_TIME]('-1', links()) is None
    assert h[oven.CMD_PROG_MODE]('Broil', links()) is None


# --- the start batch --------------------------------------------------

def test_start_batch_matches_measured_payload():
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Defrost', temp=30, minutes=1)
    segs, body = h[oven.CMD_START]('Start', links())
    assert segs == ['device', '0']
    assert body == [
        {'href': '/devices/0'},
        {'href': '/mode/vs/0',
         'rep': {'x.com.samsung.da.modes': ['Defrost']}},
        {'href': '/temperatures/vs/0',
         'rep': {'x.com.samsung.da.items': [{
             'x.com.samsung.da.desired': '30',
             'x.com.samsung.da.id': '0',
             'x.com.samsung.da.unit': 'Celsius'}]}},
        {'href': '/operational/state/vs/0',
         'rep': {'x.com.samsung.da.state': 'Run',
                 'x.com.samsung.da.operationTime': '00:01:00'}},
    ]


def test_run_rides_inside_the_batch_not_as_a_separate_write():
    """The whole reason for the batch: mode, setpoint, time and Run
    reach the appliance in one message."""
    h = oven.command_handlers({})
    stage(h, links(), 'Defrost', temp=30, minutes=1)
    _, body = h[oven.CMD_START]('Start', links())
    op = [e for e in body if e.get('href') == '/operational/state/vs/0']
    assert len(op) == 1
    assert op[0]['rep']['x.com.samsung.da.state'] == 'Run'


@pytest.mark.parametrize('minutes,wire', [
    (1,    '00:01:00'),
    (10,   '00:10:00'),
    (95,   '01:35:00'),
    (1439, '23:59:00'),
])
def test_duration_hour_field_is_zero_padded(minutes, wire):
    """Regression: an unpadded hour is mis-parsed by the firmware.

    '0:10:00' for a ten-minute cook came back as a ~609-minute one on
    hardware (2026-09-20). Both write paths must produce a two-digit
    hour, which is what the measured payload and the appliance's own
    client send."""
    h = oven.command_handlers({})
    stage(h, links(), 'Convection', temp=160, minutes=minutes)
    _, body = h[oven.CMD_START]('Start', links())
    op = [e for e in body if e.get('href') == '/operational/state/vs/0'][0]
    assert op['rep']['x.com.samsung.da.operationTime'] == wire


def test_cook_time_and_start_agree_on_the_wire_format():
    """The two paths that write operationTime must format it the same
    way -- they did not, which is the bug above."""
    h = oven.command_handlers({})
    _, live = h[oven.CMD_COOK_TIME]('10', links(state='Run'))
    stage(h, links(), 'Convection', temp=160, minutes=10)
    _, body = h[oven.CMD_START]('Start', links())
    staged = [e for e in body
              if e.get('href') == '/operational/state/vs/0'][0]['rep']
    assert (live['x.com.samsung.da.operationTime']
            == staged['x.com.samsung.da.operationTime']
            == '00:10:00')


# --- refusals ---------------------------------------------------------

@pytest.mark.parametrize('mode', ['Autocook', 'SteamClean'])
def test_start_refuses_a_mode_the_board_does_not_declare_startable(mode):
    state = {'program': {'mode': mode, 'temp_c': 100, 'minutes': 10}}
    h = oven.command_handlers(state)
    assert h[oven.CMD_START]('Start', links()) is None


def test_start_refuses_when_remote_control_is_off():
    h = oven.command_handlers({})
    lk = links(remote='false')
    stage(h, lk, 'Defrost', temp=30, minutes=1)
    assert h[oven.CMD_START]('Start', lk) is None


def test_start_refuses_while_a_cycle_is_running():
    h = oven.command_handlers({})
    stage(h, links(), 'Defrost', temp=30, minutes=1)
    assert h[oven.CMD_START]('Start', links(state='Run')) is None


def test_start_refuses_with_no_program_selected():
    h = oven.command_handlers({})
    assert h[oven.CMD_START]('Start', links()) is None


def test_start_refuses_out_of_range_temperature():
    h = oven.command_handlers({})
    stage(h, links(), 'Defrost', temp=200, minutes=1)   # Defrost maxes at 60
    assert h[oven.CMD_START]('Start', links()) is None


def test_start_refuses_when_the_board_publishes_no_modespec():
    h = oven.command_handlers({})
    lk = links()
    stage(h, lk, 'Defrost', temp=30, minutes=1)
    del lk['/mode/vs/0']['x.com.samsung.da.modeSpec']
    assert h[oven.CMD_START]('Start', lk) is None


# --- one-shot JSON path -----------------------------------------------

def test_start_program_stages_and_starts_in_one_message():
    state = {}
    h = oven.command_handlers(state)
    segs, body = h[oven.CMD_START_PROGRAM](
        json.dumps({'mode': 'Convection', 'temp_c': 180, 'minutes': 25}),
        links())
    assert segs == ['device', '0']
    mode_el = [e for e in body if e.get('href') == '/mode/vs/0'][0]
    assert mode_el['rep']['x.com.samsung.da.modes'] == ['Convection']
    assert state['program'] == {'mode': 'Convection', 'temp_c': 180,
                                'minutes': 25}


def test_start_program_falls_back_to_mode_defaults():
    h = oven.command_handlers({})
    _, body = h[oven.CMD_START_PROGRAM](
        json.dumps({'mode': 'Convection'}), links())
    temp = [e for e in body if e.get('href') == '/temperatures/vs/0'][0]
    assert temp['rep']['x.com.samsung.da.items'][0][
        'x.com.samsung.da.desired'] == '160'


def test_rejected_start_program_leaves_the_staged_program_alone():
    """An automation sending a bad program must not corrupt what the
    person staged in the UI."""
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Defrost', temp=30, minutes=1)
    before = dict(state['program'])
    assert h[oven.CMD_START_PROGRAM](
        json.dumps({'mode': 'Convection', 'temp_c': 900}), links()) is None
    assert state['program'] == before


@pytest.mark.parametrize('payload', ['not json', '[]', '"x"',
                                     '{"mode": "Broil"}', '{}'])
def test_start_program_rejects_bad_payloads(payload):
    h = oven.command_handlers({})
    assert h[oven.CMD_START_PROGRAM](payload, links()) is None


# --- projection -------------------------------------------------------

def test_project_publishes_the_staged_program_and_its_bounds():
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Defrost', temp=45, minutes=8)
    sensors = oven.project(state, oven.flatten(links()))
    assert sensors['program_mode'] == 'Defrost'
    assert sensors['program_temp_c'] == 45
    assert sensors['program_minutes'] == 8
    assert sensors['program_temp_min_c'] == 30
    assert sensors['program_temp_max_c'] == 60
    assert sensors['program_startable'] == ['Convection', 'Defrost']
    assert sensors['program_ready'] is True


def test_project_reports_not_ready_when_start_would_refuse():
    state = {}
    h = oven.command_handlers(state)
    stage(h, links(), 'Defrost', temp=200, minutes=1)
    sensors = oven.project(state, oven.flatten(links()))
    assert sensors['program_ready'] is False


def test_internal_spec_key_never_reaches_mqtt():
    state = {}
    sensors = oven.project(state, oven.flatten(links()))
    assert oven.SPEC_KEY not in sensors
    json.dumps(sensors)     # must be serialisable for the state topic


# --- the cook clock ---------------------------------------------------

def op_rep(state='Run', total='00:10:00', remaining='00:10:00', progress='1'):
    return {'x.com.samsung.da.state': state,
            'x.com.samsung.da.operationTime': total,
            'x.com.samsung.da.remainingTime': remaining,
            'x.com.samsung.da.progressPercentage': progress}


def test_anchor_only_moves_when_the_value_changes():
    """The bug this replaced: /operational/state/vs/0 is polled twice a
    second, so re-anchoring on every update pinned the extrapolation to
    the quantised value and the clock never advanced between granules."""
    st = {}
    oven.on_observation(st, '/operational/state/vs/0', op_rep())
    first = st['remaining_anchor']
    oven.on_observation(st, '/operational/state/vs/0', op_rep())   # unchanged
    assert st['remaining_anchor'] == first, 'anchor moved on an unchanged value'
    oven.on_observation(st, '/operational/state/vs/0',
                        op_rep(remaining='00:09:00'))
    assert st['remaining_anchor'] != first


def test_clock_advances_between_device_updates():
    st = {}
    oven.on_observation(st, '/operational/state/vs/0', op_rep())
    ts = st['remaining_anchor'][0]
    a, _, _ = oven.estimate_remaining(st, ts)
    b, _, _ = oven.estimate_remaining(st, ts + 30)
    assert a - b == 30, 'clock did not advance with wall time'


def test_progress_drives_a_short_cook():
    """Granularity is total/100 for progress against 60s for remaining,
    so progress is finer for anything under 100 minutes."""
    st = {}
    oven.on_observation(st, '/operational/state/vs/0',
                        op_rep(total='00:10:00', progress='20'))
    remaining, source, _ = oven.estimate_remaining(st, st['progress_anchor'][0])
    assert source == 'progress'
    assert remaining == 480          # 80% of 600s


def test_remaining_drives_a_long_cook():
    """Past 100 minutes the arithmetic inverts: 1% of a 3-hour cook is
    108s, coarser than remainingTime's 60s."""
    st = {}
    oven.on_observation(st, '/operational/state/vs/0',
                        op_rep(total='03:00:00', remaining='02:30:00',
                               progress='17'))
    _, source, _ = oven.estimate_remaining(st, st['remaining_anchor'][0])
    assert source == 'remaining'


def test_finish_epoch_does_not_move_with_now():
    """The invariant the published finish time rests on.

    Regression: it was computed as `now + remaining`, and because
    remaining is rounded to a whole second while `now` advances
    continuously, the sum crossed a second boundary roughly once a
    second. The whole state topic was republished each time, which is
    exactly what the timestamp sensor exists to avoid. Deriving it from
    the anchor makes it independent of `now` by construction, which a
    sleep-based test cannot show -- the old one slept 1.1s and passed on
    a 0.1s drift that happened not to cross a boundary."""
    st = {}
    oven.on_observation(st, '/operational/state/vs/0', op_rep())
    ts = st['remaining_anchor'][0]
    epochs = {oven.estimate_remaining(st, ts + d)[2]
              for d in (0, 0.3, 1, 7.5, 59, 120)}
    assert len(epochs) == 1, f'finish epoch moved with now: {epochs}'


def test_published_clock_fields_do_not_tick():
    """No field may change more than once a minute, or every poll
    republishes the state topic for the length of every cook."""
    st = {}
    oven.on_observation(st, '/operational/state/vs/0', op_rep())
    base = oven.flatten(links(state='Run'))
    base['machine_state'] = 'active'
    seen = set()
    for _ in range(4):
        s = oven.project(st, dict(base))
        seen.add((s['finish_at'], s['completion_time'],
                  s['completion_minutes']))
        time.sleep(0.4)
    assert len(seen) == 1, f'clock fields changed within a second: {seen}'


def test_completion_time_carries_no_seconds():
    st = {}
    oven.on_observation(st, '/operational/state/vs/0', op_rep())
    base = oven.flatten(links(state='Run'))
    base['machine_state'] = 'active'
    assert oven.project(st, dict(base))['completion_time'].endswith(':00')


def test_clock_resets_when_the_cycle_ends():
    st = {}
    oven.on_observation(st, '/operational/state/vs/0', op_rep())
    assert 'remaining_anchor' in st
    oven.on_observation(st, '/operational/state/vs/0',
                        op_rep(state='Ready', remaining='00:00:00',
                               total='00:00:00', progress='0'))
    assert 'remaining_anchor' not in st
    assert 'progress_anchor' not in st


def test_clock_is_absent_while_idle():
    sensors = oven.project({}, oven.flatten(links()))
    assert 'finish_at' not in sensors
    assert sensors.get('clock_source') is None


def test_finish_at_survives_sampling_jitter():
    """A correctly-running cook should publish a finish time once.

    Each decrement is seen up to one poll interval late, so the
    recomputed epoch wobbles by a fraction of a second. Publishing that
    republishes the whole state topic for no information.
    """
    st = {}
    base = oven.flatten(links(state='Run'))
    base['machine_state'] = 'active'
    seen = set()
    t0 = time.time()
    for i in range(6):
        # Same cook, each decrement observed a little late.
        st['_total_s'] = 600
        st['remaining_anchor'] = (t0 + i * 60 + (i % 3) * 0.4, 600 - i * 60)
        st['progress_anchor'] = None
        seen.add(oven.project(st, dict(base))['finish_at'])
    assert len(seen) == 1, f'jitter republished the finish time: {seen}'


def test_a_real_change_still_gets_through():
    """The deadband must not swallow news: a paused or extended cycle
    moves the finish time by far more than sampling ever could."""
    st = {}
    base = oven.flatten(links(state='Run'))
    base['machine_state'] = 'active'
    t0 = time.time()
    st['_total_s'] = 600
    st['remaining_anchor'] = (t0, 600)
    first = oven.project(st, dict(base))['finish_at']
    st['remaining_anchor'] = (t0 + 120, 600)      # 2 min of pause
    assert oven.project(st, dict(base))['finish_at'] != first
