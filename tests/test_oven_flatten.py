"""Oven descriptor flatten() contracts for the HA Number entity's range.

The oven reports ``x.com.samsung.da.desired = 0`` whenever no cycle is
set. That is "no setpoint", not a 0 °C target, and publishing it as one
makes Home Assistant reject every state message against the Number
entity's declared 30-270 range.
"""

from __future__ import annotations

import pytest

from mqtt_demo.samples import oven


def _links(desired, current=180):
    """A /temperatures/vs/0 link tree carrying one desired/current pair."""
    return {
        '/temperatures/vs/0': {
            'x.com.samsung.da.items': [{
                'x.com.samsung.da.current': str(current),
                'x.com.samsung.da.desired': str(desired),
            }],
        },
    }


@pytest.mark.parametrize('desired', [
    oven.SETPOINT_MIN_C,
    oven.SETPOINT_MIN_C + oven.SETPOINT_STEP_C,
    180,
    oven.SETPOINT_MAX_C,
])
def test_settable_setpoints_are_published_unchanged(desired):
    assert oven.flatten(_links(desired))['target_temp_c'] == desired


@pytest.mark.parametrize('desired', [
    0,                              # the idle oven; see module docstring
    oven.SETPOINT_MIN_C - 1,
    oven.SETPOINT_MAX_C + 1,
])
def test_unsettable_setpoints_are_published_as_absent(desired):
    assert oven.flatten(_links(desired))['target_temp_c'] is None


def test_out_of_range_setpoint_does_not_suppress_current_temperature():
    """The guard applies to the setpoint alone. A cooling oven still
    reports its cavity temperature after the cycle ends."""
    sensors = oven.flatten(_links(0, current=210))

    assert sensors['target_temp_c'] is None
    assert sensors['current_temp_c'] == 210


def test_missing_temperature_resource_leaves_both_absent():
    sensors = oven.flatten({})

    assert sensors['target_temp_c'] is None
    assert sensors['current_temp_c'] is None


def test_every_committed_write_is_a_value_flatten_will_publish():
    """The write path snaps to the step grid *before* bounds-checking, so
    it accepts more than flatten() publishes: 29 commits as 30, and 271 as
    270. That is fine for a slider, but it means the two range checks are
    not symmetric. What has to hold is the weaker invariant: any setpoint
    the oven is actually told to adopt is one flatten() will show back,
    otherwise a write appears to succeed and then reads as unknown."""
    handler = oven.command_handlers()[oven.CMD_SETPOINT]

    for requested in range(-20, oven.SETPOINT_MAX_C + 40):
        write = handler(str(requested), _links(180))
        if write is None:
            continue
        _path, body = write
        committed = int(body['x.com.samsung.da.items'][0][
            'x.com.samsung.da.desired'])
        assert oven.flatten(_links(committed))['target_temp_c'] == committed


def test_zero_is_rejected_on_the_write_path_too():
    """0 is the one value that neither snaps into range nor publishes."""
    handler = oven.command_handlers()[oven.CMD_SETPOINT]

    assert handler('0', _links(180)) is None


def test_idle_zero_cavity_temperature_is_published_as_absent():
    """The idle oven reports current=0 next to desired=0
    (local-tools/comparisons/oven_device0.json). That is not a reading."""
    sensors = oven.flatten(_links(0, current=0))

    assert sensors['current_temp_c'] is None
    assert sensors['target_temp_c'] is None


def _op_links(state, pct):
    return {'/operational/state/vs/0': {
        'x.com.samsung.da.state': state,
        'x.com.samsung.da.progressPercentage': pct,
    }}


def test_progress_percentage_is_zero_unless_active():
    assert oven.flatten(_op_links('Ready', '1'))['progress_percentage'] == 0
    assert oven.flatten(_op_links('Run', '37'))['progress_percentage'] == 37
