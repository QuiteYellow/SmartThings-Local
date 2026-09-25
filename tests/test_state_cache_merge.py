"""A sparse OBSERVE notification must not erase the rest of a resource.

These appliances can notify with a delta naming only what changed: the
dryer's /course/vs/0 answers a GET with three keys and notifies with one
of them carrying a single token (2026-09-25 hardware run, see
local-tools/HARDWARE-RESULTS-2026-09-25-notification-deltas.md). Only a
genuine push is partial; polls, sweeps, seeds, registration responses and
Block2 fetchbacks carry the whole representation.
"""
import types

from smartthings_local.ocf.state_cache import StateCache


FULL = {
    'x.com.samsung.da.options': ['DeviceType_0165', 'Course_16',
                                 'AiOption_On'],
    'x.com.samsung.da.supportedModes': ['HOMECARE_WIZARD_V2'],
    'x.com.samsung.da.supportedOptions': ['116D20E23D'],
}
DELTA = {'x.com.samsung.da.options': ['Course_27']}
HREF = '/course/vs/0'


def _cache(on_observation=None):
    return StateCache(types.SimpleNamespace(on_observation=on_observation))


def test_merge_keeps_keys_the_delta_omits():
    c = _cache()
    c.apply_rep(HREF, dict(FULL), source='seed')
    c.apply_rep(HREF, dict(DELTA), source='observe', merge=True)
    held = c.get(HREF)
    assert held['x.com.samsung.da.options'] == ['Course_27']
    assert held['x.com.samsung.da.supportedModes'] == FULL[
        'x.com.samsung.da.supportedModes']
    assert held['x.com.samsung.da.supportedOptions'] == FULL[
        'x.com.samsung.da.supportedOptions']


def test_default_still_replaces_so_a_poll_can_drop_a_key():
    c = _cache()
    c.apply_rep(HREF, dict(FULL), source='seed')
    c.apply_rep(HREF, dict(DELTA), source='poll')
    assert c.get(HREF) == DELTA


def test_registration_response_replaces():
    """delivery.registration=True reaches the cache as 'observe-register',
    and the bridge passes merge only for 'observe'."""
    c = _cache()
    c.apply_rep(HREF, dict(FULL), source='seed')
    c.apply_rep(HREF, dict(DELTA), source='observe-register')
    assert c.get(HREF) == DELTA


def test_merge_into_an_empty_cache_stores_the_delta():
    c = _cache()
    c.apply_rep(HREF, dict(DELTA), source='observe', merge=True)
    assert c.get(HREF) == DELTA


def test_changed_is_computed_on_the_merged_result():
    c = _cache()
    c.apply_rep(HREF, dict(FULL), source='seed')
    repeat = {'x.com.samsung.da.options': FULL['x.com.samsung.da.options']}
    assert c.apply_rep(HREF, repeat, source='observe', merge=True) is False
    assert c.apply_rep(HREF, dict(DELTA), source='observe',
                       merge=True) is True


def test_hook_receives_the_merged_representation():
    """mqtt_demo/samples/dryer.py:334 drops its remaining-time anchor when
    the rep has no x.com.samsung.da.state. Handing it the delta would drop
    the anchor mid-cycle on every push that omits that field."""
    seen = []

    def hook(state, href, rep):
        seen.append(rep)

    c = _cache(hook)
    c.apply_rep(HREF, dict(FULL), source='seed')
    c.apply_rep(HREF, dict(DELTA), source='observe', merge=True)
    assert 'x.com.samsung.da.supportedModes' in seen[-1]
    assert seen[-1]['x.com.samsung.da.options'] == ['Course_27']


def test_merge_does_not_mutate_the_prior_representation():
    c = _cache()
    seeded = dict(FULL)
    c.apply_rep(HREF, seeded, source='seed')
    c.apply_rep(HREF, dict(DELTA), source='observe', merge=True)
    assert seeded['x.com.samsung.da.options'] == FULL[
        'x.com.samsung.da.options']
