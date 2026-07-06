# tests/test_state_cache.py
from smartthings_local.ocf.state_cache import StateCache


class _FakeDescriptor:
    on_observation = None


def test_index_device_tree_skips_device_level_entry_at_index_zero():
    tree = [
        {'href': '/device/0', 'rep': {'n': 'Dryer'}},   # device-level, skipped
        {'href': '/mode/vs/0', 'rep': {'x': 1}},
        {'href': '/power/vs/0', 'rep': {'y': 2}},
    ]
    indexed = StateCache.index_device_tree(tree)
    assert indexed == {'/mode/vs/0': {'x': 1}, '/power/vs/0': {'y': 2}}
    assert '/device/0' not in indexed


def test_index_device_tree_stub_entry_becomes_empty_dict():
    tree = [
        {'href': '/device/0', 'rep': {}},
        {'href': '/oven/vs/0'},   # no 'rep' key at all — a stub resource
    ]
    indexed = StateCache.index_device_tree(tree)
    assert indexed == {'/oven/vs/0': {}}


def test_index_device_tree_non_list_input_returns_empty():
    assert StateCache.index_device_tree({'not': 'a list'}) == {}
    assert StateCache.index_device_tree(None) == {}


def test_apply_rep_reports_change_and_updates_cache():
    cache = StateCache(_FakeDescriptor())
    changed = cache.apply_rep('/mode/vs/0', {'x': 1}, source='poll')
    assert changed is True
    assert cache.get('/mode/vs/0') == {'x': 1}
    unchanged = cache.apply_rep('/mode/vs/0', {'x': 1}, source='poll')
    assert unchanged is False
