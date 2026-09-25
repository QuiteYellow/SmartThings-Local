"""Wi-Fi RSSI from /rm/wifi/vs/0, shared by the dryer and oven descriptors.

The two boards measured (docs/appliance-resources.md, 2026-09-18) report
the same field in different shapes: the dryer wraps it in a one-element
list, the oven sends a bare integer.
"""

from __future__ import annotations

import json

from mqtt_demo.descriptor import WIFI_HREF, WIFI_PATH, wifi_rssi_dbm
from mqtt_demo.samples import dryer, oven


def test_list_shape_is_the_dryers():
    assert wifi_rssi_dbm({WIFI_HREF: {'x.com.samsung.rm.rssi': [-61]}}) == -61


def test_scalar_shape_is_the_ovens():
    assert wifi_rssi_dbm({WIFI_HREF: {'x.com.samsung.rm.rssi': -80}}) == -80


def test_absent_or_malformed_reads_as_none():
    assert wifi_rssi_dbm({}) is None
    assert wifi_rssi_dbm({WIFI_HREF: {}}) is None
    assert wifi_rssi_dbm({WIFI_HREF: {'x.com.samsung.rm.rssi': []}}) is None
    assert wifi_rssi_dbm({WIFI_HREF: {'x.com.samsung.rm.rssi': 'weak'}}) is None


def test_both_descriptors_publish_and_poll_it():
    for mod, rssi in ((dryer, [-61]), (oven, -80)):
        links = {WIFI_HREF: {'x.com.samsung.rm.rssi': rssi}}
        assert mod.flatten(links)['wifi_rssi'] == (rssi[0] if isinstance(rssi, list) else rssi)
        polled = [p for t in mod.__dict__[f"{mod.__name__.split('.')[-1].upper()}_POLL_TIERS"]
                  for p in t.paths]
        assert WIFI_PATH in polled
        cfg = json.loads(dict(mod.build_discovery('t', 'ha', 'x'))['ha/sensor/t/wifi_rssi/config'])
        assert cfg['device_class'] == 'signal_strength'
        assert cfg['entity_category'] == 'diagnostic'
        assert cfg['unit_of_measurement'] == 'dBm'
