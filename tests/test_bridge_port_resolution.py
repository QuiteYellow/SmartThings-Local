"""Port-resolution logic for the MQTT bridge: the stateless pre-flight
gate and standard/dynamic OCF port discovery in PushBridge. The DTLS probe is
faked so these run without hardware; only routing and selection are exercised.
"""
import logging
import types

import pytest

import mqtt_demo.bridge as bridge


def _mk_bridge(ocf_port, default=49155, discovered=None):
    """A PushBridge shell with only the attributes _resolve_port touches,
    bypassing the heavyweight __init__ (MQTT client, cert paths, …)."""
    b = bridge.PushBridge.__new__(bridge.PushBridge)
    b.app = types.SimpleNamespace(ip='192.0.2.9', ocf_port=ocf_port, index=0)
    b.descriptor = types.SimpleNamespace(default_observe_port=default)
    b._discovered_port = discovered
    b.log = logging.getLogger('test-bridge')
    return b


def _fake_directory(ports, *, error=None):
    """Return a plaintext-directory stand-in advertising ``ports``."""
    def fake(ip, **kw):
        if error is not None:
            raise error
        return types.SimpleNamespace(
            ports=tuple(ports),
            found=bool(ports),
            attempts=1,
            response_received=bool(ports),
            error_code=None if ports else 'no_secure_ports',
        )
    return fake


@pytest.fixture(autouse=True)
def silent_directory(monkeypatch):
    """Default every test to a device that advertises nothing.

    Without this the directory tier would read a real socket. Tests about
    the band sweep keep their original meaning, and the ones about the
    directory override it explicitly.
    """
    monkeypatch.setattr(
        bridge, 'discover_ocf_secure_ports', _fake_directory(()))


def _fake_port_probe(live_ports):
    """Return a one-port probe stand-in for the selected live ports."""
    def fake(ip, port, **kw):
        alive = port in live_ports
        return types.SimpleNamespace(
            port=port,
            is_dtls_server=alive,
        )
    return fake


def _fake_port_set(live_ports):
    """Return an aggregate probe stand-in with explicit ambiguity."""
    def fake(ip, ports, **kw):
        live = tuple(port for port in ports if port in live_ports)
        if len(live) == 1:
            outcome = 'selected'
            selected_port = live[0]
        elif live:
            outcome = 'ambiguous'
            selected_port = None
        else:
            outcome = 'unreachable'
            selected_port = None
        return types.SimpleNamespace(
            outcome=outcome,
            selected_port=selected_port,
        )
    return fake


def test_pinned_live_port_is_gated_and_returned(monkeypatch):
    monkeypatch.setattr(bridge, 'probe_dtls_port', _fake_port_probe({49155}))
    b = _mk_bridge(ocf_port=49155)
    assert b._resolve_port() == 49155


def test_pinned_dead_port_raises_for_backoff(monkeypatch):
    monkeypatch.setattr(bridge, 'probe_dtls_port', _fake_port_probe(set()))
    b = _mk_bridge(ocf_port=49155)
    with pytest.raises(ConnectionError):
        b._resolve_port()


def test_autodiscovery_finds_and_caches_live_port(monkeypatch):
    # Only 49154 answers; it isn't the descriptor default, so discovery is
    # what finds it — and it must be cached for the next reconnect.
    monkeypatch.setattr(bridge, 'probe_dtls_ports', _fake_port_set({49154}))
    b = _mk_bridge(ocf_port=None, default=49155)
    assert b._resolve_port() == 49154
    assert b._discovered_port == 49154


def test_autodiscovery_refuses_ambiguous_live_ports(monkeypatch):
    monkeypatch.setattr(
        bridge,
        'probe_dtls_ports',
        _fake_port_set({5684, 49154}),
    )
    b = _mk_bridge(ocf_port=None, default=49155)
    with pytest.raises(ConnectionError, match='multiple DTLS listeners'):
        b._resolve_port()


def test_cached_live_port_is_reused_without_rediscovery(monkeypatch):
    # Cached 49156 and the default 49155 are both live; the cache-first
    # path must return the previously proven port without an ambiguous
    # full-set probe.
    monkeypatch.setattr(
        bridge,
        'probe_dtls_port',
        _fake_port_probe({49155, 49156}),
    )
    b = _mk_bridge(ocf_port=None, default=49155, discovered=49156)
    assert b._resolve_port() == 49156


def test_autodiscovery_all_dead_raises_and_clears_cache(monkeypatch):
    monkeypatch.setattr(bridge, 'probe_dtls_port', _fake_port_probe(set()))
    monkeypatch.setattr(bridge, 'probe_dtls_ports', _fake_port_set(set()))
    b = _mk_bridge(ocf_port=None, discovered=49154)
    with pytest.raises(ConnectionError):
        b._resolve_port()
    assert b._discovered_port is None


def test_candidate_ports_cover_band_plus_default(monkeypatch):
    b = _mk_bridge(ocf_port=None, default=49200)
    cands = b._candidate_ports()
    assert set(bridge.OCF_PORT_BAND) <= set(cands)
    assert bridge.OCF_STANDARD_SECURE_PORT in cands
    assert 49200 in cands
    assert cands == sorted(cands)


def test_an_advertised_port_is_probed_before_the_band(monkeypatch):
    # The device names 49155 and it answers, so the band is never swept.
    # This is the one exchange that gets the port right on a device whose
    # DTLS port sits outside the band entirely.
    swept = []

    def fake_set(ip, ports, **kw):
        swept.append(tuple(ports))
        return types.SimpleNamespace(outcome='selected', selected_port=ports[0])

    monkeypatch.setattr(
        bridge, 'discover_ocf_secure_ports', _fake_directory((51163,)))
    monkeypatch.setattr(bridge, 'probe_dtls_ports', fake_set)
    b = _mk_bridge(ocf_port=None, default=49155)

    assert b._resolve_port() == 51163
    assert swept == [(51163,)]
    assert b._discovered_port == 51163


def test_an_advertised_port_that_does_not_answer_falls_back_to_the_band(
        monkeypatch):
    # A directory serialised before the DTLS bind, or after the port moved,
    # advertises a port nothing is listening on. The probe is what decides,
    # so the band still runs.
    monkeypatch.setattr(
        bridge, 'discover_ocf_secure_ports', _fake_directory((49999,)))
    monkeypatch.setattr(bridge, 'probe_dtls_ports', _fake_port_set({49154}))
    b = _mk_bridge(ocf_port=None, default=49155)

    assert b._resolve_port() == 49154
    assert b._discovered_port == 49154


def test_a_failed_directory_read_falls_back_to_the_band(monkeypatch):
    monkeypatch.setattr(
        bridge,
        'discover_ocf_secure_ports',
        _fake_directory((), error=OSError('no route')),
    )
    monkeypatch.setattr(bridge, 'probe_dtls_ports', _fake_port_set({49154}))
    b = _mk_bridge(ocf_port=None, default=49155)

    assert b._resolve_port() == 49154


def test_a_pinned_port_never_reads_the_directory(monkeypatch):
    # A pinned OCF_PORT is gated but never overridden, so there is nothing
    # for an advertisement to contribute.
    read = []

    def fake_directory(ip, **kw):
        read.append(ip)
        return types.SimpleNamespace(ports=(49999,), found=True)

    monkeypatch.setattr(
        bridge, 'discover_ocf_secure_ports', fake_directory)
    monkeypatch.setattr(bridge, 'probe_dtls_port', _fake_port_probe({49155}))
    b = _mk_bridge(ocf_port=49155)

    assert b._resolve_port() == 49155
    assert read == []


def test_a_cached_port_never_reads_the_directory(monkeypatch):
    read = []

    def fake_directory(ip, **kw):
        read.append(ip)
        return types.SimpleNamespace(ports=(49999,), found=True)

    monkeypatch.setattr(
        bridge, 'discover_ocf_secure_ports', fake_directory)
    monkeypatch.setattr(bridge, 'probe_dtls_port', _fake_port_probe({49156}))
    b = _mk_bridge(ocf_port=None, default=49155, discovered=49156)

    assert b._resolve_port() == 49156
    assert read == []


def test_ambiguity_in_the_directory_tier_still_demands_a_pinned_port(
        monkeypatch):
    # Two advertised ports that both answer are as ambiguous as two swept
    # ones: nothing here can choose between them, so say so.
    monkeypatch.setattr(
        bridge,
        'discover_ocf_secure_ports',
        _fake_directory((49154, 49155)),
    )
    monkeypatch.setattr(
        bridge, 'probe_dtls_ports', _fake_port_set({49154, 49155}))
    b = _mk_bridge(ocf_port=None, default=49155)

    with pytest.raises(ConnectionError, match='multiple DTLS listeners'):
        b._resolve_port()
