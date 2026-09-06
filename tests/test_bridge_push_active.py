"""Push Active must mean the appliance chose to send something (#41).

A device answers every OBSERVE register CON with a 2.05 carrying the
current representation, and that answer arrives on the observe token
exactly as a spontaneous notification does. At session start the cache
is empty, so every one of those answers is a cache change -- which used
to set the same "something pushed recently" timestamp a real
notification sets. The result was Push Active reading online for its
whole ten-minute window on an appliance with no route to Samsung's
cloud, which is emitting nothing at all.

The session resolves the token, the Message ID and the Observe option,
so it is the only layer that can tell the two apart. The bridge reads
`ObserveDelivery.registration` rather than inferring anything.
"""
import threading
import types

import cbor2

from mqtt_demo.bridge import PushBridge
from smartthings_local.ocf.state_cache import StateCache
from smartthings_local.protocol.dtls_session import ObserveDelivery

HREF = '/operational/state/vs/0'


def _bridge():
    """A bridge reduced to its cache plumbing, with nothing that needs a
    socket, an MQTT client or a descriptor."""
    bridge = object.__new__(PushBridge)
    bridge.descriptor = types.SimpleNamespace(
        on_observation=None,
        observe_paths=(),
    )
    bridge.notif_count = 0
    bridge.last_change_ts = None
    bridge._last_change_source = None
    bridge._last_observe_change_ts = None
    bridge._fetch_lock = threading.Lock()
    bridge._fetch_gen = {}
    bridge.maybe_publish_state = lambda **kwargs: None
    bridge.cache = StateCache(bridge.descriptor)
    bridge.cache.set_on_change(bridge._on_cache_change)
    return bridge


def _deliver(bridge, *, registration, href=HREF, query=(), **fields):
    bridge._on_observe_delivery(ObserveDelivery(
        href=href,
        payload=cbor2.dumps(fields),
        query=query,
        registration=registration,
    ))


def test_registration_answer_does_not_count_as_push():
    bridge = _bridge()

    _deliver(bridge, registration=True, state='Ready')

    # The cache took the payload -- that part is load-bearing, since both
    # sides seed from this first representation.
    assert bridge.cache.get(HREF) == {'state': 'Ready'}
    assert bridge.notif_count == 1
    # ...but it is not evidence of push.
    assert bridge._last_observe_change_ts is None
    assert bridge.cache.source[HREF] == 'observe-register'


def test_a_change_the_device_chose_to_send_does_count():
    bridge = _bridge()

    _deliver(bridge, registration=True, state='Ready')
    _deliver(bridge, registration=False, state='Running')

    assert bridge._last_observe_change_ts is not None
    assert bridge.cache.source[HREF] == 'observe'


def test_query_variants_each_get_their_own_registration_answer():
    """Two query-qualified relations on one href register separately, so
    both answers arrive and neither is push. Position alone cannot tell
    them apart, because the href is the same for both."""
    bridge = _bridge()

    _deliver(bridge, registration=True, query=('if=oic.if.a',), state='Ready')
    _deliver(bridge, registration=True, query=('if=oic.if.s',), state='Ready')

    assert bridge._last_observe_change_ts is None
    assert bridge.cache.source[HREF] == 'observe-register'


def test_a_reconnect_re_registers_and_that_is_still_not_push():
    """Reconnects and the 6-hourly refresh both retire the token and
    subscribe again, so the answers come round again. The session marks
    each one, and the bridge keeps no per-session state of its own."""
    bridge = _bridge()

    _deliver(bridge, registration=True, state='Ready')
    _deliver(bridge, registration=False, state='Running')
    bridge._last_observe_change_ts = None

    _deliver(bridge, registration=True, state='Ready')

    assert bridge._last_observe_change_ts is None
    assert bridge.cache.source[HREF] == 'observe-register'


def test_a_blockwise_registration_answer_stays_a_registration():
    """An empty or partial payload goes out to a fetchback thread, and
    the re-read must not launder the registration answer into a push."""
    bridge = _bridge()
    scheduled = []
    bridge._schedule_fetchback = (
        lambda href, delay_s=0.0, source='observe':
        scheduled.append((href, source)))

    bridge._on_observe_delivery(ObserveDelivery(
        href=HREF, payload=b'', registration=True))

    assert scheduled == [(HREF, 'observe-register')]
