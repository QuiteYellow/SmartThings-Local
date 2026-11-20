"""What the library reports once a fragment length is in force.

These appliances cannot send a record larger than a negotiated
`max_fragment_length`, measured by @fredrikbae on a TP1X board and reported on
mbillow/localthings#504. An integration therefore needs two things the library
did not give it: the limit itself, and a way to tell a representation that
cannot fit from an appliance that has gone quiet.

`DtlsCoapSession.negotiated_fragment_length` is the first.
`FragmentLimitTimeoutError` is the second, and these tests pin what it does
*not* claim as carefully as what it does: it fires on a first block that drew
nothing, which an appliance with its radio off also produces.
"""

from __future__ import annotations

from smartthings_local.errors import (
    FragmentLimitTimeoutError,
    SessionTimeoutError,
)
from smartthings_local.protocol.dtls_session import DtlsCoapSession


class _Connection:
    """Only what the session touches for these two features."""

    def __init__(self, fragment_length=None):
        self.negotiated_fragment_length = fragment_length


class _Provider:
    def __init__(self, connection):
        self.connection = connection

    def configure_context(self, context):
        return None

    def create_dtls_connection(self, *, mtu):
        return self.connection


def _session():
    return DtlsCoapSession(
        "192.0.2.10", 49154, auth=_Provider(_Connection()),
    )


# -- the negotiated limit, read from the session -------------------------


def test_no_session_means_no_negotiated_limit():
    assert _session().negotiated_fragment_length is None


def test_the_limit_is_read_from_the_live_connection():
    session = _session()
    session.conn = _Connection(fragment_length=1024)
    assert session.negotiated_fragment_length == 1024


def test_an_engine_that_cannot_negotiate_reports_none():
    class _NoLimit(_Connection):
        def __init__(self):
            super().__init__()
            del self.negotiated_fragment_length

    session = _session()
    session.conn = _NoLimit()
    assert session.negotiated_fragment_length is None


# -- the typed read timeout ----------------------------------------------


def test_a_first_block_that_drew_nothing_under_a_limit_is_typed():
    session = _session()
    session.conn = _Connection(fragment_length=1024)
    error = session._read_timeout(0)
    assert isinstance(error, FragmentLimitTimeoutError)
    assert error.fragment_length == 1024


def test_a_later_block_stays_an_ordinary_timeout():
    """Blocks were arriving, so the deadline was the binding constraint."""
    session = _session()
    session.conn = _Connection(fragment_length=1024)
    error = session._read_timeout(3)
    assert type(error) is SessionTimeoutError


def test_without_a_negotiated_limit_it_stays_an_ordinary_timeout():
    session = _session()
    session.conn = _Connection(fragment_length=None)
    assert type(session._read_timeout(0)) is SessionTimeoutError


def test_the_typed_timeout_is_still_a_timeout():
    """Existing handlers keep working, as HandshakePeerCleanupError does."""
    error = FragmentLimitTimeoutError(1024)
    assert isinstance(error, SessionTimeoutError)
    assert isinstance(error, TimeoutError)


def test_the_typed_timeout_carries_no_limit_when_none_is_known():
    assert FragmentLimitTimeoutError().fragment_length is None
