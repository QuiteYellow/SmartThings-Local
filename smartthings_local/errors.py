"""Public, redacted exception types for smartthings-local."""

__all__ = [
    'AuthenticationError',
    'AuthorizationError',
    'BlockwiseError',
    'EndpointError',
    'HandshakePeerCleanupError',
    'MalformedMessageError',
    'ObserveError',
    'PeerInitiatedHandshakeError',
    'ProbeError',
    'SessionClosedError',
    'SessionError',
    'SessionIdentifierError',
    'SessionResetError',
    'SessionTimeoutError',
    'SmartThingsLocalError',
]


class SmartThingsLocalError(Exception):
    """Base class for classified library failures.

    Subclasses expose a stable ``code`` and a fixed, non-sensitive message.
    They intentionally do not accept arbitrary detail because backend errors
    can contain remote endpoints, local paths, or credential metadata.
    """

    code = 'smartthings_local_error'
    message = 'SmartThings Local operation failed'

    def __init__(self):
        super().__init__(self.message)

    def __repr__(self):
        return f'{type(self).__name__}(code={self.code!r})'


class EndpointError(SmartThingsLocalError, OSError):
    """An endpoint could not be resolved, bound, or connected."""

    code = 'endpoint'
    message = 'endpoint operation failed'


class ProbeError(SmartThingsLocalError, ConnectionError):
    """A DTLS probe failed before producing a protocol result."""

    code = 'probe'
    message = 'DTLS probe failed'


class SessionError(SmartThingsLocalError, ConnectionError):
    """A connected-session operation failed."""

    code = 'session'
    message = 'session operation failed'


class AuthenticationError(SessionError):
    """The peer or local credentials could not be authenticated."""

    code = 'authentication'
    message = 'authentication failed'


class AuthorizationError(SmartThingsLocalError, PermissionError):
    """The authenticated peer is not authorized for an operation."""

    code = 'authorization'
    message = 'operation is not authorized'


class SessionTimeoutError(SmartThingsLocalError, TimeoutError):
    """A bounded session operation exceeded its deadline."""

    code = 'timeout'
    message = 'session operation timed out'


class PeerInitiatedHandshakeError(SessionError):
    """The peer was already handshaking toward this endpoint, so ours failed.

    A DTLS client never legitimately receives a ClientHello. An OCF server
    with a message for an endpoint it holds no session for opens one itself,
    and a stack that keys its peer table on address and port alone then feeds
    our ClientHello into that client-role context, which rejects it. The
    collision clears the peer, so an immediate retry normally succeeds. The
    caller owns that retry policy; this is expected peer behaviour rather
    than a fault.
    """

    code = 'peer_initiated_handshake'
    message = 'peer initiated a concurrent handshake'


class HandshakePeerCleanupError(SessionTimeoutError):
    """A cleanup alert was sent for an HVR-only half-open DTLS peer.

    The caller may apply its device-specific settle delay and retry policy.
    """

    code = 'handshake_peer_cleanup'
    message = 'handshake peer cleanup was sent'


class FragmentLimitTimeoutError(SessionTimeoutError):
    """A read gave up on its first block while a fragment length was in force.

    These appliances cannot send a record larger than a negotiated
    `max_fragment_length`, so a resource whose representation exceeds it never
    arrives at all. Reported on mbillow/localthings#504 by @fredrikbae, who
    measured it on a TP1X board: the response never comes and the session is
    unusable afterwards.

    **This names the conditions, not a proven cause.** What the library knows
    is that the first block of the transfer drew nothing and that a fragment
    length was negotiated. An appliance that has powered its radio down
    produces the same silence. What separates the two is whether other, smaller
    resources on the same device still answer, and that is the caller's to
    decide -- which is the reason this carries the limit rather than asserting
    the reason.

    A timeout on a later block stays an ordinary :class:`SessionTimeoutError`:
    blocks were arriving, so the representation fits and the deadline was the
    binding constraint.

    Subclasses :class:`SessionTimeoutError`, so existing handlers are
    unaffected.
    """

    code = 'fragment_limit_timeout'
    message = 'first block drew nothing under a negotiated fragment length'

    def __init__(self, fragment_length=None):
        super().__init__()
        #: The negotiated length in bytes, or None when it was unavailable.
        self.fragment_length = fragment_length


class SessionClosedError(SessionError):
    """An operation was attempted on a closed session."""

    code = 'session_closed'
    message = 'session is closed'


class SessionResetError(SessionError):
    """The peer rejected an exchange with a CoAP RST.

    Distinct from a closed session: the transport is still up and every
    other exchange on it is unaffected. Only the message the RST names has
    been refused.
    """

    code = 'session_reset'
    message = 'peer reset the exchange'


class SessionIdentifierError(SessionError):
    """No free Message ID or token was available for a new exchange.

    Every identifier in the space is held by an exchange that has not yet
    completed, which in practice means requests are leaking rather than
    that the session is genuinely saturated.
    """

    code = 'session_identifier'
    message = 'no free message identifier for a new exchange'


class MalformedMessageError(SmartThingsLocalError, ValueError):
    """A protocol message could not be decoded safely."""

    code = 'malformed_message'
    message = 'malformed protocol message'


class BlockwiseError(SessionError):
    """A Block1 or Block2 transfer violated its bounded contract."""

    code = 'blockwise'
    message = 'blockwise transfer failed'


class ObserveError(SessionError):
    """A CoAP Observe relation could not be established or maintained."""

    code = 'observe'
    message = 'Observe relation failed'
