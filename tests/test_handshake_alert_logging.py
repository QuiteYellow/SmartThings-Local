"""A handshake that dies at the TLS layer must say why, in the log only.

`connect()` turns any `SSL.Error` into a bare `SessionError`, whose
message is the class default. That is deliberate -- the errors module
refuses arbitrary detail because backend errors can carry remote
endpoints, local paths or credential metadata -- but it left the alert
itself unrecoverable, so a rejected handshake read as "session
operation failed" and nothing more.

The alert now reaches the local log. These tests pin both halves: the
reason survives, and the raised exception stays redacted.
"""

from __future__ import annotations

import logging

import pytest
from OpenSSL import SSL

from smartthings_local.errors import SessionError
from smartthings_local.protocol.dtls_session import _openssl_error_reasons


def test_a_peer_alert_is_named():
    error = SSL.Error([("SSL routines", "", "tlsv1 alert unknown ca")])

    assert _openssl_error_reasons(error) == "tlsv1 alert unknown ca"


def test_several_stacked_reasons_are_all_kept():
    error = SSL.Error([
        ("SSL routines", "ssl3_read_bytes", "sslv3 alert handshake failure"),
        ("SSL routines", "ssl3_get_record", "wrong version number"),
    ])

    assert _openssl_error_reasons(error) == (
        "sslv3 alert handshake failure, wrong version number"
    )


def test_a_syscall_error_keeps_its_string_and_drops_the_errno():
    assert _openssl_error_reasons(
        SSL.SysCallError(-1, "Unexpected EOF")) == "Unexpected EOF"


def test_an_empty_error_falls_back_to_its_type():
    assert _openssl_error_reasons(SSL.Error()) == "Error"
    assert _openssl_error_reasons(SSL.SysCallError()) == "SysCallError"


def test_nothing_but_reason_strings_survives():
    """The guard that keeps this inside the redaction contract: a host,
    a filesystem path or a key blob in the args is not a reason string
    and must not be echoed."""
    error = SSL.Error([
        ("SSL routines", "/etc/ssl/private/client.key", "bad decrypt"),
    ])

    reasons = _openssl_error_reasons(error)
    assert reasons == "bad decrypt"
    assert "/etc/ssl" not in reasons


def test_the_raised_error_stays_redacted():
    """Detail goes to the log, never onto the exception a consumer may
    surface or a reporter may paste into an issue."""
    assert str(SessionError()) == "session operation failed"
    assert SessionError().args == ("session operation failed",)


class _NullAuth:
    def configure_context(self, _context):
        return None


def test_connect_logs_the_alert_and_still_raises_a_redacted_error(
    caplog, monkeypatch
):
    """The whole point, end to end: drive connect() into the SSL.Error
    branch and check the alert lands in the log while the exception the
    caller sees carries nothing."""
    from smartthings_local.protocol import dtls_session

    def reject(*_args, **_kwargs):
        raise SSL.Error([("SSL routines", "", "tlsv1 alert unknown ca")])

    monkeypatch.setattr(dtls_session, "_drive_dtls_handshake", reject)
    session = dtls_session.DtlsCoapSession(
        "127.0.0.1", 49155, auth=_NullAuth())

    with caplog.at_level(logging.WARNING, logger=dtls_session.__name__):
        with pytest.raises(SessionError) as raised:
            session.connect(timeout=1.0)

    assert "tlsv1 alert unknown ca" in caplog.text
    assert str(raised.value) == "session operation failed"
