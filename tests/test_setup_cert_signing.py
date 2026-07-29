import shutil
import subprocess

import pytest

import setup_cert

# All of these drive the real `openssl` CLI the way setup_cert does.
pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl CLI not available")

UUID = "04700f20-1111-2222-3333-444455556666"


def _make_ca(dir_path):
    """A throwaway self-signed CA standing in for the AC14K_M signer."""
    cert = dir_path / "ca.pem"
    key = dir_path / "ca.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=AC14K_M"],
        check=True, capture_output=True)
    return cert, key


def test_mint_cert_produces_sha1_leaf_with_uuid(tmp_path):
    ca_cert, ca_key = _make_ca(tmp_path)
    paths = setup_cert.mint_cert(
        UUID, ca_cert, ca_key, [ca_cert], tmp_path / "out")

    for name in ("key", "leaf", "fullchain"):
        assert paths[name].exists() and paths[name].stat().st_size > 0

    text = subprocess.run(
        ["openssl", "x509", "-in", str(paths["leaf"]), "-noout", "-text"],
        check=True, capture_output=True, text=True).stdout
    assert "sha1WithRSAEncryption" in text          # SHA-1 signed leaf
    assert f"URI:urn:uuid:{UUID}" in text           # UUID in the SAN
    assert "1.3.6.1.4.1.51414" in text              # custom OIDs parsed
    # fullchain is leaf + supplied chain
    assert paths["fullchain"].read_text().count("BEGIN CERTIFICATE") == 2


def test_mint_cert_surfaces_openssl_error(tmp_path):
    """A genuine signing failure raises CommandError carrying openssl's
    output, instead of a bare non-zero-exit traceback."""
    ca_cert, _ = _make_ca(tmp_path)
    with pytest.raises(setup_cert.CommandError) as exc:
        setup_cert.mint_cert(
            UUID, ca_cert, tmp_path / "missing.key", [ca_cert],
            tmp_path / "out")
    assert "command failed" in str(exc.value)
    assert len(str(exc.value)) > 40  # includes detail, not just an exit code


def test_mint_cert_retries_when_sha1_signing_blocked(tmp_path, monkeypatch):
    """Simulate a Fedora/RHEL crypto policy rejecting SHA-1: the first
    (plain) signing attempt fails, and the SHA-1-override retry recovers."""
    ca_cert, ca_key = _make_ca(tmp_path)
    real_run = setup_cert.run
    attempts = {"plain": 0}

    def fake_run(cmd, **kw):
        # Only the plain attempt has no OPENSSL_CONF override in its env.
        if cmd[:3] == ["openssl", "x509", "-req"] and "env" not in kw:
            attempts["plain"] += 1
            raise setup_cert.CommandError(
                "error: sha1 signature disabled by crypto policy")
        return real_run(cmd, **kw)

    monkeypatch.setattr(setup_cert, "run", fake_run)
    paths = setup_cert.mint_cert(
        UUID, ca_cert, ca_key, [ca_cert], tmp_path / "out")

    assert attempts["plain"] == 1        # the plain path was exercised
    assert paths["leaf"].exists()        # the override retry recovered


def test_command_error_includes_stderr():
    with pytest.raises(setup_cert.CommandError) as exc:
        setup_cert.run(["openssl", "x509", "-in", "/no/such/file"])
    assert "command failed" in str(exc.value)
