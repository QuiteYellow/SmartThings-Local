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


def test_mint_self_signed_default(tmp_path):
    """The default path: a self-signed SHA-256 leaf carrying only the UUID,
    no AC14K_M, no vendor OIDs, no org identity."""
    paths = setup_cert.mint_self_signed(UUID, tmp_path / "out")

    for name in ("key", "leaf", "fullchain"):
        assert paths[name].exists() and paths[name].stat().st_size > 0

    text = subprocess.run(
        ["openssl", "x509", "-in", str(paths["leaf"]), "-noout", "-text"],
        check=True, capture_output=True, text=True).stdout
    assert "sha256WithRSAEncryption" in text        # SHA-256, not SHA-1
    assert "sha1WithRSAEncryption" not in text
    assert f"URI:urn:uuid:{UUID}" in text           # UUID in the SAN
    assert "1.3.6.1.4.1.51414" not in text          # no vendor OIDs

    subject = subprocess.run(
        ["openssl", "x509", "-in", str(paths["leaf"]), "-noout", "-subject"],
        check=True, capture_output=True, text=True).stdout
    assert f"uuid:{UUID}" in subject
    assert "Samsung" not in subject                 # no vendor org claimed

    issuer = subprocess.run(
        ["openssl", "x509", "-in", str(paths["leaf"]), "-noout", "-issuer"],
        check=True, capture_output=True, text=True).stdout
    assert "AC14K_M" not in issuer
    # The leaf signs itself, so issuer and subject are the same DN...
    assert issuer.replace("issuer=", "") == subject.replace("subject=", "")
    # ...and there is no CA above it to put in the fullchain.
    assert paths["fullchain"].read_text().count("BEGIN CERTIFICATE") == 1


def test_both_mint_paths_write_the_documented_filenames(tmp_path):
    """README, docs/bridge-demo.md, mqtt_demo/.env.example and
    mqtt_demo/config.py's defaults all name client_fullchain.pem and
    client.key, so both paths have to write those, not one each."""
    ca_cert, ca_key = _make_ca(tmp_path)
    minted = {
        "self-signed": setup_cert.mint_self_signed(UUID, tmp_path / "ss"),
        "fallback": setup_cert.mint_cert(
            UUID, ca_cert, ca_key, [ca_cert], tmp_path / "fb"),
    }
    for path_name, paths in minted.items():
        assert paths["key"].name == "client.key", path_name
        assert paths["fullchain"].name == "client_fullchain.pem", path_name
        assert paths["key"].exists() and paths["fullchain"].exists()


def test_mint_cert_produces_sha1_leaf_with_uuid(tmp_path):
    # mint_cert is the --fallback (AC14K_M-signed) path; it stays SHA-1.
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


def test_sha1_retry_does_not_give_openssl_3_config_to_libressl(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if cmd == ["openssl", "version"]:
            return subprocess.CompletedProcess(cmd, 0, "LibreSSL 3.3.6\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(setup_cert, "run", fake_run)
    monkeypatch.setenv("OPENSSL_CONF", "/synthetic/inherited.cnf")

    setup_cert.run_allow_sha1(["openssl", "x509", "-req"])

    assert calls[1][0] == ["openssl", "x509", "-req"]
    assert "OPENSSL_CONF" not in calls[1][1]["env"]


def test_command_error_includes_stderr():
    with pytest.raises(setup_cert.CommandError) as exc:
        setup_cert.run(["openssl", "x509", "-in", "/no/such/file"])
    assert "command failed" in str(exc.value)
