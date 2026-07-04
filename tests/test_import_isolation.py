"""protocol/ and ocf/ must be vendorable on their own — no dependency
on mqtt_demo/. This copies just those two directories into an empty
temp dir and imports every module in them there, so a stray
`from mqtt_demo... import ...` fails loudly instead of silently
passing because mqtt_demo/ happens to also be on sys.path in-repo."""
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_protocol_and_ocf_import_without_mqtt_demo_present(tmp_path):
    for pkg in ('protocol', 'ocf'):
        shutil.copytree(REPO_ROOT / pkg, tmp_path / pkg)

    import_lines = [
        "import protocol.coap",
        "import protocol.dtls_session",
        "import ocf.state_cache",
        "import ocf.poll_scheduler",
        "import ocf.keepalive",
        "import ocf.observe_refresh",
    ]
    script = "\n".join(import_lines) + "\nprint('OK')\n"

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"protocol/ocf failed to import without mqtt_demo/ present:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "OK" in result.stdout
