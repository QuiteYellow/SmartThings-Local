"""smartthings_local (protocol/ + ocf/) must be vendorable on its own — no
dependency on mqtt_demo/. This copies just the smartthings_local package into
an empty temp dir and imports every module in it there, so a stray
`from mqtt_demo... import ...` fails loudly instead of silently passing
because mqtt_demo/ happens to also be on sys.path in-repo."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_smartthings_local_imports_without_mqtt_demo_present(tmp_path):
    shutil.copytree(REPO_ROOT / "smartthings_local", tmp_path / "smartthings_local")

    import_lines = [
        "import smartthings_local.protocol.coap",
        "import smartthings_local.protocol.dtls_session",
        "import smartthings_local.ocf.state_cache",
        "import smartthings_local.ocf.poll_scheduler",
        "import smartthings_local.ocf.keepalive",
        "import smartthings_local.ocf.observe_refresh",
    ]
    script = "\n".join(import_lines) + "\nprint('OK')\n"

    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp_path)

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=env,
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"smartthings_local failed to import without mqtt_demo/ present:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "OK" in result.stdout
